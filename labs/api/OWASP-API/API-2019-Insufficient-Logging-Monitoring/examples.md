# API10:2019 Insufficient Logging & Monitoring - Code Examples

Each section below pairs a **blind** implementation (an attack would leave no usable trace) with a **observable** one that emits structured security events. The final sections show the **alerting and SIEM configuration** that turns those events into real-time detection.

## Python (structlog)

### Blind
```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    user = request.json.get('user')
    if not check_password(user, request.json.get('pass')):
        return jsonify({'error': 'invalid credentials'}), 401   # nothing logged
    return jsonify({'token': issue_token(user)})

@app.route('/api/v1/invoices/<id>')
def invoice(id):
    inv = load_invoice(id)
    if inv.owner != current_user():
        return jsonify({'error': 'forbidden'}), 403              # denial not recorded
    return jsonify(inv.to_dict())
```

A credential-stuffing run and a BOLA enumeration walk both produce only anonymous 401/403 responses—no actor, no object, nothing to alert on.

### Observable
```python
import re, structlog
from flask import Flask, request, jsonify, g

app = Flask(__name__)
log = structlog.get_logger()

CONTROL = re.compile(r'[\r\n\t\x00-\x1f]')
def safe(v):                       # prevent log injection (CRLF forging)
    return CONTROL.sub(' ', str(v))[:256]

@app.before_request
def add_context():
    g.request_id = request.headers.get('X-Request-Id') or new_id()
    g.source_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    user = request.json.get('user')
    if not check_password(user, request.json.get('pass')):
        log.warning('auth.failure', outcome='failure',
                    auth_subject=safe(user), source_ip=safe(g.source_ip),
                    endpoint='/api/v1/auth/login', status=401,
                    request_id=g.request_id)          # secrets are NEVER logged
        return jsonify({'error': 'invalid credentials'}), 401
    log.info('auth.success', outcome='success', auth_subject=safe(user),
             source_ip=safe(g.source_ip), request_id=g.request_id)
    return jsonify({'token': issue_token(user)})

@app.route('/api/v1/invoices/<id>')
def invoice(id):
    inv = load_invoice(id)
    if inv.owner != current_user():
        log.warning('authz.denied', outcome='failure',
                    auth_subject=current_user(), object_id=safe(id),
                    endpoint='/api/v1/invoices/{id}', status=403,
                    source_ip=safe(g.source_ip), request_id=g.request_id)
        return jsonify({'error': 'forbidden'}), 403
    return jsonify(inv.to_dict())
```

Now every failed login and every denied object carries the subject, source, endpoint, and object id—exactly the fields a detection needs to spot stuffing and enumeration.

## Node.js (Express + pino)

### Blind
```javascript
const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/v1/auth/login', (req, res) => {
    if (!checkPassword(req.body.user, req.body.pass))
        return res.status(401).json({ error: 'invalid credentials' }); // silent
    res.json({ token: issueToken(req.body.user) });
});
```

### Observable
```javascript
const express = require('express');
const pino = require('pino');
const app = express();
app.use(express.json());

// redact never keeps secrets out of the log stream
const log = pino({ redact: ['req.headers.authorization', '*.pass', '*.token'] });

const clean = v => String(v).replace(/[\r\n\t\x00-\x1f]/g, ' ').slice(0, 256);

app.use((req, res, next) => {
    req.ctx = {
        request_id: req.get('X-Request-Id') || newId(),
        source_ip: req.get('X-Forwarded-For') || req.ip,
    };
    next();
});

app.post('/api/v1/auth/login', (req, res) => {
    if (!checkPassword(req.body.user, req.body.pass)) {
        log.warn({ event: 'auth.failure', outcome: 'failure',
                   auth_subject: clean(req.body.user),
                   source_ip: req.ctx.source_ip, endpoint: '/api/v1/auth/login',
                   status: 401, request_id: req.ctx.request_id });
        return res.status(401).json({ error: 'invalid credentials' });
    }
    log.info({ event: 'auth.success', outcome: 'success',
               auth_subject: clean(req.body.user),
               source_ip: req.ctx.source_ip, request_id: req.ctx.request_id });
    res.json({ token: issueToken(req.body.user) });
});

app.get('/api/v1/invoices/:id', (req, res) => {
    const inv = loadInvoice(req.params.id);
    if (inv.owner !== currentUser(req)) {
        log.warn({ event: 'authz.denied', outcome: 'failure',
                   auth_subject: currentUser(req), object_id: clean(req.params.id),
                   endpoint: '/api/v1/invoices/{id}', status: 403,
                   source_ip: req.ctx.source_ip, request_id: req.ctx.request_id });
        return res.status(403).json({ error: 'forbidden' });
    }
    res.json(inv);
});
```

## Java (Spring Boot + SLF4J/Logback + MDC)

### Observable
```java
// A filter puts request-scoped context on the MDC so every log line carries it
@Component
class ContextFilter extends OncePerRequestFilter {
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        MDC.put("request_id", header(req, "X-Request-Id", UUID.randomUUID().toString()));
        MDC.put("source_ip",  header(req, "X-Forwarded-For", req.getRemoteAddr()));
        try { chain.doFilter(req, res); } finally { MDC.clear(); }
    }
}

@RestController
class InvoiceController {
    private static final Logger log = LoggerFactory.getLogger(InvoiceController.class);

    @GetMapping("/api/v1/invoices/{id}")
    public ResponseEntity<?> get(@PathVariable String id, Principal p) {
        Invoice inv = service.load(id);
        if (!inv.getOwner().equals(p.getName())) {
            // structured event: subject + denied object; MDC adds request_id + source_ip
            log.warn("authz.denied outcome=failure auth_subject={} object_id={} " +
                     "endpoint=/api/v1/invoices/{id} status=403",
                     p.getName(), sanitize(id));
            return ResponseEntity.status(403).body(Map.of("error", "forbidden"));
        }
        return ResponseEntity.ok(inv);
    }

    // strip CR/LF so a crafted id cannot forge a log line
    private static String sanitize(String v) {
        return v.replaceAll("[\\r\\n\\t\\x00-\\x1f]", " ");
    }
}
```

```xml
<!-- logback-spring.xml: emit JSON so fields (incl. MDC) are machine-parseable -->
<appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
  <encoder class="net.logstash.logback.encoder.LogstashEncoder">
    <includeMdcKeyName>request_id</includeMdcKeyName>
    <includeMdcKeyName>source_ip</includeMdcKeyName>
  </encoder>
</appender>
```

## Alerting & SIEM Configuration

Structured events are only half the job—these rules turn them into real-time detection. Thresholds shown are illustrative starting points; tune them to your own baseline.

### ElastAlert 2 (against Elasticsearch/OpenSearch): 401 spike = credential stuffing
```yaml
name: auth-failure-spike-per-source
type: frequency
index: api-logs-*
num_events: 20                 # 20+ failed logins ...
timeframe:
  minutes: 1                   # ... within 1 minute ...
filter:
  - term: { event: "auth.failure" }
query_key: source_ip          # ... from a single source IP
alert:
  - "slack"
realert:
  minutes: 10
```

### Sigma rule (portable): authorization-denial enumeration (BOLA sweep)
```yaml
title: API Authorization Denial Enumeration
logsource:
  product: api
  category: application
detection:
  denial:
    event: "authz.denied"
    status: 403
  timeframe: 5m
  condition: denial | count() by auth_subject > 50   # one subject, 50+ denials
level: high
description: One subject accrues many 403s across distinct object ids -> BOLA enumeration
```

### Prometheus / Alertmanager: rate-of-error and throttle spikes
```yaml
groups:
  - name: api-abuse
    rules:
      - alert: HighAuthFailureRate
        expr: sum(rate(api_auth_failures_total[5m])) by (source_ip) > 1
        for: 2m
        labels: { severity: high }
        annotations:
          summary: "Elevated 401s from {{ $labels.source_ip }} (possible credential stuffing)"

      - alert: RateLimitAbuse
        expr: sum(rate(api_throttled_total[5m])) by (client_id) > 0.5
        for: 5m
        labels: { severity: medium }
        annotations:
          summary: "Client {{ $labels.client_id }} repeatedly hitting rate limits"
```

### Splunk SPL: one token seen from many sources (stolen-token replay)
```
index=api_logs event=auth.success
| bucket _time span=5m
| stats dc(source_ip) as ips values(source_ip) as sources by token_id, _time
| where ips > 3
| eval detection="token used from multiple IPs in 5m (possible replay)"
```

## What Changed, and Why

| Gap | Blind | Observable |
|-----|-------|-----------|
| Auth failures | Silent 401 | Structured `auth.failure` with subject + source |
| Authz denials | Silent 403 | `authz.denied` with subject + object id |
| Format | Free text or nothing | Consistent JSON, machine-parseable |
| Context | No actor/object | request id, client, subject, source IP, endpoint, object id |
| Log injection | Raw input concatenated | CR/LF stripped; structured fields |
| Secrets | Tokens/PII risk in logs | Redaction; identifiers and outcomes only |
| Detection | Nobody watching | Tuned SIEM/alerting rules on 401/403/429, token spread |

## Next Steps

- **[Prevention](prevention.md)**: The full capture → centralise → alert → respond pipeline
- **[Attack Vectors](attack-vectors.md)**: The undetected attacks these events and rules are built to catch
- **[API Security Learning Path](/learn/api)**: Return to the full OWASP API Top 10
- **[Practice](/practice)**: Wire up structured logging and an alert against sample traffic
