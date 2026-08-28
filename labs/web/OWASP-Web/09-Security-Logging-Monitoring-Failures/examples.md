# Security Logging and Monitoring Failures - Examples

Each pair below shows a **vulnerable** logging approach and the **secure** version in the same language. The examples focus on the failures that define A9:2021: events not captured, unstructured or context-free entries, secrets and untrusted input written verbatim, and logs that never reach a place where they can be alerted on.

## Table of Contents

- [1. Structured Security Logging (Python)](#1-structured-security-logging-python)
- [2. Structured Security Logging (Node.js)](#2-structured-security-logging-nodejs)
- [3. Structured Security Logging (Java)](#3-structured-security-logging-java)
- [4. Preventing Log Injection](#4-preventing-log-injection)
- [5. Alerting & SIEM Configuration](#5-alerting--siem-configuration)
- [6. Side-by-Side Summary](#6-side-by-side-summary)

## 1. Structured Security Logging (Python)

### Vulnerable

```python
import logging
logging.basicConfig(filename="app.log", level=logging.INFO)

def login(username, password):
    user = db.find_user(username)
    if not user or not user.check(password):
        # A9: failed logins are the #1 signal - and this one is
        #   - unstructured free text (not SIEM-parseable)
        #   - missing source IP, request id, timestamp standard
        #   - logging the PASSWORD in cleartext (CWE-532)
        logging.info("login failed for " + username + " pw=" + password)
        return False
    # A9: successful login not logged at all -> no audit trail
    return True

def transfer(user, amount, to_acct):
    # A9: high-value transaction with NO log event
    bank.move(user, amount, to_acct)
```

### Secure

```python
import logging, json, sys
from datetime import datetime, timezone

# JSON formatter -> one structured event per line, SIEM-consumable
class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),  # UTC / RFC 3339
            "level": record.levelname,
            **record.__dict__.get("event", {}),
        }
        return json.dumps(payload)

handler = logging.StreamHandler(sys.stdout)   # stdout -> collector ships off-host
handler.setFormatter(JsonFormatter())
log = logging.getLogger("security")
log.addHandler(handler)
log.setLevel(logging.INFO)

_FORBIDDEN = {"password", "token", "secret", "cvv", "card"}

def emit(event, outcome, **fields):
    if _FORBIDDEN & set(fields):
        raise ValueError("refusing to log a sensitive field")
    log.info("", extra={"event": {"event": event, "outcome": outcome, **fields}})

def login(username, password, request):
    user = db.find_user(username)
    ctx = {"user_id": getattr(user, "id", None),
           "source_ip": request.remote_addr,
           "request_id": request.headers.get("X-Request-Id")}
    if not user or not user.check(password):
        emit("authn.login.failure", "denied", reason="invalid_credentials", **ctx)
        return False
    emit("authn.login.success", "success", **ctx)     # success IS logged
    return True

def transfer(user, amount, to_acct, request):
    bank.move(user, amount, to_acct)
    emit("txn.funds_transfer", "success", user_id=user.id,
         amount=str(amount), to_acct=to_acct,          # identifiers, not secrets
         request_id=request.headers.get("X-Request-Id"))
```

**What changed**: failed *and* successful logins are captured; the password is gone; every event is structured JSON with who/what/when/where; high-value transactions are audited; output goes to stdout for a collector to ship centrally.

## 2. Structured Security Logging (Node.js)

### Vulnerable

```javascript
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  authenticate(username, password)
    .then(ok => {
      // A9: console.log to a local file, unstructured, no context,
      //     and it prints the token to the log on success.
      if (!ok) console.log(`bad login ${username}`);
      else console.log(`ok ${username} token=${issueToken(username)}`);
      res.sendStatus(ok ? 200 : 401);
    })
    .catch(err => {
      // A9: error swallowed into a generic line, no event, no alerting hook
      console.log('error');
      res.sendStatus(500);
    });
});
```

### Secure

```javascript
const express = require('express');
const pino = require('pino');
const crypto = require('crypto');

const log = pino({
  timestamp: pino.stdTimeFunctions.isoTime,        // UTC RFC 3339
  redact: { paths: ['*.password', '*.token', 'req.headers.authorization'],
            censor: '[REDACTED]' },
  formatters: { level: (label) => ({ level: label }) }
});

const app = express();
app.use(express.json({ limit: '64kb' }));

// Attach a correlation id to every request for cross-service tracing
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || crypto.randomUUID();
  next();
});

app.post('/login', async (req, res) => {
  const { username } = req.body;
  const base = { user_id: username, source_ip: req.ip, request_id: req.id };
  try {
    const ok = await authenticate(username, req.body.password);
    if (!ok) {
      log.warn({ event: 'authn.login.failure', outcome: 'denied',
                 reason: 'invalid_credentials', ...base });
      return res.sendStatus(401);
    }
    log.info({ event: 'authn.login.success', outcome: 'success', ...base });
    res.sendStatus(200);
  } catch (err) {
    // Log the error WITH context and rethrow-style detail, never swallow it
    log.error({ event: 'authn.login.error', outcome: 'error',
                err: err.message, ...base });
    res.sendStatus(500);
  }
});
```

**What changed**: `pino` emits structured JSON with automatic secret redaction; a correlation ID is attached per request; failures, successes, and errors each become a distinct, alertable event.

## 3. Structured Security Logging (Java)

### Vulnerable

```java
// Spring controller
@RestController
class AuthController {
    private static final Logger log =
        LoggerFactory.getLogger(AuthController.class);

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Creds c) {
        try {
            if (!auth.check(c.user, c.pass)) {
                // A9: string-concatenated, no context, and the raw
                //     username can inject CR/LF to forge log lines
                log.info("Login failed: " + c.user + " / " + c.pass);
                return ResponseEntity.status(401).build();
            }
            return ResponseEntity.ok().build();          // success not logged
        } catch (Exception e) {
            // A9: exception swallowed, nothing useful recorded
        }
        return ResponseEntity.status(500).build();
    }
}
```

### Secure

```java
// Uses SLF4J + Logback with a JSON encoder (logstash-logback-encoder)
// and MDC for structured, escaped context fields.
@RestController
class AuthController {
    private static final Logger log =
        LoggerFactory.getLogger("security");

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Creds c,
                                   HttpServletRequest req) {
        // MDC values are encoded by the JSON layout -> no log injection,
        // and never place the password in MDC or the message.
        MDC.put("user_id", c.user);
        MDC.put("source_ip", req.getRemoteAddr());
        MDC.put("request_id", req.getHeader("X-Request-Id"));
        try {
            if (!auth.check(c.user, c.pass)) {
                log.warn("authn.login.failure outcome=denied reason=invalid_credentials");
                return ResponseEntity.status(401).build();
            }
            log.info("authn.login.success outcome=success");   // success audited
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            // Log WITH the exception, then let it propagate to a handler
            log.error("authn.login.error outcome=error", e);
            throw e;
        } finally {
            MDC.clear();
        }
    }
}
```

```xml
<!-- logback-spring.xml: JSON to stdout for a central collector -->
<configuration>
  <appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
  </appender>
  <root level="INFO">
    <appender-ref ref="JSON"/>
  </root>
</configuration>
```

**What changed**: MDC carries structured, encoder-escaped context (defeating log injection); the password never touches the log; success and error paths are both recorded; JSON output is ready for a SIEM.

## 4. Preventing Log Injection

When a value that the user controls must appear in a message string, neutralize newlines so an attacker cannot forge extra log lines (CWE-117). Structured fields handle this for you; the manual guard is for the cases where you still build a message.

```python
# Python: sanitize CR/LF/control chars before free-text logging
import re
_CTRL = re.compile(r"[\r\n\t\x00-\x1f]")

def safe(v: str) -> str:
    return _CTRL.sub(" ", str(v))

log.warn("authn.login.failure user=%s", safe(username))

# Attacker input:
#   username = "alice\n2026-01-01 INFO authn.login.success user_id=admin"
# After safe():
#   "alice 2026-01-01 INFO authn.login.success user_id=admin"
#   -> a single, honest line; no forged success event.
```

> If logs are ever rendered in a web dashboard, also **HTML-encode** untrusted fields at display time — otherwise injected markup becomes stored XSS in the analyst's browser.

## 5. Alerting & SIEM Configuration

Structured logs are only useful once a rule turns them into an alert with escalation. The examples below sit on top of the events emitted above.

#### Prometheus alert rule (threshold + pipeline health)

```yaml
groups:
  - name: security
    rules:
      # Cumulative across the fleet defeats per-IP rotation
      - alert: CredentialStuffingSuspected
        expr: sum(rate(authn_login_failure_total[5m])) > 20
        for: 2m
        labels: { severity: high }
        annotations:
          runbook: "https://runbooks.internal/auth-bruteforce"

      # Detect an access-control probe: many denials from one subject
      - alert: AccessControlProbe
        expr: sum by (user_id) (rate(authz_denied_total[10m])) > 5
        for: 5m
        labels: { severity: medium }

      # Monitoring-of-the-monitoring: the log shipper is down
      - alert: LogShipperDown
        expr: up{job="filebeat"} == 0
        for: 5m
        labels: { severity: critical }
```

#### Elastic (ELK) detection query

```json
POST /logs-*/_search
{
  "query": {
    "bool": {
      "filter": [
        { "term":  { "event": "authn.login.failure" } },
        { "range": { "timestamp": { "gte": "now-5m" } } }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "source_ip", "size": 20 },
      "aggs": { "failures": { "value_count": { "field": "event" } } }
    }
  }
}
# Wire this into an alerting watcher: page when any bucket, or the
# fleet-wide sum, crosses the tuned threshold.
```

#### Alertmanager escalation

```yaml
route:
  receiver: slack-secops
  routes:
    - matchers: [severity="critical"]
      receiver: pagerduty-oncall     # critical wakes a human
  repeat_interval: 30m               # keep paging until acknowledged
receivers:
  - name: slack-secops
    slack_configs: [{ channel: '#secops-alerts' }]
  - name: pagerduty-oncall
    pagerduty_configs: [{ routing_key: '<key>' }]
```

## 6. Side-by-Side Summary

| Aspect | Vulnerable | Secure |
|--------|-----------|--------|
| Failed logins | Not logged, or free text | Structured `authn.login.failure` event |
| Successful logins | Not logged | Audited as `authn.login.success` |
| Context | Username only | user_id, source_ip, request_id, outcome |
| Secrets | Password/token in the log | Redacted; never captured |
| Format | Free-text, per-developer | JSON, shared schema, UTC |
| Errors | Swallowed / "error" | Logged with detail, then rethrown |
| Injection | Raw input concatenated | CR/LF neutralized / encoder-escaped |
| Destination | Local file only | stdout → collector → central SIEM |
| Detection | None | Threshold alerts + escalation + runbook |

## What's Next?

- **[Overview](./overview.md)**: Understand the A9:2021 category and its lineage
- **[Attack Vectors](./attack-vectors.md)**: The undetected activity these examples defend against
- **[Prevention](./prevention.md)**: The six-layer defense these examples implement
- **[Lab](./lab/no-logging-lab/)**: Hands-on practice in a safe, isolated environment

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
