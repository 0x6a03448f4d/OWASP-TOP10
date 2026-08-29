# C9: Implement Security Logging and Monitoring - Code Examples

Each pair below shows an **insecure** approach—no security event, no context, or a leak—next to the **secure** version in the same technology: structured events with context, redaction, injection-safety, and an alertable signal. The final sections show the SIEM correlation and alert-routing configuration that turns those logs into detection.

## 1. Authentication Logging (Python / Flask)

### Insecure
```python
from flask import Flask, request
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)   # unstructured, local stdout only

@app.route("/api/session", methods=["POST"])
def login():
    user = request.json.get("username")
    pw   = request.json.get("password")
    if not check_password(user, pw):
        # No structured event, no context, no way to alert on a spike.
        # Worse: logs the password in cleartext, and concatenates raw input
        # (CRLF in `user` forges a fake log line).
        logging.info("login failed for " + user + " pw=" + pw)
        return {"error": "invalid"}, 401
    return {"token": issue_token(user)}
```

### Secure
```python
import logging, json, re, datetime, uuid
from flask import Flask, request, g

app = Flask(__name__)
_CTRL = re.compile(r"[\r\n\t\x00-\x1f\x7f]")

def safe(v):                                    # neutralize untrusted data
    return _CTRL.sub(" ", str(v))[:256]

class JsonFormatter(logging.Formatter):
    def format(self, r):
        base = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "level": r.levelname, "service": "auth-api", "env": "prod"}
        base.update(getattr(r, "sec", {}))      # structured fields only
        return json.dumps(base)

log = logging.getLogger("security")
h = logging.StreamHandler(); h.setFormatter(JsonFormatter())
log.addHandler(h); log.setLevel(logging.INFO)

@app.before_request
def trace():
    g.trace_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())

@app.route("/api/session", methods=["POST"])
def login():
    user = request.json.get("username")
    pw   = request.json.get("password")         # never logged
    if not check_password(user, pw):
        log.info("login failed", extra={"sec": {
            "event": "authn.login.failure", "outcome": "failure",
            "actor": {"user_name": safe(user), "src_ip": request.remote_addr,
                      "ua": safe(request.headers.get("User-Agent", ""))},
            "target": {"resource": "/api/session", "method": "POST"},
            "reason": "invalid_credentials", "trace_id": g.trace_id}})
        return {"error": "invalid"}, 401
    log.info("login success", extra={"sec": {
        "event": "authn.login.success", "outcome": "success",
        "actor": {"user_name": safe(user), "src_ip": request.remote_addr},
        "trace_id": g.trace_id}})
    return {"token": issue_token(user)}
```

**What changed**: a real security event (`authn.login.failure`) with actor/target/outcome and a trace ID; the password is never logged; untrusted input is neutralised; the record is structured JSON a SIEM can count and alert on.

## 2. Access-Control Failure Logging (Node.js / Express)

### Insecure
```javascript
app.get("/api/invoices/:id", (req, res) => {
  const inv = db.getInvoice(req.params.id);
  if (inv.ownerId !== req.user.id) {
    // Silent denial. Enumeration of 1000s of IDs leaves no trace.
    return res.sendStatus(403);
  }
  res.json(inv);
});
```

### Secure
```javascript
const pino = require("pino");
const log = pino({ base: { service: "billing-api", env: "prod" },
                   redact: ["req.headers.authorization", "*.password", "*.token"],
                   timestamp: pino.stdTimeFunctions.isoTime });

app.use((req, res, next) => {         // correlation ID per request
  req.traceId = req.headers["x-request-id"] || crypto.randomUUID();
  next();
});

app.get("/api/invoices/:id", (req, res) => {
  const inv = db.getInvoice(req.params.id);
  if (!inv || inv.ownerId !== req.user.id) {
    log.warn({
      event: "authz.deny", outcome: "failure",
      actor: { userId: req.user.id, srcIp: req.ip },
      target: { type: "invoice", id: String(req.params.id) },
      traceId: req.traceId,
    }, "authorization denied");     // one actor + many denials = enumeration alert
    return res.sendStatus(403);
  }
  res.json(inv);
});
```

**What changed**: every authorization denial is logged with the actor and the exact target object, so a single user probing many invoice IDs becomes an obvious, alertable pattern. `pino`'s `redact` guarantees auth headers and secrets never reach the log.

## 3. Admin Action & Permission-Change Logging (Java / Spring Boot)

### Insecure
```java
@PatchMapping("/api/users/{id}/role")
public User changeRole(@PathVariable String id, @RequestBody RoleDto dto) {
    // A privilege escalation with no audit trail whatsoever.
    return userService.setRole(id, dto.getRole());
}
```

### Secure
```java
// logback-spring.xml uses net.logstash.logback.encoder.LogstashEncoder
// so every entry is structured JSON shipped to the pipeline.
private static final Logger audit = LoggerFactory.getLogger("security.audit");

@PatchMapping("/api/users/{id}/role")
public ResponseEntity<User> changeRole(@PathVariable String id,
                                       @RequestBody RoleDto dto,
                                       @AuthenticationPrincipal Principal actor,
                                       HttpServletRequest req) {
    String prev = userService.getRole(id);
    User updated = userService.setRole(id, dto.getRole());

    audit.atInfo()
        .addKeyValue("event", "admin.role.change")
        .addKeyValue("outcome", "success")
        .addKeyValue("actor_id", actor.getName())
        .addKeyValue("src_ip", req.getRemoteAddr())
        .addKeyValue("target_user", id)
        .addKeyValue("from_role", prev)
        .addKeyValue("to_role", dto.getRole())
        .addKeyValue("trace_id", MDC.get("traceId"))
        .log("role changed");        // self-grant to admin -> critical alert
    return ResponseEntity.ok(updated);
}
```

**What changed**: the sensitive administrative action is recorded with actor, target, and the before/after value. Correlation on `event="admin.role.change"` where `to_role="admin"` and `actor_id == target_user` is a high-severity self-escalation alert.

## 4. High-Value Transaction & Exfiltration Signal (Python)

### Insecure
```python
@app.route("/api/export")
def export():
    rows = db.export(request.args.get("table"))
    return jsonify(rows)          # no record of who exported how much
```

### Secure
```python
@app.route("/api/export")
def export():
    table = safe(request.args.get("table"))
    rows  = db.export(table)
    log.info("data export", extra={"sec": {
        "event": "data.export", "outcome": "success",
        "actor": {"user_id": g.user_id, "src_ip": request.remote_addr},
        "target": {"table": table}, "row_count": len(rows),
        "trace_id": g.trace_id}})   # baseline row_count -> alert on anomalies
    return jsonify(rows)
```

**What changed**: exports now carry a `row_count` that can be baselined per user. A pull 20x above an actor's norm, or a bulk export at 3am, becomes a detectable exfiltration signal instead of an invisible event.

## 5. SIEM Correlation Rules

Structured events make detection a query. These example rules (Sigma-style pseudocode) run in the SIEM over the centralized stream and encode a baseline-relative threshold to keep them actionable.

```yaml
# Credential stuffing: failure spike across many accounts from few sources
title: Credential Stuffing - Auth Failure Spike
detection:
  selection:
    event: "authn.login.failure"
  timeframe: 5m
  condition: selection | count() by actor.src_ip > 100
             and distinct(actor.user_name) > 20
level: high

---
# Access-control enumeration: one actor, many denials across distinct objects
title: BOLA/IDOR Enumeration - Authorization Denials
detection:
  selection:
    event: "authz.deny"
  timeframe: 10m
  condition: selection | distinct(target.id) by actor.userId > 25
level: high

---
# Privilege self-escalation: actor grants themselves admin
title: Privilege Escalation - Self-Grant to Admin
detection:
  selection:
    event: "admin.role.change"
    to_role: "admin"
  condition: selection | where actor_id == target_user
level: critical
```

## 6. Alert Routing (fight alert fatigue)

Tuned routing sends only high-fidelity, actionable alerts to a human, and deduplicates the rest. Severity—not volume—decides who gets paged.

```yaml
# Alertmanager-style config
route:
  receiver: soc-dashboard            # default: visible, not noisy
  group_by: ['alertname', 'actor']   # collapse duplicates
  group_wait: 30s
  routes:
    - matchers: ['severity="critical"']   # self-escalation, log tampering, ATO
      receiver: pagerduty
      continue: false
    - matchers: ['severity="high"']       # stuffing, enumeration
      receiver: soc-ticket

inhibit_rules:                       # suppress noise that would bury real alerts
  - source_matchers: ['alertname="ServiceDown"']
    target_matchers: ['alertname="LogGap"']

receivers:
  - name: pagerduty
    pagerduty_configs: [{ severity: critical }]
  - name: soc-ticket
  - name: soc-dashboard
```

## 7. Log-Gap & Integrity Monitoring

Silence is a signal. If a service stops shipping logs, or an integrity check fails, alert—an attacker's first move is often to disable logging.

```yaml
# Alert if a service that normally logs goes quiet (possible tampering/outage)
title: Log Gap - Service Stopped Reporting
detection:
  selection:
    service: "auth-api"
  timeframe: 10m
  condition: selection | count() == 0     # expected steady stream, now silent
level: critical
```

## What Changed, and Why

| Concern | Insecure | Secure |
|---------|----------|--------|
| Event coverage | Only crashes; silent denials | Authn, authz, admin, high-value txns logged |
| Context | "login failed for X" | who/what/when/where + trace ID |
| Format | Free-text string | Consistent structured JSON |
| Secrets/PII | Password logged in cleartext | Redacted/masked at the boundary |
| Log injection | Raw input concatenated | Structured fields + neutralised values |
| Detection | Nothing to alert on | SIEM rules + tuned, severity-routed alerts |

## Next Steps

- **[How to Implement](prevention.md)**: The full logging, monitoring, and response pipeline
- **[Threats Addressed](attack-vectors.md)**: What these logs let you catch
- **[Overview](overview.md)**: What the control is and why it matters
- **[Proactive Controls](/learn/proactive)**: Return to the full OWASP Proactive Controls catalog
- **[Practice](/practice)**: Apply the control in hands-on exercises
