# Insufficient Logging & Monitoring - Examples

Each example pairs a **vulnerable** implementation (a real detection gap) with a **secure** one that generates a structured, correlatable security event. The goal is always the same: an event that answers *who, what, when, where, and outcome*, shipped somewhere an attacker cannot erase it.

## Table of Contents
- [1. Authentication Logging (Python / Flask)](#py-auth)
- [2. Access-Control Denials (Python / Flask)](#py-authz)
- [3. Structured Security Logging (Node.js)](#node-struct)
- [4. High-Value Action Audit Trail (Java)](#java-audit)
- [5. Preventing Log Injection](#log-injection)
- [6. Never Logging Secrets](#no-secrets)
- [7. Threshold Alerting for Slow Attacks](#alerting)
- [8. Shipping to a SIEM + Detection Rules](#siem)
- [Summary](#summary)

## 1. Authentication Logging (Python / Flask)

### Vulnerable: No Logging

```python
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    if check_password(username, password):
        session["user"] = username
        return "OK"
    return "Failed", 401
# Nothing is recorded. A brute force or credential-stuffing campaign is
# completely invisible: no failure count, no source IP, no trail at all.
```

### Secure: Structured Auth Events

```python
import logging, json, datetime

security_log = logging.getLogger("security")   # routed to its own file/handler

def audit(event, outcome, request, actor=None, **extra):
    security_log.info(json.dumps({
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event, "outcome": outcome,
        "actor": actor or "anonymous",
        "src_ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "request_id": request.headers.get("X-Request-ID", ""),
        **extra,
    }))

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    if check_password(username, request.form["password"]):
        audit("auth.login.success", "success", request, actor=username)
        session["user"] = username
        return "OK"
    audit("auth.login.failure", "failure", request,
          actor=username, reason="bad_password")
    return "Failed", 401

# Emitted event (one line of newline-delimited JSON):
# {"ts":"2026-08-28T14:03:22.481Z","event":"auth.login.failure",
#  "outcome":"failure","actor":"alice","src_ip":"203.0.113.44",
#  "user_agent":"curl/8.4","request_id":"7f3c9a2e","reason":"bad_password"}
```

## 2. Access-Control Denials (Python / Flask)

Authorization failures (HTTP 403) are the single highest-signal security event — a burst of them is 403-walking. They are also the most commonly forgotten.

### Vulnerable: Silent Denial

```python
@app.route("/admin/export")
def admin_export():
    if not current_user.is_admin:
        return "Forbidden", 403      # denied, but no record of who probed
    return export_all_users()
```

### Secure: Every Denial Logged

```python
@app.route("/admin/export")
def admin_export():
    if not current_user.is_admin:
        audit("authz.denied", "denied", request,
              actor=current_user.name, resource="/admin/export")
        return "Forbidden", 403
    audit("data.export", "success", request,
          actor=current_user.name, resource="all_users", record_count=count_users())
    return export_all_users()
# Now a scan of /admin/* produces a stream of authz.denied events from one
# source -- exactly the pattern an alert rule can catch (see section 7).
```

## 3. Structured Security Logging (Node.js)

### Vulnerable: console.log Free Text

```javascript
app.post("/login", (req, res) => {
  if (authenticate(req.body.user, req.body.pass)) {
    return res.send("ok");
  }
  console.log("login failed for " + req.body.user);   // un-parseable, no IP
  res.status(401).send("no");
});
```

### Secure: pino JSON Logger

```javascript
const pino = require("pino");
const log = pino({ base: { service: "web-api" }, timestamp: pino.stdTimeFunctions.isoTime });

function ctx(req) {
  return { src_ip: req.ip, request_id: req.id,
           user_agent: req.headers["user-agent"] };
}

app.post("/login", (req, res) => {
  if (authenticate(req.body.user, req.body.pass)) {
    log.info({ event: "auth.login.success", outcome: "success",
               actor: req.body.user, ...ctx(req) });
    return res.send("ok");
  }
  log.warn({ event: "auth.login.failure", outcome: "failure",
             actor: req.body.user, reason: "bad_password", ...ctx(req) });
  res.status(401).send("no");
});
// pino emits newline-delimited JSON on stdout -- ideal for shipping to a SIEM.
```

## 4. High-Value Action Audit Trail (Java)

Money movement, role changes, and data deletion need an audit trail with **before/after** state and the acting principal — so a rogue admin created during an intrusion is visible on review.

### Vulnerable: No Audit

```java
public void changeRole(User target, Role newRole) {
    target.setRole(newRole);
    repository.save(target);   // who did this? from what? to what? unknown
}
```

### Secure: SLF4J Structured Audit

```java
private static final Logger audit = LoggerFactory.getLogger("security.audit");

public void changeRole(User actor, User target, Role newRole) {
    Role previous = target.getRole();
    target.setRole(newRole);
    repository.save(target);

    audit.info("event=account.role.change outcome=success "
        + "actor={} target={} from={} to={} src_ip={} request_id={}",
        actor.getUsername(), target.getUsername(),
        previous, newRole, RequestContext.ip(), RequestContext.requestId());
}
// Logback can render this as JSON (logstash-logback-encoder) for the SIEM.
// A grant of role=ADMIN now triggers the high-severity rule in section 8.
```

## 5. Preventing Log Injection

User-controlled data written into a line-oriented log unescaped lets an attacker forge entries with embedded newlines (CWE-117).

### Vulnerable: Raw Concatenation

```python
# username = "attacker\n2026-08-28 09:00:00 INFO Login success: user=admin"
logger.info("Login failed: user=" + username)
# The attacker's newline injects a second, forged "success" line.
```

### Secure: Neutralise, or Emit JSON

```python
import re
_CONTROL = re.compile(r"[\r\n\t\x00-\x1f\x7f]")
def clean(v): return _CONTROL.sub(" ", str(v))

audit("auth.login.failure", "failure", request, actor=clean(username))
# Better: JSON encoding escapes newlines inside a value as \n, so the
# attacker's payload can never break out into its own log line.
```

## 6. Never Logging Secrets

### Vulnerable: Logging the Whole Request

```python
logger.info("Password change request: " + str(request.form))
# Leaks the plaintext password/token into the log store (CWE-532) --
# the log itself becomes the breach.
```

### Secure: Allow-List / Redact

```python
SENSITIVE = {"password", "pass", "token", "authorization",
             "card", "cvv", "ssn", "secret", "api_key"}

def redact(d):
    return {k: ("[REDACTED]" if k.lower() in SENSITIVE else v) for k, v in d.items()}

audit("account.password.change", "success", request,
      actor=current_user.name, fields=list(redact(request.form).keys()))
# Records THAT a password changed and WHICH fields were sent -- never the value.
```

## 7. Threshold Alerting for Slow Attacks

Logging each failure is necessary but not sufficient; aggregation over a window turns an invisible trickle into a visible attack.

```python
from collections import defaultdict
from datetime import datetime, timedelta, timezone

_fails = defaultdict(list)

def note_failure(user, ip, request):
    now = datetime.now(timezone.utc)
    window = now - timedelta(minutes=15)      # long window catches low-and-slow
    _fails[user] = [t for t in _fails[user] if t > window] + [now]
    if len(_fails[user]) >= 10:
        audit("auth.bruteforce.detected", "failure", request,
              actor=user, count=len(_fails[user]))
        send_alert(f"Sustained login failures for {user} from {ip}")

# Also alert on the DISTRIBUTED shape: many distinct accounts succeeding from
# never-before-seen IPs in a short window == credential stuffing.
```

## 8. Shipping to a SIEM + Detection Rules

### Forward Structured Logs Off-Box (Filebeat)

```yaml
# filebeat.yml -- parse the app's NDJSON and ship it encrypted to the SIEM
filebeat.inputs:
  - type: filestream
    paths: ["/var/log/app/security.json"]
    parsers:
      - ndjson: { target: "", add_error_key: true }
output.logstash:
  hosts: ["siem-ingest.internal:5044"]
  ssl.certificate_authorities: ["/etc/pki/ca.crt"]
```

### Detection Rules (SIEM pseudo-DSL)

```
rule "authz_denial_burst":          # 403-walking / forced browsing
  when count(event="authz.denied") group_by(src_ip) over 5m > 15
  then alert(severity="medium")

rule "distributed_stuffing":        # many accounts, new IPs, few tries each
  when count(event="auth.login.success") group_by(src_ip is new) over 10m
       across > 20 distinct actors
  then alert(severity="high")

rule "privilege_grant":             # any admin/superuser grant is high-signal
  when event="account.role.change" and to in ("ADMIN","superuser")
  then alert(severity="high")

rule "log_source_silent":           # monitor the monitoring
  when no_events(service="web-api") over 10m
  then alert(severity="high", note="log source stopped -- possible blinding")
```

> The last rule is easy to forget and vital: a log source that goes *silent* is itself a signal. Attackers who cannot erase off-box logs will try to stop them being produced.

## Summary

| Anti-pattern (vulnerable) | Secure practice |
|---|---|
| No logging on auth / authz paths | Structured events for every login, logout, and 403 denial |
| Free-text `console.log` / print | JSON/key=value with a consistent schema across services |
| No context (just "login failed") | who / what / when / where / outcome on every entry |
| High-value actions unrecorded | Audit trail with actor and before/after state |
| User input concatenated into logs | Neutralise control chars / emit JSON (stop log injection) |
| Secrets and full request bodies logged | Allow-list and redact; never log passwords/tokens/PAN |
| Events logged but never watched | Real-time alerts on tuned thresholds for slow/distributed attacks |
| Logs only on the local, editable host | Ship off-box to append-only SIEM; monitor the pipeline itself |

## Next Steps

- **[Overview](./overview.html)**: Concepts, business impact, and self-assessment.
- **[Attack Vectors](./attack-vectors.html)**: The undetected attacks these logs are designed to reveal.
- **[Prevention](./prevention.html)**: The full layered defence, from generation to response.
- **[Hands-On Lab](./lab/insufficient-logging-monitoring/)**: Instrument a vulnerable app and catch an attack in a safe environment.

*Edition note: This is A10:2017, which became A09:2021 – Security Logging and Monitoring Failures in the 2021 edition. This lesson keeps the 2017 framing.*
