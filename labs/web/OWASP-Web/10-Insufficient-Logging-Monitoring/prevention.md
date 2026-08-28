# Insufficient Logging & Monitoring - Prevention

## Table of Contents
- [Defence Strategy: Fix the Whole Pipeline](#strategy)
- [1. Log the Right Security Events, With Context](#log-events)
- [2. Use a Structured, Consistent Format](#structured)
- [3. Never Log Secrets or Sensitive Data](#no-secrets)
- [4. Prevent Log Injection and Forging](#log-injection)
- [5. Centralise and Ship Off-Box (SIEM)](#centralize)
- [6. Make Logs Tamper-Resistant and Append-Only](#tamper)
- [7. Alert in Real Time on Tuned Thresholds](#alerting)
- [8. Synchronise Time and Set Retention](#time-retention)
- [9. Have an Incident-Response Process](#response)
- [10. Monitor the Monitoring](#monitor-monitoring)
- [Implementation Checklist](#checklist)

## Defence Strategy: Fix the Whole Pipeline

Because detection is a pipeline — **generate → collect → detect → respond** — a defence that fixes only one stage fixes nothing. Volume of logs is not the goal; a closed loop from event to action is. The layers below map onto the pipeline: layers 1–4 make events *generate* correctly, 5–6 make them *collect* reliably and survive tampering, 7 makes them *detect*, and 9–10 make the organisation *respond*.

```
GENERATE   log the right events, with context, structured, no secrets
   |
COLLECT    ship off-box to central, append-only storage in near real time
   |
DETECT     correlate and alert on tuned thresholds and patterns
   |
RESPOND    an owned, documented process triages and escalates every alert
   |
ASSURE     monitor the pipeline itself so a silent failure is caught
```

## 1. Log the Right Security Events, With Context

The application is the only layer that understands security *meaning* — that a login failed for `alice`, that a 403 was an admin-page probe, that a transfer was high-value. Log these deliberately, and make every entry answer **who, what, when, where, and outcome**.

Events that must be logged:

- **Authentication**: successful and failed logins, logout, password change, MFA challenge, account lockout.
- **Access control**: every authorization denial (403), admin-function access, privilege/role changes.
- **Input validation**: server-side validation failures (early signal of injection/traversal probing).
- **High-value actions**: money movement, data export/delete, role/permission grants, API-key issuance — with before/after state.
- **Session & account lifecycle**: session creation/reuse, token issuance, account creation, email/phone changes, recovery flows.

```python
# Python -- a small helper that guarantees consistent security context
import logging, json, datetime

security_log = logging.getLogger("security")

def log_security_event(event, outcome, request, actor=None, **extra):
    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event,                       # e.g. auth.login.failure
        "outcome": outcome,                   # allowed | denied | success | failure
        "actor": actor or "anonymous",
        "src_ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "request_id": request.headers.get("X-Request-ID", ""),
        **extra,
    }
    security_log.info(json.dumps(entry))

# Usage at the point where the security decision is made:
@app.post("/login")
def login():
    user = request.form.get("username")
    if authenticate(user, request.form.get("password")):
        log_security_event("auth.login.success", "success", request, actor=user)
        return "ok"
    log_security_event("auth.login.failure", "failure", request,
                       actor=user, reason="bad_password")
    return "invalid credentials", 401

@app.post("/admin/delete")
def admin_delete():
    if not current_user.is_admin:
        log_security_event("authz.denied", "denied", request,
                           actor=current_user.name, resource="/admin/delete")
        return "forbidden", 403
    ...
```

## 2. Use a Structured, Consistent Format

Free-text logs (`"Login failed"`) cannot be counted, correlated, or alerted on. Emit **structured** events (JSON or strict key=value) with a consistent schema across every service, so a SIEM can query `event=auth.login.failure` across the whole estate.

```
BAD  (free text, un-parseable, no context):
  Login failed

GOOD (structured, one schema everywhere):
  {"ts":"2026-08-28T14:03:22.481Z","event":"auth.login.failure",
   "outcome":"failure","actor":"alice","src_ip":"203.0.113.44",
   "user_agent":"curl/8.4","request_id":"7f3c9a2e","reason":"bad_password"}
```

```javascript
// Node.js -- structured logging with pino
const pino = require("pino");
const log = pino({ base: { service: "web-api" } });

app.post("/login", (req, res) => {
  const ctx = { src_ip: req.ip, request_id: req.id,
                user_agent: req.headers["user-agent"] };
  if (authenticate(req.body.user, req.body.pass)) {
    log.info({ event: "auth.login.success", outcome: "success",
               actor: req.body.user, ...ctx });
    return res.send("ok");
  }
  log.warn({ event: "auth.login.failure", outcome: "failure",
             actor: req.body.user, reason: "bad_password", ...ctx });
  res.status(401).send("invalid credentials");
});
```

## 3. Never Log Secrets or Sensitive Data

Logging *too much of the wrong thing* is its own breach. Passwords, session tokens, API keys, full card numbers (PAN), and unnecessary PII must never reach the log store — doing so turns logs into a high-value target and can itself violate PCI-DSS/GDPR (CWE-532). Log security *context*, not sensitive payloads.

```python
# Redact/allow-list before emitting. Never log the raw request body.
SENSITIVE = {"password", "pass", "token", "authorization",
             "card", "cvv", "ssn", "secret", "api_key"}

def safe_fields(data: dict) -> dict:
    return {k: ("[REDACTED]" if k.lower() in SENSITIVE else v)
            for k, v in data.items()}

log_security_event("account.update", "success", request,
                   actor=user, changed=list(safe_fields(request.form).keys()))
# Log WHICH fields changed, never their sensitive values.
```

> Rule of thumb: if leaking a field would itself be a breach, it does not belong in a log line. Mask all but the last four digits of identifiers, and hash values you only need to correlate.

## 4. Prevent Log Injection and Forging

If untrusted input is written into a line-oriented log unescaped, an attacker can embed newlines and forge entries (CWE-117). Neutralise control characters, and prefer structured logging where the framework encodes field values for you.

```python
# Strip/encode CR, LF, and other control chars from any user-supplied value
import re
_CONTROL = re.compile(r"[\r\n\t\x00-\x1f\x7f]")

def clean(value: str) -> str:
    return _CONTROL.sub(" ", str(value))

# Safer still: emit JSON so newlines inside a value are escaped as \n
# and can never break out into a new log line.
log_security_event("auth.login.failure", "failure", request,
                   actor=clean(request.form.get("username", "")))
```

## 5. Centralise and Ship Off-Box (SIEM)

Logs that stay on the machine that generated them die with that machine — rotated away, or deleted by the attacker who compromised it. Ship every security event to a central store (ELK/OpenSearch, Splunk, Loki, or a managed SIEM) in near real time, where it can be correlated across services.

```yaml
# Filebeat -> Logstash/OpenSearch: forward the app's structured log off-box
# filebeat.yml
filebeat.inputs:
  - type: filestream
    paths: ["/var/log/app/security.json"]
    parsers:
      - ndjson: { target: "", overwrite_keys: true }
output.logstash:
  hosts: ["siem-ingest.internal:5044"]
  ssl.certificate_authorities: ["/etc/pki/ca.crt"]   # encrypt in transit
```

Centralisation is what makes lateral-movement and distributed-attack detection possible: only a store that sees *all* services can spot one identity suddenly touching many of them.

## 6. Make Logs Tamper-Resistant and Append-Only

Assume the attacker reaches the host. Logs must survive that:

- Ship off-box *immediately*, so a copy exists before an attacker can act.
- Store centrally as **append-only**, with write-once/immutable retention (e.g. object-lock/WORM buckets).
- Restrict who can read and administer the log store with least privilege — log admins should not be the same accounts being monitored.
- Optionally sign or hash-chain entries so tampering is detectable.

```bash
# Example: object storage with immutability (write-once-read-many)
aws s3api put-object-lock-configuration --bucket security-logs \
  --object-lock-configuration \
  'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=COMPLIANCE,Days=365}}'
# COMPLIANCE mode: not even the root account can delete before expiry.
```

## 7. Alert in Real Time on Tuned Thresholds

Collection without detection is just storage. Define rules that fire on the attack *patterns* — not just single events — and tune thresholds to catch the slow, distributed activity that naive counters miss.

```
# Elastic/OpenSearch detection-rule sketch (pseudo-DSL)
rule "distributed_credential_stuffing":
  when   count(event="auth.login.success") group_by(src_ip is new)
         over 10m > 20 distinct actors
  then   alert(severity="high", channel="soc-oncall")

rule "authz_denial_burst":               # 403-walking / forced browsing
  when   count(event="authz.denied") group_by(src_ip) over 5m > 15
  then   alert(severity="medium", channel="soc-oncall")

rule "privilege_change":                 # any admin/role grant is high-signal
  when   event="account.role.change" and new_role in ("admin","superuser")
  then   alert(severity="high", channel="soc-oncall")
```

```python
# Application-side aggregation for slow brute force (per-account window)
from collections import defaultdict
from datetime import datetime, timedelta, timezone

_failures = defaultdict(list)

def note_login_failure(user, ip):
    now = datetime.now(timezone.utc)
    window = now - timedelta(minutes=15)
    _failures[user] = [t for t in _failures[user] if t > window] + [now]
    if len(_failures[user]) >= 10:
        log_security_event("auth.bruteforce.detected", "failure",
                           request, actor=user, count=len(_failures[user]))
        raise_alert(f"Sustained login failures for {user} from {ip}")
```

**Tune to reduce noise**: an alert that is muted for crying wolf detects nothing. Track false-positive rates, escalate by severity, and route each alert to an owner.

## 8. Synchronise Time and Set Retention

- **Time sync**: run NTP on every host and log timestamps in **UTC / ISO 8601**. Without synchronised clocks you cannot build a forensic timeline across servers.
- **Retention**: keep security logs long enough to cover realistic dwell times — often **one year or more**, and per any regulatory requirement (PCI-DSS Requirement 10 mandates audit trails and retention). Logs rotated away after a few days are useless when a breach is found months later.

```
# Consistent, sortable, timezone-explicit timestamps everywhere
2026-08-28T14:03:22.481Z   # UTC, ISO 8601 -- correlatable across services
# NOT: "Aug 28 09:03:22"    # local, ambiguous, un-sortable across zones
```

## 9. Have an Incident-Response Process

The Target-class lesson is blunt: alerts *fired* and were *ignored*. Detection is only real when a defined process turns a signal into action. Every alert needs an **owner**, a **runbook**, and an **escalation path** with time targets.

- **Ownership**: an on-call rotation receives high-severity alerts 24/7.
- **Runbooks**: documented triage steps per alert type (verify, contain, escalate).
- **Escalation & SLAs**: defined time-to-acknowledge and time-to-respond, tested with drills.
- **Preserve evidence**: capture and protect logs before remediation destroys them.

> Align to a recognised framework (e.g. NIST SP 800-61): *Prepare → Detect & Analyse → Contain, Eradicate & Recover → Post-Incident*. Rehearse it — an untested plan fails under pressure.

## 10. Monitor the Monitoring

Detection controls that silently stop working are as dangerous as never having them (the expired-certificate class of failure). Treat the pipeline itself as a monitored asset:

- Heartbeat checks: alert if a service *stops* sending logs (silence is a signal).
- Watch log-shipper health, ingestion lag, disk pressure, and dropped events.
- Track expiry of certificates and credentials the pipeline depends on.
- Periodically fire a synthetic security event and assert it reaches the SIEM and alerts.

## Implementation Checklist

| Layer | Control | Done when… |
|---|---|---|
| Generate | Log auth, authz-denials, validation failures, high-value actions | Every security decision emits an event with who/what/when/where/outcome |
| Generate | Structured, consistent schema | SIEM can query one event name across all services |
| Generate | No secrets in logs; input neutralised | Passwords/tokens/PAN never appear; newlines can't forge entries |
| Collect | Ship off-box to central store | Logs exist somewhere the app host cannot edit |
| Collect | Append-only / immutable retention | An attacker on the host cannot erase the record |
| Detect | Real-time alerts on tuned thresholds | Slow brute force, stuffing, 403-bursts, priv-changes all alert |
| Detect | Time-sync + retention policy | UTC/ISO 8601 everywhere; logs kept 1yr+ / per regulation |
| Respond | Owned IR process with runbooks + SLAs | Every high-severity alert reaches a person who acts, in a set time |
| Assure | Monitor the pipeline itself | A stopped log source or expired cert raises its own alert |

## Next Steps

- **[Examples](./examples.html)**: Vulnerable vs. secure logging in Python, Node, and Java, plus SIEM/alerting config.
- **[Attack Vectors](./attack-vectors.html)**: The undetected attacks these defences are designed to surface.
- **[Overview](./overview.html)**: Concepts, business impact, and self-assessment.
- **[Hands-On Lab](./lab/insufficient-logging-monitoring/)**: Add logging, alerting, and response to a vulnerable app.

*Edition note: This is A10:2017. In the OWASP Top 10 2021 it became A09:2021 – Security Logging and Monitoring Failures. This lesson keeps the 2017 framing.*
