# C9: Implement Security Logging and Monitoring - How to Implement

## How to Implement This Control

Implementing security logging and monitoring is building a **pipeline**, not adding a library. The stages below map one-to-one onto the pipeline from the overview: decide what to log, log it with context in a structured format, protect and centralise it, monitor and alert on it, and wire it into a tested response process. Skipping any stage breaks the chain.

### Implementation Principles

- **Log the right events, not all events**: coverage of security-relevant events beats volume; volume without monitoring is just cost and alert fatigue.
- **Context by default**: every security event carries who/what/when/where plus a correlation ID—make it structurally impossible to log an event without them.
- **Detection is the goal**: logging exists to feed monitoring, alerting, and response. If it does not end in an action, it is not the control.
- **Treat logs as a disclosure surface**: redact secrets and PII, and neutralise untrusted data, at the logging boundary.

## 1. Decide What to Log

Start from a documented list of security-relevant events so coverage is deliberate, not accidental:

| Category | Events to log |
|----------|---------------|
| Authentication | Login success/failure, logout, MFA challenge/failure, password reset, token issue/refresh/revoke |
| Access control | Every authorization denial, with actor and target object |
| Input validation | Rejected inputs, schema violations, WAF/deny events, injection-pattern hits |
| High-value transactions | Payments, transfers, order placement, data exports/downloads (with volume) |
| Administrative actions | User CRUD, role/permission changes, config changes, feature-flag changes |
| Identity & permission changes | Grants, revocations, group membership, credential/key rotation |
| Integrity events | Log-service start/stop, logging config changes, integrity-check failures |

> Write this list down as a logging standard. "Auditable events are not logged" is the first item in the A09 failure category—an explicit standard is what closes it.

## 2. Emit Structured Logs with Full Context

Use a structured logger and a shared schema so every service emits the same machine-parseable shape. Bind context (actor, trace ID) once per request rather than passing it to every call.

```python
# Python — structured logging with a consistent schema
import logging, json, datetime

class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": record.levelname,
            "event": record.__dict__.get("event"),
            "outcome": record.__dict__.get("outcome"),
            "actor": record.__dict__.get("actor"),
            "target": record.__dict__.get("target"),
            "trace_id": record.__dict__.get("trace_id"),
            "service": "auth-api",
            "env": "prod",
            "message": record.getMessage(),
        }
        return json.dumps({k: v for k, v in payload.items() if v is not None})

log = logging.getLogger("security")
handler = logging.StreamHandler()          # stdout -> collected by the platform
handler.setFormatter(JsonFormatter())
log.addHandler(handler)
log.setLevel(logging.INFO)

def log_authn_failure(user_id, src_ip, trace_id, reason):
    log.info("login failed", extra={
        "event": "authn.login.failure", "outcome": "failure",
        "actor": {"user_id": user_id, "src_ip": src_ip},
        "target": {"resource": "/api/session", "method": "POST"},
        "trace_id": trace_id, "reason": reason,
    })
```

Generate a correlation/trace ID at the edge (or accept an inbound one), attach it to every log line for that request, and propagate it to downstream services so a single operation is traceable end-to-end.

## 3. Prevent Log Injection

Never build log lines by concatenating untrusted input. Prefer structured fields (the value is a JSON string, so newlines are escaped), and additionally neutralise control characters for any value that reaches a text sink.

```python
# Neutralize untrusted data before it is logged
import re
_CTRL = re.compile(r"[\r\n\t\x00-\x1f\x7f]")

def safe(value: str) -> str:
    # Strip CR/LF and control chars so an attacker cannot forge log lines
    return _CTRL.sub(" ", str(value))[:256]

# BAD:  log.info("login user=" + username)          # CRLF -> forged entry
# GOOD: structured field + neutralized value
log.info("login attempt", extra={"actor": {"user_name": safe(username)}})
```

> Structured logging is the strongest defence: because each field is serialised as a JSON string, embedded newlines cannot start a new record. Neutralisation is defence in depth for anything that is later rendered as plain text.

## 4. Never Log Secrets or PII in Cleartext

Redact at the boundary so sensitive values cannot reach the log store even by accident. Maintain a deny-list of field names and mask them centrally.

```python
# Redact sensitive fields before any log write
REDACT = {"password", "pass", "token", "authorization", "cookie",
          "ssn", "card", "cvv", "secret", "api_key"}

def redact(obj):
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if k.lower() in REDACT else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj

log.info("request received", extra={"body": redact(request_body)})
```

Rules of thumb: never log full passwords, session tokens, API keys, authorization headers, full card numbers (PAN), or more PII than an investigation genuinely needs. Where an identifier is required, log a hashed or truncated form.

## 5. Ship Logs Off-Host and Centralize

Local disk is where evidence goes to be deleted. Forward logs in near-real time to a central SIEM or log-management platform, so they survive host compromise and can be correlated across services.

```yaml
# Filebeat -> central pipeline (excerpt)
filebeat.inputs:
  - type: container
    paths: ["/var/log/containers/*.log"]
output.logstash:
  hosts: ["logpipe.internal:5044"]
  ssl.enabled: true            # encrypt logs in transit

# The application only writes structured JSON to stdout;
# the platform (not the app) handles shipping and buffering.
```

Aggregate everything—app, proxy, host, cloud audit (e.g. CloudTrail), identity provider—into one place so correlation across sources is possible.

## 6. Protect Log Integrity and Set Retention

- **Append-only / write-once**: use storage that cannot be edited in place (e.g. object storage with object-lock/immutability, or an append-only index). The service account that writes logs must not be able to delete them.
- **Integrity verification**: hash or sign batches so tampering is detectable; alert on integrity-check failures and on unexpected log gaps.
- **Access control**: restrict who can read logs (they contain sensitive context) and who can administer the pipeline.
- **Retention**: keep security logs long enough for investigation and compliance (commonly months to a year or more, per your regulatory obligations), then expire them on a defined schedule.

```bash
# Example: S3 bucket for logs with Object Lock (immutability) + lifecycle
aws s3api put-object-lock-configuration --bucket sec-logs \
  --object-lock-configuration 'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=COMPLIANCE,Days=365}}'
# Writer role: s3:PutObject only. No s3:DeleteObject, no lock bypass.
```

## 7. Synchronize Time (NTP)

Correlation and legal timelines require every clock to agree. Synchronise all hosts to a trusted time source and log timestamps in UTC with an explicit offset.

```bash
# Ensure NTP/chrony is enabled and healthy on every host
timedatectl set-ntp true
chronyc tracking          # verify offset is within a few milliseconds
# Log timestamps in UTC, ISO-8601, e.g. 2026-08-29T14:03:11.482Z
```

## 8. Monitor: Centralize, Baseline, Correlate

Ingest the centralized logs into a SIEM and build detections on top. First establish a **baseline** of normal behaviour—typical login rates, export volumes, geographies, admin-action frequency—then flag deviations.

```
# Example detection logic (pseudocode over the log stream)
# Credential stuffing: many auth failures across many accounts from few IPs
alert if count(event="authn.login.failure") by src_ip
        over 5m > baseline_p99 * 3

# Access-control enumeration: one actor, many denials across distinct objects
alert if distinct(target.id where event="authz.deny") by actor.user_id
        over 10m > 25

# Exfiltration: export volume far above the actor's norm
alert if sum(export.rows) by actor.user_id
        over 1h > actor_baseline * 20
```

Correlate across sources: an authn-failure spike *followed by* a success *followed by* a privilege change from the same actor is a far stronger signal than any single event.

## 9. Alert: Tuned, Actionable, Real-Time

Alerting is where most programs fail—either no thresholds, or so many alerts that responders tune them out. Build alerts that a human can act on:

- **Actionable**: each alert states what happened, who/where, severity, and the first response step. Link to the relevant logs.
- **Tuned thresholds**: set thresholds from the baseline, not guesses; suppress and deduplicate to fight **alert fatigue**.
- **Prioritised routing**: severity decides the channel—dashboard vs. ticket vs. page. Not everything wakes someone at 3am.
- **Real-time for the urgent**: account takeover and privilege escalation alert immediately; slow-burn trends can be reviewed on a schedule.

```yaml
# Alertmanager-style routing: severity decides urgency
route:
  receiver: dashboard
  routes:
    - matchers: ['severity="critical"']   # ATO, priv-esc, log tampering
      receiver: pagerduty
    - matchers: ['severity="high"']
      receiver: soc-ticket
inhibit_rules:                             # deduplicate to reduce fatigue
  - source_matchers: ['alert="host_down"']
    target_matchers: ['alert="log_gap"']
```

## 10. Integrate with Incident Response

Detection only matters if it triggers action. Wire alerts into a documented incident-response plan:

- Each alert type maps to a **playbook** with an owner, escalation path, and containment steps.
- The correlation/trace ID in the alert lets responders pull the full request chain instantly.
- Define severities and SLAs so response time matches impact.
- Run post-incident reviews and feed lessons back into detections and thresholds.

## 11. Test That Detection Works

An untested alert is an assumption. Prove the pipeline fires:

- **Pentests and scans should trigger alerts**—if a red-team run produces no signal, that is a finding, not a pass.
- **Detection engineering**: use adversary-emulation exercises (purple teaming) to verify each detection actually fires on the technique it targets.
- **Synthetic events**: periodically inject benign test events to confirm the pipeline (ship -> ingest -> alert -> route) is healthy end-to-end.
- **Log-gap monitoring**: alert if a service stops sending logs—silence can mean an outage or an attacker.

## Implementation Checklist

- [ ] A documented list of security-relevant events exists and is implemented.
- [ ] Every security event is logged with who/what/when/where + a correlation ID.
- [ ] Logs are structured (e.g. JSON) with a consistent, documented schema.
- [ ] Untrusted data is neutralised (no log injection); structured fields are used.
- [ ] Secrets and PII are redacted/masked at the logging boundary.
- [ ] Logs are shipped off-host in near-real time to a central SIEM/log platform.
- [ ] Storage is append-only/immutable, integrity-protected, and access-controlled.
- [ ] Retention meets investigation and compliance needs, with a defined expiry.
- [ ] All clocks are NTP-synchronised; timestamps are UTC/ISO-8601.
- [ ] A baseline of normal behaviour exists; anomalies are detected.
- [ ] Alerts are tuned, actionable, deduplicated, and severity-routed.
- [ ] Alerts feed a documented, owned incident-response playbook.
- [ ] Detection is tested—pentests/red-team exercises trigger alerts.
- [ ] Log-gap and integrity-failure monitoring is in place.

## Key Takeaways

1. **Instrument the right events with context**—coverage and who/what/when/where + trace ID make logs useful.
2. **Structure, redact, and neutralise**—machine-parseable records, no secrets/PII, no log injection.
3. **Centralize, protect, and time-sync**—off-host, append-only storage on synchronised clocks survives attackers.
4. **Monitor against a baseline and alert with discipline**—tuned, actionable alerts beat a firehose.
5. **Close the loop and test it**—alerts feed a rehearsed response, and pentests prove detection fires.

## Next Steps

- **[Examples](examples.md)**: Insecure vs. secure structured logging and alerting across stacks
- **[Threats Addressed](attack-vectors.md)**: What this control catches
- **[Overview](overview.md)**: What the control is and why it matters
- **[Proactive Controls](/learn/proactive)**: Return to the full OWASP Proactive Controls catalog
- **[Practice](/practice)**: Apply the control in hands-on exercises
