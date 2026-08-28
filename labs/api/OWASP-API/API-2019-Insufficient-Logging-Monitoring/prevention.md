# API10:2019 Insufficient Logging & Monitoring - Prevention

## Prevention Strategy Overview

Building detection is a pipeline, not a single control. Data has to be **captured**, then **centralised**, then **watched**, then **acted on**—a gap at any stage means blindness:

1. Log every security-relevant event with enough context to investigate.
2. Use one consistent, structured format so the data is machine-parseable.
3. Centralise to a tamper-resistant store (SIEM/ELK) with synchronised time.
4. Alert in real time on tuned thresholds and known attack patterns.
5. Wire alerts into an incident-response process with an owner.
6. Protect the logs: prevent injection, and never write secrets or PII.

### Core Principles

- **Detectability is a requirement, not a nice-to-have**: treat "could we see this attack?" as an acceptance criterion for every security-relevant feature.
- **Context over volume**: a few well-structured events beat a firehose of free text—log *who, what, which object, and the outcome*.
- **Off-box and tamper-resistant**: logs the application host can rewrite are not evidence.
- **Detection must connect to response**: an alert nobody receives or acts on is the same as no alert.

## 1. Log All Security-Relevant Events, With Context

Decide deliberately *what* is a security event, and ensure each one carries the fields needed to investigate it. At minimum, log the following:

| Event type | Log on | Why |
|------------|--------|-----|
| Authentication | Success *and* failure, logout, token issue/refresh | Detect credential stuffing / brute force |
| Authorization | Every denial (403), privilege change | Detect BOLA/function-level enumeration |
| Input validation | Every rejected/malformed request | Detect fuzzing and injection probing |
| Rate limiting | Every throttle (429) and lockout | Detect abuse pushing limits |
| Sensitive actions | Data export, role change, config change, deletion | Detect abuse of high-value flows |

Every record should carry a consistent set of context fields:

```
timestamp (UTC, ms)   event type + outcome (success/failure)
request id            client / account id
auth subject (user)   source IP (+ derived geo/ASN)
http method           endpoint / route template
object id (if any)    status code
                      NEVER: passwords, tokens, full PANs, raw PII
```

## 2. Use One Consistent, Structured Format

Free-text logs cannot be reliably parsed or correlated. Emit **structured** events (JSON is the common choice) so every field is queryable in the SIEM.

```
# Bad: unparseable, no actor, no object, no outcome
User request failed for invoice

# Good: structured, attributable, correlatable
{"ts":"2026-08-28T14:03:11.482Z","event":"authz.denied","outcome":"failure",
 "client_id":"acct_8842","auth_subject":"user_1021","source_ip":"203.0.113.44",
 "method":"GET","endpoint":"/api/v1/invoices/{id}","object_id":"inv_990771",
 "status":403,"request_id":"b1f2c3d4"}
```

Standardise the schema across every service (a shared logging library helps), and consider an interoperable event vocabulary such as the **OWASP Logging Cheat Sheet** guidance or the **OpenTelemetry** log data model so downstream tooling agrees on field names.

## 3. Centralise to a Tamper-Resistant Store

Logs that live only on the host are useless the moment the host is compromised. Ship them off-box in real time.

```yaml
# Ship application logs to a central pipeline (example: Filebeat -> Elasticsearch)
# filebeat.yml (excerpt)
filebeat.inputs:
  - type: filestream
    paths: ["/var/log/api/*.json"]
    parsers:
      - ndjson: { target: "", overwrite_keys: true }
output.logstash:
  hosts: ["logpipeline.internal:5044"]

# Tamper-resistance:
#  - forward in real time so a host compromise cannot erase history
#  - store append-only / WORM; restrict who can delete indices
#  - sign or hash-chain critical audit streams
#  - keep the SIEM in a separate trust/account boundary from the app
```

Send everything to a SIEM or log platform (ELK/OpenSearch, Splunk, a managed service) so events from every service are correlated in one place, and lock down who can modify or delete the stored data.

## 4. Real-Time Alerting on Tuned Thresholds

Centralised data only helps if something watches it. Define alerts for the signals that mark an attack in progress, and **tune the thresholds** to your baseline so they fire on abuse without drowning responders in noise.

```
Alert when, per rolling window:
  401 rate          > N failed logins/min from one source OR against one account
  403 rate          > N denials/min from one subject (enumeration)
  429 rate          > N throttles/min from one client (abuse at the limit)
  distinct objects  one subject touches > N distinct object ids/min (scraping/BOLA)
  token spread      one token seen from > N IPs / > 1 country in M minutes
  validation fails  > N rejects/min clustered on one endpoint (fuzzing)
  5xx spike         sudden rise (error-triggering probes / instability)
```

Start thresholds conservative, review the false positives, and ratchet them in—an alert that always cries wolf is quickly ignored, which recreates the blindness you were fixing.

## 5. Monitor Per-Client and Per-Token, Not Just Aggregate

The attacks in this category hide in aggregate dashboards. Build baselines *per caller* so a single abusive client stands out even while total traffic looks normal.

- Track request volume, error rate, and distinct-object count **per API key / token / account**.
- Alert on deviation from each caller's own baseline, not just a global threshold.
- Correlate a token across source IPs and geographies to catch replay of stolen credentials.

## 6. Prevent Log Injection

Untrusted data written verbatim lets an attacker forge log lines (CRLF injection) or attack a log viewer. Neutralise it before it is logged.

```python
# Encode/strip control characters in any untrusted field before logging
import re

def safe(value: str) -> str:
    # remove CR/LF and other control chars that could forge a new log line
    return re.sub(r'[\r\n\t\x00-\x1f]', ' ', str(value))[:256]

log.info("login.failure", extra={"user": safe(submitted_username),
                                 "source_ip": safe(client_ip)})
```

Structured logging helps here by construction: when fields are serialised as JSON values, a newline inside a value cannot break out and start a new record. Prefer it over string concatenation into a text line.

## 7. Never Log Secrets or Sensitive Data

- Never log passwords, session tokens, API keys, authorization headers, full card numbers, or raw PII.
- Log *identifiers and outcomes* instead: a user id, an account id, a masked value, a boolean result.
- Add redaction/masking at the logging layer so a careless `log.info(request)` cannot leak the whole payload.

```python
# Redact known-sensitive keys centrally, so no caller can leak them
SENSITIVE = {"password", "token", "authorization", "card", "ssn", "secret"}

def redact(d: dict) -> dict:
    return {k: ("***" if k.lower() in SENSITIVE else v) for k, v in d.items()}
```

## 8. Time Synchronisation and Retention

- **Sync clocks** (NTP) across every host and log in UTC, so events from different services can be correctly ordered during an investigation.
- **Retain** security logs long enough to investigate a breach discovered months later—align retention with your regulatory and IR requirements, balanced against the duty not to hoard sensitive data.
- **Protect retained logs** with the same access controls as the data they describe.

## 9. Integrate With Incident Response

Detection is only valuable if it triggers action. Close the loop:

- Route alerts to an on-call channel/pager with a named owner, not an unwatched inbox.
- Write runbooks: for a 401 spike, for enumeration, for token replay—what to check, how to contain (block key, force re-auth, rate-limit), whom to notify.
- Rehearse: run tabletop exercises and replay historical attacks so the detections and the response are both proven.
- Feed lessons back into thresholds and new detections after every incident.

## Framework-Specific Notes

### Python (structlog / logging)
```python
import structlog
log = structlog.get_logger()

# JSON output, bound context, no secrets
log.bind(request_id=rid, client_id=cid).warning(
    "auth.failure", auth_subject=user_id, source_ip=ip, status=401)
```

### Node.js (pino)
```javascript
const logger = require('pino')({ redact: ['req.headers.authorization', '*.password', '*.token'] });
logger.warn({ event: 'authz.denied', client_id, auth_subject, object_id, status: 403 },
            'authorization denied');
```

### Java (SLF4J + Logback JSON + MDC)
```java
MDC.put("request_id", requestId);
MDC.put("client_id", clientId);
log.warn("auth.failure subject={} ip={} status=401", userId, sourceIp);
// logback encoder emits structured JSON; MDC fields ride along on every line
```

## Key Takeaways

1. **Capture the right events** — auth, authz, validation, throttling, and sensitive actions, each with actor and object context.
2. **Structure and centralise** — one JSON schema shipped off-box to a tamper-resistant SIEM makes the data usable.
3. **Alert on the attack signals** — tuned thresholds on 401/403/429, per-client volume, and token spread.
4. **Protect the logs** — encode untrusted input, redact secrets, and make records append-only.
5. **Connect detection to response** — alerts must reach a human with a runbook, or they change nothing.

## Next Steps

- **[Code Examples](examples.md)**: Structured security logging in Python, Node, and Java, plus alerting/SIEM config
- **[Attack Vectors](attack-vectors.md)**: The undetected attacks these controls are built to catch
- **[API Security Learning Path](/learn/api)**: Return to the full OWASP API Top 10
- **[Practice](/practice)**: Build and tune a detection against sample traffic
