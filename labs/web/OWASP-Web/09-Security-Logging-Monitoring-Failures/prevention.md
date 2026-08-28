# Security Logging and Monitoring Failures - Prevention

## Table of Contents

- [Defense in Depth: The Six Layers](#defense-in-depth-the-six-layers)
- [Layer 1: Capture the Right Events](#layer-1-capture-the-right-events)
- [Layer 2: Structured, Consistent Format](#layer-2-structured-consistent-format)
- [Layer 3: Centralize and Ship Off-Host](#layer-3-centralize-and-ship-off-host)
- [Layer 4: Integrity and Tamper-Resistance](#layer-4-integrity-and-tamper-resistance)
- [Layer 5: Monitoring, Alerting, and Thresholds](#layer-5-monitoring-alerting-and-thresholds)
- [Layer 6: Incident Response and Recovery](#layer-6-incident-response-and-recovery)
- [Cross-Cutting Hygiene](#cross-cutting-hygiene)
- [Implementation Checklist](#implementation-checklist)

## Defense in Depth: The Six Layers

Preventing A9:2021 is not a single control but a pipeline that must work end to end. A gap at any stage reintroduces the vulnerability: events you never capture cannot be shipped; logs you never centralize cannot be alerted on; alerts with no runbook lead nowhere. Build — and test — all six layers.

```
[1] Capture   ->  [2] Format   ->  [3] Centralize  ->  [4] Integrity
   right events    structured        ship off-host       append-only
        |               |                 |                  |
        +---------------+--------+--------+------------------+
                                 |
                        [5] Monitor & Alert
                         thresholds + escalation
                                 |
                        [6] Respond & Recover
                         NIST SP 800-61 lifecycle
```

## Layer 1: Capture the Right Events

Log all **authentication, access-control, and input-validation failures**, plus high-value transactions, with enough user context to trace an actor — and never so much that you record a secret. Define a fixed vocabulary of event names so every service speaks the same language.

```python
# Python: a small helper that enforces "what to log"
import logging, json
log = logging.getLogger("security")

def security_event(event, outcome, *, user_id=None, source_ip=None,
                   request_id=None, **extra):
    # Never accept password/token/card fields into a security event.
    forbidden = {"password", "token", "secret", "card", "cvv"}
    if forbidden & set(extra):
        raise ValueError("attempted to log a sensitive field")
    log.info(json.dumps({
        "event": event,          # e.g. "authn.login.failure"
        "outcome": outcome,      # "success" | "denied" | "error"
        "user_id": user_id,      # subject identifier, NOT the password
        "source_ip": source_ip,
        "request_id": request_id,
        **extra,
    }))

# Auditable events you MUST emit:
security_event("authn.login.failure", "denied",
               user_id="u_10432", source_ip="203.0.113.44",
               request_id="b1f2c9", reason="invalid_credentials")
security_event("authz.denied", "denied",
               user_id="u_10432", resource="/api/admin/export")
security_event("txn.funds_transfer", "success",
               user_id="u_10432", amount="5000.00", currency="USD")
```

> **Rule of thumb**: log the *identifier* and the *outcome*, never the credential. If a field would harm the user were the log to leak, it does not belong in the log.

## Layer 2: Structured, Consistent Format

Free-text logs cannot be queried or alerted on reliably. Emit **structured JSON** (or strict key=value) with a shared schema so a SIEM can parse every field. Standardise timestamps to **UTC (RFC 3339)** and include a correlation ID that follows a request across services.

```javascript
// Node.js with pino: structured logs by default
const pino = require('pino');
const log = pino({
  level: 'info',
  timestamp: pino.stdTimeFunctions.isoTime,   // RFC 3339 UTC
  redact: {                                    // defense-in-depth redaction
    paths: ['req.headers.authorization', '*.password', '*.token', '*.cvv'],
    censor: '[REDACTED]'
  },
  formatters: { level: (label) => ({ level: label }) }
});

// A consistent event shape across the whole service:
log.warn({
  event: 'authn.login.failure',
  outcome: 'denied',
  user_id: 'u_10432',
  source_ip: req.ip,
  request_id: req.id,             // propagate via a header, e.g. X-Request-Id
  reason: 'invalid_credentials'
});
```

A shared field vocabulary — `event`, `outcome`, `user_id`, `source_ip`, `request_id` — is what turns a pile of lines into a queryable dataset.

## Layer 3: Centralize and Ship Off-Host

Logs on the box that produced them are lost when the box is compromised, reimaged, or autoscaled away. Ship them, in near-real-time, to a central platform (ELK/OpenSearch, Splunk, Loki, a managed SIEM) where they can be correlated across services and survive the loss of any single host.

```yaml
# Filebeat: tail the app log and forward to central storage
# filebeat.yml
filebeat.inputs:
  - type: filestream
    id: app-logs
    paths: ["/var/log/app/*.json"]
    parsers:
      - ndjson: { target: "", overwrite_keys: true }

output.logstash:
  hosts: ["logstash.internal:5044"]
  ssl.enabled: true                 # encrypt logs in transit
  ssl.certificate_authorities: ["/etc/pki/ca.crt"]

# In containers, prefer the platform's log driver so stdout/stderr
# is collected even if the pod is rescheduled:
#   docker run --log-driver=fluentd ...
#   (or a DaemonSet collector in Kubernetes)
```

In cloud-native environments, write structured logs to **stdout/stderr** and let a node-level collector (Fluent Bit/Fluentd DaemonSet) ship them — so evidence outlives ephemeral pods.

## Layer 4: Integrity and Tamper-Resistance

Once centralized, logs must be **append-only** and protected from the very accounts that could be compromised. Use write-once storage, restrict deletion to a separate privileged role, and add cryptographic integrity so tampering is detectable.

```bash
# AWS example: send audit logs to a bucket with Object Lock (WORM)
aws s3api put-object-lock-configuration \
  --bucket audit-logs-prod \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 400}}
  }'
# COMPLIANCE mode: even the root account cannot delete before expiry.

# Detect tampering with a hash chain (each record binds the previous):
#   record_n.hash = SHA256(record_n.data || record_{n-1}.hash)
# A broken chain reveals insertion, deletion, or edits.
```

- **Least privilege**: the app account may append to logs but must not be able to delete or rewrite them.
- **Separate the ingest and admin roles**: whoever can write logs should not be able to purge them.
- **Retention**: define a period that satisfies legal/compliance needs (often 90 days hot, 1 year+ cold) and enforce it automatically.

## Layer 5: Monitoring, Alerting, and Thresholds

Logging without monitoring is the single most common form of A9. Turn events into **alerts with thresholds that account for distributed, low-and-slow attacks**, and route them to an on-call channel a human actually watches. This is the layer the 2025 "Logging & Alerting Failures" rename emphasises most.

```yaml
# Prometheus + Alertmanager: alert on a burst of auth failures
# rules.yml
groups:
  - name: security
    rules:
      - alert: CredentialStuffingSuspected
        # cumulative across ALL sources, not just per-IP (defeats rotation)
        expr: sum(rate(authn_login_failure_total[5m])) > 20
        for: 2m
        labels: { severity: high }
        annotations:
          summary: "Elevated login failures across the fleet"
          runbook: "https://runbooks.internal/auth-bruteforce"

      - alert: AccessControlProbe
        expr: sum by (user_id) (rate(authz_denied_total[10m])) > 5
        for: 5m
        labels: { severity: medium }

      - alert: LogPipelineDown            # monitor the monitoring!
        expr: up{job="filebeat"} == 0
        for: 5m
        labels: { severity: critical }
```

```yaml
# Alertmanager: escalate, don't just notify
route:
  receiver: slack-secops
  group_by: [alertname]
  routes:
    - matchers: [severity="critical"]
      receiver: pagerduty-oncall      # wakes a human
route_options:
  repeat_interval: 30m                 # keep paging until acknowledged
```

Design principles for effective alerting:

- **Correlate across sources** so distributed attacks (many IPs, few attempts each) still trip a rule.
- **Tune for signal**: every alert should be worth waking someone. Ruthlessly suppress false positives to prevent alert fatigue.
- **Escalate**: critical alerts page on-call and repeat until acknowledged; they never die silently in a muted channel.
- **Test detection**: run an authorised scan/pen test and confirm it fires. If it does not, the rule is broken.

## Layer 6: Incident Response and Recovery

An alert must land in a defined process, not an inbox. Adopt an incident-response and recovery plan — **NIST SP 800-61** is the canonical reference — so that when detection works, the organisation knows exactly what to do.

```
NIST SP 800-61 lifecycle (map every alert to this):

  1. Preparation      - runbooks, tooling, on-call rota, log access ready
  2. Detection &      - the alert fires; triage severity; open an incident
     Analysis
  3. Containment,     - isolate hosts, revoke sessions/keys, preserve logs
     Eradication &      (the append-only store is now your evidence),
     Recovery           remove the foothold, restore from clean state
  4. Post-Incident    - blameless review; feed findings back into
     Activity           detection rules and Layer-1 event coverage
```

The append-only central logs from Layer 4 are what make containment and the post-incident review possible: they scope the breach, prove what was and was not touched, and turn each incident into better detection next time.

## Cross-Cutting Hygiene

### Prevent Log Injection (Encode Untrusted Data)

Neutralize control characters — especially `CR`/`LF` — in any user-controlled value before it is written, and prefer structured fields (which are escaped by the serializer) over string concatenation.

```java
// Java: strip CR/LF so attackers can't forge log lines (CWE-117)
String safe = untrusted.replaceAll("[\\r\\n]", "_");
log.warn("authn.login.failure user={} ip={}", safe, sourceIp);

// Better: structured logging escapes values for you
MDC.put("user_id", untrusted);   // SLF4J/Logback JSON encoder handles escaping
log.warn("authn.login.failure");
```

### Never Log Secrets

Maintain a deny-list of fields (password, token, secret, authorization header, PAN, CVV) and apply redaction at the logging framework level so a careless call site cannot leak them. Mask PII (e.g. show only the last four digits) where partial data is genuinely needed.

### Synchronize Time and Define Retention

Run NTP on every host, log exclusively in **UTC**, and set a retention policy that balances forensic value, cost, and privacy obligations. Unsynchronized clocks make cross-service timelines — the core forensic artifact — untrustworthy.

## Implementation Checklist

| Control | What good looks like |
|---------|----------------------|
| Event coverage | All auth, access-control, and input-validation failures + high-value txns logged |
| Context | who / what / when / where / outcome on every security event |
| Format | Structured JSON, shared schema, UTC (RFC 3339) timestamps, correlation IDs |
| Centralization | Shipped off-host to a SIEM in near-real-time, encrypted in transit |
| Integrity | Append-only / WORM storage; delete separated from write; hash chaining |
| Alerting | Thresholds that survive distributed attacks; escalation to on-call |
| Pipeline health | Monitoring-of-the-monitoring: shipper/sensor down alerts |
| Response | Documented IR plan (NIST SP 800-61) that alerts feed into |
| Hygiene | Log-injection encoding, no secrets, NTP/UTC, retention enforced |
| Validation | Authorized scan/pen test confirmed to generate an alert |

## Key Takeaways

1. Prevention is a **pipeline**: capture → format → centralize → integrity → alert → respond. Any gap reopens A9.
2. Capture **security-relevant events with context**, in a **structured** format, and ship them **off-host**.
3. Make logs **tamper-resistant** and free of **secrets**; encode untrusted input to stop **log injection**.
4. Logging only counts if it **alerts** — with escalation — and feeds a real **incident-response plan**.
5. **Prove it**: your own authorised scans and pen tests must generate alerts.

## What's Next?

- **[Overview](./overview.md)**: Understand the A9:2021 category and its lineage
- **[Attack Vectors](./attack-vectors.md)**: See the undetected activity these defenses catch
- **[Examples](./examples.md)**: Vulnerable vs secure structured logging in Python, Node, and Java
- **[Lab](./lab/no-logging-lab/)**: Practice prevention in a safe, isolated environment

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
