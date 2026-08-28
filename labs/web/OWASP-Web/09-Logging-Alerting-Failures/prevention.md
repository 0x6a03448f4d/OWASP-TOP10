# A9:2025 — Logging & Alerting Failures: Prevention

## Table of Contents

- [Defense Strategy: Close the Loop](#defense-strategy-close-the-loop)
- [Layer 1 — Log the Right Events](#layer-1--log-the-right-events)
- [Layer 2 — Structure and Context](#layer-2--structure-and-context)
- [Layer 3 — Never Log Secrets; Prevent Log Injection](#layer-3--never-log-secrets-prevent-log-injection)
- [Layer 4 — Centralise, Synchronise, Retain](#layer-4--centralise-synchronise-retain)
- [Layer 5 — Tamper Resistance & Integrity](#layer-5--tamper-resistance--integrity)
- [Layer 6 — Detection as Code (Correlation)](#layer-6--detection-as-code-correlation)
- [Layer 7 — Actionable Alerting & Fighting Fatigue](#layer-7--actionable-alerting--fighting-fatigue)
- [Layer 8 — Response & Escalation](#layer-8--response--escalation)
- [Implementation Checklist](#implementation-checklist)
- [Next Steps](#next-steps)

## Defense Strategy: Close the Loop

Preventing Logging & Alerting Failures is not about buying a product — it is about building and maintaining an end-to-end loop where a security-relevant event reliably becomes a **timely, owned response**. Each layer below is necessary; a gap in any one neutralises the rest. Work them in order: there is no point tuning alerts if you are not yet logging the events that should trigger them.

```
Log  ->  Structure  ->  Sanitise  ->  Centralise  ->  Protect  ->  Detect  ->  Alert  ->  Respond
 |          |            |             |              |            |          |         |
 what     context     no secrets    off-host      append-only   rules    tuned &   runbook +
 to log   + IDs       + no injection + synced      + integrity   as code  routed    on-call
```

## Layer 1 — Log the Right Events

Start from a definition of **security-relevant events** and guarantee each one is logged. Aligning to the OWASP logging vocabulary keeps event names consistent and searchable.

| Domain | Must-log events |
|--------|-----------------|
| Authentication | Login success/**failure**, logout, MFA outcome, password reset, token issue/revoke. |
| Authorization | Every access-control **denial**; use of admin/privileged functions. |
| Input validation | Rejected/malformed input, schema violations, WAF/server-side blocks. |
| High-value actions | Payments, role changes, data export, deletion, config changes. |
| Account lifecycle | Registration, email/password change, lockout, new-device login. |
| Pipeline health | Logger errors, dropped events, shipping-agent up/down. |

> **Key rule:** log *failures and denials*, not just successes. The single most common gap in this category is recording only the happy path.

## Layer 2 — Structure and Context

Emit **structured** (JSON or key-value) logs so machines can parse, index, and correlate them. Every security event should carry a consistent envelope and a correlation ID that follows the request across services.

#### Python — structured security logger

```python
import logging, json, sys
from pythonjsonlogger import jsonlogger

def build_logger():
    handler = logging.StreamHandler(sys.stdout)   # stdout -> collector ships it
    handler.setFormatter(jsonlogger.JsonFormatter(
        '%(asctime)s %(levelname)s %(name)s %(message)s',
        rename_fields={'asctime': 'timestamp', 'levelname': 'severity'},
        datefmt='%Y-%m-%dT%H:%M:%S%z'))          # ISO-8601 timestamps
    log = logging.getLogger('security')
    log.setLevel(logging.INFO)
    log.addHandler(handler)
    return log

security_log = build_logger()

def log_security_event(event, outcome, request, **context):
    security_log.info(event, extra={
        'event': event,               # stable, enumerated name e.g. authn_login_failed
        'outcome': outcome,           # success | failure | denied
        'actor_id': getattr(request, 'user_id', None),
        'source_ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'correlation_id': request.headers.get('X-Correlation-ID'),
        'service': 'orders-api',
        'env': 'production',
        **context,                    # event-specific, already-sanitised fields
    })

# Usage at the point a security decision is made:
log_security_event('authz_denied', 'denied', request,
                   target_resource=f'order:{order_id}', reason='not_owner')
```

#### Node.js (Express) — correlation ID + Pino

```javascript
const pino = require('pino');
const { randomUUID } = require('crypto');
const log = pino({ base: { service: 'orders-api', env: 'production' } });

// Attach/propagate a correlation ID on every request
app.use((req, res, next) => {
  req.correlationId = req.get('X-Correlation-ID') || randomUUID();
  res.set('X-Correlation-ID', req.correlationId);
  next();
});

function logSecurityEvent(req, event, outcome, context = {}) {
  log.info({
    event, outcome,
    actorId: req.user?.id ?? null,
    sourceIp: req.ip,
    userAgent: req.get('User-Agent'),
    correlationId: req.correlationId,
    ...context,                       // pre-sanitised fields only
  }, event);
}

// Example: an authorization denial
logSecurityEvent(req, 'authz_denied', 'denied', {
  targetResource: `order:${req.params.id}`, reason: 'not_owner' });
```

## Layer 3 — Never Log Secrets; Prevent Log Injection

Two opposite mistakes live here: logging *too much* (secrets/PII — CWE-532) and logging untrusted data *unsafely* (log injection — CWE-117). Fix both.

#### Redact / never capture secrets and PII

```python
# Maintain a deny-list of sensitive keys and redact before writing.
SENSITIVE = {'password', 'passwd', 'authorization', 'cookie', 'set-cookie',
             'token', 'access_token', 'refresh_token', 'ssn', 'card', 'cvv', 'secret'}

def redact(obj):
    if isinstance(obj, dict):
        return {k: ('***REDACTED***' if k.lower() in SENSITIVE else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj

# Prefer to NEVER pass secrets to the logger at all; redaction is a safety net,
# not a licence to log raw request bodies or full user records.
```

#### Neutralise untrusted data (stop log forging)

```python
# Structured logging already prevents most injection because fields are
# serialised as JSON values -- newlines become \n, not new log lines.
# If you must build line-based logs, strip CR/LF and control chars first:

import re
def clean_for_log(value: str) -> str:
    return re.sub(r'[\r\n\t\x00-\x1f\x7f]', ' ', str(value))[:512]

log.info('login_failed', extra={'username': clean_for_log(untrusted_username)})
```

> **Why structured logging wins twice:** it makes correlation possible *and* it neutralises log injection, because an attacker's newline lands inside a JSON string value instead of starting a forged line.

## Layer 4 — Centralise, Synchronise, Retain

Logs must leave the host that produced them, in near real time, so an attacker who compromises the workload cannot erase the record. Applications should log to `stdout` and let the platform collect and forward.

#### Fluent Bit — ship container stdout to a central store

```ini
[SERVICE]
    Flush        1
    Log_Level    info

[INPUT]
    Name         tail
    Path         /var/log/containers/*.log
    Tag          app.*

[FILTER]
    Name         kubernetes           # enrich with pod/namespace/node metadata
    Match        app.*

[OUTPUT]
    Name         opensearch           # or es / splunk / loki / cloud sink
    Match        app.*
    Host         logs.internal
    Port         9200
    TLS          On
    Retry_Limit  False                # never silently drop security logs
```

#### Time synchronisation (non-negotiable for correlation)

```bash
# All hosts synchronise to NTP; all timestamps are UTC and ISO-8601.
timedatectl set-ntp true
timedatectl set-timezone UTC
# Application never trusts a client-supplied timestamp -- the server stamps events.
```

**Retention**: keep security logs long enough to satisfy the slowest realistic detection and your compliance obligations. A common baseline is hot/searchable for weeks and cold/archived for a year or more; align to PCI-DSS, HIPAA, SOC 2, or local law as applicable.

## Layer 5 — Tamper Resistance & Integrity

Centralised logs must also be hard to alter. The goal is that neither an external attacker nor a malicious insider can quietly rewrite history.

- **Append-only / WORM storage**: write-once buckets (object-lock), append-only indices, or a dedicated logging account the app can write to but not modify or delete.
- **Least privilege**: the application's log-shipping identity has *write*, never *delete*. Analysts have *read*. Almost no one has *modify*.
- **Integrity verification**: hash-chain or sign batches so tampering is detectable.

```python
# Lightweight tamper-evidence: chain each record to the previous hash.
import hashlib, json

def sealed_record(event: dict, prev_hash: str) -> dict:
    body = json.dumps(event, sort_keys=True, separators=(',', ':'))
    event['_prev'] = prev_hash
    event['_hash'] = hashlib.sha256((prev_hash + body).encode()).hexdigest()
    return event
# Any deletion or edit breaks the chain and is detectable on verification.
```

## Layer 6 — Detection as Code (Correlation)

Logs become security value only when rules turn them into detections. Treat detection logic as **code**: version-controlled, peer-reviewed, and tested against sample events, so rules evolve deliberately instead of by ad-hoc clicks in a console.

#### Sigma — portable detection rule (credential stuffing)

```yaml
title: Horizontal Credential Stuffing
status: stable
description: One source failing auth against many distinct accounts
logsource:
    product: application
    service: auth
detection:
    selection:
        event: 'authn_login_failed'
    timeframe: 10m
    condition: selection | count(actor_id) by source_ip > 50   # 50+ distinct users
level: high
tags:
    - attack.credential_access
    - attack.t1110.004                # Credential Stuffing (MITRE ATT&CK)
```

#### Correlations every application should ship with

| Detection | Correlate on | Catches |
|-----------|--------------|---------|
| Vertical brute force | Many failures for one account | Targeted password guessing |
| Horizontal stuffing | One IP/ASN vs. many accounts | Low-and-slow credential stuffing |
| Authz-denial spike | Many `authz_denied` per actor | IDOR / privilege probing |
| Recon signature | Many 404/403 per source | Enumeration / forced browsing |
| Exfil volume | Data read vs. per-user baseline | Bulk exfiltration |
| Impossible travel | Geo/time between logins | Account takeover |
| Pipeline heartbeat | Absence of expected logs | Attacker silencing detection |

## Layer 7 — Actionable Alerting & Fighting Fatigue

An alert is only useful if a human trusts it and can act on it. The enemy is **alert fatigue**: when most alerts are noise, responders mute the channel and miss the one that mattered. Engineer for high signal.

- **Alert on correlations, not raw events.** Never page on a single failed login; page on the *pattern*.
- **Deduplicate and group.** Collapse identical alerts into one incident with a count, so a flood becomes a single ticket (this also defeats alert-fatigue attacks).
- **Score by severity and route accordingly.** Critical → page on-call; medium → queue for triage; low → dashboard only.
- **Make every alert actionable.** Include what fired, the evidence, the correlation ID, and a link to the runbook.
- **Tune continuously.** Track false-positive rate per rule; a rule nobody trusts is worse than no rule.

#### Prometheus Alertmanager — grouping and routing to fight fatigue

```yaml
route:
  group_by: ['alertname', 'source_ip']   # collapse a flood into ONE incident
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h                     # don't re-page for the same thing
  routes:
    - matchers: [ 'severity="critical"' ]
      receiver: pagerduty-oncall          # wake someone
    - matchers: [ 'severity="warning"' ]
      receiver: triage-queue              # review, don't page
receivers:
  - name: pagerduty-oncall
    pagerduty_configs: [ { routing_key: '<key>' } ]
  - name: triage-queue
    slack_configs: [ { channel: '#sec-triage' } ]

inhibit_rules:                            # suppress downstream noise
  - source_matchers: [ 'alertname="PipelineDown"' ]
    target_matchers:  [ 'severity="warning"' ]
    equal: ['service']
```

## Layer 8 — Response & Escalation

Detection without response is theatre. Every alert class needs an **owner**, a **runbook**, and an **escalation path**, so a fired alert reliably becomes action within minutes.

- **On-call rotation**: a named human is responsible 24/7 for critical alerts; paging integrates with a scheduling tool.
- **Runbooks**: each detection links to step-by-step triage/containment guidance (confirm, scope, contain, escalate).
- **Escalation**: if the first responder does not acknowledge within an SLA, the alert escalates automatically.
- **Automated first response (SOAR)**, used carefully: e.g. auto-block a source IP after confirmed stuffing, force re-authentication, or quarantine a token — paired with human review.
- **Feedback loop**: every incident and every false positive feeds rule tuning, so the system gets quieter and sharper over time.

```
# Example runbook stub linked from the 'Horizontal Credential Stuffing' alert:
1. CONFIRM   -- is one source_ip failing auth across many distinct actor_ids?
2. SCOPE     -- which accounts were TARGETED? which SUCCEEDED (authn_login_success)?
3. CONTAIN   -- block source_ip/ASN; force password reset + re-auth on hit accounts.
4. ESCALATE  -- if any account succeeded + performed a high-value action, page IR lead.
5. LEARN     -- record false positives; adjust the count() threshold if needed.
```

## Implementation Checklist

1. **Define** your list of security-relevant events and log every one — including failures and denials.
2. **Structure** all security logs (JSON) with a consistent envelope and a propagated correlation ID.
3. **Sanitise**: redact secrets/PII (CWE-532) and neutralise untrusted data (CWE-117).
4. **Centralise** off-host in near real time; log to stdout and let a collector ship it.
5. **Synchronise** clocks to UTC via NTP; server stamps every event.
6. **Protect** logs with append-only/WORM storage, least privilege, and integrity checks.
7. **Detect** with version-controlled correlation rules (detection as code) covering the core attack patterns.
8. **Alert** on correlations, deduplicated, severity-scored, and routed — never on raw single events.
9. **Respond** via on-call, runbooks, and automatic escalation; measure MTTR.
10. **Watch the watcher**: alert on pipeline silence; test detections regularly (purple-team / synthetic events).

## Next Steps

- **[Overview](./overview.html)**: The category, the 2025 edition, and why alerting is central.
- **[Attack Vectors](./attack-vectors.html)**: The undetected-attack patterns these layers are built to catch.
- **[Examples](./examples.html)**: Vulnerable vs. secure logging in Python and Node.js, plus SIEM rules.
- **[Hands-On Lab](./lab/logging-alerting-failures/)**: Instrument a blind app until the attack fires an alert.

---

*Part of the [OWASP Top 10 Educational Repository](/learn/web) — A9:2025, Logging & Alerting Failures.*
