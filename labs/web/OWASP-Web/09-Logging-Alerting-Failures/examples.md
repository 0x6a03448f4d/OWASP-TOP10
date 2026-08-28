# A9:2025 — Logging & Alerting Failures: Examples

## Table of Contents

- [How to Read These Examples](#how-to-read-these-examples)
- [Example 1 — Authentication (Python / Flask)](#example-1--authentication-python--flask)
- [Example 2 — Authorization & High-Value Actions (Node.js / Express)](#example-2--authorization--high-value-actions-nodejs--express)
- [Example 3 — Log Injection & Secret Leakage](#example-3--log-injection--secret-leakage)
- [Example 4 — Detection & Alerting Config (SIEM)](#example-4--detection--alerting-config-siem)
- [Side-by-Side Summary](#side-by-side-summary)
- [Next Steps](#next-steps)

## How to Read These Examples

Each example shows a **vulnerable** implementation and the **secure** version that fixes it. The point of this category is that the vulnerable code often *works perfectly*—it just leaves no usable trace and raises no alarm. The secure version produces structured, contextual, sanitised security events, and the final example turns those events into a firing alert.

## Example 1 — Authentication (Python / Flask)

### Vulnerable

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = authenticate(username, password)
    if user:
        return {'status': 'ok', 'token': issue_token(user)}
    # FAILURE: the failed login is never recorded.
    # No username, no IP, no count -> credential stuffing is invisible.
    return {'status': 'invalid'}, 401
```

**Why it fails:** only the happy path is (implicitly) handled; failures vanish. An attacker can try millions of credentials and generate zero security signal. There is nothing to correlate, so no alert can ever fire.

### Secure

```python
import logging, sys, re
from flask import Flask, request
from pythonjsonlogger import jsonlogger

app = Flask(__name__)

# --- structured security logger to stdout (collector ships it off-host) ---
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(jsonlogger.JsonFormatter(
    '%(asctime)s %(levelname)s %(message)s',
    rename_fields={'asctime': 'timestamp', 'levelname': 'severity'},
    datefmt='%Y-%m-%dT%H:%M:%S%z'))
slog = logging.getLogger('security')
slog.setLevel(logging.INFO)
slog.addHandler(_handler)

def _clean(v):                                  # neutralise log injection (CWE-117)
    return re.sub(r'[\r\n\t\x00-\x1f\x7f]', ' ', str(v))[:256]

def sec_event(event, outcome, **ctx):
    slog.info(event, extra={
        'event': event, 'outcome': outcome,
        'source_ip': request.remote_addr,
        'user_agent': _clean(request.headers.get('User-Agent', '')),
        'correlation_id': request.headers.get('X-Correlation-ID'),
        'service': 'auth-api', 'env': 'production', **ctx})

@app.route('/login', methods=['POST'])
def login():
    username = _clean(request.form.get('username', ''))
    user = authenticate(username, request.form.get('password', ''))
    if user:
        sec_event('authn_login_success', 'success', actor=username)  # no secrets logged
        return {'status': 'ok', 'token': issue_token(user)}
    # SUCCESS PATH FOR DETECTION: the failure is a first-class security event.
    sec_event('authn_login_failed', 'failure', actor=username, reason='bad_credentials')
    return {'status': 'invalid'}, 401
```

**What changed:** failures are logged with *who, from where, and why*; the username and user-agent are sanitised; no password or token value is written; timestamps are ISO-8601; and the record is JSON that a SIEM can count and correlate. This is the raw material every detection in Example 4 depends on.

## Example 2 — Authorization & High-Value Actions (Node.js / Express)

### Vulnerable

```javascript
app.post('/api/transfer', (req, res) => {
  const { amount, from, to } = req.body;
  if (req.user.id !== accountOwner(from)) {
    return res.status(403).send('Forbidden');   // denial NOT logged
  }
  doTransfer(from, to, amount);
  console.log('transfer done');                 // useless: no who/what/how-much
  res.send('ok');
});
```

**Why it fails:** the 403 denial—your best early warning of IDOR/privilege probing—is thrown away. The completed transfer is "logged" with a bare string that names no actor, amount, or accounts, so it is useless for detection or forensics.

### Secure

```javascript
const pino = require('pino');
const { randomUUID } = require('crypto');
const log = pino({ base: { service: 'payments-api', env: 'production' } });

app.use((req, res, next) => {                    // propagate a correlation id
  req.cid = req.get('X-Correlation-ID') || randomUUID();
  res.set('X-Correlation-ID', req.cid);
  next();
});

const secEvent = (req, event, outcome, ctx = {}) => log.info({
  event, outcome, actorId: req.user?.id ?? null,
  sourceIp: req.ip, correlationId: req.cid, ...ctx }, event);

app.post('/api/transfer', (req, res) => {
  const { amount, from, to } = req.body;

  if (req.user.id !== accountOwner(from)) {
    // EARLY-WARNING SIGNAL: log every authorization denial.
    secEvent(req, 'authz_denied', 'denied',
             { action: 'transfer', targetAccount: from, reason: 'not_owner' });
    return res.status(403).send('Forbidden');
  }

  secEvent(req, 'funds_transfer', 'initiated',
           { amount, fromAccount: from, toAccount: to });   // high-value action
  try {
    doTransfer(from, to, amount);
    secEvent(req, 'funds_transfer', 'success', { amount, fromAccount: from, toAccount: to });
    res.send('ok');
  } catch (e) {
    secEvent(req, 'funds_transfer', 'failure', { amount, error: e.message });
    res.status(500).send('error');
  }
});
```

**What changed:** denials are logged (feeding the "authz-denial spike" detection), and the high-value action is logged with full context at initiation and completion. Note account numbers are logged as identifiers for traceability—in a real system, mask them per PCI-DSS and never log full PANs.

## Example 3 — Log Injection & Secret Leakage

### Vulnerable

```python
# CWE-117 (log injection) + CWE-532 (secrets in logs), both at once.
logger.info("Login for " + username + " body=" + str(request.json))

# If username = "admin\n2025-08-28 12:00:00 INFO Login success user=ceo",
# the attacker forges a fake success line in a line-based log.
# And dumping request.json writes the plaintext password/token to disk.
```

### Secure

```python
import re

SENSITIVE = {'password', 'passwd', 'token', 'authorization',
             'cookie', 'ssn', 'card', 'cvv', 'secret'}

def clean(v):                                   # strip CR/LF/control chars
    return re.sub(r'[\r\n\t\x00-\x1f\x7f]', ' ', str(v))[:256]

def redact(d):                                  # drop sensitive keys
    return {k: ('***REDACTED***' if k.lower() in SENSITIVE else v)
            for k, v in (d or {}).items()}

# Structured value -> newline becomes \n INSIDE a JSON string, not a new line.
slog.info('authn_login_failed', extra={
    'event': 'authn_login_failed', 'outcome': 'failure',
    'actor': clean(username),
    'fields': redact(request.json)})            # secrets never hit disk
```

**What changed:** untrusted values are sanitised so they cannot forge log lines, sensitive keys are redacted so credentials never reach storage, and structured JSON makes both problems structurally hard to reintroduce.

## Example 4 — Detection & Alerting Config (SIEM)

Structured events are only half the job—now turn them into **alerts**. Below are three ways to express the same idea (credential stuffing) plus the routing that keeps alerts actionable and fatigue-free.

#### Sigma rule (portable across SIEMs) — horizontal credential stuffing

```yaml
title: Horizontal Credential Stuffing
id: 7c1e2a10-a9f2-4b3d-9c11-3f2b1d0e4a55
status: stable
description: One source IP fails authentication across many distinct accounts
logsource:
    product: application
    service: auth
detection:
    failed:
        event: 'authn_login_failed'
    timeframe: 10m
    condition: failed | count(actor) by source_ip > 50   # 50+ distinct users / 10 min
level: high
falsepositives:
    - Shared corporate NAT/proxy egress IPs (allow-list them)
tags:
    - attack.credential_access
    - attack.t1110.004
```

#### Elasticsearch / ELK — threshold detection rule (Detection-as-Code)

```json
{
  "name": "Horizontal Credential Stuffing",
  "type": "threshold",
  "index": ["security-*"],
  "query": "event: \"authn_login_failed\"",
  "threshold": {
    "field": "source_ip",
    "value": 1,
    "cardinality": [ { "field": "actor", "value": 50 } ]
  },
  "interval": "5m",
  "risk_score": 73,
  "severity": "high",
  "actions": [
    { "action_type": "pagerduty", "params": { "severity": "critical" } }
  ]
}
```

#### Splunk SPL — scheduled correlation search

```
index=security event="authn_login_failed" earliest=-10m
| stats dc(actor) AS distinct_users, count AS attempts BY source_ip
| where distinct_users > 50
| eval severity="high", rule="credential_stuffing"
| sendalert pagerduty param.severity="critical"
```

#### Alert routing & deduplication (fight alert fatigue)

```yaml
# Prometheus Alertmanager: collapse a flood into ONE incident and route by severity.
route:
  group_by: ['alertname', 'source_ip']    # dedupe identical alerts
  repeat_interval: 4h                      # don't re-page for the same thing
  routes:
    - matchers: [ 'severity="critical"' ]
      receiver: pagerduty-oncall           # page a human + runbook link
    - matchers: [ 'severity="warning"' ]
      receiver: triage-queue               # review, don't page

# Also ship a heartbeat/"dead man's switch": alert if NO auth events arrive in 15m,
# because silence can mean the attacker stopped your logging pipeline.
```

## Side-by-Side Summary

| Concern | Vulnerable | Secure |
| --- | --- | --- |
| Failed logins | Not logged | Logged with actor, IP, reason |
| Authz denials | Discarded (403 only) | Logged as early-warning events |
| High-value actions | `console.log('done')` | Structured, full context, init + result |
| Format | Free-text / `print` | Structured JSON, correlation ID |
| Timestamps | Local / missing | ISO-8601 UTC, server-assigned |
| Untrusted input | Concatenated raw (CWE-117) | Sanitised / structured values |
| Secrets | Full body dumped (CWE-532) | Redacted, never on disk |
| Storage | On-host, mutable | Centralised, append-only |
| Detection | None | Correlation rule (as code) |
| Alerting | None | Deduped, severity-routed, on-call |

> **The throughline:** the secure code does not just "log more"—it logs the *right events* in a *structured, safe, centralised* form that a *rule* can turn into a *tuned, owned alert*. Every link in that chain is required.

## Next Steps

- **[Overview](./overview.html)**: The category, the 2025 edition, and why alerting is central.
- **[Attack Vectors](./attack-vectors.html)**: The undetected-attack patterns these examples defend against.
- **[Prevention](./prevention.html)**: The full layered defense model behind this code.
- **[Hands-On Lab](./lab/logging-alerting-failures/)**: Add these events and rules to a blind app and watch the alert fire.

---

*Part of the [OWASP Top 10 Educational Repository](/learn/web) — A9:2025, Logging & Alerting Failures.*
