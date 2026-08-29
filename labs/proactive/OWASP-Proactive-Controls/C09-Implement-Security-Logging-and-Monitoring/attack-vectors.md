# C9: Implement Security Logging and Monitoring - Threats Addressed

## Table of Contents
- [Why This Control Exists](#why-this-control-exists)
- [The Detection Blind Spot](#the-detection-blind-spot)
- [Threats That Go Undetected Without It](#threats-that-go-undetected-without-it)
- [How Blind Spots Chain into Breaches](#how-blind-spots-chain-into-breaches)

## Why This Control Exists

> **⚠ DEFENSIVE FRAMING** — the threats below are described so you can instrument detection for them in systems you own or are authorised to defend. Each is a class of attack that succeeds *quietly* when logging and monitoring are absent.

Most controls stop an attack. This one **reveals** it. Security logging and monitoring rarely prevents the first malicious request—its job is to ensure that request, and the thousand that follow, are seen, correlated, alerted on, and answered before they become a breach. The threats this control addresses are therefore best understood as **attacks whose damage is proportional to how long they run undetected**. Remove the control and the attacker gains their most valuable asset: time.

The absence of this control is itself an OWASP Top 10 category—**Security Logging and Monitoring Failures (A09)**. The threats below are the concrete attacks that category leaves open.

## The Detection Blind Spot

```
WITHOUT logging & monitoring:

  Attacker acts        -> no event recorded
        v
  Attacker persists    -> no correlation, no baseline deviation flagged
        v
  Attacker exfiltrates -> no alert fires
        v
  Third party notices  -> victim learns of breach weeks/months later
                          (long dwell time = maximum damage)

WITH the control:

  Attacker acts        -> structured event logged (who/what/when/where + trace ID)
        v
  Centralized SIEM     -> correlates against a known-normal baseline
        v
  Tuned alert fires    -> actionable signal routed to responders
        v
  Incident response    -> containment begins in minutes/hours (low dwell time)
```

## Threats That Go Undetected Without It

### 1. Credential Stuffing

Attackers replay breached username/password pairs across your login endpoint at scale. Each individual attempt looks like a normal login; only the *aggregate* reveals the attack.

```
# Thousands of attempts, many accounts, distributed IPs:
POST /api/session  {"user":"alice@corp.com","pass":"<leaked-1>"}   -> 401
POST /api/session  {"user":"bob@corp.com","pass":"<leaked-2>"}     -> 401
POST /api/session  {"user":"carol@corp.com","pass":"<leaked-3>"}   -> 200  # hit
```

**Undetected without the control**: authentication failures are not logged or not baselined, so the spike of 401s across many accounts never becomes an alert—the successful takeover is invisible until fraud appears downstream.
**What detects it**: structured authn logs (success/failure, actor, src IP) + a rate/anomaly alert on failure spikes and improbable-travel logins.

### 2. Brute-Force and Password Spraying

A focused attacker hammers one account, or sprays one common password across many accounts to stay under per-account lockouts.

```
POST /api/session  {"user":"admin","pass":"Spring2026!"}   -> 401
POST /api/session  {"user":"jsmith","pass":"Spring2026!"}  -> 401
POST /api/session  {"user":"kpatel","pass":"Spring2026!"}  -> 200
```

**Undetected without the control**: with no logging of failures and no threshold alerting, the slow, low-and-slow spray never trips anything.
**What detects it**: per-account and cross-account failure counters, alerting on one password succeeding across many users.

### 3. Account Enumeration

Attackers use response differences (timing, error text, status codes) on login, registration, or password-reset endpoints to build a list of valid accounts to target next.

```
POST /api/reset  {"email":"alice@corp.com"}   -> "reset sent"      (exists)
POST /api/reset  {"email":"nobody@corp.com"}  -> "no such user"    (does not exist)
```

**Undetected without the control**: a single actor probing hundreds of addresses generates no security event, so the reconnaissance completes silently.
**What detects it**: logging of validation/lookup outcomes with actor context, and alerting on a single source generating a high volume of lookups.

### 4. Access-Control Probing (IDOR / BOLA Enumeration)

Attackers walk object identifiers or fuzz authorization boundaries to reach data that belongs to other users.

```
GET /api/invoices/1001   -> 403 (not mine)
GET /api/invoices/1002   -> 403
GET /api/invoices/1003   -> 200  # authorization gap found
```

**Undetected without the control**: if access-control failures are not logged, hundreds of "forbidden" outcomes from one actor across many objects raise no flag—the one success that leaks data is buried.
**What detects it**: log every authorization denial with actor + target, and alert on a single actor accumulating many denials across distinct objects.

### 5. Injection and Input-Validation Attacks

SQLi, command injection, path traversal, and template injection begin as anomalous, rejected inputs long before a payload succeeds.

```
GET /api/search?q=' OR '1'='1
GET /api/files?path=../../../../etc/passwd
POST /api/render  {"tpl":"{{7*7}}"}
```

**Undetected without the control**: validation failures and WAF blocks that are never logged mean the probing phase is invisible, and defenders lose the early warning that precedes a successful exploit.
**What detects it**: log input-validation failures and WAF/deny events, and alert on injection-pattern clusters from a source.

### 6. Data Exfiltration

Once inside, attackers pull data—bulk exports, scripted downloads, oversized queries—often far exceeding any legitimate usage pattern.

```
GET /api/export?table=customers&limit=5000000
# 400x the largest export any real user has ever requested
```

**Undetected without the control**: if high-value transactions and export volumes are not logged and baselined, terabytes can leave before anyone notices.
**What detects it**: log data exports/downloads with row/byte counts, baseline normal volumes, and alert on volume anomalies and off-hours bulk access.

### 7. Privilege Escalation and Permission Abuse

Attackers and malicious insiders grant themselves roles, add group memberships, or flip permission flags to widen their access.

```
PATCH /api/users/9021  {"role":"user"  -> "admin"}
POST  /api/groups/superadmins/members  {"user":"u_9021"}
```

**Undetected without the control**: unlogged permission changes are the classic silent escalation—the attacker's expanded access looks legitimate on every subsequent request.
**What detects it**: log all permission/role/identity changes, and alert on privilege grants, especially self-grants and out-of-process changes.

### 8. Administrative and Configuration Abuse

Post-compromise persistence often runs through admin functions: disabling controls, creating backdoor accounts, changing config, or turning off logging itself.

```
POST /api/admin/users            {"user":"svc_backup","role":"admin"}
PUT  /api/admin/config/logging   {"enabled": false}   # blinding the defender
```

**Undetected without the control**: without administrative-action logging (shipped off-host), the attacker's first move—disabling local logging—erases the rest.
**What detects it**: log admin actions to a centralized, append-only store, and alert on new privileged accounts and any change to logging/security config.

### 9. Log Tampering and Anti-Forensics

An attacker who reaches a host will try to delete or edit logs to erase their trail—trivially possible when logs sit only on local, mutable disk.

```
$ shred -u /var/log/app/audit.log
$ sed -i '/203.0.113.44/d' /var/log/nginx/access.log
```

**Undetected without the control**: local-only logs are the first thing wiped, destroying the evidence of everything above.
**What detects it**: ship logs off-host in near-real time to append-only, integrity-protected storage; alert on log-gap and integrity-check failures.

### 10. Log Injection and Forged Entries

When untrusted input is written to logs verbatim, an attacker embeds newlines and control characters to forge log lines, corrupt parsers, or plant payloads that execute when a log viewer or downstream tool renders them.

```
# Attacker sets username to a value containing CRLF + a fake entry:
user = "admin\n2026-08-29T14:00:00Z INFO login success user=attacker src=trusted"
# Naive logger writes two lines; the forged second line frames a clean login.
```

**Undetected without the control**: forged entries mislead investigators and can hide the real activity; malicious markup can even attack the SIEM/log-viewer.
**What detects it**: neutralise (encode/strip newlines and control chars) untrusted data before logging, and prefer structured fields over string concatenation.

### 11. Sensitive-Data Leakage Through Logs

Over-logging turns the log store into a breach target: passwords, tokens, and PII captured in cleartext are copied everywhere logs go.

```
INFO auth attempt body={"user":"alice","password":"hunter2"} token=eyJhbGciOi...
# Every log reader and every log backup now holds live credentials.
```

**The threat**: the control done carelessly *creates* exposure. A leaked or over-broad log store hands the attacker exactly what they came for.
**What prevents it**: redact/mask secrets and PII at the logging boundary; never log full credentials, tokens, or card numbers.

### 12. Slow, Low-Signal Reconnaissance and Scanning

Automated scanners and manual recon probe for endpoints, versions, and misconfigurations. Individually each request is unremarkable; together they map your attack surface.

```
GET /.git/config      -> 404
GET /actuator/env     -> 404
GET /admin            -> 401
GET /backup.sql       -> 404   # hundreds of probes from one source
```

**Undetected without the control**: no aggregation means the scan blends into background noise, and the one probe that hits stays hidden.
**What detects it**: correlate 4xx/deny patterns per source, and alert on scanning signatures—this is also how you verify a pentest actually trips detection.

## How Blind Spots Chain into Breaches

The threats above rarely act alone. The signature of a major breach is a *chain* that ran undetected because no single stage was logged or alerted:

```
Credential stuffing (unlogged 401 spike)     -> account takeover
        +
Access-control probing (unlogged 403s)        -> reach other users' data
        +
Privilege escalation (unlogged role change)   -> admin access
        +
Bulk export (unbaselined volume)              -> exfiltration
        +
Local log wipe (no off-host copy)             -> no forensic trail
        =  long-dwell breach, discovered by a third party
```

Each link is individually catchable with this control in place—and individually invisible without it. That is why logging and monitoring is the control that converts a slow-motion catastrophe into a contained incident.

## Key Takeaways

1. **This control fights dwell time**—the threats it addresses are attacks whose damage grows with every hour they run unseen.
2. **The aggregate is the signal**—stuffing, spraying, enumeration, and probing are invisible per-request and obvious once correlated against a baseline.
3. **Silent escalation and exfil are the endgame**—unlogged permission changes and un-baselined exports are how a foothold becomes a breach.
4. **Protect the logs themselves**—off-host, append-only storage defeats tampering; redaction and neutralisation stop leakage and log injection.
5. **Chains are catchable link by link**—instrument every stage and the breach never assembles.

## Next Steps

- **[How to Implement](prevention.md)**: Build the logging, monitoring, and response pipeline
- **[Examples](examples.md)**: Insecure vs. secure structured logging and alerting across stacks
- **[Overview](overview.md)**: What the control is and why it matters
- **[Proactive Controls](/learn/proactive)**: Return to the full OWASP Proactive Controls catalog
- **[Practice](/practice)**: Apply the control in hands-on exercises
