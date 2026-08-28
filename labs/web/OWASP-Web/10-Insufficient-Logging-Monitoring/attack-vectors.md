# Insufficient Logging & Monitoring - Attack Vectors

> **Educational purpose only.** This page describes attacker behaviour at a conceptual level so defenders understand what missing detection looks like from the other side. It contains no weaponised exploit code.

## Table of Contents
- [The Core Attack Flow](#core-flow)
- [Attack Patterns That Thrive on Missing Detection](#patterns)
- [Attacks Against the Logs Themselves](#tampering)
- [The Attacker's Perspective](#attacker-perspective)
- [Next Steps](#next-steps)

## The Core Attack Flow

Insufficient Logging & Monitoring is unusual: there is no single request that "exploits" it. Instead, missing detection is the condition that lets *every other* attack run to completion. The attacker's strategy is simply to **operate below the victim's ability to see them** — and where the victim has no logging, no monitoring, and no response process, that threshold is effectively infinite.

```
1. RECON quietly        probe the app, learn which actions are watched
                        (do failed logins get rate-limited? do 403s alert?)
2. STAY UNDER THE LINE  spread activity across time, accounts, and source IPs
                        so no single counter crosses a threshold
3. ACHIEVE FOOTHOLD     brute force / credential stuffing / enumeration that
                        would trip an alert on a monitored system
4. ESCALATE & PERSIST   create accounts, change roles, plant access -- none
                        of it reviewed because none of it is logged
5. ACT ON OBJECTIVE     exfiltrate data or move laterally at leisure
6. COVER TRACKS         where logs exist locally, forge or erase them so the
                        post-incident investigation finds nothing
```

The vulnerability lives at every stage: if security-relevant events are not **generated**, steps 3–5 are invisible; if they are generated but not **collected and correlated**, the slow-and-distributed shaping in step 2 defeats naive counters; if they are collected but no one **responds**, even a fired alert changes nothing. Each pattern below is a concrete instance of an attack that succeeds *because* one of those stages is broken.

## Attack Patterns That Thrive on Missing Detection

### 1. Low-and-Slow Brute Force

On a monitored system, hammering a login endpoint trips a per-account or per-IP threshold within seconds. Against an app that logs nothing (or logs failures without aggregating them), the attacker simply slows down below any human's ability to notice and keeps going indefinitely.

```
# Naive burst -- would trip any rate limiter or alert
for pw in wordlist:
    POST /login  user=alice  password=$pw     # 1000 tries/sec, obvious

# Low-and-slow -- one attempt every few minutes, forever
# No per-account failure counter, no alert on sustained failures
#   09:03  /login alice  FAIL
#   09:11  /login alice  FAIL
#   09:19  /login alice  FAIL   ... days later ...  SUCCESS
```

**Detection gap**: failed logins are not counted per account over a long window, so a steady trickle of failures never crosses a threshold and never alerts.

### 2. Distributed Credential Stuffing

The attacker replays millions of username/password pairs leaked from other breaches. To evade per-IP limits, requests are spread across a large botnet or proxy pool, and each account is tried only a handful of times.

```
# Each source IP makes only a few requests -- individually unremarkable
203.0.113.7   -> POST /login  bob@x.com    (valid pw from a prior breach) OK
198.51.100.4  -> POST /login  carol@x.com  FAIL
192.0.2.55    -> POST /login  dave@x.com   (valid pw) OK
# Thousands of account takeovers accumulate, but no single IP or account
# stands out. Success events are never correlated with the stuffing pattern.
```

**Detection gap**: logins are not aggregated across the *whole* endpoint. Nobody watches for "a spike in logins succeeding from never-before-seen IPs" or "many distinct accounts, one attempt each, one shared user-agent."

### 3. Username / Account Enumeration

Before stuffing credentials, attackers build a list of valid accounts by abusing responses that differ for existing vs. non-existing users (login, registration, and password-reset endpoints).

```
POST /reset  email=alice@x.com   -> "We sent a reset link"     (exists)
POST /reset  email=ghost@x.com   -> "No account with that email" (does not)
# The attacker scripts this across a huge email list to harvest valid users.
# Thousands of reset probes generate zero security log entries.
```

**Detection gap**: validation and lookup endpoints do not log high-rate, high-cardinality probing, so a scan of tens of thousands of emails looks like ordinary traffic.

### 4. Object / ID Enumeration (IDOR Probing)

Having authenticated as one low-value user, the attacker walks predictable identifiers to reach other users' data. Each request is individually "authorized" for the session, so nothing is denied — and nothing that *should* look suspicious is recorded.

```
GET /api/invoices/1001   -> 200 (mine)
GET /api/invoices/1002   -> 200 (someone else's -- BOLA)
GET /api/invoices/1003   -> 200
# One session pulling thousands of sequential object IDs in minutes is a
# textbook scraping signature -- but only if per-session request rate and
# object-access breadth are logged and alerted on. Here they are not.
```

**Detection gap**: access to objects is not logged with actor + object owner, so "user X read 5,000 records belonging to other users in 4 minutes" is never surfaced.

### 5. Authorization Probing (403 Walking)

The attacker maps the application's privileged surface by requesting admin and internal paths, noting which return 403 (exists, forbidden) versus 404 (absent). Every 403 is a signpost pointing at a function worth attacking.

```
GET /admin            -> 403   (exists!)
GET /admin/users      -> 403   (exists!)
GET /admin/export     -> 403   (exists!)
GET /internal/debug   -> 404
# Hundreds of forced-browsing requests, most returning 403.
# Access-control denials are the single highest-signal security event --
# and they are exactly what un-instrumented apps forget to log.
```

**Detection gap**: authorization failures (HTTP 403) are not logged at all, or are buried in a web-server access log nobody reads, so a burst of denials never triggers review.

### 6. Input-Validation Probing (Injection & Traversal Recon)

Before a working injection, an attacker sends many malformed inputs to find where validation is weak — quote marks, path-traversal sequences, template syntax, oversized fields. Server-side validation failures are a strong early-warning signal that is routinely discarded.

```
GET /search?q=' OR '1'='1              -> validation/parse error
GET /file?name=../../../../etc/passwd  -> rejected
POST /profile  name={{7*7}}            -> rejected
# Each rejection is a probe. Logged and aggregated, a rash of validation
# failures from one source screams "someone is fuzzing us."
# Unlogged, the attacker enumerates weaknesses in total silence.
```

**Detection gap**: input-validation failures are treated as ordinary user error and dropped, so reconnaissance for injection and traversal produces no monitored signal.

### 7. Session & Token Abuse

A stolen session cookie or bearer token is replayed from a new location and device. Without logging that ties sessions to their origin, the same token appearing simultaneously in two countries raises no flag.

```
Session ABC123 created:  src_ip=198.51.100.10  ua="Chrome/Win"  geo=US
Session ABC123 reused:   src_ip=203.0.113.200  ua="curl/8.4"    geo=elsewhere
# Concurrent use of one session from two continents is a classic takeover
# signal -- but only detectable if session events record IP, device, and geo.
```

**Detection gap**: session creation and reuse are not logged with context, so impossible-travel and device-change signals are never computed.

### 8. Privilege Escalation & Rogue Account Creation

Once inside, the attacker grants themselves power: adds an admin account, elevates their own role, or attaches a new API key. These are among the most security-critical events in any system — and are frequently logged nowhere the security team can see.

```
POST /admin/users            create user "svc-backup" role=admin
PATCH /users/me/role         self -> "administrator"
POST /users/me/api-keys      new long-lived key issued
# A reviewed audit trail of role/permission changes would catch every one.
# With no such trail, the new admin persists indefinitely.
```

**Detection gap**: high-value account and permission changes are not logged with before/after state and actor, so persistence mechanisms are invisible.

### 9. Lateral Movement & Pivoting

From a first foothold the attacker reaches other services, internal APIs, and databases. Because each hop uses valid (stolen) credentials and no service correlates access across the environment, the movement blends into normal service-to-service traffic.

```
app-server --(stolen svc token)--> internal-billing-api   200
app-server --(same token)--------> user-export endpoint    200
app-server --(same token)--------> analytics DB replica    200
# No centralized log correlates one identity suddenly touching many services
# it never touched before. Each service sees only its own slice.
```

**Detection gap**: logs live in per-service silos, never centralised or correlated, so cross-service anomalies (one identity, many new destinations) are never assembled into a picture.

### 10. Slow Data Exfiltration Below Thresholds

Rather than one giant download that a volume alert might catch, the attacker drips data out — small paginated pulls, spread over days, sometimes to a benign-looking destination.

```
GET /api/customers?page=1&size=50   ...  (repeat for weeks)
# 50 records * many pages * many days = the whole database, quietly.
# No alert on cumulative export volume per user, so the trickle is invisible.
```

**Detection gap**: there is no cumulative, per-actor accounting of sensitive-record access, so exfiltration paced under any per-request limit never registers.

## Attacks Against the Logs Themselves

The patterns above exploit logs that were never written. The next three target logs that *are* written — because logs that an attacker can forge, poison, or erase are barely better than no logs at all.

### 11. Log Injection (Forging Entries)

When user-controlled data is written into logs without neutralising newlines and control characters, an attacker embeds fake log lines. This corrupts the record, frames other users, and can break log parsers or downstream dashboards.

```
Attacker submits a username containing a newline plus a forged entry:

  username = "attacker\n2026-08-28 09:00:00 INFO Login success: user=admin"

Naive code:  logger.info("Login failed: user=" + username)

Resulting log file:
  2026-08-28 08:59:59 WARN Login failed: user=attacker
  2026-08-28 09:00:00 INFO Login success: user=admin   <-- forged by attacker
```

**Why it works**: untrusted input is concatenated straight into a line-oriented log with no encoding (CWE-117), so the attacker controls what "the logs say."

### 12. Log Erasure & Tampering (Anti-Forensics)

An attacker who reaches the host deletes or edits local log files to remove evidence — frequently the very first post-exploitation action. If logs live only on the compromised box and are world-writable, the trail simply disappears.

```
# Classic anti-forensics on a compromised host
$ echo > /var/log/app/security.log      # truncate the evidence
$ sed -i '/203.0.113.200/d' access.log  # surgically remove attacker IP
$ history -c                             # wipe the shell trail
# If nothing was shipped off-box, the investigation now has nothing.
```

**Why it works**: logs are stored locally and mutably, so whoever controls the host controls the evidence. Only append-only, off-box copies survive.

### 13. Blinding the Pipeline

Instead of erasing individual entries, a sophisticated attacker disables logging or breaks the shipping pipeline — stops the log agent, fills the disk so writes fail silently, or lets a monitoring certificate expire — then operates in the resulting blind spot.

```
$ systemctl stop filebeat        # log shipper no longer forwards events
$ pkill -f auditd                # host audit daemon silenced
# Or subtler: monitoring TLS cert expired months ago and nobody noticed,
# so the SIEM has been receiving nothing -- a silent detection outage.
```

**Why it works**: the *health* of the logging pipeline is itself unmonitored, so a detection outage looks identical to "quiet, nothing happening."

### 14. Alert Fatigue & Signal Drowning

Where alerts do exist but are noisy and untuned, the attacker exploits the humans. A flood of benign-looking activity buries the one real signal, or the team has already muted the channel because it cries wolf hourly.

```
# Generate thousands of low-value alerts to bury the real one
- trigger harmless 404s and validation errors en masse
- the genuine "new admin created" alert arrives in a stream of noise
- an untuned, un-owned alert queue means it is never triaged
```

**Why it works**: detection without *tuning* and *ownership* is theatre; an alert nobody can act on is functionally the same as no alert.

## The Attacker's Perspective

Missing detection changes the attacker's whole calculus. Time stops being a risk and becomes a resource: with no clock ticking toward discovery, the patient attacker always wins. The table maps each goal to the detection gap it relies on and the control that closes it.

| Attacker goal | Detection gap relied upon | What closes it |
|---|---|---|
| Guess credentials unnoticed | Failed logins not counted per account/endpoint | Aggregated auth logging + threshold alerts |
| Take over many accounts | Successful logins not correlated across IPs | Endpoint-wide correlation, impossible-travel checks |
| Map privileged surface | 403 denials never logged | Log every access-control failure and alert on bursts |
| Scrape other users' data | Object access not tied to actor/owner | Per-actor access accounting and rate alerts |
| Persist via rogue admin | Role/permission changes unlogged | Audit trail of high-value actions with before/after |
| Move laterally unseen | Logs siloed per service | Centralised logs (SIEM) with cross-service correlation |
| Exfiltrate slowly | No cumulative per-actor volume tracking | Aggregate export/read accounting with alerts |
| Rewrite the story | User input logged unescaped (log injection) | Neutralise/encode data before logging (CWE-117) |
| Erase the evidence | Local, mutable, world-writable logs | Append-only, off-box, access-controlled storage |
| Operate in a blind spot | Pipeline health unmonitored | Monitor the monitoring (heartbeats, cert/expiry checks) |

> The through-line: none of these are exotic exploits. They are ordinary attacks made *successful* by the absence of eyes. Fixing this category rarely blocks the first request — it shrinks the attacker's dwell time from months to minutes and guarantees there is evidence to act on.

## Next Steps

- **[Prevention](./prevention.html)**: Layered defences that close each of these detection gaps.
- **[Examples](./examples.html)**: Vulnerable vs. secure logging you can copy, in Python, Node, and Java.
- **[Overview](./overview.html)**: Concepts, business impact, and where this sits in the OWASP Top 10.
- **[Hands-On Lab](./lab/insufficient-logging-monitoring/)**: Practise spotting undetected attacks in a safe, isolated environment.

*Edition note: This is A10:2017. In the OWASP Top 10 2021 it became A09:2021 – Security Logging and Monitoring Failures, broadened but conceptually the same. This lesson keeps the 2017 framing.*
