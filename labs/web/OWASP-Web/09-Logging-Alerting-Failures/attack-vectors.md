# A9:2025 — Logging & Alerting Failures: Attack Vectors

## Table of Contents

- [Understanding the Detection Gap](#understanding-the-detection-gap)
- [Core Attack Flow](#core-attack-flow)
- [Attack Patterns](#attack-patterns)
- [Chaining: A Full Undetected Campaign](#chaining-a-full-undetected-campaign)
- [Next Steps](#next-steps)

## Understanding the Detection Gap

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are described so you can recognise, detect, and fix these gaps in systems you own or are authorised to test. The "attack" in this category is usually the *absence* of a reaction, not a clever payload.

Every other Top 10 category describes how an attacker gets in. This one describes how they **stay in**. When logging and alerting fail, an attacker's actions produce no alert, no page, and no response — so they can move slowly, deliberately, and without pressure. The attacker's strategy shifts from "exploit fast before someone notices" to "there is no one to notice, so take your time."

Attacks against this category fall into two families:

- **Operating under the radar**: conducting reconnaissance, credential attacks, privilege abuse, and exfiltration in a way that generates no alert because the events are unlogged, uncorrelated, or below a threshold.
- **Attacking the logs themselves**: injecting forged entries, deleting evidence, or deliberately flooding the alert pipeline so real signals are lost (alert-fatigue exploitation).

### Core Attack Flow

```
1. Probe quietly
   ↓
   Enumerate users, endpoints, params -- watch for any reaction (rate-limit, block, challenge)
2. Confirm blindness
   ↓
   No lockout, no CAPTCHA, no slowdown -> conclude nothing is watching
3. Operate at leisure
   ↓
   Slow credential stuffing, privilege abuse, lateral movement -- paced under any threshold
4. Achieve objective
   ↓
   Exfiltrate data / persist -- still no alert
5. Cover tracks
   ↓
   Delete or forge logs, or bury the event under injected noise
```

Step 2 is the pivot unique to this category. An attacker's first job is to *measure your detection capability*. Every unpunished probe is a data point telling them how far they can go.

## Attack Patterns

### 1. Reconnaissance With No Reaction

The attacker sends a burst of abnormal requests purely to see what the application does in response. Silence is the answer they are hoping for.

```
# Forced browsing / endpoint enumeration
GET /admin           -> 403
GET /api/v1/internal -> 404
GET /backup.zip      -> 404
GET /.git/config     -> 200   (!)

# No rate limit, no alert on the burst of 404s, no alert on the sensitive-path hit
```

**The failure**: a spike of 404s and 403s against sensitive paths from one source is a textbook recon signature. If no rule counts "many errors from one IP in a short window," the map-making phase is free and invisible.

### 2. Username Enumeration via Response Differences

Login, registration, and password-reset flows often reveal whether an account exists — through different messages, status codes, or response times. Enumeration is quiet by nature: each request looks like a normal, failed login.

```
POST /login  {"user":"alice","pass":"x"}  -> "Incorrect password"    (alice exists)
POST /login  {"user":"zoe","pass":"x"}    -> "No such user"          (zoe does not)

# 50,000 requests build a validated list of real accounts.
# Each is a "failed login" -- individually boring, collectively an attack.
```

**The failure**: without logging failures *with the attempted username and source*, and without a rule that correlates "many distinct usernames probed from one IP," enumeration never rises above background noise.

### 3. Slow ("Low-and-Slow") Credential Stuffing

Armed with a breached credential list, the attacker tries reused passwords — but paces the attack to stay under any naive threshold, and rotates source IPs.

```
# Naive detection: "alert if > 10 failures per account per minute"
# Attacker response: 1 attempt per account, spread across 40,000 accounts,
#                    1 request/sec, rotating through a proxy pool.

for user, pw in breached_list:      # 40,000 pairs
    try_login(user, pw)             # distributed, throttled, IP-rotated
    sleep(1)
```

**The failure**: per-account thresholds miss the horizontal attack. The signal is only visible when you correlate across accounts ("one IP or ASN touching thousands of distinct accounts") and across the fleet ("global failure rate spiking"). No correlation rule means no detection.

### 4. Privilege Abuse and Access-Control Probing

An authenticated low-privilege user pokes at objects and endpoints they should not reach. Even when the app correctly *blocks* them, each denial is an intelligence signal — and a warning that should be logged.

```
GET /api/orders/1001   -> 200  (own order)
GET /api/orders/1002   -> 403  (someone else's -- IDOR probe)
GET /api/orders/1003   -> 403
POST /api/admin/users  -> 403  (privilege probe)

# Each 403 is a blocked attack AND an early-warning event.
```

**The failure**: teams often log only *errors* and successes, treating a 403 as "working as intended" and therefore not worth recording. But a stream of authorization denials from one account is one of the strongest pre-breach indicators there is. Not logging denials discards your best early warning.

### 5. Data Exfiltration Below the Volume Radar

After gaining access, the attacker pulls data. Done in one giant query it might stand out; paginated and paced, it blends into normal usage.

```
GET /api/customers?page=1&size=100
GET /api/customers?page=2&size=100
...            (repeat 5,000 times over 8 hours)

# Total: 500,000 records exported. Per-request it looks ordinary.
```

**The failure**: without a baseline of normal per-user data access and an alert on deviation ("this account read 500x its daily average"), bulk exfiltration is indistinguishable from a busy day. Volume/anomaly alerting is the control that would catch it.

### 6. Lateral Movement Across Unstitched Services

In a microservices or cloud estate, an attacker who compromises one service pivots to others. If each service logs in isolation with no shared correlation ID, no single view ever assembles the movement into one story.

```
[auth-svc]    login from new IP for svc-account            (logged, in silo A)
[orders-svc]  svc-account reads all orders                 (logged, in silo B)
[billing-svc] svc-account exports invoices                 (logged, in silo C)

# Three benign-looking lines in three systems. No correlation_id joins them.
# The attack is only visible when the three are stitched together.
```

**The failure**: logs without a propagated correlation/trace ID cannot be joined. The attack exists in the data but not in any single view, so no analyst and no rule ever sees the whole.

### 7. Log Injection / Forging (CWE-117)

When untrusted input is written to logs without neutralisation, an attacker controls part of the log. They can forge entries, break log parsers, or inject fake events to frame another user or hide their own.

```
# Vulnerable: raw username concatenated into a line-based log
username = "admin\n2025-08-28 14:00:00 INFO  Login success user=victim ip=10.0.0.9"
log.info("Login failed for user=" + username)

# Resulting log file now contains a FORGED "Login success" line:
2025-08-28 14:00:00 INFO  Login failed for user=admin
2025-08-28 14:00:00 INFO  Login success user=victim ip=10.0.0.9   <-- injected
```

**The failure**: newline and control characters in unescaped input let the attacker write arbitrary log lines. This corrupts investigations, poisons SIEM parsers, and can even trigger code paths in a log viewer. The fix is to encode/escape untrusted data and prefer structured logging where fields cannot bleed into each other.

### 8. Log Deletion and Tampering

An attacker who reaches the host clears the evidence. If logs live only where the workload runs, they are within reach of anyone who compromises it.

```
# On a compromised container / host
> /var/log/app/security.log        # truncate the security log
rm -f /var/log/app/*.log           # or delete outright
journalctl --rotate --vacuum-time=1s   # discard system journals

# Container restart also wipes ephemeral logs -- the attacker just triggers a crash.
```

**The failure**: on-host, mutable logs offer no forensic value after compromise. Only logs shipped off-host in real time to append-only, access-controlled storage survive the attacker who owns the box.

### 9. Timestamp and Clock Manipulation

Investigations depend on ordering events across systems. If clocks are unsynchronised — or the attacker can influence a timestamp — the timeline becomes unreliable and correlation breaks.

```
# Symptoms that defeat correlation:
- Service A logs in local time, Service B in UTC, Service C is 4 minutes off (no NTP)
- Application trusts a client-supplied "event_time" field
- Attacker sets device clock backward to reorder or hide events

Result: responders cannot establish "what happened first" -- causality is lost.
```

**The failure**: without synchronised UTC clocks (NTP) and server-assigned timestamps, the sequence of an incident cannot be reconstructed, and every derived conclusion is contestable.

### 10. Alert-Fatigue Exploitation (Flooding)

A sophisticated attacker turns a noisy alerting setup into cover. By deliberately generating a flood of low-value alerts, they exhaust or desensitise responders — then conduct the real attack inside the noise.

```
# Step 1: trigger thousands of benign-but-alerting events
for i in range(100000):
    hit_endpoint_that_always_alerts()      # e.g. a known-noisy 404 rule

# Step 2: responders mute the channel / raise the threshold to cope
# Step 3: run the real intrusion while the alert everyone needed is buried
```

**The failure**: an un-deduplicated, untuned alert pipeline is a weapon that can be turned against its owner. Alert fatigue is not only an operational nuisance — it is an exploitable condition. Deduplication, rate-limiting of identical alerts, and severity scoring are the defenses.

### 11. Killing or Blinding the Pipeline

Rather than evade detection, the attacker disables it — and counts on no one noticing that the logs went quiet.

```
# Stop the shipping agent so nothing reaches the SIEM
systemctl stop fluent-bit

# Or fill the disk so logging silently fails open
dd if=/dev/zero of=/var/log/filler bs=1M   # log writes now error and are dropped

# Or revoke the log-forwarder's credentials to the central store
```

**The failure**: if you do not alert on the *absence* of logs (a "dead man's switch" / heartbeat), an attacker can simply turn detection off. Silence should itself be an alarm.

### 12. Logging Secrets to Turn Logs Into a Target (CWE-532)

Sometimes the vulnerability is what you *do* log. Applications that dump full requests, tokens, or PII into logs create a concentrated, often less-protected copy of their most sensitive data — a prize for anyone who reaches the log store.

```
DEBUG  Incoming request headers: {Authorization: "Bearer eyJhbGciOi...", Cookie: "session=..."}
DEBUG  User record: {ssn: "123-45-6789", card: "4111111111111111", password: "hunter2"}

# The log aggregator, backups, and anyone with read access now hold live secrets.
```

**The failure**: logs are frequently readable by more people and systems than the primary datastore, and are retained for a long time. Writing secrets or full PII to them turns a logging feature into a data-exposure vulnerability.

## Chaining: A Full Undetected Campaign

Individually, the patterns above are gaps. Chained, they are a breach that no one sees until it is far too late:

```
1. Recon        -- enumerate endpoints; no rule counts the 404 spike        (Pattern 1)
2. Enumerate    -- harvest valid usernames from response differences        (Pattern 2)
3. Access       -- low-and-slow credential stuffing lands one account       (Pattern 3)
4. Escalate     -- probe authz; 403s are never logged, so no warning        (Pattern 4)
5. Move         -- pivot across services; no correlation_id stitches it      (Pattern 6)
6. Exfiltrate   -- paginate data under the (absent) volume threshold        (Pattern 5)
7. Persist/hide -- forge and delete logs; stop the shipping agent           (Patterns 7, 8, 11)

Detection points that SHOULD have fired: 1, 2, 3, 4, 5, 6.
Detection points that DID fire: 0.
Outcome: breach discovered 90 days later -- by a third party.
```

The lesson of the chain is that this category offers **many** chances to catch an attacker — recon, enumeration, credential abuse, privilege probing, lateral movement, exfiltration. Each is a tripwire you either built or you did not. Prevention is about making sure at least several of these tripwires exist, fire, and reach someone who acts.

## Next Steps

- **[Overview](./overview.html)**: What the category is and why the 2025 edition centers alerting.
- **[Prevention](./prevention.html)**: Build the tripwires — structured logging, correlation, tuned alerting, and response.
- **[Examples](./examples.html)**: Vulnerable vs. secure logging code and concrete SIEM detection rules.
- **[Hands-On Lab](./lab/logging-alerting-failures/)**: Run an undetected attack, then instrument the app so it fires.

---

*Part of the [OWASP Top 10 Educational Repository](/learn/web) — A9:2025, Logging & Alerting Failures.*
