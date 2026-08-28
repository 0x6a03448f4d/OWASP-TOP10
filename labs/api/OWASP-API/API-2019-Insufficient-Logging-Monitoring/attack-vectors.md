# API10:2019 Insufficient Logging & Monitoring - Attack Vectors

## Table of Contents
- [Understanding the Attack Vectors](#understanding-the-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Attacks That Proceed Undetected](#attacks-that-proceed-undetected)
- [Log Injection, Forging, and Tampering](#log-injection-forging-and-tampering)
- [Chaining: Why Blindness Amplifies Everything](#chaining-why-blindness-amplifies-everything)

## Understanding the Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are described so you can recognise these patterns in telemetry for systems you own or are authorised to test, and build the detections that catch them.

Insufficient Logging & Monitoring is unusual among the OWASP API risks: there is no payload that "exploits" it directly. Instead, the vulnerability is the **absence of a witness**. Every technique on this page is an ordinary attack—credential stuffing, enumeration, scraping—paired with the crucial fact that, against a blind API, **none of it triggers an alert**. The attacker's advantage is time: they can be slow, careful, and thorough because nobody is counting.

Two angles matter here:

- **Attacks that run undetected** because the security events were never logged or never monitored.
- **Attacks on the logs themselves**—injecting forged entries or tampering with records—to defeat whatever monitoring does exist and to cover tracks.

## Core Attack Flow

```
1. Probe quietly
   ↓
   Send ordinary-looking requests; each one individually looks legitimate
2. Observe that nothing pushes back
   ↓
   No lockout, no 429, no challenge, no change in behaviour
3. Scale up under the radar
   ↓
   Increase rate/breadth; a blind API never counts the failures
4. Achieve the goal + persist
   ↓
   Take over accounts, harvest objects, exfiltrate data
5. (Optional) Cover tracks
   ↓
   Forge or delete log entries if logs are reachable and unprotected
```

## Attacks That Proceed Undetected

### 1. Slow, Low-and-Slow Credential Stuffing

The attacker replays leaked username/password pairs, deliberately pacing requests to stay under naive per-IP limits and spreading them across many source addresses.

```
POST /api/v1/auth/login   {"user":"a@corp.com","pass":"<leaked-1>"}   -> 401
POST /api/v1/auth/login   {"user":"b@corp.com","pass":"<leaked-2>"}   -> 401
POST /api/v1/auth/login   {"user":"c@corp.com","pass":"<leaked-3>"}   -> 200  # hit
# thousands more, paced and distributed
```

**Why it stays invisible**: if failed logins are not logged with client and source context, and if there is no alert on the *rate* of 401s, a 5%-hit-rate stuffing run looks like a trickle of unrelated typos.

**What detection needs**: authentication-failure logging plus alerting on 401 rate per endpoint, per source, and per account.

### 2. Object-ID (BOLA) Enumeration

The attacker walks an identifier space to find objects they can read. Where authorization is broken, they harvest data; where it holds, they generate 403s.

```
GET /api/v1/invoices/1001   -> 200   # not mine, but returned (BOLA)
GET /api/v1/invoices/1002   -> 403
GET /api/v1/invoices/1003   -> 200
GET /api/v1/invoices/1004   -> 403
...            # sequential walk across the id range
```

**Why it stays invisible**: the 403s are the fingerprint of enumeration, but if authorization denials are not logged with the *subject* and the *object id*, and if the denied-access rate is not monitored, one client touching thousands of objects it does not own raises nothing.

**What detection needs**: authz-denial logging with subject + object id, and an alert on a single subject accumulating many denials or accessing many distinct object ids.

### 3. High-Volume Scraping Through the Front Door

Every request is well-formed and returns 200; only the aggregate volume from one caller reveals harvesting.

```
GET /api/v1/profiles/000001  -> 200
GET /api/v1/profiles/000002  -> 200
GET /api/v1/profiles/000003  -> 200
# 200,000 successful requests from one token over 6 hours
```

**Why it stays invisible**: aggregate dashboards show only "traffic is up." Without per-client / per-token volume monitoring, a full-dataset scrape is indistinguishable from popularity.

**What detection needs**: per-client throughput baselines and an alert when one caller's successful-request volume deviates sharply from normal.

### 4. Authorization-Failure Probing (403 Sweeps)

Before committing to an attack, an adversary maps which endpoints and objects are reachable—deliberately generating denials to learn the boundaries.

```
GET  /api/v1/admin/users        -> 403
POST /api/v1/admin/settings     -> 403
GET  /api/v1/internal/metrics   -> 403
DELETE /api/v1/users/42         -> 403
# a burst of denied privileged calls = reconnaissance
```

**Why it stays invisible**: each 403 is "working as intended," so teams often discard them. But a *burst* of denials against privileged routes from one caller is a loud signal—if anyone is counting.

**What detection needs**: treat 403 as a security event, not noise; alert on clustered denials against sensitive routes.

### 5. Stolen-Token / Session Abuse and Replay

A leaked or phished token is replayed. Each call is authenticated and returns 200, so it looks legitimate.

```
Authorization: Bearer <stolen-token>
# same token seen from:
203.0.113.10  (New York)   09:14
198.51.100.7  (Frankfurt)  09:15
192.0.2.55    (Singapore)  09:17
# one token, three continents, three minutes
```

**Why it stays invisible**: without logging the token/client identifier alongside source IP and geo, and without correlating a single token across sources, impossible-travel and multi-origin replay are simply unseen.

**What detection needs**: per-token usage logging and alerting on a token used from many IPs/geos or far above its normal call volume.

### 6. Input-Validation Probing and Fuzzing

The attacker sends malformed and hostile payloads to find parser weaknesses and injection points.

```
GET /api/v1/search?q=' OR '1'='1
GET /api/v1/search?q=<script>alert(1)</script>
GET /api/v1/search?q=../../../../etc/passwd
POST /api/v1/orders   {"qty": -2147483648}
```

**Why it stays invisible**: if the API silently rejects bad input without logging the rejection, endpoint, and reason, a systematic fuzzing campaign produces no record at all—the defender never learns they were being probed.

**What detection needs**: log validation failures with endpoint + reason, and alert on rejections clustering on one endpoint or from one caller.

## Log Injection, Forging, and Tampering

Where monitoring *does* exist, attackers target the logs themselves—either to poison them or to erase evidence.

### 7. Log Injection via Unencoded Input (CRLF / Forged Entries)

If untrusted input is written into logs verbatim, an attacker can embed newline characters to forge additional log lines—framing another user, hiding their own action, or breaking a log parser.

```
# Attacker sends a username containing CRLF + a fake line:
username = "attacker\r\n2026-08-28 14:05:02 INFO login success user=admin ip=10.0.0.9"

# Naive logger writes it straight through:
2026-08-28 14:05:01 WARN login failure user=attacker
2026-08-28 14:05:02 INFO login success user=admin ip=10.0.0.9   <-- forged
```

**Payoff**: fabricated events mislead responders, poison SIEM correlation, or inject content that a downstream log viewer interprets (log-based XSS in a dashboard). The fix is to **encode/escape untrusted data before logging** and to prefer structured logging where fields cannot break the record boundary.

### 8. Log Tampering and Deletion to Cover Tracks

An intruder who reaches the host looks for the record of their own activity.

```
# If logs are local, writable, and unsigned:
$ shred -u /var/log/api/access.log      # destroy evidence
$ sed -i '/203.0.113.44/d' /var/log/api/auth.log   # selectively erase
```

**Payoff**: the forensic trail disappears, and the breach becomes unprovable and unbounded. The defence is to **ship logs off-box in real time** to an append-only / write-once store the application host cannot rewrite, so a compromise of the host cannot rewrite history.

### 9. Sensitive Data Harvested From the Logs Themselves

When secrets are logged in cleartext, the log store becomes the softest target.

```
# Anti-pattern: tokens and PII written into logs
INFO request user=jane token=eyJhbGciOi... card=4111111111111111 ssn=123-45-6789
```

**Payoff**: an attacker (or an over-broadly-permissioned insider) reads live credentials and regulated data straight out of the logs—no application exploit required. Never log secrets, tokens, passwords, or PII; log *identifiers and outcomes* instead.

## Chaining: Why Blindness Amplifies Everything

Insufficient logging and monitoring rarely appears alone in a breach report—it is the force multiplier that turns a contained incident into a catastrophic one:

```
Broken auth (weak lockout)            -> credential stuffing succeeds
        +
No 401-rate alerting                   -> the stuffing runs for weeks
        +
No per-client volume monitoring        -> the taken-over accounts scrape data unseen
        +
Local, unprotected logs                -> the little evidence there is gets wiped
        =  a small auth weakness becomes an unbounded, unprovable breach
```

Another common chain:

```
BOLA on /invoices/{id}    -> attacker can read others' records
        +
403s and 200s not monitored -> the enumeration walk is never noticed
        -> full dataset exfiltrated; discovered months later by a researcher
```

## Key Takeaways

1. **The vulnerability is the missing witness**—ordinary attacks succeed quietly because nothing is counting.
2. **Rate-of-error is the loudest signal you are ignoring**—spikes of 401/403/429 mark stuffing, enumeration, and abuse in progress.
3. **Per-client and per-token context is what makes an attack visible**—aggregate dashboards hide slow, distributed, single-caller abuse.
4. **Logs are an attack surface too**—encode untrusted input to stop forging, and ship logs off-box so they cannot be wiped.
5. **Never let the log store become the breach**—log identifiers and outcomes, never secrets or PII.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build logging, centralisation, alerting, and response that catch these early
- **[Code Examples](examples.md)**: Structured security logging and SIEM/alerting rules that detect each pattern above
- **[API Security Learning Path](/learn/api)**: Return to the full OWASP API Top 10
- **[Practice](/practice)**: Hunt for these patterns in sample telemetry
