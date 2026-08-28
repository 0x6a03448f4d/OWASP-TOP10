# API10:2019 Insufficient Logging & Monitoring - Overview

## Table of Contents
- [What is Insufficient Logging & Monitoring?](#what-is-insufficient-logging--monitoring)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detection](#prevalence-and-detection)
- [Common Misunderstandings](#common-misunderstandings)
- [A Note on the 2023 Edition](#a-note-on-the-2023-edition)

## What is Insufficient Logging & Monitoring?

**Insufficient Logging & Monitoring** (API10 in the 2019 OWASP API Security Top 10) is not a flaw an attacker *exploits*—it is the flaw that lets every other attack proceed **undetected**. When an API fails to record security-relevant events, fails to centralise and watch those records, and fails to alert and respond when something looks wrong, an intruder can probe, enumerate, brute-force, and exfiltrate for days, weeks, or months with nobody noticing.

This category is defined by three linked failures, any one of which is enough to be blind:

- **Logging**: security-relevant events (failed logins, authorization denials, input-validation failures, token errors) are never written down, or are written without enough context to be useful.
- **Monitoring**: whatever is logged is scattered across hosts, never centralised, and never actively watched.
- **Alerting & response**: even when a pattern is visible in the data, no threshold fires, no human is paged, and no incident-response process kicks in.

The OWASP definition is deliberately outcome-focused: the problem is measured by how long an attack can run before it is seen. The industry term for that gap is **dwell time**—the interval between initial compromise and detection. Insufficient logging and monitoring is what makes dwell time long.

### Core Concept

```
Sufficient logging & monitoring:
  Auth events   -> every login success/failure logged with client id + source IP
  Authz events  -> every 403 / object-access denial logged with subject + object id
  Validation    -> every rejected/malformed input logged with endpoint + reason
  Format        -> consistent structured (JSON) records, machine-parseable
  Centralised   -> shipped to a SIEM/log store, tamper-resistant, time-synced
  Alerting      -> tuned thresholds fire on spikes of 401/403/429 + enumeration
  Response      -> alerts feed an incident-response runbook with an owner

Insufficient logging & monitoring:
  Auth events   -> failed logins not recorded; brute force is invisible
  Authz events  -> 403s dropped; BOLA enumeration leaves no trace
  Validation    -> malformed/hostile input silently discarded
  Format        -> free-text logs, no client/object context, unparseable
  Centralised   -> logs live only on the box, rotated away, never read
  Alerting      -> no thresholds; a 10,000-request scrape triggers nothing
  Response      -> breach first learned about from a third party, months later
```

### Why It's Critical for APIs

APIs concentrate several conditions that make missing telemetry especially costly:

- They are **machine-to-machine**, so there is no human watching a screen who might notice something "looks wrong." If the API does not log it, nobody sees it.
- They expose **enumerable, structured resources** (`/users/1`, `/users/2`, …), so abuse often looks like ordinary traffic—only the *rate and pattern* distinguish an attack, and only monitoring can see rate and pattern.
- They are **high-volume**, so a slow attack blends into the noise unless per-client and per-token baselines exist.
- They are the **direct interface to the data**, so an undetected attacker is exfiltrating records, not just poking at a login page.

## Why Does This Matter?

### Business Impact

- **Long dwell time, larger breach**: the damage from an intrusion scales with how long it runs undetected. Missing telemetry is a direct multiplier on breach cost and record count.
- **Breach discovered by outsiders**: a large share of breaches are first reported by a third party (a customer, a researcher, a payment processor, law enforcement) rather than caught internally—an outcome that is both more expensive and more reputationally damaging.
- **No forensic trail**: without logs you cannot answer the questions that follow every incident—what was accessed, whose data, for how long. That uncertainty forces worst-case breach notifications.
- **Regulatory exposure**: frameworks such as PCI-DSS, HIPAA, SOC 2, and GDPR explicitly require audit logging and timely detection. Insufficient monitoring is itself a compliance finding, independent of any breach.
- **Slow, blind response**: even once an incident is known, the absence of centralised, contextual logs turns containment into guesswork.

### Technical Impact

- **Credential stuffing and brute force run free**: without failed-login logging and rate-of-error alerting, an attacker can grind through leaked password lists indefinitely.
- **Authorization probing goes unseen**: a sweep of denied object accesses (the fingerprint of BOLA/IDOR enumeration) is invisible if 403s are not logged and counted.
- **Scraping is indistinguishable from use**: high-volume harvesting of data through legitimate endpoints leaves no alert if per-client volume is never monitored.
- **Attacker persistence is untracked**: stolen-token replay and abuse look like normal calls unless tokens are logged and correlated per client.
- **Tracks can be covered**: if logs are not integrity-protected and centralised, an intruder who reaches the host can edit or delete the very records that would expose them.

## Technical Context

### Failure Modes

The 2019 category is best understood as a checklist of things that are *not* happening. Each row below is a distinct way an API ends up blind.

| Failure mode | What is missing | Consequence |
|--------------|-----------------|-------------|
| Auth/authz failures not logged | Failed logins and 403 denials never recorded | Brute force and BOLA enumeration invisible |
| Input-validation failures not logged | Malformed/hostile payloads silently rejected | Probing and fuzzing leave no trace |
| No per-client / per-token monitoring | No baseline of normal volume per caller | Slow abuse blends into aggregate traffic |
| Logs lack context | No client id, endpoint, object id, or outcome | Records exist but cannot be investigated |
| No centralisation / SIEM | Logs stay on the host, rotated away | Nobody is watching; nothing correlates |
| No alerting thresholds | No rule fires on spikes or patterns | Data exists but no one is notified |
| No rate-of-error monitoring | 401/403/429 rates never trended | The clearest attack signal is ignored |
| Logs not integrity-protected | Writable, unsigned, non-centralised logs | Attacker edits or deletes the evidence |
| Sensitive data logged in cleartext | Tokens, passwords, PII written to logs | The log store itself becomes a breach target |

### What a Useful Security Event Looks Like

The difference between a log that helps and a log that does not is **context**. Compare:

```
# Useless: free text, no actor, no object, no outcome
ERROR user request failed

# Useful: structured, attributable, correlatable
{
  "ts": "2026-08-28T14:03:11.482Z",
  "event": "authz.denied",
  "outcome": "failure",
  "client_id": "acct_8842",
  "auth_subject": "user_1021",
  "source_ip": "203.0.113.44",
  "method": "GET",
  "endpoint": "/api/v1/invoices/{id}",
  "object_id": "inv_990771",
  "status": 403,
  "request_id": "b1f2c3d4"
}
```

With the structured record, a SIEM can answer "did `user_1021` just try to read 500 invoices that are not theirs?" The free-text line cannot answer anything.

### The Signals Monitoring Should Watch

- **Spikes in 401** (authentication failures) — credential stuffing / brute force.
- **Spikes in 403** (authorization failures) — object-ID or function-level enumeration.
- **Spikes in 429** (rate-limit hits) — scraping or automated abuse pushing limits.
- **High-volume 2xx from one client** on enumerable endpoints — successful scraping.
- **Sequential / patterned object ids** in requests — enumeration walking an id space.
- **One token from many IPs / geographies** — token theft and replay.
- **Input-validation rejections clustered on one endpoint** — fuzzing or injection probing.

## Real-World Impact

Rather than cite specific fabricated figures, it is more durable to describe the **classes of incident** that recur precisely because logging and monitoring were insufficient.

### Incident Class 1: Credential Stuffing That Ran for Months

**Pattern**:
- Attackers replay username/password pairs from prior third-party breaches against a login or token API.
- Failed authentications are not logged, or are logged but never counted against a threshold, so the sustained failure rate raises no alarm.

**Outcome**: A slice of accounts (those reusing passwords) is quietly taken over. The activity is frequently only recognised after downstream fraud, or after a customer reports it—long after the API could have flagged the failed-login spike.

**Root cause**: No authentication-failure logging with per-client context and no rate-of-error alerting.

### Incident Class 2: Object-ID Enumeration Discovered by a Researcher

**Pattern**:
- An endpoint like `/api/v1/records/{id}` is walked across a large id range.
- Where authorization is broken (BOLA), the attacker harvests records; where it holds, they generate a wave of 403s.
- Neither the successful harvest nor the 403 wave is monitored, so nothing fires.

**Outcome**: Bulk personal data is collected over hours or days. The organisation typically learns of it only when a security researcher or journalist demonstrates the enumeration—i.e., detection came from outside.

**Root cause**: No monitoring of denied-access rate and no per-client volume baseline that would have flagged one caller touching thousands of objects.

### Incident Class 3: High-Volume Scraping Mistaken for Traffic

**Pattern**:
- A public or lightly-authenticated API is harvested at scale to rebuild a competitor dataset or profile users.
- Because each request is individually well-formed and returns 200, aggregate dashboards show only "increased usage."

**Outcome**: A substantial fraction of the dataset is exfiltrated through the front door. Without per-client monitoring, the scrape is indistinguishable from growth until the data surfaces elsewhere.

**Root cause**: No per-client/per-token volume monitoring and no alerting on abnormal single-caller throughput.

> Note: these are recurring *incident classes*, not a single named breach. The durable lesson is identical across all of them—the attack technique varied, but the reason it succeeded quietly was always the same: security-relevant events were not logged, not centralised, and not alerted on.

## Prevalence and Detection

Insufficient logging and monitoring is difficult to see from the outside—an attacker cannot tell whether they are being watched—yet it is one of the most consistently reported weaknesses in breach post-mortems.

Rather than quote a single statistic, the defensible picture is:

- OWASP characterises this category as **hard for defenders to notice** (it produces no error the team sees) but **highly impactful**, because it is the multiplier on every other incident.
- The recurring pattern across public breach reports is a **long gap between compromise and discovery**, and a **large share of breaches first reported by an external party** rather than caught by the victim.
- The most common concrete gaps are **unlogged auth/authz failures, no centralised log store, and no alerting thresholds**—exactly the failure modes listed above.

## Common Misunderstandings

### Myth 1: "We have logs, so we are covered"

**Reality**: Having logs and *using* them are different things. Logs that are never centralised, never alerted on, and lack client/object context are write-only—they help nobody until after a breach, if at all.

### Myth 2: "Logging is an ops concern, not a security one"

**Reality**: Ops logging answers "is the service up?" Security logging answers "is someone attacking it?" The two overlap but are not the same; auth failures, authz denials, and validation rejections must be captured deliberately for security.

### Myth 3: "Log everything and we will find it later"

**Reality**: Volume without structure and alerting just hides the signal. You need *the right events, in a parseable format, with thresholds that page someone*—not a firehose nobody reads.

### Myth 4: "A spike in errors is just noise"

**Reality**: A spike in 401/403/429 is the single clearest signal of an attack in progress. Treating rate-of-error as noise is discarding your best early-warning system.

### Myth 5: "More detail in logs is always better"

**Reality**: Logging tokens, passwords, full card numbers, or PII in cleartext turns your log store into a second breach target and can itself violate regulation. Log *identifiers and outcomes*, never secrets.

### Myth 6: "If we are attacked, the logs will be there"

**Reality**: Logs that live only on the compromised host, are world-writable, or are unsigned can be edited or wiped by the intruder. Ship them off-box to a tamper-resistant store in real time.

## How This Differs from Related Issues

| Aspect | Insufficient Logging & Monitoring | Broken Authentication (API2) | Resource Consumption (API4) |
|--------|-----------------------------------|------------------------------|-----------------------------|
| **Nature** | Failure to *detect* attacks | Failure to *prevent* auth bypass | Failure to *limit* usage |
| **Exploited directly?** | No—it enables other attacks to run unseen | Yes | Yes |
| **Symptom** | Long dwell time, external discovery | Account takeover | Exhaustion / cost |
| **Fix domain** | Telemetry, SIEM, alerting, IR | Auth logic | Rate limits / quotas |

## Key Takeaways

1. **This is the flaw that hides the others**—it is measured in dwell time, not in a single exploit.
2. **Log the security events, not just the ops events**—auth failures, authz denials, and validation rejections, each with client and object context.
3. **Logging without monitoring is write-only**—centralise to a SIEM and put tuned thresholds on 401/403/429 and enumeration patterns.
4. **Protect the logs**—ship them off-box, make them tamper-resistant, and never write secrets or PII into them.
5. **Detection must connect to response**—an alert that pages nobody is the same as no alert.

## How to Identify if You're Vulnerable

- [ ] Are failed logins and token errors logged with client id and source IP?
- [ ] Are authorization denials (403) logged with the subject and the object id they were denied?
- [ ] Are input-validation failures logged with endpoint and reason?
- [ ] Is every security log a consistent, structured, machine-parseable record?
- [ ] Are logs shipped to a centralised, tamper-resistant store in real time?
- [ ] Do alerts fire automatically on spikes of 401/403/429 and on enumeration patterns?
- [ ] Is there per-client / per-token volume monitoring, not just aggregate traffic?
- [ ] Are clocks synchronised (NTP) and is retention long enough for investigation?
- [ ] Is untrusted data encoded before it is logged (no log injection)?
- [ ] Do alerts feed a real incident-response runbook with a named owner?

If you answered "no" or "not sure" to several of these, an attacker could be operating against your API right now without your knowledge.

## A Note on the 2023 Edition

In the 2019 OWASP API Security Top 10, Insufficient Logging & Monitoring was a **standalone entry (API10:2019)**. In the **2023** revision it was **dropped as a dedicated item**; the list changed shape and this concern is now treated as a cross-cutting operational practice rather than a numbered risk. That editorial change does *not* make the problem less real—detection capability is still essential, and it remains a numbered item (A09:2021) in the broader OWASP Top 10 for web applications. This lesson intentionally keeps the **2019 framing** because it states the requirement most clearly: an API must log security-relevant events, watch them, and respond.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attacks proceed undetected against a blind API
- **[Prevention](prevention.md)**: Build logging, monitoring, alerting, and response that see attacks early
- **[Examples](examples.md)**: Structured security logging in Python, Node, and Java, plus alerting/SIEM config
- **[API Security Learning Path](/learn/api)**: Return to the full OWASP API Top 10
- **[Practice](/practice)**: Apply these detection skills hands-on
