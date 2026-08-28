# A9:2025 — Logging & Alerting Failures: Overview

## Table of Contents

- [What Are Logging & Alerting Failures?](#what-are-logging--alerting-failures)
- [The 2025 Edition: From Monitoring to Alerting](#the-2025-edition-from-monitoring-to-alerting)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)
- [Self-Assessment](#self-assessment)
- [Next Steps](#next-steps)

## What Are Logging & Alerting Failures?

**Logging & Alerting Failures** occur when an application does not record security-relevant events with enough detail, does not turn those records into *timely, actionable alerts*, or does not act on the alerts it produces. Unlike most categories in the Top 10, this is not a flaw an attacker exploits to break in — it is a **detection and response gap** that lets every other attack proceed unnoticed, for longer, and with a worse outcome.

The failure is defined by silence. When authentication abuse, access-control violations, input-validation failures, or high-value actions leave no usable trace — or leave a trace that no one is watching — the organisation loses the ability to answer the three questions every incident turns on: *Did something happen? What exactly happened? And can we prove it afterwards?*

At its core, this category covers:

- **Insufficient logging**: security-relevant events (logins, failures, access-control denials, high-value transactions) are not recorded, or are recorded without the context needed to investigate.
- **Missing or mis-tuned alerting**: logs exist but no alert fires; or alerts are so noisy they are muted; or thresholds are set so high real attacks slip under them.
- **No correlation or detection logic**: individual events look benign in isolation because nothing joins them into an attack narrative.
- **No response or escalation workflow**: an alert fires into a channel nobody owns, with no runbook, no on-call, and no escalation path.
- **Logs that cannot be trusted**: they are unmonitored, lost on container restart, mutable by an attacker, missing time synchronisation, or polluted with secrets and PII.

### Core Concept

```
Effective detection & response:
  Log        -> every security-relevant event, structured, with full context
  Centralise -> ship off-host to tamper-resistant, append-only storage
  Detect     -> correlation rules turn events into a scored, deduplicated alert
  Alert      -> actionable, routed to an owner, tuned to keep signal high
  Respond    -> runbook + on-call + escalation close the loop within minutes

Logging & Alerting Failure:
  Log        -> auth successes only, no failures, no context, no user/IP
  Centralise -> logs stay on the box; wiped on redeploy or by the attacker
  Detect     -> no rules; 10,000 events/day, none correlated
  Alert      -> either nothing fires, or everything does and is ignored
  Respond    -> alert lands in a dead channel; breach found months later by a third party
```

## The 2025 Edition: From Monitoring to Alerting

This category has a long lineage in the OWASP Top 10, and the name change matters:

| Edition | Name | Emphasis |
|---------|------|----------|
| A10:2017 | Insufficient Logging & Monitoring | Are events being recorded and watched at all? |
| A09:2021 | Security Logging & Monitoring Failures | Broadened to the quality and coverage of logging and monitoring. |
| **A9:2025** | **Logging & Alerting Failures** | **Producing logs is not enough — the loop must close with timely, actionable alerting and response.** |

The 2025 rename to **"Alerting"** is deliberate. Across a decade of breach retrospectives, the recurring lesson was not that organisations lacked logs — it was that the signal existed and *nobody acted on it in time*. Teams had checked the "we have logging" box while the parts that actually shorten dwell time — detection logic, tuned alerts, ownership, and an escalation workflow — were missing. The 2025 edition reframes the category around that gap: the deliverable is not a log file, it is a **timely response**.

> **Continuity note.** A9:2025 is a direct evolution of A09:2021 (Security Logging & Monitoring Failures) and A10:2017 (Insufficient Logging & Monitoring). Everything true of the earlier categories still applies; 2025 adds explicit weight to alerting quality, alert fatigue, correlation, and the response workflow.

## Why Does This Matter?

This category is unusual because it rarely causes an incident — it *amplifies* every other one. A cross-site scripting bug that is detected and contained in an hour is a footnote; the same bug undetected for six months is a headline. The cost of a breach scales with **dwell time** (how long the attacker operates before discovery), and dwell time is exactly what logging and alerting exist to compress.

### Business Impact

- **Extended dwell time**: attackers linger for weeks or months, escalating from a foothold to full compromise, because nothing raised an alarm.
- **Discovery by outsiders**: breaches surface via a customer, a security researcher, a ransom note, or law enforcement — never a good look, and always after the damage is done.
- **Regulatory exposure**: frameworks such as GDPR, PCI-DSS, HIPAA, SOC 2, and ISO 27001 mandate audit logging, monitoring, and breach notification within fixed windows (GDPR requires notification within 72 hours of *becoming aware* — which you cannot do if you never become aware).
- **Failed forensics**: with no reliable logs, incident responders cannot scope the breach, so the organisation must assume worst case — maximising notification costs and reputational harm.
- **No accountability**: without an audit trail, insider abuse and privilege misuse are undetectable and unprovable.

### Technical Impact

- **Undetected reconnaissance and enumeration**: username enumeration, forced browsing, and parameter tampering generate no alert, so attackers map the app freely.
- **Slow credential stuffing succeeds**: an attacker throttling below your (missing) threshold walks into accounts one at a time.
- **Privilege abuse is invisible**: access-control failures that *are* blocked still signal an attack in progress — if you log them. If you do not, you lose your earliest warning.
- **Exfiltration goes unseen**: bulk data access that should trip a volume alert instead looks like ordinary traffic.
- **Evidence is destroyed or forged**: mutable, on-host logs let an attacker wipe their tracks or inject fabricated entries to mislead responders (log injection).

## Technical Context

### What Counts as a Security-Relevant Event?

The single most common root cause in this category is not knowing *what* to log. A useful baseline — drawn from the OWASP logging guidance — is to log every event where a security decision is made or a high-value action occurs:

| Category | Events to log |
|----------|---------------|
| Authentication | Login success and **failure**, logout, MFA challenge/failure, password reset, token issuance and revocation. |
| Access control | Every authorization **denial**, attempts to act on another user's resource, use of admin functions. |
| Input validation | Rejected inputs, schema violations, values that trip a WAF or server-side check. |
| High-value actions | Money movement, role/permission changes, data export, account deletion, configuration changes. |
| Session & account | Session creation/termination, new-device logins, email/password changes, account lockout. |
| System & integrity | Startup/shutdown, config reloads, failures in the logging pipeline itself. |

### The Anatomy of a Useful Log Entry

An event is only actionable if it carries enough context to answer *who, what, when, where, and from where*. Structured (machine-parseable) logging is what makes correlation and alerting possible at all.

```json
{
  "timestamp": "2025-08-28T14:03:11.482Z",   // ISO-8601, UTC, synchronised clock
  "event": "authn_login_failed",              // stable, enumerated event name
  "outcome": "failure",
  "severity": "warning",
  "actor": { "user_id": "u_8471", "username": "a.khan" },
  "source": { "ip": "203.0.113.44", "user_agent": "curl/8.4.0" },
  "target": { "resource": "session", "action": "create" },
  "context": { "reason": "bad_password", "attempt": 14, "mfa": "not_reached" },
  "correlation_id": "req_1b9f...c2",           // ties events across services
  "service": "auth-api",
  "env": "production"
}
```

Contrast that with the failure mode: `logger.info("login failed")` — no user, no IP, no count, no correlation ID, unparseable, and therefore un-alertable.

### The Detection Pipeline

```
Application  ->  Structured event
                   |
                   v
Collector    ->  ship OFF-HOST (agent / stdout -> Fluent Bit)
                   |
                   v
Central store->  append-only, time-synced, access-controlled (SIEM / log platform)
                   |
                   v
Detection    ->  correlation rules + thresholds turn events into candidate alerts
                   |
                   v
Alerting     ->  deduplicate, score, route to an OWNER with a runbook
                   |
                   v
Response     ->  on-call triages -> contains -> escalates within minutes
```

A failure at *any* stage neutralises the whole chain. Perfect logs that stay on a host the attacker controls are worthless; perfect detection rules that alert into an unowned channel are worthless. This is why the category is best understood as an end-to-end **loop**, not a feature.

### Alerting Is a Distinct Discipline

The 2025 emphasis on alerting recognises that turning events into good alerts is its own engineering problem:

- **Signal vs. noise**: an alert that fires on every failed login trains responders to ignore it. Alert on *patterns* (many failures across many accounts from one IP), not on every atomic event.
- **Correlation**: the attack story lives across events — one failed login is noise, 500 failures against 500 usernames from one ASN in ten minutes is credential stuffing.
- **Thresholds and tuning**: too tight and you drown; too loose and you miss the slow attacker. Thresholds need baselines and continuous tuning.
- **Ownership and escalation**: every alert needs an owner, a runbook, and an escalation path, or it is just noise with extra steps.

## Real-World Impact

The examples below are well-documented **classes** of incident. Exact figures vary by source and are omitted deliberately; the durable lesson is in the detection-and-response pattern, not the number.

### Case Class 1: The Ignored Alert (large-retailer breach, 2013)

**Pattern**: Malware planted on point-of-sale systems *did* trigger alerts from the organisation's threat-detection tooling. The alerts were received — and not acted upon in time. Data exfiltration continued for weeks.

**Lesson**: An alert nobody triages is indistinguishable from no alert at all. Detection without a staffed, trusted response workflow is a Logging & Alerting Failure even when the logging works.

### Case Class 2: The Blind Spot in Monitoring (credit-bureau breach, 2017)

**Pattern**: Attackers exploited an unpatched component and then operated for an extended period. Public post-incident reporting attributed part of the long dwell time to a network-inspection device that was not inspecting traffic because a certificate used for decryption had expired — so the monitoring that should have seen the exfiltration was effectively switched off.

**Lesson**: Monitoring silently failing is worse than no monitoring, because it also removes the pressure to look elsewhere. The health of the logging/monitoring pipeline is itself a security-relevant event that must be alerted on.

### Case Class 3: Detected by an Outsider (cloud-data breach, 2019)

**Pattern**: A large volume of customer data was accessed through a misconfiguration. The activity was not caught by internal detection; the organisation learned of it via an external tip.

**Lesson**: When your first notification comes from outside, your detection layer has failed. Volume-based and anomaly-based alerting on data access is what turns exfiltration into a page instead of a press release.

### Case Class 4: The Industry Baseline (annual breach reports)

**Pattern**: Year after year, widely-cited industry breach reports find that a large share of breaches take weeks or months to discover, and that a substantial fraction are discovered by third parties rather than the victim's own monitoring.

**Lesson**: Long dwell time and third-party discovery are the statistical signature of this category. Reducing both is the whole point of investing in logging and alerting.

## Prevalence and Detectability

OWASP has historically noted that this category is **challenging to test for** and under-represented in automated scan data — precisely because the flaw is an *absence*. A scanner can see a missing security header; it cannot easily see that an alert failed to fire or that nobody was watching. Much of the supporting evidence comes from breach retrospectives and survey data rather than vulnerability scans.

Rather than cite precise percentages (which differ across reports and years), the defensible picture is:

- The category is **widespread**: insufficient security logging and weak alerting are found in a large fraction of assessments.
- It is **hard to detect automatically**, so it is frequently discovered only during — or after — a real incident.
- Its **impact is multiplicative**: it rarely rates "critical" alone but sharply worsens the severity of everything else.

### Relevant CWE Mappings

- **CWE-778**: Insufficient Logging
- **CWE-223**: Omission of Security-relevant Information
- **CWE-532**: Insertion of Sensitive Information into Log File (logging secrets/PII)
- **CWE-117**: Improper Output Neutralization for Logs (log injection/forging)
- **CWE-779**: Logging of Excessive Data (noise that buries signal)

## Common Misunderstandings

### Myth 1: "We have logging, so we're covered."

**Reality**: Producing logs is the easy 20%. If nothing correlates them, no alert fires, and no one is on call, you have a write-only archive you will read *after* the breach — never during. The 2025 edition exists to correct exactly this false sense of security.

### Myth 2: "More logs mean more security."

**Reality**: Volume without structure and tuning causes **alert fatigue** — the state where responders mute or ignore alerts because most are noise. A firehose of unstructured logs actively *hides* the one event that mattered. Signal quality beats volume.

### Myth 3: "The cloud/platform logs everything for us."

**Reality**: Infrastructure logs (load balancer, container stdout) capture requests, not *application security semantics*. Only your code knows that this request was an authorization denial or a suspicious money transfer. Platform logging is necessary, not sufficient.

### Myth 4: "Logs are just for debugging."

**Reality**: Debug logs and security event logs serve different audiences and needs — the latter must be structured, tamper-resistant, retained, and monitored. Treating security logging as a byproduct of debug output is how critical events get filtered out in production.

### Myth 5: "Log everything, we'll sort it out later."

**Reality**: Two failure modes hide here. Logging *too little* misses the event; logging *too much of the wrong thing* dumps passwords, tokens, and PII into log files (CWE-532), turning your logs into a second breach target. Log the right events, and never log secrets in cleartext.

### Myth 6: "Our logs are trustworthy evidence."

**Reality**: If logs live on the compromised host, are writable by the app user, lack integrity protection, or have unsynchronised clocks, an attacker can delete or forge them — and a court or auditor can dismiss them. Trustworthy logs are centralised, append-only, integrity-checked, and time-synchronised.

## Self-Assessment

Ask these questions about your application. Several "no" or "not sure" answers indicate an active exposure:

- [ ] Are authentication **failures** (not just successes) logged with user, IP, and a running attempt count?
- [ ] Is every access-control **denial** logged?
- [ ] Are high-value actions (money movement, role changes, exports, deletions) logged with actor and target?
- [ ] Are logs **structured** (JSON/key-value) and carrying a correlation ID across services?
- [ ] Are logs shipped **off-host** to centralised, append-only, access-controlled storage?
- [ ] Do clocks use synchronised UTC (NTP) so events can be ordered across systems?
- [ ] Does at least one **correlation rule** exist (e.g. credential stuffing, privilege abuse, exfiltration volume)?
- [ ] When an alert fires, does it reach a named **owner** with a runbook and an escalation path?
- [ ] Are alerts **deduplicated and tuned** so responders trust rather than mute them?
- [ ] Are you certain no secrets, tokens, or full PII are written to logs in cleartext?
- [ ] Is untrusted data **neutralised** before being logged (no log injection)?
- [ ] Do you alert when the logging pipeline itself **stops** producing data?

## Next Steps

- **[Attack Vectors](./attack-vectors.html)**: How attackers operate *undetected*, and how they forge or delete logs.
- **[Prevention](./prevention.html)**: Layered defenses — structured logging, correlation, tuned alerting, tamper resistance, and response.
- **[Examples](./examples.html)**: Vulnerable vs. secure security logging in Python and Node.js, plus SIEM detection rules.
- **[Hands-On Lab](./lab/logging-alerting-failures/)**: Practice detecting an attack that a broken logging setup would miss.

---

*Part of the [OWASP Top 10 Educational Repository](/platform/frontend/owasp-labs.html) — A9:2025, Logging & Alerting Failures.*
