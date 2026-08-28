# Security Logging and Monitoring Failures - Overview

## Table of Contents

- [What are Security Logging and Monitoring Failures?](#what-are-security-logging-and-monitoring-failures)
- [Lineage: 2017 A10 → 2021 A9 → 2025](#lineage-2017-a10--2021-a9--2025)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)
- [Self-Assessment](#self-assessment)

## What are Security Logging and Monitoring Failures?

**Security Logging and Monitoring Failures** (A9:2021) is the category that covers everything an application *does not see*. Where most OWASP categories describe a way in — an injection, a broken access check, a weak cipher — this one describes the absence of the machinery that would have *noticed* the attack. It is a failure of visibility and response rather than a single exploitable flaw, and that is exactly what makes it dangerous: a breach that is never detected is a breach that runs to completion.

The category is unusual in the Top 10 because it was voted in almost entirely from the community survey rather than from raw CWE data. Insufficient logging is hard to test for from the outside — an attacker cannot "see" whether their probes were recorded — but practitioners consistently rank it among the most damaging gaps they encounter during incident response. Without reliable logging and active monitoring, teams cannot detect an active attack, cannot scope a confirmed breach, and cannot prove what an attacker did or did not touch.

At its core, A9:2021 is present when one or more of the following is true:

- **Auditable events are not logged**: logins, failed logins, access-control failures, and high-value transactions leave no record.
- **Warnings and errors produce no, or inadequate, log messages**: the application swallows exceptions or logs them without enough context to act on.
- **Logs are not monitored**: they are written but nobody — and no system — is watching them for suspicious activity.
- **Logs are stored only locally**: a single compromised host also loses its evidence, and there is no central view across services.
- **Alerting is missing or ineffective**: there are no thresholds, no escalation, and no defined response, so alerts either never fire or are ignored.
- **Active attacks go unnoticed**: penetration tests, vulnerability scans, and credential-stuffing campaigns run in real time and trigger nothing.
- **Logs are not tamper-resistant**: an attacker who reaches the host can edit or delete the logs and erase their own tracks.
- **Logs lack context, leak secrets, or are injectable**: entries omit the who/what/where needed for investigation, record passwords and tokens in cleartext, or let attacker-controlled input forge log lines.

### Core Concept

```
An attacker probes, exploits, and exfiltrates.

WITH logging & monitoring:
  probe        -> failed-auth events logged -> threshold crossed -> ALERT
  exploit      -> access-control failure logged with user context -> ALERT
  exfiltrate   -> anomalous data volume logged -> ALERT -> response & containment

WITHOUT logging & monitoring (A9:2021):
  probe        -> nothing recorded
  exploit      -> nothing recorded
  exfiltrate   -> nothing recorded
  detection    -> weeks or months later, usually from an OUTSIDE party
```

The defining symptom of A9 is **dwell time**: the gap between initial compromise and detection. When that gap stretches to weeks or months — and when the alarm is finally raised by a customer, a researcher, a payment processor, or law enforcement rather than by the organisation itself — A9:2021 is the root cause.

## Lineage: 2017 A10 → 2021 A9 → 2025

This category has been renamed twice, and understanding the lineage keeps it distinct from its siblings on this platform:

| Edition | Rank | Name | Emphasis |
|---------|------|------|----------|
| 2017 | A10 | Insufficient Logging & Monitoring | The basic gap: events not logged, breaches not detected. |
| 2021 | A9 | Security Logging and Monitoring Failures | Broadened to include log integrity, alerting, response, and log injection. |
| 2025 (draft lineage) | — | Logging & Alerting Failures | Sharper focus on *alerting* and timely response, not just log presence. |

> **This lesson is the 2021 (A9) framing.** The platform hosts separate lessons for the 2017 (A10 "Insufficient Logging & Monitoring") and 2025 ("Logging & Alerting Failures") editions. The 2017 lesson is the narrower origin; the 2025 lesson leans hardest on alerting and response time. Here we cover the full 2021 scope: capture, centralisation, integrity, monitoring, alerting, and incident response together.

## Why Does This Matter?

A9:2021 rarely causes a breach on its own — instead it turns a small, containable incident into a large, unbounded one. Every other weakness in the Top 10 becomes more expensive when nobody is watching.

### Business Impact

- **Uncontrolled breach scope**: without logs you cannot tell whether one record or one million were taken, so regulators, courts, and customers must be told to assume the worst.
- **Regulatory exposure**: GDPR, HIPAA, PCI-DSS, and SOX all mandate audit logging and timely breach notification. Missing logs are themselves a compliance finding.
- **Longer, costlier incident response**: reconstructing an attack without telemetry can take weeks of forensic work that reliable logs would have made minutes of query time.
- **Loss of trust**: "we were breached but cannot say what was taken" is far more damaging than a precise, well-scoped disclosure.
- **No feedback loop**: teams that cannot see attacks cannot learn from them, so the same weaknesses are exploited repeatedly.

### Technical Impact

- **Extended dwell time**: attackers move laterally, escalate, and establish persistence at leisure.
- **Destroyed evidence**: local-only, mutable logs let an intruder delete the record of their own activity.
- **Unscopeable compromise**: without user context and correlation IDs, investigators cannot follow a single actor across services.
- **Missed early warning**: reconnaissance — scans, forced-browsing, credential stuffing — is the cheapest thing to detect, and A9 throws that advantage away.
- **Secondary exposure**: logs that record passwords, tokens, or full PII in cleartext become a breach target in their own right.

## Technical Context

### What Counts as an Auditable Event?

Not everything needs to be logged, but a defined set of **security-relevant events** always does:

| Category | Events to capture |
|----------|-------------------|
| Authentication | Successful logins, failed logins, logout, password change/reset, MFA challenges |
| Access control | Authorization denials, privilege changes, role assignments, admin actions |
| Input validation | Rejected input, schema violations, WAF blocks, deserialization failures |
| High-value transactions | Payments, transfers, data exports, permission grants, account deletion |
| System & integrity | Config changes, service start/stop, key rotation, log tampering attempts |

### What Makes a Log Entry Useful?

A log line is only as good as the context it carries. The minimum useful fields are the **who, what, when, where, and outcome**:

```json
{
  "timestamp": "2026-08-28T14:03:11.204Z",   // WHEN - UTC, synchronized clock
  "level": "WARN",
  "event": "authn.login.failure",             // WHAT - stable event name
  "user_id": "u_10432",                       // WHO  - subject, never the password
  "source_ip": "203.0.113.44",                // WHERE
  "user_agent": "Mozilla/5.0 ...",
  "request_id": "b1f2...c9",                   // correlation across services
  "outcome": "denied",
  "reason": "invalid_credentials"
}
```

Two anti-patterns are common. First, entries with no subject ("Error occurred") that cannot be tied to a user or request. Second, entries that over-share — recording the submitted password, a session token, or a full credit-card number. The goal is **enough context to investigate, nothing that would harm the user if the log leaked**.

### Consistent, Machine-Consumable Format

Logs must be parseable by a centralized log-management or SIEM platform. Free-text lines that vary between developers cannot be reliably searched or alerted on. Structured logging (JSON, or a strict key=value convention) with a shared field vocabulary is what lets a query like "show all `authz.denied` events for `user_id=u_10432` in the last hour" return an answer at all.

### The Detect-and-Respond Pipeline

```
  App / infra  --emit-->  Ship (agent)  --to-->  Central store (SIEM)
                                                     |
                                                 Correlate & enrich
                                                     |
                                              Alerting rules + thresholds
                                                     |
                                          On-call escalation + runbook
                                                     |
                                    Incident response (NIST SP 800-61)
```

Every stage can fail independently. Events may not be emitted; the shipper may be down; the store may drop fields; rules may be absent; alerts may fire into a channel nobody reads; or there may be no runbook telling on-call what to do. A9:2021 is any break in this chain.

## Real-World Impact

The incident *classes* below are drawn from widely reported, publicly documented breaches. The point of each is the **logging or monitoring failure**, not the initial exploit.

### Class 1: Alerts Fired but Nobody Acted

**Pattern**: A large retail payment breach in which malware on point-of-sale systems *did* trigger alerts from a deployed detection product — but the alerts were not acted upon, and automatic containment had been disabled. The telemetry existed; the **response** did not.
**Lesson**: Logging without monitoring, and monitoring without a response process, is theatre. Alerting must terminate in a human or automation that is accountable for acting.

### Class 2: A Blind Spot in the Monitoring Itself

**Pattern**: A major credit-bureau breach in which traffic that should have been inspected went uninspected for months because a certificate on a monitoring appliance had expired. Attacker data left the network unseen; detection came only after the certificate was renewed.
**Lesson**: Monitoring infrastructure needs its own health monitoring. A silent sensor is worse than no sensor because it manufactures false confidence.

### Class 3: Long Dwell Time in Merged Environments

**Pattern**: A hospitality-industry breach in which intruders had access to a reservation database for *years* before discovery, largely because the acquired environment was never brought under unified monitoring.
**Lesson**: Coverage gaps — especially in acquired, legacy, or "temporary" systems — are where dwell time hides. If it is not monitored, it is not defended.

### Class 4: Detected by an Outsider, Not by You

**Pattern**: A cloud-hosted financial-data breach discovered only after an external party reported that data was publicly exposed, rather than through the organisation's own detection. The exfiltration produced no internal alert.
**Lesson**: If your detection story is "a stranger will email us," you do not have detection. Instrument access to sensitive data with volume and anomaly alerting.

### Class 5: Supply-Chain Compromise, Detected Late and Externally

**Pattern**: A widely used software build was trojanised and distributed to thousands of organisations; the intrusion persisted undetected for months and was ultimately surfaced by a security firm noticing anomalous behaviour on its own network — not by the affected organisations' monitoring.
**Lesson**: Sophisticated attackers are quiet by design. Baseline "normal" behaviour so that *quiet-but-abnormal* activity (new outbound destinations, off-hours admin actions) still generates signal.

## Prevalence and Statistics

### OWASP Top 10 2021 Positioning

- **#9** in the 2021 list, up from **#10** in 2017.
- Included **primarily from the community survey** (ranked highly by practitioners) because it is difficult to measure with automated tests.
- Maps to a small set of CWEs — this is a category defined by *absence*, which does not show up as a discrete code flaw the way injection does.

### Representative CWE Mappings

- **CWE-778**: Insufficient Logging
- **CWE-117**: Improper Output Neutralization for Logs (log injection)
- **CWE-223**: Omission of Security-relevant Information
- **CWE-532**: Insertion of Sensitive Information into Log File
- **CWE-1295**: Debug Messages Revealing Unnecessary Information

### Why It Is Under-Reported

Automated scanners and most bug-bounty submissions cannot observe a defender's internal telemetry, so this category is systematically invisible to outside-in testing. Its true prevalence is best understood through **incident-response data** — the repeated finding that organisations learn of breaches from third parties and cannot scope them — rather than through scan counts.

## Common Misunderstandings

### Myth 1: "We have logs, so we're covered."

**Reality**: Logs that nobody reads and no rule alerts on are evidence for a post-mortem, not a defence. Detection requires *monitoring and alerting* on top of the logs. The 2025 rename to "Logging & Alerting Failures" exists precisely to hammer this point home.

### Myth 2: "More logging is always better."

**Reality**: Log everything and you drown the signal in noise, blow up storage cost, and risk recording secrets and PII. The goal is the *right* events with the *right* context — security-relevant, structured, and alertable — not maximum volume.

### Myth 3: "Logging sensitive data helps debugging."

**Reality**: Passwords, tokens, session IDs, and full card numbers in logs turn your log store into a high-value breach target and often violate PCI-DSS/GDPR outright. Log identifiers and outcomes, never secrets.

### Myth 4: "Local log files are fine."

**Reality**: An attacker who compromises the host can edit or delete local logs and erase their tracks. Logs must be shipped off-host to append-only, tamper-resistant central storage in near-real-time.

### Myth 5: "Untrusted input in logs is harmless — it's just text."

**Reality**: Unescaped input enables *log injection*: forged log lines, broken parsers, and — when logs are rendered in a web dashboard — stored XSS in the very tool your responders trust. Neutralize CR/LF and encode untrusted data before it is written.

### Myth 6: "A penetration test will surely trip our alarms."

**Reality**: In a large fraction of engagements, scans and exploitation attempts generate *zero* alerts. If your own authorised testers can operate silently, so can a real adversary. Detecting the pen test is a concrete, testable success criterion.

## Self-Assessment

A "no" or "not sure" to any of these is a finding:

1. Are successful and **failed** logins, access-control denials, and high-value transactions all logged with user and request context?
2. Are logs written in a **consistent, structured format** and shipped to a **central** store (SIEM), not just kept locally?
3. Is the central store **append-only / tamper-resistant**, with integrity you could defend in an investigation?
4. Are there **alerting thresholds** (e.g. bursts of failed logins) that escalate to a human or automation with a defined runbook?
5. If a penetration test or vulnerability scan ran right now, would it **generate an alert**?
6. Are clocks **synchronized (NTP/UTC)** and is a **retention period** defined and enforced?
7. Do you have an **incident-response plan** (aligned to something like NIST SP 800-61) that these alerts feed into?
8. Are you confident logs contain **no passwords, tokens, or unmasked PII**, and that untrusted input is **encoded** before logging?

## Key Takeaways

1. A9 is about **visibility and response**, not a single exploitable bug — its symptom is long dwell time and third-party detection.
2. Log the right **security-relevant events** with sufficient context, in a **structured, centralizable** format.
3. Logging is necessary but not sufficient: you also need **monitoring, alerting, and a response process**.
4. Protect the logs themselves — **tamper-resistant storage, no secrets, encode against log injection**.
5. Prove it works by confirming your own **scans and pen tests generate alerts**.

## What's Next?

- **[Attack Vectors](./attack-vectors.md)**: How attacker activity slips past absent or ineffective logging
- **[Prevention](./prevention.md)**: Layered logging, monitoring, alerting, and response defenses
- **[Examples](./examples.md)**: Vulnerable vs secure structured logging in Python, Node, and Java
- **[Lab](./lab/no-logging-lab/)**: Hands-on practice with a safe, isolated environment

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
