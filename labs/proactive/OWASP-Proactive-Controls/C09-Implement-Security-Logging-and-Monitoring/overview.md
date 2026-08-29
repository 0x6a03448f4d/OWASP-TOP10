# C9: Implement Security Logging and Monitoring - Overview

## Table of Contents
- [What is this control?](#what-is-this-control)
- [Why This Control Matters](#why-this-control-matters)
- [What to Log and With What Context](#what-to-log-and-with-what-context)
- [From Event to Response: The Pipeline](#from-event-to-response-the-pipeline)
- [Real-World Incident Classes](#real-world-incident-classes)
- [Common Misunderstandings](#common-misunderstandings)

## What is this control?

**Security Logging and Monitoring** is the proactive control of recording security-relevant events, watching those records in near-real time, and wiring them into detection and response. It is the discipline that lets an organisation *know* when something is going wrong—and prove afterwards what happened. Logging without monitoring is a write-only archive nobody reads; monitoring without logging has nothing to watch. The control requires both, joined to an incident-response process that can act on what they surface.

This is the defensive counterpart to **Security Logging and Monitoring Failures** (the OWASP Top 10 category A09). That failure category describes what goes wrong when auditable events are not logged, warnings and errors generate no or inadequate log messages, logs are not monitored for suspicious activity, logs are stored only locally, alerting thresholds are missing, and penetration tests or scans do not trigger alerts. This control is the set of practices that close every one of those gaps.

### Core Concept

```
Blind system (failure mode):
  Events        -> only crashes are logged; auth, access, admin actions are not
  Context       -> "error occurred" with no who / what / when / where
  Format        -> free-text strings, each service different, unparseable
  Storage       -> local disk on each host, rotated away in days
  Monitoring    -> nobody looks; logs read only after a breach is announced
  Alerting      -> none, or so noisy every alert is ignored
  Response      -> discovered by a third party months later

Instrumented system (control applied):
  Events        -> auth, access-control, validation, admin, high-value txns logged
  Context       -> who, what, when, where, plus a correlation / trace ID
  Format        -> consistent, machine-parseable structured records (e.g. JSON)
  Storage       -> centralized, append-only, integrity-protected, retained
  Monitoring    -> SIEM correlates events against a known-normal baseline
  Alerting      -> tuned, actionable alerts routed to responders
  Response      -> detection triggers a rehearsed incident-response playbook
```

### The three obligations

The control is often summarised as three linked obligations, none of which stands alone:

- **Log** the security-relevant events, with enough context to reconstruct what happened, in a consistent structured format.
- **Monitor** those logs—centralise, correlate, and compare against a baseline of normal behaviour so anomalies stand out.
- **Detect and respond**—turn signal into tuned, actionable alerts that feed a tested incident-response process.

## Why This Control Matters

### Business Impact of Getting It Right

- **Dwell time collapses**: the damage of a breach is largely a function of how long the attacker operates undetected. Detection is the difference between catching credential stuffing in an hour and learning of a full data exfil from a journalist months later.
- **Provable accountability**: complete, tamper-resistant audit records answer "what did the attacker touch?" during response and satisfy regulators, auditors, and courts afterward.
- **Regulatory alignment**: PCI-DSS, HIPAA, SOC 2, ISO 27001, and GDPR breach-notification duties all assume you can log access to sensitive data, retain those logs, and detect misuse.
- **Faster, cheaper response**: correlated, contextual logs turn a multi-week forensic reconstruction into a query, shrinking both the cost and the notification window.

### Technical Impact of Getting It Wrong

- **Silent compromise**: without logged authentication and access-control failures, brute force, credential stuffing, and privilege abuse leave no trace to alert on.
- **No forensic trail**: after an incident, missing or locally-stored (and attacker-wiped) logs make scope, root cause, and impact impossible to establish.
- **Alert fatigue**: the opposite failure—logging everything with no tuning—buries the one real alert under thousands of benign ones, so real detection still fails.
- **Log injection and tampering**: untrusted data written verbatim lets an attacker forge entries, break parsers, or inject downstream payloads; unprotected storage lets them erase their tracks.

## What to Log and With What Context

### Security-relevant events to capture

Log the events that let you detect abuse and reconstruct an incident. At minimum:

| Event class | Examples | Why it matters |
|-------------|----------|----------------|
| Authentication | Login success and failure, logout, MFA challenge/failure, password reset, token issue/refresh | Detect brute force, credential stuffing, account takeover |
| Access-control failures | Denied authorization, attempts to reach another user's object, forbidden admin routes | Detect enumeration and privilege abuse (IDOR/BOLA probing) |
| Input-validation failures | Rejected input, schema violations, WAF blocks, injection-pattern hits | Detect active exploitation attempts and scanning |
| High-value transactions | Payments, transfers, order placement, data exports/downloads | Detect fraud and bulk exfiltration |
| Administrative actions | Role/permission changes, user creation/deletion, config changes, feature-flag flips | Detect insider abuse and post-compromise persistence |
| Permission & identity changes | Grants, revocations, group membership, key/credential rotation | Detect privilege escalation and backdoor accounts |

### Sufficient context: who, what, when, where

An event is only useful if it answers the investigator's questions. Every security log entry should carry:

- **Who**: authenticated subject (user/service ID), and the source IP and user-agent of the request.
- **What**: the action attempted, the target resource, and the outcome (allowed/denied, success/failure).
- **When**: a precise, timezone-explicit timestamp from a time-synchronised clock (see NTP below).
- **Where**: the service/host/component that produced the event and the environment (prod/staging).
- **Correlation**: a request/trace/correlation ID that ties the entry to every other log line for the same operation across services.

### Structured, machine-parseable format

Free-text log lines that differ between services cannot be searched, correlated, or alerted on reliably. Emit **structured** records—typically JSON—with a consistent schema and stable field names, so a SIEM can index and query them:

```json
{
  "timestamp": "2026-08-29T14:03:11.482Z",
  "event": "authn.login.failure",
  "outcome": "failure",
  "actor": { "user_id": "u_8842", "src_ip": "203.0.113.44", "ua": "curl/8.4" },
  "target": { "resource": "/api/session", "method": "POST" },
  "reason": "invalid_password",
  "trace_id": "b7f1c2a9-3e5d-4a11-9c2e-77a0d1e4f8bd",
  "service": "auth-api",
  "env": "prod"
}
```

> The field names matter less than their *consistency*. Pick a schema, document it, and make every service emit the same shape so correlation is a query, not a research project.

## From Event to Response: The Pipeline

The control is a pipeline, and it is only as strong as its weakest stage:

```
1. Instrument   -> emit structured security events with full context + trace ID
        v
2. Ship         -> forward off-host in near-real time (never trust local disk alone)
        v
3. Centralize   -> SIEM / log platform ingests, normalizes, and correlates
        v
4. Baseline     -> learn normal behavior; flag statistically anomalous activity
        v
5. Alert        -> tuned thresholds fire actionable, deduplicated alerts
        v
6. Respond      -> alert triggers a tested incident-response playbook
        v
7. Test         -> verify (red team / pentest) that detection actually fires
```

### Supporting requirements that make the pipeline trustworthy

- **Centralization & correlation**: aggregate logs from every service into a SIEM or log-management platform. Only centrally can you correlate a failed login here with a privilege change there.
- **Tamper-resistant, append-only storage**: protect log integrity (write-once/append-only stores, hashing/signing, restricted access) so an attacker who reaches a host cannot rewrite history. Keep logs long enough to satisfy investigation and compliance retention needs.
- **Time synchronisation (NTP)**: synchronise every clock to a trusted time source and log in a consistent timezone (UTC). Without it, cross-system correlation and legal timelines fall apart.
- **Real-time, tuned alerting**: alerts must be actionable and thresholds tuned to fight *alert fatigue*—every false alarm erodes trust in the next real one.
- **Baseline & anomaly detection**: establish what normal looks like (login rates, data-export volumes, geographies) so deviations become detectable signal.
- **Incident-response integration**: detection is worthless if nobody acts. Route alerts to a rehearsed playbook with owners, escalation, and containment steps.
- **Test that detection works**: penetration tests, scans, and red-team exercises should trigger alerts. If they do not, the pipeline is decorative.

### Two things you must NOT do

- **Never log secrets or sensitive data in cleartext**: passwords, session tokens, API keys, full card numbers, and unnecessary PII must be redacted, masked, or omitted. Logs are copied, shipped, and widely read—treat them as a disclosure surface.
- **Never write untrusted data verbatim**: neutralise (encode/strip newlines and control characters) any user-controlled value before logging it, or an attacker can forge entries and inject downstream payloads (see log injection).

## Real-World Incident Classes

Rather than cite specific breach figures, the durable, defensible pattern across public post-mortems is that **detection failures extend dwell time**—attackers operate for weeks or months because the events that would have exposed them were never logged, never monitored, or never alerted on.

### Class 1: Long-dwell breaches discovered by outsiders

A recurring pattern in major breaches is that the victim learns of the compromise from a third party (a bank, a researcher, law enforcement) rather than from their own monitoring. The technical root cause is consistent: the security-relevant events existed but were not logged, centralised, or alerted on, so the intrusion ran undetected for a long dwell time.

### Class 2: Credential stuffing and brute force at scale

Automated login attacks succeed quietly when authentication failures are not logged and rate-anomalies are not alerted. With structured authn logs and a baseline, a spike of failures from many IPs against many accounts is an obvious, catchable signal; without them it is invisible until fraud appears downstream.

### Class 3: Enumeration and access-control probing (IDOR/BOLA)

Attackers walk sequential IDs or fuzz authorization boundaries. If access-control failures are logged with actor and target, a single actor generating hundreds of "forbidden" outcomes across many objects is a clear detection; unlogged, the enumeration completes silently.

### Class 4: Insider and post-compromise privilege abuse

Role changes, new admin accounts, and mass data exports are the fingerprints of both malicious insiders and attackers establishing persistence. Logging administrative actions and permission changes—and alerting on the anomalous ones—is frequently the only control that surfaces this behaviour.

### Class 5: Bulk data exfiltration

Large exports and downloads that dwarf normal usage are detectable only if high-value transactions are logged and baselined for volume. Absent that, terabytes can leave before anyone notices.

## Common Misunderstandings

### Myth 1: "We log everything, so we're covered"

**Reality**: Volume is not detection. If nobody monitors the logs, if they are unstructured, or if alerting is untuned, logging "everything" just produces an expensive archive and crushing alert fatigue. Log the *right* events, and monitor them.

### Myth 2: "Application logs are the same as security logs"

**Reality**: Debug and performance logs rarely capture authentication, access-control, and admin events with the actor/target/outcome context an investigation needs. Security events must be deliberately instrumented.

### Myth 3: "Logs on the server are good enough"

**Reality**: Local-only logs are exactly what an attacker deletes after landing on the host, and they cannot be correlated across services. Ship logs off-host to a centralised, append-only store in near-real time.

### Myth 4: "More alerts mean more security"

**Reality**: Untuned alerting is the primary cause of missed detections—responders learn to ignore a channel that cries wolf. Fewer, higher-fidelity, actionable alerts beat a firehose.

### Myth 5: "It's fine to log the request as-is"

**Reality**: Logging raw requests captures passwords, tokens, and PII, and lets an attacker inject forged log lines or downstream payloads. Redact sensitive fields and neutralise untrusted data before it is written.

### Myth 6: "We have a SIEM, so detection works"

**Reality**: A SIEM that no red-team exercise or pentest ever manages to trigger is unproven. Test detection deliberately; an untested alerting rule is an assumption, not a control.

## How This Control Relates to A09

| Aspect | The Failure (A09) | The Control (C9) |
|--------|-------------------|------------------|
| **Auditable events** | Not logged, or logged without context | Security events logged with who/what/when/where + trace ID |
| **Format** | Inconsistent free text, unparseable | Consistent, machine-parseable structured records |
| **Storage** | Local only, mutable, short retention | Centralized, append-only, integrity-protected, retained |
| **Monitoring** | Nobody watches; no baseline | SIEM correlation against a known-normal baseline |
| **Alerting** | Missing thresholds or alert fatigue | Tuned, actionable, real-time alerts |
| **Response** | Detected late, by a third party | Detection feeds a tested incident-response playbook |

## Key Takeaways

1. **Log, monitor, respond—all three**: any one alone fails. Records nobody reads, or monitoring with nothing to read, both leave you blind.
2. **Context is what makes a log useful**: who, what, when, where, and a correlation ID turn an entry into evidence.
3. **Structure enables detection**: consistent, machine-parseable records are the precondition for correlation and alerting.
4. **Centralize, protect, and time-sync**: append-only off-host storage on synchronised clocks is what survives an attacker and holds up in an investigation.
5. **Tune alerts and test detection**: fight alert fatigue with actionable alerts, and prove the pipeline fires by making pentests trip it.
6. **Never leak through your logs**: redact secrets and PII, and neutralise untrusted data to prevent log injection.

## Next Steps

- **[Threats Addressed](attack-vectors.md)**: What goes undetected when this control is missing or weak
- **[How to Implement](prevention.md)**: A practical, layered implementation of logging, monitoring, and response
- **[Examples](examples.md)**: Insecure vs. secure structured logging and alerting across stacks
- **[Proactive Controls](/learn/proactive)**: Return to the full OWASP Proactive Controls catalog
- **[Practice](/practice)**: Apply the control in hands-on exercises
