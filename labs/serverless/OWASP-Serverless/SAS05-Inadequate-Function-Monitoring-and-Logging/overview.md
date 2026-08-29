# SAS-5: Inadequate Function Monitoring and Logging - Overview

## Table of Contents
- [What is Inadequate Function Monitoring and Logging?](#what-is-inadequate-function-monitoring-and-logging)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Inadequate Function Monitoring and Logging?

**Inadequate Function Monitoring and Logging** occurs when a serverless application cannot see what its own functions are doing well enough to notice an attack. The individual functions may be correctly written, but the platform around them emits only shallow, operational logs—so injection attempts, credential abuse, reconnaissance, data exfiltration, and cost-driven abuse spread across many short-lived invocations without ever surfacing an alert. It is not one broken function; it is the accumulated *blindness* of a system that was never instrumented to detect security-relevant behaviour.

Serverless makes this blindness the default. Functions are **ephemeral** (they spin up, handle one event, and vanish), **event-driven** (triggered by queues, streams, object writes, HTTP, schedules, and other services), and **highly distributed** (a single logical request may pass through a dozen functions and managed services). The classic vantage points—a long-lived server with a syslog, a host you can SSH into, a network tap—do not exist. What remains by default is a scattering of per-function execution logs that record duration and errors, not identity, intent, or the shape of an attack.

### Core Concept

```
Adequate Monitoring & Logging:
  Security events -> logged by the function code, with identity + request context
  Correlation    -> one trace/request id followed across every function and service
  Tracing        -> distributed tracing (X-Ray / OpenTelemetry) spans the whole chain
  Alerting       -> anomalies page a human: error, invocation, and COST spikes
  Retention      -> tamper-resistant, centralized, long enough to investigate
  Managed svcs   -> CloudTrail / data-plane events captured and correlated

Inadequate Monitoring & Logging:
  Security events -> never logged; function only prints "start" / "done"
  Correlation    -> each function logs to its own stream, nothing ties them together
  Tracing        -> no way to follow a request as it fans out across functions
  Alerting       -> no alarms; a 100x invocation spike is noticed on the invoice
  Retention      -> default group, short retention, writable by the function role
  Managed svcs   -> blind spots between Lambda, S3, DynamoDB, EventBridge, IAM
```

### Why It's Critical for Serverless

Serverless concentrates several conditions that make missing visibility especially damaging:

- Functions are **ephemeral**, so if a security event is not written *during* the invocation, there is no host, process, or memory left afterwards to reconstruct it from.
- Applications are **highly distributed**, so an attack is naturally smeared across many small invocations and services—each individually unremarkable, the pattern only visible when correlated.
- The platform is **event-driven**, so triggers arrive from many sources (S3, SQS, EventBridge, API Gateway); an attacker can enter through a path that no one is watching.
- Billing is **per-invocation**, so abuse shows up as cost. Without alerting, the first signal of a **denial-of-wallet** attack (SAS-8) is the bill, not a page.
- Default logs are **operational, not security-oriented**—they answer "did it run and how long," not "who did this, with what identity, and was it malicious."

## Why Does This Matter?

### Business Impact

- **Undetected Breach Duration**: The core cost of missing logging is *dwell time*—attackers operate for weeks or months because nothing raised an alarm, multiplying the data lost and the clean-up required.
- **Denial-of-Wallet**: Unbounded, unmonitored invocation and cost spikes translate directly into a runaway cloud bill—a financial denial-of-service unique to pay-per-use platforms.
- **No Forensics, No Story**: After an incident, ephemeral functions leave nothing behind. Without prior logging you cannot tell regulators, customers, or insurers what was accessed.
- **Regulatory Exposure**: GDPR, HIPAA, PCI-DSS, and SOC 2 all require the ability to detect and reconstruct access to sensitive data. Inadequate logging is itself a compliance finding, independent of any breach.
- **Slow, Expensive Response**: When detection finally happens out-of-band, responders start from zero—no timeline, no scope, no indicators—stretching containment and cost.

### Technical Impact

- **Silent Injection**: Event-data injection attempts (SAS-1) across many functions succeed or fail unnoticed because payloads and outcomes are never logged with context.
- **Invisible Credential/Role Abuse**: A function's over-broad IAM role is assumed and used against other services with no alert on the anomalous access pattern.
- **Undetected Reconnaissance**: An attacker probes with many small, low-and-slow invocations; each looks like normal traffic because there is no baseline or correlation.
- **Unseen Exfiltration**: A function reads a datastore and ships records to an external endpoint; without egress-aware, per-request logging the transfer never registers.
- **Blind Spots Between Services**: Actions that occur in managed services (an S3 object copied, an IAM policy attached) are missed entirely if data-plane and control-plane events are not captured.

## Technical Context

### Why Default Logs Are Insufficient

Out of the box, a function platform gives you an execution log: a start line, whatever the code happened to `print`, an error/stack trace on failure, and a billing/duration report. That is enough to debug a crash. It is nowhere near enough to detect an attack, because it lacks the four things security detection needs—**identity, request correlation, intent, and a baseline**.

```
Default CloudWatch log line (operational):
  START RequestId: 7f3c... Version: $LATEST
  END   RequestId: 7f3c...
  REPORT RequestId: 7f3c... Duration: 42.11 ms  Billed: 43 ms  Max Memory: 84 MB

What a security event needs instead (structured):
  {
    "ts": "2026-08-29T12:04:11Z",
    "level": "SECURITY",
    "event": "authz_denied",
    "request_id": "7f3c...",         // correlate across the whole chain
    "trace_id": "1-66cf...",         // X-Ray / OTel distributed trace
    "identity": "arn:aws:sts::...:assumed-role/order-fn/...",
    "source_ip": "203.0.113.9",
    "resource": "orders/44120",
    "outcome": "DENY",
    "reason": "cross_tenant_access"
  }
```

### Common Failure Modes

| Failure Mode | What It Looks Like | Why the Attack Goes Undetected |
|--------------|--------------------|--------------------------------|
| Default logs only | Function prints nothing security-relevant; relies on START/END/REPORT | No identity, resource, or outcome to alert on |
| No centralization | Each function logs to its own group; nothing aggregates them | An attack spanning functions is never seen as one event |
| No correlation | No shared request/trace id across the chain | Cannot follow a request as it fans out; events look unrelated |
| No distributed tracing | X-Ray/OTel disabled; no spans between functions and services | The path of a malicious request is invisible |
| No anomaly alerting | No alarms on error/invocation/cost spikes or unusual IAM use | Abuse continues until a human happens to look (or the bill arrives) |
| Context-poor logs | Messages lack identity, source IP, tenant, resource | Even when logged, events cannot be attributed or scoped |
| Short retention | Logs expire in days; group is writable by the function role | Evidence is gone—or tampered with—before investigation |
| Managed-service blind spots | CloudTrail/data-plane events not captured | Actions inside S3, DynamoDB, IAM never appear anywhere |

### Illustrative Scenarios

#### 1. Injection Attempts Smeared Across Functions

```
# An attacker fuzzes an event field that flows into several downstream functions.
# Each function logs only START/END. There is no record of:
#   - the malicious payload,
#   - which functions rejected vs. mishandled it,
#   - that the SAME source repeated it 4,000 times in an hour.
# Result: a slow injection campaign is indistinguishable from normal traffic.
```

#### 2. Denial-of-Wallet Cost Spike

```
# A publicly reachable function is triggered in a tight loop.
Invocations/min:  12  ->  11  ->  9  ->  8,900  ->  9,400  ->  9,100 ...
# No CloudWatch alarm on invocation rate or estimated charges.
# First human signal: the monthly bill. (Ties directly to SAS-8.)
```

#### 3. Role Abuse With No Alert

```
# A compromised function assumes its over-broad role and calls services it never
# normally touches:
#   normal:  dynamodb:GetItem on Orders
#   sudden:  s3:GetObject on backups/*, iam:ListRoles, sts:AssumeRole
# Without baselining "normal" per-function behaviour, none of this pages anyone.
```

## Real-World Impact

The examples below are described as **incident classes**—patterns repeatedly observed across the industry—rather than specific named breaches, because the defining feature of this weakness is precisely that the details often go unrecorded.

### Case Class 1: Long-Dwell Cloud Intrusions

**Weakness**:
- Attackers obtain access (leaked key, vulnerable function, over-broad role) and operate inside a cloud account for an extended period.
- The organisation has execution logs but no security-event logging, no correlation, and no anomaly alerting across its functions and managed services.

**Impact**:
- Industry incident-response reporting consistently shows attacker dwell times measured in weeks or months; missing or unmonitored logging is a recurring root cause for why intrusions are found late—often by an outside party rather than internal detection.

**Root Cause**: Detection was never built. Logs existed for debugging but were not security-oriented, centralized, or alerted on, so there was nothing to notice the intruder.

### Case Class 2: Denial-of-Wallet Against Public Functions

**Weakness**:
- A function reachable from the internet (via an API or a public trigger) has no rate limiting and—critically—no alerting on invocation count or estimated cost.

**Impact**:
- Automated abuse or a loop drives invocations up by orders of magnitude. Because pay-per-use billing scales silently, the financial impact accrues unnoticed until it appears on the invoice—a documented class of "denial-of-wallet" incidents unique to serverless economics (see SAS-8).

**Root Cause**: Cost and invocation rate were never treated as security signals, so no alarm connected the spike to a human in time to stop it.

### Case Class 3: Managed-Service Blind Spots

**Weakness**:
- Security telemetry is limited to the functions themselves. Data-plane activity in managed services (object reads/writes, table scans, IAM changes) is not captured through CloudTrail or service logs.

**Impact**:
- Repeated, well-documented incidents involve access or exfiltration that happened *between* services—in storage or identity—where the organisation had no visibility at all, so the activity left no trace in the places anyone was watching.

**Root Cause**: Monitoring stopped at the function boundary; the gaps between managed services were never instrumented.

## Prevalence and Statistics

Inadequate monitoring and logging is a durable member of both the OWASP Serverless Top 10 (as SAS-5) and the broader OWASP Top 10 lineage (as "Security Logging and Monitoring Failures"). It is distinctive because it is rarely the vulnerability an attacker exploits—it is the reason every *other* exploitation succeeds quietly.

Rather than cite precise figures (which vary by source and year), the defensible picture is:

- Logging and monitoring failures are consistently characterised by OWASP as **hard to test for and highly consequential**: the impact is measured in how long a breach goes undetected.
- The most commonly observed gaps are **reliance on default execution logs, no centralization or correlation, no distributed tracing, and no anomaly/cost alerting**.
- The impact is rated **indirect but severe**: it does not open the door, but it ensures no one notices who walked through—extending dwell time and inflating every downstream cost.

> Note: exact percentages and dwell-time figures differ between reports. Treat any single figure as illustrative; the durable takeaway is that serverless breaches are commonly discovered late, and inadequate monitoring is the reason why.

## Common Misunderstandings

### Myth 1: "CloudWatch already logs everything"

**Reality**: The platform logs *execution*—start, end, duration, and whatever you printed. It does not log identity, request correlation, security outcomes, or intent. Security events must be emitted deliberately by your function code.

### Myth 2: "Each function logs, so we're covered"

**Reality**: Per-function logs in separate streams hide exactly the attacks that matter—the ones smeared across many functions. Without centralization and a shared correlation id, no one can see the campaign as a single event.

### Myth 3: "Monitoring is an ops concern, not security"

**Reality**: In serverless, cost *is* a security signal (denial-of-wallet), and invocation/error anomalies are how you detect abuse. Ops metrics and security detection are the same telemetry viewed with different questions.

### Myth 4: "We'll turn on tracing if we ever need to investigate"

**Reality**: Functions are ephemeral. If tracing and logging were not on *during* the attack, there is nothing to turn on afterwards—the invocations that mattered are gone. Detection must be instrumented before the incident.

### Myth 5: "Alerts on errors are enough"

**Reality**: Many attacks produce *successful* responses—valid-looking reads, authorised-but-abusive role use, quiet exfiltration. You must also alert on invocation spikes, cost spikes, and unusual identity/IAM behaviour, not just 5xx.

### Myth 6: "Logs are logs; retention and permissions don't matter"

**Reality**: If retention is days, evidence expires before investigation. If the function's own role can write and delete its log group, an attacker who owns the function can erase the trail. Retention must be adequate and tamper-resistant.

## How SAS-5 Differs from Related Issues

| Aspect | Inadequate Monitoring & Logging (SAS-5) | Event-Data Injection (SAS-1) | Denial-of-Wallet / Resource Exhaustion (SAS-8) |
|--------|------------------------------------------|-------------------------------|-------------------------------------------------|
| **Root cause** | No security visibility across functions | Untrusted event data reaches a sink | Unbounded, billable invocation |
| **What it does** | Lets other attacks go unnoticed | Executes attacker intent | Drives cost/exhaustion |
| **Typical fix** | Log security events, correlate, trace, alert | Validate/parameterise event input | Throttle, cap concurrency, budget alarms |
| **Detection** | It *is* the detection layer | Payload/behaviour analysis | Invocation & cost anomaly alerts |

## Key Takeaways

1. **Serverless is blind by default**—ephemeral, event-driven, distributed functions emit operational logs, not security telemetry.
2. **Security events must be logged by your code**—with identity, source, resource, and outcome, not just start/end.
3. **Correlate and trace across the chain**—a shared request/trace id and distributed tracing turn scattered invocations into one visible story.
4. **Alert on anomalies, including cost**—error, invocation, and spend spikes, plus unusual IAM use, are how you catch what "success" hides.
5. **Instrument before the incident**—you cannot retro-fit visibility onto invocations that already vanished.

## How to Identify if You're Vulnerable

- [ ] Do your functions log security-relevant events (authz decisions, validation failures, sensitive access) with identity and request context?
- [ ] Are logs centralized and correlated across functions and services (a shared request/trace id), not siloed per function?
- [ ] Is distributed tracing (X-Ray or OpenTelemetry) enabled across the function chain?
- [ ] Do you alert on error-rate, invocation-rate, and *cost* spikes—not just crashes?
- [ ] Do you alert on unusual IAM/role usage (a function calling services it never normally touches)?
- [ ] Are management- and data-plane events from managed services (CloudTrail, S3, DynamoDB) captured and correlated?
- [ ] Is log retention long enough to investigate, and are log stores tamper-resistant against the function's own role?
- [ ] Have you baselined "normal" behaviour so anomalies are detectable?
- [ ] Are security alerts wired into an incident-response process, not just a dashboard no one watches?
- [ ] Could you reconstruct, today, exactly what a single suspicious request did across every function it touched?

If you answered "no" or "not sure" to several of these, an attacker could already be operating in your functions unseen.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attacker activity goes undetected across ephemeral functions
- **[Prevention](prevention.md)**: Build security logging, correlation, tracing, and anomaly alerting
- **[Examples](examples.md)**: Vulnerable vs. secure logging, tracing, and alerting in Lambda
