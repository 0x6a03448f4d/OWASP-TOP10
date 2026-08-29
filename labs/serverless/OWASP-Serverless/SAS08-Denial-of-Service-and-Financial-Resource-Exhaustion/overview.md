# SAS-8: Denial of Service and Financial Resource Exhaustion - Overview

## Table of Contents
- [What is Denial of Service & Financial Resource Exhaustion?](#what-is-denial-of-service--financial-resource-exhaustion)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Denial of Service & Financial Resource Exhaustion?

**Denial of Service & Financial Resource Exhaustion** is what happens when the two properties that make serverless attractive—*it scales automatically* and *you pay per use*—are turned against you. Because functions scale out on demand, an attacker can exhaust the finite concurrency your account or region is allowed and starve legitimate traffic (a classic denial of service). Because every invocation and every millisecond of execution is billed, that same flood becomes a **financial** attack: the platform keeps scaling and keeps charging, and the bill—not an outage—is the damage. This second, serverless-specific variant is widely called **Denial of Wallet (DoW)**.

The weakness is not one broken function. It is the accumulated absence of *limits*: no per-function concurrency cap, no rate limiting on public endpoints, timeouts and memory sized far larger than needed, event sources wired into loops that amplify themselves, and no cost controls to notice or halt a spike. On traditional infrastructure a flood eventually hits a fixed ceiling—the server falls over and stops costing more. Serverless removes that ceiling by design: it elastically absorbs the load, so the natural failure mode shifts from "the box crashed" to "the meter kept running."

### Core Concept

```
Two linked risks from the same root (no limits):

  (1) Denial of Service (DoS)
      Concurrency is finite (account/region cap).
      One function hogging concurrency starves EVERY other function.
      Legitimate traffic is throttled (429/503) while the flood runs.

  (2) Denial of Wallet (DoW)  -- the serverless twist
      Billing is per-invocation + per-GB-second of duration.
      Auto-scaling means the platform NEVER refuses the load...
      ...it just keeps scaling and keeps charging.
      Damage = a massive invoice, not (only) an outage.

Bounded (safe):
  Concurrency  -> per-function RESERVED cap; account limit understood
  Endpoints    -> API Gateway throttling + usage-plan quotas + WAF rate rules
  Duration     -> short timeouts, right-sized memory
  Input        -> payload size limits, pagination caps
  Events       -> no self-triggering loops; DLQs; bounded retries
  Cost         -> Budgets + Cost Anomaly Detection + CloudWatch alarms

Unbounded (vulnerable):
  Concurrency  -> no reserved cap; one function can consume the whole account
  Endpoints    -> public, anonymous, no throttle, no quota, no WAF
  Duration     -> 15-min timeout + max memory "just in case"
  Input        -> unbounded body/loop drives long, expensive runs
  Events       -> S3-write loop / fan-out storm / uncapped retries
  Cost         -> no budget, no alarm; first signal is the bill
```

### Why It's Critical for Serverless

Serverless concentrates several conditions that make resource exhaustion especially damaging:

- It **auto-scales without a human in the loop**, so there is no natural back-pressure—the platform will happily spin up thousands of concurrent executions in response to a flood.
- It is **billed per invocation and per duration**, so load converts directly into money; a denial-of-service and a denial-of-wallet are the *same* attack viewed through availability vs. cost.
- Concurrency is a **shared, finite pool**. Account- and region-level limits mean one greedy function can throttle unrelated functions in the same account—the blast radius is the whole tenant, not one service.
- It is **event-driven**, so functions can trigger themselves or fan out—an S3 write that invokes a function that writes to the same bucket is an infinite, self-amplifying, self-billing loop.
- **Retries multiply cost.** Asynchronous invocations and stream/queue sources retry on failure; a function that fails expensively is charged for every retry.

## Why Does This Matter?

### Business Impact

- **Runaway Cloud Bill (Denial of Wallet)**: The signature serverless impact. Pay-per-use turns a flood into an invoice that can climb by orders of magnitude before anyone notices, because nothing crashed to raise the alarm.
- **Full-Application Outage**: Because concurrency is shared, one exhausted function throttles the rest. A DoS against a single public endpoint can take down every other function in the account.
- **Forced Trade-off Under Pressure**: Teams discovering a live DoW must choose between leaving functions running (cost keeps climbing) and disabling them (self-inflicted outage)—both are bad.
- **Budget and Forecast Destruction**: Even a short spike can blow a monthly cloud budget, distort forecasts, and trigger difficult conversations with finance and providers over unplanned charges.
- **Amplified by Downstream Costs**: Each abusive invocation may call paid downstream services (databases, third-party APIs, other functions), multiplying the per-request cost far beyond the function's own price.

### Technical Impact

- **Concurrency Exhaustion**: The account/region concurrency limit is consumed, so new invocations of *any* function are throttled—a platform-wide availability failure.
- **Self-Amplification**: Recursive triggers and fan-out storms cause invocation counts to grow without bound from a single initial event.
- **Retry Multiplication**: A function that errors is retried by its event source; expensive failures are billed repeatedly, accelerating both cost and concurrency pressure.
- **Downstream Overload**: A flood of functions opening connections can exhaust a database's connection pool or a downstream API's rate limit, cascading the outage beyond the functions themselves.
- **Degraded, Not Failed**: Because the platform absorbs load, symptoms are subtle—latency, throttles, and cost—rather than a clean crash, which delays detection.

## Technical Context

### Why Serverless Turns a Flood Into a Bill

On a fixed server, throughput has a hard ceiling: once CPU and memory are saturated, the box refuses or drops work, and—crucially—the cost stops rising. Serverless deliberately removes that ceiling. The platform meets demand by launching more concurrent executions, and it charges for each one. So the same attack that would merely have *degraded* a server instead scales elastically and bills elastically. The finite resource is no longer CPU on one host; it is your **account concurrency limit** (availability) and your **budget** (money).

```
Traditional server under flood:
  requests -> queue -> saturate CPU/RAM -> drop/refuse -> cost is FLAT (fixed box)
  Failure mode: outage. Bill: unchanged.

Serverless under flood:
  requests -> auto-scale concurrency -> platform keeps accepting -> $$$ climbs
  Failure mode: (a) throttle once account limit hit  AND/OR  (b) huge bill.
  The "ceiling" that protected you is gone by design.
```

### Common Exhaustion Scenarios

#### 1. Unbounded / Expensive Functions

```
# A function provisioned "just in case":
  memorySize: 3008 MB      # billed per GB-second -> ~10x a 256 MB function
  timeout:    900 s        # a slow/looping request can run for 15 minutes
# One expensive invocation is costly; a flood of them is catastrophic.
```

**Risk**: Oversized memory and long timeouts multiply the cost and concurrency held by every single invocation.

#### 2. No Rate Limiting on Public Endpoints

```
POST /api/render   (anonymous, no API key, no throttle, no WAF)
# An attacker replays this as fast as their bandwidth allows.
# Every request is a billable invocation; nothing caps the rate.
```

**Risk**: A public, anonymous endpoint with no throttle is an open tap on both concurrency and spend.

#### 3. Recursive / Self-Triggering Invocations

```
S3 bucket "uploads"  --(ObjectCreated)-->  resizeFn
resizeFn writes the resized image BACK into "uploads"
        --(ObjectCreated)-->  resizeFn  --(ObjectCreated)-->  resizeFn ...
# An infinite loop that scales and bills itself with no external attacker.
```

**Risk**: An event source that a function feeds back into creates an unbounded, self-billing loop.

#### 4. Amplification via Event Sources

```
# Fan-out: one message -> many messages -> many invocations
SNS/EventBridge fan-out, SQS re-drive without a cap, or a function
that publishes N events per invocation. Retries on failure multiply again:
  1 poisoned message -> repeated redelivery -> repeated (billed) invocations.
```

**Risk**: Fan-out and uncapped retries turn a small trigger into an exponential invocation storm.

#### 5. Expensive Downstream Calls

```
# Each invocation calls a metered third-party API and a database:
  function()  ->  paid-translation-API  +  RDS query  +  another Lambda
# The function's own price is the SMALL part of the per-request cost.
```

**Risk**: Downstream metered services and connection pools can be exhausted or run up long before the function budget is.

### Where the Limits Are Missing

| Layer | Missing Limit | Consequence |
|-------|---------------|-------------|
| Function config | No reserved concurrency cap | One function drains the whole account's concurrency |
| Function config | Oversized memory / long timeout | Each invocation costs and holds far more than it needs |
| API Gateway | No throttling / usage-plan quota | Unbounded request rate becomes unbounded invocations |
| Edge | No WAF rate rule | Anonymous floods reach the function directly |
| Event source | Self-trigger / no DLQ / uncapped retries | Recursive loops and retry storms self-amplify |
| Input handling | No payload/pagination limits | Large inputs drive long, expensive runs |
| Cost / observability | No Budgets, anomaly detection, or alarms | The first signal of abuse is the invoice |

## Real-World Impact

The examples below are described as **incident classes**—patterns repeatedly observed and documented across the industry—rather than specific named breaches with invented figures. No dollar amounts or invocation counts are asserted here; the durable lesson is in the *mechanism*.

### Case Class 1: Denial-of-Wallet Cost Spike Against a Public Function

**Weakness**:
- A function reachable from the internet (an API route or a public trigger) has no rate limiting, no reserved concurrency cap, and no cost alerting.

**Impact**:
- Automated abuse drives invocations up by orders of magnitude. Because pay-per-use billing scales silently, the financial impact accrues unnoticed until it appears on the invoice—the widely documented "denial-of-wallet" pattern unique to serverless economics. Developers have repeatedly reported unexpectedly large bills from exactly this class of abuse.

**Root Cause**: Auto-scaling with no rate limit and no cost control; nothing capped the invocation rate or connected the spike to a human in time to stop it.

### Case Class 2: Concurrency-Exhaustion Denial of Service

**Weakness**:
- No per-function reserved concurrency cap, so a single flooded (or looping) function is free to consume the entire account/region concurrency pool.

**Impact**:
- Once the shared limit is reached, *unrelated* functions in the same account are throttled and start returning errors—a full-application outage caused by one endpoint. This "noisy neighbour" starvation is a recurring, well-understood serverless failure mode.

**Root Cause**: Concurrency treated as unlimited; without reserved caps, one function's load is every function's problem.

### Case Class 3: Recursive Event-Source Loop (Self-Inflicted)

**Weakness**:
- A function is triggered by an event source it also writes to (the classic S3→Lambda→same-bucket loop), or fans out messages that trigger itself, with no loop guard.

**Impact**:
- A single initial event spawns an unbounded chain of invocations that scales and bills itself—no external attacker required. Cloud providers now explicitly warn about, and offer built-in detection for, recursive-invocation loops precisely because this class of self-inflicted incident is so common.

**Root Cause**: An event topology wired into a cycle, with no idempotency check, prefix separation, or recursion guard to break it.

## Prevalence and Statistics

Denial of Service & Financial Resource Exhaustion is a distinctive member of the OWASP Serverless Top 10 (as SAS-8) and echoes the broader industry concern of "Unrestricted Resource Consumption" (OWASP API Security Top 10). It is distinctive because serverless adds a *financial* dimension that traditional DoS does not have: the platform's greatest strength—seamless auto-scaling—is exactly what makes the attack pay off.

Rather than cite precise figures (which vary by source and year), the defensible picture is:

- Resource-exhaustion and rate-limiting failures are consistently characterised by OWASP as **common and easy to trigger**—an unthrottled public endpoint is exploitable with nothing more than a loop.
- The most commonly observed gaps are **no reserved concurrency caps, no API-layer throttling or quotas, oversized timeouts/memory, unguarded recursive triggers, and no cost alerting**.
- The impact is rated **availability- and cost-severe**: it ranges from throttling the whole account (DoS) to an uncapped, self-scaling bill (DoW), often at the same time.

> Note: exact percentages and dollar figures differ between reports and are easy to sensationalise. Treat any single number as illustrative; the durable takeaway is that auto-scaling without limits converts a flood into either an outage, a bill, or both—cheaply and reliably.

## Common Misunderstandings

### Myth 1: "Serverless auto-scales, so it can't be DoS'd"

**Reality**: Auto-scaling defers the failure; it does not remove it. Concurrency is finite at the account/region level, and cost is unbounded. You trade "the server fell over" for "everything is throttled and the bill exploded."

### Myth 2: "Pay-per-use means I only pay for real usage"

**Reality**: You pay for *every* invocation, including malicious and looping ones. Pay-per-use is exactly what makes denial-of-wallet possible: the attacker spends your money, not their own.

### Myth 3: "One function's traffic can't affect my other functions"

**Reality**: Concurrency is a shared account pool. Without reserved caps, one function's flood starves every other function—the blast radius is the whole account, not one service.

### Myth 4: "Retries make things more reliable, so they're always good"

**Reality**: Retries also multiply cost and concurrency. A function that fails expensively is billed for each automatic retry; without capped retries and dead-letter queues, failure becomes an amplifier.

### Myth 5: "A recursive loop would be obvious immediately"

**Reality**: An S3-write or fan-out loop can scale to thousands of invocations in minutes while every individual invocation looks normal. Without a recursion guard and invocation/cost alarms, the first clear signal is the bill.

### Myth 6: "A budget alert will stop the spending"

**Reality**: AWS Budgets and Cost Anomaly Detection *notify*; they do not automatically cap spend. Alerts must be paired with enforceable controls—reserved concurrency caps, throttles, and automated responses—to actually halt an attack.

## How SAS-8 Differs from Related Issues

| Aspect | DoS & Financial Exhaustion (SAS-8) | Inadequate Monitoring (SAS-5) | Broken Authentication (SAS-2) |
|--------|-------------------------------------|-------------------------------|-------------------------------|
| **Root cause** | No limits on scaling, cost, or recursion | No security visibility across functions | Weak/absent identity checks |
| **What it does** | Exhausts concurrency and/or runs up the bill | Lets other attacks go unnoticed | Grants unauthorised access |
| **Typical fix** | Reserved concurrency, throttling, timeouts, cost controls | Log, correlate, trace, alert | Enforce authn/authz per function |
| **Detection** | Invocation & cost anomaly alarms | It *is* the detection layer | Auth-failure and anomaly logs |

## Key Takeaways

1. **Auto-scaling has no natural ceiling**—serverless trades "the box crashes" for "concurrency is throttled and the bill keeps climbing."
2. **DoS and Denial of Wallet are one attack**—a flood that exhausts concurrency also runs up cost; pay-per-use makes availability and money the same target.
3. **Concurrency is shared and finite**—without reserved caps, one greedy function starves the whole account.
4. **Recursion and retries amplify**—self-triggering event sources and uncapped retries turn small events into unbounded, self-billing storms.
5. **Alerts are not enforcement**—budgets and anomaly detection notify; caps, throttles, and automated responses are what actually stop the spend.

## How to Identify if You're Vulnerable

- [ ] Does every function have a **reserved concurrency** cap so it cannot drain the whole account?
- [ ] Do you know your account/region concurrency limit and how much headroom remains for other functions?
- [ ] Are public endpoints protected by API Gateway **throttling and usage-plan quotas** (and, ideally, WAF rate rules)?
- [ ] Are function timeouts as short as the workload allows, and is memory right-sized rather than maxed "just in case"?
- [ ] Do you enforce input/payload size limits and pagination caps so a single request can't run unbounded?
- [ ] Are event sources free of self-triggering loops (e.g. an S3-write loop), with dead-letter queues and **capped retries**?
- [ ] Do you have recursion/loop detection enabled or a guard in code against self-amplification?
- [ ] Are downstream calls protected by timeouts and circuit breakers so they can't be exhausted or run up cost?
- [ ] Do you have **AWS Budgets, Cost Anomaly Detection, and CloudWatch alarms** on invocation count and estimated charges (ties to SAS-5)?
- [ ] Do public functions require authentication where possible, to reduce anonymous abuse (ties to SAS-2)?

If you answered "no" or "not sure" to several of these, a single loop or flood could throttle your application, run up your bill, or both.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How a flood or a loop becomes an outage and a bill
- **[Prevention](prevention.md)**: Cap concurrency, throttle, bound cost, and guard against recursion
- **[Examples](examples.md)**: Vulnerable vs. secure serverless.yml, API Gateway, Budgets, and WAF
