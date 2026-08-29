# SAS-9: Serverless Business Logic Manipulation - Overview

## Table of Contents

- [What is Serverless Business Logic Manipulation?](#what-is-serverless-business-logic-manipulation)
- [Why Does This Matter?](#why-does-this-matter)
- [The Distributed Flow Problem](#the-distributed-flow-problem)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Characteristics](#prevalence-and-characteristics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Serverless Business Logic Manipulation?

**Serverless Business Logic Manipulation** is the abuse of an application's *intended flow*. A serverless application is rarely one program: it is many small functions chained together by events, queues, topics, and orchestration—Step Functions, SQS/SNS, EventBridge, DynamoDB Streams. The complete business rule ("validate the cart, charge the card, *then* fulfil the order") is not enforced in a single place. It is **distributed across independent functions**, and each function tends to assume that whatever ran before it ran correctly.

That assumption is the vulnerability. When the steps of a workflow are separate, independently-invokable units, an attacker who can reach a *later* step directly—or reorder, replay, or forge the events that connect the steps—can make the application do things the designed sequence would never allow: fulfil an unpaid order, grant access without an approval, redeem a credit twice, or skip a fraud check entirely.

> **The one-sentence version:** In serverless, the business logic is spread across many functions connected by events—so anyone who can invoke a step out of order, replay an event, or tamper with the state passed between steps can bypass the rules the intended flow was supposed to guarantee.

This is distinct from injection or broken authentication. Every function may authenticate correctly and every input may be well-formed; the flaw is that the *sequence and preconditions* are not enforced where they need to be—at every step—because each function trusts its upstream.

### Core Concept

```
Intended flow (what the designer drew):
  [validateCart] -> [chargePayment] -> [fulfilOrder] -> [grantAccess]
        every arrow is an event / queue / state transition

What the attacker sees (each box is separately reachable):
  [validateCart]   [chargePayment]   [fulfilOrder]   [grantAccess]
        |                |                 |                |
   skip it          skip it          INVOKE THIS       INVOKE THIS
                                     directly          directly

Manipulations available:
  - Invoke a LATER step directly, skipping validation/payment/authz
  - Replay or reorder the events that connect steps
  - Duplicate delivery -> a non-idempotent step runs twice (double-spend)
  - Tamper with intermediate state (Step Functions state, a DynamoDB
    "paid=true" flag, an S3 object) that a downstream step trusts
  - Forge an event onto a queue/topic a function consumes
```

### Why It's Critical for Serverless

Traditional monoliths tend to run a whole transaction inside one process, where the sequence is enforced by ordinary control flow—you cannot call the "fulfil" branch without first passing through the "charge" branch in the same function. Serverless deliberately decomposes that transaction. The properties that make serverless attractive are the same properties that expose the flow:

- Each step is an **independently invokable function** with its own trigger; if its invoke permission or event source is loose, it can be fired out of band.
- Steps communicate through **at-least-once messaging** (SQS, SNS, EventBridge). Duplicate and out-of-order delivery are normal, not exceptional—so a handler that isn't idempotent is a double-processing bug waiting to happen.
- State is **handed between functions** as data (Step Functions state, DynamoDB records, S3 objects). If a downstream function trusts that data without re-checking it, tampering upstream changes the outcome.
- The flow is **asynchronous**. A function often assumes a prior async step already finished; race conditions and timing gaps become exploitable business logic.

## Why Does This Matter?

### Business Impact

- **Payment Bypass**: Fulfilment or provisioning triggered without a completed, verified payment step—goods shipped, licences issued, or credit granted for free.
- **Double-Spend / Double-Provision**: A duplicate queue delivery processed twice redeems a coupon, refunds an order, or credits a wallet more than once.
- **Authorization Bypass**: An "approve" or "grant access" step invoked out of band skips the human approval or policy check the workflow was built around.
- **Fraud-Control Evasion**: Risk, KYC, or velocity checks placed as an earlier step are simply skipped by entering the flow later.
- **Financial and Inventory Loss**: Every one of the above maps directly to money lost, inventory over-committed, or entitlements over-granted.

### Technical Impact

- **Broken Invariants**: System state that "cannot happen" in the designed flow (fulfilled-but-unpaid, granted-but-unapproved) becomes reachable.
- **Non-Idempotent Side Effects**: Exactly-once business effects (charge, ship, credit) execute multiple times under at-least-once delivery.
- **State Tampering**: Downstream logic that trusts an intermediate flag or payload is steered by modifying that data between steps.
- **Event Forgery**: A function consuming a queue/topic acts on messages an attacker was able to publish, as if they came from a legitimate upstream.
- **Race Conditions**: Concurrent or reordered executions interleave in ways single-threaded reasoning never anticipated.

## The Distributed Flow Problem

The heart of this category is that a workflow drawn as a straight line is, in reality, a set of loosely coupled components. Consider a checkout implemented as five functions:

| Step | Function | Precondition the designer assumed | What actually enforces it? |
|------|----------|-----------------------------------|----------------------------|
| 1 | `validateCart` | Cart items exist and are in stock | Nothing downstream re-checks |
| 2 | `runFraudCheck` | Order passed risk scoring | Nothing downstream re-checks |
| 3 | `chargePayment` | Card was actually charged | A `paid=true` flag in DynamoDB |
| 4 | `fulfilOrder` | Steps 1–3 completed | Trusts the incoming event/flag |
| 5 | `grantAccess` | Order was fulfilled | Trusts the incoming event |

Every "precondition" in that table is an *assumption*, not a *control*. If `fulfilOrder` can be invoked directly, or reached by publishing a crafted event, or reached with a tampered `paid=true` flag, then steps 1–3 never happened—yet the order ships. The designed sequence lived only in the diagram; it was never enforced at step 4.

> A distributed workflow is only as sequential as its *weakest re-check*. If any later step trusts that earlier steps ran, that step is the entry point an attacker will use.

## Technical Context

### Common Manipulation Scenarios

#### 1. Direct Invocation of a Later Step

```bash
# The fulfilment function is invokable by anyone with the permission,
# or exposed via a Function URL / API route, or triggered by a topic
# the attacker can publish to:
aws lambda invoke --function-name fulfilOrder \
  --payload '{"orderId":"A-1001","items":[...]}' out.json

# fulfilOrder assumes chargePayment already ran. It did not.
```

**Risk**: The paid/validated/approved preconditions are skipped entirely by entering the workflow at a later node.

#### 2. Replaying or Reordering Events

```
# Capture a legitimate "order.paid" event, then replay it N times, or
# deliver "order.fulfilled" before "payment.captured" ever fires.
EventBridge/SNS/SQS deliver the same or out-of-order events,
and each consumer acts on them as if authentic and in-sequence.
```

**Risk**: Replays trigger repeated fulfilment; reordering defeats sequence-dependent guards.

#### 3. Duplicate Delivery and Non-Idempotent Handlers

```
SQS/SNS/EventBridge guarantee AT-LEAST-ONCE delivery.
The same message CAN and WILL be delivered more than once.

Non-idempotent handler:
  on message -> creditWallet(userId, 50)   # runs twice -> +100
  on message -> shipItem(orderId)          # runs twice -> two shipments
```

**Risk**: Double-spend, double-refund, double-provision—without any "attack" beyond normal duplicate delivery, and amplifiable on purpose.

#### 4. Tampering with Intermediate State

```
Downstream function reads a flag/object an upstream step wrote:
  paid = ddb.get(orderId).paid            # trusts "paid": true
  state = event.detail                    # trusts Step Functions state
  doc = s3.get("orders/A-1001/status")    # trusts an S3 object

If the attacker can write that flag/object (loose IAM, a separate
write path, an unsigned state blob), the downstream logic is steered.
```

**Risk**: The precondition a later step relies on is forged by editing the data it trusts.

#### 5. Forging Events onto a Consumed Queue/Topic

```bash
# If a function consumes a queue/topic the attacker can publish to:
aws sns publish --topic-arn arn:...:order-events \
  --message '{"type":"order.paid","orderId":"A-1001"}'

# The consumer treats the forged event as a legitimate upstream signal.
```

**Risk**: The attacker manufactures the "prior step happened" signal the consumer trusts.

### Where the Sequence Silently Breaks

| Mechanism | Manipulation | Consequence |
|-----------|--------------|-------------|
| Function invoke (IAM / URL) | Call a later step directly | Skip validation / payment / authz |
| Queue / topic (SQS, SNS) | Forge or replay events | Fake or repeat an upstream signal |
| At-least-once delivery | Process a duplicate twice | Double-spend / double-provision |
| Shared state (DynamoDB, S3) | Tamper a trusted flag/object | Forge a precondition |
| Orchestration state | Alter unsigned inter-step data | Steer the downstream branch |
| Async timing | Race / reorder steps | Interleave in an unsafe order |

## Real-World Impact

Business-logic manipulation is documented as a *class* of problem across event-driven and serverless systems. The examples below describe the recurring incident patterns—not specific named breaches—because the value is in recognising the shape of the flaw.

### Pattern 1: Workflow-Bypass Fulfilment

**Setup**:

- A checkout is split into validation, payment, and fulfilment functions connected by events.
- The fulfilment function is reachable—directly via a broad invoke permission or Function URL, or by publishing to the topic it consumes—and it trusts that payment already succeeded.

**Impact**:

- An attacker triggers fulfilment for orders that were never paid or never risk-checked, obtaining goods, licences, or access for free.

**Root Cause**: The payment/authorization precondition was enforced only by the *position* of the step in the intended flow, never re-verified inside the fulfilment step.

### Pattern 2: Duplicate-Processing Double-Spend

**Setup**:

- A wallet-credit, refund, or coupon-redeem function consumes an SQS/SNS message.
- The handler performs its financial side effect without deduplicating on a message or idempotency key.

**Impact**:

- Normal at-least-once duplicate delivery—or an attacker deliberately re-submitting—causes the credit/refund/redemption to apply multiple times, creating money or entitlements out of nothing.

**Root Cause**: The handler assumed exactly-once delivery. The platform provides at-least-once, so any non-idempotent effect is inherently double-counted under retries.

### Pattern 3: Trusted-State Tampering

**Setup**:

- A downstream step reads a `status`/`approved`/`paid` flag written by an earlier step to DynamoDB or S3.
- A separate, over-permissioned path (a broad IAM role, an unauthenticated write, or an unsigned state blob passed between steps) lets that flag be set independently.

**Impact**:

- Setting the flag to its "success" value makes the downstream step behave as though the earlier controls passed, granting the outcome without them.

**Root Cause**: Intermediate state was treated as trusted server-side data when it was actually attacker-influenceable, and it was neither integrity-protected nor re-validated by the consumer.

## Prevalence and Characteristics

Business logic manipulation is inherently **application-specific**, which makes it both common and hard to catch with generic tooling. Scanners find injection and misconfiguration; they rarely understand that "fulfil" should be unreachable without "pay."

- It is characterised as **high-impact and low-visibility**: exploitation often looks like a normal, well-formed invocation or a normal duplicate delivery.
- The most common sub-issues are **missing per-step re-validation, non-idempotent handlers, over-broad invoke permissions, and trusted-but-tamperable intermediate state**.
- It is frequently found **only by design review and abuse-case testing**, because it is a property of how the functions are wired together, not of any single function in isolation.

> Note: exploitation leaves little that looks anomalous in a single function's logs—each invocation is individually valid. The signal lives in the *relationships* between steps (a fulfilment with no matching payment, two credits for one message id), which is exactly what per-function monitoring misses.

## Common Misunderstandings

### Myth 1: "The workflow diagram enforces the order"

**Reality**: A diagram is documentation. Unless each step re-checks its preconditions, the order exists only on paper—any step reachable out of band runs regardless of what came before.

### Myth 2: "Only our functions can invoke each other, so it's safe"

**Reality**: This is only true if invoke permissions and event-source policies are actually tight. Broad IAM, Function URLs, and topics/queues that accept outside publishes routinely make "internal" steps externally reachable.

### Myth 3: "Queues deliver each message once"

**Reality**: SQS, SNS, and EventBridge are *at-least-once*. Duplicates and reordering are guaranteed to happen eventually. A handler that isn't idempotent is not "mostly fine"—it is a latent double-spend.

### Myth 4: "The earlier step already validated it"

**Reality**: The earlier step validated it *in the intended path*. A later step cannot assume it was reached through that path; it must re-validate authorization and required state itself.

### Myth 5: "State we wrote is state we can trust"

**Reality**: A DynamoDB flag or S3 object is only trustworthy if nothing else can write it and its integrity is verified. Intermediate state passed between steps should be validated—and, where it crosses a trust boundary, signed.

### Myth 6: "This is just an authorization bug"

**Reality**: Authorization is part of it, but idempotency, sequencing, event integrity, and race conditions are equally central. Fixing IAM alone leaves duplicate-processing and state-tampering wide open.

## How Business Logic Manipulation Differs from Related Issues

| Aspect | Business Logic Manipulation | Broken Authentication (SAS-2) | Event-Data Injection (SAS-1) |
|--------|-----------------------------|-------------------------------|------------------------------|
| **Root cause** | Distributed flow not enforced per step | Identity not proven or verified | Untrusted data reaches an interpreter |
| **Input is** | Well-formed and often authentic | Missing/forged credentials | Malicious payload in a field |
| **Where it lives** | Between functions (wiring & sequence) | At the auth boundary | At a data sink |
| **Typical fix** | Re-validate + idempotency + tight invoke | Verify identity everywhere | Validate + parameterise |
| **Detection** | Design review, abuse cases, invariant checks | Auth testing | Fuzzing, code review |

## Key Takeaways

1. **The flow is distributed**—the business rule lives across many functions, not in one place, so no single function enforces the whole sequence.
2. **Every later step must re-validate**—authorization and required state have to be re-checked at each step; trusting the upstream is the bug.
3. **At-least-once is the default**—handlers with real side effects must be idempotent, or duplicates become double-spends.
4. **Intermediate state is untrusted until proven**—validate it, restrict who can write it, and sign it across trust boundaries.
5. **Lock the doors**—restrict who and what can invoke each function so steps cannot be fired out of band.

## How to Identify if You're Vulnerable

Ask these questions about your serverless workflows:

- [ ] If someone invoked the *last* step of a workflow directly, would it refuse because earlier steps did not run?
- [ ] Does every step re-check authorization and the required prior state, rather than trusting the event that reached it?
- [ ] Are all financial/provisioning handlers idempotent (dedupe on a message or idempotency key)?
- [ ] Do you assume exactly-once delivery anywhere? (You should assume at-least-once.)
- [ ] Can any queue/topic your functions consume be published to from outside the intended producer?
- [ ] Is intermediate state (DynamoDB flags, S3 objects, inter-step payloads) writable only by the step that owns it, and validated by consumers?
- [ ] Is inter-step state that crosses a trust boundary integrity-protected (signed) rather than blindly trusted?
- [ ] Are invoke permissions and Function URLs scoped so later steps cannot be called out of band?
- [ ] Do you verify the source and integrity of each event before acting on it?
- [ ] Have you written abuse-case tests that try to skip, replay, reorder, and duplicate steps?

If you answered "no" or "not sure" to several of these, an attacker can likely bend your workflow today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers skip, replay, reorder, and forge steps
- **[Prevention](prevention.md)**: Re-validate every step, enforce idempotency, and lock invocation
- **[Examples](examples.md)**: Vulnerable vs. secure Lambda & Step Functions workflows (Node.js & Python)
- **[Serverless Security Track](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Range](/practice)**: Apply these techniques hands-on
