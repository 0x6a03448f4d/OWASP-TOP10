# SAS-9: Serverless Business Logic Manipulation - Attack Vectors

## Table of Contents

- [Understanding Logic-Manipulation Vectors](#understanding-logic-manipulation-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Manipulation Patterns](#manipulation-patterns)
- [Chaining Manipulation with Role Privileges](#chaining-manipulation-with-role-privileges)

## Understanding Logic-Manipulation Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in serverless applications you own or are authorised to test.

An attacker exploiting this weakness is not looking for a malformed input—the requests are usually perfectly well-formed. They are looking for a **step that trusts its upstream**: a function that assumes payment happened, that approval was granted, that validation passed, or that it will only ever see each message once. The exploit is to satisfy that assumption *falsely*—by entering the flow late, by manufacturing the "prior step" signal, by replaying it, or by editing the state the step reads.

The attacker's objectives in this category are usually:

- Reach a value-producing step (fulfil, grant, credit, refund) without paying the cost of the earlier steps.
- Make a single legitimate action happen more than once (double-spend / double-provision).
- Forge or tamper with the events and state that connect steps, so a downstream function acts on a lie.
- Exploit the function's IAM role once a step runs, to pivot across the workflow and the account.

### Core Attack Flow

```
1. Map the workflow
   |
   Which functions form the chain? What events/queues/state connect them?
2. Find the trusting step
   |
   Which later step acts WITHOUT re-checking payment/authz/prior state?
3. Find the door
   |
   Can I invoke it directly? Publish its event? Write its state? Replay it?
4. Enter the flow late (or twice)
   |
   Trigger the step out of order, or deliver its message again
5. Bank the outcome
   |
   Goods shipped, access granted, wallet credited -- controls skipped
6. Pivot on the role
   |
   Use the step's IAM credentials to reach more of the workflow
```

## Manipulation Patterns

### 1. Direct Invocation of a Downstream Step

A fulfilment or access-granting function is reachable on its own—through a broad `lambda:InvokeFunction` grant, a Function URL, or an API route—and it trusts that payment and validation already ran.

```bash
# The intended path is: validate -> charge -> fulfil.
# The attacker skips straight to fulfil:
aws lambda invoke --function-name fulfilOrder \
  --payload '{"orderId":"A-1001","items":[{"sku":"GPU","qty":1}]}' out.json

# fulfilOrder (vulnerable) assumes it was reached only after payment:
#   handler(event): ship(event.orderId, event.items)   # no paid-check
```

**Payoff**: goods, licences, or access delivered for orders that were never paid for or risk-checked—the earlier steps are simply not on the path the attacker took.

### 2. Forging the "Prior Step Happened" Event

A consumer subscribes to a topic/queue and treats each message as an authentic upstream signal. If the attacker can publish to that topic/queue, they manufacture the signal.

```bash
# The fulfilment consumer trusts "order.paid" events on this topic.
# If the topic accepts outside publishes (loose policy), forge one:
aws sns publish --topic-arn arn:aws:sns:...:order-events \
  --message '{"type":"order.paid","orderId":"A-1001","amount":0}'

# Consumer: on "order.paid" -> fulfil(orderId)   # never checks the charge
```

**Payoff**: the consumer acts as though a real payment event arrived. No later step re-verifies the charge with the payment provider, so the forged event is authoritative.

### 3. Replaying a Legitimate Event

A captured or re-submittable event is delivered again and again. Each delivery re-runs the downstream side effect.

```bash
# One real "refund.approved" event, replayed:
for i in 1 2 3 4 5; do
  aws sqs send-message --queue-url $REFUND_Q \
    --message-body '{"type":"refund.approved","orderId":"A-1001","amount":200}'
done

# Consumer refunds $200 each time -> $1000 refunded for one order.
```

**Payoff**: a single approved action becomes many. Replays are indistinguishable from legitimate retries unless the handler deduplicates.

### 4. Duplicate-Delivery Double-Spend (No Attacker Effort Required)

SQS, SNS, and EventBridge are at-least-once. The platform itself re-delivers messages on visibility timeouts and retries. A non-idempotent handler double-processes them—and an attacker can amplify this deliberately.

```
# Normal duplicate delivery already causes this:
on "wallet.credit" (msg m1) -> balance += 50   # delivered twice -> +100

# Deliberate amplification: submit many actions quickly so retries and
# concurrent consumers overlap, then rely on the missing idempotency key.
```

**Payoff**: wallet credits, coupon redemptions, refunds, or provisioning apply multiple times. This is the classic *duplicate-processing double-spend* class—it needs no forged input, only a handler that assumed exactly-once.

### 5. Tampering with Intermediate State (DynamoDB / S3 Flag)

A downstream step gates on a flag an earlier step wrote. If that flag is writable by another path, the attacker sets it directly.

```bash
# fulfilOrder gates on a DynamoDB flag set by chargePayment:
#   if item.paid == true: ship(order)
# If a broad role / separate write path can set it:
aws dynamodb update-item --table-name orders \
  --key '{"orderId":{"S":"A-1001"}}' \
  --update-expression 'SET paid = :t' \
  --expression-attribute-values '{":t":{"BOOL":true}}'

# Now the gate opens without any real charge.
```

**Payoff**: the precondition a later step relies on is forged by editing the shared state it trusts, rather than by going through the step that legitimately sets it.

### 6. Tampering with Orchestration State Between Steps

Step Functions (and hand-rolled orchestrators) pass a state object from one task to the next. If a task blindly trusts fields another task or the client placed there, those fields steer the branch.

```
# A state field decides the branch and the amount:
#   { "orderId":"A-1001", "approved": true, "amount": 0, "tier": "admin" }
# If any task copies client-supplied fields into state without validation,
# a downstream Choice/task acts on "approved": true and "tier":"admin".
```

**Payoff**: control-flow decisions and privileged parameters are dictated by tampered inter-step state instead of by verified server-side facts.

### 7. Reordering / Out-of-Sequence Delivery

Standard queues and fan-out do not guarantee order. A step that assumes "the previous message already arrived" can be hit before its predecessor.

```
# Intended: "payment.captured" precedes "order.fulfilled".
# Deliver them out of order (or make fulfil arrive first):
send "order.fulfilled" now
send "payment.captured" never (or much later)

# A fulfil handler that assumes capture already ran ships anyway.
```

**Payoff**: sequence-dependent guards are defeated because the sequence was assumed, not enforced—the consumer never confirms the predecessor completed.

### 8. Exploiting the Async Gap (Race Condition)

Between "check" and "act," an asynchronous system leaves a window. Concurrent invocations both pass the same check before either commits the effect.

```
# Coupon single-use check, then redeem -- but async and non-atomic:
#   if coupon.used == false:            # both concurrent runs read false
#       apply_discount(); coupon.used = true
# Fire 20 redemptions simultaneously; several pass the check before any
# write lands -> the "single-use" coupon is used many times.
```

**Payoff**: TOCTOU race turns a single-use rule into a multi-use one. The same shape breaks stock limits, one-per-customer offers, and balance checks.

### 9. Out-of-Band Guardrail Bypass

A guardrail (fraud scoring, human approval, quota check) is implemented as its own step. Entering the flow after it, or triggering the guarded action through a different trigger, skips the guardrail.

```bash
# The guarded action has two triggers: the reviewed path and a raw one.
# Reviewed:  request -> fraudCheck -> approve -> grantAccess
# Raw:       grantAccess is ALSO subscribed to an internal "provision" topic
aws sns publish --topic-arn arn:...:provision \
  --message '{"userId":"u9","role":"admin"}'   # bypasses fraudCheck+approve
```

**Payoff**: the control exists but is not on every path to the action; the attacker takes the path that misses it.

### 10. Idempotency-Key Abuse

Where an idempotency key exists but is attacker-supplied and unbound to the request contents, the attacker manipulates the key to force either replay or a fresh "first" processing.

```
# Handler dedupes on a client-provided key it never binds to the payload:
#   if seen(event.idempotencyKey): return cached
# Reuse one key across DIFFERENT payloads -> second payload returns the
# first's cached success (skips its own checks); or rotate the key to
# force the "exactly-once" effect to run again.
```

**Payoff**: a weak idempotency scheme is turned into either a bypass (wrong cached result) or a replay (repeat the effect), defeating the very control meant to prevent double-processing.

## Chaining Manipulation with Role Privileges

Logic manipulation is often the foothold; the execution role decides how far it spreads. Once a step runs on the attacker's terms, its IAM permissions are available to the code—and to any state or downstream steps it can reach.

```
Direct-invoke fulfilOrder                  -> ships one unpaid order
        +
Its role has dynamodb:UpdateItem on orders  -> flip paid=true for many orders
        +
Its role can sns:Publish to order-events    -> forge "paid" for the whole fleet
        =  one reachable step -> workflow-wide free fulfilment
```

A second chain weaponises duplicate processing at scale:

```
Non-idempotent creditWallet handler   -> each duplicate = free money
        -> submit N actions, rely on at-least-once retries
        -> concurrent consumers double-process without a dedup key
        -> balance inflates faster than reconciliation notices
```

A third chain uses state tampering to launder the bypass as legitimate:

```
Write paid=true / approved=true directly in DynamoDB
        -> downstream steps now see a "valid" order
        -> audit trail shows a normal fulfilment (state looked paid)
        -> the missing charge is only visible by reconciling with the PSP
```

## Key Takeaways

1. **Attackers enter the flow late**—they invoke, forge, or replay their way to the value-producing step, skipping the steps that cost them something.
2. **Well-formed does not mean legitimate**—the requests look normal; the abuse is in sequence, repetition, and trust.
3. **At-least-once delivery is a weapon**—duplicate and replayed events double-spend any non-idempotent handler with no exotic payload required.
4. **Trusted state is tamperable state**—flags and inter-step payloads a downstream step believes can be forged if writable or unsigned.
5. **The role sets the blast radius**—a manipulated step plus a broad role turns one bypass into a workflow-wide compromise.

## Next Steps

- **[Prevention Guide](prevention.md)**: Re-validate every step, enforce idempotency, and lock invocation
- **[Code Examples](examples.md)**: Vulnerable vs. secure Lambda & Step Functions workflows
- **[Serverless Security Track](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Range](/practice)**: Try these vectors hands-on
