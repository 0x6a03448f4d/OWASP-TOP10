# SAS-9: Serverless Business Logic Manipulation - Prevention

## Prevention Strategy Overview

Preventing business-logic manipulation is one principle applied at every node: **no step may trust that the steps before it ran—each function re-establishes its own preconditions**, and every side effect is made safe to repeat. Because the platform gives you at-least-once delivery and independently invokable functions, you cannot rely on position in a diagram to enforce order. You have to enforce it in code. That gives a layered plan:

1. Re-validate authorization and required prior state at the top of every step.
2. Make every handler idempotent—dedupe on a message/idempotency key so effects happen exactly once.
3. Orchestrate server-side; do not let the client drive the sequence, and validate the state passed between steps.
4. Restrict who and what can invoke each function so steps cannot be fired out of band.
5. Verify the source and integrity of every event before acting on it.
6. Enforce sequencing and guardrails on every path to a guarded action, and detect broken invariants.

### Core Principles

- **Trust nothing upstream**: a step is reached through many paths; it must prove its own preconditions, not assume the intended path was taken.
- **Design for at-least-once**: duplicates and reordering are guaranteed; correctness cannot depend on exactly-once or in-order delivery.
- **State is data, not truth**: an intermediate flag or payload is only trustworthy if it is access-controlled and, across a trust boundary, integrity-protected.
- **Contain the blast radius**: least-privilege invoke and execution roles turn a bypass of one step into a contained failure.

## 1. Re-Validate Authorization and State at Every Step

The single most important control: every function re-checks authorization and the required prior state before it acts. Do not trust that the event reaching you implies the earlier steps ran.

```javascript
// Node.js -- fulfilOrder re-establishes its own preconditions.
// It does NOT trust that "being invoked" means payment happened.
exports.handler = async (event) => {
  const orderId = requireString(event.orderId);

  // 1. Re-read authoritative state (written only by the payment step).
  const order = await getOrder(orderId);
  if (!order) throw new Error('Unknown order');

  // 2. Re-verify the REQUIRED preconditions here, at fulfilment time.
  if (order.status !== 'PAID')      throw new Error('Not paid');
  if (order.fraudReview !== 'PASS') throw new Error('Fraud review incomplete');
  if (order.fulfilled === true)     return { ok: true, note: 'already fulfilled' };

  // 3. Confirm the caller/step is actually allowed to fulfil this order.
  await assertAuthorized(event.principal, 'order:fulfil', orderId);

  // Only now perform the effect.
  await ship(order);
  await markFulfilled(orderId);
  return { ok: true };
};
```

The rule is simple: *the step that performs the effect is the step that verifies the right to perform it.* Payment is confirmed by re-reading authoritative order state (ideally reconciled with the payment provider), not by trusting a boolean the caller supplied or an event that merely arrived.

## 2. Make Every Handler Idempotent

Under at-least-once delivery, a handler *will* see the same message more than once. Give each unit of work a stable idempotency key and record its completion atomically, so repeats become no-ops.

```python
# Python -- conditional write makes the effect exactly-once.
# The key is derived from the business event, not supplied blindly by a client.
import boto3
from botocore.exceptions import ClientError

ddb = boto3.client('dynamodb')

def already_processed(idem_key: str) -> bool:
    try:
        # Insert the key ONLY if it does not already exist.
        ddb.put_item(
            TableName='processed_events',
            Item={'k': {'S': idem_key}},
            ConditionExpression='attribute_not_exists(k)',
        )
        return False           # we won the race -> first time
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return True        # someone already processed this key
        raise

def handler(event, context):
    order_id = event['orderId']
    # Bind the key to the message identity AND the operation.
    idem_key = f"credit:{order_id}:{event['messageId']}"
    if already_processed(idem_key):
        return {'ok': True, 'note': 'duplicate ignored'}
    credit_wallet(order_id, event['amount'])   # runs at most once
    return {'ok': True}
```

Key points: derive the idempotency key from the event's identity (and operation), not from a value the client can freely reuse across different payloads; make the "record completion" and "do the effect" atomic where possible (a conditional write, a transaction, or a unique constraint) so two concurrent duplicates cannot both proceed.

## 3. Orchestrate Server-Side; Validate Inter-Step State

Let a server-side orchestrator own the sequence. Do not let the client tell you which step comes next, and do not let a downstream task trust fields another party placed in the shared state.

```json
# AWS Step Functions (ASL) -- the state machine, not the client,
# decides the order. Each task still validates its own preconditions.
{
  "StartAt": "ValidateCart",
  "States": {
    "ValidateCart":  { "Type": "Task", "Resource": "...:validateCart",
                       "Next": "ChargePayment" },
    "ChargePayment": { "Type": "Task", "Resource": "...:chargePayment",
                       "Next": "PaidGate" },
    "PaidGate": {
      "Type": "Choice",
      "Choices": [
        { "Variable": "$.payment.status", "StringEquals": "CAPTURED",
          "Next": "FulfilOrder" }
      ],
      "Default": "FailOrder"
    },
    "FulfilOrder": { "Type": "Task", "Resource": "...:fulfilOrder", "End": true },
    "FailOrder":   { "Type": "Fail", "Error": "PaymentNotCaptured" }
  }
}
```

Server-side orchestration removes the "invoke a later step directly" path *from the happy path*—but the individual task Lambdas must still be locked down (Section 4), because the state machine is not the only thing that can invoke them. Where state crosses a trust boundary (for example a callback token or a resumable state blob), sign it and verify the signature before trusting it:

```python
# Python -- sign inter-step state so a tampered blob is rejected.
import hmac, hashlib, json, os

SECRET = os.environ['STATE_SIGNING_KEY'].encode()

def sign_state(state: dict) -> str:
    body = json.dumps(state, sort_keys=True, separators=(',', ':')).encode()
    return hmac.new(SECRET, body, hashlib.sha256).hexdigest()

def verify_state(state: dict, sig: str) -> dict:
    expected = sign_state(state)
    if not hmac.compare_digest(expected, sig):
        raise ValueError('Tampered inter-step state')   # reject forged flags
    return state
```

Never copy client-supplied fields (`approved`, `amount`, `tier`, `role`) into orchestration state unvalidated. Derive them server-side from authoritative sources.

## 4. Restrict Who and What Can Invoke Each Function

An internal step should be invokable only by the orchestrator or the specific event source that legitimately precedes it—never by the public, and never by every principal in the account.

```yaml
# serverless.yml -- fulfilOrder has NO public URL and NO broad invoke grant.
# Only the state machine's role may invoke it.
service: checkout
provider:
  name: aws
  runtime: nodejs20.x
  # No account-wide provider.iam block handing out lambda:InvokeFunction.

functions:
  fulfilOrder:
    handler: src/fulfil.handler
    # No 'url: true', no public 'http'/'httpApi' event on this internal step.
    # Invoked only as a Step Functions task (see the state machine's role).

resources:
  Resources:
    FulfilPermission:
      Type: AWS::Lambda::Permission
      Properties:
        FunctionName: !Ref FulfilOrderLambdaFunction
        Action: lambda:InvokeFunction
        Principal: states.amazonaws.com          # ONLY Step Functions
        SourceArn: !GetAtt CheckoutStateMachine.Arn
```

For queue/topic-triggered steps, scope the resource policy so only the intended producer can publish, and give each function its own least-privilege execution role—deny `lambda:InvokeFunction`, `sns:Publish`, and `dynamodb:UpdateItem` on tables/topics it has no business touching, so a manipulated step cannot flip flags or forge events for the rest of the workflow.

## 5. Verify Event Source and Integrity

Before acting on an event, confirm it came from a legitimate source and has not been tampered with. Do not treat "it arrived on my queue" as proof of authenticity.

```javascript
// Node.js -- verify the event before trusting its contents.
exports.handler = async (event) => {
  for (const rec of event.Records ?? []) {
    // 1. Confirm the source ARN is one we expect.
    if (rec.eventSourceARN !== process.env.EXPECTED_QUEUE_ARN) {
      throw new Error('Unexpected event source');
    }
    // 2. Verify a message signature/HMAC set by the real producer.
    const body = JSON.parse(rec.body);
    if (!verifySignature(body.payload, body.sig)) {
      throw new Error('Unsigned or tampered event');   // rejects forged events
    }
    // 3. Only now use the payload -- and still re-check state (Section 1).
    await process(body.payload);
  }
};
```

Where the platform offers native verification (for example SNS message signature verification, or EventBridge rules constrained by source and detail-type), use it. For your own producers, sign the payload with a shared secret or KMS and verify on consume, so a forged publish to the topic is rejected.

## 6. Enforce Sequencing and Guardrails on Every Path

A guardrail is only a guardrail if it is on *every* route to the guarded action. Track workflow state explicitly and refuse transitions that skip required steps.

```python
# Python -- explicit state-machine guard: only allow legal transitions.
ALLOWED = {
    'CREATED':   {'VALIDATED'},
    'VALIDATED': {'PAID'},
    'PAID':      {'FULFILLED'},
    'FULFILLED': {'CLOSED'},
}

def transition(order_id, to_state):
    order = get_order(order_id)
    frm = order['status']
    if to_state not in ALLOWED.get(frm, set()):
        # Blocks CREATED -> FULFILLED (skipping VALIDATED/PAID) etc.
        raise ValueError(f'Illegal transition {frm} -> {to_state}')
    # Atomic conditional update: only move if still in the expected state.
    conditional_set_status(order_id, expected=frm, new=to_state)
```

Guard the *action*, not the path. If `grantAccess` can be reached both through review and through an internal topic, put the review/state check inside `grantAccess` so neither path can skip it. Use atomic conditional writes (compare-and-set) so concurrent transitions cannot both succeed—this closes the check-then-act race.

## 7. Handle At-Least-Once Delivery Semantics Explicitly

Assume every message can arrive more than once and out of order, and configure the platform to help.

```yaml
# serverless.yml -- FIFO queue with content-based dedup for ordering +
# de-duplication where the platform can provide it; DLQ for poison messages.
functions:
  processPayment:
    handler: src/pay.handler
    events:
      - sqs:
          arn: !GetAtt PaymentQueue.Arn
          batchSize: 1                 # simpler idempotency reasoning
resources:
  Resources:
    PaymentQueue:
      Type: AWS::SQS::Queue
      Properties:
        FifoQueue: true                # best-effort ordering
        ContentBasedDeduplication: true
        RedrivePolicy:
          deadLetterTargetArn: !GetAtt PaymentDLQ.Arn
          maxReceiveCount: 5           # stop infinite reprocessing
    PaymentDLQ:
      Type: AWS::SQS::Queue
      Properties: { FifoQueue: true }
```

Platform features (FIFO ordering, content-based dedup, DLQs, a bounded `maxReceiveCount`) reduce duplicates and contain poison messages—but they are *not* a substitute for application-level idempotency (Section 2). FIFO dedup windows are time-bounded; your idempotency key is the durable guarantee.

## 8. Detection and Monitoring of Broken Invariants

Exploitation looks normal per-function; the signal is in the relationships between steps. Continuously check the invariants the flow is supposed to preserve.

```
# Reconciliation / invariant checks (run continuously or on a schedule):
- Fulfilled orders with NO matching captured payment (workflow bypass)
- More than one credit/refund/redemption per idempotency key (double-spend)
- Access granted without a corresponding approval record (guardrail skip)
- Orders whose status jumped states illegally (e.g. CREATED -> FULFILLED)
- Invocations of internal steps from unexpected principals/sources
- Wallet/inventory totals drifting from the sum of authoritative events
```

Alert on any invariant breach, emit a metric per anomaly class, and make the checks part of financial reconciliation. Because each individual invocation is valid, these cross-step invariants are often the *only* place the attack becomes visible.

## Defence-in-Depth Summary

| Layer | Control | Stops |
|-------|---------|-------|
| Every step | Re-validate authz + required prior state | Skipping validation/payment/authz |
| Side effects | Idempotency key + atomic completion | Duplicate-processing double-spend |
| Orchestration | Server-side sequence; sign inter-step state | Client-driven flow & state tampering |
| Invocation | Scoped invoke policy; no public URL on internal steps | Out-of-band direct invocation |
| Events | Verify source + signature | Forged and replayed events |
| Sequencing | Explicit transitions; compare-and-set | Reordering & check-then-act races |
| Delivery | FIFO/dedup/DLQ + assume at-least-once | Duplicates, reordering, poison loops |
| Operations | Cross-step invariant reconciliation | Missed bypasses and double-spends |

## Key Takeaways

1. **Re-validate at every step**—the function that performs the effect verifies authorization and prior state itself; never trust the upstream.
2. **Make handlers idempotent**—dedupe on an event-bound key with atomic completion so at-least-once delivery cannot double-spend.
3. **Own the sequence server-side**—orchestrate with validated, signed state instead of a client-driven flow.
4. **Lock invocation and verify events**—scope who can invoke each step and confirm every event's source and integrity.
5. **Watch the invariants**—reconcile across steps to catch bypasses and duplicates that each look normal in isolation.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure Lambda & Step Functions workflows (Node.js & Python)
- **[Attack Vectors](attack-vectors.md)**: Understand what you are defending against
- **[Serverless Security Track](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Range](/practice)**: Harden a vulnerable workflow hands-on
