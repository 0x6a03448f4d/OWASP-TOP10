# SAS-9: Serverless Business Logic Manipulation - Code Examples

Each pair below shows a **vulnerable** serverless workflow step and the **secure** version of the same step, in both Node.js and Python. The examples cover the core failures of this category—fulfilment that trusts its upstream, non-idempotent handlers under at-least-once delivery, tampered intermediate state, forged events, and check-then-act races—plus a Step Functions state machine and a least-privilege `serverless.yml`. Every secure version does the same two things: **re-establish its own preconditions** and **make its effect safe to repeat**.

## Example 1: Fulfilment That Trusts the Upstream -> Payment Bypass

### Vulnerable (Node.js)

```javascript
// fulfilOrder is invoked as a later step. It ASSUMES payment already ran.
exports.handler = async (event) => {
  const { orderId, items } = event;

  // No re-check: if this function is reached at all, it ships.
  // Direct invoke, forged event, or replay all bypass validation + payment.
  await ship(orderId, items);
  return { ok: true };
};
```

### Secure (Node.js)

```javascript
// fulfilOrder re-establishes payment/authz/state itself -- it trusts nothing.
exports.handler = async (event) => {
  const orderId = requireString(event.orderId);

  // 1. Re-read authoritative state written only by the payment step.
  const order = await getOrder(orderId);
  if (!order) throw new Error('Unknown order');

  // 2. Re-verify the required preconditions HERE, at fulfilment time.
  if (order.status !== 'PAID')      throw new Error('Not paid');
  if (order.fraudReview !== 'PASS') throw new Error('Fraud review incomplete');

  // 3. Idempotent: never ship the same order twice.
  if (order.fulfilled === true) return { ok: true, note: 'already fulfilled' };

  // 4. Confirm the invoking step/principal may fulfil this order.
  await assertAuthorized(event.principal, 'order:fulfil', orderId);

  await ship(orderId, order.items);          // items from trusted state, not event
  await markFulfilled(orderId);              // atomic compare-and-set on status
  return { ok: true };
};
```

### Vulnerable (Python)

```python
def handler(event, context):
    order_id = event["orderId"]
    # Trusts a boolean the CALLER supplied -- attacker just sets paid=True.
    if event.get("paid"):
        ship(order_id, event["items"])
    return {"ok": True}
```

### Secure (Python)

```python
def handler(event, context):
    order_id = require_str(event, "orderId")

    # 1. Authoritative state, not a caller-supplied flag.
    order = get_order(order_id)
    if order is None:
        raise ValueError("Unknown order")

    # 2. Re-verify preconditions at the point of effect.
    if order["status"] != "PAID":
        raise ValueError("Not paid")
    if order["fraud_review"] != "PASS":
        raise ValueError("Fraud review incomplete")

    # 3. Idempotent fulfilment.
    if order.get("fulfilled"):
        return {"ok": True, "note": "already fulfilled"}

    assert_authorized(event.get("principal"), "order:fulfil", order_id)
    ship(order_id, order["items"])           # trusted state, not event input
    mark_fulfilled(order_id)                 # conditional update on status
    return {"ok": True}
```

## Example 2: Non-Idempotent Handler -> Duplicate-Processing Double-Spend

### Vulnerable (Node.js)

```javascript
// SQS/SNS are AT-LEAST-ONCE. This credits the wallet every delivery.
exports.handler = async (event) => {
  for (const rec of event.Records) {
    const { userId, amount } = JSON.parse(rec.body);
    await creditWallet(userId, amount);   // duplicate delivery -> double credit
  }
  return { ok: true };
};
```

### Secure (Node.js)

```javascript
const { DynamoDBClient, PutItemCommand } = require('@aws-sdk/client-dynamodb');
const ddb = new DynamoDBClient({});

// Insert the idempotency key ONLY if unseen; effect runs at most once.
async function claim(idemKey) {
  try {
    await ddb.send(new PutItemCommand({
      TableName: 'processed_events',
      Item: { k: { S: idemKey } },
      ConditionExpression: 'attribute_not_exists(k)',
    }));
    return true;                            // first time
  } catch (e) {
    if (e.name === 'ConditionalCheckFailedException') return false; // duplicate
    throw e;
  }
}

exports.handler = async (event) => {
  for (const rec of event.Records) {
    const { userId, amount } = JSON.parse(rec.body);
    // Key bound to the message identity + operation, not a reusable client value.
    const idemKey = `credit:${userId}:${rec.messageId}`;
    if (!(await claim(idemKey))) continue;  // duplicate -> no-op
    await creditWallet(userId, amount);     // exactly once
  }
  return { ok: true };
};
```

### Vulnerable (Python)

```python
def handler(event, context):
    for rec in event["Records"]:
        msg = json.loads(rec["body"])
        # Replays and platform retries each redeem the coupon again.
        redeem_coupon(msg["userId"], msg["code"])
    return {"ok": True}
```

### Secure (Python)

```python
import json, boto3
from botocore.exceptions import ClientError

ddb = boto3.client("dynamodb")

def claim(idem_key: str) -> bool:
    try:
        ddb.put_item(
            TableName="processed_events",
            Item={"k": {"S": idem_key}},
            ConditionExpression="attribute_not_exists(k)",
        )
        return True                          # won the race -> first time
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False                     # already processed
        raise

def handler(event, context):
    for rec in event["Records"]:
        msg = json.loads(rec["body"])
        idem_key = f"redeem:{msg['userId']}:{msg['code']}:{rec['messageId']}"
        if not claim(idem_key):
            continue                         # duplicate ignored
        redeem_coupon(msg["userId"], msg["code"])   # exactly once
    return {"ok": True}
```

## Example 3: Tampered Intermediate State -> Forged Precondition

### Vulnerable (Python)

```python
# grantAccess gates on a DynamoDB flag. Any path that can write the flag
# (broad IAM, a separate endpoint) forges the "approved" precondition.
def handler(event, context):
    user_id = event["userId"]
    item = get_item("access_requests", user_id)
    if item.get("approved") is True:        # trusts a tamperable flag
        provision_admin(user_id)
    return {"ok": True}
```

### Secure (Python)

```python
# Trust the flag only if it was set by the approval step AND is signed,
# and re-derive authorization from the authoritative approval record.
import hmac, hashlib, os

SECRET = os.environ["STATE_SIGNING_KEY"].encode()

def verify(fields: dict, sig: str) -> bool:
    body = f"{fields['userId']}|{fields['approved']}|{fields['approver']}".encode()
    return hmac.compare_digest(hmac.new(SECRET, body, hashlib.sha256).hexdigest(), sig)

def handler(event, context):
    user_id = require_str(event, "userId")
    item = get_item("access_requests", user_id)

    # 1. There must be a real approval record with an integrity signature.
    if not item or item.get("approved") is not True:
        raise PermissionError("No approval on record")
    if not verify(item, item.get("sig", "")):
        raise PermissionError("Approval flag failed integrity check")

    # 2. Re-check policy: is this approver allowed to grant THIS access?
    if not approver_may_grant(item["approver"], user_id, item["tier"]):
        raise PermissionError("Approver not authorized for this grant")

    provision(user_id, item["tier"])         # tier from the signed record
    return {"ok": True}
```

## Example 4: Forged / Replayed Event -> Source and Integrity Verification

### Vulnerable (Node.js)

```javascript
// Consumer trusts any message on the topic as a real "order.paid" signal.
exports.handler = async (event) => {
  for (const rec of event.Records) {
    const msg = JSON.parse(rec.body);
    if (msg.type === 'order.paid') {
      await fulfil(msg.orderId);            // forged publish -> free fulfilment
    }
  }
};
```

### Secure (Node.js)

```javascript
exports.handler = async (event) => {
  for (const rec of event.Records) {
    // 1. Confirm the event source ARN is the expected queue.
    if (rec.eventSourceARN !== process.env.EXPECTED_QUEUE_ARN) {
      throw new Error('Unexpected event source');
    }
    const msg = JSON.parse(rec.body);

    // 2. Verify the producer's signature -- rejects forged/tampered events.
    if (!verifySignature(msg.payload, msg.sig)) {
      throw new Error('Unsigned or tampered event');
    }

    // 3. Idempotency guard -- rejects replays of a genuine event.
    if (!(await claim(`fulfil:${msg.payload.orderId}:${rec.messageId}`))) continue;

    // 4. STILL re-check authoritative state -- never fulfil on the event alone.
    const order = await getOrder(msg.payload.orderId);
    if (order?.status !== 'PAID') throw new Error('Not paid');

    await fulfil(order.orderId);
  }
};
```

## Example 5: Check-Then-Act Race -> Atomic Compare-and-Set

### Vulnerable (Python)

```python
# Single-use coupon, but the check and the write are not atomic.
def handler(event, context):
    code = event["code"]
    coupon = get_coupon(code)
    if not coupon["used"]:                  # 20 concurrent runs all read False
        apply_discount(event["orderId"], coupon["value"])
        set_used(code, True)                # ...then all set it True
    return {"ok": True}
```

### Secure (Python)

```python
# One atomic conditional update decides the single winner.
from botocore.exceptions import ClientError

def handler(event, context):
    code = require_str(event, "code")
    try:
        # Flip used False -> True only if it is still False. Exactly one wins.
        ddb.update_item(
            TableName="coupons",
            Key={"code": {"S": code}},
            UpdateExpression="SET used = :t",
            ConditionExpression="used = :f",
            ExpressionAttributeValues={":t": {"BOOL": True}, ":f": {"BOOL": False}},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return {"ok": True, "note": "coupon already used"}   # losers no-op
        raise
    apply_discount(event["orderId"], get_coupon(code)["value"])  # only the winner
    return {"ok": True}
```

## Example 6: Server-Side Orchestration (Step Functions)

Let the state machine own the sequence so the happy path cannot skip a step. Each task Lambda still re-validates (Examples 1–5); the orchestrator removes the client from deciding order.

### Secure (Amazon States Language)

```json
{
  "Comment": "Checkout: order enforced server-side, gated on real payment.",
  "StartAt": "ValidateCart",
  "States": {
    "ValidateCart":  { "Type": "Task", "Resource": "arn:aws:lambda:...:validateCart",
                       "Next": "RunFraudCheck" },
    "RunFraudCheck": { "Type": "Task", "Resource": "arn:aws:lambda:...:runFraudCheck",
                       "Next": "ChargePayment" },
    "ChargePayment": { "Type": "Task", "Resource": "arn:aws:lambda:...:chargePayment",
                       "ResultPath": "$.payment", "Next": "PaidGate" },
    "PaidGate": {
      "Type": "Choice",
      "Choices": [
        { "Variable": "$.payment.status", "StringEquals": "CAPTURED",
          "Next": "FulfilOrder" }
      ],
      "Default": "FailOrder"
    },
    "FulfilOrder": { "Type": "Task", "Resource": "arn:aws:lambda:...:fulfilOrder",
                     "End": true },
    "FailOrder":   { "Type": "Fail", "Error": "PaymentNotCaptured",
                     "Cause": "Fulfilment blocked: payment not captured" }
  }
}
```

## Example 7: Least-Privilege Invocation in serverless.yml

Server-side orchestration only helps if the internal steps cannot be invoked out of band. Give `fulfilOrder` no public URL and allow only Step Functions to invoke it, and scope each function's execution role tightly.

### Vulnerable (over-exposed, over-privileged)

```yaml
service: checkout
provider:
  name: aws
  runtime: nodejs20.x
  iam:
    role:
      statements:
        - Effect: Allow
          Action: "*"            # every action...
          Resource: "*"          # ...on everything. A foothold = takeover.

functions:
  fulfilOrder:
    handler: src/fulfil.handler
    url: true                    # PUBLIC Function URL -- anyone can invoke it
    events:
      - sns: arn:aws:sns:us-east-1:111122223333:order-events   # + open topic
```

### Secure (scoped invocation and per-function role)

```yaml
service: checkout
provider:
  name: aws
  runtime: nodejs20.x
  # No account-wide wildcard role.

functions:
  fulfilOrder:
    handler: src/fulfil.handler
    # No 'url: true'; no public http/sns trigger on this internal step.
    iamRoleStatements:
      - Effect: Allow
        Action: [ "dynamodb:GetItem", "dynamodb:UpdateItem" ]
        Resource: "arn:aws:dynamodb:*:*:table/orders"     # this table only
      # Note: no lambda:InvokeFunction, no sns:Publish, no wildcard.

resources:
  Resources:
    FulfilPermission:
      Type: AWS::Lambda::Permission
      Properties:
        FunctionName: !Ref FulfilOrderLambdaFunction
        Action: lambda:InvokeFunction
        Principal: states.amazonaws.com                   # ONLY Step Functions
        SourceArn: !GetAtt CheckoutStateMachine.Arn
```

## What Changed, and Why

| Manipulation | Vulnerable | Secure |
|--------------|------------|--------|
| Direct invoke / skip steps | Ships if reached at all | Re-reads state; requires PAID + fraud PASS + authz |
| Caller-supplied precondition | Trusts `event.paid` | Ignores it; uses authoritative order state |
| Duplicate delivery | Credits/redeems every delivery | Idempotency key + conditional insert -> exactly once |
| Tampered state flag | Trusts `approved=true` | Requires signed approval + re-checked policy |
| Forged / replayed event | Acts on any topic message | Verifies source ARN + signature + dedup + state |
| Check-then-act race | Non-atomic check then write | Single atomic compare-and-set picks one winner |
| Out-of-band invocation | Public URL + wildcard role | Step Functions-only invoke + least privilege |

> Every secure step does the same two things in order: **re-establish its own preconditions** (authorization + required prior state, verified not assumed), then **make its effect idempotent** so at-least-once delivery cannot double-count it. Server-side orchestration and scoped invocation are the backstops that keep the steps on their intended path.

## Next Steps

- **[Prevention](prevention.md)**: The full layered defence strategy
- **[Attack Vectors](attack-vectors.md)**: How these manipulations are exploited
- **[Serverless Security Track](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice Range](/practice)**: Fix a vulnerable workflow hands-on
