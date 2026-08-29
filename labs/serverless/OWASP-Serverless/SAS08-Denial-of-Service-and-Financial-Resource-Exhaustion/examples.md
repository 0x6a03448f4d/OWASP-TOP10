# SAS-8: Denial of Service and Financial Resource Exhaustion - Code Examples

Each pair below shows a **vulnerable** configuration (or function) and the **secure** version. The examples focus on what dominates real serverless DoS/DoW findings: no concurrency caps, unthrottled public endpoints, oversized timeouts/memory, recursive event loops, uncapped retries, unprotected downstream calls, and no cost controls.

## 1. Reserved Concurrency — serverless.yml

### Vulnerable
```yaml
# No reserved concurrency anywhere. A flood on ONE function drains the whole
# account's shared concurrency pool and throttles every other function.
service: shop
provider:
  name: aws
  runtime: nodejs20.x
functions:
  report:                       # low-importance, PUBLIC, unlimited
    handler: handler.report
    events:
      - http: { path: /report, method: get }
  checkout:                     # critical path — no protected capacity
    handler: handler.checkout
    events:
      - http: { path: /checkout, method: post }
# Flood /report -> it consumes all 1,000 account concurrency -> checkout 429s.
```

### Secure
```yaml
# Every function capped; critical functions get protected capacity.
service: shop
provider:
  name: aws
  runtime: nodejs20.x
functions:
  report:
    handler: handler.report
    reservedConcurrency: 10     # hard ceiling: a flood self-throttles here
    events:
      - http: { path: /report, method: get, private: true }
  checkout:
    handler: handler.checkout
    reservedConcurrency: 100    # guaranteed capacity for the critical path
    events:
      - http: { path: /checkout, method: post }
# Now flooding /report caps at 10 concurrent; checkout's 100 are untouched.
# Leave account headroom unreserved so no function can take the whole pool.
```

## 2. API Gateway Throttling & Usage-Plan Quotas

### Vulnerable
```yaml
# Public, anonymous endpoint with no throttle and no quota.
functions:
  render:
    handler: handler.render
    events:
      - http:
          path: /render
          method: post
          # no 'private', no API key, no usage plan
# Request rate is bounded only by the attacker's bandwidth.
# Every request is a billable invocation.
```

### Secure
```yaml
# Require an API key, and attach a usage plan: rate + burst + daily quota.
provider:
  name: aws
  runtime: nodejs20.x
  apiGateway:
    usagePlan:
      throttle:
        rateLimit: 50           # steady-state req/s
        burstLimit: 100         # token-bucket burst
      quota:
        limit: 100000           # hard daily cap...
        period: DAY             # ...per API key

functions:
  render:
    handler: handler.render
    events:
      - http:
          path: /render
          method: post
          private: true         # enforce API key -> subject to the usage plan
# Unbounded request rate is now a bounded, per-key invocation rate.
```

## 3. Function Timeout & Memory Sizing

### Vulnerable
```yaml
# "Just in case" sizing: max timeout, max memory. Every invocation can run
# for 15 minutes at the highest per-GB-second price.
functions:
  thumbnail:
    handler: handler.thumb
    timeout: 900                # 15 minutes
    memorySize: 3008           # ~10x the cost of a 256 MB function
# A slow/looping input holds max resource for max time = max billable cost/unit.
```

### Secure
```yaml
# Right-sized to the actual task; reject oversized input before the costly path.
functions:
  thumbnail:
    handler: handler.thumb
    timeout: 10                 # as short as the task truly needs
    memorySize: 256            # right-sized; profile, don't guess-max
```

```javascript
// handler.thumb — cap input size and batch length up front (Node.js)
const MAX_BYTES = 256 * 1024;   // 256 KB
const MAX_ITEMS = 100;

exports.handler = async (event) => {
  if ((event.body || '').length > MAX_BYTES)
    return { statusCode: 413, body: 'Payload too large' };
  const { items = [] } = JSON.parse(event.body || '{}');
  if (items.length > MAX_ITEMS)
    return { statusCode: 400, body: 'Too many items' };
  // ...only now do the real, bounded work
  return { statusCode: 200, body: 'ok' };
};
```

## 4. Recursive Event Loop (S3 → Lambda)

### Vulnerable
```yaml
# The function is triggered by ANY object created in the bucket, and writes
# its output back into the SAME bucket -> infinite, self-billing loop.
functions:
  resize:
    handler: handler.resize
    events:
      - s3:
          bucket: media
          event: s3:ObjectCreated:*      # fires on the output too!
# handler.resize: reads media/x.jpg, writes media/x-resized.jpg back to 'media'
#   -> ObjectCreated -> resize -> ObjectCreated -> resize -> ... (unbounded)
```

### Secure
```yaml
# Separate input and output locations so the output can NEVER re-trigger.
functions:
  resize:
    handler: handler.resize
    events:
      - s3:
          bucket: media
          event: s3:ObjectCreated:*
          rules:
            - prefix: incoming/            # trigger ONLY on incoming/*
# handler.resize writes to processed/* (a different prefix, or a different
# bucket) -> the write cannot match the trigger -> no loop.
# Also: enable the platform's recursive-invocation detection, and add an
# idempotency guard so a re-seen object key is a no-op.
```

## 5. Retries & Dead-Letter Queues (SQS)

### Vulnerable
```yaml
# No redrive cap and no DLQ. A poison message that fails AFTER expensive work
# is redelivered forever -> billed for every retry.
functions:
  worker:
    handler: handler.worker
    events:
      - sqs:
          arn: arn:aws:sqs:us-east-1:123:jobs
          # source queue has no maxReceiveCount, no DLQ configured
# One crafted failing message = unbounded, repeated, billed invocations.
```

### Secure
```yaml
# Finite redrive to a DLQ, capped async retries, partial-batch reporting.
resources:
  Resources:
    JobsQueue:
      Type: AWS::SQS::Queue
      Properties:
        RedrivePolicy:
          deadLetterTargetArn: !GetAtt JobsDLQ.Arn
          maxReceiveCount: 5            # after 5 tries -> DLQ, not re-billed
    JobsDLQ:
      Type: AWS::SQS::Queue

functions:
  worker:
    handler: handler.worker
    maximumRetryAttempts: 2             # cap async retries
    events:
      - sqs:
          arn: !GetAtt JobsQueue.Arn
          functionResponseType: ReportBatchItemFailures   # only failed items retry
# Poison messages land in the DLQ for inspection instead of looping forever.
```

## 6. Protecting Downstream Calls

### Vulnerable
```javascript
// New DB connection per invocation, no timeout, no breaker. 1,000 concurrent
// functions -> 1,000 connections + 1,000 metered API calls, unbounded.
exports.handler = async (event) => {
  const db = await connectToDatabase();      // fresh connection every time
  const data = await callPaidApi(event);     // no timeout -> can hang for the
                                             // full function timeout, still billed
  return { statusCode: 200, body: JSON.stringify(data) };
};
```

### Secure
```javascript
// Reuse connections; hard-timeout and circuit-break the downstream call.
const db = connectToDatabase();              // init OUTSIDE handler -> reused,
                                             // small bounded pool
const breaker = makeBreaker({ threshold: 5, cooldownMs: 30000 });

async function withTimeout(p, ms) {
  return Promise.race([
    p,
    new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms)),
  ]);
}

exports.handler = async (event) => {
  if (breaker.isOpen())
    return { statusCode: 503, body: 'temporarily unavailable' }; // shed load, cheap
  try {
    const data = await withTimeout(callPaidApi(event), 2000);    // 2s hard cap
    return { statusCode: 200, body: JSON.stringify(data) };
  } catch (e) {
    breaker.recordFailure();                 // trip -> stop hammering downstream
    return { statusCode: 503, body: 'temporarily unavailable' };
  }
};
```

## 7. Cost Controls: Budgets, Anomaly Detection, Alarms

### Vulnerable
```
# No budget, no anomaly detection, no alarms. A denial-of-wallet loop drives
# invocations 1000x and the first human signal is the monthly invoice.
```

### Secure
```yaml
# AWS Budgets — notify well before the ceiling (Budgets NOTIFY, they don't cap)
resources:
  Resources:
    MonthlyBudget:
      Type: AWS::Budgets::Budget
      Properties:
        Budget:
          BudgetType: COST
          TimeUnit: MONTHLY
          BudgetLimit: { Amount: 500, Unit: USD }   # your ceiling
        NotificationsWithSubscribers:
          - Notification:
              NotificationType: ACTUAL
              ComparisonOperator: GREATER_THAN
              Threshold: 80                          # alert at 80%
            Subscribers:
              - { SubscriptionType: SNS, Address: !Ref SecurityTopic }

    # CloudWatch alarm — invocation-rate spike (early DoW/DoS signal, SAS-5)
    InvocationSpikeAlarm:
      Type: AWS::CloudWatch::Alarm
      Properties:
        Namespace: AWS/Lambda
        MetricName: Invocations
        Statistic: Sum
        Period: 60
        EvaluationPeriods: 2
        Threshold: 5000
        ComparisonOperator: GreaterThanThreshold
        AlarmActions: [ !Ref SecurityTopic ]         # SNS -> on-call page
# Also enable AWS Cost Anomaly Detection (ML spend-spike alerts) and, for
# real enforcement, a responder that sets reservedConcurrency to 0 to auto-halt.
```

## 8. WAF Rate Limiting at the Edge

### Vulnerable
```
# No WAF. Anonymous floods reach API Gateway and the function directly;
# the only ceiling is the attacker's bandwidth.
```

### Secure
```yaml
# AWS WAF rate-based rule on the API/CloudFront distribution
Rules:
  - Name: RateLimitPerIP
    Priority: 1
    Statement:
      RateBasedStatement:
        Limit: 2000                 # requests per 5-min window, per IP
        AggregateKeyType: IP
    Action: { Block: {} }           # 403 the offending IP for the window
    VisibilityConfig: { SampledRequestsEnabled: true,
                        CloudWatchMetricsEnabled: true,
                        MetricName: RateLimitPerIP }
# Layer managed rule groups (bot control, known-bad IPs) for broader abuse.
```

## What Changed, and Why

| Gap | Vulnerable | Secure |
|-----|------------|--------|
| Concurrency | No caps; one function drains the account | Reserved concurrency per function; contained blast radius |
| Endpoint rate | Public, anonymous, unthrottled | API keys + usage-plan throttle & daily quota |
| Unit cost | 900s timeout, 3008 MB memory | Short timeout, right-sized memory, input caps |
| Recursion | S3-write loop on the same bucket | Separate input/output prefixes + recursion detection |
| Retries | No cap, no DLQ; poison msg billed forever | maxReceiveCount + DLQ + capped async retries |
| Downstream | Per-call connect, no timeout/breaker | Pooled connections, hard timeouts, circuit breaker |
| Cost visibility | None; first signal is the invoice | Budgets + anomaly detection + invocation/billing alarms |
| Edge | No WAF; floods reach the function | WAF rate-based rule blocks floods per IP |

## Next Steps

- **[Prevention](prevention.md)**: The full serverless DoS/DoW prevention strategy
- **[Attack Vectors](attack-vectors.md)**: The floods and loops these controls stop
- **[Overview](overview.md)**: Why auto-scaling turns a flood into a bill
