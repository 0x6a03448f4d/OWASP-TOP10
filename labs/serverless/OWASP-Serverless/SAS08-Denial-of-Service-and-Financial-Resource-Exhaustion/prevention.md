# SAS-8: Denial of Service and Financial Resource Exhaustion - Prevention

## Prevention Strategy Overview

Preventing this weakness is about one theme applied everywhere: **put a limit on every dimension that can scale**—concurrency, request rate, duration, input size, recursion, retries, downstream load, and cost. Auto-scaling is safe only when it is bounded. The layered strategy:

1. Cap concurrency per function (and understand your account limit).
2. Throttle and quota public endpoints at the API layer, with a WAF rate rule in front.
3. Shrink each unit of work—short timeouts, right-sized memory, input size limits.
4. Break amplification—guard against recursion, cap retries, use dead-letter queues.
5. Protect downstream calls with timeouts and circuit breakers.
6. Bound cost—Budgets, Cost Anomaly Detection, and CloudWatch alarms (ties to SAS-5).
7. Reduce anonymous abuse with authentication (ties to SAS-2) and design for graceful degradation.

### Core Principles

- **Every scaling dimension needs a ceiling**: if something can grow without a cap, assume an attacker (or a bug) will grow it.
- **Alerts are not enforcement**: budgets notify; concurrency caps, throttles, and automated responses are what actually stop the spend.
- **Isolate blast radius**: reserved concurrency turns "one function drains the account" into "one function throttles itself."
- **Fail closed and cheap**: prefer a contained throttle or a rejected oversized request over an unbounded, billable run.

## 1. Cap Per-Function Reserved Concurrency

Reserved concurrency does two jobs at once: it *guarantees* a function some capacity and—more importantly here—it *caps* the maximum concurrent executions, so a flood on one function cannot drain the shared account pool and starve the rest.

```yaml
# serverless.yml — cap each function; the cap IS the DoS/DoW circuit breaker.
functions:
  render:
    handler: handler.render
    reservedConcurrency: 20      # hard ceiling: never more than 20 at once
  checkout:
    handler: handler.checkout
    reservedConcurrency: 50      # protected capacity for critical path
# Leave unreserved headroom in the account so no single function can take it all.
# Optionally cap regional/account concurrency via a support limit for the account.
```

Reserve capacity for critical functions *and* ceiling non-critical ones. A public, low-importance endpoint should have a small reserved cap so, even under flood, it self-throttles instead of consuming everyone's concurrency.

## 2. Throttle and Quota Public Endpoints (API Gateway)

The API layer is where you convert "unbounded request rate" into "bounded invocations." Use per-stage/per-method throttling and usage-plan quotas with API keys.

```yaml
# serverless.yml — API Gateway usage plan: rate + burst + daily quota
provider:
  apiGateway:
    usagePlan:
      throttle:
        rateLimit: 50            # steady-state requests/second
        burstLimit: 100          # token-bucket burst ceiling
      quota:
        limit: 100000            # hard cap on requests...
        period: DAY              # ...per day, per API key

functions:
  publicApi:
    handler: handler.api
    events:
      - http:
          path: /render
          method: post
          private: true          # require an API key -> subject to the usage plan
```

Set method-level throttles for hot routes, and prefer usage plans with quotas for any partner/public traffic so a single key cannot exceed a daily ceiling.

## 3. Add a WAF Rate-Limit Rule at the Edge

A WAF rate rule stops floods before they reach API Gateway or the function, and can block by IP or by matching pattern.

```yaml
# AWS WAF: rate-based rule attached to the API/CloudFront distribution
Rule: RateLimitPerIP
  Type: RateBasedStatement
  Limit: 2000                    # max requests per 5-minute window, per IP
  AggregateKeyType: IP
  Action: Block                  # 403 the offending IP for the window
# Layer with managed rule groups (bot control, known-bad IPs) for anonymous abuse.
```

## 4. Shrink Each Unit of Work

The cheaper and shorter each invocation, the less any flood or loop can cost. Size timeout and memory to the *actual* workload, not "just in case," and reject oversized input early.

```yaml
# serverless.yml — tight, right-sized function limits
functions:
  thumbnail:
    handler: handler.thumb
    timeout: 10                  # seconds — as short as the task truly needs
    memorySize: 256              # right-sized; billed per GB-second
    events:
      - http:
          path: /thumb
          method: post
          request:
            # Enforce a small max payload at the API layer where supported,
            # and validate size in code before doing any expensive work.
```

```javascript
// Reject oversized/expensive input BEFORE the costly path (Node.js)
const MAX_BYTES = 256 * 1024;          // 256 KB body cap
const MAX_ITEMS = 100;                  // pagination / batch cap

exports.handler = async (event) => {
  if ((event.body || '').length > MAX_BYTES)
    return { statusCode: 413, body: 'Payload too large' };
  const items = JSON.parse(event.body).items || [];
  if (items.length > MAX_ITEMS)
    return { statusCode: 400, body: 'Too many items' };
  // ...only now do the real work
};
```

## 5. Break Amplification: Recursion, Retries, DLQs

Amplification is what turns a small event into a storm. Remove the loops and cap the retries.

```
# Avoid the S3-write loop: separate input and output locations/prefixes.
#   Trigger on  s3://media/incoming/*   (ObjectCreated)
#   Write to    s3://media/processed/*   (DIFFERENT prefix -> no self-trigger)
# Plus: enable the platform's recursive-invocation detection where available,
# and add an idempotency/recursion guard key in code so a re-seen event is a no-op.
```

```yaml
# serverless.yml — cap retries and send failures to a dead-letter queue
functions:
  worker:
    handler: handler.worker
    maximumRetryAttempts: 2          # async invoke: don't retry forever
    onError: arn:aws:sqs:...:dlq     # async DLQ for poison events
    events:
      - sqs:
          arn: arn:aws:sqs:...:jobs
          # On the SOURCE queue, set a finite redrive policy:
          #   maxReceiveCount: 5  ->  message moves to DLQ, not re-billed forever
          functionResponseType: ReportBatchItemFailures
```

## 6. Protect Downstream Calls (Circuit Breakers & Pooling)

Function concurrency maps directly onto downstream load. Bound that too, or a flood becomes a database or third-party-API outage—and a bigger bill.

```javascript
// Timeout + circuit breaker around a metered downstream call
async function callDownstream(input) {
  if (breaker.isOpen()) throw new Error('circuit open - shedding load');
  try {
    return await withTimeout(downstream(input), 2000);   // hard 2s cap
  } catch (e) {
    breaker.recordFailure();     // trip after N failures -> stop hammering
    throw e;
  }
}
// Reuse connections across invocations (init OUTSIDE the handler) and set a
// small pool so N concurrent functions can't open N*infinity DB connections.
```

## 7. Bound Cost: Budgets, Anomaly Detection, Alarms

Cost is a security signal in serverless. Wire spend and invocation rate into alarms so a spike pages a human—this is the SAS-5 monitoring layer applied to SAS-8.

```yaml
# AWS Budgets — notify BEFORE the month's spend runs away
Budget: MonthlyServerlessCeiling
  Amount: <your ceiling>   TimeUnit: MONTHLY
  Notifications:
    - Threshold: 80%   -> SNS: engineering
    - Threshold: 100%  -> SNS: engineering + finance (page)
# Note: Budgets NOTIFY; they do not auto-cap. Pair with enforceable controls.
```

```yaml
# CloudWatch alarms — invocation-rate + estimated charges (early DoW signal)
InvocationSpikeAlarm:
  Namespace: AWS/Lambda   MetricName: Invocations   Statistic: Sum
  Period: 60   EvaluationPeriods: 2   Threshold: 5000
  AlarmActions: [ SNS -> on-call ]

BillingSpikeAlarm:
  Namespace: AWS/Billing  MetricName: EstimatedCharges  Statistic: Maximum
  Threshold: <budget ceiling>   AlarmActions: [ SNS -> security + finance ]

# Enable AWS Cost Anomaly Detection for ML-based spend-spike alerts, and wire
# a responder (e.g. a Lambda that lowers reserved concurrency to 0) for auto-halt.
```

## 8. Reduce Anonymous Abuse and Degrade Gracefully

Every request that must be authenticated is a request an anonymous attacker cannot cheaply flood. Where a function need not be public, require auth (ties to SAS-2). And design so that, when limits *are* hit, the system sheds load cleanly rather than cascading.

- Put authentication/authorization in front of any function that does not need to be anonymous; use API keys + usage plans for partner traffic.
- Return fast, cheap `429`/`503` responses when throttled—never a long, billable error path.
- Prefer queue-based load levelling (SQS in front of the function) so bursts are absorbed and processed at a bounded rate instead of scaling concurrency 1:1.
- Keep non-critical functions capped low so their failure never consumes the capacity of critical ones.

## Serverless DoS / DoW Prevention Checklist

| Control | What It Buys You |
|---------|------------------|
| Per-function reserved concurrency | One function can't drain the shared account pool (contains DoS) |
| API Gateway throttling + usage-plan quotas | Unbounded request rate becomes a bounded invocation rate |
| WAF rate-based rule | Floods blocked at the edge before they cost anything |
| Short timeouts + right-sized memory | Each invocation is cheap; floods and loops cost far less |
| Input size & pagination limits | A single request can't run unbounded/expensive |
| Recursion guards + separate input/output prefixes | No self-triggering, self-billing loops |
| Capped retries + dead-letter queues | Poison messages aren't re-billed forever |
| Downstream timeouts + circuit breakers | Concurrency can't exhaust DBs or metered APIs |
| Budgets + Cost Anomaly Detection + alarms | A spike pages a human early (DoW early warning, SAS-5) |
| Auth on non-public functions | Cuts cheap anonymous abuse (SAS-2) |

## Key Takeaways

1. **Cap concurrency per function** — the reserved-concurrency ceiling is your primary DoS/DoW circuit breaker and blast-radius limiter.
2. **Throttle at the edge and API layer** — WAF rate rules plus API Gateway throttling and quotas turn an unbounded flood into a bounded rate.
3. **Make each unit cheap and short** — right-sized memory, short timeouts, and input limits shrink what any abuse can cost.
4. **Kill amplification** — separate input/output prefixes, recursion guards, capped retries, and DLQs stop self-scaling storms.
5. **Bound cost and enforce, don't just alert** — Budgets and anomaly detection warn; caps, throttles, and auto-responders actually halt the spend.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure serverless.yml, API Gateway, Budgets, and WAF
- **[Attack Vectors](attack-vectors.md)**: Understand the floods and loops these controls stop
- **[Overview](overview.md)**: Why auto-scaling turns a flood into a bill
