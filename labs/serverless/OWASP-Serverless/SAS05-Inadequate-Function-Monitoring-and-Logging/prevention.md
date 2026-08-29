# SAS-5: Inadequate Function Monitoring and Logging - Prevention

## Prevention Strategy Overview

Preventing this weakness is not about one control—it is about **building the security visibility that serverless does not give you by default**:

1. Log security-relevant events from the function code, with full context.
2. Centralize and correlate those logs across every function and service.
3. Trace requests end-to-end as they fan out across the function chain.
4. Alert on anomalies—error, invocation, and *cost* spikes, plus unusual IAM use.
5. Protect the logs (retention, tamper-resistance) and wire alerts into incident response.

### Core Principles

- **Instrument before the incident**: ephemeral functions leave nothing behind—visibility must exist during the invocation or not at all.
- **Security context is your job**: the platform logs execution; identity, resource, and outcome must be added by your code.
- **Correlate everything**: a single request/trace id threaded through the whole chain turns scattered invocations into one investigable story.
- **Treat cost as a signal**: in serverless, spend and invocation rate are security telemetry, not just billing.

## 1. Log Security Events From the Function Code

Emit structured, security-oriented events for the things that matter—authz decisions, validation failures, sensitive-data access, and privileged actions—each carrying identity and request context.

```javascript
// Node.js (Lambda): structured security logging helper
function securityEvent(evt, ctx, fields) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    level: 'SECURITY',
    request_id: ctx.awsRequestId,          // correlate within this invocation
    trace_id: process.env._X_AMZN_TRACE_ID, // correlate across the chain
    function: ctx.functionName,
    source_ip: evt.requestContext?.identity?.sourceIp,
    identity: evt.requestContext?.identity?.userArn,
    ...fields                               // event, resource, outcome, reason
  }));
}

// Use it at security decision points:
securityEvent(event, context, {
  event: 'authz_denied', resource: `orders/${id}`,
  outcome: 'DENY', reason: 'cross_tenant_access'
});
```

Log the *decision points*, not the payloads—never write secrets, tokens, full PII, or raw credentials into logs. Redact before emitting.

## 2. Centralize and Correlate Across Functions

Per-function log streams hide cross-function attacks. Ship everything into one place and correlate on a shared id.

```
# Fan logs out of CloudWatch into a central store / SIEM / Security Lake
CloudWatch Logs (per function)
      -> Subscription filter
      -> Kinesis Data Firehose / central log account
      -> SIEM (Splunk/Elastic/OpenSearch) or Amazon Security Lake
# Correlate on request_id / trace_id so one request's path across N functions
# and services reassembles into a single timeline.
```

Propagate a correlation id across asynchronous boundaries (SQS/SNS/EventBridge) by putting it in the message attributes, so the chain stays joined even when functions are decoupled.

## 3. Enable Distributed Tracing

Tracing is what lets you follow one request as it fans out. Turn it on at the platform level and instrument downstream calls.

```yaml
# AWS SAM / template.yaml — enable X-Ray tracing for the function and API
Globals:
  Function:
    Tracing: Active          # AWS X-Ray active tracing on every function
  Api:
    TracingEnabled: true

# Grant the minimal tracing permissions (managed policy):
#   AWSXRayDaemonWriteAccess
# Or emit OpenTelemetry spans via the ADOT Lambda layer for vendor-neutral traces.
```

```python
# Python (Lambda): auto-instrument AWS SDK calls so downstream spans appear
from aws_xray_sdk.core import patch_all
patch_all()   # DynamoDB, S3, HTTP calls become child spans of the request trace
```

## 4. Alert on Anomalies (Including Cost)

Error-only alerting misses successful-but-abusive activity. Alarm on error rate, invocation rate, and estimated charges, and route alarms to a human.

```
# CloudWatch alarm: invocation-rate spike (abuse / denial-of-wallet early signal)
Alarm: HighInvocationRate
  Namespace: AWS/Lambda   Metric: Invocations   Stat: Sum
  Period: 60   Threshold: 5000   EvaluationPeriods: 2
  Action: SNS -> on-call (page)

# CloudWatch alarm: estimated charges (denial-of-wallet, ties to SAS-8)
Alarm: BillingSpike
  Namespace: AWS/Billing   Metric: EstimatedCharges
  Threshold: <your budget ceiling>   Action: SNS -> security + finance

# CloudWatch alarm: error-rate spike
Alarm: HighErrorRate
  Namespace: AWS/Lambda   Metric: Errors   Stat: Sum
  Threshold: <baseline * 3>   Action: SNS -> on-call
```

```json
# EventBridge rule: react to unusual IAM / role behaviour in near real time
{
  "source": ["aws.iam", "aws.sts"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["AttachRolePolicy", "AssumeRole", "CreateAccessKey"]
  }
}
# Target: a responder function / SNS topic. Pair with GuardDuty findings for
# managed anomaly detection on credential and API-call behaviour.
```

## 5. Capture Managed-Service Events

Monitoring must not stop at the function boundary. Capture control-plane and data-plane activity so actions *between* services are visible.

```
# Turn on the seams that functions can't see:
- CloudTrail (management events)  -> IAM changes, role assumption, config changes
- CloudTrail data events          -> S3 object GET/PUT, DynamoDB item access
- VPC Flow Logs / egress logging   -> unexpected outbound destinations
- GuardDuty                        -> managed threat detection over CloudTrail,
                                       DNS, and (for Lambda) network activity
# Feed all of it into the same central store as the function logs, and correlate.
```

## 6. Protect Retention and Integrity

Evidence that expires or can be deleted by the workload is no evidence at all.

```
# Set adequate, explicit retention (not the short default)
LogGroup retention: 365 days   # long enough to investigate + meet compliance

# Keep the log store OUT of the workload's reach:
- The function's execution role must NOT hold logs:DeleteLogStream,
  logs:DeleteLogGroup, or logs:PutRetentionPolicy for its own group.
- Ship logs to a separate, locked-down security account in near real time.
- Store forensic copies in object storage with immutability
  (Object Lock / WORM) so they cannot be altered or deleted.
```

## 7. Baseline Normal Behaviour

You cannot flag "unusual" without a definition of "usual." Establish baselines so anomalies become detectable.

- Record each function's normal invocation rate, duration, error rate, and typical set of downstream services/resources.
- Alert when a function starts calling services it never normally touches, reads far more records than usual, or spikes in rate or cost.
- Use anomaly-detection features (CloudWatch anomaly detection bands, GuardDuty) to adapt thresholds instead of guessing static ones.

## 8. Integrate With Incident Response

An alert no one receives is not detection. Close the loop.

```
# Alerts must reach a responder, with enough context to act:
SNS / EventBridge  -> on-call paging (PagerDuty/Opsgenie) + ticket
                    -> automated first response (e.g. throttle a function,
                       disable a leaked key, snapshot logs) via a responder Lambda
# Rehearse: run game-days that assume a function is compromised and verify the
# telemetry actually reconstructs what happened.
```

## Serverless Monitoring Checklist

| Control | What It Buys You |
|---------|------------------|
| Structured security events in code | Identity, resource, and outcome for every security decision |
| Centralization + correlation | Cross-function attacks visible as one timeline |
| Distributed tracing (X-Ray/OTel) | Follow a request end-to-end across the chain |
| Error/invocation/cost alarms | Catch abuse and denial-of-wallet early (SAS-8) |
| IAM/role anomaly alerting | Detect credential and privilege abuse |
| CloudTrail + data events | Close the blind spots between managed services |
| Protected retention | Evidence survives long enough—and cannot be erased |
| Baselines + IR integration | Anomalies are defined, alerts reach a human |

## Key Takeaways

1. **Log security events yourself** — the platform gives you execution logs; identity, resource, and outcome are your responsibility.
2. **Centralize and correlate** — a shared request/trace id is what makes a distributed attack visible as one story.
3. **Trace across the chain** — distributed tracing follows a request through every function and managed service.
4. **Alert on anomalies, especially cost** — invocation and spend spikes are the early warning for denial-of-wallet.
5. **Protect the evidence and act on it** — tamper-resistant retention plus real incident response turns telemetry into detection.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure Lambda logging, tracing, and alerting
- **[Attack Vectors](attack-vectors.md)**: Understand the activity you're trying to surface
- **[Overview](overview.md)**: Why serverless is blind by default
