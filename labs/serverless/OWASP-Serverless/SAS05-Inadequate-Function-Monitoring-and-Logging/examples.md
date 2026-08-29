# SAS-5: Inadequate Function Monitoring and Logging - Code Examples

Each pair below shows a **vulnerable** function (or configuration) and the **secure** version. The examples focus on what dominates real serverless findings: functions that emit no security context, missing distributed tracing, no anomaly/cost alerting, and log stores the workload can erase.

## 1. Lambda Handler — Node.js: Structured Security Logging

### Vulnerable
```javascript
// Nothing security-relevant is logged. Ephemeral invocation leaves no trace
// of who was denied, what they touched, or that anything happened at all.
exports.handler = async (event) => {
  const id = event.pathParameters.id;
  const tenant = event.requestContext.authorizer.tenantId;

  const order = await getOrder(id);
  if (order.tenantId !== tenant) {
    // Silent denial: no log, no identity, no correlation id.
    return { statusCode: 403, body: 'Forbidden' };
  }
  return { statusCode: 200, body: JSON.stringify(order) };
};
// CloudWatch shows only: START / END / REPORT. An attacker walking tenants
// produces thousands of 403s that are invisible.
```

### Secure
```javascript
// Structured, security-oriented events with identity + correlation ids.
function securityEvent(event, context, fields) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    level: 'SECURITY',
    request_id: context.awsRequestId,             // correlate this invocation
    trace_id: process.env._X_AMZN_TRACE_ID,       // correlate across the chain
    function: context.functionName,
    source_ip: event.requestContext?.identity?.sourceIp,
    identity: event.requestContext?.authorizer?.principalId,
    ...fields
  }));
}

exports.handler = async (event, context) => {
  const id = event.pathParameters.id;
  const tenant = event.requestContext.authorizer.tenantId;

  const order = await getOrder(id);
  if (order.tenantId !== tenant) {
    securityEvent(event, context, {
      event: 'authz_denied', resource: `orders/${id}`,
      outcome: 'DENY', reason: 'cross_tenant_access'
    });
    return { statusCode: 403, body: 'Forbidden' };
  }

  securityEvent(event, context, {
    event: 'sensitive_read', resource: `orders/${id}`, outcome: 'ALLOW'
  });
  return { statusCode: 200, body: JSON.stringify(order) };
};
// Now a tenant-walking sweep emits thousands of correlated authz_denied
// events from one identity/source -> a detectable, alertable pattern.
```

## 2. Lambda Handler — Python: Context-Rich Logging Without Leaking Secrets

### Vulnerable
```python
import json

def handler(event, context):
    # Prints the ENTIRE event -> dumps tokens, PII, and secrets into logs,
    # yet still records nothing about the security decision or outcome.
    print("event:", json.dumps(event))
    user = authenticate(event)          # failures raise and bubble up raw
    data = read_records(user)
    return {"statusCode": 200, "body": json.dumps(data)}
# Two failures at once: sensitive data leaked INTO logs, and no structured
# security event to actually detect abuse.
```

### Secure
```python
import json, logging, os
logger = logging.getLogger()
logger.setLevel(logging.INFO)

REDACT = {"authorization", "password", "token", "ssn", "card"}

def redact(d):
    return {k: ("***" if k.lower() in REDACT else v) for k, v in d.items()}

def security_event(context, **fields):
    logger.info(json.dumps({
        "level": "SECURITY",
        "request_id": context.aws_request_id,
        "trace_id": os.environ.get("_X_AMZN_TRACE_ID"),
        "function": context.function_name,
        **fields,
    }))

def handler(event, context):
    try:
        user = authenticate(event)
    except AuthError as e:
        security_event(context, event="auth_failed",
                       source_ip=event.get("requestContext", {})
                                     .get("identity", {}).get("sourceIp"),
                       outcome="DENY", reason=str(e.code))   # code, not secret
        return {"statusCode": 401, "body": "Unauthorized"}

    records = read_records(user)
    security_event(context, event="sensitive_read", identity=user.id,
                   outcome="ALLOW", record_count=len(records))  # volume signal
    return {"statusCode": 200, "body": json.dumps(records)}
# Logs carry decision + context (and a record_count that surfaces bulk reads),
# never the raw secrets.
```

## 3. Distributed Tracing Configuration (AWS SAM)

### Vulnerable
```yaml
# template.yaml — tracing disabled. A request that fans out across five
# functions and DynamoDB cannot be followed; each invocation is an island.
Resources:
  OrderApi:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: nodejs20.x
      # no Tracing, no X-Ray permissions, no downstream instrumentation
```

### Secure
```yaml
# template.yaml — active tracing everywhere, so one trace_id spans the chain.
Globals:
  Function:
    Tracing: Active            # X-Ray active tracing on every function
  Api:
    TracingEnabled: true

Resources:
  OrderApi:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: nodejs20.x
      Policies:
        - AWSXRayDaemonWriteAccess     # minimal permission to emit trace data
      # For vendor-neutral tracing, attach the ADOT (OpenTelemetry) layer instead.
```

```javascript
// Node.js: instrument the AWS SDK so downstream calls become child spans
const AWSXRay = require('aws-xray-sdk-core');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const ddb = AWSXRay.captureAWSv3Client(new DynamoDBClient({}));
// Now DynamoDB/S3/HTTP calls appear as spans under the request's trace,
// so a malicious request's full path is reconstructable.
```

## 4. Anomaly & Cost Alerting (CloudWatch)

### Vulnerable
```
# No alarms at all. The only "monitoring" is opening the dashboard by hand.
# A denial-of-wallet loop drives invocations 1000x; the first signal is the
# monthly invoice. Successful-but-abusive reads never trip anything.
```

### Secure
```yaml
# CloudFormation: alarm on invocation-rate spikes (abuse / denial-of-wallet)
InvocationSpikeAlarm:
  Type: AWS::CloudWatch::Alarm
  Properties:
    Namespace: AWS/Lambda
    MetricName: Invocations
    Dimensions: [{ Name: FunctionName, Value: !Ref OrderApi }]
    Statistic: Sum
    Period: 60
    EvaluationPeriods: 2
    Threshold: 5000
    ComparisonOperator: GreaterThanThreshold
    AlarmActions: [ !Ref SecurityTopic ]        # SNS -> on-call page

# Alarm on estimated charges — cost as a security signal (ties to SAS-8)
BillingSpikeAlarm:
  Type: AWS::CloudWatch::Alarm
  Properties:
    Namespace: AWS/Billing
    MetricName: EstimatedCharges
    Dimensions: [{ Name: Currency, Value: USD }]
    Statistic: Maximum
    Period: 21600
    EvaluationPeriods: 1
    Threshold: 500                               # your budget ceiling
    ComparisonOperator: GreaterThanThreshold
    AlarmActions: [ !Ref SecurityTopic ]

# Alarm on error-rate spikes (probing / injection failures)
ErrorRateAlarm:
  Type: AWS::CloudWatch::Alarm
  Properties:
    Namespace: AWS/Lambda
    MetricName: Errors
    Dimensions: [{ Name: FunctionName, Value: !Ref OrderApi }]
    Statistic: Sum
    Period: 60
    EvaluationPeriods: 2
    Threshold: 50
    ComparisonOperator: GreaterThanThreshold
    AlarmActions: [ !Ref SecurityTopic ]
```

## 5. Detecting Unusual IAM / Role Use (EventBridge)

### Vulnerable
```
# CloudTrail is on but nothing reacts to it. A compromised function assumes
# its role and calls AttachRolePolicy / CreateAccessKey — recorded, but no
# one is alerted, so it sits unnoticed in the trail.
```

### Secure
```yaml
# EventBridge rule: page a responder on sensitive IAM/STS API calls in near real time
IamAnomalyRule:
  Type: AWS::Events::Rule
  Properties:
    EventPattern:
      source: [ "aws.iam", "aws.sts" ]
      detail-type: [ "AWS API Call via CloudTrail" ]
      detail:
        eventName:
          - AttachRolePolicy
          - PutRolePolicy
          - CreateAccessKey
          - AssumeRole
    Targets:
      - Arn: !Ref SecurityTopic                  # SNS -> security on-call
        Id: notify-security
# Pair with GuardDuty for managed anomaly detection over CloudTrail, DNS,
# and Lambda network activity — no static thresholds to hand-tune.
```

## 6. Protecting Log Retention and Integrity

### Vulnerable
```yaml
# Default log group: short/undefined retention, and the function's own
# execution role can manage it. An attacker who owns the function deletes
# the streams or shortens retention and erases their own trail.
OrderFnRole:
  # ...
  Policies:
    - PolicyDocument:
        Statement:
          - Effect: Allow
            Action: [ "logs:*" ]        # includes DeleteLogStream, PutRetentionPolicy
            Resource: "*"
```

### Secure
```yaml
# Explicit, adequate retention; workload role can only WRITE, not manage/delete.
OrderFnLogGroup:
  Type: AWS::Logs::LogGroup
  Properties:
    LogGroupName: /aws/lambda/order-fn
    RetentionInDays: 365                 # long enough to investigate + comply

OrderFnRole:
  # ...
  Policies:
    - PolicyDocument:
        Statement:
          - Effect: Allow
            Action:
              - logs:CreateLogStream
              - logs:PutLogEvents        # write only — no delete/retention control
            Resource: !GetAtt OrderFnLogGroup.Arn

# Plus: ship logs off-account in near real time (subscription filter ->
# central security account) and keep immutable forensic copies (S3 Object Lock).
```

## What Changed, and Why

| Gap | Vulnerable | Secure |
|-----|-----------|--------|
| Security events | Only START/END; silent denials | Structured events with identity, resource, outcome, correlation ids |
| Sensitive data in logs | Whole event dumped (tokens, PII) | Redacted fields; log the decision, not the secret |
| Tracing | Disabled; invocations are islands | X-Ray/OTel active; one trace across the chain |
| Alerting | None; first signal is the invoice | Error, invocation, and cost alarms to on-call |
| IAM anomalies | Recorded but never actioned | EventBridge/GuardDuty alerts in near real time |
| Log integrity | Workload can delete its own logs | Write-only role, off-account shipping, immutable copies |

## Next Steps

- **[Prevention](prevention.md)**: The full serverless monitoring strategy
- **[Attack Vectors](attack-vectors.md)**: The activity these controls surface
- **[Overview](overview.md)**: Why serverless is blind by default
