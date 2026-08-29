# SAS-10: Improper Exception Handling and Verbose Error Messages - Code Examples

Each pair below shows a **vulnerable** function (or configuration) and the **secure** version. The examples focus on what dominates real serverless findings: raw errors returned to the caller, secrets and stack traces in the dump, fail-open security checks, non-idempotent retries, enumeration oracles, and lost audit trails.

## Table of Contents

- [1. Lambda Handler (Node.js) — Raw Error vs. Generic Client Error](#ex1)
- [2. Lambda Handler (Python) — Verbose Dump vs. Redacted Logging](#ex2)
- [3. Fail-Open vs. Fail-Closed Authorization](#ex3)
- [4. Non-Idempotent Retry vs. Idempotent + Cleanup](#ex4)
- [5. Error Oracle vs. Uniform Response](#ex5)
- [6. API Gateway — Passthrough vs. Mapped Errors](#ex6)
- [7. Lost Audit Trail vs. Log-Before-Return](#ex7)

## 1. Lambda Handler (Node.js) — Raw Error vs. Generic Client Error

### Vulnerable
```javascript
// No try/catch. Any throw is serialised straight back to the caller
// through the API Gateway proxy integration, stack trace and all.
exports.handler = async (event) => {
  const body = JSON.parse(event.body);          // throws on bad JSON
  const order = await db.getOrder(body.orderId); // throws on DB error
  return { statusCode: 200, body: JSON.stringify(order) };
};

// Malformed body -> client receives:
// {
//   "errorType": "SyntaxError",
//   "errorMessage": "Unexpected token } in JSON at position 42",
//   "trace": ["SyntaxError: ...","    at Runtime.handler (/var/task/index.js:3:24)"]
// }
// File paths, runtime internals, and the failing operation are disclosed.
```

### Secure
```javascript
// Reusable boundary: caller gets a generic message + correlation id,
// full detail goes only to CloudWatch.
const withErrorBoundary = (fn) => async (event, context) => {
  const correlationId = context.awsRequestId;
  try {
    return await fn(event, context);
  } catch (err) {
    console.error(JSON.stringify({               // server-side only
      level: 'ERROR', correlationId, name: err.name,
      message: err.message, stack: err.stack, fn: context.functionName
    }));
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        error: 'internal_error',
        message: 'The request could not be processed.',
        correlationId                            // safe to show, leaks nothing
      })
    };
  }
};

exports.handler = withErrorBoundary(async (event) => {
  let body;
  try { body = JSON.parse(event.body); }
  catch { const e = new Error('bad_request'); e.statusCode = 400; throw e; }
  const order = await db.getOrder(body.orderId);
  return { statusCode: 200, body: JSON.stringify(order) };
});
// Caller sees: {"error":"internal_error","message":"...","correlationId":"..."}
```

## 2. Lambda Handler (Python) — Verbose Dump vs. Redacted Logging

### Vulnerable
```python
import json

def handler(event, context):
    try:
        user = authenticate(event)
        return {"statusCode": 200, "body": json.dumps(read(user))}
    except Exception as e:
        # Dumps the whole event AND the environment "to help debugging".
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": str(e),
                "event": event,                 # tokens, PII in the body
                "env": dict(os.environ),        # DB_PASSWORD, ARNs, account id
            }),
        }
# The 500 response hands the caller live secrets and infrastructure ids.
```

### Secure
```python
import json, logging, os
log = logging.getLogger()
log.setLevel(logging.INFO)

REDACT = {"authorization", "password", "token", "secret", "ssn", "card"}

def redact(d):
    return {k: ("***" if k.lower() in REDACT else v) for k, v in (d or {}).items()}

def client_error(status, code, msg, context):
    return {"statusCode": status,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": code, "message": msg,
                                "correlationId": context.aws_request_id})}

def handler(event, context):
    try:
        user = authenticate(event)
        return {"statusCode": 200, "body": json.dumps(read(user))}
    except AuthError:
        return client_error(401, "unauthorized", "Authentication required.", context)
    except Exception as e:
        # Full detail to logs, redacted, never the raw env or event.
        log.error(json.dumps({"level": "ERROR", "type": type(e).__name__,
                              "message": str(e),
                              "input": redact(event.get("headers")),
                              "correlation_id": context.aws_request_id}),
                  exc_info=True)
        return client_error(500, "internal_error",
                            "The request could not be processed.", context)
# Secrets never enter the response, and are redacted before they reach logs.
```

## 3. Fail-Open vs. Fail-Closed Authorization

### Vulnerable
```python
def handler(event, context):
    try:
        claims = verify_token(event["headers"]["authorization"])
    except Exception:
        claims = {}                       # error -> empty claims, keep going
    # Missing role is treated as "unrestricted" downstream.
    if claims.get("role") == "admin" or not claims:   # BUG: `not claims`
        return do_admin_action(event)
    return {"statusCode": 403, "body": "Forbidden"}
# A malformed/expired token makes verify_token throw -> empty claims ->
# the `not claims` branch grants the admin action. The error OPENS the gate.
```

### Secure
```python
def handler(event, context):
    try:
        claims = verify_token(event["headers"].get("authorization", ""))
    except Exception as e:
        log.warning(json.dumps({"event": "auth_error",
                                "reason": type(e).__name__,
                                "correlation_id": context.aws_request_id}))
        return client_error(401, "unauthorized", "Authentication required.", context)

    if claims.get("role") != "admin":     # explicit allow only on success
        return client_error(403, "forbidden", "Access denied.", context)

    return do_admin_action(event)         # reached only when every check passed
# Any exception in verification results in a hard 401 deny. Fail CLOSED.
```

## 4. Non-Idempotent Retry vs. Idempotent + Cleanup

### Vulnerable
```javascript
// SQS trigger = at-least-once delivery.
exports.handler = async (event) => {
  for (const record of event.Records) {
    const msg = JSON.parse(record.body);
    await chargeCard(msg.orderId, msg.amount);  // side effect committed
    await markPaid(msg.orderId);                // throws intermittently
    // Any throw here -> message not deleted -> SQS re-delivers ->
    // chargeCard runs AGAIN -> the customer is charged twice.
  }
};
```

### Secure
```javascript
// Idempotency key + compensation make retries safe.
exports.handler = async (event) => {
  for (const record of event.Records) {
    const msg = JSON.parse(record.body);
    const key = record.messageId;               // stable per logical message

    if (await alreadyProcessed(key)) continue;  // dedupe on retry

    try {
      // Provider idempotency key: a repeated charge is a no-op provider-side.
      await chargeCard(msg.orderId, msg.amount, { idempotencyKey: key });
      await markPaid(msg.orderId);
      await recordProcessed(key);               // commit the marker LAST
    } catch (err) {
      await compensate(msg.orderId);            // undo partial state
      console.error(JSON.stringify({ level: 'ERROR', key,
        message: err.message }));               // logged, then rethrow to retry
      throw err;                                // safe: next run dedupes
    }
  }
};
```

## 5. Error Oracle vs. Uniform Response

### Vulnerable
```javascript
// Different outcomes reveal whether the account exists.
exports.handler = async (event) => {
  const { email, password } = JSON.parse(event.body);
  const user = await findUser(email);
  if (!user) return { statusCode: 404, body: 'user not found' };   // tell #1
  if (!verify(password, user.hash))
    return { statusCode: 401, body: 'wrong password' };            // tell #2
  return { statusCode: 200, body: token(user) };
};
// 404 vs 401 (and the faster 404 path) enumerates valid emails.
```

### Secure
```javascript
const DUMMY_HASH = process.env.DUMMY_HASH;      // for constant-time path

exports.handler = withErrorBoundary(async (event) => {
  const { email, password } = JSON.parse(event.body);
  const user = await findUser(email);           // may be null
  // Always do the same work so timing does not distinguish the cases.
  const ok = await constantTimeVerify(password, user ? user.hash : DUMMY_HASH);
  if (!user || !ok) {
    return { statusCode: 401,
             body: JSON.stringify({ error: 'invalid_credentials',
                                    message: 'Email or password is incorrect.' }) };
  }
  return { statusCode: 200, body: token(user) };
});
// Identical status, identical message, flattened timing -> no oracle.
```

## 6. API Gateway — Passthrough vs. Mapped Errors

### Vulnerable
```yaml
# Non-proxy integration that forwards the Lambda error verbatim, and no
# gateway responses configured -> runtime crashes/timeouts reach the client raw.
Resources:
  Api:
    Type: AWS::Serverless::Api
    Properties:
      # (no x-amazon-apigateway-gateway-responses)
      # integration responses simply pass $input.path('$.errorMessage') through
      # so "OperationalError: FATAL: password authentication failed ..." is returned.
```

### Secure
```yaml
# Gateway replaces internal 4xx/5xx with generic bodies, so a function
# crash, timeout, or init failure never reaches the client verbatim.
Resources:
  Api:
    Type: AWS::Serverless::Api
    Properties:
      DefinitionBody:
        x-amazon-apigateway-gateway-responses:
          DEFAULT_5XX:
            responseTemplates:
              application/json: '{"error":"internal_error","message":"The request could not be processed."}'
          DEFAULT_4XX:
            responseTemplates:
              application/json: '{"error":"bad_request","message":"The request was invalid."}'
          INTEGRATION_TIMEOUT:
            responseTemplates:
              application/json: '{"error":"timeout","message":"The request timed out."}'
# Function URLs need the same discipline: the handler boundary is the only
# thing between a raw exception and the client, so it must never be omitted.
```

## 7. Lost Audit Trail vs. Log-Before-Return

### Vulnerable
```python
def handler(event, context):
    user = authorize(event)                 # may throw -> crash before any log
    result = do_sensitive_action(user, event)
    # The ONLY audit line runs after the risky work:
    audit_log(user, "sensitive_action", "ok")
    return {"statusCode": 200, "body": json.dumps(result)}
# If do_sensitive_action throws, the function crashes and NOTHING is logged.
# The platform shows only START/END. The action's outcome is invisible.
```

### Secure
```python
def handler(event, context):
    cid = context.aws_request_id
    try:
        user = authorize(event)
        # Log the DECISION as it is made, before the risky work.
        audit_log(cid, identity=user.id, event="sensitive_action",
                  outcome="ATTEMPT")
        result = do_sensitive_action(user, event)
        audit_log(cid, identity=user.id, event="sensitive_action",
                  outcome="SUCCESS")
        return {"statusCode": 200, "body": json.dumps(result)}
    except AuthError:
        audit_log(cid, event="sensitive_action", outcome="DENY")
        return client_error(403, "forbidden", "Access denied.", context)
    except Exception as e:
        # Even an unexpected crash is recorded before we return.
        audit_log(cid, event="sensitive_action", outcome="ERROR",
                  reason=type(e).__name__)
        log.error(json.dumps({"correlation_id": cid, "type": type(e).__name__}),
                  exc_info=True)
        return client_error(500, "internal_error",
                            "The request could not be processed.", context)
# The audit trail survives every path: attempt, success, deny, and crash.
```

## Summary

| # | Vulnerable Pattern | Secure Pattern |
|---|---|---|
| 1 | Unhandled throw serialised to caller | Boundary + generic error + correlation id |
| 2 | Event/env dumped in response | Redacted, server-side-only logging |
| 3 | Exception yields empty claims (fail-open) | Exception yields hard deny (fail-closed) |
| 4 | Retry re-runs a committed charge | Idempotency key + compensation |
| 5 | 404/401 + timing reveal existence | Uniform response + constant-time check |
| 6 | Gateway forwards raw runtime error | Gateway maps 4xx/5xx to generic bodies |
| 7 | Sole audit line after risky work | Log decision before work; log every path |

## Next Steps

- **[Prevention](prevention.md)**: The full serverless error-handling strategy
- **[Attack Vectors](attack-vectors.md)**: The techniques these controls shut down
- **[Overview](overview.md)**: Why serverless surfaces and retries errors by default
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply these controls in hands-on exercises
