# SAS-10: Improper Exception Handling and Verbose Error Messages - Prevention

The fix for SAS-10 is a single, repeatable discipline applied to every function: **catch the error, decide deliberately what happens next, tell the caller nothing internal, and tell the logs everything.** This page turns that sentence into concrete controls—handler wrappers, API Gateway error mapping, fail-closed security paths, idempotent retries, and uniform responses—so no exception is ever left to the platform's hostile defaults.

## Table of Contents

- [Guiding Principles](#principles)
- [1. Wrap Every Handler](#wrap)
- [2. Two Audiences: Generic Out, Detailed In](#two-audiences)
- [3. Map Errors at API Gateway](#gateway)
- [4. Keep Secrets and Stack Traces Out](#secrets)
- [5. Fail Closed on Security Paths](#failclosed)
- [6. Idempotency and Cleanup on Error](#idempotency)
- [7. Uniform Responses (No Oracles)](#uniform)
- [8. Guarantee the Audit Trail](#logging)
- [9. Disable Verbose Output in Production](#debug)
- [Prevention Checklist](#checklist)

## Guiding Principles

> **The platform default is: surface the raw error and retry.** Every principle below is about overriding one half of that default deliberately.

- **No exception reaches the platform serialiser.** Each handler has an outermost catch.
- **Two audiences.** The caller gets a generic message plus a correlation id; the logs get the full structured detail.
- **Fail closed.** On any security-relevant error, deny—never fall through to the privileged path.
- **Safe to repeat.** Assume at-least-once delivery: clean up partial work and make side effects idempotent.
- **Uniform to strangers.** Equivalent failures produce equivalent responses and timing, so errors are not an oracle.
- **Nothing is lost.** Every error is caught, classified, and logged, so the audit trail survives the failure.

## 1. Wrap Every Handler

Give each function one outermost boundary that turns any exception into a controlled, generic response. A shared wrapper (middleware/decorator) makes this consistent across a large fleet of small functions.

```javascript
// Node.js: a reusable wrapper applied to every handler
const withErrorBoundary = (fn) => async (event, context) => {
  const correlationId = context.awsRequestId;
  try {
    return await fn(event, context);
  } catch (err) {
    // FULL detail -> server-side logs only, keyed by correlationId
    console.error(JSON.stringify({
      level: 'ERROR', correlationId,
      name: err.name, message: err.message, stack: err.stack,
      function: context.functionName
    }));
    // GENERIC detail -> caller
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        error: 'internal_error',
        message: 'The request could not be processed.',
        correlationId              // let support correlate, leak nothing
      })
    };
  }
};

exports.handler = withErrorBoundary(async (event, context) => {
  // ... business logic; may throw freely, the boundary handles it ...
});
```

The correlation id is the bridge: it is safe to show the caller and lets an operator find the full trace in the logs without any internal detail crossing the wire.

## 2. Two Audiences: Generic Out, Detailed In

Design the response and the log as two separate artifacts with opposite goals.

| | Caller Response | Server-Side Log |
|---|---|---|
| **Goal** | Reveal nothing internal | Capture everything to debug |
| **Message** | Generic, stable, uniform | Exact exception + stack |
| **Identifiers** | Correlation id only | Correlation id + request/trace ids |
| **Secrets** | Never | Never (redacted) |
| **Format** | Small JSON | Structured JSON for querying |

Handle **known** error types explicitly and map them to safe client statuses; let everything unexpected fall to a single generic 500.

```python
# Python: classify known errors, generic fallback for the rest
def handler(event, context):
    try:
        return _run(event, context)
    except ValidationError as e:
        log.warning({"kind": "validation", "detail": str(e),
                     "correlation_id": context.aws_request_id})
        return client_error(400, "invalid_request",
                            "One or more fields are invalid.", context)
    except NotAuthorized:
        return client_error(403, "forbidden", "Access denied.", context)
    except Exception as e:                       # unexpected -> generic
        log.error({"kind": "unhandled", "type": type(e).__name__,
                   "message": str(e), "correlation_id": context.aws_request_id},
                  exc_info=True)                 # full stack to logs only
        return client_error(500, "internal_error",
                            "The request could not be processed.", context)
```

## 3. Map Errors at API Gateway

Even with a handler boundary, configure the gateway as a second wall so an unexpected function crash (timeout, OOM, init failure) is never returned raw. Use gateway error responses / integration mappings to replace internal errors with generic bodies.

```yaml
# AWS SAM / OpenAPI: gateway-level generic responses
# (illustrative; keeps runtime errors from reaching the client verbatim)
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
```

- Do not enable full request/response passthrough of Lambda errors to clients in production.
- For non-proxy integrations, map integration responses so driver/runtime messages are replaced, not forwarded.
- Apply the same treatment to **Function URLs**: put your own boundary in the handler, because a Function URL returns the function's output directly.

## 4. Keep Secrets and Stack Traces Out

Two rules, no exceptions: never serialise the environment or config into an error, and redact sensitive fields before anything is logged.

```javascript
// Redact before logging; never spread `process.env` or the raw event
const REDACT = new Set(['authorization','password','token','secret','ssn','card']);
const redact = (obj) => Object.fromEntries(
  Object.entries(obj || {}).map(([k, v]) =>
    [k, REDACT.has(k.toLowerCase()) ? '***' : v])
);

// GOOD: log selected, redacted context
console.error(JSON.stringify({ level:'ERROR', correlationId,
  input: redact(safeSubsetOfEvent) }));

// NEVER: console.error(err, process.env)      // dumps secrets
// NEVER: return { body: JSON.stringify(err) } // dumps stack + fields
```

- Store secrets in a secret manager and reference them at runtime (ties to **SAS-7**); an error that cannot see a plaintext secret cannot leak one.
- Strip stack traces, DSNs, ARNs, and account ids from anything client-bound.
- Treat logs as a sensitive sink too—redact there, since log stores are often more widely readable than secret stores.

## 5. Fail Closed on Security Paths

For authentication, authorization, signature checks, and validation, the failure branch must **deny**. Never let a caught exception drop through to the allowed path.

```python
# WRONG: fail-open
try:
    claims = verify_token(hdr)
except Exception:
    claims = {}            # error -> empty claims -> treated as allowed later

# RIGHT: fail-closed
try:
    claims = verify_token(hdr)
except Exception as e:
    log.warning({"event":"auth_error","reason":type(e).__name__,
                 "correlation_id": ctx.aws_request_id})
    return client_error(401, "unauthorized", "Authentication required.", ctx)
if claims.get("role") != "admin":
    return client_error(403, "forbidden", "Access denied.", ctx)
return admin_action(event)   # reached only on explicit success
```

- Make the security decision an explicit allow, reachable only after every check *succeeds*.
- Ensure every failure branch ends in a `return`/deny—a missing `return` is a fall-through bypass.
- Default deny in feature-flag and policy fetches: if the policy service errors, deny, do not "default to allow".

## 6. Idempotency and Cleanup on Error

Assume at-least-once delivery. An error after a side effect will be retried, so make side effects safe to repeat and roll back partial work.

```javascript
// Idempotency key makes a repeated charge a no-op
exports.handler = withErrorBoundary(async (event) => {
  const key = event.messageId;                 // stable per logical event
  if (await alreadyProcessed(key)) return ok(); // dedupe on retry

  await withCleanup(async () => {
    await chargeCard(event.orderId, event.amount, { idempotencyKey: key });
    await markPaid(event.orderId);
    await recordProcessed(key);                // commit the dedupe marker last
  }, /* onError */ async () => {
    await compensate(event.orderId);           // undo partial state
  });
});
```

- Use an **idempotency key** (message id, request id) so a retried invocation detects and skips completed work.
- Prefer provider idempotency features (e.g. payment idempotency keys, conditional writes) over home-grown guards.
- On the error path, **compensate**: undo or reconcile partial writes so state stays consistent.
- Order operations so the durable "done" marker is written last, after the side effects it guards.

## 7. Uniform Responses (No Oracles)

Equivalent failures must look—and take—the same from the outside.

- Return the **same status and body** for "user not found" and "wrong password"; distinguish them only in the logs.
- Avoid status/message shapes that change based on whether a record exists.
- For authentication comparisons, use **constant-time** checks and complete the same work regardless of validity to flatten timing.
- Keep a small, fixed set of client error codes; do not surface the internal exception type as the code.

```javascript
// Same outward result whether or not the account exists
async function login(email, password) {
  const user = await findUser(email);          // may be null
  const ok = await constantTimeVerify(password, user?.hash ?? DUMMY_HASH);
  if (!user || !ok) return unauthorized();      // identical response + timing
  return session(user);
}
```

## 8. Guarantee the Audit Trail

The handler boundary must log *before* it returns, so a failure can never erase the record of what happened.

- Emit a structured security event on every deny, error, and sensitive action, keyed by the correlation id.
- Put the audit write inside the boundary's catch, so even unexpected crashes are recorded.
- Do not place the only audit log *after* risky work—if that work throws, the log never runs. Log the decision as it is made.
- Send logs to a durable, access-controlled store (e.g. CloudWatch) that the function's own role cannot delete (ties to **SAS-5** monitoring).

## 9. Disable Verbose Output in Production

- Gate debug logging behind an environment flag that is **off** in production; never ship a function that prints the whole event by default.
- Turn off framework debug/echo modes and detailed error pages for production stages.
- Set log levels appropriately (INFO/WARN in prod), and route true debug detail to a level that is not emitted in production.
- Review that no `print(event)` / `console.log(event)` statements survive into the deployed artifact.

## Prevention Checklist

| Control | What It Prevents |
|---|---|
| Outermost handler boundary on every function | Raw errors reaching the caller |
| Generic client message + correlation id | Stack-trace / internals disclosure |
| API Gateway / Function URL error mapping | Crash/timeout errors leaking verbatim |
| No env/config serialised; logs redacted | Secret and infrastructure exposure |
| Fail-closed security branches | Authorization / validation bypass |
| Idempotency keys + compensation | Duplicate side effects, partial state |
| Uniform responses + constant-time checks | Enumeration and timing oracles |
| Log-before-return in the boundary | Lost audit trail on crash |
| Debug/verbose output off in production | Secondary leaks via logs |
| Explicit known-error handling + generic fallback | Inconsistent, leaky error shapes |

> **Bottom line**: every function should be boring when it fails—a generic message to the caller, a rich structured record in the logs, a hard deny on security paths, and a safe-to-retry side effect. Boring failures are secure failures.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure Lambda and API Gateway error handling
- **[Attack Vectors](attack-vectors.md)**: Understand exactly what these controls shut down
- **[Overview](overview.md)**: Why serverless surfaces and retries errors by default
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply these controls in hands-on exercises
