# SAS-10: Improper Exception Handling and Verbose Error Messages - Attack Vectors

Attacking this weakness is mostly about **making things break on purpose** and reading what falls out. An attacker sends malformed, oversized, or unexpected input to force an unhandled exception, then mines the response for internals—or exploits *how* the function fails: a check that is skipped, a write that half-completes, a message that is retried. This page walks the attacker's workflow, from triggering errors to weaponising fail-open and duplicate-side-effect behaviour.

## Table of Contents

- [The Attacker's Mindset](#mindset)
- [Phase 1: Triggering Errors](#triggering)
- [Phase 2: Harvesting Internals](#harvesting)
- [Phase 3: Error and Timing Oracles](#oracles)
- [Phase 4: Exploiting Fail-Open Logic](#failopen)
- [Phase 5: Forcing Duplicate Side Effects](#duplicate)
- [Phase 6: Destroying the Audit Trail](#audit)
- [A Full Attack Chain](#chain)

## The Attacker's Mindset

A defender sees an error as an accident. An attacker sees it as an **interface**—a second, undocumented API that answers questions the normal responses will not. Every exception is a chance to learn what runtime you use, where your files live, what your database is called, and how your security checks behave under stress.

> **Core idea**: The attacker does not need the function to succeed. They need it to *fail in an informative way*. Verbose errors, inconsistent responses, and unsafe failure modes are the payload.

### What the attacker is hunting for

- **Fingerprints**: runtime and library versions, framework names, file paths.
- **Infrastructure**: ARNs, account IDs, region, function and layer names, internal hostnames.
- **Secrets**: environment variables, connection strings, tokens caught in a dump.
- **Data structure**: table and column names, query text, key formats.
- **Behavioural tells**: does an error skip a check? repeat an action? confirm a record exists?

## Phase 1: Triggering Errors

The first move is to reliably make the function throw. Serverless handlers are small and often validate little, so the paths to an exception are numerous.

### Malformed input

```
# Break the parser: the handler calls JSON.parse / json.loads on the body
POST /orders  Content-Type: application/json

{ "userId": 42, }          # trailing comma -> SyntaxError
{ "userId": }              # missing value  -> SyntaxError
%%%not-json%%%             # not JSON at all -> SyntaxError
```

### Type and shape confusion

```
# The handler expects a string id and indexes into the result.
GET /orders/{id}

/orders/../../etc          # unexpected shape
/orders/999999999999999999 # out-of-range -> overflow / DB error
/orders?id[]=1&id[]=2       # array where a scalar is expected -> TypeError
```

### Missing / unexpected fields

```
# Omit a field the handler dereferences without checking:
{ }                        # event.body.userId is undefined -> "Cannot read
                           # property 'id' of undefined"
# Or supply a field of the wrong type to break downstream code paths.
```

### Resource and dependency pressure

- Oversized payloads or deeply nested JSON to exhaust memory or hit limits.
- Requests that force a downstream call to time out (slow dependency, throttled table) so the handler throws a timeout/throttling exception.
- Values that violate a database constraint (duplicate key, wrong type) to surface a driver error carrying the query text.

## Phase 2: Harvesting Internals

Once an error is returned, the attacker reads it carefully. A single verbose response can collapse hours of blind guessing.

### Reading a raw stack trace

```
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{
  "errorType": "TypeError",
  "errorMessage": "Cannot read properties of undefined (reading 'id')",
  "trace": [
    "TypeError: Cannot read properties of undefined (reading 'id')",
    "    at Runtime.handler (/var/task/src/handlers/orders.js:37:28)",
    "    at Runtime.handleOnceNonStreaming (/var/runtime/index.mjs:...)"
  ]
}
```

**Harvested**: the code lives at `/var/task/src/handlers/orders.js`, it is Node on the AWS runtime, and line 37 dereferences an `id` without a guard—the attacker now knows exactly which field to omit and where the logic is thin.

### Reading an infrastructure / secret leak

```json
{
  "errorType": "OperationalError",
  "errorMessage": "connection to server at \"orders-db.internal\" failed",
  "env": {
    "DB_DSN": "postgres://app:S3cr3t-pw@orders-db.internal:5432/prod",
    "AWS_LAMBDA_FUNCTION_NAME": "orders-api-prod",
    "FUNCTION_ARN": "arn:aws:lambda:us-east-1:123456789012:function:orders-api-prod"
  }
}
```

**Harvested**: a live database credential, the internal hostname, the region, the account id `123456789012`, and the exact function name—enough to pivot without ever "hacking" anything further.

### Fingerprinting from database driver errors

```
{ "errorMessage":
  "error: column \"is_admin\" does not exist\n  Position: 34\n  Query:
   SELECT id, email, is_admn FROM users WHERE tenant_id = $1" }
```

**Harvested**: the table (`users`), real column names, that a typo path exists, and that there is an `is_admin` column worth targeting elsewhere.

## Phase 3: Error and Timing Oracles

Even when the body is generic, *differences* between responses leak information. The attacker turns the function into an oracle by comparing status codes, messages, or response times across inputs.

### Existence oracle via error type

```
POST /login  {"email":"alice@example.com","password":"x"}  -> 500 (KeyError)
POST /login  {"email":"ghost@example.com","password":"x"}  -> 404 (not found)
```

The `500` only occurs for accounts that exist (a downstream lookup succeeds, then a later step throws). Comparing the two responses enumerates valid emails—no verbose body required, just an inconsistency.

### Timing oracle

```
Valid record   -> heavy code path runs, then errors  -> ~380 ms
Invalid record -> fails fast at the first check      ->  ~40 ms
```

When the error path for real data does more work before failing, the response time itself distinguishes real from fake—an enumeration channel that survives even a perfectly generic error message.

### Validation-order oracle

- An input that triggers a "record not found" only after passing an earlier authorization check tells the attacker that authorization *passed*—confirming access boundaries.
- Different error shapes for "malformed token" vs. "expired token" vs. "unknown user" map out the authentication pipeline step by step.

## Phase 4: Exploiting Fail-Open Logic

The highest-value target is a function whose *error path skips a security control*. Instead of extracting data, the attacker deliberately induces the exception that makes the check disappear.

### Making the check throw

```python
def handler(event, context):
    try:
        claims = verify_token(event["headers"]["authorization"])
    except Exception:
        claims = {}                 # fail-open: error -> empty claims
    if claims.get("role") == "admin" or not claims:   # BUG
        return admin_action(event)  # empty claims slips through
    return forbidden()
```

**Attack**: send a header the verifier cannot process—a malformed JWT, a token signed by an unknown key, or an oversized value that makes `verify_token` raise. The exception drops the attacker into the empty-claims branch and grants the privileged action.

### Common fail-open shapes to probe

- A `try/except` around authentication that sets a default identity on failure.
- A feature-flag or policy fetch that "defaults to allow" when the config service errors.
- Input validation wrapped so that a validator exception is logged and execution continues with the unchecked input.
- A signature/HMAC check whose failure branch is missing a `return`, so execution falls through.

> The attacker's tell that fail-open exists: inducing an error *helps* rather than blocks them. If a malformed credential yields *more* access than a missing one, the failure mode is open.

## Phase 5: Forcing Duplicate Side Effects

On at-least-once event sources, an unhandled error *after* a side effect causes the platform to retry the whole invocation. An attacker who can make the tail of the function fail turns one action into many.

```javascript
// Trigger: SQS message -> charge, then a fragile post-step
exports.handler = async (event) => {
  await chargeCard(event.orderId, event.amount);  // committed
  await notifyLedger(event.orderId);              // attacker makes this throw
  // Unacknowledged -> SQS re-delivers -> chargeCard runs AGAIN
};
```

### How the attacker induces the tail failure

- Craft the order so the downstream `notifyLedger` call hits a validation or size limit and throws, while the earlier charge still succeeds.
- Flood a shared dependency so the post-step is throttled and errors, while the side effect ahead of it commits.
- Exploit a timeout: size the work so the function times out just after the side effect, before acknowledgement.

**Impact**: duplicate charges, duplicate emails, double-inserted records, or repeated privileged operations—driven entirely by the missing cleanup/idempotency on the error path.

## Phase 6: Destroying the Audit Trail

An uncaught exception that crashes the function *before* its logging line means no security event is ever recorded. An attacker who understands this will deliberately fail the function early, on the very requests they most want hidden.

- Trigger the crash *before* the audit write so the malicious action leaves no structured record—only the platform's bare START/END remains.
- Combine with fail-open: the request both bypasses the control *and* avoids being logged, because the log statement sat after the point of failure.
- Use error floods to bury a single real attack in noise, betting the team has alert fatigue on 500s.

## A Full Attack Chain

Putting the phases together against a hypothetical serverless orders API:

1. **Trigger**: The attacker posts malformed JSON to `/orders`. The unhandled `SyntaxError` is serialised back with a full trace.
2. **Harvest**: The trace reveals the Node runtime version, the file path `/var/task/src/handlers/orders.js`, and—on a second, DB-level error—the connection string in an echoed environment object.
3. **Recon expand**: A driver error leaks the `users` table and an `is_admin` column. The account id and function ARN come from the same dump.
4. **Oracle**: Using response-shape differences, the attacker enumerates valid customer emails without any verbose body.
5. **Fail-open**: A malformed authorization header makes the token verifier throw; the fail-open branch grants an admin action.
6. **Duplicate**: On the async fulfilment function, the attacker sizes the order so the post-charge step throws; the retry double-charges.
7. **Cover**: Because the audit log statement ran after the point of failure, none of the privileged calls left a structured record.

> Every step here is powered by the same root cause: errors that were never caught, mapped, and failed *closed*. Fix the error handling and the entire chain loses its fuel.

## Defensive Summary

| Attacker Move | What Enables It | Control That Breaks It |
|---|---|---|
| Read stack traces | Raw errors returned to caller | Generic client error + server-side log |
| Steal secrets from dumps | Env/config echoed on failure | Never serialise env; redact logs |
| Enumerate via oracles | Inconsistent status/message/timing | Uniform responses; constant-time checks |
| Bypass via fail-open | Error path skips the check | Fail closed; deny on exception |
| Duplicate side effects | Retry after uncommitted ack | Idempotency keys + cleanup on error |
| Erase the trail | Crash before the audit write | Catch-and-log around every path |

## Next Steps

- **[Prevention Guide](prevention.md)**: Build generic client errors, structured server-side logging, and fail-closed paths
- **[Code Examples](examples.md)**: Vulnerable vs. secure Lambda and API Gateway error handling
- **[Overview](overview.md)**: Why serverless surfaces and retries errors by default
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
