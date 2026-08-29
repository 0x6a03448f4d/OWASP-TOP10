# SAS-10: Improper Exception Handling and Verbose Error Messages - Overview

## Table of Contents

- [What is Improper Exception Handling and Verbose Error Messages?](#what-is-it)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Improper Exception Handling and Verbose Error Messages?

**Improper Exception Handling and Verbose Error Messages** occurs when a serverless function lets an exception decide its own fate: the error bubbles up unhandled, the platform serialises whatever it can, and the caller receives a response full of internal detail—or the function fails in a way that quietly skips a security check, half-completes a write, or vanishes without leaving an audit record. It is not one broken line; it is the accumulated consequence of thousands of small, quickly-written functions that were never given a deliberate answer to the question *"what should happen when this goes wrong?"*

Serverless magnifies this class of bug. Functions are small, single-purpose, and written fast—often with the "happy path" as the only path anyone tested. There is no long-lived process to hold a considered global error handler, no operator watching a console, and the platform is *helpful* by default: an unhandled exception is dutifully captured and returned to the caller through API Gateway, a Function URL, or the invoke response. That helpfulness is exactly the problem. The default behaviour of "surface the raw error" is convenient in development and catastrophic in production.

### Core Concept

```
Improper handling (what the caller should NEVER see):
  Raw exception   -> "TypeError: Cannot read property 'id' of undefined"
  Stack trace     -> file paths, line numbers, framework internals
  Query text      -> the failing SQL / NoSQL filter, table + column names
  Infrastructure  -> ARNs, account IDs, region, function + layer names
  Configuration   -> env vars, connection strings, secrets in the dump
  Failure mode    -> error skips an authz check (fail-open) or half-writes

Proper handling (what "good" looks like):
  To the CALLER   -> generic message + correlation id, nothing internal
  To the LOGS     -> full structured detail, server-side only (CloudWatch)
  On SECURITY err -> fail closed: deny, do not fall through
  On WRITE err    -> clean up / roll back; idempotent so retries are safe
  Debug output    -> OFF in production, no verbose dumps to the response
  Every path      -> the error is caught, classified, and recorded
```

### Why It's Critical for Serverless

Serverless concentrates several conditions that turn a sloppy `catch` into a real vulnerability:

- The platform **returns unhandled errors to the caller by default**. Through API Gateway, a Lambda Function URL, or a direct invoke, an uncaught exception is serialised back over the wire unless you intervene.
- Functions are **tiny and numerous**. Each is a fresh opportunity to forget a `try/catch`, and there is no shared, always-on error middleware the way a monolith has one global handler.
- The execution context is **packed with sensitive material**—environment variables hold secrets (ties to **SAS-7**), and the identity carries broad IAM permissions. An error dump that echoes the environment leaks all of it.
- Invocations are **retried automatically**. Asynchronous and stream event sources are *at-least-once*: an exception *after* a side effect but before acknowledgement means the platform runs the function again, duplicating the side effect (ties to **SAS-9**).
- Functions are **ephemeral**. A crash that occurs before the audit line is written means the record of what happened simply never exists.

## Why Does This Matter?

### Business Impact

- **Reconnaissance Handed to Attackers**: Verbose errors give an adversary a free, precise map—runtime versions, library names, file layout, table and column names, internal hostnames, ARNs, and account IDs—removing the guesswork from the next stage of the attack.
- **Direct Secret Exposure**: When environment variables or connection strings appear in an error dump, credentials leak with no exploit required, and the blast radius is whatever those credentials can reach.
- **Silent Security Bypass**: Fail-open error handling—where a thrown exception causes an authorization or validation check to be skipped—can grant access or accept bad input without any obvious sign that a control failed.
- **Duplicated or Corrupted Transactions**: Unhandled errors on non-idempotent write paths, combined with automatic retries, produce double charges, duplicate records, and inconsistent state—a data-integrity and financial problem, not just a bug.
- **Lost Accountability**: A function that crashes before logging leaves no audit trail, undermining incident response, compliance evidence, and forensics.

### Technical Impact

- **Information Disclosure**: Stack traces, query text, and infrastructure identifiers reveal the exact internals to target.
- **Enumeration and Oracles**: Responses that differ by error type turn the function into an oracle—"user not found" vs. "wrong password", or a validation error that only fires on real records, lets an attacker enumerate valid data.
- **Inconsistent / Partial State**: An exception between two writes leaves the system half-updated; without cleanup the data model drifts out of integrity.
- **Duplicate Side Effects**: At-least-once retries re-run everything before the failure point, so non-idempotent effects (emails, charges, inserts) happen twice or more.
- **Fail-Open Authorization**: A `catch` that logs and continues—or a check wrapped so its failure returns "allow"—converts an error into an access-control bypass.

## Technical Context

### Common Failure Scenarios in Serverless

#### 1. Unhandled Exception Returned to the Caller

```javascript
// Node.js Lambda behind API Gateway (proxy integration), no try/catch
exports.handler = async (event) => {
  const body = JSON.parse(event.body);        // throws on malformed input
  const user = await db.getUser(body.userId); // throws on DB error
  return { statusCode: 200, body: JSON.stringify(user) };
};

// Malformed body -> the runtime serialises the raw error to the client:
{
  "errorType": "SyntaxError",
  "errorMessage": "Unexpected token } in JSON at position 42",
  "trace": [
    "SyntaxError: Unexpected token } in JSON at position 42",
    "    at JSON.parse (<anonymous>)",
    "    at Runtime.handler (/var/task/index.js:2:24)"
  ]
}
```

**Risk**: File paths, line numbers, runtime internals, and the failing operation are disclosed to anyone who can send a bad request.

#### 2. Secrets and Infrastructure in the Error Dump

```json
{
  "errorType": "OperationalError",
  "errorMessage": "could not connect to server: Connection refused",
  "context": {
    "DB_HOST": "orders-db.internal",
    "DB_PASSWORD": "S3cr3t-pw",
    "DB_DSN": "postgres://app:S3cr3t-pw@orders-db.internal:5432/prod",
    "FUNCTION_ARN": "arn:aws:lambda:us-east-1:123456789012:function:orders-api",
    "ACCOUNT_ID": "123456789012"
  }
}
```

**Risk**: A handler that echoes its environment or config on failure leaks live credentials, internal hostnames, ARNs, and the account ID—this is where SAS-10 and **SAS-7 (secrets storage)** meet.

#### 3. Fail-Open on a Security Check

```python
def handler(event, context):
    try:
        claims = verify_token(event["headers"]["authorization"])
    except Exception:
        claims = {}          # BUG: verification error -> empty claims, continue
    # Downstream code treats missing role as "not restricted" and proceeds.
    return do_privileged_action(claims)
```

**Risk**: The exception path *skips* authentication instead of denying. An attacker who can make `verify_token` throw (expired key, malformed header) is let through.

#### 4. Unhandled Error After a Side Effect (Duplicate Work)

```javascript
// SQS/async trigger = at-least-once delivery
exports.handler = async (event) => {
  await chargeCard(event.orderId, event.amount);   // side effect committed
  await markPaid(event.orderId);                    // throws intermittently
  // Exception here -> platform RETRIES the whole message -> card charged AGAIN
};
```

**Risk**: Because the failure happens after a non-idempotent side effect and before acknowledgement, the automatic retry duplicates it—the SAS-10 / **SAS-9 (business-logic / flow)** overlap.

#### 5. Error-Type Oracle Enabling Enumeration

```
GET /account?email=alice@example.com   -> 500 "KeyError: 'stripe_customer_id'"
GET /account?email=nobody@example.com  -> 404 "not found"
```

**Risk**: The two error shapes differ only for accounts that exist, so the endpoint confirms which emails are registered—an information-disclosure oracle built entirely out of inconsistent error handling.

### Where the Detail Leaks Out

| Exposure Channel | What Leaks | Consequence |
|---|---|---|
| API Gateway proxy response | Unmapped runtime error + trace | Recon, stack fingerprinting |
| Lambda Function URL | Raw exception body | Direct info disclosure |
| Synchronous invoke response | `errorMessage` / `trace` fields | Internals to any caller |
| Error object echoing env/config | Secrets, ARNs, account IDs | Credential + infra exposure |
| Verbose debug logging left on | Full events, tokens, PII | Secondary leak via logs |
| Differing status/messages | Existence of records | Enumeration / oracle |

## Real-World Impact

The incidents below are described as **classes of failure** that are repeatedly documented across the industry, not as claims about any single named breach with invented specifics.

### Case Class 1: Stack Traces as Free Reconnaissance

**Failure**:

- Functions and web endpoints ship with framework debug behaviour left on, so unhandled exceptions render full stack traces—file paths, library versions, and sometimes fragments of configuration—straight to the client.

**Impact**:

- Automated scanners and manual testers routinely trigger errors specifically to read these traces, then match the disclosed versions and paths to known vulnerabilities. Verbose error output is one of the most consistently reported findings in application assessments precisely because it turns a single bad request into a detailed internal map.

**Root Cause**: Development-grade error verbosity carried into production, with no mapping layer to replace raw errors with generic client responses.

### Case Class 2: Secrets Surfacing Through Error and Debug Output

**Failure**:

- Handlers log or return the full event or their own environment on failure "to help debugging", and the execution environment holds secrets in environment variables.

**Impact**:

- Credentials, tokens, and connection strings end up in client responses or in log stores that are more widely readable than the secret store itself—a documented pattern behind many credential-exposure incidents. The leaked credential is then reused directly, with no further exploitation of the function needed.

**Root Cause**: Treating the execution environment as safe to dump, and conflating "log everything" with observability. Overlaps directly with SAS-7.

### Case Class 3: Retries Turning One Action Into Many

**Failure**:

- Event-driven functions perform a non-idempotent side effect and then hit an unhandled error before acknowledging the event, on an at-least-once source (queues, streams, async invokes).

**Impact**:

- The platform re-delivers and re-runs the function, repeating the side effect—duplicated charges, duplicate notifications, or double-inserted records. This is a well-understood consequence of at-least-once delivery and is the reason platform guidance repeatedly stresses idempotent function design.

**Root Cause**: Error paths that neither clean up partial work nor make the operation safe to repeat, combined with automatic retry semantics. Overlaps with SAS-9.

## Prevalence and Statistics

Improper error handling and information leakage through error messages are among the **most consistently observed weaknesses** in application security work. They map to long-standing CWE entries—such as improper error handling, generation of an error message containing sensitive information, and information exposure through an error message—and appear across the OWASP Top 10 (notably under Security Misconfiguration) and the OWASP Serverless Top 10.

Rather than cite precise counts (which vary by source and year), the defensible picture is:

- Verbose error output is characterised as **highly prevalent and trivially detectable**—a single malformed request often surfaces it.
- The most commonly observed sub-issues are **raw stack traces returned to callers, environment/secret leakage in error dumps, fail-open handling of security checks, and duplicate side effects from retried failures**.
- The impact spans **information disclosure up through credential exposure, security-control bypass, and data-integrity loss**—so severity is best judged by what the specific leak or fail-open enables, not by the error itself.

> Note: exact percentages differ between reports. Treat any single figure as illustrative; the durable takeaway is that verbose, unhandled errors are common, easy to trigger, and cheap to exploit—while the fix (generic client errors + detailed server-side logs + fail-closed paths) is well understood.

## Common Misunderstandings

### Myth 1: "A stack trace is just noise; it doesn't really help an attacker"

**Reality**: A trace names your runtime version, libraries, file paths, and the failing operation. That is exactly the reconnaissance an attacker needs to match your stack to a known CVE and craft the next request.

### Myth 2: "It's fine to log the whole event so we can debug later"

**Reality**: Full events and environments contain tokens, PII, and secrets. Dumping them relocates the exposure into a log store that is often more widely readable than the secret store. Log decisions and context, redact the rest.

### Myth 3: "Catching every exception and continuing makes the function more robust"

**Reality**: A blanket `catch` that swallows the error and proceeds is how fail-open bugs are born. For security-relevant operations, an error must fail *closed*—deny and stop—not fall through to the privileged path.

### Myth 4: "If the function threw, nothing happened"

**Reality**: The exception may have fired *after* a side effect already committed. On at-least-once sources the platform then retries, so "it failed" can actually mean "it happened, twice." Design for cleanup and idempotency.

### Myth 5: "Different error messages are more user-friendly"

**Reality**: Error responses that vary by whether a record exists become an enumeration oracle. User-facing messages should be uniform for equivalent failures; the distinguishing detail belongs in the logs, keyed by a correlation id.

### Myth 6: "The platform handles errors for me, so I don't need my own handler"

**Reality**: The platform's default is to *surface* the raw error to the caller and (for async) to *retry*. Both defaults are hostile in production. You need an explicit handler that maps errors, logs detail, and controls retry behaviour.

## How Improper Error Handling Differs from Related Issues

| Aspect | Improper Error Handling (SAS-10) | Secrets Storage (SAS-7) | Business Logic / Flow (SAS-9) |
|---|---|---|---|
| **Root cause** | Unhandled/verbose/fail-open errors | Secrets exposed at rest or in env | Abusable flow & retry semantics |
| **Where it lives** | The handler's error paths | Configuration & secret stores | Multi-step / event-driven logic |
| **Typical fix** | Catch, map, log, fail closed | Use a secret manager, least priv | Idempotency, cleanup, invariants |
| **Detection** | Trigger errors, read responses | Config/secret scan | Flow & replay testing |

## Key Takeaways

1. **The default is hostile**—serverless platforms surface raw errors to callers and retry failures automatically; you must override both deliberately.
2. **Two audiences, two messages**—the caller gets a generic error plus a correlation id; the full detail goes only to server-side structured logs.
3. **Fail closed on anything security-relevant**—an exception in an authz or validation path must deny, never fall through to "allow".
4. **Errors can duplicate work**—on at-least-once sources, clean up partial writes and make side effects idempotent so retries are safe.
5. **Never lose the record**—ensure the error is caught and logged so the audit trail survives the crash, and keep secrets and stack traces out of both the response and the logs.

## How to Identify if You're Vulnerable

Ask these questions about your functions:

- [ ] Does every handler wrap its work so no exception can reach the platform's default serialiser?
- [ ] Do client responses ever contain a stack trace, exception type, query text, ARN, or account id?
- [ ] Is API Gateway (or the Function URL layer) mapping internal errors to generic client messages?
- [ ] Are secrets and environment variables guaranteed to stay out of both error responses and logs?
- [ ] Is verbose/debug logging disabled in production?
- [ ] Do security-relevant error paths fail *closed* (deny) rather than fall through?
- [ ] On write/side-effect paths, do error paths clean up partial state, and are the effects idempotent for safe retries?
- [ ] Are error responses uniform enough that they cannot be used to enumerate valid records?
- [ ] Is every error caught, classified, and logged so the audit trail survives a failure?
- [ ] Are known error types handled explicitly, with a single generic fallback for the unexpected?

If you answered "no" or "not sure" to several of these, you likely have exploitable error-handling weaknesses today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers trigger errors to harvest internals and exploit fail-open behaviour
- **[Prevention](prevention.md)**: Build generic client errors, server-side logging, and fail-closed paths
- **[Examples](examples.md)**: Vulnerable vs. secure error handling in Lambda and API Gateway
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply these controls in hands-on exercises
