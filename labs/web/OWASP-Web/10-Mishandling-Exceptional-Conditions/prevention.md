# Mishandling of Exceptional Conditions - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [1. Fail Securely (Fail Closed)](#1-fail-securely-fail-closed)
- [2. Centralized, Consistent Error Handling](#2-centralized-consistent-error-handling)
- [3. Generic Messages Out, Full Detail to Logs](#3-generic-messages-out-full-detail-to-logs)
- [4. Deterministic Resource Cleanup](#4-deterministic-resource-cleanup)
- [5. Catch at the Right Boundary — Never Swallow](#5-catch-at-the-right-boundary--never-swallow)
- [6. Eliminate Error & Timing Oracles](#6-eliminate-error--timing-oracles)
- [7. Validate Edge Cases: Size, Type, Encoding](#7-validate-edge-cases-size-type-encoding)
- [8. Graceful Degradation, Timeouts, Circuit Breakers](#8-graceful-degradation-timeouts-circuit-breakers)
- [9. Production Hardening](#9-production-hardening)
- [10. Test the Error Path](#10-test-the-error-path)
- [Prevention Checklist](#prevention-checklist)

## Prevention Strategy Overview

Preventing this class is about one discipline: **treating the error path as a first-class, security-relevant part of the design**, not an afterthought bolted on when a bug appears. The layered strategy below moves from the single most important rule (fail closed) outward to consistency, cleanup, oracles, input, resilience, and testing.

### Core Principles
- **Fail closed**: when a security-relevant operation cannot complete, deny.
- **Fail consistently**: identical responses and timing for every failure of the same kind, so nothing leaks.
- **Fail cleanly**: release every resource and roll back every transaction, always.
- **Fail loudly to logs, quietly to clients**: full detail server-side behind an error ID; a generic message to the user.
- **Fail deliberately**: catch narrowly at a known boundary and decide what to do — never swallow.

## 1. Fail Securely (Fail Closed)

The default answer to any security question that cannot be computed must be "no." Structure security decisions so that the *only* way to reach the "allow" branch is an explicit, successful positive result.

```java
// Java — FAIL CLOSED: default deny, allow only on explicit success
public boolean canAccess(User user, Document doc) {
    try {
        return authzService.check(user, doc);   // true only on success
    } catch (Exception e) {
        log.error("authz check failed, denying by default", e);
        return false;                            // error == DENY
    }
}
```

```python
# Python — the allow path requires a positive result; everything else denies
def is_authorized(user, resource) -> bool:
    try:
        decision = authz.check(user, resource)
    except Exception:
        logger.exception("authz error; denying")
        return False                # fail closed
    return decision is True         # only an explicit True allows
```

> **Availability vs. security**: if failing closed would take down critical functionality, degrade to a *safe* reduced mode (for example read-only, or a restricted feature set) — never to "allow everyone." Make that degraded mode an explicit, reviewed decision, not an accidental side effect of a `catch` block.

## 2. Centralized, Consistent Error Handling

Scattered `try/catch` blocks drift apart and each becomes a chance to leak or to fail open. Funnel errors through **one handler per boundary** so behaviour is uniform and reviewable in a single place.

```javascript
// Express (Node.js) — one central error handler, mounted last
app.get('/api/me', async (req, res, next) => {
    try {
        res.json(await loadUser(req.userId));
    } catch (err) {
        next(err);                 // hand off to the central handler
    }
});

// Central handler: generic body out, full detail to logs
app.use((err, req, res, next) => {
    const errorId = crypto.randomUUID();
    logger.error({ errorId, err });           // server-side only
    res.status(err.status || 500)
       .json({ error: 'Internal server error', errorId });
});
```

```java
// Spring Boot (Java) — @ControllerAdvice centralizes every controller's errors
@ControllerAdvice
class ApiErrorHandler {
    private static final Logger log = LoggerFactory.getLogger(ApiErrorHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String,String>> handle(Exception e) {
        String id = UUID.randomUUID().toString();
        log.error("error id={}", id, e);       // detail to logs
        return ResponseEntity.status(500)
            .body(Map.of("error", "Internal server error", "errorId", id));
    }
}
```

Also register a **last-resort handler** for the truly unexpected, so an uncaught error becomes a clean 500 instead of a crash or a leaked trace:

```javascript
// Node.js — do not let unhandled rejections silently kill or corrupt state
process.on('unhandledRejection', (reason) => {
    logger.error({ msg: 'unhandled rejection', reason });
    // log, alert, and shut down gracefully if state may be corrupt
});
```

## 3. Generic Messages Out, Full Detail to Logs

The client gets a generic message plus a correlation ID; the server logs the full context. Support can still trace any incident by its ID without ever exposing internals to an attacker.

```json
{
  "error": "Something went wrong. Please try again.",
  "errorId": "b1f3c9e2-7a4d-4b0a-9c2e-1f5a7d8e0c33"
}
```
Stack trace, SQL, hostnames, and secrets go to the log ONLY, keyed by the same errorId.

```python
# Python (Flask) — one place decides what the client sees
@app.errorhandler(Exception)
def on_error(e):
    error_id = uuid.uuid4().hex
    app.logger.exception("error_id=%s", error_id)   # full trace to logs
    return jsonify(error="Internal server error", error_id=error_id), 500
```

Never rely on "debug mode off" alone to hide traces — make the generic response the explicit, tested behaviour.

## 4. Deterministic Resource Cleanup

Every resource acquired must be released on *every* path, including the exception path. Use the language's guaranteed-cleanup construct rather than manual release.

```python
# Python — context managers release even when the body raises
with pool.connection() as conn:          # released on normal exit AND on error
    with conn.transaction():             # commits on success, ROLLS BACK on error
        conn.execute(query, params)
```

```java
// Java — try-with-resources closes in reverse order, even on exception
try (Connection conn = pool.getConnection();
     PreparedStatement ps = conn.prepareStatement(SQL)) {
    ps.setString(1, id);
    return ps.executeQuery();
}   // conn and ps are closed automatically, success or failure
```

```go
// Go — defer guarantees release; roll back unless we reach commit
tx, err := db.Begin()
if err != nil { return err }
defer tx.Rollback()                // no-op if Commit already ran
if _, err := tx.Exec(q, id); err != nil {
    return err                     // deferred Rollback runs
}
return tx.Commit()
```

```cpp
// C++ / RAII — the lock is released when the guard leaves scope, even on throw
{
    std::lock_guard<std::mutex> guard(mtx);
    doWork();                      // if this throws, guard still unlocks
}
```

**Rule**: never release a resource in a plain sequential statement after the work — an exception in the work skips it. Always use `try/finally`, context managers, `defer`, or RAII.

## 5. Catch at the Right Boundary — Never Swallow

Catch **specific** exceptions where you can actually do something about them. A caught exception must be handled, translated, or re-thrown — never discarded.

```java
// BAD — swallows everything, hides attacks and bugs
try { validateSignature(req); }
catch (Exception e) { /* nothing */ }

// GOOD — specific, logged, and the failure stops the request
try {
    validateSignature(req);
} catch (SignatureException e) {
    log.warn("signature validation failed for {}", req.id(), e);
    throw new AuthenticationException("invalid signature");  // fail closed
}
```

- **Catch narrow, not broad**: catching `Exception`/`Throwable` at random points hides real problems.
- **Never leave a catch block empty**. If an error is truly ignorable, log why, with a comment explaining the reasoning.
- **Preserve the cause** when re-throwing, so the log chain stays intact.
- **Do not catch what you cannot handle** — let it propagate to the central boundary handler.

## 6. Eliminate Error & Timing Oracles

Make failures indistinguishable. For authentication, return the *same* response for every failure reason, and keep the timing uniform.

```python
# Python — uniform response AND uniform timing for login
def login(email, password):
    user = db.find(email)
    # Always run a hash comparison, even when the user is absent,
    # so timing does not reveal existence.
    stored = user.hash if user else DUMMY_HASH
    ok = bcrypt.checkpw(password, stored)
    if user and ok:
        return issue_session(user)
    return generic_login_error()      # identical body + status for all failures
```

```go
// Go — constant-time comparison for tokens/keys, never ==
import "crypto/subtle"
valid := subtle.ConstantTimeCompare(provided, expected) == 1
```

For cryptography, treat every decryption failure identically — do not distinguish "bad padding" from "bad MAC," and prefer authenticated encryption (AES-GCM, ChaCha20-Poly1305) so a single verification step replaces the two-outcome path that creates padding oracles. For blind-injection oracles, ensure malformed input produces the *same* generic error as any other failure.

## 7. Validate Edge Cases: Size, Type, Encoding

Bound the *shape* of input before it reaches parsers and regexes, so exotic inputs cannot exhaust resources or trip overflows.

```javascript
// Express — cap body size so oversized payloads are rejected, not buffered
app.use(express.json({ limit: '100kb' }));
```

```python
# Reject deeply nested / oversized structured input; guard decompression
MAX_DEPTH = 32
MAX_DECOMPRESSED = 10 * 1024 * 1024     # 10 MB cap defeats zip bombs
# Validate type explicitly — reject {"amount": []} where a number is required
if not isinstance(payload.get("amount"), (int, float)):
    raise ValidationError("amount must be numeric")
```

```python
# Avoid catastrophic backtracking (ReDoS)
#  - bound input length BEFORE matching
#  - avoid nested quantifiers like (a+)+
#  - prefer a linear-time engine (RE2) or a vetted, anchored pattern
if len(value) > 254:
    raise ValidationError("too long")
EMAIL = re2.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
```

Validate against an allow-list of expected types, lengths, ranges, and encodings. Normalise encoding once, early, and reject anything that does not round-trip cleanly.

## 8. Graceful Degradation, Timeouts, Circuit Breakers

In distributed systems, dependencies fail constantly. Bound every remote call and contain failures so one fault does not cascade.

- **Timeouts** on every network call — an unbounded call is an unbounded outage waiting to happen.
- **Bounded retries with backoff and jitter** — naive retries create retry storms that amplify an outage.
- **Circuit breakers** — stop calling a failing dependency, return a safe fallback, and give it time to recover.
- **Bulkheads** — isolate resource pools so one slow dependency cannot drain the threads others need.
- **Dead-letter queues** — route poison messages aside instead of reprocessing them forever.

```go
// Go — every outbound call gets a deadline
ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
defer cancel()
resp, err := client.Do(req.WithContext(ctx))
if err != nil {
    return cachedFallback()        // degrade safely, do not hang or fail open
}
```

```python
# Circuit-breaker sketch — trip after repeated failures, fall back safely
if breaker.state == OPEN:
    return safe_default()          # do not hammer the failing dependency
try:
    result = call_dependency()
    breaker.record_success()
    return result
except DependencyError:
    breaker.record_failure()
    return safe_default()
```

The security point: a fallback must itself be safe. Degrading to "serve stale read-only data" is fine; degrading to "skip the authorization check" is a fail-open bug.

## 9. Production Hardening

- **Debug mode off** in every production service — no interactive debugger, no auto-rendered traces.
- **Custom error pages** for 4xx/5xx that never reveal internals.
- **Strip framework/version banners** so errors do not fingerprint the stack.
- **Scrub logs** — full detail is fine server-side, but keep secrets and full card/credential values out of logs too.
- **Alert on error-rate spikes** — a surge of 500s or auth errors is often an attack in progress.

```python
# Django — production settings
DEBUG = False
ALLOWED_HOSTS = ["app.example.com"]
# 500 handler renders a static page; the traceback goes to logging/Sentry only
```

## 10. Test the Error Path

The error path is under-tested by default, so test it on purpose:
- **Negative and boundary tests**: malformed input, wrong types, empty and oversized values, unexpected encodings.
- **Fault injection / chaos**: force dependencies to time out, error, and return garbage, and assert the app fails *closed* and cleans up.
- **Fuzzing**: throw random and malformed inputs at parsers and endpoints to surface uncaught exceptions.
- **Oracle checks**: assert that login/reset responses and timings are indistinguishable for valid vs invalid accounts.
- **Resource-leak tests**: run error-triggering inputs in a loop and assert pools/handles return to baseline.

```python
# Example assertion: a failing authz dependency must DENY, not allow
def test_authz_fails_closed(monkeypatch):
    monkeypatch.setattr(authz, "check", raises(TimeoutError))
    assert is_authorized(user, resource) is False   # fail closed
```

## Prevention Checklist

| Area | Control |
|------|---------|
| Fail closed | Security decisions default to deny on any error or timeout |
| Centralization | One error handler per boundary; a last-resort handler for the unexpected |
| Disclosure | Generic message + error ID to clients; full detail to logs only |
| Cleanup | try/finally, context managers, defer, RAII on every path |
| Transactions | Atomic with rollback; no half-committed state |
| No swallowing | No empty catch blocks; catch specific, handle or rethrow |
| No oracles | Uniform responses and timing; constant-time comparisons |
| Input edges | Bound size, type, depth, encoding; ReDoS-safe regexes |
| Resilience | Timeouts, bounded retries, circuit breakers, safe fallbacks |
| Production | Debug off, banners stripped, error-rate alerting |
| Testing | Negative, fault-injection, fuzz, oracle, and leak tests |

## Next Steps
- **[Code Examples](./examples.html)**: Vulnerable vs. secure implementations in Java, Python, Node.js, and Go
- **[Attack Vectors](./attack-vectors.html)**: How these weaknesses are exploited
- **[Hands-On Lab](./lab/mishandling-exceptional-conditions/)**: Practice failing securely and cleaning up on the error path
