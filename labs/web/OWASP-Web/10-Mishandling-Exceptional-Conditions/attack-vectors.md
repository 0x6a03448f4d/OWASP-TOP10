# Mishandling of Exceptional Conditions - Attack Vectors

## Table of Contents
- [Understanding the Attack Surface](#understanding-the-attack-surface)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Exceptional Conditions](#chaining-exceptional-conditions)

## Understanding the Attack Surface

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these weaknesses in systems you own or are authorised to test.

Attacks in this category share one strategy: **push the application off the happy path and see what happens.** The exceptional path is under-tested and under-instrumented, so the attacker's job is to *manufacture* an exceptional condition — a malformed input, an exhausted resource, a timed-out dependency, a pathological payload — and then read the security-relevant consequence: a skipped control, a leaked internal, a distinguishable signal, or a downed service.

The attacker's goals in this category are usually one of:
- Bypass a control by making it throw (fail-open).
- Extract internals from error output (disclosure).
- Build an oracle from inconsistent responses or timing (enumeration, padding oracle, blind injection).
- Exhaust or crash the system (denial of service).
- Corrupt state by interrupting an operation midway (partial failure).

### Core Attack Flow

```
1. Probe
   |
   Send malformed / oversized / unexpected / boundary input
2. Observe
   |
   Read status codes, error bodies, response timing, side effects
3. Trigger
   |
   Force a dependency to fail, a resource to exhaust, a check to throw
4. Exploit
   |
   Bypass the skipped control, decrypt via the oracle, or crash the service
```

## Common Attack Patterns

### 1. Fail-Open Authentication / Authorization

The attacker forces the security decision to throw, and the surrounding code treats the error as "allow."

```java
// Vulnerable server logic
try {
    if (!authz.canAccess(user, doc)) return deny();
} catch (Exception e) {
    // "be resilient" — but this permits on error
}
return serve(doc);

// Attack: exhaust the DB connection pool so canAccess() throws
for i in 1..500: open_slow_request()   // saturate pool
GET /doc/secret                        // now canAccess throws -> served
```

**Payoff**: authorization bypass with no credential attack. Any lever that makes the check fail — pool exhaustion, cache poisoning, a downstream 500, a malformed token that trips a parser — becomes an access-control bypass.

### 2. Verbose Error / Stack-Trace Leakage

An unexpected input triggers an unhandled exception, and the framework returns the full trace.

```
GET /api/orders?id=' HTTP/1.1

HTTP/1.1 500 Internal Server Error
{
  "exception": "psycopg2.ProgrammingError: syntax error at or near \"'\"",
  "traceback": "File \"/srv/app/orders.py\", line 88, in get_order\n    cur.execute(sql)",
  "sql": "SELECT * FROM orders WHERE id=''",
  "dsn": "postgres://app:S3cr3t@db.internal:5432/prod"
}
```

**Payoff**: source paths, ORM/engine, table names, internal hostnames, and sometimes live credentials — all volunteered by the error handler.

### 3. Account Enumeration via Inconsistent Responses

The login or reset flow answers "unknown user" differently from "wrong password."

```
POST /login  {"user":"alice@corp.com","pass":"x"}
-> 200 {"error":"Incorrect password"}          # user EXISTS

POST /login  {"user":"ghost@corp.com","pass":"x"}
-> 404 {"error":"No account with that email"}  # user does NOT exist
```

**Payoff**: a clean valid/invalid oracle. The attacker sprays an email list and keeps every address that returns the "exists" branch, then targets those with phishing or credential stuffing. Status code, body text, redirect target, and even a set-cookie difference all leak the answer.

### 4. Timing Oracle on the Error Path

Even when the body is identical, the code path length differs.

```python
# Vulnerable: password hash only computed when the user exists
user = db.find(email)
if not user:
    return generic_error()          # returns fast — NO hashing
if not bcrypt.check(pw, user.hash): # slow — only for real users
    return generic_error()
```

```
# Attacker measures response time
existing@corp.com  -> ~250 ms  (bcrypt ran)
ghost@corp.com     -> ~4 ms    (returned before hashing)
```

**Payoff**: a timing side channel enumerates users despite an identical error message. The same shape appears in token comparison, coupon validation, and API-key checks.

### 5. Padding / Cryptographic Error Oracle

Decryption returns a distinguishable error for "bad padding" versus "bad MAC."

```
POST /decrypt  (ciphertext with tampered last block)
-> 500 "Padding is invalid and cannot be removed"   # padding oracle!

POST /decrypt  (ciphertext with valid padding, bad MAC)
-> 400 "Authentication failed"
```

**Payoff**: the two distinguishable errors let an attacker decrypt ciphertext byte-by-byte without the key (the classic padding-oracle attack; POODLE and Lucky Thirteen are variants). The fix is uniform, constant-time handling of every decryption failure.

### 6. Error-Based Blind Injection

When results are not returned, the *presence or absence of an error* becomes the boolean channel.

```
id=1 AND 1=CAST((SELECT substr(pw,1,1) FROM users LIMIT 1) AS int)
-> 500  (cast error) when the guessed char is non-numeric  = TRUE branch
-> 200  when it matches                                     = FALSE branch
```

**Payoff**: the differing error behaviour reconstructs data one bit at a time. Suppressing distinct error responses removes the channel.

### 7. Unhandled Exception Crash (Denial of Service)

A crafted input reaches a code path with no handler and terminates the worker.

```
POST /api/profile   {"age": "not-a-number"}
# Server: int(payload["age"])  -> ValueError -> uncaught -> worker dies

# Repeat to keep every worker cycling through crash/restart:
while true: curl -d '{"age":"x"}' https://target/api/profile
```

**Payoff**: repeated malformed requests keep workers crashing and restarting, denying service to legitimate users at trivial cost.

### 8. Catastrophic Backtracking (ReDoS)

A vulnerable regular expression meets an input engineered to explode its runtime.

```
# Vulnerable pattern with nested quantifiers
EMAIL = /^([a-zA-Z0-9]+)*@/

# Attack input — each added 'a' roughly doubles the work
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" @ ...  -> seconds/minutes of 100% CPU
```

**Payoff**: one request pins a CPU core; a handful pin the fleet (the Cloudflare 2019 outage class). Bound input length and use linear-time regex engines or vetted patterns.

### 9. Resource Leak on the Error Path

An exception is thrown after a resource is acquired but before it is released.

```python
# Vulnerable — conn never returned if the query throws
conn = pool.acquire()
rows = conn.execute(user_supplied_query)   # throws on bad input
conn.release()                             # never reached

# Attack: send inputs that throw, repeatedly
for i in 1..pool_size: trigger_query_error()   # pool now empty -> outage
```

**Payoff**: each error leaks a connection (or file handle, or lock) until the pool is exhausted and the whole service stalls — a slow-motion denial of service driven entirely by the error path.

### 10. Swallowed Exception Hiding an Attack

An empty or over-broad `catch` discards the error and lets the program continue.

```java
try {
    validateSignature(request);   // throws on tampering
} catch (Exception e) {
    // swallowed — no log, no rethrow
}
process(request);                 // proceeds with an UNVERIFIED request
```

**Payoff**: signature/integrity failures are silently ignored, so tampered requests are processed and no alert is ever raised. The attack leaves no trace precisely because the exception was swallowed.

### 11. TOCTOU / Race in Error & Retry Handling

Recovery, retry, and fallback logic opens a window between check and use.

```
# Vulnerable: on failure, retry against a fallback that re-reads state
balance = read_balance(acct)          # check
if primary_debit(acct, amount) fails:
    fallback_debit(acct, amount)      # re-reads balance -> double spend
                                      # under concurrent requests
```

**Payoff**: concurrent requests exploit the retry/fallback window to bypass a limit or double-spend, because the error-recovery path re-checks state that another request has already changed.

### 12. Half-Committed Transaction / Inconsistent State

A multi-step operation fails midway with no rollback.

```
# Vulnerable: no transaction around a two-step operation
deduct_credits(user, 10)     # step 1 succeeds
grant_entitlement(user, x)   # step 2 throws (network blip)
# Result: credits gone, entitlement not granted — OR the reverse,
# depending on ordering. Attacker triggers the blip deliberately.
```

**Payoff**: an attacker who reliably interrupts step 2 can obtain the entitlement while avoiding the charge (or corrupt records at will). Atomic transactions with rollback close this.

### 13. Unexpected Input Size / Type / Encoding

Inputs the parser did not anticipate trip overflows, type confusion, or resource blowups.

```
- 500 MB JSON body            -> memory exhaustion (no size limit)
- deeply nested JSON/XML      -> stack overflow / billion-laughs expansion
- highly compressible upload  -> decompression bomb (zip/gzip)
- {"amount": []} where a number is expected -> type-confusion / crash
- overlong UTF-8 / mixed encoding -> validation bypass, parser error
```

**Payoff**: memory/CPU exhaustion, crashes, or a validation bypass — all from an input whose *shape*, not content, was never bounded.

### 14. Insecure Fallback on Error

When the secure path errors, the code quietly falls back to an insecure one.

```python
# Vulnerable: TLS verification fails, so retry without it
try:
    resp = get(url, verify=True)
except SSLError:
    resp = get(url, verify=False)   # downgraded — MITM now trivial
```

**Payoff**: the attacker *causes* the secure attempt to fail (a forged cert error, a blocked port) to trigger the insecure fallback — downgrading TLS, dropping a signature check, or reverting to a default credential.

## Chaining Exceptional Conditions

Individually minor error-path issues combine into full compromise:

```
Verbose error leaks DB host + table names   -> map the schema
        +
Error-based blind injection oracle          -> extract the admin hash
        +
Timing oracle on login                      -> confirm the admin username
        =  account takeover, no single "big" bug required
```

Another common chain:

```
Malformed input crashes a worker            -> forces failover
        +
Failover path fails open on authz           -> requests served unchecked
        +
Swallowed exception suppresses the alert    -> nobody notices for hours
```

## Key Takeaways
1. **Attackers manufacture exceptions on purpose** — the error path is the target, not an accident.
2. **Any distinguishable failure is an oracle** — body, status, headers, or timing all leak.
3. **Fail-open controls are bypassed by making them throw** — resource exhaustion is a common lever.
4. **Leaked resources and unhandled inputs are cheap denial of service** — one request can pin a core or drain a pool.
5. **Swallowed exceptions hide the attack** — silence on the error path is an attacker's friend.

## Next Steps
- **[Prevention Guide](./prevention.html)**: Fail securely and handle errors safely across every layer
- **[Code Examples](./examples.html)**: Vulnerable vs. secure handling in four languages
- **[Hands-On Lab](./lab/mishandling-exceptional-conditions/)**: Practice triggering and fixing these weaknesses
