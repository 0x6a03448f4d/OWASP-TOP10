# Mishandling of Exceptional Conditions - Examples

## Table of Contents
- [Java — Fail-Open vs. Fail-Closed Authorization](#java--fail-open-vs-fail-closed-authorization)
- [Python — Verbose Errors & Leaked Resources](#python--verbose-errors--leaked-resources)
- [Node.js — Swallowed Async Errors & Enumeration Oracle](#nodejs--swallowed-async-errors--enumeration-oracle)
- [Go — Ignored Errors & Missing Cleanup](#go--ignored-errors--missing-cleanup)
- [What Changed, and Why](#what-changed-and-why)

Each pair below shows a **vulnerable** implementation and the **secure** version in the same language. The themes are the ones that dominate real error-path findings: failing open, leaking internals, swallowing exceptions, building oracles, and leaking resources.

## Java — Fail-Open vs. Fail-Closed Authorization

### Vulnerable
```java
@GetMapping("/admin/report")
public ResponseEntity<Report> adminReport(Principal principal) {
    boolean isAdmin;
    try {
        isAdmin = roleService.hasRole(principal.getName(), "ADMIN");
    } catch (Exception e) {
        // "Be resilient if the role service is down."
        isAdmin = true;               // FAIL-OPEN: an error grants admin
    }
    if (isAdmin) {
        return ResponseEntity.ok(reportService.build());
    }
    return ResponseEntity.status(403).build();
}
```
An attacker who can make `roleService.hasRole` throw — by exhausting its connection pool or feeding input that trips a downstream error — is handed the admin report. The exception is caught, but the recovery decision is backwards.

### Secure
```java
private static final Logger log = LoggerFactory.getLogger(AdminController.class);

@GetMapping("/admin/report")
public ResponseEntity<?> adminReport(Principal principal) {
    boolean isAdmin;
    try {
        isAdmin = roleService.hasRole(principal.getName(), "ADMIN");
    } catch (Exception e) {
        String id = UUID.randomUUID().toString();
        log.error("role check failed, denying by default id={}", id, e);
        // FAIL-CLOSED: cannot verify -> deny, and return a generic error
        return ResponseEntity.status(503)
            .body(Map.of("error", "Service temporarily unavailable", "errorId", id));
    }
    if (!isAdmin) {
        return ResponseEntity.status(403).build();
    }
    return ResponseEntity.ok(reportService.build());
}
```
The allow branch is reachable only on an explicit successful `true`. Any error denies, logs full detail under an ID, and returns a generic message.

## Python — Verbose Errors & Leaked Resources

### Vulnerable
```python
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["DEBUG"] = True            # tracebacks rendered to the client

@app.route("/orders")
def orders():
    conn = pool.getconn()             # acquire connection
    cur = conn.cursor()
    # user-controlled input straight into a query; may raise
    cur.execute("SELECT * FROM orders WHERE id = " + request.args["id"])
    rows = cur.fetchall()
    conn.close()                      # NEVER reached if execute() raises
    return jsonify(rows)
# On error: full stack trace + SQL + DSN returned, and the connection leaks.
```

### Secure
```python
import logging, uuid
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["DEBUG"] = False           # no tracebacks to clients
log = logging.getLogger("app")

@app.route("/orders")
def orders():
    order_id = request.args.get("id", "")
    if not order_id.isdigit():                     # validate the edge case
        return jsonify(error="Invalid order id"), 400
    # context managers release the connection AND the cursor on every path
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
        return jsonify(cur.fetchall())

@app.errorhandler(Exception)
def on_error(e):
    error_id = uuid.uuid4().hex
    log.exception("error_id=%s", error_id)         # full detail -> logs only
    return jsonify(error="Internal server error", error_id=error_id), 500
```
Parameterised query, validated input, guaranteed cleanup via `with`, generic client message, and full detail confined to server logs behind an error ID.

## Node.js — Swallowed Async Errors & Enumeration Oracle

### Vulnerable
```javascript
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await db.findByEmail(email);
    if (!user) {
        // Distinct message + fast return = user-enumeration oracle
        return res.status(404).json({ error: 'No account with that email' });
    }
    try {
        const ok = await bcrypt.compare(password, user.hash);  // only for real users
        if (!ok) return res.status(401).json({ error: 'Wrong password' });
        return res.json({ token: issue(user) });
    } catch (e) {
        // swallowed — a bcrypt/internal error silently falls through
    }
    res.json({ token: issue(user) });   // FAIL-OPEN on the swallowed error
});
```
Two flaws compound: the response reveals whether an account exists (in both text and timing), and the empty `catch` lets a comparison error fall through to issuing a token.

### Secure
```javascript
const DUMMY_HASH = '$2b$12$'.padEnd(60, 'x');   // constant-work placeholder

app.post('/login', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const user = await db.findByEmail(email);
        // Always run a comparison so timing does not leak existence
        const hash = user ? user.hash : DUMMY_HASH;
        const ok = await bcrypt.compare(password, hash);
        if (!user || !ok) {
            // Identical status + body for every failure reason
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        return res.json({ token: issue(user) });
    } catch (err) {
        next(err);                      // to the central handler — never swallow
    }
});

// Central handler: generic body, detail to logs
app.use((err, req, res, next) => {
    const errorId = crypto.randomUUID();
    logger.error({ errorId, err });
    res.status(500).json({ error: 'Internal server error', errorId });
});
```
Uniform response and timing remove the oracle; errors propagate to one handler instead of being swallowed into a fail-open path.

## Go — Ignored Errors & Missing Cleanup

### Vulnerable
```go
func Transfer(db *sql.DB, from, to string, amount int) {
    tx, _ := db.Begin()                        // error ignored
    tx.Exec("UPDATE acct SET bal = bal - ? WHERE id = ?", amount, from)
    tx.Exec("UPDATE acct SET bal = bal + ? WHERE id = ?", amount, to)
    tx.Commit()                                // if step 2 failed, we still commit
    // No error checks: a mid-transaction failure leaves inconsistent balances,
    // and a failed Begin() leads to a nil-deref panic that crashes the worker.
}
```

### Secure
```go
func Transfer(ctx context.Context, db *sql.DB, from, to string, amount int) error {
    tx, err := db.BeginTx(ctx, nil)
    if err != nil {
        return fmt.Errorf("begin: %w", err)    // check every error
    }
    defer tx.Rollback()                        // guaranteed cleanup; no-op after Commit

    if _, err := tx.ExecContext(ctx,
        "UPDATE acct SET bal = bal - ? WHERE id = ? AND bal >= ?",
        amount, from, amount); err != nil {
        return fmt.Errorf("debit: %w", err)    // deferred Rollback runs
    }
    if _, err := tx.ExecContext(ctx,
        "UPDATE acct SET bal = bal + ? WHERE id = ?", amount, to); err != nil {
        return fmt.Errorf("credit: %w", err)   // deferred Rollback runs
    }
    return tx.Commit()                         // atomic: both steps or neither
}
```
Every error is checked and wrapped, `defer tx.Rollback()` guarantees the transaction is never left half-committed, and the operation is atomic under failure.

## What Changed, and Why

| Weakness | Vulnerable | Secure |
|----------|------------|--------|
| Fail-open control | Exception in role check grants admin | Error denies by default (fail closed) |
| Verbose errors | Debug on; trace, SQL, DSN to client | Generic message + error ID; detail to logs |
| Resource leak | Connection closed only on success | Context manager / `defer` releases on every path |
| Enumeration oracle | Different body/timing for unknown user | Uniform response + constant-work comparison |
| Swallowed exception | Empty catch falls through to allow | Propagate to one central handler |
| Half-committed state | Commit regardless of step failures | Atomic transaction with guaranteed rollback |
| Ignored errors | `_` discards error; later panic | Every error checked, wrapped, and returned |

## Next Steps
- **[Overview](./overview.html)**: Why exceptional-condition handling is a security concern
- **[Attack Vectors](./attack-vectors.html)**: How attackers exploit the error path
- **[Prevention](./prevention.html)**: The full layered defensive strategy
- **[Hands-On Lab](./lab/mishandling-exceptional-conditions/)**: Practice fixing these patterns in a safe environment
