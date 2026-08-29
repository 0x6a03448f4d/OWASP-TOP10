# C4: Address Security from the Start - Examples

Each pair below shows an **insecure design** and the **secure design** that addresses the same feature. The difference is rarely a syntax fix—it is a decision made (or missed) about requirements, trust boundaries, and control placement. The final section shows the design *artifacts*—a threat-model snippet and an abuse case—that produce these decisions in the first place.

> **Read these for the design intent, not the syntax.** In every "insecure" example the code runs perfectly; what is missing is a control that should have been required during design.

## Example 1: Fund Transfer (Python / Flask)

### Insecure Design
The design trusted the client to send an honest amount and never required limits, ownership, or server-side validation.

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/transfer', methods=['POST'])
def transfer():
    data = request.get_json()
    # DESIGN GAPS:
    #  - 'from_account' comes from the client (no ownership check)
    #  - no rule that amount > 0 or amount <= balance
    #  - no idempotency: a double-submit transfers twice
    move_money(data['from_account'], data['to_account'], data['amount'])
    return jsonify({'status': 'ok'})

# Attacker: {"from_account":"any","to_account":"me","amount":-999999}
```

### Secure Design
The design derives the account from the session, enforces limits server-side, checks ownership, and makes the operation idempotent—all requirements written before coding.

```python
from flask import Flask, request, jsonify, g
from decimal import Decimal

app = Flask(__name__)

@app.route('/api/transfer', methods=['POST'])
@require_auth                       # authentication is a boundary requirement
def transfer():
    data = request.get_json()
    # Identity is derived server-side, never taken from the body:
    src = get_account_for_user(g.current_user)

    amount = Decimal(str(data.get('amount', '0')))
    to_account = data['to_account']
    idem_key = request.headers.get('Idempotency-Key')

    # Security requirements enforced as invariants:
    if amount <= 0 or amount > MAX_TRANSFER:
        return jsonify({'error': 'invalid amount'}), 400
    if amount > src.balance:
        return jsonify({'error': 'insufficient funds'}), 400
    if not owns(g.current_user, src):
        return jsonify({'error': 'forbidden'}), 403

    # Idempotency makes double-submit / concurrency safe by design:
    if already_processed(idem_key):
        return jsonify({'status': 'ok', 'replay': True})

    with transaction():             # atomic; no partial / race state
        move_money(src, to_account, amount)
        record(idem_key)
    audit_log('transfer', user=g.current_user, amount=amount)  # repudiation control
    return jsonify({'status': 'ok'})
```

## Example 2: Multi-Step Password Reset (Node.js / Express)

### Insecure Design
Each step is an independent endpoint with no enforced sequence, so the final step can be called directly.

```javascript
const express = require('express');
const app = express();
app.use(express.json());

// Step 1 (intended first): verify identity, send code
app.post('/reset/request', (req, res) => { sendCode(req.body.email); res.json({ok:true}); });

// Step 2 (intended last): set the new password
app.post('/reset/complete', (req, res) => {
    // DESIGN GAP: nothing proves step 1 happened for THIS user.
    // No token, no state -> attacker calls this directly.
    setPassword(req.body.email, req.body.newPassword);
    res.json({ ok: true });
});
// Attacker: POST /reset/complete {email: victim, newPassword: pwned}
```

### Secure Design
The flow is a server-side state machine: completing the reset requires a single-use, expiring token proving the earlier verified step.

```javascript
const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

// Step 1: issue a single-use, expiring, hashed token bound to the user
app.post('/reset/request', rateLimit, async (req, res) => {
    const user = await findUserByEmail(req.body.email);
    // Always respond the same way (no user enumeration):
    if (user) {
        const token = crypto.randomBytes(32).toString('hex');
        await storeResetToken({
            userId: user.id,
            tokenHash: sha256(token),
            expiresAt: Date.now() + 15 * 60 * 1000,
            used: false
        });
        await emailResetLink(user.email, token);
    }
    res.json({ ok: true });         // identical response either way
});

// Step 2: only reachable WITH a valid unused token -> sequence enforced
app.post('/reset/complete', rateLimit, async (req, res) => {
    const rec = await consumeResetToken(sha256(req.body.token)); // atomic single-use
    if (!rec || rec.used || rec.expiresAt < Date.now()) {
        return res.status(400).json({ error: 'invalid or expired token' });
    }
    await setPassword(rec.userId, req.body.newPassword); // strong-hash inside
    await revokeSessions(rec.userId);   // defense in depth
    res.json({ ok: true });
});
```

## Example 3: Object Update / Mass Assignment (Java / Spring Boot)

### Insecure Design
The design binds the raw request body straight onto the persistent entity, so any field—including privilege fields—is client-writable.

```java
@RestController
class UserController {

    // DESIGN GAP: the whole User entity is bound from the request.
    // A client can set isAdmin or balance simply by adding the field.
    @PutMapping("/api/users/{id}")
    public User update(@PathVariable Long id, @RequestBody User incoming) {
        incoming.setId(id);
        return userRepository.save(incoming);   // over-permissive binding
    }
}
// Attacker: PUT /api/users/42 {"displayName":"x","isAdmin":true}
```

### Secure Design
An explicit DTO defines exactly which fields are writable; authority is checked server-side; privilege fields are never bindable.

```java
// Explicit input model: ONLY the fields a user may change.
record UserUpdateDto(String displayName, String avatarUrl) {}

@RestController
class UserController {

    @PutMapping("/api/users/{id}")
    public UserView update(@PathVariable Long id,
                           @Valid @RequestBody UserUpdateDto dto,
                           @AuthenticationPrincipal AppUser caller) {

        // Authorization: you may only edit your own record (deny by default).
        if (!caller.getId().equals(id)) {
            throw new AccessDeniedException("forbidden");
        }
        User user = userRepository.findById(id).orElseThrow();

        // Map ONLY the allow-listed fields. isAdmin/balance are unreachable.
        user.setDisplayName(dto.displayName());
        user.setAvatarUrl(dto.avatarUrl());

        return UserView.of(userRepository.save(user)); // view hides internals
    }
}
```

## Design Artifacts That Produce These Decisions

The secure versions above did not appear during coding—they were decided earlier, in artifacts like these. This is what "addressing security from the start" looks like on paper.

### Artifact A: Threat-Model Snippet (Fund Transfer)

A data-flow sketch with a trust boundary, then STRIDE prompts and the control each threat drives.

```
DATA-FLOW (transfer feature)

  [Browser]  --request-->  || TRUST BOUNDARY ||  --> [Transfer API] --> [Ledger DB]
  (untrusted client)                                 (authn/authz here)

STRIDE analysis at the boundary:

  Threat (STRIDE)        Scenario                          Control (design decision)
  --------------------   -------------------------------   -----------------------------
  Spoofing               Caller forges another account     Derive account from session,
                                                            not from request body
  Tampering              Negative / oversized amount        Server-side invariant:
                                                            0 < amount <= min(balance, MAX)
  Repudiation            User denies making a transfer      Append-only audit log
  Info disclosure        Error leaks balances/accounts      Generic error messages
  Denial of service      Scripted flood of transfers        Rate limit per user + per IP
  Elevation of privilege Move money from others' accounts   Ownership check (owns(user,acct))

Concurrency note: double-submit could transfer twice
  -> DECISION: require Idempotency-Key + atomic transaction.
```

### Artifact B: Abuse Case (as a testable requirement)

An abuse case names the attacker goal, the mitigating control, and the test that proves it—so design intent becomes an executable check.

```
ABUSE CASE  AC-TRANSFER-01
  Actor:      Authenticated user acting maliciously
  Goal:       Transfer funds out of an account they do not own,
              or in an invalid (negative / over-limit) amount.

  Preconditions the attacker relies on:
    - Server trusts 'from_account' from the request body   [MUST NOT]
    - No amount bounds are enforced server-side            [MUST NOT]

  Mitigating security requirements:
    SR-1  Account MUST be derived from the authenticated session.
    SR-2  0 < amount <= min(balance, MAX_TRANSFER), enforced server-side.
    SR-3  Operation MUST be idempotent (Idempotency-Key), safe under concurrency.
    SR-4  All transfers MUST be written to an append-only audit log.

  Acceptance tests (must pass before ship):
    T-1  Request with body 'from_account' != caller's account -> 403.
    T-2  amount <= 0 OR amount > balance OR amount > MAX -> 400.
    T-3  Same Idempotency-Key twice -> money moves exactly once.
    T-4  Every successful transfer produces one audit record.
```

## What Changed, and Why

| Design decision | Insecure Design | Secure Design (C4) |
|-----------------|-----------------|--------------------|
| Identity source | Taken from the request body | Derived from the authenticated session |
| Business rules | Assumed / client-side only | Server-side invariants (limits, ownership) |
| Workflow order | Steps callable in any order | Server-side state machine, single-use tokens |
| Data binding | Whole entity bound from request | Explicit DTO / allow-listed fields |
| Concurrency | Unconsidered (double-submit) | Idempotency + atomic transaction |
| Where decided | Discovered in production | Threat model & abuse cases, up front |

## Key Takeaways

1. **The insecure code often runs perfectly**—the flaw is a missing requirement, not a typo.
2. **Derive security-relevant state server-side**—never let the client assert identity, price, or role.
3. **Enforce sequence and limits on the server**—model workflows as state machines with real invariants.
4. **Bind only allow-listed fields**—explicit DTOs stop mass assignment by design.
5. **The artifacts come first**—a threat-model snippet and abuse cases are what turn secure intent into testable requirements.

## Next Steps

- **[How to Implement](prevention.md)**: The full SDLC, threat-modeling, and design-pattern workflow
- **[Threats Addressed](attack-vectors.md)**: The design flaws these examples prevent
- **[Proactive Controls](/learn/proactive)**: Explore the full set of OWASP Proactive Controls
- **[Practice](/practice)**: Apply secure design thinking to hands-on scenarios
