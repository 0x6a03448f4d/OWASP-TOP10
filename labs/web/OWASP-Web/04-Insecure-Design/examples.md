# A04:2021 – Insecure Design - Examples

Each example contrasts a **vulnerable design** with a **secure design**. The point is not to fix a typo — the vulnerable code often works perfectly and passes its functional tests. The flaw is in what the design *assumes* and *omits*. Watch for the missing control in each pair.

## Table of Contents

- [Example 1: Trusting Client-Supplied Price (Python / Flask)](#ex1)
- [Example 2: Skippable Checkout Workflow (Node.js / Express)](#ex2)
- [Example 3: OTP With No Anti-Automation (Python)](#ex3)
- [Example 4: Check-Then-Act Race Condition (Java)](#ex4)
- [Example 5: Single-Use Coupon Abuse (Node.js)](#ex5)
- [Example 6: Weak Knowledge-Based Recovery (Python)](#ex6)
- [Example 7: Broken Tenant Segregation (Java)](#ex7)
- [Summary of Design Principles](#summary)
- [Next Steps](#next-steps)

## Example 1: Trusting Client-Supplied Price (Python / Flask)

**The design flaw:** The client tells the server what the item costs. Price is authoritative data that must live on the server.

**Vulnerable Design**
```python
@app.route('/checkout', methods=['POST'])
def checkout():
    data = request.get_json()
    # DESIGN FLAW: price and total come straight from the client.
    total = sum(item['price'] * item['qty'] for item in data['items'])
    charge_card(data['card_token'], total)
    return jsonify({'charged': total})

# Attacker POSTs {"items":[{"sku":"LAPTOP","price":1,"qty":1}], ...}
```

**Secure Design**
```python
@app.route('/checkout', methods=['POST'])
def checkout():
    data = request.get_json()
    total = Decimal('0')
    for item in data['items']:
        # Price is looked up server-side from the trusted catalog.
        product = Catalog.get_or_404(item['sku'])
        qty = int(item['qty'])
        if qty < 1 or qty > product.max_per_order:
            abort(400, 'invalid quantity')
        total += product.price * qty      # server computes the total

    if total <= 0:
        abort(400, 'invalid total')
    charge_card(data['card_token'], total)
    return jsonify({'charged': str(total)})
```

**Principle:** The client may say *what* it wants (SKU, quantity), never *what it costs*.

## Example 2: Skippable Checkout Workflow (Node.js / Express)

**The design flaw:** Each step is an independent endpoint that trusts the client to have completed the previous ones. The confirm step can be called directly without paying.

**Vulnerable Design**
```javascript
app.post('/checkout/payment', (req, res) => { chargeCard(req.body); res.sendStatus(200); });

app.post('/checkout/confirm', async (req, res) => {
  // DESIGN FLAW: assumes payment already happened. Never verifies it.
  const order = await Orders.create({ items: req.body.items, status: 'CONFIRMED' });
  res.json({ orderId: order.id });          // free order if payment skipped
});
```

**Secure Design**
```javascript
// Authoritative server-side state machine; transitions are validated.
const NEXT = { CREATED: 'SHIPPING_SET', SHIPPING_SET: 'PAID', PAID: 'CONFIRMED' };

app.post('/checkout/payment', async (req, res) => {
  const order = await Orders.get(req.body.orderId, req.user);
  if (order.status !== 'SHIPPING_SET') return res.status(409).json({ error: 'bad state' });
  await chargeCard(order.total, req.body.cardToken);   // server-known total
  await order.transitionTo('PAID');
  res.sendStatus(200);
});

app.post('/checkout/confirm', async (req, res) => {
  const order = await Orders.get(req.body.orderId, req.user);
  if (order.status !== 'PAID') return res.status(409).json({ error: 'payment required' });
  await order.transitionTo('CONFIRMED');
  res.json({ orderId: order.id });
});
```

**Principle:** Model workflows as a server-side state machine. Every transition asserts its legal predecessor.

## Example 3: OTP With No Anti-Automation (Python)

**The design flaw:** A 6-digit code with unlimited attempts and unlimited re-requests. The math guarantees it will be brute-forced.

**Vulnerable Design**
```python
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    expected = otp_store.get(data['user_id'])
    # DESIGN FLAW: no attempt cap, no lockout, no expiry check.
    if data['code'] == expected:
        return issue_session(data['user_id'])
    return jsonify({'error': 'invalid'}), 401
```

**Secure Design**
```python
MAX_ATTEMPTS = 5

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    uid = data['user_id']
    rec = otp_store.get(uid)

    if rec is None or rec.expires_at < now():
        abort(400, 'code expired, request a new one')          # short TTL
    if rec.attempts >= MAX_ATTEMPTS:
        otp_store.invalidate(uid)                              # lock out
        abort(429, 'too many attempts; code invalidated')

    rec.attempts += 1
    otp_store.save(rec)
    if hmac.compare_digest(str(data['code']), str(rec.code)):  # constant-time
        otp_store.invalidate(uid)                             # one-time use
        return issue_session(uid)
    return jsonify({'error': 'invalid'}), 401
```

**Principle:** A small secret space must be paired with strict rate limiting, short TTL, an attempt cap, and single use — all designed in.

## Example 4: Check-Then-Act Race Condition (Java)

**The design flaw:** The balance is checked, then debited in a separate step. Concurrent requests all pass the check before any debit lands.

**Vulnerable Design**
```java
public void withdraw(long accountId, BigDecimal amount) {
    Account acct = repo.findById(accountId);
    // DESIGN FLAW: check-then-act is not atomic. 100 concurrent
    // requests all see the same balance and all "succeed".
    if (acct.getBalance().compareTo(amount) >= 0) {
        acct.setBalance(acct.getBalance().subtract(amount));
        repo.save(acct);
    } else {
        throw new InsufficientFundsException();
    }
}
```

**Secure Design**
```java
@Transactional
public void withdraw(long accountId, BigDecimal amount) {
    if (amount.signum() <= 0) throw new ValidationException("amount must be > 0");

    // Atomic, conditional UPDATE: the database enforces the invariant.
    int rows = jdbc.update(
        "UPDATE account SET balance = balance - ? " +
        "WHERE id = ? AND balance >= ?",
        amount, accountId, amount);

    if (rows == 0) throw new InsufficientFundsException();  // lost the race, safely
}
```

**Principle:** Replace check-then-act with an atomic operation so concurrency cannot break the invariant. Treat concurrency as adversarial.

## Example 5: Single-Use Coupon Abuse (Node.js)

**The design flaw:** "Has this coupon been used?" is checked and then marked used in two steps, so parallel requests each see it as unused.

**Vulnerable Design**
```javascript
async function applyCoupon(userId, code) {
  const coupon = await db.coupons.findOne({ code });
  // DESIGN FLAW: non-atomic check-then-mark; N parallel calls all pass.
  if (coupon.used) throw new Error('already used');
  await db.coupons.update({ code }, { used: true });
  return coupon.discount;
}
```

**Secure Design**
```javascript
async function applyCoupon(userId, code) {
  // Atomic reserve: only ONE update can flip used:false -> used:true.
  const result = await db.coupons.findOneAndUpdate(
    { code, used: false },                     // condition is part of the write
    { $set: { used: true, usedBy: userId, usedAt: new Date() } },
    { returnDocument: 'after' }
  );
  if (!result.value) throw new Error('coupon invalid or already used');
  return result.value.discount;
}
```

**Principle:** Redemption of a limited resource must be a single atomic reservation with a uniqueness guarantee.

## Example 6: Weak Knowledge-Based Recovery (Python)

**The design flaw:** Account recovery is gated on a "security question" whose answer is public information.

**Vulnerable Design**
```python
@app.route('/recover', methods=['POST'])
def recover():
    data = request.get_json()
    user = Users.get(data['email'])
    # DESIGN FLAW: recovery hinges on a guessable/public answer,
    # and is weaker than the password it bypasses.
    if user.security_answer.lower() == data['answer'].lower():
        return reset_password(user, data['new_password'])
    abort(401)
```

**Secure Design**
```python
@app.route('/recover', methods=['POST'])
def recover():
    data = request.get_json()
    user = Users.get(data['email'])
    # Always respond identically to prevent account enumeration.
    if user:
        # Send a single-use, short-lived, high-entropy token to a
        # pre-verified channel. Recovery is at least as strong as login.
        token = secrets.token_urlsafe(32)
        recovery_tokens.store(user.id, hash_token(token), ttl_minutes=15)
        send_to_verified_channel(user, token)
    return jsonify({'status': 'if the account exists, a reset link was sent'})
```

**Principle:** Recovery must rely on possession of a verified channel and a high-entropy, short-lived, single-use token — never on public knowledge factors — and must not leak whether an account exists.

## Example 7: Broken Tenant Segregation (Java)

**The design flaw:** The endpoint trusts the tenant id from the URL and never checks it against the caller's identity.

**Vulnerable Design**
```java
@GetMapping("/orgs/{orgId}/invoices")
public List<Invoice> list(@PathVariable String orgId) {
    // DESIGN FLAW: orgId is trusted from the URL. No check that the
    // caller belongs to orgId -> cross-tenant data access.
    return invoiceRepo.findByOrgId(orgId);
}
```

**Secure Design**
```java
@GetMapping("/orgs/{orgId}/invoices")
public List<Invoice> list(@PathVariable String orgId, Authentication auth) {
    String callerOrg = ((AppUser) auth.getPrincipal()).getOrgId();
    // Trust boundary: the caller may only act within their own org.
    if (!callerOrg.equals(orgId)) {
        throw new AccessDeniedException("cross-tenant access denied");
    }
    // Defense in depth: scope the query itself to the authenticated org.
    return invoiceRepo.findByOrgId(callerOrg);
}
```

**Principle:** Tenant segregation is a trust boundary enforced server-side from the authenticated identity, with the query scoped to that identity as defense in depth.

## Summary of Design Principles

| Design flaw | Secure design principle |
|---|---|
| Client supplies price/role/limit | Derive all security-relevant values server-side. |
| Workflow steps trust each other | Authoritative server-side state machine; validate every transition. |
| Small secret, unlimited guesses | Rate limit, cap attempts, short TTL, single use. |
| Check-then-act on shared state | Atomic operations / conditional updates / unique constraints. |
| Non-atomic redemption | Atomic reservation with uniqueness guarantee. |
| Knowledge-based recovery | Possession of a verified channel + high-entropy token. |
| Trusting client-supplied tenant id | Enforce segregation from the authenticated identity at a trust boundary. |

> In every pair, the vulnerable version is *correct code for an incorrect design*. The fix is not a patch — it is a different design that includes the missing control.

## Next Steps

- **[Overview](./overview.html)**: The design-vs-implementation distinction and why this category exists.
- **[Attack Vectors](./attack-vectors.html)**: How these flaws are discovered and abused.
- **[Prevention](./prevention.html)**: The layered process and guardrails that produce secure designs.
- **[Hands-On Lab](./lab/missing-rate-limit-lab/)**: Apply these principles by fixing a missing-rate-limit design.
