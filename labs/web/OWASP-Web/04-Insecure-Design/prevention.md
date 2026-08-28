# A04:2021 – Insecure Design - Prevention

## Table of Contents

- [Defense Philosophy: Shift Left](#defense-philosophy)
- [Layer 1: A Secure Development Lifecycle](#sdlc)
- [Layer 2: Threat Modeling (STRIDE)](#threat-modeling)
- [Layer 3: Security Requirements & Abuse Cases](#requirements)
- [Layer 4: Secure Design Patterns & Reference Architecture](#patterns)
- [Layer 5: Secure-by-Design Guardrails](#guardrails)
- [Layer 6: Rate Limiting & Resource Control](#rate-limiting)
- [Layer 7: Segregation of Trust & Tiers](#segregation)
- [Layer 8: Server-Side Plausibility Checks](#server-side-logic)
- [Layer 9: Abuse-Case Tests in CI](#testing)
- [Design-Review Checklist](#checklist)
- [Next Steps](#next-steps)

## Defense Philosophy: Shift Left

Insecure Design cannot be fixed with a scanner or a WAF rule, because the vulnerability is the *absence* of a control, not the presence of a bug. The only durable defense is to build security into the design — to "shift left" so threats are identified and controls specified **before** code exists. OWASP's guidance is unusually process-oriented: establish a secure development lifecycle, use threat modeling, write abuse cases, and reuse vetted secure design patterns.

The layers below move from process (how you decide what to build) to concrete technical guardrails (what the running system enforces). No single layer is sufficient; together they make secure design the path of least resistance.

## Layer 1: A Secure Development Lifecycle (SDLC)

| Phase | Security activity |
|---|---|
| Requirements | Write security & privacy requirements and abuse/misuse cases alongside functional stories. |
| Design | Threat model the feature; choose vetted secure design patterns; define trust boundaries. |
| Implementation | Use hardened, paved-road libraries and guardrail frameworks; peer review against the threat model. |
| Verification | Automated abuse-case tests, design review, targeted testing of modeled threats. |
| Release / operate | Monitor business-logic metrics and abuse signals; feed incidents back into the model. |

Engage security professionals (or a trained security champion) to evaluate and design controls, including privacy-related ones. A mature library of secure design patterns makes this affordable at scale.

## Layer 2: Threat Modeling (STRIDE)

The highest-leverage activity. Draw the system's data flows, mark trust boundaries, and for each element ask "what can go wrong?" using **STRIDE**:

| Threat | Property violated | Example control to design in |
|---|---|---|
| **S**poofing | Authenticity | Strong authentication on every trust boundary, including internal calls. |
| **T**ampering | Integrity | Server-side validation; never trust client-supplied prices/roles/limits. |
| **R**epudiation | Non-repudiation | Tamper-evident audit logging of sensitive actions. |
| **I**nformation disclosure | Confidentiality | Least-privilege data access; uniform responses to prevent enumeration. |
| **D**enial of service | Availability | Rate limits, resource caps, pagination bounds, query-cost limits. |
| **E**levation of privilege | Authorization | Deny-by-default authorization enforced at a central trust boundary. |

A lightweight four-question version works in a design meeting: *What are we building? What can go wrong? What are we going to do about it? Did we do a good enough job?*

## Layer 3: Security Requirements & Abuse/Misuse Cases

For every user story, write the adversarial counterpart. If the story is "apply a coupon," the abuse case is "apply the same single-use coupon 100 times in parallel." Turning abuse cases into explicit, testable requirements is what prevents the control from being forgotten.

```
Story:        A user transfers funds between accounts.
Requirements (security):
  R1  amount MUST be > 0 and <= source balance (server-enforced).
  R2  transfers MUST be atomic (no check-then-act race).
  R3  > $10,000/day MUST require step-up authentication.
  R4  MAX 20 transfers per account per minute.
  R5  every transfer MUST be written to an immutable audit log.
Abuse cases (must FAIL):
  A1  negative amount is rejected.
  A2  100 concurrent transfers cannot overdraw the balance.
  A3  transfer to another tenant's account is denied.
```

## Layer 4: Secure Design Patterns & Reference Architecture

Do not reinvent security-critical workflows. Maintain a library of vetted, reusable patterns and a reference architecture new features must follow:

- **Authoritative server-side state machine**: each workflow transition is validated server-side, so steps cannot be skipped or reordered.
- **Idempotency keys**: mutating operations require a client-supplied key so replays collapse to one effect.
- **Reservation pattern**: for limited resources, atomically reserve before confirming, rather than check-then-act.
- **Deny-by-default authorization**: a central policy layer where access is denied unless explicitly granted.
- **Tiered architecture**: separate layers with trust boundaries and least privilege between tiers.

## Layer 5: Secure-by-Design Guardrails

Make the secure way the easy (and only) way. A guardrail is a paved-road abstraction used for a whole class of operation, so the control cannot be forgotten.

```python
# Guardrail: a repository that ALWAYS scopes to the current tenant.
class TenantScopedRepo:
    def __init__(self, session, tenant_id):
        self._session = session
        self._tenant_id = tenant_id          # bound once, from the auth context

    def get_order(self, order_id):
        # Every query is automatically constrained to the caller's tenant.
        return (self._session.query(Order)
                .filter_by(id=order_id, tenant_id=self._tenant_id)
                .one_or_none())
```

Because the tenant filter is baked in, a developer physically cannot write a cross-tenant query through this path. The guardrail turns a design rule into an enforced invariant.

## Layer 6: Design-Level Rate Limiting & Resource Control

Anti-automation must be a deliberate design decision on every sensitive or expensive endpoint, enforced centrally.

**Token-bucket limiting at the edge (NGINX):**
```
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

location /login {
    limit_req zone=login burst=3 nodelay;   # 5/min, small burst
    proxy_pass http://app;
}
```

**Application-layer limiter (Express + middleware):**
```javascript
const rateLimit = require('express-rate-limit');

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,     // 15 minutes
  max: 5,                        // 5 attempts per window per key
  keyGenerator: req => req.body.userId || req.ip,
  standardHeaders: true,
  handler: (req, res) => res.status(429).json({ error: 'Too many attempts' })
});

app.post('/verify-otp', otpLimiter, verifyOtpHandler);
```

Complement rate limits with: account lockout / step-up after N failures, CAPTCHA or proof-of-work for anonymous bursts, pagination caps, maximum query depth/cost, request-size limits, and per-tenant quotas.

## Layer 7: Segregation of Trust & Tiers

Design boundaries so compromise or abuse of one component, tenant, or user does not cascade:

- **Tenant isolation**: every data access is scoped to the authenticated tenant at a trust boundary; never trust a client-supplied tenant id.
- **Zero-trust between services**: authenticate and authorize internal calls (mTLS, signed tokens). Never treat "internal network" as authorization (CWE-501).
- **Least privilege**: each component gets only the permissions and data it needs; isolate high-value functions into their own trust zone.
- **Segregation of duties**: sensitive operations (large payouts, config changes) require separate roles or approvals, designed into the workflow.

## Layer 8: Server-Side Plausibility & Business-Logic Checks

All security-relevant validation must happen server-side, expressed as domain invariants. Client-side checks are for UX only.

```java
// Java: authoritative, server-side domain invariants
public Order placeOrder(OrderRequest req, AuthContext ctx) {
    Product p = catalog.findById(req.getSku())        // price from server,
        .orElseThrow(() -> new NotFound());           // NOT from the client
    int qty = req.getQty();

    if (qty < 1 || qty > p.getMaxPerOrder())
        throw new ValidationException("invalid quantity");
    if (qty > inventory.available(p))
        throw new ValidationException("insufficient stock");

    Money total = p.getPrice().multiply(qty);         // server computes total
    Coupon c = req.getCouponCode() == null ? null
        : coupons.reserveSingleUse(req.getCouponCode(), ctx.userId()); // atomic
    total = applyDiscount(total, c);

    if (total.isNegativeOrZero())                     // discounts can't invert
        throw new ValidationException("invalid total");

    return orders.createFor(ctx.tenantId(), p, qty, total);  // tenant-scoped
}
```

Each abuse case is closed by an explicit invariant: price is server-derived, quantity is bounded, the coupon is atomically reserved, the total cannot go negative, and the order is tenant-scoped.

## Layer 9: Abuse-Case Tests in CI

Design controls rot without tests that assert abuse *fails*. Encode each abuse case as an automated test on every change.

```python
# pytest: abuse cases must FAIL (i.e., be rejected)
def test_negative_quantity_rejected(client, auth):
    r = client.post('/order', json={'sku': 'SKU1', 'qty': -3}, headers=auth)
    assert r.status_code == 400

def test_single_use_coupon_not_reusable_concurrently(client, auth):
    results = run_parallel(lambda: client.post('/coupon',
                           json={'code': 'SAVE50'}, headers=auth), n=20)
    assert sum(r.status_code == 200 for r in results) == 1

def test_cross_tenant_order_denied(client, auth_tenant_a):
    r = client.get('/orgs/other-tenant/orders', headers=auth_tenant_a)
    assert r.status_code in (403, 404)
```

## Design-Review Checklist

- [ ] A threat model exists for this feature, with trust boundaries and abuse cases documented.
- [ ] Security requirements are written and testable, not implicit.
- [ ] Every multi-step workflow is an authoritative server-side state machine; steps cannot be skipped or reordered.
- [ ] No security decision depends on a client-supplied value (price, role, limit, tenant, eligibility).
- [ ] Sensitive/expensive endpoints have rate limits, lockouts, and resource caps by design.
- [ ] Limited resources use atomic reservation, not check-then-act; races are tested.
- [ ] Tenant/role segregation is enforced at a central trust boundary; internal calls are authenticated.
- [ ] Recovery and fallback paths are at least as strong as the primary path.
- [ ] Identifiers are opaque and responses uniform, preventing enumeration.
- [ ] Abuse-case tests run in CI and block regressions.

## Next Steps

- **[Overview](./overview.html)**: The design-vs-implementation distinction and why this category exists.
- **[Attack Vectors](./attack-vectors.html)**: The patterns these defenses are designed to stop.
- **[Examples](./examples.html)**: Full vulnerable-vs-secure implementations in Python, Node.js, and Java.
- **[Hands-On Lab](./lab/missing-rate-limit-lab/)**: Add designed-in rate limiting to a vulnerable workflow.
