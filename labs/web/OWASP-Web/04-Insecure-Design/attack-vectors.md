# A04:2021 – Insecure Design - Attack Vectors

> **Educational purpose only.** This page describes how design-level weaknesses are abused, at a conceptual level, so developers and defenders can recognize and eliminate them. It contains no weaponized exploit code. The request examples are illustrative of *legitimate-looking* traffic that produces illegitimate outcomes.

## Table of Contents

- [The Core Attack Flow](#the-core-flow)
- [Design-Flaw Attack Patterns](#patterns)
  1. [Workflow Step-Skipping](#v1-workflow-bypass)
  2. [Trusting Client-Supplied Values](#v2-client-trust)
  3. [Missing Anti-Automation](#v3-no-rate-limit)
  4. [Small-Secret Brute Force](#v4-otp-brute)
  5. [Negative / Boundary Quantities](#v5-negative)
  6. [Coupon and Refund Abuse](#v6-coupon)
  7. [Race-Condition Workflow Abuse](#v7-race)
  8. [Weak Recovery / Fallback Paths](#v8-recovery)
  9. [Broken Trust Boundaries](#v9-tenant)
  10. [Resource Enumeration by Design](#v10-enumeration)
  11. [Unbounded Resource Consumption](#v11-resource-exhaustion)
  12. [Implicit Inter-Service Trust](#v12-implicit-trust)
- [Detection Techniques](#detection)
- [Next Steps](#next-steps)

## The Core Attack Flow

Attacking an insecure design does not look like a traditional exploit. There is no malformed payload and no crash. Instead, the attacker studies the intended behavior, then finds an *unintended path through legitimate operations*:

```
Step 1  Map the workflow      Observe the happy path: which requests, in
                             which order, with which fields.
Step 2  Question assumptions  Ask "what does the server TRUST here?"
                             (client price? step order? one attempt?
                              this field's sign? this tenant id?)
Step 3  Break the assumption  Replay/modify a request that violates the
                             unspoken rule the design assumed users obey.
Step 4  Observe the outcome   Did the server enforce the rule, or accept
                             the illegitimate state?
Step 5  Automate / scale      If a control is missing, repeat at machine
                             speed to maximize impact.
```

The attacker's core tool is an intercepting proxy that replays and edits HTTP requests the browser would never send. Every pattern below is a specific instance of "the server trusted something it should have verified."

## Design-Flaw Attack Patterns

### 1. Workflow Step-Skipping (State-Transition Abuse)

**The assumption:** "Users go through steps in order, so by the time they hit `/confirm` they must have paid."
**The abuse:** The attacker POSTs directly to a later step, skipping the ones that enforce payment.

```
# Intended sequence
POST /checkout/shipping
POST /checkout/payment      <-- charges the card
POST /checkout/confirm

# Abuse: attacker never sends the payment step
POST /checkout/shipping
POST /checkout/confirm      <-- order confirmed, never charged
```

**Root design flaw:** The order's state machine has no server-side gate asserting `state == PAID` before `CONFIRMED`.

### 2. Trusting Client-Supplied Security Values

**The assumption:** "The price/role/limit shown in the form is the one the server will use."
**The abuse:** The attacker edits the value in the request body.

```
POST /cart/add
{ "sku": "LAPTOP-15", "price": 1299.00, "qty": 1 }

# Attacker edits the price the client submitted:
POST /cart/add
{ "sku": "LAPTOP-15", "price": 1.00, "qty": 1 }
```

**Root design flaw:** Price is authoritative on the client. A secure design looks the price up server-side from the SKU.

### 3. Missing Anti-Automation (No Rate Limiting)

**The assumption:** "One person tries to log in a few times."
**The abuse:** The attacker scripts thousands of attempts — credential stuffing, spraying, enumeration, scraping.

```
for cred in leaked_credentials:      # millions of pairs
    POST /login {user, pass}         # no lockout, no throttle,
                                     # no CAPTCHA, no bot check
```

**Root design flaw:** The workflow was designed to authenticate one honest user, not to resist automation (CWE-799).

### 4. Small-Secret Brute Force (OTP / Reset Codes)

**The assumption:** "A 6-digit code is secret."
**The abuse:** A 6-digit code has only 1,000,000 possibilities; with no cap and unlimited re-requests, the space is guessable.

```
POST /verify-otp { "phone": "...", "code": "000000" }
POST /verify-otp { "phone": "...", "code": "000001" }
...                                   # exhaust the space
```

**Root design flaw:** A small secret space paired with unlimited guessing.

### 5. Negative and Boundary Quantities

**The assumption:** "Quantities and amounts are positive."
**The abuse:** A negative value inverts the arithmetic.

```
POST /transfer { "to": "attacker", "amount": -500 }
# If interpreted naively: pulls 500 FROM the recipient TO the attacker.

POST /cart { "sku": "GIFTCARD", "qty": -3 }
# Order total drops by 3x the price; attacker "owed" money.
```

**Root design flaw:** Domain rules ("amount > 0", "qty in 1..maxStock") were never expressed as server-side invariants.

### 6. Coupon, Promotion, and Refund Abuse

**The assumption:** "A coupon is used once; a refund matches a real return."
**The abuse:** Apply a single-use coupon repeatedly, stack exclusive promotions, or refund items never returned.

```
POST /cart/apply-coupon { "code": "SAVE50" }   x N in parallel
# Discount applied N times because "already used?" is checked
# per-request, not atomically reserved.
```

**Root design flaw:** Redemption/refund not modeled as authoritative, atomic, auditable state transitions with enforced uniqueness.

### 7. Race-Condition Workflow Abuse (TOCTOU)

**The assumption:** "Requests happen one at a time, so a check-then-act is safe."
**The abuse:** Fire many concurrent requests in the window between the check and the act.

```
Thread A: check balance=100  ----\
Thread B: check balance=100  ----- both pass the check,
Thread C: check balance=100  ----/  each withdraws 100 -> 300 withdrawn
```

**Root design flaw:** A non-atomic check-then-act instead of an atomic, transactional reservation. Concurrency was never modeled as adversarial.

### 8. Weak Recovery and Fallback Paths

**The assumption:** "Recovery is for legitimate users who forgot their password."
**The abuse:** Target the recovery path because it is the weakest link.

```
POST /recover { "user": "victim", "securityAnswer": "Springfield" }
# Answer is the victim's publicly-known hometown.
```

**Root design flaw:** The fallback is weaker than the primary authentication it bypasses.

### 9. Broken Trust Boundaries and Tenant Segregation

**The assumption:** "Each customer only ever sees their own `tenant_id`, so we can trust it."
**The abuse:** Change the tenant/org identifier and reach another tenant's data.

```
GET /api/orgs/1024/reports        # my org
GET /api/orgs/1025/reports        # someone else's org -> 200 OK
```

**Root design flaw:** Authorization is not enforced as a first-class trust-boundary constraint on cross-tenant references (CWE-501).

### 10. Resource Enumeration by Design

**The assumption:** "Nobody will iterate our sequential IDs / discover valid usernames."
**The abuse:** Sequential identifiers plus responses that distinguish "exists" from "does not exist" enable wholesale enumeration.

```
POST /forgot-password { "email": "a@corp.com" } -> "No such account"
POST /forgot-password { "email": "b@corp.com" } -> "Reset link sent"
# The differing responses enumerate valid accounts by design.
```

**Root design flaw:** Existence leaked through predictable identifiers and distinguishable responses.

### 11. Unbounded Resource Consumption

**The assumption:** "Users request reasonable amounts of work."
**The abuse:** Request enormous page sizes, deep queries, or giant exports to exhaust CPU/memory/cost.

```
GET /api/search?limit=100000000&expand=all&depth=50
POST /report/generate { "range": "10years", "format": "pdf" }  x100
```

**Root design flaw:** No designed limits on request cost, pagination, concurrency, or query complexity.

### 12. Implicit Inter-Service / Internal Trust

**The assumption:** "This request came from our internal network, so it is trustworthy."
**The abuse:** After reaching the internal network (SSRF, compromised dependency, pivot), forge internal trust headers.

```
POST /internal/admin/grant
X-Internal: true
X-User-Role: admin                # forged; the service trusts it blindly
```

**Root design flaw:** A "hard shell, soft interior" design; a secure design authenticates and authorizes every call regardless of origin.

## Detection Techniques

| Technique | What it surfaces |
|---|---|
| **Threat modeling / design review** | The primary method: enumerate assets, trust boundaries, and abuse cases to find controls never designed. |
| **Abuse-case testing** | Drive the workflow off the happy path (skip steps, replay, negate, parallelize) and assert rejection. |
| **Request replay / value fuzzing** | Edit prices, quantities, ids, and step order to test what the server actually trusts. |
| **Concurrency testing** | Fire N simultaneous requests at any one-time benefit to expose TOCTOU races. |
| **Rate/volume monitoring** | Alert on request-frequency anomalies — the fingerprint of missing anti-automation. |
| **Business-metric anomaly detection** | Watch for impossible outcomes: negative totals, discounts exceeding price, refunds without returns. |

> **Key insight:** Every pattern reduces to one sentence — *the server trusted something it should have verified*. Find those trust assumptions and you have found the design flaws.

## Next Steps

- **[Overview](./overview.html)**: The design-vs-implementation distinction and why this category exists.
- **[Prevention](./prevention.html)**: Threat modeling, secure design patterns, and guardrails that close these gaps.
- **[Examples](./examples.html)**: Concrete vulnerable-vs-secure code for these patterns.
- **[Hands-On Lab](./lab/missing-rate-limit-lab/)**: Exploit a missing-rate-limit design, then add the control.
