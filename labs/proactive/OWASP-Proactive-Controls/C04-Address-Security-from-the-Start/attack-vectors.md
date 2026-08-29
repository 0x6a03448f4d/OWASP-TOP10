# C4: Address Security from the Start - Threats Addressed

## Table of Contents
- [Understanding Design-Level Threats](#understanding-design-level-threats)
- [Why Design Flaws Are Invisible to Tools](#why-design-flaws-are-invisible-to-tools)
- [The Threats This Control Addresses](#the-threats-this-control-addresses)
- [How Design Flaws Compound](#how-design-flaws-compound)

## Understanding Design-Level Threats

> **⚠ EDUCATIONAL PURPOSE ONLY** — the abuse scenarios below are shown so you can recognise and design out these weaknesses in systems you own or are authorised to test.

Unlike an implementation bug—where code does something its author did not intend—a **design-level threat** exploits code doing exactly what it was told to do, toward a goal that was never safe. The attacker does not need a clever payload; they need only to use the system in a way the designer never considered but never forbade.

Addressing security from the start neutralises these threats at the source: the missing control is added to the design, the abuse case is written as a requirement, and the trust boundary is drawn before a single line of code exists. This page catalogs the threat classes C4 is meant to prevent—each is a symptom of security that was *not* addressed from the start.

## Why Design Flaws Are Invisible to Tools

```
Implementation bug (tools CAN find it):
   query = "SELECT * FROM u WHERE id=" + input   -> SQL injection
   A scanner sees untrusted data flow into a sink. Flagged.

Design flaw (tools CANNOT find it):
   transfer(from, to, amount)   # works perfectly...
   ...but no rule ever said amount must be > 0 and <= balance.
   Nothing is "wrong" with the code. The REQUIREMENT is missing.
```

A scanner has no oracle for "this business rule should exist." That gap is exactly what threat modeling and design review fill—and why the following threats survive even a clean SAST/DAST report.

## The Threats This Control Addresses

### 1. Business-Logic Abuse

The workflow behaves as coded, but the sequence, quantity, or value can be manipulated to the attacker's benefit because the rules live in the wrong place or are absent.

```http
POST /api/checkout HTTP/1.1
Content-Type: application/json

{ "item": "laptop", "unit_price": 0.01, "qty": -5 }
# Price and quantity were "validated" only in the browser.
# Server trusts the client -> negative qty credits the account,
# tampered price sells a laptop for a cent.
```

**Design fix (C4)**: Write the abuse case ("attacker submits a price/quantity the UI would never send") during design; require server-side re-validation of every business rule at the trust boundary.

### 2. Missing or Insufficient Security Controls

A needed control—authorization tier, rate limit, ownership check, approval step—was simply never part of the design, so there is nothing to bypass.

```http
GET /api/invoices/84213 HTTP/1.1
Authorization: Bearer <valid token for user A>

HTTP/1.1 200 OK
{ "invoice_id": 84213, "owner": "userB", "amount": 9400 }
# Authentication exists; AUTHORIZATION (does A own this invoice?)
# was never designed in. Any logged-in user reads any invoice.
```

**Design fix (C4)**: Enumerate required controls per asset during design; make "who is allowed to do this to this object?" an explicit, testable requirement for every endpoint.

### 3. Insecure-by-Design Workflows (Skippable Steps)

A multi-step process exposes each step as an independent endpoint with no enforced state, so a later step can be reached without completing the earlier ones.

```http
Intended:  verify-identity  ->  set-new-password
Attacker skips step 1:

POST /api/account/set-new-password HTTP/1.1
{ "user": "victim", "new_password": "pwned123" }

HTTP/1.1 200 OK   # never proved identity; sequence not enforced
```

**Design fix (C4)**: Model the flow as a server-side state machine; each transition must require the prior verified state. Design the sequence, do not assume the client follows it.

### 4. Implicit Trust Across Boundaries

Components—services, tiers, or third parties—are designed to trust each other because of where they sit, not because trust was verified.

```
# Internal service call, no auth because "it's on the private network":
GET http://billing.internal/api/charge?acct=123&amount=5000

# An attacker who reaches ANY internal host (via SSRF or a
# compromised pod) can now invoke billing directly. Flat trust
# turns one foothold into full internal reach.
```

**Design fix (C4)**: Draw explicit trust boundaries; authenticate and authorize service-to-service calls; adopt "assume breach" so no single position grants everything.

### 5. Missing Anti-Automation on Sensitive Flows

High-value flows are designed for the honest single user and never for the scripted adversary sending thousands of requests.

```http
POST /api/giftcard/redeem   { "code": "GC-0001" }
POST /api/giftcard/redeem   { "code": "GC-0002" }
POST /api/giftcard/redeem   { "code": "GC-0003" }
...      # no throttle, no lockout, no challenge ->
         # brute-force enumeration of every valid card.
```

**Design fix (C4)**: Identify automation abuse cases in design; require rate limiting, throttling, monitoring, and challenges as part of the flow's definition, not as a later add-on.

### 6. Trusting Client-Supplied State and Identity

The design lets the client assert facts about itself—role, price, user id, entitlement—that the server accepts without independent proof.

```http
POST /api/order HTTP/1.1
{ "user_id": 4021, "role": "admin", "discount_pct": 100 }
# The client "shouldn't" send role or discount, but nothing
# stops it. Server derives authority from the request body.
```

**Design fix (C4)**: Derive identity and entitlements server-side from the authenticated session; never accept security-relevant state from the client. This is an architectural rule, not a validation tweak.

### 7. Bespoke Security Primitives

Home-grown authentication, session, token, or cryptography schemes are designed without the scrutiny that proven libraries have absorbed over years.

```python
# Custom "token" = base64 of predictable fields, no signature:
token = base64(user_id + ":" + role + ":" + issued_at)
# Attacker decodes, edits role to admin, re-encodes. No integrity
# check was ever designed in.
```

**Design fix (C4)**: Choose proven, maintained frameworks for auth, sessions, and crypto during design. Reserve bespoke code for genuine business logic, never for security primitives.

### 8. Mass Assignment / Over-Permissive Data Binding

The design binds incoming request fields directly to internal objects, so a client can set fields it was never meant to touch.

```http
PATCH /api/users/me HTTP/1.1
{ "displayName": "Sam", "isAdmin": true, "accountBalance": 999999 }
# The design auto-maps every JSON field onto the user record.
# isAdmin and accountBalance were never meant to be client-writable.
```

**Design fix (C4)**: Design explicit input models / allow-lists of writable fields per operation; never bind raw requests onto domain objects.

### 9. Ignoring Failure and Abuse Modes

The "happy path" is designed thoroughly while error, retry, race, and partial-failure paths are left to chance—where attackers live.

```
# Two concurrent redeem requests for a one-time coupon:
T1: read balance (valid) --\
T2: read balance (valid) ---\--> both pass the check
T1: apply coupon            \--> applied twice (race condition)
T2: apply coupon             --> double credit
# The design never considered concurrency at the boundary.
```

**Design fix (C4)**: In threat modeling, walk the failure and concurrency modes ("what if this runs twice at once?"); design idempotency, locking, and safe-failure behaviour deliberately.

## How Design Flaws Compound

Design weaknesses rarely act alone; a missing control plus implicit trust becomes a full breach with no memory-corruption exploit anywhere in sight.

```
Client-trusted role (threat #6)      -> attacker claims "role": "support"
        +
Missing authorization check (#2)     -> support role is never verified server-side
        +
Implicit internal trust (#4)         -> support endpoint calls billing with no auth
        =  privilege escalation to financial actions, entirely by design gaps
```

Another common chain:

```
Skippable workflow step (#3)   -> reach fulfillment without payment
        -> no anti-automation (#5) lets it be scripted at scale
        -> mass assignment (#8) sets "status": "paid" on the order
        =  inventory drained, revenue lost, zero code-level "bugs"
```

Every link in these chains is a decision that was never made—which is precisely what addressing security from the start prevents.

## Key Takeaways

1. **Design threats exploit missing decisions, not broken code**—the system works as built, toward an unsafe goal.
2. **Scanners are blind to absent controls**—there is no error to detect when a requirement simply does not exist.
3. **Business logic and trust boundaries are the prime targets**—abuse the sequence, the values, or the implicit trust.
4. **Client-supplied security state is never trustworthy**—identity and entitlements must be derived server-side.
5. **Design flaws chain**—several small omissions combine into full compromise, so each must be closed in the design.

## Next Steps

- **[How to Implement](prevention.md)**: Build these defenses into the SDLC and architecture
- **[Examples](examples.md)**: Insecure design vs. secure design, side by side
- **[Proactive Controls](/learn/proactive)**: Explore the full set of OWASP Proactive Controls
- **[Practice](/practice)**: Spot and fix design-level flaws in hands-on scenarios
