# API6:2019 Mass Assignment - Overview

## Table of Contents
- [What is Mass Assignment?](#what-is-mass-assignment)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Mass Assignment?

**Mass Assignment** occurs when an API automatically binds client-supplied input directly to the properties of an internal object—a database model, a domain entity, or a configuration record—*without an allow-list* of which fields a client is actually permitted to set. The convenience feature that makes modern frameworks pleasant to use (take the whole request body, map it onto an object in one line) becomes a vulnerability the moment the object contains fields the client should never control.

The attack is disarmingly simple. An attacker looks at a legitimate request, guesses or discovers the names of extra, sensitive properties on the underlying object, and simply *adds those fields to the request body*. If the framework binds them blindly, the attacker has just written to a field the user interface never exposed—setting their own `role` to `admin`, flipping `isVerified` to `true`, inflating a `balance`, or re-pointing a record's `user_id` at someone else.

> **Edition note.** This lesson uses the **2019** framing, where Mass Assignment is its own category: **API6:2019**. In the 2023 edition it was merged with Excessive Data Exposure into a single, broader category—**API3:2023 Broken Object Property Level Authorization (BOPLA)**. The vulnerability class did not go away; it was reclassified. Everything below applies directly to the "unauthorized modification of object properties" half of BOPLA.

### Core Concept

```
What the client is SUPPOSED to send (create-user form):
  {
    "username": "alice",
    "email":    "alice@example.com",
    "password": "s3cr3t"
  }

What the attacker ACTUALLY sends (extra fields appended):
  {
    "username":   "alice",
    "email":      "alice@example.com",
    "password":   "s3cr3t",
    "role":       "admin",       <-- server-controlled field
    "isVerified": true,          <-- server-controlled field
    "balance":    999999,        <-- server-controlled field
    "user_id":    41             <-- identity / ownership field
  }

Vulnerable binding (no allow-list):
  user = User(**request.json)    # every key becomes a column
  db.save(user)                  # role=admin is now persisted

Secure binding (explicit allow-list):
  data = {k: request.json[k] for k in ("username", "email", "password")}
  user = User(**data)            # role/isVerified/balance never touched
```

The essential defect is a **trust boundary that was never drawn**. The request body is untrusted input, but auto-binding treats it as if the client were authorised to set every field on the object. Nothing in the code distinguishes "fields a user may edit" from "fields only the server may set."

### Why It's Critical for APIs

Mass Assignment is especially at home in API codebases for a few structural reasons:

- APIs are **object-centric**: they accept and return JSON that maps closely onto persistence models, so the temptation to bind body→model directly is constant.
- Modern frameworks **encourage auto-binding**: ActiveRecord, Eloquent, Spring's data binding, and `Object.assign(model, req.body)` all make one-line binding the path of least resistance.
- The **extra fields are invisible in the UI** but fully documented by the model, schema, or a leaky GET response—so attackers can learn the property names easily.
- The same object is often **reused for create, update, and internal logic**, so a field that is legitimate for the server to set is exposed to client binding by accident.

## Why Does This Matter?

### Business Impact

- **Privilege Escalation**: The classic outcome—a normal user sets `role: "admin"`, `is_staff: true`, or `permissions: [...]` during signup or profile update and gains administrative control.
- **Financial Tampering**: Binding a client-controlled `balance`, `credit`, `discount`, `price`, or `isPaid` lets an attacker grant themselves money or free goods.
- **Authorization Bypass and Account Takeover**: Overwriting an ownership field such as `user_id`, `owner_id`, or `account_id` re-assigns a record to another user or lets an attacker act on someone else's data.
- **Trust and Verification Bypass**: Flipping `isVerified`, `emailConfirmed`, `kycPassed`, or `approved` skips controls that gate the rest of the platform.
- **Regulatory Fallout**: When these fields govern access to personal or financial data, an exploited Mass Assignment becomes a reportable breach under GDPR, PCI-DSS, and similar regimes.

### Technical Impact

- **Integrity Violation**: Attackers write to fields that were meant to be read-only or server-managed, corrupting the trustworthiness of the data model.
- **State Machine Corruption**: Directly setting status fields (`order.status = "shipped"`, `ticket.state = "closed"`) bypasses the transitions and checks that should govern them.
- **Broken Access Control**: Identity and tenancy fields become client-controlled, collapsing the isolation between users or tenants.
- **Nested-Object Compromise**: Binding into nested structures (`user.address.country`, `order.customer.id`) can reach related records the top-level endpoint never intended to expose.

## Technical Context

### How Auto-Binding Turns Into a Vulnerability

Every mainstream framework offers a "bind the request onto an object" shortcut. Each is safe only when paired with an explicit allow-list; each is vulnerable by default when the object carries sensitive fields.

| Framework / Pattern | Convenient (vulnerable) call | What gets bound |
|---------------------|------------------------------|-----------------|
| Flask / SQLAlchemy | `User(**request.json)` | Every JSON key → model attribute/column |
| Django REST Framework | `ModelSerializer` with `fields = "__all__"` | Every model field becomes writable |
| Express / Mongoose | `new Model(req.body)` / `Object.assign(doc, req.body)` | Every body key → document field |
| Rails ActiveRecord | `User.new(params[:user])` without `permit` | Every param → attribute (the original "mass assignment") |
| Laravel Eloquent | `User::create($request->all())` with `$guarded = []` | Every input → attribute |
| Spring MVC | `@ModelAttribute` / binding onto a JPA `@Entity` | Every matching request param/JSON field → setter |

#### 1. Binding the Request Body Straight to a Persistence Model

```http
POST /api/users HTTP/1.1
Content-Type: application/json

{ "username": "mallory", "password": "pw", "role": "admin" }

# Server:
user = User(**request.get_json())   # role="admin" is bound and saved
db.session.add(user); db.session.commit()
```

**Risk**: The very first request creates an administrator, because the `User` model has a `role` column and nothing filters it out.

#### 2. Hidden / Read-Only Fields Set via PATCH Updates

```http
PATCH /api/users/me HTTP/1.1
Content-Type: application/json

{ "displayName": "Mallory", "isVerified": true, "balance": 5000 }

# Server merges the whole body onto the loaded record:
for k, v in request.get_json().items():
    setattr(current_user, k, v)     # isVerified and balance overwritten
```

**Risk**: A profile-update endpoint that is meant to change a display name silently accepts verification and balance changes because it merges every key.

#### 3. Nested-Object Binding

```http
PUT /api/orders/77 HTTP/1.1
{
  "note": "leave at door",
  "customer": { "id": 1042 },      <-- re-points the order at another customer
  "discount": { "percent": 100 }   <-- nested field the UI never exposes
}
```

**Risk**: Deep binding follows object graphs, so an attacker reaches related entities (customer, discount, address) that the endpoint never meant to be writable.

#### 4. Identity / Ownership Fields

```http
POST /api/comments HTTP/1.1
{ "text": "hi", "user_id": 3 }     <-- attacker is user 9, forges authorship as user 3
```

**Risk**: Ownership is decided by the request body instead of the authenticated session, so records can be forged or re-assigned.

### Which Fields Attackers Target

| Category | Example field names | Consequence if bound |
|----------|---------------------|----------------------|
| Authorization | `role`, `is_admin`, `is_staff`, `permissions`, `scopes`, `groups` | Privilege escalation |
| Verification / status | `isVerified`, `emailConfirmed`, `approved`, `kycPassed`, `status` | Control / workflow bypass |
| Financial | `balance`, `credit`, `price`, `discount`, `isPaid` | Financial tampering |
| Identity / tenancy | `id`, `user_id`, `owner_id`, `account_id`, `tenant_id` | Authorization bypass, data theft |
| Timestamps / audit | `created_at`, `updated_by`, `version` | Audit tampering, optimistic-lock bypass |

## Real-World Impact

### Case Class 1: The GitHub / Rails Mass-Assignment Incident (2012)

**Situation**:
- Early Rails made `attr_accessible` opt-in, so models accepted every submitted attribute by default. This became the textbook example of Mass Assignment.
- A researcher demonstrated the class of flaw against a high-profile Rails application by submitting extra attributes that the forms never exposed—including fields that changed record ownership and privileged flags.

**Impact**:
- The demonstration showed that unfiltered attribute binding let a user modify records and elevate access they were never granted.

**Root Cause and Aftermath**: Framework auto-binding with no allow-list. The episode was influential enough that Rails changed its posture—`strong parameters` (explicit `permit`) became the standard, secure-by-default way to bind params in later versions.

### Case Class 2: Signup / Profile Privilege Escalation

**Situation**:
- A recurring, widely reported pattern across many web and API products: a registration or profile-update endpoint binds the whole body to a user model that includes an authorization field.
- An attacker appends `"role": "admin"` (or `is_staff`, `account_type: "premium"`) to an otherwise normal request.

**Impact**:
- Self-service creation of privileged accounts, or silent upgrade of an existing account to a paid or administrative tier, with no exploit beyond an extra JSON key.

**Root Cause**: The same object is used to represent both client-editable profile data and server-controlled authorization state, with no allow-list separating them.

### Case Class 3: Financial / Workflow Field Tampering

**Situation**:
- E-commerce and fintech APIs that bind order or account bodies directly to models exposing `price`, `discount`, `balance`, or `status`.

**Impact**:
- Attackers set their own discount to 100%, mark an unpaid order as paid, or advance an order's status past checks—converting a data-binding shortcut into direct monetary loss.

**Root Cause**: Server-authoritative fields (money, status) are left writable through the same binding used for benign fields, and are validated on the wrong side of the trust boundary.

## Prevalence and Detectability

Mass Assignment earned its own slot in the 2019 OWASP API Security Top 10 precisely because it is **common, easy to exploit, and hard to spot in review**—the vulnerable code usually looks like clean, idiomatic framework usage.

Rather than cite specific numbers (which vary by source and year), the durable picture is:

- OWASP characterises the exploitability as **easy**: the attacker only needs to guess plausible field names and add them to a request.
- Detectability by an outside attacker is rated **moderate**—field names are frequently leaked by verbose GET responses, API schemas, documentation, or public source, and are otherwise guessable.
- The most commonly exploited fields are **authorization flags, verification/status flags, financial values, and identity/ownership references**.
- Because the flaw hides in ordinary auto-binding, it is **frequently missed** by code review and by scanners that do not understand which object fields are sensitive.

> Note: treat any single percentage as illustrative. The reliable takeaway is that wherever a request body is bound to an object with sensitive fields and no allow-list, Mass Assignment is present and cheap to exploit.

## Common Misunderstandings

### Myth 1: "The UI doesn't show that field, so no one can set it"

**Reality**: APIs are called directly, not through your UI. Any field on the underlying object can be added to the raw request body regardless of what the front-end renders. The UI is not a security boundary.

### Myth 2: "We validate the input, so we're safe"

**Reality**: Type and format validation ("is `role` a string?") does not decide *whether the client is allowed to set `role` at all*. Mass Assignment is an authorization-of-fields problem, not a data-format problem. You need an allow-list, not just a validator.

### Myth 3: "Attackers can't know our internal field names"

**Reality**: Field names leak constantly—from verbose GET responses, OpenAPI/Swagger schemas, error messages, mobile apps, JavaScript bundles, and open-source code. They are also highly predictable (`role`, `is_admin`, `user_id`). Obscurity is not a defense.

### Myth 4: "Using an ORM makes binding safe"

**Reality**: The ORM is exactly what performs the dangerous binding. ActiveRecord, Eloquent, Mongoose, SQLAlchemy, and JPA all happily write whatever keys you hand them unless you constrain the input first.

### Myth 5: "It only matters on create, not on update"

**Reality**: PATCH/PUT updates are often *worse*, because merging the whole body onto an already-persisted record lets an attacker flip a single sensitive field (`isVerified`, `balance`) without touching anything else.

### Myth 6: "This was removed from the OWASP list, so it's obsolete"

**Reality**: It was *merged*, not retired. In 2023 it became part of API3:2023 (BOPLA). The 2019 framing is still the clearest way to learn the specific "auto-binding without an allow-list" failure, and the defense is unchanged.

## How Mass Assignment Differs from Related Issues

| Aspect | Mass Assignment (API6:2019) | Excessive Data Exposure (API3:2019) | Broken Object Level Auth (API1:2019) |
|--------|-----------------------------|-------------------------------------|--------------------------------------|
| **Direction** | Client *writes* fields it shouldn't | Server *returns* fields it shouldn't | Client accesses another object's data |
| **Root cause** | Auto-binding with no allow-list | Serializing the whole object out | Missing per-object ownership check |
| **Typical fix** | Input allow-list / DTO in | Output allow-list / DTO out | Authorize the object per request |
| **2023 mapping** | API3:2023 BOPLA (write side) | API3:2023 BOPLA (read side) | API1:2023 BOLA |

Note how Mass Assignment and Excessive Data Exposure are mirror images—one is the write side, the other the read side of "the object has fields the client shouldn't touch." That symmetry is exactly why the 2023 edition folded both into BOPLA.

## Key Takeaways

1. **Mass Assignment is an allow-list problem**—the framework binds every field the client sends unless you explicitly restrict which fields are bindable.
2. **The UI is not the API**—hidden and read-only fields are fully reachable in the raw request body.
3. **Sensitive fields are the prize**—authorization, verification, financial, and identity fields turn a data-binding shortcut into privilege escalation and fraud.
4. **Never bind the request straight to a persistence model**—separate the input model (DTO/schema) from the domain model.
5. **Still relevant in 2023+**—folded into API3:2023 BOPLA, with the same root cause and the same fix.

## How to Identify if You're Vulnerable

- [ ] Does any endpoint bind the whole request body to a model (`Model(**body)`, `new Model(req.body)`, `Object.assign(doc, body)`)?
- [ ] Do your models contain authorization, verification, financial, or identity fields alongside client-editable ones?
- [ ] Is there an explicit allow-list (DTO, schema, `permit`, `fillable`) for every create and update endpoint?
- [ ] Are server-controlled fields marked read-only / excluded (`@JsonIgnore`, `read_only`, `guarded`)?
- [ ] Do PATCH/PUT handlers merge arbitrary keys onto a loaded record?
- [ ] Can nested objects be bound (e.g. `customer.id`, `address.country`) without restriction?
- [ ] Is ownership (`user_id`) taken from the session, never from the request body?
- [ ] Would adding `"role":"admin"` or `"isVerified":true` to a normal request be rejected—or silently accepted?

If you answered "yes" to the binding questions or "no"/"not sure" to the allow-list questions, you likely have exploitable Mass Assignment today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers discover and exploit bindable fields
- **[Prevention](prevention.md)**: Allow-lists, DTOs, and separating input models from domain models
- **[Examples](examples.md)**: Vulnerable vs. secure binding in Flask, Express, and Spring
- **[API Security Top 10](/learn/api)**: Return to the full learning path
- **[Practice](/practice)**: Test your understanding against hands-on challenges
