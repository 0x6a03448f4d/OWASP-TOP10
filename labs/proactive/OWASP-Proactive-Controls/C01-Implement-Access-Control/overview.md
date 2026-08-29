# C1: Implement Access Control - Overview

## Table of Contents
- [What is Access Control?](#what-is-access-control)
- [Why Does This Matter?](#why-does-this-matter)
- [Key Concepts and Principles](#key-concepts-and-principles)
- [Authorization Models: RBAC, ABAC, ReBAC](#authorization-models-rbac-abac-rebac)
- [Control vs. Risk: A Defense, Not a Bug](#control-vs-risk-a-defense-not-a-bug)
- [Real-World Impact](#real-world-impact)
- [Common Misunderstandings](#common-misunderstandings)
- [Self-Assessment](#self-assessment)

> **This is a proactive control — a defense you build in, not a vulnerability to find.** C1 in the OWASP Proactive Controls (2024) is the deliberate practice of *Implementing Access Control*. It is the primary mitigation for the risk OWASP names *Broken Access Control* (A01 in the OWASP Top 10). This lesson teaches how to design and enforce the control correctly.

## What is Access Control?

**Access control** (also called **authorization**) is the mechanism that decides, for every attempted operation, whether the *authenticated* subject is *permitted* to perform that operation on that specific resource. It is the enforcement of your application's policy about who may do what, to which data, under which conditions.

It is essential to separate two ideas that are often confused:

- **Authentication** answers *"who are you?"* — it establishes identity (login, tokens, sessions).
- **Access control / authorization** answers *"are you allowed to do this?"* — it evaluates a permission for an already-identified subject.

Authentication is a prerequisite, but proving identity grants nothing on its own. A correctly authenticated user must still be stopped from reading another user's invoice, deleting a record they do not own, or reaching an admin-only function. That stopping is access control. When it is implemented consistently, users can do and see only what they are explicitly permitted to — nothing more.

### The Principle It Enforces

Access control operationalizes the **principle of least privilege**: every subject should hold the minimum set of permissions required to perform its legitimate function, and no more. Paired with least privilege is **deny by default**: absent an explicit grant, the answer is "no." Together they invert the dangerous default of open-until-restricted into the safe default of closed-until-granted.

### Core Concept

```
WITHOUT the control (implicit / client-trusting):
  Request arrives -> is the user logged in? -> YES -> serve whatever was asked
  (No check of WHICH record, WHICH function, or WHETHER this user owns it.)
  Result: any authenticated user can reach any object by changing an ID or URL.

WITH the control (deny-by-default, server-side, per-request):
  Request arrives
    -> authenticate subject
    -> load the target resource
    -> ask the authorization layer:
         may THIS subject perform THIS action on THIS resource?
    -> default answer is DENY
    -> allow only on an explicit, logged, auditable grant
  Result: forged IDs, forced-browsed URLs, and role jumps are refused.
```

### Where the Control Lives

Access control is not a single line of code in one place. It is a discipline applied at every point where a subject references a function, a URL, or a data record. The control has three durable requirements:

- It runs **server-side**, on trusted infrastructure the client cannot influence.
- It runs on **every request**, not only the first one and not only in the UI.
- It checks the **specific resource** being referenced, not merely the subject's role in the abstract.

## Why Does This Matter?

OWASP has ranked **Broken Access Control as the #1 web application risk** in the current Top 10. Implementing access control well is therefore the single highest-leverage defensive investment most applications can make. When the control is absent or inconsistent, the consequences are direct and severe.

### Business Impact of a Missing or Weak Control

- **Unauthorized data access**: One user reads another's financial, medical, or personal records simply by changing an identifier — a mass-scrapeable breach.
- **Unauthorized data modification**: Attackers alter or delete records they do not own, corrupting integrity and destroying trust.
- **Privilege escalation**: A standard account performs administrative actions, taking over the application.
- **Regulatory exposure**: Cross-tenant data leakage triggers GDPR, HIPAA, and PCI-DSS obligations, fines, and mandatory breach notification.
- **Reputational damage**: Access-control breaches are trivially reproducible and highly publicized, because a researcher only needs to change a number to prove them.

### Why the Control Is Worth the Effort

- **It addresses the most prevalent risk class.** Access-control flaws appear in a very large share of assessed applications; a solid control removes an entire family of them at once.
- **It is cheap when designed in, expensive when retrofitted.** Centralizing authorization early costs a fraction of chasing scattered checks across a mature codebase.
- **It composes.** A single well-tested authorization layer protects endpoints that do not exist yet, because new code routes through the same gate.
- **It is auditable.** A centralized, logged control produces the evidence auditors and incident responders need.

## Key Concepts and Principles

Implementing C1 well means internalizing a set of reinforcing principles. Each is a design rule you apply, not a feature you install.

### 1. Deny by Default
The default outcome of any authorization decision is **deny**. Access to functions, data, and URLs is refused unless an explicit rule grants it. New routes, fields, and actions are therefore closed until someone deliberately opens them — the opposite of the "forgot to add a check" failure mode.

### 2. Enforce Server-Side, Never Trust the Client
Every authorization decision is made on the server. Hidden form fields, disabled buttons, client-side role flags, and "the UI never shows that link" are *not* access control — they are presentation. An attacker crafts requests directly, so the server must re-decide every time, regardless of what the client claims.

### 3. Centralize Authorization Logic
Route decisions through a single, well-tested component (a policy engine, middleware, or service) rather than copy-pasting `if (user.role == ...)` across hundreds of handlers. Scattered checks drift, and the one that is forgotten becomes the breach. Centralization makes the policy reviewable and consistently applied.

### 4. Principle of Least Privilege
Grant the minimum permission necessary. Default new users and services to the lowest useful role, elevate narrowly and temporarily, and revoke promptly. Least privilege shrinks the blast radius of any single compromised credential.

### 5. Check Ownership at the Record Level
Role is not enough. A user with the "customer" role is allowed to view *their* orders, not *all* orders. On every object reference, verify that the subject is entitled to *that specific record* — the check that prevents Insecure Direct Object References (IDOR).

### 6. Check Every Reference, Not Just the UI
Enforcement belongs at the data/function layer, on every API call and every direct request. Hiding a menu item stops honest users from stumbling; it does nothing against an attacker who calls the endpoint directly.

### 7. Log Access-Control Failures
Repeated denials are a strong signal of enumeration or privilege-probing. Log every failed authorization decision with the subject, resource, and action, and alert on patterns — the control should be observable, not silent.

### 8. Make Policy Auditable, and Don't Rely on Obscurity
The policy should be expressible, reviewable, and testable. Security must never depend on an endpoint being "secret," an ID being hard to guess, or a URL being undocumented — attackers enumerate all three. Obscurity is not a control.

### Key Concepts at a Glance

| Principle | What it means | Failure it prevents |
|-----------|---------------|---------------------|
| Deny by default | No grant => no access | Forgotten checks, forced browsing |
| Server-side enforcement | Decide on trusted infra every request | Client tampering, hidden-field abuse |
| Centralized logic | One authorization gate | Drift, inconsistent checks |
| Least privilege | Minimum necessary permission | Over-broad roles, wide blast radius |
| Record-level ownership | Verify entitlement to this object | IDOR / BOLA |
| Check every reference | Enforce at data/function layer | UI-only "security" |
| Log failures | Record and alert on denials | Silent enumeration |
| Auditable, not obscure | Reviewable explicit policy | Security-by-obscurity collapse |

## Authorization Models: RBAC, ABAC, ReBAC

Access control is expressed through a model. The right choice depends on how your permissions are naturally described.

### RBAC — Role-Based Access Control
Permissions attach to **roles**, and subjects hold roles (`admin`, `editor`, `viewer`). Simple, widely understood, and effective when access maps cleanly onto job functions. Its limitation is that roles alone cannot express "this record belongs to this user" — RBAC must be combined with record-level ownership checks to prevent IDOR.

### ABAC — Attribute-Based Access Control
Decisions evaluate **attributes** of the subject, resource, action, and environment (department, clearance, record owner, time of day, request origin). More expressive than RBAC and well suited to fine-grained, context-dependent policy, at the cost of greater complexity.

### ReBAC — Relationship-Based Access Control
Decisions follow **relationships** in a graph: a user may edit a document because they are its *owner*, or a member of a *team* that was *granted* access to a *folder* containing it. This models sharing and collaboration naturally and underpins several modern authorization systems.

> These models are not mutually exclusive. A common, robust pattern is RBAC for coarse function-level gates (*is this subject an admin?*) combined with ownership/attribute checks for record-level decisions (*does this subject own this order?*).

## Control vs. Risk: A Defense, Not a Bug

It is worth stating plainly, because the two are frequently conflated:

| Aspect | The Risk (what OWASP Top 10 catalogs) | The Control (what you implement) |
|--------|----------------------------------------|----------------------------------|
| Name | Broken Access Control (A01) | C1: Implement Access Control |
| Nature | A weakness / failure state | A deliberate defense |
| You want to | Eliminate it | Build and maintain it |
| Examples | IDOR, privilege escalation, forced browsing | Deny-by-default, centralized checks, ownership verification |
| Measured by | Findings in a pentest | Coverage and consistency of enforcement |

Implementing C1 correctly is precisely how you drive the Broken Access Control risk toward zero. The rest of this lesson treats the control from that angle: the [threats it addresses](attack-vectors.md), [how to implement it](prevention.md), and [missing-control vs. control-applied code](examples.md).

## Real-World Impact

The following are **classes** of real incidents that a correctly implemented C1 control prevents. They are described generically rather than tied to fabricated figures.

### Class 1: Direct Object Reference Exposure (IDOR / BOLA)
An application serves records by an identifier taken from the request — `/api/invoices/1043` — and returns the record without checking that the caller owns it. Changing the number to `1044` returns someone else's invoice. Scripted, this becomes a bulk export of every record. This pattern recurs across banking, healthcare, e-commerce, and social platforms and is consistently among the most reported real-world access-control failures. The control that stops it is a record-level ownership check on every reference.

### Class 2: Privilege Escalation via Unprotected Function
An administrative action (delete any user, change any role, view all accounts) is reachable by any authenticated session because the function-level check was assumed to be covered by the UI hiding the link. A standard user calls the endpoint directly and gains administrative effect. The control that stops it is a deny-by-default, server-side function-level check.

### Class 3: Forced Browsing to Unlinked Resources
Sensitive pages or endpoints (`/admin`, `/reports/export`, staging APIs) are protected only by not being linked. Attackers discover them through wordlists, JavaScript inspection, and search history. Because obscurity was the only barrier, discovery equals access. The control that stops it is enforced authorization on the resource itself, independent of how it was reached.

### Class 4: Metadata / Parameter Tampering
A request carries its own authority — a hidden `role=user` field, a client-supplied `account_id`, or a JWT claim the server never re-validates. The attacker edits it to `role=admin`. Because the server trusted client-provided authority, the change is honored. The control that stops it is deriving authority solely from server-side state, never from client input.

## Common Misunderstandings

### Myth 1: "The user is logged in, so they're authorized."
**Reality**: Authentication and authorization are different steps. A valid session says who the subject is; it says nothing about whether they may touch a specific record or function. Every request still needs an authorization decision.

### Myth 2: "We hide the button, so users can't do it."
**Reality**: Hiding UI is presentation, not enforcement. Attackers call endpoints directly with tools like curl. Authorization must be enforced server-side at the API, not in the rendered page.

### Myth 3: "The IDs are random UUIDs, so nobody can guess them."
**Reality**: Unguessable identifiers are not access control. IDs leak through referrers, logs, shared links, JavaScript, and other API responses. Obscurity delays no serious attacker; you still need an ownership check.

### Myth 4: "We check the role once at login."
**Reality**: A login-time check cannot know which record a later request targets. Authorization is per-request and per-resource, because the sensitive decision is "may this subject touch *this* object *now*."

### Myth 5: "Each endpoint does its own check, so we're covered."
**Reality**: Scattered checks drift and are forgotten. The endpoint someone forgets is the breach. Centralize the decision so coverage is verifiable and new code is protected by default.

### Myth 6: "Access control is only about admin vs. user."
**Reality**: Most real breaches are horizontal — one ordinary user reaching another ordinary user's data. Role checks alone miss this entirely; you need record-level ownership checks.

## Self-Assessment

Use these questions to gauge whether your access-control *control* is actually implemented, not merely assumed:

- [ ] Is the default authorization outcome **deny**, with access granted only by explicit rule?
- [ ] Is every authorization decision made **server-side**, independent of any client-supplied role or flag?
- [ ] Is authorization logic **centralized** in a single reviewable component rather than copy-pasted per handler?
- [ ] On every object reference, do you verify the subject is entitled to **that specific record** (ownership/tenant check)?
- [ ] Are administrative and sensitive **functions** gated by a server-side check, not merely hidden in the UI?
- [ ] Are unlinked and undocumented endpoints protected by **enforced authorization**, not obscurity?
- [ ] Do you apply **least privilege** — new subjects default to the lowest useful role?
- [ ] Are **access-control failures logged** and alerted on to detect enumeration?
- [ ] Is the policy **auditable and tested** — can you prove which subjects may do what?
- [ ] Do automated tests assert that a non-owner and a lower-privilege user are **denied**?

If you answered "no" or "not sure" to several of these, the control is incomplete — and the Broken Access Control risk is present today.

## Key Takeaways

1. **Access control is authorization** — it enforces who may do what to which resource, and it is distinct from authentication.
2. **Deny by default and least privilege** are the two principles the control operationalizes.
3. **Enforce server-side, on every request, at the record level** — the UI is not a control.
4. **Centralize the decision** so it is consistent, auditable, and protects code that does not exist yet.
5. **This is the primary defense against the #1 web risk** — implementing C1 well is how Broken Access Control is prevented.

## Next Steps

- **[Threats Addressed](attack-vectors.md)**: What goes wrong when the control is missing or weak
- **[How to Implement](prevention.md)**: Layered, practical implementation of the control
- **[Examples](examples.md)**: Missing-control vs. control-applied code across stacks
- **[Proactive Controls](/learn/proactive)**: Return to the full OWASP Proactive Controls catalog
- **[Practice](/practice)**: Apply the control in hands-on exercises
