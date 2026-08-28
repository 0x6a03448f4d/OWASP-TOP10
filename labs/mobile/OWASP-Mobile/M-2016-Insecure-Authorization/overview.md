# M6:2016 Insecure Authorization - Overview

## Table of Contents
- [What is Insecure Authorization?](#what-is-insecure-authorization)
- [Authorization vs. Authentication (M6 vs. M4)](#authorization-vs-authentication-m6-vs-m4)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Severity](#prevalence-and-severity)
- [Common Misunderstandings](#common-misunderstandings)

## What is Insecure Authorization?

**Insecure Authorization** (M6 in the OWASP Mobile Top 10, 2016 edition) covers failures in *authorization*—the decision about **what an already-identified user is allowed to do**. The category exists because mobile apps repeatedly make or enforce that decision in the wrong place: inside the client, where the user controls everything, instead of on the server, where the app controls nothing the attacker can reach.

A mobile app is not a trust boundary. It is code and data sitting on a device the attacker fully owns—they can decompile it, hook it at runtime, read and rewrite its local storage, and, most importantly, they can ignore it entirely and talk straight to your backend API. Any permission check that lives only in the app is therefore advisory. If the server does not independently re-derive the caller's identity and re-check their entitlements on *every* request, the app is relying on the honesty of a component the attacker controls.

> **The one-sentence definition:** Insecure Authorization is any design in which the authorization decision can be influenced or bypassed by the client—because the check is missing on the server, or because the server trusts a role, permission, or user identifier that the client supplied.

### Core Concept

```
Insecure (authorization decided or trusted client-side):
  Client  -> hides the "Admin" button in the UI for normal users
  Client  -> sends {"user_id": 1001, "role": "admin"} and server believes it
  Server  -> GET /api/accounts/{id}  returns ANY id with a valid token
  Server  -> POST /api/admin/*  has no role check; the UI just never calls it

Secure (authorization decided and enforced server-side):
  Server  -> identity comes ONLY from the verified session/token, never the body
  Server  -> every request re-checks: is THIS caller allowed THIS action?
  Server  -> per-object ownership check: does account {id} belong to caller?
  Server  -> admin routes verify an admin role stored server-side
  Client  -> hiding UI is a convenience, never the control
```

The distinction that hides most vulnerabilities is between **hiding a capability** and **blocking a capability**. Greying out a button, omitting a menu item, or navigating to a "you are not allowed" screen changes what the user *sees*. It does nothing to what the user can *send*. Blocking happens only when the server refuses the request.

## Authorization vs. Authentication (M6 vs. M4)

The 2016 Mobile Top 10 deliberately splits these into two categories, and conflating them is the single most common source of confusion. They fail in different ways and are fixed with different controls.

| Aspect | M4: Insecure Authentication | M6: Insecure Authorization |
|--------|-----------------------------|----------------------------|
| **Question answered** | *Who are you?* | *What are you allowed to do?* |
| **Typical failure** | Weak/absent identity proof: skippable login, offline auth, guessable tokens, no session on the server | Missing or client-side permission checks: IDOR, role trust, direct admin calls |
| **Attacker starts as** | Anonymous, trying to become *someone* | A *valid, authenticated* low-privilege user |
| **Result of exploit** | Impersonation / logging in as another user | A real user reaching data or actions beyond their entitlement |
| **Core fix** | Prove identity properly, server-side sessions/tokens | Enforce entitlements server-side on every request |

A useful mental model: **M4 is the lock on the front door; M6 is whether the rooms inside are locked.** An attacker who defeats M4 walks in as somebody else. An attacker exploiting M6 walked in legitimately as themselves, then opened doors that should have been closed to them. The two frequently chain—a weak login (M4) gives you a valid session, and a missing server-side check (M6) then lets that session reach everything—but the defenses are separate and both are required.

## Why Does This Matter?

### Business Impact

- **Mass data exposure via one bug**: An object reference that is not ownership-checked (IDOR) lets a single authenticated attacker enumerate every other user's records—profiles, messages, statements, health data—by incrementing an id.
- **Privilege escalation**: A normal user who can reach admin functionality can change prices, refund themselves, alter other accounts, or export the whole dataset.
- **Regulatory exposure**: Cross-tenant or cross-user access to personal, financial, or health records triggers GDPR, HIPAA, PCI-DSS, and similar obligations, including mandatory breach notification.
- **Fraud and financial loss**: Authorization gaps on money-movement, coupon, entitlement, or subscription endpoints are directly monetizable.
- **Trust and contractual damage**: "Any customer can read any other customer's data" is a reputational and B2B-contract failure, not just a technical one.

### Technical Impact

- **Horizontal escalation**: Access to peers' objects at the same privilege level (user A reads user B's data).
- **Vertical escalation**: Access to higher-privilege functionality (user becomes, in effect, an admin).
- **Integrity loss**: Not only reading but modifying or deleting objects the caller does not own.
- **Complete confidentiality loss for a data class**: One missing check on a list/detail endpoint can expose an entire table.

## Technical Context

### How the Authorization Decision Goes Wrong

#### 1. Authorization enforced only in the client (hiding vs. blocking)

The app decides what to show based on a role it holds locally, and never learns that the server must still block the action.

```kotlin
// Android (Kotlin): the app hides admin UI for non-admins...
if (currentUser.role == "admin") {
    showAdminPanel()
}
// ...but the admin endpoint itself has no server-side role check.
// An attacker skips the UI and calls it directly:
//   POST /api/admin/users/1001/promote   -> 200 OK
```

**Why it fails:** The `if` runs on the attacker's device. Removing it (patching the APK, hooking with Frida) or simply replaying the underlying HTTP request bypasses it completely.

#### 2. Server trusts a client-supplied role, permission, or user id

```http
POST /api/transfer HTTP/1.1
Authorization: Bearer <valid token for user 1001>
Content-Type: application/json

{ "from_user_id": 1002, "amount": 5000, "role": "admin" }
```

If the backend reads `from_user_id` or `role` from the request body instead of deriving them from the authenticated token, the caller has just declared themselves someone—or something—they are not. Identity and privilege must never be taken from data the client can edit.

#### 3. Insecure Direct Object Reference (IDOR) via the mobile API

```http
GET /api/accounts/1001/statements HTTP/1.1   # the app's own request
GET /api/accounts/1002/statements HTTP/1.1   # attacker changes the id
GET /api/accounts/1003/statements HTTP/1.1   # ...and enumerates everyone
```

The token is valid; the object is not the caller's. Without a per-object ownership check, the server happily returns another user's data. This is the most common concrete form of M6.

#### 4. Forced browsing to hidden / undocumented endpoints

The mobile UI never surfaces `/api/admin/...`, so developers assume it is safe. But the endpoint is reachable by anyone who observes the app's traffic once, or guesses conventional paths. "Not shown in the app" is not an access control.

#### 5. Trusting locally-stored entitlement flags

```
// Entitlements cached on-device and trusted by the app for gating:
SharedPreferences: { "is_premium": true, "tier": "enterprise" }
// Editable on a rooted device, via backup, or by hooking the getter.
```

Feature entitlements (premium/paid tiers, feature flags) enforced from local storage are trivially flipped. The server must be the authority on what the account is entitled to.

### Horizontal vs. Vertical Escalation

| Dimension | Horizontal escalation | Vertical escalation |
|-----------|-----------------------|---------------------|
| **Definition** | Reach objects of *other users at the same level* | Reach functionality of a *higher privilege level* |
| **Typical trigger** | Change an object id / reference (IDOR) | Call an admin/privileged endpoint directly |
| **Example** | User 1001 reads user 1002's statements | Normal user promotes their own account to admin |
| **Root fix** | Per-object ownership check on every access | Role/permission check on every privileged route |

## Real-World Impact

The examples below are described as **classes of incident** that recur across mobile and API assessments, not as specific attributed CVEs. The pattern is what matters; each has been observed repeatedly in the wild.

### Incident Class 1: IDOR on a mobile banking / fintech API

**Setup**: The app fetched account details at `/api/accounts/{accountId}/...`. The server verified the token was valid (authentication) but never verified that `{accountId}` belonged to the caller (authorization).

**Impact**: Any authenticated customer could increment or substitute the account id and read balances, statements, and personal details of other customers—mass exposure of financial PII from a single missing ownership check.

**Root cause**: Authorization treated as "has a valid token" rather than "is allowed *this specific object*."

### Incident Class 2: Vertical escalation via a direct admin call

**Setup**: The admin console was a hidden section of the same app. The client checked a local `role` before revealing admin screens, but the admin API endpoints performed no server-side role check.

**Impact**: A standard user who observed the app's traffic once could replay the admin requests (create users, change other users' data, alter entitlements) directly—full vertical escalation with an ordinary account.

**Root cause**: Authorization enforced in the UI only; privileged routes trusted that "the app wouldn't call them."

### Incident Class 3: Trusted client-supplied identity on a multi-tenant API

**Setup**: A B2B mobile app sent a `tenant_id` / `org_id` in each request body and the backend scoped queries to that value.

**Impact**: Changing the id in the request returned another organization's data—cross-tenant breach—because the tenant scope came from the client instead of from the authenticated principal's server-side record.

**Root cause**: The scoping identifier was attacker-controlled input rather than a property of the verified session.

## Prevalence and Severity

Authorization flaws are consistently among the most common and most impactful issues found in mobile and API assessments. In the OWASP *API* Security Top 10 the closely-related object- and function-level authorization failures (BOLA/BFLA) sit at the very top of the list, which reflects how routinely these defects appear behind mobile front-ends—because the mobile client and the API it calls share the same weakness.

- **Prevalence**: High. Authorization is per-endpoint and per-object, so a large app has hundreds of places to get it wrong, and one omission is enough.
- **Detectability for an attacker**: High. Intercepting one request and changing an id or a role field is a low-skill, high-yield probe.
- **Impact**: Moderate to severe—from reading one extra record up to full dataset exposure or administrative takeover.

> Rather than quote a single percentage, treat this as the durable takeaway: authorization defects are common, cheap for an attacker to find, and frequently critical in impact. The 2016 edition lists them as their own category (M6) precisely because they are so prevalent and are missed when teams focus only on login (M4).

## Common Misunderstandings

### Myth 1: "If the button isn't in the app, the user can't do it"

**Reality**: The UI is a suggestion. The attacker sends HTTP, not taps. Every capability the API exposes must be independently guarded on the server, whether or not any screen surfaces it.

### Myth 2: "The token is valid, so the request is authorized"

**Reality**: A valid token proves *who* is calling (authentication). It says nothing about whether that caller may touch *this object* or invoke *this function*. Authorization is a separate check that must run after identity is established.

### Myth 3: "We obfuscated the app / used certificate pinning, so nobody sees the API"

**Reality**: Obfuscation and pinning raise effort, not certainty. Determined testers unpack apps and bypass pinning routinely. Security through obscurity of the client is never an authorization control.

### Myth 4: "Authorization is the same as authentication"

**Reality**: They are distinct (M4 vs. M6). Perfect login does not grant per-object or per-function permission checks; you can authenticate flawlessly and still leak every user's data through one IDOR.

### Myth 5: "We send the role from the app, and the app is ours"

**Reality**: The app runs on the attacker's device. Any value it sends—role, permission, user id, tenant, entitlement—is attacker-controlled input. Derive privilege from server-side state keyed by the authenticated principal.

### Myth 6: "IDs are random UUIDs, so IDOR is impossible"

**Reality**: Unguessable ids raise the bar but are not an access control. UUIDs leak (logs, referrals, previous responses, shared links), and "hard to guess" is not "not allowed." Still perform the ownership check.

## How M6 Differs from Related Categories

| Aspect | M6 Insecure Authorization | M4 Insecure Authentication | M2 Insecure Data Storage |
|--------|---------------------------|----------------------------|--------------------------|
| **Core question** | May this identity do this? | Is this really that identity? | Is data on the device protected? |
| **Attacker** | Authenticated, low-privilege | Unauthenticated/impersonating | Has device / storage access |
| **Typical bug** | Missing/client-side authz, IDOR | Weak token, skippable login | Secrets in plaintext prefs/DB |
| **Primary fix** | Server-side per-request checks | Strong server-side auth | Encrypt / don't store |

## Key Takeaways

1. **Authorization is a server decision.** The client may hide UI for convenience, but only the server can block an action.
2. **Never trust client-supplied identity or privilege.** Derive user id, role, tenant, and entitlements from the authenticated session/token, not from the request body or local storage.
3. **Check ownership on every object access.** A valid token is not permission to touch a specific record—IDOR is the most common concrete form of M6.
4. **Guard every privileged route.** Hidden and undocumented endpoints still need role/permission checks; the UI not showing them is not protection.
5. **M6 is not M4.** You can authenticate perfectly and still fail authorization catastrophically.

## How to Identify if You're Vulnerable

Ask these questions about your mobile app and its backend:

- [ ] Does the server re-check permissions on *every* request, independent of the app's UI state?
- [ ] Is the caller's identity derived *only* from the verified token/session (never from a body/query/header the client sets)?
- [ ] Is there a per-object ownership check before returning or modifying any object referenced by id?
- [ ] Do privileged/admin endpoints verify a role stored server-side, not one sent by the client?
- [ ] If you strip the app's UI checks (or replay raw requests), does the backend still refuse unauthorized actions?
- [ ] Are entitlements (premium/tier/feature flags) enforced server-side rather than from local storage?
- [ ] Is the default answer "deny," so a route with no explicit check fails closed?
- [ ] Have you tested with two accounts, swapping ids/roles between them, to confirm isolation?

If you answered "no" or "not sure" to several of these, you likely have exploitable authorization gaps behind your mobile app today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers intercept, tamper, and escalate
- **[Prevention](prevention.md)**: Enforce authorization on the server, every time
- **[Examples](examples.md)**: Vulnerable vs. secure across Android, iOS, and the backend
- **[Mobile Learning Path](/learn/mobile)**: Continue the OWASP Mobile Top 10
- **[Practice](/practice)**: Apply these techniques in the hands-on challenges
