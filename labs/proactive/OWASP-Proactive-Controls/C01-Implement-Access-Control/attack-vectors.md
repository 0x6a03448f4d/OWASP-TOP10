# C1: Implement Access Control - Threats Addressed

## Table of Contents
- [Threats Addressed — What Goes Wrong Without It](#threats-addressed--what-goes-wrong-without-it)
- [The Threats This Control Prevents](#the-threats-this-control-prevents)
- [How These Threats Chain](#how-these-threats-chain)
- [Mapping Threats to the Control](#mapping-threats-to-the-control)

## Threats Addressed — What Goes Wrong Without It

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you understand the threats the access-control *control* neutralizes, and can verify your own systems. This page describes what attackers do *when the control is missing or weak*; the [How to Implement](prevention.md) page shows how to shut each one down.

This is the inverse view of C1. Where the [overview](overview.md) defines the control, this page catalogs the concrete failures that appear in its absence. Every item below is a symptom of one missing property: no deny-by-default, no server-side check, no record-level ownership check, or authority trusted from the client. Read each as "here is the hole the control fills."

The unifying theme is cheapness. Broken access control is exploited not with elaborate payloads but by **changing a value and re-sending an ordinary request**. An identifier becomes a different identifier; a hidden field becomes `admin`; an unlinked path is requested directly. That low cost is exactly why OWASP ranks the risk first — and why the control matters.

## The Threats This Control Prevents

### 1. Broken Object-Level Authorization (IDOR / BOLA)

The canonical failure. A resource is served by an identifier taken from the request, and the server never checks that the caller owns it. Incrementing or swapping the identifier returns another user's data.

```http
GET /api/invoices/1043 HTTP/1.1      # my own invoice -> 200 OK
Authorization: Bearer <valid-token-for-user-A>

GET /api/invoices/1044 HTTP/1.1      # someone ELSE's invoice
Authorization: Bearer <valid-token-for-user-A>
-> 200 OK  { "customer": "user-B", "total": 4820.00, ... }
```

```bash
# Scripted, this becomes a full export:
for id in $(seq 1 100000); do
  curl -s -H "Authorization: Bearer $TOKEN" https://api.target/api/invoices/$id
done
```

**Missing property**: a record-level ownership check (*does subject A own invoice 1044?*). **The control**: verify entitlement to the specific object on every reference.

### 2. Broken Function-Level Authorization (Privilege Escalation)

An administrative or sensitive function is reachable by any authenticated session because the function-level check was assumed to be handled by the UI hiding the link.

```http
# A normal user simply calls the admin endpoint directly:
POST /api/admin/users/55/role HTTP/1.1
Authorization: Bearer <valid-token-for-a-STANDARD-user>
Content-Type: application/json

{"role":"admin"}
-> 200 OK      # no server-side role check -> standard user is now admin
```

**Missing property**: a deny-by-default, server-side function-level check. **The control**: gate every privileged function on the server, independent of the UI.

### 3. Vertical Privilege Escalation via Parameter / Metadata Tampering

The request carries its own authority — a client-supplied role, tier, or flag — and the server trusts it instead of deriving authority from server-side state.

```json
POST /api/account/update
{ "email": "attacker@evil.com",
  "role": "admin",
  "account_tier": "enterprise" }
-> 200 OK   # server persisted role=admin because it trusted the body
```

```html
<!-- Hidden fields are not a control; the attacker edits them at will -->
<input type="hidden" name="role" value="user">   <!-- changed to "admin" -->
```

**Missing property**: authority derived only from trusted server-side state. **The control**: ignore client-supplied roles/permissions; look up the subject's real privileges server-side.

### 4. Horizontal Privilege Escalation (Cross-Tenant / Cross-User)

A user reaches another user's data *at the same privilege level* by supplying someone else's identifier. Role checks pass because the roles are identical — only ownership differs.

```http
GET /api/users/me/messages?account_id=8842 HTTP/1.1   # not my account
Authorization: Bearer <valid-token-for-account-7311>
-> 200 OK   # server keyed off the client-supplied account_id, not the token
```

**Missing property**: scoping every query to the authenticated subject's own tenant/records. **The control**: derive the owning account from the session/token, never from a request parameter.

### 5. Forced Browsing to Unprotected Resources

Sensitive endpoints are "protected" only by not being linked. Attackers discover them through wordlists, JavaScript, sitemaps, and history, and reach them directly.

```http
# Discovered via a content-discovery wordlist, never linked in the UI:
GET /admin/dashboard           -> 200 OK   (should require admin)
GET /reports/2026/export.csv   -> 200 OK   (bulk data, unauthenticated)
GET /api/internal/debug        -> 200 OK   (staging endpoint in prod)
GET /user/1/settings           -> 200 OK   (another user's settings)
```

**Missing property**: enforcement on the resource itself, regardless of how it was reached. **The control**: deny by default; authorize every resource independently of whether it is linked.

### 6. Insecure Direct Access to Static / Stored Files

Files are served from a predictable path with no per-request authorization, so any user who knows or guesses the path downloads any other user's upload.

```http
GET /uploads/medical/patient-7311-scan.pdf HTTP/1.1
-> 200 OK   # web server streams the file with no ownership check

# Predictable naming makes enumeration trivial:
GET /uploads/medical/patient-7312-scan.pdf   -> 200 OK  (not mine)
```

**Missing property**: authorization in front of file delivery. **The control**: serve protected files through an authorizing handler that checks ownership, never straight from a public directory.

### 7. Missing Authorization on State-Changing Methods

Read paths are checked but write/delete paths on the same resource are not — or only some HTTP methods are gated.

```http
GET    /api/documents/900   -> 403  (read is correctly denied to non-owners)
DELETE /api/documents/900   -> 204  (delete is NOT checked -> data destroyed)
PUT    /api/documents/900   -> 200  (overwrite is NOT checked -> tampering)
```

**Missing property**: the same ownership/role check on *every* verb and action. **The control**: authorize the action, not just the read; cover create/update/delete uniformly.

### 8. Trusting Unverified Token Claims

The application reads authority from a token or cookie without validating it server-side, so a forged or altered claim is honored.

```json
# JWT payload edited; signature not verified, or "alg":"none" accepted:
{ "sub": "user-A", "role": "admin" }   # attacker changed role from "user"
-> server grants admin because it trusted the decoded claim
```

**Missing property**: cryptographic verification plus a server-side authority lookup. **The control**: verify token integrity *and* resolve real permissions from trusted state, not from unverified claims.

### 9. Enumeration Without Detection

Even where individual checks exist, the absence of logging lets an attacker probe thousands of object references undetected until they find the one gap.

```
# 40,000 requests, 39,997 denied, 3 succeed -- and nobody is alerted:
GET /api/orders/1  403
GET /api/orders/2  403
...                       # a wall of denials that should have triggered an alarm
GET /api/orders/7311  200 # the one missed check, now being harvested
```

**Missing property**: logging and alerting on access-control failures. **The control**: record every denial with subject/resource/action and alert on abnormal denial rates.

### Threat Summary

| # | Threat | Attacker action | Missing property the control supplies |
|---|--------|-----------------|----------------------------------------|
| 1 | IDOR / BOLA | Swap a record ID | Record-level ownership check |
| 2 | Broken function-level authz | Call an admin endpoint directly | Server-side function gate, deny by default |
| 3 | Parameter/metadata tampering | Send `role=admin` | Authority from server state only |
| 4 | Horizontal escalation | Supply another account_id | Scope queries to the subject |
| 5 | Forced browsing | Request an unlinked path | Deny by default on every resource |
| 6 | Direct file access | Guess a file path | Authorize file delivery |
| 7 | Unchecked write methods | DELETE/PUT a non-owned record | Authorize every action/verb |
| 8 | Trusting token claims | Edit a JWT claim | Verify + server-side lookup |
| 9 | Undetected enumeration | Probe IDs at scale | Log and alert on failures |

## How These Threats Chain

In real incidents these rarely appear alone. A single missing check becomes a full breach when combined:

```
Forced browsing finds /api/users/{id}      -> endpoint has no ownership check
        +
IDOR over the id parameter (1..N)          -> enumerate every user record
        +
No logging on repeated 200s from one IP    -> harvesting goes unnoticed
        =  full customer database exfiltrated with ordinary GET requests
```

```
Parameter tampering sets role=admin        -> server trusts client authority
        +
Function-level endpoint unprotected        -> /api/admin/* now reachable
        =  standard account escalates to full application takeover
```

## Mapping Threats to the Control

Every threat above is defeated by one or more properties of C1. That is the point of implementing the control as a coherent whole rather than patching symptoms:

- **Deny by default** -> neutralizes forced browsing and forgotten endpoints (5, 7).
- **Server-side enforcement** -> neutralizes UI-only "security," hidden-field and claim tampering (2, 3, 8).
- **Record-level ownership checks** -> neutralize IDOR, cross-tenant access, and direct file access (1, 4, 6).
- **Authorize every action** -> neutralizes unchecked write/delete methods (7).
- **Least privilege** -> shrinks the impact of any single escalation (2, 3).
- **Log and alert on failures** -> neutralizes silent enumeration (9).

## Key Takeaways

1. **These are symptoms of one absent control** — not nine unrelated bugs. Implement C1 and the whole family closes.
2. **Exploitation is cheap** — changing an ID or a field and re-sending is the entire technique.
3. **Horizontal beats vertical in the wild** — most breaches are user-reaching-user, which role checks alone miss.
4. **The UI is never the control** — every threat here bypasses the browser and calls the server directly.
5. **Silence is a vulnerability** — without logging, enumeration succeeds by attrition.

## Next Steps

- **[How to Implement](prevention.md)**: Build the control that shuts every threat above
- **[Examples](examples.md)**: Missing-control vs. control-applied code side by side
- **[Proactive Controls](/learn/proactive)**: Return to the full OWASP Proactive Controls catalog
- **[Practice](/practice)**: Try to find and fix these threats hands-on
