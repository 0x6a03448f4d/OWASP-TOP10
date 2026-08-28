# M6:2016 Insecure Authorization - Prevention

## Prevention Strategy Overview

There is one governing rule for M6, and everything else is detail:

> **Enforce every authorization decision on the server, on every request, using an identity the client cannot influence.** The mobile app may hide, disable, or omit UI for a better experience—but it must never be the thing that *blocks* an action.

Concretely, that decomposes into five principles:

1. **Server-side is the only side.** Re-check permissions on the backend for every endpoint and every object—never assume the client already did.
2. **Derive identity from the token/session, never from client input.** User id, role, tenant, and entitlements come from the authenticated principal, not from the body, query, or headers.
3. **Check ownership per object.** Before returning or mutating any object referenced by id, verify it belongs to (or is shared with) the caller.
4. **Deny by default, least privilege.** A route with no explicit allow decision fails closed; grant the narrowest rights that work.
5. **Keep authorization logic out of the client.** The app enforces nothing security-relevant; it merely reflects decisions the server already made.

## 1. Enforce Authorization on the Server, Every Request

Authentication (who you are) and authorization (what you may do) are two checks. The second one is the one mobile apps skip. Make it mandatory and centralized so no route can forget it.

```javascript
// Node/Express: identity from the verified token ONLY, then per-request authz
const jwt = require('jsonwebtoken');

function authenticate(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    // The principal is whatever the SIGNED token says — never the request body.
    req.principal = jwt.verify(token, process.env.JWT_PUBLIC_KEY);
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthenticated' });
  }
}

// Deny-by-default role gate for privileged routes.
function requireRole(role) {
  return (req, res, next) => {
    // req.principal.role comes from the server-signed token / a server lookup,
    // NOT from req.body.role.
    if (req.principal?.role !== role) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

app.post('/api/admin/users/:id/promote',
  authenticate, requireRole('admin'), promoteHandler);   // blocked for non-admins
```

```python
# Python/FastAPI: same shape — identity is a server-verified dependency
from fastapi import Depends, HTTPException

def current_principal(token: str = Depends(bearer_token)) -> Principal:
    # Verifies the signature and loads the principal from server-side state.
    return verify_and_load(token)          # raises 401 on failure

def require_role(role: str):
    def dep(p: Principal = Depends(current_principal)) -> Principal:
        if p.role != role:                 # role is server-side, not client input
            raise HTTPException(403, "Forbidden")
        return p
    return dep

@app.post("/api/admin/users/{user_id}/promote")
def promote(user_id: int, p: Principal = Depends(require_role("admin"))):
    ...
```

## 2. Never Trust Client-Supplied Identity or Privilege

The most dangerous line of code in a mobile backend is one that reads *who* or *what* from the request. Identity and privilege are properties of the authenticated session, not payload fields.

```javascript
// VULNERABLE — trusts the body
app.post('/api/transfer', authenticate, (req, res) => {
  const fromUserId = req.body.from_user_id;   // attacker sets this to anyone
  transfer(fromUserId, req.body.amount);
});

// SECURE — identity comes from the verified principal
app.post('/api/transfer', authenticate, (req, res) => {
  const fromUserId = req.principal.sub;        // server-derived, unforgeable
  transfer(fromUserId, req.body.amount);       // amount is data; identity is not
});
```

The same applies to `role`, `tenant_id`/`org_id`, `is_premium`, and any entitlement. Scope every query by the principal's server-side tenant, not a client-sent one.

## 3. Per-Object Ownership Checks (Stop IDOR)

A valid token is not permission to touch a specific object. Before reading or mutating any resource addressed by id, confirm the caller is entitled to *that* resource.

```javascript
// VULNERABLE — returns any account for any authenticated user (IDOR)
app.get('/api/accounts/:id/statements', authenticate, async (req, res) => {
  const acct = await Accounts.findById(req.params.id);
  res.json(await acct.statements());
});

// SECURE — scope by owner, or verify ownership explicitly
app.get('/api/accounts/:id/statements', authenticate, async (req, res) => {
  const acct = await Accounts.findOne({
    _id: req.params.id,
    ownerId: req.principal.sub        // ownership is part of the lookup
  });
  if (!acct) return res.status(404).json({ error: 'Not found' });  // don't leak existence
  res.json(await acct.statements());
});
```

```python
# Python — explicit ownership assertion before use
acct = repo.get_account(account_id)
if acct is None or acct.owner_id != principal.id:
    raise HTTPException(404, "Not found")   # 404, not 403, to avoid confirming the id exists
return acct.statements()
```

> Returning `404 Not Found` rather than `403 Forbidden` for objects the caller doesn't own avoids confirming that an id exists—a small but useful reduction in enumeration signal. Pick one convention and apply it consistently.

## 4. Deny by Default and Least Privilege

- **Fail closed**: the framework default for any route must be "authenticated + explicitly authorized." A new endpoint with no decorator/middleware should be unreachable, not open.
- **Centralize the policy**: use one authorization layer (middleware, policy objects, a policy engine) so checks can't be forgotten per-route. Enumerate what each role/permission may do, and grant nothing beyond it.
- **Prefer permissions over role name checks**: gate on a specific capability (`can_refund`, `can_export`) rather than scattering `if role == 'admin'`, which drifts as roles multiply.

```python
# Deny-by-default policy check (framework-agnostic pseudocode)
def authorize(principal, action, resource):
    # No matching grant -> deny. There is no implicit allow.
    if not policy.permits(principal, action, resource):
        raise Forbidden()
# Every handler calls authorize(...) before doing work.
```

## 5. Guard Against Mass Assignment

Never bind a whole request body onto a model. Allow-list the fields a user may set, so `role` or `balance` can't ride in on an update.

```javascript
// SECURE — explicit allow-list of user-settable fields
const ALLOWED = ['displayName', 'avatarUrl', 'locale'];
const updates = {};
for (const k of ALLOWED) if (k in req.body) updates[k] = req.body[k];
await Users.update({ _id: req.principal.sub }, updates);   // role/balance ignored
```

## 6. The Mobile Client's (Limited) Role

The client should still hide UI the user can't use—for usability, not security—and it must get the truth about entitlements from the server, never from local storage it can't protect.

```kotlin
// Android (Kotlin): UI reflects a SERVER decision; it does not make one.
// Fetch capabilities from the backend after login; render accordingly.
val caps = api.getMyCapabilities()          // server is the source of truth
if (caps.canAccessAdmin) adminButton.isVisible = true   // convenience only

// Do NOT gate on a locally-stored flag you can't trust:
//   if (prefs.getBoolean("is_admin", false)) { ... }   // editable on-device
```

```swift
// iOS (Swift): same principle — capabilities come from the server
let caps = try await api.myCapabilities()
adminButton.isHidden = !caps.canAccessAdmin   // UX hint, not a control
```

Crucially, even with this UI gating, **the server still enforces the check on every admin/privileged request**. If an attacker flips the boolean or removes the UI, the worst outcome is a visible-but-non-functional button—the action still returns `403`.

## 7. Don't Rely on Obscurity of the Client

- **Obfuscation, pinning, and root/jailbreak detection are defense-in-depth, not authorization.** They raise attacker effort; they never make a missing server check safe.
- **Hidden endpoints are not protected endpoints.** Every route needs a server-side check whether or not any screen calls it.
- **Unguessable ids (UUIDs) are not access control.** Ids leak; still check ownership.

## 8. Test Authorization Explicitly

Authorization bugs are invisible to single-account testing. Build the checks into your test suite and pentest scope.

```python
# Automated cross-account isolation test (pseudocode)
alice = login('alice'); bob = login('bob')
bobs_account = create_account(bob)

# Alice must NOT be able to read Bob's object:
resp = GET(f'/api/accounts/{bobs_account.id}/statements', token=alice.token)
assert resp.status in (403, 404), "IDOR: Alice read Bob's account!"

# A normal user must NOT reach an admin route:
resp = POST('/api/admin/users/1/promote', token=alice.token)
assert resp.status == 403, "Vertical escalation: non-admin promoted a user!"
```

Add these classes of test: cross-user object access (horizontal), privileged-route access as a normal user (vertical), client-supplied `role`/`user_id` ignored, and mass-assignment of privileged fields rejected. Run them in CI so a regression fails the build.

## Prevention Checklist

| Control | What it stops |
|---------|---------------|
| Server-side check on every request | UI-only/"hidden endpoint" bypass |
| Identity from token, never from body | Client-supplied role/user-id spoofing |
| Per-object ownership check | IDOR / horizontal escalation |
| Role/permission check on privileged routes | Vertical escalation |
| Deny by default, least privilege | Forgotten routes, over-broad grants |
| Field allow-lists on writes | Mass-assignment escalation |
| Server-authoritative entitlements | Local flag tampering |
| Cross-account tests in CI | Regressions shipping unnoticed |

## Key Takeaways

1. **The server decides, every time.** Re-check authorization on every request and every object—never trust that the client already did.
2. **Identity is unforgeable or it is worthless.** Derive user, role, and tenant from the verified token; ignore anything the client sends about who it is.
3. **Ownership checks kill IDOR.** Scope every object lookup by the caller, and fail closed when it doesn't match.
4. **The client only reflects decisions.** Hide UI for usability, but the app must never be the control that blocks an action.
5. **Test with two accounts.** Authorization flaws are invisible until you swap ids and roles between users—automate that in CI.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure across Android, iOS, and the backend
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Mobile Learning Path](/learn/mobile)**: Continue the OWASP Mobile Top 10
- **[Practice](/practice)**: Apply these defenses in the hands-on challenges
