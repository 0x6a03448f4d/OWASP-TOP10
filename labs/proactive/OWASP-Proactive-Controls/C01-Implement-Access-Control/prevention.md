# C1: Implement Access Control - How to Implement

## Table of Contents
- [Implementation Strategy Overview](#implementation-strategy-overview)
- [1. Deny by Default](#1-deny-by-default)
- [2. Enforce Server-Side on Every Request](#2-enforce-server-side-on-every-request)
- [3. Centralize Authorization Logic](#3-centralize-authorization-logic)
- [4. Record-Level Ownership Checks (Stop IDOR)](#4-record-level-ownership-checks-stop-idor)
- [5. Least Privilege](#5-least-privilege)
- [6. Choose an Authorization Model](#6-choose-an-authorization-model)
- [7. Check Every Reference, Not the UI](#7-check-every-reference-not-the-ui)
- [8. Log Failures and Make Policy Auditable](#8-log-failures-and-make-policy-auditable)
- [9. Test the Control](#9-test-the-control)
- [Implementation Checklist](#implementation-checklist)

## Implementation Strategy Overview

Implementing C1 is not one check in one place; it is a small number of principles applied *everywhere consistently*. The goal is to make "authorized" the only path to a resource, and to make that path go through code you can review, test, and observe.

1. Make **deny** the default outcome of every decision.
2. Enforce every decision **server-side**, on **every request**.
3. Route decisions through a **centralized** authorization layer.
4. Check **record-level ownership**, not just role, on every object reference.
5. Apply **least privilege**, choose a fitting **model** (RBAC/ABAC/ReBAC), and enforce at the **data/function layer**.
6. **Log** failures, keep the policy **auditable**, and **test** the control.

> **Core discipline**: authority must be derived only from trusted server-side state and checked against the *specific* resource being accessed, on *every* access. Everything below is an application of that one sentence.

## 1. Deny by Default

Structure the authorization layer so that the absence of an explicit grant means refusal. New routes, fields, and actions are then closed until deliberately opened — the forgotten check fails safe instead of failing open.

```javascript
// Express: a global gate that denies anything not explicitly allowed.
// Mounted BEFORE route handlers, so an unguarded route is refused, not served.
app.use((req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'authentication required' });
  req.authorize = (allowed) => {
    if (!allowed) throw new ForbiddenError();   // default path is DENY
    return true;
  };
  next();
});
```

```python
# Deny-by-default framing for any handler:
def authorize(subject, action, resource):
    decision = policy.evaluate(subject, action, resource)
    if decision is not ALLOW:      # None, DENY, or error all fall here
        raise Forbidden()          # closed unless explicitly ALLOW
    return True
```

Prefer allow-lists over block-lists: enumerate what *is* permitted, not what is forbidden. A block-list is one missed entry away from exposure.

## 2. Enforce Server-Side on Every Request

The client is attacker-controlled. Hidden fields, disabled buttons, and client-side role flags are presentation only. Re-decide authorization on the server for every request, and derive authority from the session/token, never from the request body or query.

```javascript
// WRONG: trusting client-supplied authority
const role = req.body.role;                    // attacker sets this
if (role === 'admin') { /* ... */ }

// RIGHT: authority comes from trusted server-side state
const subject = await users.findById(req.session.userId);   // server lookup
if (!policy.can(subject, 'admin:manage')) throw new ForbiddenError();
```

Rules:

- Never read `role`, `account_id`, `is_admin`, or entitlements from client input for a decision.
- Resolve the subject and their permissions from the server session or a verified token, then a trusted store.
- Verify token integrity (signature, expiry, audience) before trusting *any* claim — and still confirm sensitive permissions against server state.

## 3. Centralize Authorization Logic

Put the decision in one place so it is consistent, reviewable, and hard to forget. Handlers ask a shared component; they do not each re-implement the rules.

```javascript
// A single policy module -- the one source of truth for "can X do Y to Z?"
class Policy {
  can(subject, action, resource) {
    // 1. function-level: does the subject's role permit this action at all?
    if (!ROLE_ACTIONS[subject.role]?.has(action)) return false;
    // 2. record-level: for owned resources, must the subject own it?
    if (resource?.ownerId && resource.ownerId !== subject.id
        && subject.role !== 'admin') return false;
    return true;   // reached only on an explicit pass of BOTH gates
  }
}
module.exports = new Policy();
```

```javascript
// Every handler funnels through the same gate:
app.get('/api/invoices/:id', requireAuth, async (req, res, next) => {
  const invoice = await invoices.findById(req.params.id);
  if (!invoice) return res.status(404).end();
  if (!policy.can(req.user, 'invoice:read', invoice)) return res.status(403).end();
  res.json(invoice);
});
```

Mature stacks externalize this further into a dedicated policy engine (for example a policy-as-code service or a relationship/authorization service) so the rules live outside application code and can be audited and versioned independently.

## 4. Record-Level Ownership Checks (Stop IDOR)

The single most common breach is horizontal: one user reaching another's records. Role checks never catch it, because both users hold the same role. The fix is to verify, on *every* object reference, that the subject is entitled to *that specific record*.

### Pattern A: Scope the query to the subject
The strongest version makes it impossible to load a non-owned record at all — the ownership condition is part of the query, not a check after the fact.

```python
# Django ORM: filter by owner so a foreign id simply returns nothing
def get_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, owner=request.user)  # scoped
    return JsonResponse(serialize(order))
# Requesting someone else's id -> 404, never their data.
```

```sql
-- SQL: the owner is a WHERE condition, bound from the session, not the request
SELECT * FROM orders
WHERE id = :order_id
  AND owner_id = :session_user_id;   -- non-owner match => zero rows
```

### Pattern B: Load then verify ownership
```javascript
async function getDocument(req, res) {
  const doc = await documents.findById(req.params.id);
  if (!doc) return res.status(404).end();
  if (doc.ownerId !== req.user.id && !req.user.isAdmin) {
    log.warn('authz_denied', { user: req.user.id, doc: doc.id });
    return res.status(403).end();          // explicit ownership gate
  }
  res.json(doc);
}
```

> Apply the ownership check to **every verb** — read, update, delete, and any custom action — not just the GET. A common bug is a guarded read next to an unguarded delete on the same resource.

## 5. Least Privilege

Grant the minimum permission necessary, and grant it narrowly and temporarily.

- Default new users, services, and tokens to the **lowest useful role**.
- Prefer many **fine-grained permissions** over a few broad roles, so a grant does not carry unrelated power.
- Make elevation **explicit, scoped, and time-bounded** (for example, just-in-time admin), and **revoke promptly**.
- Give service accounts only the specific scopes they need — never a wildcard.

```python
# Permission catalog: small, specific grants composed into roles
PERMISSIONS = {
  'viewer':  {'order:read'},
  'staff':   {'order:read', 'order:refund'},
  'admin':   {'order:read', 'order:refund', 'user:manage'},
}
def has_permission(subject, perm):
    return perm in PERMISSIONS.get(subject.role, set())   # unknown role -> empty set -> deny
```

## 6. Choose an Authorization Model

Match the model to how your permissions are naturally described. Many systems combine coarse RBAC for function-level gates with ownership/attribute checks for record-level decisions.

| Model | Decision is based on | Best for | Watch out for |
|-------|----------------------|----------|---------------|
| RBAC | The subject's role(s) | Access mapping onto job functions | Cannot express ownership alone — add record checks |
| ABAC | Attributes of subject/resource/action/context | Fine-grained, context-dependent policy | Complexity; policy sprawl |
| ReBAC | Relationships in a graph (owner, member, shared) | Sharing and collaboration | Requires a relationship store and careful modeling |

```python
# ABAC-style decision: subject + resource + context attributes
def can_view_record(subject, record, ctx):
    return (
        subject.department == record.department       # attribute match
        and subject.clearance >= record.sensitivity   # ordered attribute
        and ctx.request_ip in CORPORATE_RANGES        # environment attribute
    )   # all must hold; default is deny
```

## 7. Check Every Reference, Not the UI

Enforce at the data and function layer, where the resource actually lives — not in the rendered page. Hiding a link is a usability nicety, not a control; the endpoint must refuse an unauthorized caller regardless of how they arrived.

- Guard **APIs**, not just server-rendered pages — most access is now direct API calls.
- Serve protected files through an **authorizing handler**, never straight from a public directory.
- Apply the check to **every discovered path**, including unlinked, staging, and legacy endpoints (deny by default handles the ones you forgot).

```python
# Protected file download: authorize BEFORE streaming bytes
def download(request, file_id):
    f = get_object_or_404(File, id=file_id, owner=request.user)   # ownership gate
    return FileResponse(open(f.secure_path, 'rb'))                # only then serve
# Files live outside the web root; there is no direct URL to guess.
```

## 8. Log Failures and Make Policy Auditable

The control should be observable. Log every denied decision with enough context to investigate, and alert on patterns that indicate enumeration or probing. Keep the policy expressed in a form you can review and prove.

```python
def deny(subject, action, resource):
    log.warning('authz_denied',
                subject=subject.id, role=subject.role,
                action=action, resource=getattr(resource, 'id', None),
                ip=request.remote_addr, ts=now())
    metrics.increment('authz.denied')      # alert when this spikes per-subject/IP
    raise Forbidden()
```

Alert on: bursts of denials from one subject or IP, a single subject touching many distinct object IDs, and denials on endpoints that should never be probed. For auditability, keep roles, permissions, and policy rules in version control and able to answer "who can do what to which resource?" on demand.

## 9. Test the Control

Access control that is not tested regresses silently. Assert the *negative* cases — that the wrong subject is denied — not only that the right one is allowed.

```javascript
// The tests that actually catch access-control regressions:
test('non-owner cannot read another user\'s invoice', async () => {
  const res = await agentAsUserA.get('/api/invoices/' + userBInvoiceId);
  expect(res.status).toBe(403);            // or 404 if you hide existence
});

test('standard user cannot call admin endpoint', async () => {
  const res = await agentAsStandardUser.post('/api/admin/users/55/role')
                     .send({ role: 'admin' });
  expect(res.status).toBe(403);
});

test('client-supplied role in body is ignored', async () => {
  const res = await agentAsStandardUser.post('/api/account/update')
                     .send({ role: 'admin' });
  const me = await agentAsStandardUser.get('/api/account');
  expect(me.body.role).toBe('user');       // server did not honor the body
});
```

Add these as a standing suite: for each protected resource, test owner-allowed, non-owner-denied, and lower-privilege-denied. Include access-control probes (IDOR, forced browsing, method tampering) in security testing and code review.

## Implementation Checklist

- [ ] Default decision is **deny**; access requires an explicit grant.
- [ ] Every decision is made **server-side**; no authority is read from client input.
- [ ] Authorization is **centralized** in one reviewable component or service.
- [ ] Every object reference has a **record-level ownership/tenant check** (queries scoped to the subject where possible).
- [ ] The ownership check covers **every verb** — read, create, update, delete, custom actions.
- [ ] **Least privilege**: new subjects default low; elevation is scoped and revocable.
- [ ] Sensitive functions are gated by a **server-side function-level check**, not the UI.
- [ ] Protected files are served through an **authorizing handler**, not a public directory.
- [ ] Token claims are **verified** and sensitive permissions re-checked against server state.
- [ ] Access-control **failures are logged and alerted** on.
- [ ] The policy is **auditable** and covered by **negative tests** (non-owner and lower-privilege denied).

## Key Takeaways

1. **Deny by default** makes the forgotten check fail safe instead of failing open.
2. **Derive authority from server state** — never from a role or ID in the request.
3. **Centralize the decision** so it is consistent, testable, and protects new code automatically.
4. **Ownership checks on every reference** are what actually stop IDOR and cross-tenant breaches.
5. **Log, audit, and test** — an unobserved, untested control decays into a broken one.

## Next Steps

- **[Examples](examples.md)**: Missing-control vs. control-applied code in Node, Python, and Java
- **[Threats Addressed](attack-vectors.md)**: The failures this implementation prevents
- **[Proactive Controls](/learn/proactive)**: Return to the full OWASP Proactive Controls catalog
- **[Practice](/practice)**: Implement and verify the control hands-on
