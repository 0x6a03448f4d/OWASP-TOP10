# C1: Implement Access Control - Code Examples

Each pair below shows the **missing-control** version (the vulnerability) and the **control-applied** version (C1 correctly implemented) in the same framework. The examples focus on the failures that dominate real findings: missing ownership checks (IDOR), UI-only function gates, and trusting client-supplied authority.

> **Reading guide**: "Missing control" is what an attacker exploits; "Control applied" is the deliberate defense. The difference is almost always a single server-side check on the *specific resource*, derived from *trusted state*.

## Example 1 — Record-Level Ownership (Node.js / Express)

### Missing control (IDOR)
```javascript
const express = require('express');
const app = express();

// Authenticated, but the handler never checks WHO owns the invoice.
app.get('/api/invoices/:id', requireAuth, async (req, res) => {
    const invoice = await db.invoices.findById(req.params.id);
    res.json(invoice);          // any logged-in user reads ANY invoice by id
});
// GET /api/invoices/1044 with user A's token returns user B's invoice.
```

### Control applied
```javascript
const express = require('express');
const app = express();

app.get('/api/invoices/:id', requireAuth, async (req, res) => {
    const invoice = await db.invoices.findById(req.params.id);
    if (!invoice) return res.status(404).end();

    // Record-level ownership check: authority from the session, not the request.
    const isOwner = invoice.ownerId === req.user.id;
    if (!isOwner && req.user.role !== 'admin') {
        log.warn('authz_denied', { user: req.user.id, invoice: invoice.id });
        return res.status(403).end();      // non-owner is refused
    }
    res.json(invoice);
});
```

Even stronger — make a foreign id unloadable by scoping the query to the owner:
```javascript
const invoice = await db.invoices.findOne({ id: req.params.id, ownerId: req.user.id });
if (!invoice) return res.status(404).end();   // someone else's id => not found
res.json(invoice);
```

## Example 2 — Function-Level Authorization (Python / Flask)

### Missing control (privilege escalation)
```python
from flask import Flask, request, jsonify
app = Flask(__name__)

# The admin link is simply hidden in the UI; the endpoint itself is open
# to any authenticated user.
@app.route('/api/admin/users/<int:uid>/role', methods=['POST'])
@login_required
def set_role(uid):
    new_role = request.json['role']
    db.users.update(uid, role=new_role)     # no server-side role check
    return jsonify(status='ok')
# A standard user POSTs here directly and makes themselves admin.
```

### Control applied
```python
from functools import wraps
from flask import Flask, request, jsonify, abort, g
app = Flask(__name__)

def require_permission(permission):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Authority is looked up from trusted server-side state, per request.
            subject = db.users.get(g.session_user_id)
            if permission not in PERMISSIONS.get(subject.role, set()):
                log.warning('authz_denied user=%s perm=%s', subject.id, permission)
                abort(403)                  # deny by default
            return fn(*args, **kwargs)
        return wrapper
    return decorator

PERMISSIONS = {'user': {'profile:edit'}, 'admin': {'profile:edit', 'user:manage'}}

@app.route('/api/admin/users/<int:uid>/role', methods=['POST'])
@login_required
@require_permission('user:manage')          # centralized, server-side gate
def set_role(uid):
    db.users.update(uid, role=request.json['role'])
    return jsonify(status='ok')
```

## Example 3 — Ownership via Query Scoping (Python / Django)

### Missing control
```python
def get_order(request, order_id):
    order = Order.objects.get(id=order_id)      # not scoped to the user
    return JsonResponse(serialize(order))       # returns anyone's order
```

### Control applied
```python
from django.shortcuts import get_object_or_404

def get_order(request, order_id):
    # The owner is part of the lookup: a foreign id yields 404, never data.
    order = get_object_or_404(Order, id=order_id, owner=request.user)
    return JsonResponse(serialize(order))

# Apply the SAME scoping to update and delete -- not just read:
def delete_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, owner=request.user)
    order.delete()
    return JsonResponse(status='deleted')
```

## Example 4 — Not Trusting Client Authority (Java / Spring Boot)

### Missing control (metadata tampering)
```java
@RestController
class AccountController {

    // Trusts a role supplied in the request body.
    @PostMapping("/api/account/update")
    public ResponseEntity<?> update(@RequestBody AccountUpdate body) {
        User u = userRepo.findById(body.getUserId()).orElseThrow();
        u.setRole(body.getRole());          // client said role=admin -> honored
        userRepo.save(u);
        return ResponseEntity.ok().build();
    }
}
```

### Control applied
```java
@RestController
class AccountController {

    // Authority comes from the authenticated principal, never the body.
    @PostMapping("/api/account/update")
    public ResponseEntity<?> update(@AuthenticationPrincipal UserDetails principal,
                                    @RequestBody AccountUpdate body) {
        User u = userRepo.findByUsername(principal.getUsername()).orElseThrow();
        u.setEmail(body.getEmail());        // only non-privileged fields accepted
        // role is NEVER set from client input; changing roles is a separate,
        // permission-gated admin operation.
        userRepo.save(u);
        return ResponseEntity.ok().build();
    }
}
```

### Method-level authorization (Spring Security)
```java
@RestController
class AdminController {

    // Deny-by-default gate declared centrally; enforced server-side per call.
    @PreAuthorize("hasAuthority('USER_MANAGE')")
    @PostMapping("/api/admin/users/{id}/role")
    public ResponseEntity<?> setRole(@PathVariable Long id, @RequestBody RoleDto dto) {
        userService.changeRole(id, dto.getRole());
        return ResponseEntity.ok().build();
    }

    // Record-level check for owned resources via a SpEL ownership expression:
    @PreAuthorize("@ownership.isOwner(authentication, #docId)")
    @DeleteMapping("/api/documents/{docId}")
    public ResponseEntity<?> delete(@PathVariable Long docId) {
        documentService.delete(docId);
        return ResponseEntity.noContent().build();
    }
}
```

## Example 5 — Protected File Download (Node.js / Express)

### Missing control
```javascript
// Static directory served directly: anyone who guesses a path gets the file.
app.use('/uploads', express.static('/var/data/uploads'));
// GET /uploads/patient-7312-scan.pdf -> streamed with no ownership check.
```

### Control applied
```javascript
// Files live OUTSIDE the web root; delivery goes through an authorizing handler.
app.get('/files/:id', requireAuth, async (req, res) => {
    const file = await db.files.findOne({ id: req.params.id, ownerId: req.user.id });
    if (!file) return res.status(404).end();     // not owned => not found
    res.sendFile(file.securePath, { root: '/var/data/private' });
});
```

## What Changed, and Why

| Threat | Missing control | Control applied (C1) |
|--------|-----------------|----------------------|
| IDOR / BOLA | Serve record by id, no owner check | Ownership check / query scoped to the subject |
| Privilege escalation | Admin endpoint open, link hidden in UI | Server-side function-level permission gate |
| Metadata tampering | Role taken from request body | Authority from authenticated principal only |
| Unchecked write verbs | Delete/update not authorized | Same ownership check on every verb |
| Direct file access | Static public directory | Authorizing handler, files outside web root |

The pattern is uniform: in every "control applied" version, the decision is made **server-side**, uses authority from **trusted state**, checks the **specific resource**, and **defaults to deny**. That is C1.

## Next Steps

- **[How to Implement](prevention.md)**: The full layered implementation strategy
- **[Threats Addressed](attack-vectors.md)**: What these controls prevent
- **[Proactive Controls](/learn/proactive)**: Return to the full OWASP Proactive Controls catalog
- **[Practice](/practice)**: Apply missing-control vs. control-applied fixes hands-on
