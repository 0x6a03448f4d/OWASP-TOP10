# M6:2016 Insecure Authorization - Code Examples

Each pair below shows a **vulnerable** and a **secure** implementation. The recurring lesson across every example is the same: **authorization belongs on the server.** The mobile snippets (Android and iOS) show what the client should—and should not—do, and every one of them is paired with the backend check that is the actual control. If the backend is right, no client tampering matters; if the backend is wrong, no client code can save it.

**Read the mobile and backend halves together.** A "secure" client with an insecure backend is still insecure. The backend snippets (Node and Python) are where the vulnerability is truly fixed.

## Example 1: Client-Side-Only Authorization (Vertical Escalation)

### Vulnerable — Android (Kotlin): the app is the only gatekeeper

```
// The app decides who is admin based on a local flag, then calls the endpoint.
// There is NO server-side role check behind /admin/promote.
class AdminActions(private val api: ApiService, private val session: Session) {

    fun maybeShowAdminPanel(view: View) {
        // Gating the UI on a client-held value...
        if (session.role == "admin") {
            view.adminButton.visibility = View.VISIBLE
        }
    }

    fun promote(userId: Long) {
        // ...but the request itself carries no proof and the server checks nothing.
        api.promote(userId)   // POST /api/admin/users/{userId}/promote
    }
}
```

### Vulnerable — iOS (Swift): same mistake

```
final class AdminActions {
    let api: ApiService
    let session: Session

    func configureUI(_ button: UIButton) {
        // Client-side gate only — cosmetic, not a control.
        button.isHidden = session.role != "admin"
    }

    func promote(userId: Int) {
        // No server-side authorization behind this call.
        api.promote(userId: userId)   // POST /api/admin/users/{userId}/promote
    }
}
```

### Vulnerable — Backend (Node/Express): trusts that "the app wouldn't call this"

```
// Any authenticated user reaching this route succeeds — the UI was the "check".
app.post('/api/admin/users/:id/promote', authenticate, async (req, res) => {
  await Users.update({ _id: req.params.id }, { role: 'admin' });
  res.json({ ok: true });      // vertical escalation for anyone who calls it
});
```

**Why it fails:** The `if (role == "admin")` runs on the attacker's device. They remove it, or simply replay `POST /api/admin/users/1001/promote` with their own valid token. The server never re-checks, so the ordinary user becomes admin.

### Secure — Android (Kotlin): client reflects a server decision

```
// The client asks the server what it may do; the UI is a hint, not a gate.
class AdminActions(private val api: ApiService) {

    suspend fun configureUI(view: View) {
        val caps = api.getMyCapabilities()          // server is source of truth
        view.adminButton.isVisible = caps.canAdminister
    }

    suspend fun promote(userId: Long): Result<Unit> {
        // The server will independently authorize this. A 403 is handled gracefully.
        return runCatching { api.promote(userId) }
    }
}
```

### Secure — iOS (Swift): identical principle

```
final class AdminActions {
    let api: ApiService

    func configureUI(_ button: UIButton) async throws {
        let caps = try await api.myCapabilities()   // authoritative, from server
        button.isHidden = !caps.canAdminister       // UX only
    }

    func promote(userId: Int) async throws {
        try await api.promote(userId: userId)       // server enforces; may throw 403
    }
}
```

### Secure — Backend (Node/Express): the real control

```
// requireRole reads the role from the SIGNED token / server-side user record,
// never from the request body. Deny by default.
function requireRole(role) {
  return (req, res, next) =>
    req.principal?.role === role ? next()
                                 : res.status(403).json({ error: 'Forbidden' });
}

app.post('/api/admin/users/:id/promote',
  authenticate, requireRole('admin'), async (req, res) => {
    await Users.update({ _id: req.params.id }, { role: 'admin' });
    res.json({ ok: true });
  });
// A non-admin token -> 403, regardless of what the app's UI did.
```

### Secure — Backend (Python/FastAPI)

```
@app.post("/api/admin/users/{user_id}/promote")
def promote(user_id: int, p: Principal = Depends(require_role("admin"))):
    users.set_role(user_id, "admin")     # only reached if p.role == "admin"
    return {"ok": True}
```

## Example 2: IDOR — Missing Ownership Check (Horizontal Escalation)

### Vulnerable — Android (Kotlin): app passes an id it happens to hold

```
// The app requests the account it "knows" about. The id is just a number in a
// URL — trivially changed in a proxy. The client cannot enforce ownership.
suspend fun loadStatements(accountId: Long) =
    api.getStatements(accountId)      // GET /api/accounts/{accountId}/statements
```

### Vulnerable — Backend (Node/Express): returns any account to any user

```
app.get('/api/accounts/:id/statements', authenticate, async (req, res) => {
  const acct = await Accounts.findById(req.params.id);   // no ownership check
  res.json(await acct.statements());
});
// Attacker (user 1001) requests /api/accounts/1002/statements -> 200 OK.
```

### Vulnerable — Backend (Python/FastAPI)

```
@app.get("/api/accounts/{account_id}/statements")
def statements(account_id: int, p: Principal = Depends(current_principal)):
    acct = repo.get_account(account_id)      # any id, for any authenticated user
    return acct.statements()
```

### Secure — Backend (Node/Express): scope by owner

```
app.get('/api/accounts/:id/statements', authenticate, async (req, res) => {
  const acct = await Accounts.findOne({
    _id: req.params.id,
    ownerId: req.principal.sub          // ownership is part of the query
  });
  if (!acct) return res.status(404).json({ error: 'Not found' }); // don't leak existence
  res.json(await acct.statements());
});
```

### Secure — Backend (Python/FastAPI): explicit ownership assertion

```
@app.get("/api/accounts/{account_id}/statements")
def statements(account_id: int, p: Principal = Depends(current_principal)):
    acct = repo.get_account(account_id)
    if acct is None or acct.owner_id != p.id:
        raise HTTPException(404, "Not found")   # caller doesn't own it -> 404
    return acct.statements()
```

### Secure — iOS (Swift): the client is unchanged, and that's the point

```
// The client still just asks for its data. Security did NOT move to the app;
// the fix lives entirely in the backend's ownership check above.
func loadStatements(accountId: Int) async throws -> [Statement] {
    try await api.statements(accountId: accountId)   // 404 if not the caller's
}
```

**Key insight:** the mobile code barely changes between vulnerable and secure. The IDOR is fixed *only* on the server, by scoping the lookup to the authenticated owner. This is the clearest demonstration that authorization is not a client concern.

## Example 3: Trusting Client-Supplied Identity

### Vulnerable — Android (Kotlin): app sends who to act as

```
// The app includes a user id in the body. On a rooted device or via a proxy,
// the attacker changes fromUserId to someone else's.
data class TransferReq(val fromUserId: Long, val amount: Long)

suspend fun transfer(fromUserId: Long, amount: Long) =
    api.transfer(TransferReq(fromUserId, amount))   // POST /api/transfer
```

### Vulnerable — Backend (Node/Express): believes the body

```
app.post('/api/transfer', authenticate, async (req, res) => {
  await transfer(req.body.from_user_id, req.body.amount);  // acts as ANY user
  res.json({ ok: true });
});
```

### Secure — Backend (Node/Express): identity from the token

```
app.post('/api/transfer', authenticate, async (req, res) => {
  // The source account is derived from the verified principal, not the body.
  await transfer(req.principal.sub, req.body.amount);
  res.json({ ok: true });
});
```

### Secure — Backend (Python/FastAPI)

```
@app.post("/api/transfer")
def transfer_funds(body: TransferBody, p: Principal = Depends(current_principal)):
    # from_user is the authenticated principal; the client cannot choose it.
    do_transfer(from_user=p.id, amount=body.amount)
    return {"ok": True}
```

### Secure — Android (Kotlin): stop sending identity at all

```
// The body carries only data (amount + destination). Identity is implicit in
// the auth token the HTTP client already attaches.
data class TransferReq(val amount: Long, val toAccount: String)

suspend fun transfer(amount: Long, toAccount: String) =
    api.transfer(TransferReq(amount, toAccount))
```

## Example 4: Entitlement Enforced from Local Storage

### Vulnerable — iOS (Swift): premium gate read from UserDefaults

```
// A jailbroken device (or a backup edit) flips this flag to unlock features.
func canUsePremiumFeature() -> Bool {
    UserDefaults.standard.bool(forKey: "is_premium")   // attacker-editable
}
```

### Vulnerable — Android (Kotlin): same via SharedPreferences

```
fun canUsePremiumFeature(): Boolean =
    prefs.getBoolean("is_premium", false)   // editable on a rooted device
```

### Secure — Backend enforces entitlement per request (Node/Express)

```
// The premium feature's endpoint checks entitlement from server-side state.
function requireEntitlement(name) {
  return async (req, res, next) => {
    const ent = await Entitlements.for(req.principal.sub);   // authoritative
    return ent.has(name) ? next() : res.status(402).json({ error: 'Upgrade required' });
  };
}

app.get('/api/reports/advanced',
  authenticate, requireEntitlement('premium'), advancedReportHandler);
```

### Secure — Client reflects server-provided entitlement (Swift)

```
// The client fetches entitlements from the server and caches them ONLY as a
// UX hint. The gate that matters is the 402/403 the backend returns.
struct Capabilities: Decodable { let isPremium: Bool }

func refreshCapabilities() async throws -> Capabilities {
    try await api.capabilities()      // server is the source of truth
}
// Show/hide premium UI from this — but the feature endpoint re-checks anyway.
```

## What Changed, and Why

| Flaw | Vulnerable | Secure (the fix is on the server) |
| --- | --- | --- |
| Client-side-only authz | `if (role == "admin")` in the app gates the action | `requireRole('admin')` on the route; UI is a hint only |
| IDOR | `findById(params.id)` returns any object | Lookup scoped by `ownerId == principal.sub`; 404 otherwise |
| Client-supplied identity | Server reads `from_user_id` / `role` from body | Identity from the verified token (`principal.sub`) only |
| Local entitlement flag | Feature gated on `UserDefaults`/`SharedPreferences` | Endpoint checks server-side entitlement every request |

**Notice the pattern:** in every "secure" pair the mobile code changes little—it stops *enforcing* and starts *reflecting*. The security-relevant change is always on the backend. That is the definition of getting M6 right.

## Next Steps

- **Prevention**: The full server-side authorization strategy
- **Attack Vectors**: How these flaws are found and exploited
- **Mobile Learning Path**: Continue the OWASP Mobile Top 10
- **Practice**: Apply these fixes in the hands-on challenges
