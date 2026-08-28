# A7:2021 – Identification and Authentication Failures: Examples

Each example below pairs a realistic **❌ vulnerable** implementation with a **✅ secure** rewrite, across Node/Express, Python, and Java, plus JWT, session, and MFA configuration. Compare them side by side; the fix is usually smaller than the flaw.

## Table of Contents

- [Example 1: Login & Password Storage (Node/Express)](#example-1-login--password-storage-nodeexpress)
- [Example 2: Session Creation & Fixation (Python/Flask)](#example-2-session-creation--fixation-pythonflask)
- [Example 3: JWT Validation (Java)](#example-3-jwt-validation-java)
- [Example 4: Account Enumeration on Reset (Node)](#example-4-account-enumeration-on-reset-node)
- [Example 5: Rate Limiting & Lockout (Python)](#example-5-rate-limiting--lockout-python)
- [Example 6: MFA / TOTP Enrollment & Verify (Node)](#example-6-mfa--totp-enrollment--verify-node)
- [Example 7: Session Cookie Configuration](#example-7-session-cookie-configuration)
- [Summary Table](#summary-table)

## Example 1: Login & Password Storage (Node/Express)

### ❌ Vulnerable
```javascript
const crypto = require('crypto');

// Fast, unsalted hash — crackable; and a leaky, non-uniform login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.getUser(email);

  if (!user) {
    return res.status(404).json({ error: 'No account with that email' }); // ENUMERATION
  }
  const hash = crypto.createHash('md5').update(password).digest('hex');    // WEAK HASH
  if (hash !== user.passwordHash) {
    return res.status(401).json({ error: 'Wrong password' });              // DIFFERENT MESSAGE
  }
  // No session regeneration, unlimited attempts, no MFA
  req.session.userId = user.id;                                            // FIXATION RISK
  res.json({ token: user.id + '-' + Date.now() });                         // PREDICTABLE TOKEN
});
```

### ✅ Secure
```javascript
const argon2 = require('argon2');
const crypto = require('crypto');

app.post('/login', loginRateLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = db.getUser(email);

  // Constant-work path whether or not the user exists (anti-enumeration)
  const storedHash = user ? user.passwordHash : DUMMY_ARGON2_HASH;
  let valid = false;
  try { valid = (await argon2.verify(storedHash, password)) && !!user; }
  catch { valid = false; }

  if (!valid) {
    // Identical status + message for unknown user and wrong password
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Rotate the session ID on login (prevents fixation)
  req.session.regenerate((err) => {
    if (err) return res.status(500).end();
    req.session.userId = user.id;
    req.session.createdAt = Date.now();
    res.json({ ok: true }); // session ID lives in a hardened cookie, not the body
  });
});
```

**What changed**: Argon2id instead of MD5; uniform response and constant work to kill enumeration; rate limiting; session regeneration; and the identifier delivered in a hardened cookie instead of a guessable body token.

## Example 2: Session Creation & Fixation (Python/Flask)

### ❌ Vulnerable
```python
import time, hashlib
sessions = {}

@app.post('/login')
def login():
    user = get_user(request.form['email'])
    if user and check_password(user, request.form['password']):
        # Predictable, guessable session identifier
        sid = hashlib.md5(
            (user['email'] + str(int(time.time()))).encode()
        ).hexdigest()                      # WEAK + PREDICTABLE
        sessions[sid] = user['id']
        resp = make_response({'ok': True})
        resp.set_cookie('sid', sid)        # no HttpOnly/Secure/SameSite
        return resp
    return {'ok': False}, 401
# No timeout, no server-side invalidation on logout
```

### ✅ Secure
```python
import secrets, time
sessions = {}                              # {sid: {'uid':..., 'created':...}}
IDLE_TTL     = 30 * 60                      # 30 minutes
ABSOLUTE_TTL = 8 * 60 * 60                  # 8 hours

@app.post('/login')
def login():
    user = get_user(request.form['email'])
    if not (user and check_password(user, request.form['password'])):
        return {'error': 'Invalid email or password'}, 401

    sid = secrets.token_urlsafe(32)         # 256-bit CSPRNG identifier
    now = time.time()
    sessions[sid] = {'uid': user['id'], 'created': now, 'seen': now}
    resp = make_response({'ok': True})
    resp.set_cookie('sid', sid,
                    httponly=True, secure=True, samesite='Lax', max_age=IDLE_TTL)
    return resp

def current_user():
    sid = request.cookies.get('sid')
    s = sessions.get(sid)
    if not s: return None
    now = time.time()
    if now - s['seen'] > IDLE_TTL or now - s['created'] > ABSOLUTE_TTL:
        sessions.pop(sid, None)             # expire idle/absolute
        return None
    s['seen'] = now
    return s['uid']

@app.post('/logout')
def logout():
    sessions.pop(request.cookies.get('sid'), None)   # server-side invalidation
    resp = make_response({'ok': True})
    resp.delete_cookie('sid')
    return resp
```

## Example 3: JWT Validation (Java)

### ❌ Vulnerable
```java
// Trusts the token's own header to pick the algorithm — accepts alg:none
public boolean isValid(String jwt) {
    try {
        Claims claims = Jwts.parser()
            .setSigningKey(secret)         // used only if the header says so
            .parseClaimsJws(jwt)           // older API: honors header alg
            .getBody();
        return true;                       // no iss/aud check; expiry only if present
    } catch (Exception e) {
        return false;
    }
}
```

### ✅ Secure
```java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;

// Pins the algorithm/key and validates all standard claims
public Claims validate(String jwt) {
    return Jwts.parserBuilder()
        .setSigningKey(Keys.hmacShaKeyFor(secretBytes)) // fixed key; rejects alg:none
        .requireIssuer("https://auth.example.com")      // iss must match
        .requireAudience("example-api")                 // aud must match
        .setAllowedClockSkewSeconds(30)
        .build()
        .parseClaimsJws(jwt)   // throws on bad signature, expiry, or claim mismatch
        .getBody();
}
```

**What changed**: the signing key/algorithm is pinned server-side (so `alg: none` and RS256→HS256 confusion are rejected), and `iss`, `aud`, and `exp` are all validated instead of trusted.

## Example 4: Account Enumeration on Reset (Node)

### ❌ Vulnerable
```javascript
app.post('/forgot', (req, res) => {
  const user = db.getUser(req.body.email);
  if (!user) {
    return res.status(404).json({ error: 'No account with that email' }); // LEAK
  }
  const token = String(db.nextResetId++);          // SEQUENTIAL, guessable
  db.saveResetToken(user.id, token);               // never expires
  sendEmail(user.email, `/reset?token=${token}`);
  res.json({ message: 'Reset email sent' });        // reveals the account exists
});
```

### ✅ Secure
```javascript
const crypto = require('crypto');

app.post('/forgot', resetRateLimiter, (req, res) => {
  const user = db.getUser(req.body.email);
  if (user) {
    const token = crypto.randomBytes(32).toString('hex');  // high-entropy, single-use
    db.saveResetToken(user.id, token, { ttlMinutes: 15 }); // short-lived
    sendEmail(user.email, `/reset?token=${token}`);
  }
  // Same response whether or not the account exists (no enumeration)
  res.json({ message: 'If that email is registered, a reset link has been sent.' });
});

app.post('/reset', (req, res) => {
  const rec = db.getResetToken(req.body.token);
  if (!rec || rec.expired || rec.used) {
    return res.status(400).json({ error: 'Invalid or expired reset link' });
  }
  db.updatePassword(rec.userId, req.body.newPassword); // screened + Argon2id hashed
  db.consumeResetToken(rec.token);                     // single-use
  db.invalidateAllSessions(rec.userId);                // kill attacker sessions
  res.json({ ok: true });
});
```

## Example 5: Rate Limiting & Lockout (Python)

### ❌ Vulnerable
```python
@app.post('/login')
def login():
    user = get_user(request.form['email'])
    if user and check_password(user, request.form['password']):
        return start_session(user)
    return {'error': 'Invalid credentials'}, 401
# No throttling at all: unlimited brute force AND unlimited spraying
```

### ✅ Secure
```python
import time
from collections import defaultdict

FAILS = defaultdict(list)          # key -> [timestamps]
WINDOW = 15 * 60                   # 15 minutes

def too_many(key, limit):
    now = time.time()
    FAILS[key] = [t for t in FAILS[key] if now - t < WINDOW]
    return len(FAILS[key]) >= limit

@app.post('/login')
def login():
    email = request.form['email'].lower()
    ip = request.remote_addr
    # Layer per-account AND per-IP so spraying (many accounts) is also caught
    if too_many(f'acct:{email}', 5) or too_many(f'ip:{ip}', 50):
        return {'error': 'Too many attempts. Try again later.'}, 429

    user = get_user(email)
    if user and check_password(user, request.form['password']):
        FAILS.pop(f'acct:{email}', None)
        return start_session(user)

    FAILS[f'acct:{email}'].append(time.time())
    FAILS[f'ip:{ip}'].append(time.time())
    return {'error': 'Invalid email or password'}, 401
```

> In production, back the counters with Redis (shared across instances), add exponential backoff, and prefer temporary throttling over permanent lockout to avoid abuse-driven denial of service.

## Example 6: MFA / TOTP Enrollment & Verify (Node)

### ❌ Vulnerable
```javascript
// "MFA" that is trivially bypassed
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  if (!user) return res.status(401).end();
  // Second factor is optional and never enforced; code has no attempt limit
  if (req.body.otp && req.body.otp === user.lastOtp) { /* ... */ }
  return res.json({ ok: true }); // logs in even with NO otp
});
```

### ✅ Secure
```javascript
const speakeasy = require('speakeasy');

// Enrollment: generate and store the secret (encrypted at rest)
app.post('/mfa/enroll', requireAuth, (req, res) => {
  const secret = speakeasy.generateSecret({ name: `ExampleApp (${req.user.email})` });
  db.savePendingTotpSecret(req.user.id, secret.base32);
  res.json({ otpauthUrl: secret.otpauth_url }); // render as QR for the authenticator app
});

// Login step 2: enforce and rate-limit the second factor
app.post('/login/mfa', mfaRateLimiter, (req, res) => {
  const user = db.getUser(req.session.pendingUserId); // set after password step
  if (!user || !user.totpSecret) return res.status(401).end();

  const ok = speakeasy.totp.verify({
    secret: user.totpSecret, encoding: 'base32',
    token: req.body.otp, window: 1               // small skew only
  });
  if (!ok) return res.status(401).json({ error: 'Invalid code' });

  req.session.regenerate(() => {                  // rotate after full auth
    req.session.userId = user.id;
    req.session.createdAt = Date.now();
    res.json({ ok: true });
  });
});
```

**Prefer phishing-resistant WebAuthn/passkeys where possible**; TOTP shown here is a solid step up from SMS but is still relayable through a real-time phishing proxy.

## Example 7: Session Cookie Configuration

### ❌ Vulnerable
```javascript
// Token in the URL, and a cookie with no protective flags
res.redirect(`/dashboard?sessionid=${sid}`);        // leaks via logs/Referer/history
res.setHeader('Set-Cookie', `sid=${sid}`);          // no HttpOnly/Secure/SameSite
```

### ✅ Secure
```javascript
// Never in the URL; always a hardened cookie
res.cookie('sid', sid, {
  httpOnly: true,     // not readable by JavaScript (XSS theft)
  secure:   true,     // HTTPS only
  sameSite: 'lax',    // not auto-sent on cross-site requests
  maxAge:   30 * 60 * 1000,
  path:     '/'
});
res.redirect('/dashboard'); // no token in the query string
```

## Summary Table

| Concern | Vulnerable | Secure |
|---------|-----------|--------|
| Password hashing | MD5 / SHA-1, unsalted | Argon2id / bcrypt, per-user salt |
| Login response | Different message per case | Uniform message + constant work |
| Session ID | md5(user+time), sequential | 256-bit CSPRNG, rotated at login |
| Cookie flags | None; token in URL | HttpOnly + Secure + SameSite |
| Logout | Client cookie only | Server-side invalidation + timeouts |
| Reset token | Sequential, non-expiring | High-entropy, single-use, 15-min TTL |
| Brute force / spray | No throttling | Per-IP + per-account rate limits |
| MFA | Optional / unenforced | Enforced, rate-limited, phishing-resistant preferred |
| JWT | Header picks alg; no claim checks | Pinned alg; verify sig + exp/iss/aud |

## Next Steps

- **[Overview](./overview.md)**: Concepts, lineage, and business context
- **[Attack Vectors](./attack-vectors.md)**: The techniques these fixes defend against
- **[Prevention](./prevention.md)**: The full layered-defense reference
- **[Lab](./lab/weak-session-lab/)**: Fix a deliberately weak session app yourself

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
