# C7: Secure Digital Identities - Code Examples

Each pair below shows an **insecure** implementation and the **secure** version in the same stack. The examples target the parts of identity where real findings cluster: password login, session handling, MFA enforcement, and token verification.

## 1. Password Login and Storage — Node.js / Express

### Insecure
```javascript
const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.getUser(username);

  if (!user) return res.status(404).json({ error: 'No such user' });   // enumeration
  // Fast, unsalted hash — a leaked DB is cracked in minutes:
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  if (hash !== user.passwordHash) {
    return res.status(401).json({ error: 'Wrong password' });          // enumeration
  }
  // No rate limit, no MFA, session id never regenerated:
  req.session.userId = user.id;
  res.json({ ok: true });
});
```

### Secure
```javascript
const express = require('express');
const argon2 = require('argon2');
const rateLimit = require('express-rate-limit');
const app = express();
app.use(express.json());

// Blunt brute force / stuffing before we ever hit the DB:
app.use('/login', rateLimit({ windowMs: 15*60*1000, max: 20,
  handler: (_, res) => res.status(429).json({ error: 'Too many attempts' }) }));

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.getUser(username);

  // Always do comparable work + return an IDENTICAL message => no enumeration:
  const ok = user
    ? await argon2.verify(user.passwordHash, password)   // Argon2id, per-user salt
    : await argon2.verify(DUMMY_HASH, password);         // constant-time-ish decoy

  if (!user || !ok) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  // Password proven — but NOT authenticated until MFA (see section 3):
  req.session.regenerate(err => {                        // new id kills fixation
    if (err) return res.status(500).json({ error: 'Internal server error' });
    req.session.pendingUserId = user.id;                 // no privileges yet
    res.json({ mfaRequired: true });
  });
});
```

## 2. Session Cookies and Logout — Node.js / Express

### Insecure
```javascript
app.use(session({
  secret: 'hardcoded-secret',
  resave: true,
  saveUninitialized: true,
  cookie: { }                 // no httpOnly, no secure, no sameSite, no expiry
}));

app.post('/logout', (req, res) => {
  res.clearCookie('connect.sid');       // clears the CLIENT cookie only...
  res.json({ ok: true });               // ...server session still valid = replayable
});
```

### Secure
```javascript
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET,   // from a secrets manager, not source
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,                     // JS cannot read it (XSS can't steal it)
    secure: true,                       // HTTPS only
    sameSite: 'lax',                    // CSRF mitigation
    maxAge: 30 * 60 * 1000              // idle window; pair with an absolute cap
  }
}));

app.post('/logout', (req, res) => {
  req.session.destroy(() => {           // INVALIDATE server-side
    res.clearCookie('sid').json({ ok: true });
  });
});
```

## 3. MFA Enforcement — Python / Flask

### Insecure
```python
@app.route('/mfa/verify', methods=['POST'])
def mfa_verify():
    # Trusts a client-supplied flag — attacker just sends {"mfa_passed": true}
    if request.json.get('mfa_passed'):
        session['authenticated'] = True
    return jsonify(ok=True)

@app.route('/account')
def account():
    # Never checks that step 2 actually happened server-side
    if session.get('user_id'):
        return jsonify(load_account())
    abort(401)
```

### Secure
```python
import pyotp, time
from flask import session, request, jsonify, abort

@app.route('/mfa/verify', methods=['POST'])
def mfa_verify():
    uid = session.get('pending_user_id')          # set only after password step
    if not uid:
        abort(401)
    user = db.get_user_by_id(uid)
    totp = pyotp.TOTP(user.totp_secret)
    # Server verifies the code; small window absorbs clock drift:
    if not totp.verify(request.json.get('code', ''), valid_window=1):
        record_failed_mfa(uid)                     # feeds rate limiting/lockout
        return jsonify(error='Invalid code'), 401

    session.clear()                                # drop the pending state
    session['user_id'] = uid                       # NOW authenticated (AAL2)
    session['auth_time'] = time.time()             # enables step-up checks later
    return jsonify(ok=True)

def require_step_up(max_age=300):
    # For sensitive actions: force re-auth if the session is too old
    if time.time() - session.get('auth_time', 0) > max_age:
        abort(401, 're-authentication required')
```

## 4. JWT Verification — Python (PyJWT)

### Insecure
```python
import jwt

def get_identity(token):
    # No algorithm pinning: a token with {"alg":"none"} is accepted.
    # No audience/issuer/expiry check. Attacker forges {"role":"admin"}.
    return jwt.decode(token, options={"verify_signature": False})
```

### Secure
```python
import jwt

def get_identity(token):
    try:
        return jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],          # allow-list — 'none' can never match
            audience="api.example.com",    # this service only
            issuer="https://idp.example.com",
            options={"require": ["exp", "aud", "iss"]},  # must be present
            leeway=5                        # small clock skew tolerance
        )
    except jwt.InvalidTokenError:
        raise Unauthorized("invalid token")   # bad sig / expired / wrong aud
# Keep access tokens short-lived (minutes); rotate refresh tokens; support revocation.
```

## 5. Password Storage and Reset — Java

### Insecure
```java
// MD5, no salt — a stolen table is a plaintext password list.
String hash = DigestUtils.md5Hex(password);
user.setPasswordHash(hash);

// Reset token is a small, guessable, non-expiring value:
String token = String.valueOf(new Random().nextInt(999999));   // 6 digits, brute-forceable
user.setResetToken(token);                                     // stored in the clear, never expires
```

### Secure
```java
// Argon2id via a maintained library (per-user salt handled internally):
Argon2 argon2 = Argon2Factory.create(Argon2Types.ARGON2id);
String hash = argon2.hash(3, 65536, 1, password.toCharArray());  // iterations, memKB, parallelism
user.setPasswordHash(hash);
boolean ok = argon2.verify(user.getPasswordHash(), password.toCharArray());

// Reset token: CSPRNG, stored only as a HASH, single-use, time-limited:
byte[] raw = new byte[32];
new SecureRandom().nextBytes(raw);
String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
user.setResetTokenHash(sha256(token));                 // store the hash, not the token
user.setResetTokenExpiry(Instant.now().plus(Duration.ofMinutes(30)));
// Email 'token' out-of-band. On use: check hash + expiry, then invalidate and
// destroy existing sessions. Respond identically whether or not the account exists.
```

## What Changed, and Why

| Area | Insecure | Secure |
|------|----------|--------|
| Password storage | MD5/SHA-256, unsalted | Argon2id/bcrypt, per-user salt |
| Login responses | Distinct "no user" / "wrong password" | Identical, non-enumerable message + rate limit |
| Session | Reused id, no flags, client-only logout | Regenerated id, `HttpOnly/Secure/SameSite`, server-side invalidation |
| MFA | Client `mfa_passed` flag trusted | Second factor verified server-side; step-up for sensitive actions |
| JWT | `alg:none`, signature/aud unchecked | Algorithm allow-list, `exp`/`aud`/`iss` verified |
| Reset token | Short, guessable, permanent, plaintext | CSPRNG, hashed, single-use, time-limited |

## Next Steps

- **[How to Implement](prevention.md)**: The full step-by-step build guide
- **[Threats Addressed](attack-vectors.md)**: How these weaknesses are exploited
- **[Overview](overview.md)**: What this control is and why it matters
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
