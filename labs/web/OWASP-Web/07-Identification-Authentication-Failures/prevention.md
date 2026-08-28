# A7:2021 – Identification and Authentication Failures: Prevention

## Table of Contents

- [Defense in Layers](#defense-in-layers)
- [Layer 1: Password Policy (NIST 800-63B)](#layer-1-password-policy-nist-800-63b)
- [Layer 2: Breached-Password Screening](#layer-2-breached-password-screening)
- [Layer 3: Secure Password Storage](#layer-3-secure-password-storage)
- [Layer 4: Anti-Automation (Rate Limiting & Lockout)](#layer-4-anti-automation-rate-limiting--lockout)
- [Layer 5: Multi-Factor Authentication](#layer-5-multi-factor-authentication)
- [Layer 6: Secure Session Management](#layer-6-secure-session-management)
- [Layer 7: Non-Enumerable Responses & Recovery](#layer-7-non-enumerable-responses--recovery)
- [Layer 8: Correct Token (JWT) Validation](#layer-8-correct-token-jwt-validation)
- [Implementation Checklist](#implementation-checklist)

## Defense in Layers

No single control prevents authentication failures. The attack vectors target different links in the identity chain, so the defenses must too. Think of the following eight layers as complementary—each one closes a door the others leave open.

```
Registration -> strong length-based policy + breached-password screen
Storage      -> Argon2id / bcrypt, per-user salt
Login        -> rate limit + backoff, uniform responses, MFA
Session      -> CSPRNG ID, rotate on login, HttpOnly+Secure+SameSite, timeouts
Recovery     -> high-entropy single-use tokens, no enumeration, re-auth
Tokens       -> pin alg, verify signature + exp/iss/aud, short lifetime + revocation
```

## Layer 1: Password Policy (NIST 800-63B)

Modern guidance (NIST SP 800-63B) reverses decades of counterproductive rules. **Favor length; drop mandatory composition and periodic rotation.**

| Do | Don't |
|----|-------|
| Require a minimum of 8, allow at least 64 characters | Cap length at 16 or truncate silently |
| Allow all Unicode, spaces, and paste | Force uppercase + symbol + number composition |
| Screen against breached-password lists | Force a reset every 90 days "just because" |
| Only force a reset on evidence of compromise | Use knowledge-based "security questions" |

```javascript
// Node.js — length-first validation (Express)
function validatePassword(pw) {
  const errors = [];
  if (typeof pw !== 'string') errors.push('Password required');
  // NIST: length is the primary strength lever
  if (pw.length < 8)   errors.push('Use at least 8 characters');
  if (pw.length > 64)  errors.push('Keep it under 64 characters');
  // Do NOT impose composition rules; DO block obvious weak values
  if (/^(.)\1+$/.test(pw)) errors.push('Not all the same character');
  return { ok: errors.length === 0, errors };
}
```

> Encourage passphrases ("correct horse battery staple"), support password managers by allowing paste, and show a strength meter instead of nagging composition rules.

## Layer 2: Breached-Password Screening

The single highest-impact control against credential stuffing on your own side is refusing passwords already known to be compromised. Use the **k-anonymity** range API model so the full password (or full hash) never leaves your server.

```javascript
// Node.js — k-anonymity breached-password check (HaveIBeenPwned-style range model)
const crypto = require('crypto');

async function isBreached(password) {
  const sha1 = crypto.createHash('sha1')
    .update(password).digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);      // only the first 5 hex chars are sent
  const suffix = sha1.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const body = await res.text();        // list of "SUFFIX:count" lines
  return body.split('\n').some(line => line.split(':')[0].trim() === suffix);
}

// On registration and on password change:
if (await isBreached(newPassword)) {
  return res.status(400).json({ error: 'This password has appeared in a data breach. Choose another.' });
}
```

## Layer 3: Secure Password Storage

Store passwords with a slow, salted, memory-hard hash. **Argon2id** is the current first choice; **bcrypt** and **scrypt** are acceptable. Never use MD5, SHA-1, or plain SHA-256 for passwords, and never encrypt (reversible) what should be hashed.

```python
# Python — Argon2id (argon2-cffi)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(          # sensible, tunable defaults
    time_cost=3, memory_cost=64 * 1024, parallelism=4
)

def hash_password(pw: str) -> str:
    return ph.hash(pw)         # salt is generated and embedded automatically

def verify_password(stored_hash: str, pw: str) -> bool:
    try:
        ph.verify(stored_hash, pw)
        # transparently upgrade parameters over time
        if ph.check_needs_rehash(stored_hash):
            # re-hash and persist the new value
            pass
        return True
    except VerifyMismatchError:
        return False
```

## Layer 4: Anti-Automation (Rate Limiting & Lockout)

Slow attackers down without creating a denial-of-service against real users. Combine **per-IP**, **per-account**, and **per-credential** throttling, plus exponential backoff. Remember: per-account lockout alone does not stop password spraying.

```javascript
// Node.js — layered login throttling (express-rate-limit)
const rateLimit = require('express-rate-limit');

// Per-IP: blunt cap on request volume
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,       // 15 minutes
  max: 100,
  standardHeaders: true,
  message: { error: 'Too many requests, try again later.' }
});

// Per-account: stricter, keyed on the submitted username
const accountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => `login:${(req.body.email || '').toLowerCase()}`,
  handler: (req, res) => res.status(429)
    .json({ error: 'Too many attempts. Try again shortly.' })
});

app.post('/login', ipLimiter, accountLimiter, loginHandler);
```

Also monitor for the spray pattern (one credential/IP touching many accounts) at the detection layer, add CAPTCHA/proof-of-work only after suspicious behavior, and prefer temporary backoff over permanent lockout to avoid abuse-driven DoS.

## Layer 5: Multi-Factor Authentication

MFA is the most effective single control against stolen and stuffed credentials. Prefer **phishing-resistant** factors, and enforce MFA on *every* authentication path.

| Factor | Strength | Notes |
|--------|----------|-------|
| FIDO2 / WebAuthn (passkeys, security keys) | Strongest | Phishing-resistant; bound to the origin |
| TOTP authenticator app | Good | Better than SMS; still phishable via real-time proxy |
| Push with number-matching | Good | Number-matching defeats prompt bombing |
| SMS / email OTP | Weak | SIM-swap and interception risk; last resort only |

```python
# Python — verify a TOTP second factor (pyotp), rate-limited
import pyotp

def verify_totp(user, submitted_code):
    if otp_attempts_exceeded(user.id):      # rate-limit the 2nd factor too
        raise TooManyAttempts()
    totp = pyotp.TOTP(user.totp_secret)     # secret stored encrypted
    # valid_window=1 tolerates minor clock skew; do not widen further
    if totp.verify(submitted_code, valid_window=1):
        reset_otp_attempts(user.id)
        return True
    increment_otp_attempts(user.id)
    return False
```

> Do not let account recovery downgrade the factor: if a user enrolled a passkey, recovery must not silently fall back to an emailed link that an attacker can intercept.

## Layer 6: Secure Session Management

Whether you use server-side sessions or tokens, the identity binding must be unguessable, rotated at login, hardened in transport, and revocable.

#### Generate high-entropy IDs from a CSPRNG
```javascript
// Node.js — 256-bit session identifier
const crypto = require('crypto');
const sessionId = crypto.randomBytes(32).toString('hex'); // 256 bits of entropy
// NEVER: Math.random(), timestamps, sequential counters, or md5(user+time)
```

#### Regenerate the ID at login (prevents fixation) and set hardened cookies
```javascript
// Node.js — express-session
const session = require('express-session');

app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,                 // block JS access (XSS token theft)
    secure:   true,                 // HTTPS only
    sameSite: 'lax',                // mitigate cross-site sending
    maxAge:   30 * 60 * 1000        // 30-minute idle window
  }
}));

app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  // CRITICAL: rotate the session ID on privilege change
  req.session.regenerate((err) => {
    if (err) return res.status(500).end();
    req.session.userId = user.id;
    req.session.createdAt = Date.now();     // for absolute-timeout checks
    res.json({ ok: true });
  });
});
```

#### Enforce idle and absolute timeouts, and invalidate server-side on logout
```javascript
// Absolute timeout (independent of activity)
const ABSOLUTE_MS = 8 * 60 * 60 * 1000; // 8 hours
app.use((req, res, next) => {
  if (req.session.userId &&
      Date.now() - req.session.createdAt > ABSOLUTE_MS) {
    return req.session.destroy(() => res.status(401).json({ error: 'Session expired' }));
  }
  next();
});

// Real logout: destroy server-side, then clear the cookie
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.json({ ok: true });
  });
});
```

Session management essentials, summarized:

- **Never** put the session ID in a URL, hidden field, or log line.
- **Regenerate** on login and on any privilege change.
- **Invalidate server-side** on logout, password change, and MFA reset—kill *all* the user's sessions on password change.
- **Bind** both idle and absolute timeouts; re-authenticate for sensitive actions.

## Layer 7: Non-Enumerable Responses & Recovery

Make "account exists" and "account does not exist" indistinguishable in body, status code, and timing—on login, registration, and password reset alike.

```python
# Python (Flask) — uniform login response + constant-time behavior
import secrets
from argon2 import PasswordHasher
ph = PasswordHasher()
# A pre-computed dummy hash so we spend the same time whether or not the user exists
DUMMY_HASH = ph.hash(secrets.token_hex(16))

@app.post('/login')
def login():
    user = get_user(request.form['email'])
    stored = user.password_hash if user else DUMMY_HASH
    try:
        ph.verify(stored, request.form['password'])
        valid = user is not None            # dummy never matches a real password
    except Exception:
        valid = False

    if not valid:
        # Identical message + status for unknown user and wrong password
        return {'error': 'Invalid email or password'}, 401
    return start_session(user)
```

```python
# Python (Flask) — non-enumerable password reset
@app.post('/forgot')
def forgot():
    user = get_user(request.form['email'])
    if user:
        token = secrets.token_urlsafe(32)   # high-entropy, single-use
        store_reset_token(user.id, token, ttl_minutes=15)  # short-lived
        send_reset_email(user.email, token)
    # ALWAYS return the same response, whether or not the account exists:
    return {'message': 'If that email is registered, a reset link has been sent.'}, 200
```

Recovery rules: reset tokens must be high-entropy, single-use, short-lived, and bound to the account; a completed reset must invalidate all existing sessions; and never use guessable "security questions."

## Layer 8: Correct Token (JWT) Validation

If you issue JWTs or other bearer tokens, verify them strictly. The recurring mistake is letting the token's own header decide how it is validated.

```java
// Java (Spring Security / jjwt) — strict JWT validation
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;

public Claims validate(String jwt) {
    return Jwts.parserBuilder()
        // Pin the key; the library will NOT accept alg:none or a mismatched alg
        .setSigningKey(Keys.hmacShaKeyFor(secretBytes)) // or a fixed RSA public key
        .requireIssuer("https://auth.example.com")      // validate iss
        .requireAudience("example-api")                 // validate aud
        .setAllowedClockSkewSeconds(30)                 // small skew only
        .build()
        .parseClaimsJws(jwt)      // throws on bad signature, expiry, iss/aud mismatch
        .getBody();
}
```

```javascript
// Node.js — jsonwebtoken with an explicit algorithm allow-list
const jwt = require('jsonwebtoken');

function verifyToken(token) {
  return jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],          // PIN it — never trust the token's header
    issuer:   'https://auth.example.com',
    audience: 'example-api',
    clockTolerance: 30              // seconds
  }); // throws on invalid signature, alg:none, expiry, or claim mismatch
}
```

Token rules: pin the algorithm server-side, verify the signature against a trusted key, validate `exp`/`iss`/`aud`, keep access-token lifetimes short, and maintain a revocation/denylist (or rotating refresh tokens) so a stolen token cannot be used indefinitely.

## Implementation Checklist

- [ ] Password policy favors length (min 8, allow 64+), no forced composition or periodic rotation.
- [ ] New and changed passwords screened against a breached-password list (k-anonymity).
- [ ] Passwords stored with Argon2id/bcrypt/scrypt and a per-user salt; no MD5/SHA-1/plain-SHA.
- [ ] Login rate-limited per IP, per account, and per credential, with backoff (not just per-account lockout).
- [ ] MFA available and enforced on all paths; phishing-resistant (FIDO2/WebAuthn) offered; OTP entry rate-limited.
- [ ] Session IDs come from a CSPRNG (≥128-bit), regenerated at login and on privilege change.
- [ ] Session cookies are `HttpOnly`, `Secure`, and `SameSite`; IDs never appear in URLs.
- [ ] Idle and absolute timeouts enforced; logout and password change invalidate sessions server-side.
- [ ] Login, registration, and reset responses are uniform in body, status, and timing.
- [ ] Recovery tokens are high-entropy, single-use, short-lived; no security questions.
- [ ] JWTs/bearer tokens: algorithm pinned, signature verified, `exp`/`iss`/`aud` validated, revocation available.

## Next Steps

- **[Overview](./overview.md)**: Concepts, lineage, and why this matters
- **[Attack Vectors](./attack-vectors.md)**: The techniques these layers defend against
- **[Examples](./examples.md)**: Full vulnerable-vs-secure code to compare
- **[Lab](./lab/weak-session-lab/)**: Apply these fixes to a weak session app

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
