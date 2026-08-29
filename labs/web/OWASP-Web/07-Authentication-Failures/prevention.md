# Authentication Failures (2025) - Prevention

## Table of Contents
- [Defense in Depth](#defense-in-depth)
- [Layer 1: Password Strength & Breach Screening](#layer-1-password-strength--breach-screening)
- [Layer 2: Rate Limiting, Throttling & Lockout](#layer-2-rate-limiting-throttling--lockout)
- [Layer 3: MFA & Phishing Resistance](#layer-3-mfa--phishing-resistance)
- [Layer 4: Strong Session Management](#layer-4-strong-session-management)
- [Layer 5: Secure Credential Recovery](#layer-5-secure-credential-recovery)
- [Layer 6: Non-Enumerable Responses](#layer-6-non-enumerable-responses)
- [Layer 7: Correct JWT / Token Validation](#layer-7-correct-jwt--token-validation)
- [Layer 8: OAuth2 / OIDC Configuration](#layer-8-oauth2--oidc-configuration)
- [Consolidated Checklist](#consolidated-checklist)
- [What's Next?](#whats-next)

## Defense in Depth

No single control stops account takeover, because the attack vectors chain. The goal is layered authentication: even if a password leaks, breach screening or MFA catches it; even if MFA is phished, phishing-resistant methods and session binding blunt it; even if a session is stolen, short lifetimes and server-side invalidation limit the blast radius.

```
Request to protect an account
  |  strong, breach-screened password (Layer 1)
  |  rate limiting + throttling, careful lockout (Layer 2)
  |  MFA, phishing-resistant for privileged users (Layer 3)
  |  high-entropy session, rotated + invalidated (Layer 4)
  |  non-enumerable, poison-proof recovery (Layers 5-6)
  |  correctly validated tokens / OAuth (Layers 7-8)
```

## Layer 1: Password Strength & Breach Screening

Follow NIST SP 800-63B: length over composition, screen against breach corpora, and hash with a slow, salted algorithm.

### Breach Screening with k-Anonymity

```javascript
// Node.js: check a password against HIBP without sending the full hash.
// Send only the first 5 hex chars of the SHA-1; compare suffixes locally.
import crypto from 'node:crypto';

async function isBreached(password) {
  const sha1 = crypto.createHash('sha1')
    .update(password).digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`,
                          { headers: { 'Add-Padding': 'true' } });
  const body = await res.text();
  return body.split('\n').some(line => line.split(':')[0].trim() === suffix);
}
```

### Strong Hashing at Rest

```python
# Python: Argon2id (preferred) via argon2-cffi
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)

hash = ph.hash(password)                 # store this
ph.verify(hash, password)                # raises on mismatch
if ph.check_needs_rehash(hash):          # transparently upgrade cost over time
    hash = ph.hash(password)
```

### Policy

- Minimum 8 (prefer 12+) characters; allow up to 64+ and all Unicode, including spaces.
- No mandatory composition rules; no forced periodic rotation without evidence of compromise.
- No knowledge-based "security questions."
- Reject breached and context-specific weak passwords (the site name, the username).

## Layer 2: Rate Limiting, Throttling & Lockout

Throttle by **account** and by **source**, add friction progressively, and avoid a naive lockout that becomes a denial-of-service against legitimate users.

```javascript
// Express: layered limiter with exponential backoff + CAPTCHA step-up.
import rateLimit from 'express-rate-limit';

// Per-IP coarse limit
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true,
});

// Per-account fine limit with progressive delay (pseudo)
async function accountThrottle(req, res, next) {
  const key = `login:fail:${req.body.email.toLowerCase()}`;
  const fails = await redis.incr(key);
  if (fails === 1) await redis.expire(key, 900);      // 15-min window
  if (fails > 5)  req.requireCaptcha = true;          // step-up, not hard lock
  if (fails > 20) return res.status(429)
      .json({ error: 'Too many attempts, try again later' });
  next();
}
app.post('/login', ipLimiter, accountThrottle, handleLogin);
```

> **Reset the counter on success**, and prefer graduated throttling + CAPTCHA + MFA over permanent lockout. If you must lock, use a short auto-expiring lock and alert the user, never an indefinite one an attacker can weaponise.

## Layer 3: MFA & Phishing Resistance

Offer MFA everywhere, enforce it for sensitive actions, and prefer **phishing-resistant** WebAuthn/passkeys — especially for privileged accounts. If you keep push-based MFA, use **number matching** to defeat fatigue.

### WebAuthn / Passkey Registration (server, Node)

```javascript
// @simplewebauthn/server -- origin-bound, phishing-resistant
import { generateRegistrationOptions, verifyRegistrationResponse }
  from '@simplewebauthn/server';

const options = await generateRegistrationOptions({
  rpName: 'Example', rpID: 'example.com',
  userID: user.id, userName: user.email,
  attestationType: 'none',
  authenticatorSelection: {
    residentKey: 'preferred',
    userVerification: 'preferred',      // biometric/PIN on the authenticator
  },
});
// ...later, verify the client's response is bound to the true origin:
const verification = await verifyRegistrationResponse({
  response: clientResponse,
  expectedChallenge: session.challenge,
  expectedOrigin: 'https://example.com',   // AitM proxy cannot satisfy this
  expectedRPID: 'example.com',
});
```

### TOTP as a Fallback (Python)

```python
import pyotp
secret = pyotp.random_base32()                  # store per-user, encrypted
uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name='Example')  # render as QR

# Verify with a small window; RATE-LIMIT attempts to stop OTP brute force
ok = pyotp.TOTP(secret).verify(code, valid_window=1)
```

**Hierarchy of assurance**: passkeys/security keys > app-based TOTP > push with number matching > SMS OTP (last resort). Never gate high-value recovery on SMS alone.

## Layer 4: Strong Session Management

- **High entropy**: 128-bit+ identifiers from a CSPRNG (let the framework's session store generate them).
- **Rotate** the session ID on login and on any privilege change (defeats fixation).
- **Invalidate server-side** on logout, and support "log out everywhere."
- **Timeouts**: idle timeout plus a shorter-than-forever absolute lifetime.
- **Cookie flags**: `HttpOnly`, `Secure`, `SameSite`.

```javascript
// Express + express-session
import session from 'express-session';

app.use(session({
  name: '__Host-sid',                 // __Host- prefix: HTTPS + path=/ + no domain
  secret: process.env.SESSION_SECRET, // long random secret from env, not code
  resave: false, saveUninitialized: false,
  rolling: true,                      // refresh idle timeout on activity
  cookie: {
    httpOnly: true,                   // not readable by JS -> blunts XSS theft
    secure: true,                     // HTTPS only
    sameSite: 'lax',                  // CSRF hardening
    maxAge: 30 * 60 * 1000,           // 30-min idle window
  },
}));

// Rotate the session ID at every privilege boundary:
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  req.session.regenerate(err => {     // NEW id -> old fixated id is useless
    if (err) return res.sendStatus(500);
    req.session.userId = user.id;
    req.session.save(() => res.json({ ok: true }));
  });
});

// True logout: destroy server-side state AND clear the cookie
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.clearCookie('__Host-sid').json({ ok: true }));
});
```

## Layer 5: Secure Credential Recovery

- Reset tokens: **128-bit+ CSPRNG**, **single-use**, **short expiry** (for example 15–30 min); store only a hash of the token.
- Build the reset link from a **trusted, configured origin** — never from the request `Host` / `X-Forwarded-Host`.
- Invalidate existing sessions on password change; optionally re-verify MFA.
- Respond identically whether or not the email exists (see Layer 6).

```python
import secrets, hashlib
from datetime import datetime, timedelta, timezone

def create_reset(user):
    raw = secrets.token_urlsafe(32)                      # 256-bit, CSPRNG
    user.reset_hash = hashlib.sha256(raw.encode()).hexdigest()  # store the HASH
    user.reset_expires = datetime.now(timezone.utc) + timedelta(minutes=20)
    user.save()
    base = settings.APP_ORIGIN                            # trusted, from config
    return f"{base}/reset?token={raw}"                    # raw only in the email

def consume_reset(raw, new_password):
    h = hashlib.sha256(raw.encode()).hexdigest()
    user = User.objects.filter(reset_hash=h).first()
    if not user or user.reset_expires < datetime.now(timezone.utc):
        raise ValueError("invalid or expired")
    user.set_password(new_password)                       # after breach-screening
    user.reset_hash = None                                # single use
    revoke_all_sessions(user)                             # log out everywhere
    user.save()
```

## Layer 6: Non-Enumerable Responses

Login, registration, and reset must not reveal whether an account exists — in body, status, or timing.

```python
# Uniform message regardless of existence
GENERIC = {"message": "If an account exists, a reset link has been sent."}

def forgot_password(email):
    user = find_user(email)
    if user:
        send_reset_email(user)
    else:
        do_dummy_work()          # spend comparable time -> no timing oracle
    return GENERIC               # identical response either way

# On LOGIN, always run the password hash even for unknown users, and return
# one generic "Invalid email or password" for both wrong-user and wrong-pass.
```

## Layer 7: Correct JWT / Token Validation

- **Pin the algorithm** server-side; never trust the token's `alg` header.
- Use a **strong secret** (HS*) or asymmetric keys (RS*/ES*); never reuse a public key as an HMAC secret.
- Always validate `exp`, `iss`, and `aud`; keep access tokens **short-lived** and pair with rotating refresh tokens.
- Maintain a revocation / deny-list path (or a short TTL) so logout means something.

```javascript
// Node: jsonwebtoken -- explicit, strict verification
import jwt from 'jsonwebtoken';

const claims = jwt.verify(token, PUBLIC_KEY, {
  algorithms: ['RS256'],           // PIN it -- rejects alg:none and HS confusion
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
  maxAge: '15m',                   // enforce short lifetime
});
// jwt.verify throws on bad signature, wrong alg, expiry, iss/aud mismatch.
```

```python
# Python: PyJWT -- same principles
import jwt
claims = jwt.decode(
    token, public_key,
    algorithms=["RS256"],                       # never [] or "none"
    audience="https://api.example.com",
    issuer="https://auth.example.com",
    options={"require": ["exp", "iss", "aud"]}, # fail closed if missing
)
```

## Layer 8: OAuth2 / OIDC Configuration

- **Exact-match** registered `redirect_uri` values — no wildcards, prefixes, or open redirects.
- Always send and verify **`state`** (CSRF / login-CSRF protection).
- Require **PKCE** (`S256`) for public clients (SPAs, mobile).
- Prefer the **authorization-code** flow; validate the ID token's signature, `iss`, `aud`, and `nonce`.
- Request the minimum scopes; keep client secrets out of source and out of browsers.

```javascript
// Authorization request with state + PKCE
const state    = crypto.randomUUID();
const verifier = base64url(crypto.randomBytes(32));         // PKCE verifier
const challenge = base64url(sha256(verifier));              // S256 challenge
saveToSession({ state, verifier });

const url = `https://auth.example.com/authorize?` + new URLSearchParams({
  response_type: 'code',
  client_id: CLIENT_ID,
  redirect_uri: 'https://app.example.com/callback',   // must EXACTLY match registration
  scope: 'openid profile',
  state,
  code_challenge: challenge,
  code_challenge_method: 'S256',
});

// On callback: reject if returned state != saved state, THEN exchange the code
// with the code_verifier. Validate the ID token's iss/aud/nonce/signature.
```

## Consolidated Checklist

| Area | Do |
|------|----|
| Passwords | Length over complexity; breach-screen; Argon2id/scrypt/bcrypt |
| Automation defense | Per-account + per-source throttling; CAPTCHA step-up; careful lockout |
| MFA | Enforce for sensitive actions; passkeys/WebAuthn for privileged users; number-matching push |
| Sessions | CSPRNG IDs; rotate on login/privilege change; server-side invalidation; HttpOnly+Secure+SameSite; timeouts |
| Recovery | Hashed, single-use, short-lived tokens; trusted origin for links; revoke sessions on change |
| Enumeration | Uniform responses and timing across login/signup/reset |
| Tokens | Pin alg; validate exp/iss/aud; short lifetimes; revocation path |
| OAuth/OIDC | Exact redirect_uri; state; PKCE; validate ID token |

## What's Next?

- **[Examples](./examples.md)**: side-by-side vulnerable-vs-secure implementations.
- **[Attack Vectors](./attack-vectors.md)**: the techniques these layers defend against.
- **[Overview](./overview.md)**: concepts, impact, and the 2025 edition framing.
- **[Lab](./lab/authentication-failures/)**: practice fixing these vulnerabilities.

---

*Part of the [OWASP Top 10 Educational Repository](/)*
