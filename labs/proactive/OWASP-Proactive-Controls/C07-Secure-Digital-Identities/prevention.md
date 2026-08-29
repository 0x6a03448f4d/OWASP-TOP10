# C7: Secure Digital Identities - How to Implement

## Implementation Strategy Overview

Building secure identity is not a single feature; it is a sequence of deliberate choices across registration, login, sessions, tokens, and recovery. Work through them in this order:

1. Decide the assurance level (NIST AAL) each action requires.
2. Get password handling right: policy, screening, and storage.
3. Add MFA, preferring phishing-resistant factors.
4. Manage sessions correctly from issue to invalidation.
5. Verify tokens and federated identity fully.
6. Make recovery, enumeration defense, and monitoring first-class.

### Core Principles

- **Proportionality**: match authenticator strength to the risk of the action (AAL1/2/3), and step up for sensitive operations.
- **Prefer standards over invention**: use a vetted identity library or provider; never hand-roll crypto or session primitives.
- **Fail closed and quiet**: on any auth ambiguity, deny; return generic, non-enumerable messages.
- **Defense in depth**: no single control (even MFA) is sufficient alone.

## 1. Choose the Assurance Level (NIST 800-63B AALs)

Start by mapping each action to an assurance level, then implement to the highest level any path can reach.

| Action | Suggested level | What that means |
|--------|-----------------|-----------------|
| Read low-risk personalized content | AAL1 | Strong single factor + anti-guessing controls |
| Access personal/transactional data | AAL2 | MFA required, replay-resistant |
| Admin, financial, MFA/email changes | AAL3 / step-up | Phishing-resistant hardware factor or re-auth |

## 2. Strong Password Policy and Storage

Favor length, screen against breach corpora, and hash with a slow algorithm (this reuses [C2: Use Cryptography to Protect Data](/learn/proactive)).

```
# Policy (align with NIST 800-63B):
- Minimum length 8 (12+ for sensitive accounts); allow 64+ characters
- Allow all printable Unicode, spaces, and paste (password managers)
- Screen new/changed passwords against a known-breached corpus
- NO forced composition rules; NO periodic rotation without cause
- Rotate only on evidence of compromise
```

```python
# Screen against Pwned Passwords via k-anonymity (only a hash PREFIX leaves you)
import hashlib, requests

def is_breached(password: str) -> bool:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
    return any(line.split(':')[0] == suffix for line in res.text.splitlines())

# Storage: Argon2id (preferred), or bcrypt/scrypt — never MD5/SHA-*
from argon2 import PasswordHasher
ph = PasswordHasher()                 # sensible memory/time/parallelism defaults
hashed = ph.hash(password)            # per-user salt handled internally
ph.verify(hashed, password)           # raises on mismatch
```

## 3. Multi-Factor Authentication

Add a second factor and prefer phishing-resistant, origin-bound authenticators. Order of preference: **passkeys / WebAuthn / FIDO2 > authenticator-app TOTP > SMS**.

```
# Enforce the second factor SERVER-SIDE — the session is not "authenticated"
# until step 2 completes. Never trust a client-provided "mfa_passed" flag.

Login state machine:
  1. verify password            -> state = PENDING_MFA (no privileges yet)
  2. verify second factor       -> state = AUTHENTICATED (regenerate session)
  3. sensitive action later     -> require step-up (re-auth or stronger factor)
```

```python
# TOTP verification (pyotp) with a small window for clock drift
import pyotp
totp = pyotp.TOTP(user.totp_secret)
if not totp.verify(submitted_code, valid_window=1):   # +/- 1 step
    reject()                                          # and count toward rate limit

# Prefer WebAuthn/passkeys where possible: the authenticator signs a challenge
# bound to the origin, so a phishing relay on another domain cannot reuse it.
```

## 4. Secure Session Management

Let a vetted framework mint and store sessions, but configure them deliberately.

```
Checklist:
- Session IDs from a CSPRNG, long and unpredictable
- REGENERATE the session ID on login and on any privilege change
- Idle timeout (e.g. 15-30 min) AND absolute timeout (e.g. 8-12 h)
- Cookies: HttpOnly; Secure; SameSite=Lax (or Strict for admin)
- On logout, INVALIDATE server-side — do not merely clear the cookie
- Store only a session handle client-side; keep state server-side
```

```javascript
// Express: harden the session cookie and regenerate on login
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 30*60*1000 }
}));

app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);         // password + MFA verified
  req.session.regenerate(err => {                    // NEW id — kills fixation
    if (err) return res.status(500).json({ error: 'Internal server error' });
    req.session.userId = user.id;
    res.json({ ok: true });
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.clearCookie('sid').json({ ok: true }));  // server-side kill
});
```

## 5. Correct JWT and OAuth2/OIDC Handling

If you carry identity in a token, verify it completely on every request.

```javascript
// Node (jsonwebtoken): pin the algorithm, verify aud/iss/exp
const jwt = require('jsonwebtoken');
function verify(token) {
  return jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],          // allow-list — 'none' can never match
    audience: 'api.example.com',    // this service only
    issuer: 'https://idp.example.com',
    clockTolerance: 5               // seconds
  });                               // throws on bad sig / exp / aud / iss
}
// Keep access tokens short-lived (minutes); rotate refresh tokens; support revocation.
```

```
OAuth2 / OIDC hardening:
- Public clients (SPA/mobile): Authorization Code flow + PKCE (S256)
- Always send and validate 'state' (CSRF defense on the callback)
- Pre-register EXACT redirect URIs; reject anything not on the list
- Validate the ID token: signature, aud, iss, exp, and nonce
- Do not put tokens in URLs (they leak via logs/referrer)
```

## 6. Rate Limiting, Lockout, and Anomaly Response

Make brute force and credential stuffing expensive and visible.

```
# Layered throttling on authentication endpoints:
- Per-account: exponential backoff / temporary lockout after N failures
- Per-IP and global: cap attempts/minute (blunts distributed stuffing)
- CAPTCHA or step-up challenge after a threshold
- Alert on: many-accounts-one-IP, one-account-many-IPs, MFA-prompt spikes
- Prefer soft controls that do not create a lockout DoS on real users
```

```javascript
// Express: a simple per-account + per-IP limiter on /login
const rateLimit = require('express-rate-limit');
app.use('/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,                         // per IP per window
  standardHeaders: true,
  handler: (req, res) => res.status(429).json({ error: 'Too many attempts' })
}));
```

## 7. Secure Credential Recovery and Anti-Enumeration

```
# Password reset done safely:
- Generate a CSPRNG token; store only its HASH; set a short expiry (e.g. 15-60 min)
- One-time use: invalidate on use and on a new request
- Send the token out-of-band (email/authenticated channel), never display it
- On reset: invalidate existing sessions and notify the account owner

# Anti-enumeration (login, registration, reset):
- Return an IDENTICAL response for valid and invalid accounts
  e.g. "If an account exists, a reset link has been sent."
- Keep timing comparable (do the same work either way)
- Rate-limit these endpoints
```

## 8. Secrets and Token Storage

- Store signing keys and API secrets in a manager (Vault, cloud KMS/Secrets Manager); never commit them or bake them into images.
- On the client, keep session tokens in `HttpOnly` cookies rather than `localStorage` (which is readable by any XSS).
- Rotate signing keys on a schedule and support key IDs (`kid`) so rotation does not require downtime.

## Implementation Checklist

- [ ] Each action mapped to a NIST AAL; sensitive actions require step-up.
- [ ] Password policy is length-first, with breach-corpus screening and no forced rotation.
- [ ] Passwords stored with Argon2id/bcrypt/scrypt (per-user salt).
- [ ] MFA enforced server-side; phishing-resistant factors offered/preferred.
- [ ] Session IDs are CSPRNG; regenerated on login and privilege change.
- [ ] Cookies set `HttpOnly; Secure; SameSite`; idle + absolute timeouts.
- [ ] Logout invalidates the session server-side.
- [ ] JWTs verify signature, algorithm allow-list, `exp`, and `aud`; short-lived + rotated.
- [ ] OAuth2/OIDC uses Auth Code + PKCE, validated `state`, exact redirect URIs.
- [ ] Rate limiting/lockout on auth endpoints; anomaly alerting in place.
- [ ] Reset tokens are single-use, hashed, time-limited; responses are non-enumerable.

## Key Takeaways

1. **Start from risk** — the AAL decides how strong everything downstream must be.
2. **Store and screen passwords properly** — slow hashing plus breach screening, not complexity theatre.
3. **Enforce MFA server-side** — and prefer origin-bound, phishing-resistant factors.
4. **Own the session lifecycle** — regenerate, time out, and truly invalidate.
5. **Verify every token** — signature, algorithm, expiry, audience, on every request.

## Next Steps

- **[Examples](examples.md)**: Insecure vs. secure auth, session, and MFA code in Node, Python, and Java
- **[Threats Addressed](attack-vectors.md)**: Understand what you are defending against
- **[Overview](overview.md)**: What this control is and why it matters
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
