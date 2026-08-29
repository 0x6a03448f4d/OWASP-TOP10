# Authentication Failures (2025) - Examples

## Table of Contents
- [How to Read These Examples](#how-to-read-these-examples)
- [Express (Node.js): Login & Enumeration](#express-nodejs-login--enumeration)
- [Python (Flask): Password Reset](#python-flask-password-reset)
- [Java (Spring): Session Management](#java-spring-session-management)
- [JWT Validation Config](#jwt-validation-config)
- [MFA / WebAuthn Config](#mfa--webauthn-config)
- [OAuth2 / OIDC Client Config](#oauth2--oidc-client-config)
- [What's Next?](#whats-next)

## How to Read These Examples

Each pair below shows a **vulnerable** implementation and the **secure** version in the same stack. The focus is on the failures that dominate real findings: enumerable login, unthrottled guessing, plaintext or fast-hashed passwords, weak reset tokens, non-rotating sessions, and sloppy JWT/OAuth validation.

## Express (Node.js): Login & Enumeration

### Vulnerable

```javascript
const bcrypt = require('bcrypt');
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.user.findByEmail(email);
  if (!user) {
    return res.status(404).json({ error: 'No account with that email' }); // enumeration
  }
  const ok = await bcrypt.compare(password, user.hash);
  if (!ok) {
    return res.status(401).json({ error: 'Incorrect password' });          // enumeration
  }
  req.session.userId = user.id;        // no session rotation -> fixation
  res.json({ token: user.id });        // predictable "token"
  // no rate limiting, no MFA, no breach check
});
```

### Secure

```javascript
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 50 });
// A dummy hash so unknown users cost the same time as real ones (no timing oracle)
const DUMMY_HASH = '$2b$12$........................................................';

app.post('/login', loginLimiter, accountThrottle, async (req, res) => {
  const { email, password } = req.body;
  const user = await db.user.findByEmail(String(email).toLowerCase());
  const hash = user ? user.hash : DUMMY_HASH;
  const ok = await bcrypt.compare(password, hash);

  if (!user || !ok) {
    return res.status(401).json({ error: 'Invalid email or password' });   // uniform
  }
  if (user.mfaEnabled) {
    req.session.pendingUserId = user.id;         // require second factor next
    return res.json({ mfaRequired: true });
  }
  req.session.regenerate(err => {                // rotate ID -> kills fixation
    if (err) return res.sendStatus(500);
    req.session.userId = user.id;
    req.session.save(() => res.json({ ok: true }));
  });
});
```

## Python (Flask): Password Reset

### Vulnerable

```python
import hashlib, time
from flask import request

@app.route('/forgot', methods=['POST'])
def forgot():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()
    if not user:
        return 'No such user', 404                      # enumeration
    # Low-entropy, time-correlated, non-expiring token:
    token = hashlib.md5(f"{email}{int(time.time())}".encode()).hexdigest()
    user.reset_token = token
    db.session.commit()
    # Link built from the attacker-controlled Host header:
    link = f"https://{request.host}/reset?token={token}"   # host poisoning
    send_email(email, link)
    return 'Reset sent'
```

### Secure

```python
import secrets, hashlib
from datetime import datetime, timedelta, timezone
from flask import request, current_app

GENERIC = ('If an account exists, a reset link has been sent.', 200)

@app.route('/forgot', methods=['POST'])
@limiter.limit("5 per hour")                            # throttle abuse
def forgot():
    email = request.form['email'].strip().lower()
    user = User.query.filter_by(email=email).first()
    if user:
        raw = secrets.token_urlsafe(32)                 # 256-bit CSPRNG
        user.reset_hash = hashlib.sha256(raw.encode()).hexdigest()  # store HASH
        user.reset_expires = datetime.now(timezone.utc) + timedelta(minutes=20)
        db.session.commit()
        base = current_app.config['APP_ORIGIN']         # trusted, from config
        send_email(email, f"{base}/reset?token={raw}")  # single-use, expiring
    else:
        _spend_dummy_time()                             # constant-time-ish
    return GENERIC                                      # identical either way
```

## Java (Spring): Session Management

### Vulnerable

```java
@PostMapping("/login")
public String login(@RequestParam String user, @RequestParam String pass,
                    HttpSession session) {
    Account a = repo.findByUsername(user);
    // MD5, unsalted, and == comparison (not constant-time):
    if (a != null && a.getHash().equals(md5(pass))) {
        session.setAttribute("user", a.getId());   // no session rotation
        return "home";                             // fixation + weak hashing
    }
    return "login?error=badpassword";              // enumeration via message
}
```

### Secure

```java
@PostMapping("/login")
public String login(@RequestParam String user, @RequestParam String pass,
                    HttpServletRequest request) {
    Account a = repo.findByUsername(user.toLowerCase());
    // BCryptPasswordEncoder: salted, slow, constant-time verify
    boolean ok = a != null && encoder.matches(pass, a.getHash());
    if (!ok) {
        return "login?error=invalid";              // uniform message
    }
    // Rotate the session on privilege change -> defeats fixation:
    request.changeSessionId();
    request.getSession().setAttribute("user", a.getId());
    return "home";
}
```

#### Spring Security / cookie hardening

```yaml
# application.yml
server:
  servlet:
    session:
      timeout: 30m                 # idle timeout
      cookie:
        http-only: true            # not readable by JS
        secure: true               # HTTPS only
        same-site: lax             # CSRF hardening

# In HttpSecurity: rotate on auth + cap concurrent sessions
# http.sessionManagement(s -> s
#     .sessionFixation().changeSessionId()
#     .maximumSessions(3));
```

## JWT Validation Config

### Vulnerable

```javascript
// Trusts whatever the token claims; no exp/iss/aud enforcement.
const jwt = require('jsonwebtoken');
const claims = jwt.decode(token);                 // DECODE, not verify -- no signature check!
// or, almost as bad:
const c2 = jwt.verify(token, secret);             // algorithm not pinned -> alg confusion
if (c2.role === 'admin') grantAdmin();            // no exp checked -> forever-valid
```

### Secure

```javascript
const jwt = require('jsonwebtoken');
try {
  const claims = jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],                // PIN -- rejects alg:none / HS confusion
    issuer:   'https://auth.example.com',
    audience: 'https://api.example.com',
    maxAge:   '15m',                      // short-lived access token
    clockTolerance: 5,                    // small skew allowance
  });
  // Pair with a rotating refresh token + a jti deny-list so logout revokes access.
  return claims;
} catch (e) {
  return res.status(401).json({ error: 'Invalid token' });
}
```

## MFA / WebAuthn Config

### Weak: SMS-only, unlimited attempts

```python
# SMS OTP is SIM-swappable and phishable; unlimited tries allow brute force.
def verify_sms(user, code):
    return code == user.last_sms_code          # 6 digits, no attempt limit
```

### Strong: WebAuthn (phishing-resistant) with TOTP fallback

```javascript
// @simplewebauthn/server -- assertion is bound to the real origin
const verification = await verifyAuthenticationResponse({
  response: assertion,
  expectedChallenge: session.challenge,
  expectedOrigin: 'https://example.com',   // AitM proxy origin will NOT match
  expectedRPID: 'example.com',
  authenticator: storedAuthenticator,      // matched by credential ID
  requireUserVerification: true,
});
if (!verification.verified) return res.status(401).end();
// Store the new signature counter to detect cloned authenticators:
storedAuthenticator.counter = verification.authenticationInfo.newCounter;
```

```python
# TOTP fallback with a bounded window and rate limiting (Python)
import pyotp
def verify_totp(user, code):
    if too_many_recent_attempts(user):        # stop OTP brute force
        raise TooManyAttempts()
    return pyotp.TOTP(user.totp_secret).verify(code, valid_window=1)
```

## OAuth2 / OIDC Client Config

### Vulnerable

```
# Loose redirect + no state + no PKCE
GET /authorize?client_id=app
    &redirect_uri=https://app.example.com/cb/../..   # prefix/substring matching abused
    &response_type=token                             # implicit flow leaks token in URL
# No 'state' -> login CSRF; no PKCE -> code interception on public clients
```

### Secure

```
# Authorization-code + state + PKCE; exact redirect registered at the AS
GET /authorize?client_id=app
    &redirect_uri=https://app.example.com/callback   # EXACT match, registered
    &response_type=code
    &scope=openid%20profile
    &state=RANDOM_UNGUESSABLE                        # verified on callback
    &code_challenge=BASE64URL_SHA256_VERIFIER
    &code_challenge_method=S256

# On callback:
#   1. reject if state != stored state
#   2. exchange code WITH code_verifier
#   3. validate ID token signature + iss + aud + nonce
#   4. keep the client secret server-side only
```

> **Takeaway.** The secure versions share a pattern: fail closed, be uniform to the client, pin and validate everything the server relies on, and rotate/expire credentials so a single theft has a short, revocable lifetime.

## What's Next?

- **[Overview](./overview.md)**: concepts, impact, and the 2025 edition framing.
- **[Attack Vectors](./attack-vectors.md)**: the techniques these examples defend against.
- **[Prevention](./prevention.md)**: the layered defense model behind the secure code.
- **[Lab](./lab/authentication-failures/)**: hands-on practice.

---

*Part of the [OWASP Top 10 Educational Repository](/)*
