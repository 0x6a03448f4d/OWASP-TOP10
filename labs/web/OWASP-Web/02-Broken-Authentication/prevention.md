# A2:2017 - Broken Authentication - Prevention

## Table of Contents

- [Defense in Depth](#defense-in-depth)
- [1. Store Passwords Correctly](#1-store-passwords-correctly)
- [2. Sensible Password Policy (NIST)](#2-sensible-password-policy-nist)
- [3. Screen Against Breached Passwords](#3-screen-against-breached-passwords)
- [4. Rate Limiting & Lockout](#4-rate-limiting--lockout)
- [5. Multi-Factor Authentication](#5-multi-factor-authentication)
- [6. Secure Session Management](#6-secure-session-management)
- [7. Cookie Flags & Transport](#7-cookie-flags--transport)
- [8. Timeouts & Invalidation](#8-timeouts--invalidation)
- [9. Secure Password Recovery](#9-secure-password-recovery)
- [10. Anti-Enumeration & Generic Errors](#10-anti-enumeration--generic-errors)
- [Implementation Checklist](#implementation-checklist)
- [Next Steps](#next-steps)

## Defense in Depth

No single control fixes Broken Authentication. The defenses below are layered so a failure in one does not become an account takeover. The guiding principle: **lean on your framework and identity provider** for the hard parts (session generation, hashing, MFA) rather than hand-rolling them, and add the policy controls on top.

```
Layer                    Stops
------------------------ -------------------------------------------------
Strong hashing           mass cracking after a database leak
Breached-pw screening    weak/known passwords (spraying, easy guessing)
Rate limit + backoff     brute force and (partly) credential stuffing
Bot defense + MFA        credential stuffing that survives rate limits
Session regeneration     session fixation
Secure cookies + HSTS    session sniffing and script theft
Timeouts + invalidation  stolen / lingering sessions
Hardened recovery        account takeover via the reset flow
Generic errors + timing  username enumeration
```

## 1. Store Passwords Correctly

Use a slow, salted, memory-hard hash. **Argon2id** is the current first choice; **bcrypt** and **scrypt** are solid alternatives. Never use MD5, SHA-1, or a plain SHA-2 hash for passwords, and never store plaintext.

```python
# Python — Argon2 (preferred) via argon2-cffi
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()          # sensible memory/time/parallelism defaults
hash = ph.hash(password)       # salt is generated and embedded automatically

try:
    ph.verify(hash, password)  # constant-time, raises on mismatch
    if ph.check_needs_rehash(hash):
        hash = ph.hash(password)   # transparently upgrade parameters over time
except VerifyMismatchError:
    reject_login()
```

```javascript
// Node.js — bcrypt (cost factor tuned so a hash takes ~250ms+)
const bcrypt = require('bcrypt');
const COST = 12;                                  // raise as hardware improves
const hash = await bcrypt.hash(password, COST);   // salt embedded in the hash
const ok   = await bcrypt.compare(password, hash);// constant-time comparison
```

> **Rule of thumb**: tune the parameters so a single hash takes ~0.25–0.5 seconds on production hardware. Negligible per login, devastating to an attacker doing billions of offline guesses.

## 2. Sensible Password Policy (NIST SP 800-63B)

Favor **length over composition**. Require a reasonable minimum length, allow long passphrases and the full character set, and do **not** impose arbitrary complexity rules or forced periodic rotation.

| Do | Don't |
|----|-------|
| Minimum length ~8–12; allow up to 64+ | Cap length at 16 or block spaces |
| Allow all Unicode and passphrases | Force upper+lower+digit+symbol rules |
| Screen against breached-password lists | Force rotation every 90 days "just because" |
| Offer a password-strength meter | Enforce cryptic composition users can't remember |
| Rotate only on evidence of compromise | Use knowledge-based "security questions" |

## 3. Screen Against Breached Passwords

The single highest-value policy control is rejecting passwords already known to be compromised. Use a local list or a k-anonymity API.

```python
# Python — k-anonymity check against a breached-password corpus.
# Only the first 5 hex chars of the SHA-1 are sent; the suffix is compared
# locally, so the full password/hash never leaves the server.
import hashlib, requests

def is_breached(password: str) -> bool:
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                        headers={"Add-Padding": "true"}, timeout=3)
    return any(line.split(":")[0] == suffix for line in resp.text.splitlines())

# On register / password change:
if is_breached(new_password):
    reject("That password has appeared in a data breach; choose another.")
```

> Note: SHA-1 here is only a lookup key against a public corpus—*not* how the password is stored. Storage still uses Argon2/bcrypt.

## 4. Rate Limiting & Lockout

Throttle authentication attempts on multiple keys at once—per account, per IP, and globally. Prefer **exponential backoff** and **CAPTCHA/step-up** over hard permanent lockout, which invites denial-of-service.

```python
# Flask example using a shared store (Redis) for counters.
import time, redis
r = redis.Redis()

def check_rate(username, ip):
    now = int(time.time())
    acc_fails = int(r.get(f"fail:acc:{username}") or 0)
    ip_fails  = int(r.get(f"fail:ip:{ip}") or 0)
    if acc_fails >= 5 or ip_fails >= 50:
        delay = min(2 ** acc_fails, 60)     # exponential backoff, not perma-lock
        raise TooManyAttempts(retry_after=delay, captcha_required=True)

def record_failure(username, ip):
    for key in (f"fail:acc:{username}", f"fail:ip:{ip}"):
        r.incr(key); r.expire(key, 900)     # 15-minute rolling window

def record_success(username, ip):
    r.delete(f"fail:acc:{username}")         # reset on genuine success
```

```nginx
# Nginx edge rate limit as a coarse first line of defense
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
location = /login {
    limit_req zone=login burst=5 nodelay;
    proxy_pass http://app_upstream;
}
```

## 5. Multi-Factor Authentication

MFA is the most effective single defense against credential stuffing and phishing. Prefer **phishing-resistant** factors (WebAuthn/FIDO2). TOTP is a good widely-supported option; SMS is the weakest. Critically, **verify the second factor before issuing an authenticated session**.

```python
# Python — TOTP verification (RFC 6238) with pyotp, done BEFORE login completes
import pyotp

def complete_login(user, submitted_code):
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(submitted_code, valid_window=1):
        raise InvalidSecondFactor()        # do NOT elevate the session
    regenerate_session_id()                # only now create the session
    session["authenticated"] = True
    session["uid"] = user.id
```

- **Number-matching push** defeats MFA-fatigue: the user types a number shown on screen.
- **Throttle OTP entry** (a 6-digit code has only 10^6 values) and expire codes quickly.
- **Recovery codes** should be single-use; recovery must be as strong as the primary factor.

## 6. Secure Session Management

Use your framework's session machinery—it generates high-entropy, CSPRNG-backed identifiers. The one rule developers most often miss: **regenerate the session ID at every privilege change** (especially login), which eliminates session fixation.

```php
// PHP — regenerate the session ID on login (kills fixation)
session_start();
if (password_verify($password, $user['hash'])) {
    session_regenerate_id(true);   // true = delete the OLD session file
    $_SESSION['uid'] = $user['id'];
    $_SESSION['auth'] = true;
}
```

```python
# Python/Flask — clear and reissue the session on login
from flask import session

def login_success(user):
    session.clear()                 # drop any pre-auth (fixation) state
    session["uid"] = user.id
    session["auth_at"] = time.time()
```

Never accept a session identifier from the URL or a request parameter—only from the session cookie.

## 7. Cookie Flags & Transport

The session cookie must carry the full set of protective attributes, and the whole site must be HTTPS-only with HSTS.

```
Set-Cookie: sessionid=<high-entropy value>;
            Secure;          # only sent over HTTPS
            HttpOnly;        # unreadable by JavaScript (blocks XSS theft)
            SameSite=Lax;    # or Strict; limits cross-site sending
            Path=/;
            Max-Age=1800     # aligns with idle timeout

Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

```javascript
// Node/Express — secure session cookie configuration
app.use(session({
  secret: process.env.SESSION_SECRET,        // long random, from a secret store
  name: 'sid',                               // don't advertise the framework
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 1800000 }
}));
```

## 8. Timeouts & Invalidation

Sessions must end—both from inactivity and after an absolute maximum. Logout and password changes must invalidate sessions **server-side**, not just delete the client cookie.

```python
IDLE_LIMIT = 30 * 60          # 30 minutes of inactivity
ABSOLUTE_LIMIT = 12 * 3600    # 12 hours regardless of activity

def enforce_timeouts(session):
    now = time.time()
    if now - session["last_seen"] > IDLE_LIMIT:      destroy(session)
    if now - session["auth_at"]  > ABSOLUTE_LIMIT:   destroy(session)
    session["last_seen"] = now

def logout(session_id):
    server_side_store.delete(session_id)             # attacker's copy dies too

def on_password_change(user_id):
    server_side_store.delete_all_for_user(user_id)   # revoke ALL sessions
```

## 9. Secure Password Recovery

Treat the reset flow as a first-class authentication path. Reset tokens should be long, random, single-use, short-lived, delivered out-of-band, and the flow must not leak account existence or trust attacker-controlled headers.

```python
import secrets, hashlib, time

def create_reset_token(user):
    raw = secrets.token_urlsafe(32)                  # 256 bits of entropy
    db.save_reset(user.id,
                  token_hash=hashlib.sha256(raw.encode()).hexdigest(),  # hashed
                  expires_at=time.time() + 900,      # 15 minutes
                  used=False)
    email_out_of_band(user.email,
                      link=f"https://app.example/reset?token={raw}")
    return "If that account exists, we've sent reset instructions."  # no leak

def consume_reset_token(raw):
    h = hashlib.sha256(raw.encode()).hexdigest()
    rec = db.find_reset(token_hash=h)
    if not rec or rec.used or rec.expires_at < time.time():
        raise InvalidOrExpiredToken()
    rec.used = True; db.save(rec)                    # single use
    return rec.user_id
```

- Build reset links from a **server-configured base URL**, never the request `Host` header (prevents host-header poisoning).
- After a successful reset, **invalidate all existing sessions** for that user.
- Do not use knowledge-based "security questions."

## 10. Anti-Enumeration & Generic Errors

Give the same answer whether or not an account exists, and keep response timing uniform.

```python
DUMMY_HASH = ph.hash("a-fixed-throwaway-password")   # precomputed once

def login(username, password):
    user = db.find(username)
    if user is None:
        ph.verify_ignore_result(DUMMY_HASH, password) # spend the SAME time
        return "Invalid username or password."        # generic message
    try:
        ph.verify(user.hash, password)
    except VerifyMismatchError:
        return "Invalid username or password."        # SAME generic message
    return success(user)
```

Apply the same principle to registration, password reset, and any endpoint that could confirm which accounts exist. Compare tokens and MFA codes with constant-time functions (`hmac.compare_digest`, `hash_equals`).

## Implementation Checklist

- Passwords hashed with Argon2id / bcrypt / scrypt; parameters tuned; auto-rehash on login.
- Length-based policy; full character set allowed; no forced arbitrary rotation.
- New/changed passwords screened against breached lists.
- Login throttled per-account, per-IP, and globally with exponential backoff; CAPTCHA/step-up on abuse.
- MFA available and enforced for sensitive accounts; factor verified *before* session elevation; OTP entry throttled.
- Session IDs framework-generated, high-entropy, cookie-only; regenerated at login.
- Cookies set `Secure; HttpOnly; SameSite`; site is HTTPS-only with HSTS.
- Idle and absolute timeouts enforced; logout and password change invalidate sessions server-side.
- Reset tokens random, hashed-at-rest, single-use, short-lived, out-of-band; base URL server-configured.
- Generic errors and uniform timing everywhere; constant-time secret comparison.
- Default/sample credentials removed before production.

## Next Steps

- **[Examples](./examples.md)**: These defenses as vulnerable-vs-secure pairs in four languages.
- **[Attack Vectors](./attack-vectors.md)**: Revisit each attack now that you know the fix.
- **[Overview](./overview.md)**: The concepts, impact, and 2017->2021 lineage.
- **[Launch the Lab](./lab/broken-authentication/)**: Apply and verify these fixes against the intentionally vulnerable app (port 5020).

> Practice the fixes: In the lab at `./lab/broken-authentication/`, harden the login, session, and reset flows, then re-run the attacks from the previous page to confirm they now fail.
