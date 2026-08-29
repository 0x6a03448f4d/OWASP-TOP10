# C7: Secure Digital Identities - Threats Addressed

## Table of Contents
- [What This Control Defends Against](#what-this-control-defends-against)
- [The Threats, One by One](#the-threats-one-by-one)
- [How These Threats Chain](#how-these-threats-chain)

## What This Control Defends Against

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can understand what *Secure Digital Identities* mitigates and verify it in systems you own or are authorised to test.

This control exists to close a specific family of weaknesses that OWASP groups under **A07:2021 – Identification and Authentication Failures**. Each threat below is paired with the part of the control that neutralises it. Read this page as "here is the attack, and here is why the defense removes it."

## The Threats, One by One

### 1. Credential Stuffing

Attackers replay username/password pairs harvested from other breaches, exploiting password reuse. It needs no cleverness — only volume and a login endpoint that answers unlimited attempts.

```python
# Automated replay of leaked pairs against the login API
for user, pw in leaked_pairs:            # millions of pairs
    r = post("/api/login", {"user": user, "password": pw})
    if r.status == 200:
        save_valid(user, pw)             # a small hit-rate is still thousands of accounts
```

**Mitigated by**: MFA (a valid password alone no longer suffices), breach-corpus screening at registration, rate limiting, and login anomaly detection.

### 2. Brute Force / Password Guessing

Where stuffing reuses known passwords, brute force generates them — against a single account (vertical) or one password across many accounts (horizontal / password spraying).

```python
# Password spraying: one weak password, many accounts, stays under per-account limits
for user in all_users:
    post("/api/login", {"user": user, "password": "Winter2026!"})
# No lockout + no global throttle => spraying succeeds silently
```

**Mitigated by**: account lockout / exponential backoff, global and per-IP rate limiting, breach-and-common-password screening, and MFA.

### 3. Weak and Breached Passwords

Even without automation, a password that is short, common, or already in a breach corpus is effectively public. Complexity theatre (`P@ssw0rd`) produces exactly these.

```python
# Registration accepts anything the regex allows:
password = "P@ssw0rd"        # meets "1 upper, 1 digit, 1 symbol" — and is in every wordlist
# No check against known-breached corpora => a compromised password ships to production
```

**Mitigated by**: length-first policy, screening new passwords against known-breached corpora (e.g. Pwned Passwords), and Argon2id/bcrypt storage so a database leak is not a password leak.

### 4. Session Attacks (Hijacking, Fixation, Non-Invalidation)

Once authenticated, the user is represented by a session token. If that token is predictable, stealable, fixable, or immortal, the password becomes irrelevant.

```http
# (a) Fixation: attacker sets a known session id, victim logs in, id never rotates
Set-Cookie: SESSIONID=attacker_known_value
# ...victim authenticates, server keeps the SAME id => attacker is now logged in

# (b) Non-invalidation: "logout" only clears the client cookie
POST /logout            -> 200 OK        # server session still valid
Cookie: SESSIONID=captured_value         # replayed token still works

# (c) Predictable id: sequential/timestamped tokens can be guessed
SESSIONID=00000001 ... 00000002 ...
```

**Mitigated by**: CSPRNG session IDs, **regeneration on login and on privilege change**, true server-side invalidation on logout, idle + absolute timeouts, and `HttpOnly; Secure; SameSite` cookies.

### 5. MFA Bypass

MFA only helps if it cannot be skipped, relayed, or fatigued away.

```http
# (a) Skipping the second step: the app trusts a client-side "mfa_passed" flag
POST /api/login       -> { "mfa_required": true, "session": "..." }
GET  /api/account     Cookie: session=...   # 200 without ever completing step 2

# (b) Real-time phishing relay of an SMS/TOTP code:
victim -> types code into look-alike site -> attacker replays it to the real site

# (c) MFA-fatigue: spam push prompts until the victim taps "approve"
```

**Mitigated by**: enforcing the second factor *server-side* (never a client flag), preferring phishing-resistant, origin-bound authenticators (passkeys/WebAuthn) that a relay cannot forward, number-matching / limited push prompts, and step-up re-authentication for sensitive actions.

### 6. Broken JWT and OAuth2/OIDC Handling

When identity is carried in a token or delegated via SSO, verification mistakes let an attacker forge or hijack identity.

```python
# (a) alg:none — a token with no signature is accepted
header  = {"alg": "none", "typ": "JWT"}
payload = {"sub": "attacker", "role": "admin"}
# server does not enforce an algorithm allow-list => forged admin token

# (b) Algorithm confusion — RS256 token verified as HS256 using the PUBLIC key as secret
token = sign_hs256(payload, public_key_pem)   # server "verifies" and trusts it

# (c) OAuth: missing state + loose redirect_uri
GET /authorize?...&redirect_uri=https://evil.example/cb   # code delivered to attacker
# no 'state' => CSRF login; wildcard redirect => code/token theft
```

**Mitigated by**: verifying signature with an allow-listed algorithm (reject `none`), validating `exp`/`nbf`/`aud`/`iss` on every request, keeping access tokens short-lived and rotating refresh tokens, and for OAuth2/OIDC using Authorization Code + PKCE, a validated `state`, exact-match redirect URIs, and ID-token `aud`/`nonce` checks.

### 7. Account Enumeration

Not an attack by itself, but the reconnaissance that makes the others precise: any difference in response between "valid user" and "invalid user" builds a target list.

```http
POST /login  {"user":"alice","password":"x"}  -> "Incorrect password"     # alice EXISTS
POST /login  {"user":"zzz","password":"x"}    -> "No such user"           # zzz does not
# timing differences and reset-flow wording leak the same signal
```

**Mitigated by**: identical responses (and comparable timing) for valid vs invalid accounts across login, registration, and password reset; rate-limiting these endpoints.

## How These Threats Chain

Individually survivable weaknesses combine into full account takeover:

```
Enumeration confirms valid accounts
        +
Weak/breached password (no screening)   -> credential stuffing gets a hit
        +
No MFA (or SMS MFA + SIM-swap)          -> second factor bypassed
        +
Session never regenerated               -> foothold persists after "logout"
        =  durable account takeover, no software exploit required
```

A second common chain targets tokens:

```
OAuth redirect_uri too loose  -> attacker captures the authorization code
        -> code exchanged for tokens
        -> JWT aud never validated -> token replayed against a second service
        =  cross-service identity compromise
```

## Key Takeaways

1. **Passwords alone always fall** — stuffing, spraying, and breach reuse defeat any single knowledge factor eventually; MFA is what changes the math.
2. **The session is a second password** — predictable, fixable, or immortal sessions undo a perfect login.
3. **MFA must be unskippable and unrelayable** — enforce it server-side and prefer phishing-resistant factors.
4. **Tokens are only as strong as their verification** — algorithm, signature, expiry, and audience, every request.
5. **Silence is a defense** — non-enumerable responses deny attackers the targeting they rely on.

## Next Steps

- **[How to Implement](prevention.md)**: Build secure identity step by step
- **[Examples](examples.md)**: Insecure vs. secure auth, session, and MFA code
- **[Overview](overview.md)**: What this control is and why it matters
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
