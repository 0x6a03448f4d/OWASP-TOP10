# A7:2021 – Identification and Authentication Failures: Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY.** The techniques below are described so defenders can recognize, test (with authorization), and prevent them. Never exercise these against systems you do not own or have explicit written permission to test.

## Table of Contents

- [The Core Attack Flow](#the-core-attack-flow)
- [1. Credential Stuffing](#1-credential-stuffing)
- [2. Brute Force (Vertical)](#2-brute-force-vertical)
- [3. Password Spraying (Horizontal)](#3-password-spraying-horizontal)
- [4. Default and Weak Passwords](#4-default-and-weak-passwords)
- [5. Account Enumeration](#5-account-enumeration)
- [6. Session Fixation](#6-session-fixation)
- [7. Predictable / Weak Session IDs](#7-predictable--weak-session-ids)
- [8. Session Token Theft & Exposure in URLs](#8-session-token-theft--exposure-in-urls)
- [9. Missing Session Invalidation](#9-missing-session-invalidation)
- [10. Insecure Password Recovery](#10-insecure-password-recovery)
- [11. MFA Bypass & Fatigue](#11-mfa-bypass--fatigue)
- [12. JWT / Token Validation Abuse](#12-jwt--token-validation-abuse)
- [How Defenders Detect These](#how-defenders-detect-these)

## The Core Attack Flow

Nearly every authentication attack follows the same shape: **find valid identities, obtain or forge proof, and ride the resulting session**.

```
1. RECON      -> enumerate valid usernames/emails (login, register, reset, timing)
2. ACQUIRE    -> get a credential (stuffing, spray, brute force, phishing, breach dump)
   or FORGE   -> craft a token the server will trust (weak JWT, predictable session ID)
3. AUTHENTICATE / HIJACK -> log in, or fix/steal a session, or bypass MFA
4. PERSIST    -> keep a token that is never invalidated; add attacker MFA/recovery
5. ACT        -> operate as the victim; escalate to higher-value accounts
```

The 12 vectors below map onto these stages. Anti-automation, MFA, and correct session handling break the flow at different points—which is exactly why defense must be layered.

## 1. Credential Stuffing

The most common authentication attack on the internet. The attacker takes `email:password` pairs leaked from unrelated breaches and replays them against the target, betting on password reuse. No vulnerability in *your* code is required—only the acceptance of high-volume automated logins.

```
# Conceptual loop (defenders study this shape to detect it)
for email, password in breach_dump:          # millions of pairs
    r = POST /api/login {email, password}
    if r.status == 200 and r.has_session:
        record_valid(email, password)         # account taken over
    # rotate IPs / proxies to evade per-IP limits
    # randomize timing and User-Agent to look human
```

**What makes it work**: no MFA, no bot detection, unlimited attempts, and no breached-password screening. **Tell-tale signs**: a spike in login volume with a high failure rate, many distinct usernames from few IPs (or the reverse), and datacenter/proxy source IPs.

## 2. Brute Force (Vertical)

Many password guesses against a **single** account. Effective only when the account uses a weak password and the endpoint does not throttle or lock.

```
POST /login  user=admin password=admin
POST /login  user=admin password=123456
POST /login  user=admin password=password
POST /login  user=admin password=Summer2025!
...            # dictionary + rules, thousands/sec if unthrottled
```

**Countered by**: rate limiting, exponential backoff, lockout with care (see spraying), and MFA. Brute force is loud and the easiest vector to detect via failed-attempt counters.

## 3. Password Spraying (Horizontal)

The inverse of brute force and specifically designed to defeat per-account lockout. The attacker tries **one** common password against **many** accounts, so no single account crosses its failed-attempt threshold.

```
password = "Winter2025!"
for user in [alice, bob, carol, dave, ... 50000 users]:
    POST /login {user, password}     # ONE attempt per account
# then wait, pick the next seasonal password, repeat next day
```

**Why it evades lockout**: lockout counts failures *per account*; spraying stays at one failure per account. **Detection requires** watching for a single credential or IP touching many distinct accounts, and correlating low-and-slow patterns across time.

## 4. Default and Weak Passwords

Shipped or seeded accounts (`admin/admin`, `root/root`, `guest/guest`), and user-chosen passwords that appear in breach corpora, are guessed on the first try.

```
# Attacker's first moves before any real "attack":
admin / admin        test / test         demo / demo
root / toor          service / service   admin / changeme
```

**Root cause**: no enforced password policy, no breached-password screening, and setup/sample accounts left enabled. This is CWE-521 and CWE-798.

## 5. Account Enumeration

Before guessing passwords, attackers first confirm *which accounts exist*. Any observable difference between "known" and "unknown" identities leaks that list.

#### Different response bodies
```
POST /login  user=real@site.com   -> "Incorrect password"
POST /login  user=fake@site.com   -> "No account with that email"   # LEAK
```

#### Registration and reset leaks
```
POST /register  email=real@site.com  -> "Email already in use"       # LEAK
POST /forgot     email=fake@site.com -> "No such account"            # LEAK
```

#### Timing side channel
```
# Real account: server runs full bcrypt verify  -> ~250 ms
# Unknown account: server returns immediately    ->  ~15 ms
# The response-time difference alone enumerates users.
```

**Fix direction**: identical response, status code, and timing for existent and non-existent accounts across *every* identity endpoint (covered in Prevention).

## 6. Session Fixation

If the application does not issue a **new** session ID at login, an attacker can set a known ID in the victim's browser first, then hijack the session once the victim authenticates under that same ID.

```
1. Attacker obtains a valid pre-login session ID:  SID=abc123
2. Attacker tricks victim into using it
   (e.g. link with ?sessionid=abc123, or setting the cookie via XSS)
3. Victim logs in. Server KEEPS SID=abc123 (bug: no regeneration)
4. Attacker now uses SID=abc123 -> authenticated as the victim
```

**Root cause (CWE-384)**: session identifier not regenerated on privilege change. The one-line fix is to rotate the ID at login.

## 7. Predictable / Weak Session IDs

If session identifiers are sequential, timestamp-based, or drawn from a weak PRNG, an attacker can predict or enumerate valid sessions belonging to other users.

```
# VULNERABLE token generation the attacker exploits:
session_id = md5(username + str(int(time.time())))   # guessable
session_id = last_id + 1                              # sequential -> enumerate
token      = random.randint(1000, 999999)            # tiny keyspace -> brute force
```

**Attack**: capture your own token, infer the pattern, then generate or iterate other users' tokens. **Fix direction**: at least 128 bits from a cryptographically secure RNG (see Prevention/Examples).

## 8. Session Token Theft & Exposure in URLs

A token placed in the URL, or a cookie missing protective flags, leaks through many channels the developer never intended.

```
https://app.example.com/dashboard?sessionid=abc123def456
        ^-- leaks via: server/proxy access logs, browser history,
            the Referer header sent to third parties, and any
            "share this link" the user copies and pastes.
```

Missing cookie flags widen the theft surface:

| Missing flag | How the token is stolen |
|--------------|-------------------------|
| No `HttpOnly` | JavaScript (from an XSS payload) reads `document.cookie` |
| No `Secure` | Cookie sent over plaintext HTTP and captured on the network |
| No `SameSite` | Cookie auto-sent on cross-site requests, enabling CSRF-style riding |

## 9. Missing Session Invalidation

Many "logout" implementations only delete the client-side cookie. If the session or token remains valid in the server-side store, a previously captured copy still authenticates.

```
# Attacker captured the token earlier (XSS, proxy, shared device).
# Victim clicks "Log out".
#   Client: cookie deleted.
#   Server: session record UNCHANGED.   <-- the flaw (CWE-613)
# Attacker replays the captured token -> still logged in.
```

The same flaw appears as: no idle timeout, no absolute timeout, and password changes that do not revoke existing sessions. A user who changes a compromised password reasonably assumes attacker sessions are killed—often they are not.

## 10. Insecure Password Recovery

The "forgot password" flow is a second authentication path and is frequently weaker than the primary one.

- **Knowledge-based questions**: "mother's maiden name," "first pet"—often public or guessable, and reused across sites.
- **Predictable or non-expiring reset tokens**: sequential IDs, or links that never expire and can be replayed.
- **Reset that reveals account existence**: "we sent an email" vs "no such account" leaks enumeration.
- **Reset that skips re-authentication of the session**: changing a password without invalidating other active sessions leaves the attacker logged in.

```
# Weak reset token an attacker can guess or iterate:
GET /reset?token=1001    GET /reset?token=1002    GET /reset?token=1003
# Should be: high-entropy, single-use, short-lived, and bound to the account.
```

## 11. MFA Bypass & Fatigue

MFA dramatically reduces takeover, but weak implementations are bypassable:

- **MFA not enforced on all paths**: legacy APIs, mobile endpoints, or "remember this device" flows that skip the second factor.
- **OTP brute force**: a 6-digit code with no attempt limit is only 1,000,000 guesses; without rate limiting it is brute-forceable.
- **MFA fatigue / prompt bombing**: repeatedly triggering push approvals until a tired user taps "approve."
- **Phishable factors**: SMS OTP and TOTP can be relayed through a real-time phishing proxy; the attacker forwards the code instantly.
- **Recovery downgrade**: falling back to a weaker factor (email link, security question) defeats the strong one.

**Defense direction**: prefer phishing-resistant factors (FIDO2/WebAuthn passkeys), rate-limit OTP entry, use number-matching to counter fatigue, and enforce MFA on every path.

## 12. JWT / Token Validation Abuse

Bearer tokens are only as strong as their verification. Common abuses:

#### alg: none
```
# Attacker rewrites the header to claim "no signature":
{ "alg": "none", "typ": "JWT" }.{ "sub": "admin", "role": "admin" }.
# A validator that honors "none" accepts an UNSIGNED, attacker-authored token.
```

#### Algorithm confusion (RS256 -> HS256)
```
# Server expects RS256 (verify with RSA PUBLIC key).
# Attacker sends an HS256 token and signs it with that PUBLIC key as the HMAC secret.
# A naive library uses the header's alg + the public key -> signature "valid".
```

#### Missing claim checks
```
# Token accepted despite:
#   exp in the past      -> expired token still works (no expiry check)
#   iss / aud wrong      -> token minted for another service is accepted
#   no signature verify  -> payload trusted as-is
```

**Root cause**: trusting the token's own header to choose the verification method, and skipping standard claim validation. Prevention pins the algorithm and verifies signature + `exp`/`iss`/`aud` server-side.

## How Defenders Detect These

| Vector | Primary signal | Primary control |
|--------|----------------|-----------------|
| Credential stuffing | High login volume, high failure rate, proxy IPs | MFA, bot detection, breached-password screening |
| Brute force | Many failures on one account | Rate limit + backoff, MFA |
| Password spraying | One credential/IP across many accounts | Per-IP/credential throttling, anomaly detection |
| Enumeration | Sequential probing of login/register/reset | Uniform responses and timing |
| Session fixation | Same session ID before and after login | Regenerate ID at login |
| Predictable IDs | Low-entropy tokens, guessing attempts | CSPRNG, ≥128-bit IDs |
| Missing invalidation | Token used after logout | Server-side revocation, timeouts |
| JWT abuse | Unexpected alg, invalid signatures | Pin alg, verify signature + claims |

## Next Steps

- **[Overview](./overview.md)**: The concepts, lineage, and business context
- **[Prevention](./prevention.md)**: Layered defenses with real code and configuration
- **[Examples](./examples.md)**: Vulnerable vs. secure implementations to compare
- **[Lab](./lab/weak-session-lab/)**: Exploit and then fix weak session management safely

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
