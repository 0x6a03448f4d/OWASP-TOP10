# C7: Secure Digital Identities - Overview

## Table of Contents
- [What is this control?](#what-is-this-control)
- [Why Does This Matter?](#why-does-this-matter)
- [Matching Assurance to Risk](#matching-assurance-to-risk)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Common Misunderstandings](#common-misunderstandings)

## What is this control?

**Secure Digital Identities** is the proactive control that says: implement *identity, authentication, and session management* deliberately and correctly, and match the strength of those mechanisms to the risk of the thing they protect. It is the defensive discipline whose absence OWASP catalogues as **A07:2021 – Identification and Authentication Failures**. This control is the cure; that Top 10 category is the disease.

An "identity" here is the whole lifecycle of proving *who* a subject is and keeping that proof trustworthy over time. It is not a single login form. It is a set of decisions made across the system:

- **Authentication** — verifying a claimant with one or more factors (something you know / have / are), at an assurance level that fits the risk.
- **Credential storage** — passwords protected with a slow, salted algorithm (Argon2id, bcrypt, scrypt) so a stolen database is not a stolen password list. This cross-references [C2: Use Cryptography to Protect Data](/learn/proactive).
- **Multi-factor authentication (MFA)** — a second factor, preferring phishing-resistant methods (passkeys / WebAuthn / FIDO2) over one-time codes, and TOTP over SMS.
- **Session management** — issuing, protecting, rotating, and invalidating the token that represents "still logged in" after authentication succeeds.
- **Recovery and lifecycle** — registration, credential reset, and de-provisioning done without opening a bypass around every other control.

> **The distinction that matters:** "Identification and Authentication Failures" (A07) is what an attacker exploits. "Secure Digital Identities" (C7) is the set of controls you build so there is nothing to exploit. Everything in this lesson is framed as *the defense*.

### Core Concept

```
Secure Digital Identity:
  Passwords    -> length-first policy, checked against breach corpora
  Storage      -> Argon2id / bcrypt, per-user salt, no fast hashes
  MFA          -> phishing-resistant (passkeys/WebAuthn) > TOTP > SMS
  Sessions     -> CSPRNG IDs, regenerated on login, server-side invalidation
  Cookies      -> HttpOnly + Secure + SameSite, short idle + absolute timeout
  Recovery     -> non-enumerable, single-use, time-limited tokens
  Brute force  -> rate limiting + lockout + step-up on anomaly
  Tokens (JWT) -> verify sig+alg+exp+aud, short-lived, rotated

Insecure (what A07 looks like):
  Passwords    -> complexity theatre, forced rotation, no breach check
  Storage      -> plaintext, MD5/SHA-1, unsalted, reversible encryption
  MFA          -> none, or SMS-only, or bypassable "remember me" logic
  Sessions     -> predictable IDs, never regenerated, no server-side logout
  Cookies      -> no HttpOnly/Secure, session lives forever
  Recovery     -> enumerable reset, guessable/permanent tokens
  Brute force  -> unlimited attempts, no lockout, no monitoring
  Tokens (JWT) -> alg:none accepted, no expiry, signature never checked
```

### Why It Matters at the Center of Security

Authentication is the gate in front of everything else. Access control, encryption, and business logic all assume the system knows *who* is acting. If identity can be forged, guessed, replayed, or stolen, every downstream control is operating on a lie.

## Why Does This Matter?

### Business Impact

- **Account Takeover (ATO)**: The direct outcome of weak identity — attackers operate as legitimate users, moving money, exfiltrating data, and abusing trust.
- **Mass credential stuffing**: Reused passwords from other breaches are replayed at scale; without MFA and rate limiting a small fraction still succeeds, which is enough.
- **Regulatory exposure**: Authentication weaknesses that lead to personal-data exposure trigger GDPR, HIPAA, and PCI-DSS obligations and mandatory breach notification.
- **Fraud and reputation**: Takeovers of customer and admin accounts drive chargebacks, support cost, and lasting loss of trust.

### Technical Impact

- **Session hijacking**: A stolen or predictable session token grants full access without the password ever being known.
- **Privilege escalation**: A session not regenerated on privilege change lets a low-value session inherit high-value rights.
- **Token forgery**: Broken JWT verification (`alg:none`, unchecked signature) lets an attacker mint their own identity.
- **Federation abuse**: Misconfigured OAuth2/OIDC flows (open redirects, missing `state`, unvalidated `aud`) turn SSO into a bypass.

## Matching Assurance to Risk

The central idea of this control is **proportionality**: a throwaway newsletter signup and a banking transfer should not use the same identity assurance. NIST SP 800-63B frames authentication strength as **Authenticator Assurance Levels (AALs)**. Map the sensitivity of the action to the level required.

| Level | What it requires (paraphrased) | Fits |
|-------|--------------------------------|------|
| **AAL1** | Single factor (e.g. a strong password) with anti-guessing controls | Low-risk accounts, public content personalization |
| **AAL2** | Two distinct factors; MFA required, replay-resistant | Most user accounts holding personal or transactional data |
| **AAL3** | Hardware-based, phishing-resistant cryptographic authenticator (e.g. FIDO2) | Admin, financial, and high-value operations |

The practical takeaway: pick the level from the risk, then **step up** (re-authenticate or require a stronger factor) for sensitive actions such as changing an email, disabling MFA, or moving money — even inside an already-authenticated session.

## Technical Context

### 1. Strong Password Policy (length over complexity)

Modern guidance inverts the old rules. Favor **length**, allow the full character range including spaces, and stop fighting your users:

```
DO:
  - Require a minimum length (8+; 12+ for sensitive accounts)
  - Allow very long passphrases (support 64+ characters)
  - Screen new passwords against known-breached corpora (e.g. Pwned Passwords)
  - Allow paste and password managers
  - Store with Argon2id / bcrypt / scrypt  (see C2)

DON'T:
  - Force arbitrary composition rules (1 upper, 1 symbol...)
  - Force periodic rotation with no sign of compromise
  - Impose a low maximum length or strip characters
  - Use secret questions as a primary factor
```

**Why no forced rotation?** Mandatory periodic change pushes users toward predictable transforms (`Spring2024!` → `Summer2024!`) and weakens security. Rotate on evidence of compromise, not on a calendar.

### 2. Multi-Factor Authentication (prefer phishing-resistant)

Not all second factors are equal. Order of preference:

```
Best   -> Passkeys / WebAuthn / FIDO2   (phishing-resistant, bound to origin)
Good   -> Authenticator app TOTP        (offline, no carrier dependency)
Weak   -> SMS / email one-time codes     (SIM-swap, interception, phishing)
Avoid  -> Knowledge-based "security questions" as a factor
```

SMS is still better than nothing, but it is phishable and vulnerable to SIM-swap. Passkeys are origin-bound, so a look-alike phishing site cannot relay them.

### 3. Secure Session Management

```
- Session IDs from a CSPRNG, long and unpredictable
- Regenerate the session ID on login AND on privilege change
- Idle timeout + absolute timeout (a session cannot live forever)
- Cookies: HttpOnly; Secure; SameSite=Lax or Strict
- Invalidate server-side on logout (do not merely delete the cookie)
- Bind sensitive sessions and re-authenticate for step-up actions
```

### 4. Correct Token Handling (JWT / OAuth2 / OIDC)

When identity is carried in a token, the token must be verified fully, every time:

```
JWT verification MUST check:
  - Signature (with an expected key)
  - alg is an allow-listed algorithm  (never accept "none")
  - exp / nbf  (not expired, not before)
  - aud / iss  (intended for THIS service, from a trusted issuer)
Keep access tokens short-lived; rotate refresh tokens.

OAuth2 / OIDC MUST:
  - Use the Authorization Code flow with PKCE for public clients
  - Validate the state parameter (CSRF defense)
  - Use exact-match, pre-registered redirect URIs (no open redirect)
  - Validate the ID token's signature, aud, iss, and nonce
```

### 5. Credential Recovery and Account Enumeration

```
- Password reset tokens: single-use, time-limited, CSPRNG, hashed at rest
- Reset and login return IDENTICAL responses for valid/invalid accounts
- Never confirm "no such user" or "wrong password (user exists)"
- Rate-limit reset requests; notify the account owner on reset
```

## Real-World Impact

These are described as **incident classes** — recurring, well-documented patterns — rather than any single fabricated breach or CVE.

### Class 1: Credential Stuffing at Scale

**Pattern**: Attackers take username/password pairs leaked from unrelated breaches and replay them against login endpoints, betting on password reuse. Automated tooling distributes attempts across many IPs to evade simple counters.

**Why the control stops it**: MFA breaks the "password alone is enough" assumption; breach-corpus screening rejects known-compromised passwords at registration; and rate limiting plus anomaly detection make high-volume replay expensive and visible.

### Class 2: SIM-Swap and SMS OTP Interception

**Pattern**: An attacker socially engineers a carrier into porting a victim's number, then receives the victim's SMS one-time codes and completes "MFA." Variants intercept codes via phishing relays.

**Why the control stops it**: Preferring phishing-resistant, origin-bound authenticators (passkeys / WebAuthn) removes the shared-secret code an attacker can relay or redirect entirely.

### Class 3: Session Fixation and Non-Rotated Sessions

**Pattern**: The application keeps the same session identifier before and after login, or never invalidates it server-side, so an attacker who plants or captures a session ID rides the victim's authenticated session.

**Why the control stops it**: Regenerating the session ID on login and on privilege change, plus true server-side invalidation on logout, means a captured pre-auth identifier is worthless.

### Class 4: JWT "alg:none" and Signature Confusion

**Pattern**: A service accepts a JWT whose header claims `alg: none`, or is tricked into verifying an RS256 token as HS256 using the public key as the HMAC secret. Either way the attacker forges arbitrary claims (e.g. `role: admin`).

**Why the control stops it**: Pinning an allow-list of algorithms, rejecting `none`, and validating signature, `exp`, and `aud` on every request makes forged tokens fail verification.

## Common Misunderstandings

### Myth 1: "A strong password policy means lots of complexity rules"

**Reality**: Composition rules produce predictable passwords and frustrate users. Length, a breach-corpus check, and good hashing beat symbol requirements every time.

### Myth 2: "Any MFA is equal"

**Reality**: SMS codes are phishable and vulnerable to SIM-swap. Phishing-resistant, origin-bound factors (passkeys/FIDO2) are categorically stronger.

### Myth 3: "Deleting the cookie logs the user out"

**Reality**: If the session is not invalidated *server-side*, a copy of the token still works. Logout must destroy the server session, not just the client cookie.

### Myth 4: "A JWT is signed, so it is safe"

**Reality**: A signature is only as good as its verification. Accepting `alg:none`, skipping `exp`/`aud`, or never checking the signature makes the token trivially forgeable.

### Myth 5: "Telling the user 'no account found' is helpful"

**Reality**: Distinct responses for valid vs invalid accounts hand attackers a user-enumeration oracle for targeting and credential stuffing.

## How C7 Relates to Other Controls

| Aspect | C7: Secure Digital Identities | C2: Use Cryptography | C1: Access Control |
|--------|-------------------------------|----------------------|--------------------|
| **Question answered** | Who are you, and are you still you? | Are the bytes protected? | Are you allowed to do this? |
| **Owns** | Auth, MFA, sessions, tokens | Hashing, encryption, keys | Authorization decisions |
| **Shared ground** | Uses C2's hashing to store credentials | Provides the password hash + token signing | Trusts C7's identity as its input |

## Key Takeaways

1. **Match assurance to risk** — use NIST AALs to decide how strong authentication must be for each action.
2. **Length beats complexity** — long passphrases, breach screening, and slow hashing, with no forced rotation.
3. **Prefer phishing-resistant MFA** — passkeys/WebAuthn over TOTP over SMS.
4. **Own the whole session** — CSPRNG IDs, regenerate on login/privilege change, real server-side logout, hardened cookies.
5. **Verify tokens fully** — signature, algorithm, expiry, and audience, every request; short-lived and rotated.

## Next Steps

- **[Threats Addressed](attack-vectors.md)**: What goes wrong when this control is missing or misused
- **[How to Implement](prevention.md)**: The step-by-step guide to building secure identity
- **[Examples](examples.md)**: Insecure vs. secure auth, session, and MFA code in Node, Python, and Java
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
