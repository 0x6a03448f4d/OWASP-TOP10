# Authentication Failures (2025) - Overview

## Table of Contents
- [What Are Authentication Failures?](#what-are-authentication-failures)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Classification](#prevalence-and-classification)
- [Common Misunderstandings](#common-misunderstandings)
- [Self-Assessment](#self-assessment)
- [What's Next?](#whats-next)

## What Are Authentication Failures?

**Authentication Failures** is the 2025 edition's name for the category that covers every way an application fails to reliably confirm *who* is making a request and to keep that confirmation trustworthy for the life of a session. It is the direct evolution of **A07:2021 — Identification and Authentication Failures**, which was itself the 2021 renaming and re-scoping of **A2:2017 — Broken Authentication**. The 2025 edition trims the name back toward its origins while broadening the technical scope to reflect how identity is actually verified today: passkeys, federated sign-in, and short-lived tokens rather than a single password box.

Authentication answers the question *"are you who you claim to be?"* It is distinct from **authorization** (A01, "are you allowed to do this?"). A system can authenticate a user perfectly and still make an access-control mistake, and it can authorize flawlessly yet hand a valid session to an impostor. This category is about the first half of that pair — establishing identity and preserving it.

At its core, an authentication failure happens whenever an attacker can obtain, guess, forge, or reuse the proof of identity that should belong to someone else. Concretely, the category covers:

- **Automated credential attacks**: credential stuffing (replaying breached username/password pairs), password spraying (one common password against many accounts), and classic brute force.
- **Weak, default, or breached passwords**: permitting `password1`, shipping `admin/admin`, or accepting a password already known to appear in public breach corpora.
- **Missing or weak multi-factor authentication (MFA)**: no second factor at all, or a phishable one (SMS OTP, TOTP typed into a fake page, push prompts vulnerable to fatigue).
- **Broken session management**: session fixation, predictable or low-entropy session identifiers, failure to rotate the identifier on login or privilege change, sessions that are never invalidated server-side on logout, and lifetimes that never expire.
- **Insecure credential recovery**: password-reset flows with guessable tokens, tokens that do not expire, or host-header / link poisoning that redirects the reset to an attacker.
- **Account enumeration**: login, registration, or reset responses that reveal whether a given username or email exists.
- **JWT and token flaws**: accepting `alg: none`, trusting weak or reused signing secrets, or skipping expiry, issuer, and audience validation.
- **OAuth2 / OIDC misconfiguration**: loose `redirect_uri` matching, a missing or unverified `state` parameter, and missing PKCE on public clients.

### Core Concept

```
Authentication done right:
  Identity claim   -> username / email / subject
  Proof            -> something you know + have + are (phishing-resistant preferred)
  Verification     -> constant-time compare, breach + policy checks, rate limits
  Session issued   -> high-entropy, server-tracked, rotated on privilege change
  Session ended    -> invalidated server-side on logout, idle, and absolute timeout

AUTHENTICATION FAILURE = any step where an attacker can
  obtain, guess, forge, or REUSE proof that is not theirs
  -> account takeover
```

### Continuity Across Editions

| Edition | Category name | Emphasis |
|---------|---------------|----------|
| 2017 — A2 | Broken Authentication | Passwords, session IDs, credential management |
| 2021 — A07 | Identification and Authentication Failures | Adds identity proofing, credential recovery, session lifecycle |
| 2025 — A07 | Authentication Failures | Adds MFA/phishing-resistance, JWT/token validation, OAuth/OIDC, passkeys |

> **Naming note.** The exact ranking and wording of the 2025 list are finalised by OWASP from contributed data. This lesson follows the 2025 edition's framing of the authentication category and treats its ordinal position as continuity with the well-established 2021 `A07` slot rather than asserting a precise new incidence figure.

## Why Does This Matter?

Authentication is the front door of almost every application. When it fails, an attacker does not need a clever memory-corruption exploit or an injection payload — they simply *log in as someone else* and inherit that person's data and privileges. This is why account takeover consistently sits among the most common root causes behind reported breaches.

### Business Impact

- **Account takeover (ATO)**: attackers drain balances, place fraudulent orders, exfiltrate personal data, and abuse trust relationships from a legitimate-looking session.
- **Large-scale fraud**: credential-stuffing operations monetise millions of reused passwords across retail, streaming, travel, and financial platforms.
- **Regulatory exposure**: exposed personal data triggers GDPR, CCPA, HIPAA, and PCI-DSS obligations, fines, and mandatory breach notification.
- **Reputation and churn**: publicised ATO waves erode user trust and drive customers to competitors.
- **Support and remediation cost**: forced password resets, fraud reimbursement, and incident response are expensive even when no data is technically "breached."

### Technical Impact

- **Full identity compromise**: once a session or token is stolen, every downstream authorization check trusts the attacker.
- **Privilege escalation**: a compromised admin or service account opens lateral movement across the system.
- **Persistence**: long-lived or non-revocable tokens let an attacker return long after the original theft.
- **Bypass of other controls**: MFA fatigue and adversary-in-the-middle phishing defeat controls that look strong on paper.
- **Trust-chain damage**: a forged JWT or a mis-scoped OAuth token can be accepted by many services that share the same identity provider.

## Technical Context

### Identification, Authentication, and Session — Three Distinct Steps

It is worth separating the moving parts, because failures cluster differently at each stage:

1. **Identification** — the user asserts an identity (a username, email, or subject claim). Leaking whether that identity exists is *account enumeration*.
2. **Authentication** — the user proves the claim with one or more factors. Weak proofs, missing MFA, and automated guessing live here.
3. **Session / token** — after a successful proof, the server issues a credential (a session cookie or token) that stands in for the user on subsequent requests. Fixation, weak IDs, missing rotation, and missing invalidation live here.

### The Three Authentication Factors

| Factor | Examples | Weakness |
|--------|----------|----------|
| **Something you know** | Password, PIN, security question | Guessable, reusable, phishable, breached |
| **Something you have** | Phone (SMS/TOTP), security key, passkey | SMS is SIM-swappable; TOTP is phishable; keys resist both |
| **Something you are** | Fingerprint, face, voice | Not secret, hard to revoke, spoofable in some modes |

**Multi-factor authentication** combines factors from different categories. Not all MFA is equal: SMS one-time codes and TOTP apps raise the bar against password reuse but are *phishable* — an adversary-in-the-middle page relays the code in real time. **Phishing-resistant** methods (passkeys / WebAuthn / FIDO2 security keys) bind the credential to the origin cryptographically, so a fake domain cannot complete the ceremony.

### Passwords: Policy Has Shifted

Modern guidance (**NIST SP 800-63B**) inverts much of the older "complexity" advice:

- **Favour length over composition**: allow long passphrases (at least 8, ideally 12+ characters; support up to 64+) and drop mandatory upper/lower/digit/symbol rules.
- **Screen against breach corpora**: reject passwords known to appear in public breach lists (for example via a k-anonymity range query so the full password never leaves the client).
- **Do not force periodic rotation** without evidence of compromise — it drives predictable, weaker choices.
- **Drop knowledge-based "security questions"**: the answers are often public or guessable.
- **Store with a slow, salted password hash**: Argon2id, scrypt, or bcrypt — never MD5/SHA-1 or a fast unsalted hash.

### Sessions and Tokens

```
Stateful session (server-side store):
  Cookie holds a random 128-bit+ ID -> server looks up session state
  Revocation is easy: delete the server record

Stateless token (e.g. JWT):
  Token itself carries the claims, signed by the server
  Fast and scalable, but revocation is HARD -> keep lifetimes short,
  validate alg + exp + iss + aud, and pair with a refresh/deny mechanism
```

Both models fail in similar ways: a predictable identifier can be guessed, an identifier that is never rotated enables fixation, and a credential that is never invalidated survives logout. Stateless tokens add their own failure modes around *who signed this and is it still valid*.

## Real-World Impact

The examples below are described as **classes of incident** that have been widely reported and independently documented. They are included to show how the failure modes play out, without asserting invented CVE numbers or precise victim counts.

### Class 1: Credential Stuffing Against Consumer Platforms

**Pattern**: attackers take username/password pairs from unrelated breaches and replay them at scale against streaming, retail, food-delivery, and financial services.
**Why it works**: users reuse passwords, and many sites have no rate limiting, no breach screening, and no MFA.
**Lesson**: breach screening, per-account throttling, device intelligence, and MFA break the economics of reuse.

### Class 2: MFA Fatigue / Push Bombing

**Pattern**: with a valid password in hand, an attacker triggers a flood of "approve sign-in?" push notifications until a tired or confused user taps *approve*. This technique was central to several widely reported 2022–2023 intrusions, including the well-documented Uber compromise.
**Lesson**: replace simple push approval with number-matching, rate-limit prompts, and move privileged accounts to phishing-resistant passkeys/security keys.

### Class 3: SIM Swap Defeating SMS OTP

**Pattern**: an attacker convinces (or bribes) a mobile carrier to port a victim's number to a new SIM, then receives the victim's SMS one-time codes and resets accounts.
**Lesson**: treat SMS as a low-assurance factor; prefer app-based or hardware factors, and never gate high-value recovery on SMS alone.

### Class 4: Adversary-in-the-Middle (AitM) Session-Cookie Theft

**Pattern**: a reverse-proxy phishing kit sits between the victim and the real site, relays the login and the OTP in real time, and steals the resulting *session cookie* — bypassing password and phishable MFA together.
**Lesson**: phishing-resistant WebAuthn defeats this because the credential is bound to the true origin; also bind sessions to client signals and shorten lifetimes.

### Class 5: JWT Algorithm and Secret Flaws

**Pattern**: a long-standing vulnerability class in which verifiers accept a token with `"alg": "none"`, or accept an `HS256` token signed with the public RSA key when they expected `RS256`, or trust a weak shared secret that is then brute-forced offline.
**Lesson**: pin the expected algorithm server-side, never let the token choose it, use strong secrets or asymmetric keys, and always check `exp`, `iss`, and `aud`.

### Class 6: OAuth / OIDC Redirect and State Flaws

**Pattern**: loose `redirect_uri` validation lets an attacker redirect the authorization code to a site they control; a missing or unverified `state` parameter enables login CSRF and account linking attacks.
**Lesson**: use exact-match registered redirect URIs, enforce `state`, and require PKCE for public clients.

## Prevalence and Classification

Authentication failures are among the most consistently present weakness classes in the OWASP data set — they have appeared in the Top 10 in every edition, under one name or another, since 2017. Rather than quote a specific incidence percentage for the 2025 edition (which is finalised by OWASP from contributed data), it is more useful to know the underlying weaknesses this category maps to.

### Representative CWE Mappings

| CWE | Weakness |
|-----|----------|
| **CWE-287** | Improper Authentication |
| **CWE-294** | Authentication Bypass by Capture-Replay |
| **CWE-307** | Improper Restriction of Excessive Authentication Attempts |
| **CWE-384** | Session Fixation |
| **CWE-521** | Weak Password Requirements |
| **CWE-613** | Insufficient Session Expiration |
| **CWE-620** | Unverified Password Change |
| **CWE-640** | Weak Password Recovery Mechanism |
| **CWE-798** | Use of Hard-coded Credentials |
| **CWE-346** | Origin Validation Error (relevant to OAuth/JWT audience) |

### Where the Failures Cluster

| Surface | Typical failure | Risk level |
|---------|-----------------|------------|
| Login endpoint | No rate limit, enumeration, no MFA | Critical |
| Password reset | Guessable token, host-header poisoning | Critical |
| Session cookie | Missing HttpOnly/Secure/SameSite, no rotation | High |
| JWT verification | alg confusion, missing exp/aud checks | Critical |
| OAuth client | Loose redirect_uri, missing state/PKCE | High |

## Common Misunderstandings

### Myth 1: "We have MFA, so we're safe."

**Reality**: SMS and TOTP MFA are *phishable*. An adversary-in-the-middle page relays the code in real time and steals the session. Only phishing-resistant methods (passkeys/WebAuthn/FIDO2) bind the credential to the origin.

### Myth 2: "A complex password rule (upper + digit + symbol) is what makes passwords strong."

**Reality**: NIST 800-63B favours *length* and *breach screening* over composition rules, which mostly produce predictable patterns like `Password1!`.

### Myth 3: "JWTs are secure because they're signed."

**Reality**: a signature only helps if the verifier pins the algorithm and checks `exp`, `iss`, and `aud`. Accepting `alg: none` or letting the token choose the algorithm defeats the signature entirely.

### Myth 4: "Logout clears the session."

**Reality**: deleting a client cookie does nothing if the server never invalidates the session record or the token. Stolen credentials keep working until they expire.

### Myth 5: "Hiding whether an account exists isn't worth the trouble."

**Reality**: enumeration turns credential stuffing and targeted phishing into precision tools. Uniform responses and timing across login, registration, and reset close it cheaply.

### Myth 6: "Account lockout is the answer to brute force."

**Reality**: naive lockout creates a denial-of-service vector — an attacker locks every user out. Prefer graduated throttling, breach screening, and MFA, and reserve lockout for extreme cases with care.

## Self-Assessment

Use these questions to gauge whether your application handles this category well:

1. Are login, registration, and password-reset responses **indistinguishable** whether or not the account exists (body *and* timing)?
2. Do you **screen new and changed passwords against a breach corpus** and enforce length rather than composition rules?
3. Is **MFA available and enforced** for sensitive actions, with phishing-resistant options for privileged users?
4. Are login attempts **rate-limited and throttled** per account and per source, without a trivial lockout DoS?
5. Is the **session identifier high-entropy, rotated on login and privilege change**, and invalidated server-side on logout?
6. Are session cookies set **HttpOnly, Secure, and SameSite**, with sensible idle and absolute timeouts?
7. Do password-reset tokens have **high entropy, short expiry, single use**, and are reset links built from a trusted host value (not the request `Host` header)?
8. Does JWT verification **pin the algorithm and validate `exp`, `iss`, and `aud`**?
9. Do OAuth/OIDC clients use **exact-match redirect URIs, `state`, and PKCE**?
10. Are you moving toward **passkeys / WebAuthn** as a primary or step-up factor?

## What's Next?

- **[Attack Vectors](./attack-vectors.md)**: how attackers exploit weak authentication, session, token, and recovery flows.
- **[Prevention](./prevention.md)**: layered defenses with real code and configuration.
- **[Examples](./examples.md)**: vulnerable-vs-secure code in Node/Express, Python, and Java, plus JWT/session/MFA config.
- **[Lab](./lab/authentication-failures/)**: hands-on practice in a safe, isolated environment.

---

*Part of the [OWASP Top 10 Educational Repository](/platform/frontend/index.html)*
