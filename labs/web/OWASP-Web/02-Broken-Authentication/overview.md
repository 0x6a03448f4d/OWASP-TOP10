# A2:2017 - Broken Authentication - Overview

## Table of Contents

- [What is Broken Authentication?](#what-is-broken-authentication)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)
- [Self-Assessment](#self-assessment)
- [Next Steps](#next-steps)

## What is Broken Authentication?

**Broken Authentication** was ranked **A2** in the OWASP Top 10 2017. It covers the whole family of weaknesses in how an application *confirms who a user is* (authentication) and *keeps them signed in* (session management). When these functions are implemented incorrectly, attackers can compromise passwords, keys, or session tokens—or exploit other flaws—to assume other users' identities, temporarily or permanently.

The category is deliberately broad because authentication is not one control but a chain of them: the login form, the password store, the "remember me" feature, the password-reset email, the multi-factor step, the session cookie, and the logout button are all part of the same trust boundary. A single weak link—a login endpoint with no rate limiting, a session ID that never rotates, a reset token that never expires—can undo every other control.

> **2017 -> 2021 lineage:** In the OWASP Top 10 2021, this category was renamed and broadened to **A07:2021 - Identification and Authentication Failures**, and it moved down from #2 to #7 (a sign that frameworks and managed identity providers have made secure defaults more common, not that the risk disappeared). This lesson focuses on the **2017 A2 framing**, but the weaknesses and fixes carry directly over.

### Core Concept

```
Secure authentication and session management:
  Passwords     -> hashed with bcrypt / Argon2 / scrypt, never plaintext
  Weak/breached -> rejected at registration and password change
  Login         -> rate limited, lockout / backoff, generic error messages
  MFA           -> available and enforced for sensitive accounts
  Session ID    -> long, random, server-generated, in a cookie (never the URL)
  Cookie flags  -> Secure; HttpOnly; SameSite set
  On login      -> a NEW session ID is issued (prevents fixation)
  Timeout       -> idle + absolute limits, server-side invalidation on logout

Broken authentication:
  Passwords     -> plaintext, or unsalted MD5 / SHA-1
  Weak/breached -> "password", "123456", known-breached values accepted
  Login         -> unlimited attempts, "user not found" vs "wrong password"
  MFA           -> absent, or trivially bypassed via a fallback flow
  Session ID    -> short/predictable, or passed in the URL query string
  Cookie flags  -> missing Secure / HttpOnly, readable by script or sniffable
  On login      -> the pre-login session ID is kept (session fixation)
  Timeout       -> sessions never expire, logout does not invalidate server-side
```

### Where Authentication Breaks Down

An application is likely vulnerable if it:

- **Permits credential stuffing**: automated replay of valid username/password pairs from other breaches, because there is no bot or rate-limit defense.
- **Permits brute force**: unlimited or lightly-limited guessing of a single account's password.
- **Permits weak or well-known passwords**: values such as `Password1` or `admin`, or ships with default credentials.
- **Uses weak credential recovery**: knowledge-based answers, or reset tokens that are guessable, reusable, or non-expiring.
- **Stores passwords poorly**: plaintext, or fast/unsalted hashes that crack quickly once the database leaks.
- **Lacks or has ineffective MFA**: no second factor, or one that can be skipped.
- **Exposes session IDs in the URL**: tokens that end up in browser history, server logs, and `Referer` headers.
- **Reuses session IDs after login**: enabling session fixation.
- **Fails to invalidate sessions**: sessions that do not time out, or survive logout and password change.

## Why Does This Matter?

Authentication is the gatekeeper to everything else. Access control, encryption, and audit logging all assume the system knows *who* is acting. When authentication breaks, those downstream controls protect the wrong person—often silently, because the attacker arrives holding a valid-looking identity.

### Business Impact

- **Account Takeover (ATO) at scale**: Credential stuffing compromises thousands of accounts in one campaign, driving fraud, chargebacks, and loyalty-point theft.
- **Data breaches and privacy exposure**: A hijacked session or cracked password store exposes personal and financial data, triggering GDPR / CCPA / HIPAA / PCI-DSS obligations, fines, and mandatory breach notification.
- **Direct financial loss**: Fraudulent transfers, purchases, and gift-card draining follow directly from ATO.
- **Reputation and trust**: "My account got hacked" is the most visible, personal kind of security failure a user can experience.
- **Support and remediation cost**: Forced password resets and fraud investigations spike after a stuffing wave.

### Technical Impact

- **Identity assumption**: The attacker acts *as* the victim; every action is correctly authorized and attributed to the wrong person.
- **Privilege escalation**: Compromising an administrator or service account converts one takeover into full system compromise.
- **Persistent access**: Stolen "remember me" tokens or non-expiring sessions give durable access even after a password change, unless sessions are invalidated.
- **Lateral movement**: Reused passwords let a foothold in one system open others.
- **Audit blindness**: Authenticated malicious actions blend into normal traffic.

## Technical Context

### Authentication vs Session Management vs Authorization

Broken Authentication spans the first two. Keeping them distinct is essential to reasoning about the fixes.

| Concept | Question it answers | Typical mechanism | Failure mode in A2 |
|---------|--------------------|--------------------|--------------------|
| **Authentication** | Who are you? | Password + MFA, verified against a stored hash | Weak passwords, no MFA, poor hashing, guessable reset |
| **Session management** | Are you still the same person? | Session ID in a cookie, or a signed token | Fixation, exposure in URL, no timeout, no invalidation |
| **Authorization** | Are you allowed to do this? | Roles / permissions checked per request | (Covered by A5:2017 Broken Access Control, not A2) |

### The Session Lifecycle

```
1. Anonymous visit   -> server may issue a pre-auth session ID (cart, CSRF token)
2. User logs in      -> ISSUE A NEW SESSION ID here (do not reuse the pre-auth one)
3. Authenticated use -> session ID travels in a Secure; HttpOnly cookie each request
4. Idle              -> session expires after N minutes of inactivity (idle timeout)
5. Long-lived        -> session expires after an absolute max age regardless of activity
6. Sensitive action  -> optionally re-authenticate (step-up) before it proceeds
7. Logout / password change -> DESTROY the session server-side, not just client-side
```

### Why Password Storage Belongs Here

Every password database eventually risks exposure, and the only thing standing between a stolen dump and mass account takeover is the strength of the hashing. Fast, unsalted hashes (MD5, SHA-1, plain SHA-256) can be reversed at billions of guesses per second with commodity GPUs; slow, salted, memory-hard functions (bcrypt, scrypt, Argon2) make offline cracking economically impractical.

```
Password store leaks. What happens next depends entirely on the hash:

  plaintext            -> every account owned instantly
  unsalted MD5 / SHA-1 -> cracked with rainbow tables / GPUs in minutes
  fast salted SHA-256  -> no rainbow tables, but still billions of guesses/sec
  bcrypt / Argon2      -> each guess is deliberately slow; cracking is impractical
```

## Real-World Impact

The incidents below are described as **verifiable classes of event** well documented in the security community. Exact figures vary by source and are given qualitatively—treat them as illustrative of the mechanism, not as precise statistics.

### Case Class 1: Aggregated Credential Dumps Fueling Credential Stuffing

**What happened**: Over the 2010s, breaches at many large services produced enormous collections of leaked email/password pairs, aggregated and traded (the widely-reported "Collection #1" compilation is one public example).

**Mechanism**: Attackers replay these pairs against unrelated sites, betting on password reuse. A small success rate across millions of attempts still yields many compromised accounts.

**Lesson**: Password reuse turns *someone else's* breach into *your* account-takeover problem. Defenses must assume the attacker already knows real passwords.

### Case Class 2: Streaming, Retail, and Gaming Account Takeover Waves

**What happened**: Consumer platforms with valuable accounts (media libraries, stored payment methods, loyalty balances) have repeatedly experienced publicized credential-stuffing waves, prompting forced password resets.

**Mechanism**: High-value accounts + widespread password reuse + weak automated-attack defenses. The application flaw is the same each time: treating a correct-looking password as sufficient, with no throttling or anomaly detection.

**Lesson**: Rate limiting, device/behavior signals, and MFA separate "one leaked password" from "account compromised."

### Case Class 3: MFA-Fatigue and Fallback-Flow Bypasses

**What happened**: Several widely-reported intrusions succeeded despite MFA, by abusing weak implementations—push-notification "fatigue," SMS interception, or a weaker fallback/recovery flow that skipped the second factor.

**Mechanism**: MFA that can be socially or technically bypassed is only as strong as its weakest path.

**Lesson**: Prefer phishing-resistant MFA (WebAuthn/FIDO2), number-matching push, and make every recovery/fallback path at least as strong as the primary one.

### Case Class 4: Session Tokens Exposed in URLs and Logs

**What happened**: Applications that placed session identifiers in URL query strings (`?sessionid=...`) leaked those tokens into browser history, proxy and server access logs, analytics pipelines, and the `Referer` header sent to third-party sites.

**Mechanism**: A session ID is a bearer credential—whoever holds it is the user. Once it appears in a log or referrer, anyone with access can replay it.

**Lesson**: Session IDs belong in cookies with `Secure; HttpOnly; SameSite`, never in the URL.

## Prevalence and Statistics

### OWASP Top 10 2017 Positioning

- **Rank #2 (A2:2017)** - second only to Injection.
- **Broad reach** - almost every application authenticates users, so the attack surface is nearly universal.
- **2021 successor** - became **A07:2021 Identification and Authentication Failures**, dropping to #7 as secure-by-default frameworks and identity providers matured.

### Representative CWE Mappings

| CWE | Weakness |
|-----|----------|
| **CWE-287** | Improper Authentication |
| **CWE-384** | Session Fixation |
| **CWE-613** | Insufficient Session Expiration |
| **CWE-620** | Unverified Password Change |
| **CWE-640** | Weak Password Recovery Mechanism |
| **CWE-521** | Weak Password Requirements |
| **CWE-307** | Improper Restriction of Excessive Authentication Attempts |
| **CWE-798** | Use of Hard-coded Credentials |
| **CWE-256** | Plaintext Storage of a Password |
| **CWE-916** | Use of Password Hash With Insufficient Computational Effort |
| **CWE-598** | Use of GET Request Method With Sensitive Query Strings (session IDs in URL) |

## Common Misunderstandings

### Myth 1: "HTTPS means my authentication is secure."
**Reality**: TLS protects credentials *in transit*. It does nothing about weak passwords, missing rate limiting, session fixation, poor hashing, or a guessable reset token.

### Myth 2: "We hash passwords, so a database leak is fine."
**Reality**: The *algorithm* decides your fate. Unsalted MD5/SHA-1 is cracked almost as fast as plaintext. Only slow, salted, memory-hard hashes (bcrypt, scrypt, Argon2) make a leaked store expensive to crack.

### Myth 3: "Account lockout after 5 failures stops attackers."
**Reality**: Lockout stops *vertical* brute force against one account, but not *credential stuffing* or *password spraying*, which try one password across many accounts. Naive lockout also enables denial-of-service. Rate limiting, backoff, and bot defenses matter more.

### Myth 4: "Logout just needs to delete the cookie."
**Reality**: If the server keeps the session valid, an attacker who already copied the session ID is still logged in. Logout must invalidate the session *server-side*, and password changes should invalidate all other sessions.

### Myth 5: "Any second factor makes us safe."
**Reality**: SMS can be intercepted or SIM-swapped, push prompts can be spammed until approved, and a weak recovery flow can skip MFA entirely. MFA is only as strong as its weakest path.

### Myth 6: "Complex password rules and forced 90-day rotation are best practice."
**Reality**: NIST SP 800-63B favors *length* and *screening against breached passwords* over arbitrary composition rules and forced rotation, which push users toward predictable patterns (`Password1!` -> `Password2!`).

## Self-Assessment

A "no" to any of these is a finding worth investigating:

- Are passwords stored with a slow, salted hash (bcrypt / scrypt / Argon2) and never in plaintext or fast hashes?
- Are new and changed passwords screened against a known-breached list, and is a reasonable minimum length enforced?
- Is the login endpoint rate-limited and defended against automated (credential-stuffing) traffic?
- Do login and recovery errors avoid revealing whether a username exists?
- Is a fresh session ID issued at login, and is the old one discarded (no fixation)?
- Are session cookies marked `Secure`, `HttpOnly`, and `SameSite`, and is the session ID never placed in a URL?
- Do sessions have both idle and absolute timeouts, invalidated server-side on logout and password change?
- Is MFA available, encouraged or enforced for sensitive accounts, and are recovery flows at least as strong as the primary login?
- Are password-reset tokens random, single-use, short-lived, and delivered out-of-band?
- Are default and sample credentials removed before production?

## Next Steps

- **[Attack Vectors](./attack-vectors.md)**: How attackers exploit each authentication and session weakness.
- **[Prevention](./prevention.md)**: Layered defenses with real code and configuration.
- **[Examples](./examples.md)**: Vulnerable-vs-secure code pairs in PHP, Python, Node.js, and Java.
- **[Launch the Lab](./lab/broken-authentication/)**: A safe, intentionally vulnerable app (port 5020) for hands-on practice.

> Ready to practice? Start the Broken Authentication lab from `./lab/broken-authentication/` with `docker-compose up --build` and work through identifying, exploiting, and fixing the flaws described here.
