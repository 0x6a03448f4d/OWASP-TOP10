# A7:2021 – Identification and Authentication Failures: Overview

## Table of Contents

- [What Are Identification and Authentication Failures?](#what-are-identification-and-authentication-failures)
- [Lineage: 2017 A2 → 2021 A7 → 2025](#lineage-2017-a2--2021-a7--2025)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Classification](#prevalence-and-classification)
- [Common Misunderstandings](#common-misunderstandings)
- [Self-Assessment](#self-assessment)

## What Are Identification and Authentication Failures?

**Identification and Authentication Failures** is the OWASP Top 10 2021 category (ranked **A7**) for weaknesses in how an application *confirms who a user is* and *maintains that identity over time*. When these mechanisms are missing, weak, or incorrectly implemented, an attacker can assume another user's identity—defeating every access-control decision that trusts it.

The category covers three closely related activities:

- **Identification** — establishing a claimed identity (the username, email, subject, or federated identity presented).
- **Authentication** — proving that claim with one or more factors (something you know, have, or are).
- **Session / identity management** — binding the proven identity to subsequent requests via a session token, cookie, or bearer token, and revoking it correctly.

A failure in any one of these three links breaks the whole chain. Perfectly hashed passwords do not help if the session identifier is predictable; flawless session handling does not help if the login endpoint allows unlimited credential-stuffing attempts.

### Core Concept

```
Secure identity chain:
  Identify   -> user presents a claim (username / email / federated subject)
  Authenticate -> claim proven with strong factors, rate-limited, MFA where it counts
  Session    -> new random ID issued, rotated on privilege change, bound to HttpOnly+Secure cookie
  Maintain   -> idle + absolute timeouts, server-side invalidation on logout
  Recover    -> account recovery that does not leak or bypass the above

Broken identity chain (A7):
  Identify   -> login and reset endpoints reveal which accounts exist (enumeration)
  Authenticate -> weak/breached passwords accepted, no MFA, unlimited guesses
  Session    -> predictable or long-lived tokens, no rotation after login, IDs in URLs
  Maintain   -> "logout" only clears the client; token still valid server-side
  Recover    -> reset flow is a second, weaker way to take over the account
```

### What the Category Specifically Includes

Per the OWASP 2021 definition, an application is likely vulnerable if it does any of the following:

- Permits **credential stuffing** (automated replay of breached username/password pairs).
- Permits **brute force** or **password spraying** against accounts without effective throttling or lockout.
- Permits **weak, default, or well-known breached passwords** (for example `Password1` or `admin/admin`).
- Uses **weak or ineffective credential-recovery** and forgot-password flows, such as knowledge-based "security questions."
- Stores passwords in **plaintext, encrypted, or weakly hashed** form (this overlaps with A2:2021 Cryptographic Failures).
- Has **missing or ineffective multi-factor authentication (MFA)**.
- Exposes the **session identifier in the URL**.
- **Reuses session identifiers** after successful login instead of generating a new one (session fixation).
- Does not **correctly invalidate** session IDs and tokens on logout or after a period of inactivity.

## Lineage: 2017 A2 → 2021 A7 → 2025

This category has been renamed and re-scoped across three editions of the OWASP Top 10. Understanding the lineage keeps this 2021 lesson complementary to the other two on this platform rather than duplicative.

| Edition | Name / Rank | Framing |
|---------|-------------|---------|
| **2017** | A2 — Broken Authentication | Focused on authentication and session management: weak passwords, brute force, exposed or fixed session IDs. |
| **2021** | A7 — Identification and Authentication Failures | *This lesson.* Broadened the scope to **identification**, added explicit emphasis on **identity federation** and modern automated attacks (credential stuffing). Dropped from #2 to #7—not because it got less serious, but because increased use of standardized identity libraries reduced its measured incidence. |
| **2025** | A7 — Authentication Failures | Renamed again, trimming "Identification" from the title while keeping the same underlying concerns and continuing to modernize around phishing-resistant MFA and token handling. |

> **What the 2021 revision added.** The 2017 title ("Broken Authentication") described the act of proving identity. The 2021 rename to "Identification and Authentication *Failures*" deliberately widened the lens to include **who you claim to be** (identification and account enumeration), **how identity is federated** across systems (SSO, OpenID Connect, SAML), and the full **session lifecycle**. Treat this 2021 lesson as the "broad scope" edition; the 2017 A2 lesson for the historical baseline; and the 2025 A7 lesson for the latest terminology.

## Why Does This Matter?

### Business Impact

- **Account takeover (ATO)**: The direct result—an attacker operates as a legitimate user, reading and changing data, moving money, or sending messages in their name.
- **Mass fraud from credential stuffing**: Because people reuse passwords, a breach at one site becomes free logins at yours. This drives fraud, chargebacks, and loyalty-point theft at scale.
- **Regulatory and contractual exposure**: Authentication weaknesses that lead to exposure of personal data trigger GDPR, CCPA, HIPAA, and PCI-DSS obligations and breach-notification duties.
- **Trust and brand damage**: "Users' accounts were hijacked" is one of the most reputationally damaging headlines a product can earn.
- **Support and remediation cost**: Every compromised account generates support tickets, forced password resets, and manual recovery work.

### Technical Impact

- **Full identity assumption**: A stolen or forged session token or password grants exactly the victim's privileges—including administrative ones.
- **Privilege escalation pivot**: Compromising one low-value account is often the foothold to reach higher-value internal systems.
- **Bypass of downstream controls**: Authorization, audit logging, and rate limits all trust the authenticated identity; break identity and they are all speaking about the attacker as if they were the victim.
- **Persistent access**: Tokens that are never invalidated server-side let an attacker retain access long after a password change.

## Technical Context

### The Three Failure Domains

#### 1. Credential Attacks (getting a valid password)

```
Credential stuffing -> replay known email:password pairs from other breaches
Brute force         -> many passwords against ONE account
Password spraying   -> ONE common password (e.g. "Winter2025!") against MANY accounts
Default credentials -> admin/admin, root/root left enabled
Weak policy         -> short or breached passwords accepted at registration
```

Spraying is specifically designed to evade per-account lockouts: by trying one password across thousands of accounts, the attacker stays under the failed-attempt threshold for any single account. This is why per-account lockout alone is insufficient—you also need per-IP and per-credential monitoring.

#### 2. Session Management Failures (stealing or forging the identity token)

| Failure | What goes wrong | Consequence |
|---------|-----------------|-------------|
| Predictable / weak IDs | Session ID is sequential or low-entropy | Attacker guesses valid sessions |
| Session fixation | ID is not regenerated after login | Attacker fixes a known ID, then rides the victim's authenticated session |
| ID exposed in URL | Token in query string | Leaks via logs, Referer headers, browser history, shared links |
| No server-side invalidation | Logout only deletes the client cookie | Captured token still works |
| Excessive lifetime | No idle or absolute timeout | A single theft grants indefinite access |
| Missing cookie flags | No HttpOnly / Secure / SameSite | Token stealable via XSS or sent over plaintext / cross-site |

#### 3. Identity, Recovery, and Token Validation

- **Account enumeration**: Different responses, timing, or error messages for "user exists" vs "user does not exist" let attackers build a list of valid accounts to target.
- **Insecure recovery**: "Forgot password" flows that rely on guessable security questions, email a permanent reset link, or leak whether an email is registered become a parallel, weaker authentication path.
- **Improper token validation**: With JWTs and other bearer tokens, failing to verify the signature, accepting the `alg: none` value, not checking `exp`/`iss`/`aud`, or trusting an unvalidated key lets an attacker mint their own valid-looking identity.

### Federated Identity (new emphasis in 2021)

Modern applications increasingly delegate authentication to an identity provider via **OpenID Connect**, **OAuth 2.0**, or **SAML**. The 2021 revision explicitly acknowledges this. Delegation does not remove the risk—it relocates it: the relying application must still validate the returned assertion or ID token correctly (signature, audience, expiry, nonce), protect the redirect flow against interception, and map the federated subject to a local account safely.

## Real-World Impact

The incidents below are described as **classes of well-documented, publicly reported events**, not as specific CVEs or exact figures—the durable lesson matters more than any single number.

### Case Class 1: Large-Scale Credential Stuffing Against Consumer Platforms

- **Pattern**: Attackers took username/password pairs leaked from unrelated breaches and replayed them at scale against streaming, retail, food-delivery, and gaming platforms.
- **Impact**: Waves of account takeovers, stolen stored value and loyalty points, and fraudulent orders—without exploiting any bug in the target's own code.
- **Root cause**: Password reuse by users, combined with the target accepting unlimited automated login attempts and offering no MFA.
- **Lesson**: Breached-password checks, bot/automation defenses, and MFA are the countermeasures—stronger password rules on your own site cannot fix reuse elsewhere.

### Case Class 2: Password Spraying in Enterprise Account Takeover

- **Pattern**: Threat actors sprayed a handful of seasonal or common passwords across large numbers of corporate email and VPN accounts, deliberately staying under per-account lockout thresholds.
- **Impact**: Footholds into corporate networks that were then used for data theft and lateral movement.
- **Root cause**: Weak passwords permitted, MFA not enforced on all remote-access paths, and no detection of the low-and-slow spray pattern.
- **Lesson**: Enforce phishing-resistant MFA everywhere that matters and monitor for distributed failed-login patterns, not just per-account counts.

### Case Class 3: Session Fixation and Predictable Tokens

- **Pattern**: Applications that did not regenerate the session identifier at login allowed an attacker to plant a known session ID in the victim's browser and then use that same ID once the victim authenticated.
- **Impact**: Direct session hijacking with no need to steal a password.
- **Root cause**: No session rotation on privilege change; in some cases, low-entropy or sequential identifiers.
- **Lesson**: Always issue a fresh, high-entropy session ID after authentication and after any privilege change.

### Case Class 4: JWT Signature and Algorithm Confusion

- **Pattern**: Services that accepted JWTs without properly verifying the signature—honoring the `alg: none` value, or accepting an `HS256` token signed with the public RSA key when expecting `RS256`—allowed attackers to forge tokens for arbitrary users.
- **Impact**: Complete authentication bypass and privilege escalation to administrator.
- **Root cause**: Token validation that trusted the token's own header to choose the verification algorithm.
- **Lesson**: Pin the expected algorithm server-side, verify the signature against a trusted key, and validate all standard claims.

## Prevalence and Classification

In the OWASP Top 10 2021, this category ranks **A7**—down from #2 in 2017. OWASP attributes the drop primarily to the **increased availability and adoption of standardized authentication frameworks**, which removed many hand-rolled mistakes. It remains a serious category because the impact of a single failure is so high: assuming another user's identity.

Rather than cite precise percentages (which differ by report and year), the defensible picture is:

- It is **still one of the most impactful** categories—successful exploitation typically means full account takeover.
- The most commonly observed sub-issues are **missing MFA, acceptance of weak or breached passwords, insufficient anti-automation on login, and mishandled session/token lifecycles**.
- Automated attacks (credential stuffing and spraying) make it **continuously exploited at internet scale**, not just in targeted assessments.

### Representative CWE Mappings

- **CWE-287**: Improper Authentication
- **CWE-384**: Session Fixation
- **CWE-613**: Insufficient Session Expiration
- **CWE-620**: Unverified Password Change
- **CWE-640**: Weak Password Recovery Mechanism
- **CWE-307**: Improper Restriction of Excessive Authentication Attempts
- **CWE-521**: Weak Password Requirements
- **CWE-798**: Use of Hard-coded Credentials

> Note: exact incidence figures vary between sources and editions. Treat any single number as illustrative; the durable takeaway is that authentication failures are high-impact and constantly exploited by automation.

## Common Misunderstandings

### Myth 1: "We hash passwords with bcrypt, so authentication is handled."

**Reality**: Password storage is one link. Predictable sessions, missing MFA, no rate limiting, and enumerable accounts each independently lead to takeover regardless of how well passwords are hashed.

### Myth 2: "Complex passwords (uppercase, symbol, number) are what NIST wants."

**Reality**: NIST SP 800-63B moved *away* from mandatory composition rules and periodic forced rotation. It favors **length** (long passphrases), **screening against breached-password lists**, and **not forcing arbitrary resets**. Composition rules push users toward predictable patterns like `Password1!`.

### Myth 3: "Account lockout stops brute force, so we are safe."

**Reality**: Per-account lockout does nothing against *password spraying* (one password, many accounts) and can itself be abused for denial of service. You need per-IP/per-credential throttling, breached-password checks, and MFA in addition.

### Myth 4: "Logout works—the cookie is deleted."

**Reality**: If the token is not invalidated *server-side*, a copy captured earlier still authenticates. Real logout must revoke the session in the store, and token designs need a revocation strategy.

### Myth 5: "JWTs are stateless and self-validating, so they are secure by design."

**Reality**: A JWT is only as trustworthy as its verification. Accepting `alg: none`, skipping signature checks, or not validating `exp`/`iss`/`aud` turns "stateless" into "forgeable."

### Myth 6: "We use SSO/OAuth, so authentication is the provider's problem."

**Reality**: The relying party must still validate the returned ID token/assertion correctly and protect the redirect flow. Federation relocates risk; it does not remove it.

### Myth 7: "A generic 'invalid credentials' message is enough to stop enumeration."

**Reality**: Enumeration also leaks through **response timing**, differing behavior on registration and password-reset endpoints, and rate-limit responses. Consistency must span every identity-related endpoint.

## Self-Assessment

Ask these questions about your application:

- [ ] Are login, registration, and password-reset endpoints all rate-limited and protected against automation?
- [ ] Do you screen new and changed passwords against a known-breached-password list?
- [ ] Do you follow length-over-complexity policy (NIST 800-63B) rather than forced composition and rotation?
- [ ] Is MFA available and enforced for sensitive accounts—ideally phishing-resistant (FIDO2/WebAuthn)?
- [ ] Is a new, high-entropy session ID generated at login and after every privilege change?
- [ ] Are session cookies set `HttpOnly`, `Secure`, and `SameSite`, and never placed in URLs?
- [ ] Are sessions and tokens invalidated server-side on logout, and do they have idle and absolute timeouts?
- [ ] Do login, reset, and registration responses avoid revealing whether an account exists (in body, status, and timing)?
- [ ] Is the account-recovery flow at least as strong as primary login (no guessable security questions)?
- [ ] For JWTs/bearer tokens, do you pin the algorithm, verify the signature against a trusted key, and validate all standard claims?

If you answered "no" or "not sure" to several of these, you likely have an exploitable authentication weakness today.

## Key Takeaways

1. **Identity is a chain** of identification, authentication, and session management—the weakest link defines your security.
2. **Automation is the default attacker**: credential stuffing and spraying run at internet scale, so anti-automation and MFA are not optional.
3. **Length beats complexity**, and breached-password screening beats forced rotation (NIST 800-63B).
4. **Sessions must rotate and expire**, live in hardened cookies, and be revocable server-side.
5. **The 2021 revision widened the scope** to identification, federation, and the full session lifecycle—keep this complementary to the 2017 A2 and 2025 A7 lessons.

## Next Steps

- **[Attack Vectors](./attack-vectors.md)**: How attackers discover and exploit authentication weaknesses
- **[Prevention](./prevention.md)**: Layered defenses—MFA, breached-password checks, secure sessions
- **[Examples](./examples.md)**: Vulnerable vs. secure code across Node, Python, and Java
- **[Lab](./lab/weak-session-lab/)**: Hands-on practice with weak session management

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
