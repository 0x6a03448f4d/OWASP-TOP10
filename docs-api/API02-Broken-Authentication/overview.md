# API02: Broken Authentication - Overview

## Table of Contents
- [What is Broken Authentication in APIs?](#what-is-broken-authentication-in-apis)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Broken Authentication in APIs?

**Broken Authentication** occurs when API authentication mechanisms are poorly implemented, allowing attackers to compromise authentication tokens, passwords, session IDs, or exploit implementation flaws to assume other users' identities temporarily or permanently.

Authentication is the process of verifying that users are who they claim to be. When this verification is weak or flawed, attackers can bypass it, leading to unauthorized access, account takeover, and data breaches.

### Core Concept

```
Proper Authentication Flow:
User → Credentials → Verification → Token → Access ✓

Broken Authentication:
Attacker → Weak Mechanism → Bypass → Stolen Token → Unauthorized Access ✗
```

### Why It's #2 for APIs

Unlike traditional web applications, APIs:
- Rely heavily on tokens rather than sessions
- Often lack multi-factor authentication (MFA)
- Use long-lived API keys that don't expire
- Have weak password policies
- Lack rate limiting on authentication endpoints
- Use predictable or weak token generation
- Don't properly validate token ownership

## Why Does This Matter?

### The Business Impact

- **Account Takeover**: Attackers gain full access to user accounts
- **Data Breaches**: Compromised credentials lead to data theft
- **Financial Fraud**: Unauthorized transactions and payments
- **Regulatory Violations**: GDPR, PCI-DSS, HIPAA non-compliance
- **Reputation Loss**: Customer trust destroyed permanently
- **Legal Liability**: Lawsuits and regulatory fines
- **Credential Stuffing**: Automated attacks using leaked credentials

### The Technical Impact

- **Session Hijacking**: Stealing valid authentication tokens
- **Brute Force Success**: No rate limiting allows password guessing
- **Token Theft**: JWT tokens stolen and reused
- **Weak Password Policies**: Users choose predictable passwords
- **No Token Expiration**: Tokens valid indefinitely
- **Algorithm Confusion**: JWT algorithm switching attacks
- **Credential Stuffing**: Reused passwords from breaches

## Technical Context

### How Broken Authentication Differs from Traditional Web Apps

| Traditional Web Apps | Modern APIs |
|---------------------|-------------|
| Session-based auth | Token-based (JWT, OAuth) |
| Browser cookies | HTTP headers |
| MFA often present | MFA rarely implemented |
| Session timeout | Long-lived tokens |
| Password reset flows | API key rotation |
| Rate limiting common | Often missing |

### Common Vulnerable Patterns

#### Pattern 1: Weak JWT Implementation

```
POST /api/login
{
  "username": "user@example.com",
  "password": "password123"
}

Response:
{
  "token": "eyJhbGc.iOiJIUzI1NiIs.tyJ1c2VyX2lk..."
}

VULNERABILITIES:
✗ Uses HS256 (symmetric) with weak secret
✗ No expiration time (exp claim)
✗ No refresh token mechanism
✗ Token not invalidated on logout
✗ Predictable secret key
```

#### Pattern 2: No Rate Limiting on Login

```
POST /api/login (attempt 1)
POST /api/login (attempt 2)
POST /api/login (attempt 3)
...
POST /api/login (attempt 10000)

VULNERABILITY:
✗ No rate limiting allows brute force attacks
✗ Attacker can try millions of passwords
✗ No account lockout mechanism
✗ No delay between failed attempts
```

#### Pattern 3: Weak Password Policies

```
Accepted passwords:
✗ "123456"
✗ "password"
✗ "admin"
✗ "user"
✗ 5 character passwords

VULNERABILITY:
No password complexity requirements
No minimum length enforcement
Common passwords accepted
No password breach checking
```

#### Pattern 4: Long-Lived API Keys

```
API Key: sk_live_a1b2c3d4e5f6g7h8i9j0
Created: 2020-01-01
Expires: Never

VULNERABILITIES:
✗ No expiration date
✗ No rotation policy
✗ If leaked, valid forever
✗ No scoping or permissions
✗ Hard-coded in client apps
```

### The Authentication Stack

```
┌─────────────────────────────────────┐
│   1. Credential Validation          │  ← Username/password correct?
├─────────────────────────────────────┤
│   2. Token Generation               │  ← Create secure JWT/session
├─────────────────────────────────────┤
│   3. Token Storage                  │  ← Store securely client-side
├─────────────────────────────────────┤
│   4. Token Transmission             │  ← Send in headers (not URL)
├─────────────────────────────────────┤
│   5. Token Validation               │  ← Verify signature & expiration
├─────────────────────────────────────┤
│   6. Token Revocation               │  ← Logout, password change
└─────────────────────────────────────┘

Broken authentication can occur at ANY layer
```

## Real-World Impact

### Case Study 1: T-Mobile (2021)

**Vulnerability**: Weak API authentication allowed SIM swapping  
**Impact**: Customer accounts compromised, phone numbers hijacked  
**Attack Method**: API credentials exposed, no MFA  
**Root Cause**: Insufficient authentication controls on sensitive operations

### Case Study 2: Experian (2021)

**Vulnerability**: Weak password reset API  
**Impact**: Credit reports accessible without proper authentication  
**Attack Method**: Predictable password reset tokens  
**Root Cause**: Weak token generation algorithm

### Case Study 3: Twitter (2020)

**Vulnerability**: OAuth token leak in API  
**Impact**: 5.4 million accounts exposed  
**Attack Method**: API returned authentication tokens in error messages  
**Root Cause**: Information leakage in API responses

### Case Study 4: Generic E-Commerce Platform

**Scenario**: No rate limiting on login endpoint  
**Impact**: 2,000 accounts compromised via credential stuffing  
**Attack Method**: Automated tool tried 10 million credential pairs  
**Root Cause**: Missing rate limiting and no account lockout

## Prevalence and Statistics

### OWASP API Security Top 10 2023 Data

- **#2** most critical API vulnerability
- Found in approximately **62%** of APIs tested
- **Most exploited** after BOLA in real-world attacks
- Average time to exploit: **Minutes** with automated tools
- Detection difficulty: **Easy** (automated scanners available)

### Attack Characteristics

| Metric | Value |
|--------|-------|
| **Exploitability** | Easy - automated tools widely available |
| **Prevalence** | Common - many APIs lack proper auth |
| **Detectability** | Easy - simple testing reveals issues |
| **Technical Impact** | Severe - complete account takeover |
| **Business Impact** | Critical - regulatory and reputation damage |

### Industry Vulnerabilities

Different API types face varying authentication risks:

| API Type | Risk Level | Common Issues |
|----------|------------|---------------|
| **Financial APIs** | Critical | Weak MFA, no biometrics |
| **Healthcare APIs** | Critical | Long-lived tokens, no rotation |
| **E-commerce APIs** | High | No rate limiting, weak passwords |
| **Social Media APIs** | High | OAuth misconfigurations |
| **IoT APIs** | Critical | Hardcoded credentials, no updates |
| **Internal APIs** | Medium-High | Assumption of trusted network |
| **Mobile APIs** | High | Tokens in app code, no refresh |

## Common Misunderstandings

### Myth 1: "Using JWT = Secure Authentication"

**Reality**: JWT is just a format; implementation determines security.

```python
# INSECURE JWT:
jwt.encode(payload, secret="secret123", algorithm="HS256")
# ✗ Weak secret
# ✗ Symmetric algorithm
# ✗ No expiration

# SECURE JWT:
jwt.encode(
    {
        **payload,
        'exp': datetime.utcnow() + timedelta(minutes=15),
        'iat': datetime.utcnow()
    },
    private_key,
    algorithm="RS256"
)
# ✓ Strong private key
# ✓ Asymmetric algorithm
# ✓ Short expiration
# ✓ Issued-at timestamp
```

### Myth 2: "HTTPS Protects Authentication"

**Reality**: HTTPS protects transmission, not storage or token strength.

```
HTTPS protects:
✓ Credentials in transit
✓ Token transmission
✓ Man-in-the-middle attacks

HTTPS does NOT protect:
✗ Weak passwords
✗ Stolen tokens
✗ Brute force attacks
✗ Token reuse
✗ Client-side token storage
✗ Long-lived tokens
```

### Myth 3: "API Keys Are Secure"

**Reality**: API keys are passwords; treat them accordingly.

```
API Key Risks:
✗ Often hard-coded in mobile apps
✗ Exposed in client-side JavaScript
✗ Committed to version control (GitHub)
✗ No expiration mechanism
✗ Shared across users/services
✗ No rotation policy
✗ Transmitted in URLs (logged everywhere)

Proper Usage:
✓ Server-side only
✓ Environment variables
✓ Regular rotation
✓ Expiration dates
✓ Scoped permissions
✓ Separate keys per service
✓ Transmitted in headers
```

### Myth 4: "Password Hashing = Secure"

**Reality**: Hashing algorithm and salt matter significantly.

```python
# WEAK:
md5(password)  # ✗ Crackable in seconds

# WEAK:
sha256(password)  # ✗ Too fast, no salt

# BETTER:
bcrypt(password, salt)  # ✓ Better but older

# BEST:
argon2id(password, salt)  # ✓ Modern, resistant to GPU attacks
```

### Myth 5: "Internal APIs Don't Need Strong Auth"

**Reality**: Internal breaches are common and devastating.

```
Threats to "internal" APIs:
✗ Insider threats
✗ Compromised employee accounts
✗ Lateral movement after initial breach
✗ Supply chain attacks
✗ Accidentally exposed endpoints
✗ Mobile app decompilation
✗ Network sniffing

Defense: Authenticate ALL APIs equally
```

### Myth 6: "Rate Limiting Solves Authentication Issues"

**Reality**: Rate limiting helps but doesn't replace strong authentication.

```
Rate Limiting helps with:
✓ Brute force attacks
✓ Credential stuffing
✓ DoS attacks

Rate Limiting does NOT fix:
✗ Weak passwords
✗ Token vulnerabilities
✗ Missing MFA
✗ Poor session management
✗ Credential leaks

Both are needed!
```

## Key Takeaways

1. ✅ **Use strong token generation** - RS256, proper secrets, expiration
2. ✅ **Implement rate limiting** - Prevent brute force and credential stuffing
3. ✅ **Enforce password policies** - Complexity, length, breach checking
4. ✅ **Use short-lived tokens** - 15-minute access tokens with refresh tokens
5. ✅ **Implement MFA where possible** - Especially for sensitive operations
6. ✅ **Rotate API keys regularly** - Automated rotation with expiration
7. ✅ **Use secure storage** - Never store tokens in localStorage without encryption
8. ✅ **Validate tokens properly** - Check signature, expiration, issuer
9. ✅ **Implement logout** - Token revocation and blacklisting
10. ✅ **Monitor authentication failures** - Detect attack patterns

## What's Next?

- **[Attack Vectors](./attack-vectors.md)**: Learn how attackers exploit authentication flaws
- **[Prevention](./prevention.md)**: Best practices and secure authentication patterns
- **[Examples](./examples.md)**: Code examples showing vulnerable vs secure implementations
- **[Lab](./lab/api02-weak-auth-lab/)**: Hands-on practice with authentication vulnerabilities

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
