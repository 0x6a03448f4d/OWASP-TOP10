# M03: Insecure Authentication/Authorization - Overview

## Table of Contents
- [What is Insecure Authentication/Authorization?](#what-is-insecure-authentication-authorization)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Insecure Authentication/Authorization?

**Insecure Authentication/Authorization** occurs when mobile applications fail to properly verify user identity (authentication) or enforce access controls (authorization). This includes weak session management, insecure authentication mechanisms, and inadequate authorization checks.

Mobile apps face unique authentication challenges:
- Operating on potentially untrusted devices
- Need for offline functionality
- Biometric authentication integration
- Multiple authentication factors
- Token-based authentication with APIs
- Session persistence across app restarts

### Core Concept

Authentication and authorization are two distinct but related security controls:

```
Authentication (Who are you?)
    ↓
User provides credentials → System verifies identity → Session created
    ↓
Authorization (What can you do?)
    ↓
User requests resource → System checks permissions → Access granted/denied
```

### Key Vulnerability Points

1. **Weak Password Policies**: No complexity requirements, short passwords allowed
2. **Insecure Session Management**: Predictable tokens, no expiration, token reuse
3. **Missing Multi-Factor Authentication**: Single factor authentication only
4. **Client-Side Authorization**: Access control enforced only in mobile app
5. **Biometric Implementation Flaws**: Bypassing biometric checks
6. **Token Storage Issues**: Storing tokens insecurely on device
7. **Insufficient Re-authentication**: No re-auth for sensitive operations

## Why Does This Matter?

### The Business Impact

- **Account Takeover**: Unauthorized access to user accounts
- **Data Breaches**: Access to sensitive user data
- **Financial Fraud**: Unauthorized transactions
- **Compliance Violations**: GDPR, PCI-DSS, HIPAA violations
- **Reputation Damage**: Loss of user trust
- **Legal Liability**: Lawsuits from affected users

### For Users

- Personal data exposure
- Financial losses from fraudulent transactions
- Identity theft
- Privacy violations
- Loss of access to own accounts
- Emotional distress from breach

## Technical Context

### Authentication Mechanisms

**Common Mobile Authentication Methods:**

1. **Username/Password**
   - Traditional but often implemented weakly
   - Vulnerable to brute force if no rate limiting
   - Password storage must be secure

2. **Biometric Authentication**
   - Fingerprint, Face ID, iris scanning
   - Must be implemented correctly on both client and server
   - Fallback mechanisms need equal security

3. **Token-Based (OAuth 2.0, JWT)**
   - Access tokens and refresh tokens
   - Token lifecycle management critical
   - Secure storage essential

4. **Multi-Factor Authentication (MFA)**
   - Something you know + something you have
   - SMS, authenticator apps, hardware tokens
   - Bypass prevention crucial

5. **Certificate-Based**
   - Client certificates for authentication
   - Strong but complex to implement
   - Certificate management overhead

### Authorization Mechanisms

**Access Control Models:**

1. **Role-Based Access Control (RBAC)**
   ```
   User → Role → Permissions → Resources
   ```

2. **Attribute-Based Access Control (ABAC)**
   ```
   User Attributes + Resource Attributes + Context → Decision
   ```

3. **Mandatory Access Control (MAC)**
   - System-enforced access rules
   - Cannot be changed by users

### Common Vulnerabilities

**Authentication Failures:**
```
No Rate Limiting → Brute Force Attacks → Account Compromise
Weak Passwords → Dictionary Attacks → Account Takeover
Predictable Tokens → Token Prediction → Session Hijacking
No MFA → Single Point of Failure → Easy Account Access
```

**Authorization Failures:**
```
Client-Side Only → Bypass via Proxy → Unauthorized Access
IDOR (Insecure Direct Object References) → Parameter Manipulation → Data Breach
Missing Function-Level Checks → API Abuse → Privilege Escalation
```

## Real-World Impact

### Notable Incidents

**Mobile Banking App Authentication Bypass (2022)**
- Biometric authentication could be bypassed
- Root/jailbreak detection was client-side only
- Impact: $2M in fraudulent transactions
- Result: Emergency patch, regulatory investigation

**Social Media App Session Hijacking (2021)**
- Session tokens never expired
- Tokens stored in plain text in app preferences
- Impact: 2.5M accounts compromised
- Result: Forced password reset for all users

**E-Commerce App Authorization Flaw (2023)**
- IDOR vulnerability in order API
- User could access any order by changing ID parameter
- Server didn't verify ownership
- Impact: Exposure of PII for 500K customers
- Result: $4.5M GDPR fine, class action lawsuit

### Attack Statistics

- **67%** of mobile apps have at least one authentication vulnerability
- **Account takeovers increased 307%** in 2023 for mobile banking apps
- Average cost of mobile authentication breach: **$3.86M**
- **81%** of hacking-related breaches leveraged weak/stolen credentials
- **45%** of mobile apps don't implement proper session timeout

## Prevalence and Statistics

### Current State (2024)

- **72%** of mobile apps don't enforce MFA
- **58%** have weak password policies (< 8 characters, no complexity)
- **43%** implement authorization checks only on client-side
- **65%** of mobile banking apps have session management issues
- **31%** don't properly invalidate tokens on logout

### Industry Breakdown

**Finance/Banking:**
- 89% implement some form of MFA (highest)
- Still 34% have session management issues
- Biometric authentication common but not always secure

**Healthcare:**
- 56% implement MFA
- HIPAA compliance driving improvements
- Legacy systems create authentication gaps

**E-Commerce:**
- 41% implement MFA
- High rate of IDOR vulnerabilities (52%)
- Session management often weak

**Social Media:**
- 67% implement MFA (often optional)
- Account takeover prevention improving
- Third-party authentication introduces risks

## Common Misunderstandings

### Myth vs Reality

**Myth**: "Biometric authentication is unbreakable"
**Reality**: Biometric auth can be bypassed if not properly implemented. It must be combined with secure backend verification.

**Myth**: "Client-side security checks are sufficient"
**Reality**: All security decisions must be made and enforced server-side. Client can be manipulated.

**Myth**: "Long session tokens mean better security"
**Reality**: Longer tokens don't inherently mean more secure. Randomness and unpredictability matter more than length.

**Myth**: "OAuth makes my app automatically secure"
**Reality**: OAuth is a framework, not a silver bullet. Implementation details matter greatly.

**Myth**: "Once authenticated, user is trusted for entire session"
**Reality**: Sensitive operations require re-authentication (step-up authentication).

### What This Isn't

- ❌ Just about having login functionality
- ❌ Only about preventing password guessing
- ❌ Solved by using HTTPS
- ❌ Only a frontend concern

### What This Is

- ✅ Verifying user identity properly at all entry points
- ✅ Enforcing access controls consistently
- ✅ Managing sessions securely throughout lifecycle
- ✅ Implementing defense-in-depth for authentication
- ✅ Protecting against various attack vectors

## Key Vulnerability Categories

### 1. Weak Authentication

**Examples:**
- No password complexity requirements
- No account lockout after failed attempts
- Credentials sent over insecure channels
- Weak biometric implementation
- No MFA support

**Impact:** Account takeover, unauthorized access

### 2. Session Management Flaws

**Examples:**
- Predictable session tokens
- Tokens never expire
- No session invalidation on logout
- Session fixation vulnerabilities
- Concurrent session issues

**Impact:** Session hijacking, unauthorized persistent access

### 3. Authorization Bypass

**Examples:**
- Client-side only authorization
- Insecure Direct Object References (IDOR)
- Missing function-level access control
- Horizontal/vertical privilege escalation
- Path traversal in API endpoints

**Impact:** Unauthorized data access, privilege escalation

### 4. Token Management Issues

**Examples:**
- Tokens stored insecurely
- Refresh tokens never expire
- JWT without signature verification
- Token leakage in logs/analytics
- No token revocation mechanism

**Impact:** Token theft, long-term unauthorized access

## Key Takeaways

1. **Authentication and authorization must be enforced server-side**
2. **Implement defense-in-depth: MFA, rate limiting, secure sessions**
3. **Biometric authentication requires proper implementation**
4. **Sessions must have appropriate timeouts and proper invalidation**
5. **Every API endpoint must verify both authentication and authorization**
6. **Sensitive operations require re-authentication (step-up auth)**

## Next Steps

After understanding the overview, proceed to:
1. **[Attack Vectors](./attack-vectors.md)** - Learn how authentication attacks work
2. **[Prevention](./prevention.md)** - Implement secure authentication/authorization
3. **[Examples](./examples.md)** - See vulnerable vs secure implementations
4. **[Interactive Lab](./lab/)** - Practice exploiting and fixing auth issues

---

**Remember**: Authentication proves who you are, authorization proves what you can do. Both must be properly secured.
