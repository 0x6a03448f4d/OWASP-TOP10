# Broken Authentication - Overview

## What is Broken Authentication?

**Broken Authentication** occurs when application functions related to authentication and session management are implemented incorrectly, allowing attackers to compromise passwords, keys, session tokens, or exploit other implementation flaws to assume other users' identities.

### Core Vulnerabilities

Authentication breaks down in several ways:

- **Weak Password Requirements**: Allowing simple, guessable passwords
- **Credential Stuffing**: No protection against automated attacks using breached credentials
- **Session Fixation**: Reusing session IDs before and after login
- **Exposed Session IDs**: Session tokens in URLs or insecure storage
- **Missing Session Timeout**: Sessions that never expire
- **Weak Session ID Generation**: Predictable or easily guessable tokens

## Why Does This Matter?

Authentication is the gatekeeper to your application. When it fails:

- Attackers gain unauthorized access to user accounts
- Personal and financial data gets exposed
- Identity theft becomes possible
- Business operations can be disrupted

### Business Impact

- **Data Breaches**: Millions of user accounts compromised
- **Financial Loss**: Fraudulent transactions, theft
- **Regulatory Fines**: GDPR, PCI-DSS violations
- **Reputation Damage**: Loss of customer trust

## Technical Context

### Classic 2017 Vulnerabilities

In 2017, these were the most common authentication issues:

1. **Weak Password Policies**
   - No complexity requirements
   - Allowing common passwords like "password123"
   - No password rotation

2. **Session Management Flaws**
   - Session IDs in URLs: `https://example.com?sessionid=abc123`
   - Sessions not invalidated after logout
   - Concurrent sessions allowed without warning

3. **Missing Brute Force Protection**
   - Unlimited login attempts
   - No account lockout mechanisms
   - No CAPTCHA or rate limiting

4. **Insecure Credential Storage**
   - Passwords stored in plain text
   - Weak hashing algorithms (MD5, SHA1)
   - No salt in password hashes

### Real-World Examples (2017 Era)

**Yahoo (2013-2014, disclosed 2016-2017)**
- 3 billion accounts compromised
- Weak security questions
- Inadequate password hashing

**Equifax (2017)**
- 147 million records exposed
- Weak authentication on administrative portals
- Unpatched vulnerabilities

## Key Takeaways

- Authentication must be strong at every layer
- Session management requires careful implementation
- Passwords must be properly hashed and salted
- Multi-factor authentication adds critical security
- Monitor for suspicious authentication attempts
