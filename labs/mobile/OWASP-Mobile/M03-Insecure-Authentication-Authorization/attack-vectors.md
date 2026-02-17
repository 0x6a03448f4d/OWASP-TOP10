# M03: Insecure Authentication/Authorization - Attack Vectors

## Table of Contents
- [Understanding Authentication/Authorization Attacks](#understanding-authenticationauthorization-attacks)
- [Attack Vector Categories](#attack-vector-categories)
- [Attack Scenarios](#attack-scenarios)
- [Attack Chain Analysis](#attack-chain-analysis)
- [Exploitation Techniques](#exploitation-techniques)
- [Detection Indicators](#detection-indicators)

## Understanding Authentication/Authorization Attacks

Authentication and authorization attacks exploit weaknesses in identity verification and access control mechanisms. These attacks can range from simple credential guessing to sophisticated token manipulation and privilege escalation.

### The Attack Surface

```
Authentication Layer:
User Credentials → Authentication Mechanism → Session/Token Creation
      ↓                      ↓                        ↓
  Weak Passwords      Bypass/Brute Force      Predictable Tokens
      ↓                      ↓                        ↓
Authorization Layer:
Session/Token → Access Control Check → Resource Access
      ↓                  ↓                    ↓
Token Theft      Missing Checks        IDOR/Privilege Escalation
```

## Attack Vector Categories

### 1. Credential-Based Attacks

**Brute Force Attacks**
- Systematic trying of password combinations
- Dictionary attacks using common passwords
- Credential stuffing with leaked password databases
- No rate limiting allows unlimited attempts

**Weak Password Exploitation**
- Default credentials (admin/admin, user/password)
- Passwords based on personal information
- Short passwords without complexity
- Common patterns (Password123, Summer2024)

**Credential Harvesting**
- Phishing attacks targeting mobile users
- Keyloggers on compromised devices
- Man-in-the-middle attacks on insecure connections
- Social engineering to obtain credentials

### 2. Session Management Attacks

**Session Hijacking**
- Intercepting session tokens over insecure channels
- XSS attacks stealing session cookies/tokens
- Session token prediction if weakly generated
- Replay attacks using captured tokens

**Session Fixation**
- Attacker sets known session ID for victim
- Victim authenticates with attacker's session ID
- Attacker uses same session ID to access account
- Lack of session regeneration on login

**Session Timeout Exploitation**
- Sessions that never expire
- Shared device attacks using active sessions
- Session persistence across app reinstalls
- Background session hijacking

### 3. Token Manipulation Attacks

**JWT Vulnerabilities**
- Algorithm confusion attacks (RS256 → HS256)
- None algorithm acceptance
- Weak signing keys
- Token signature not verified
- Expired token acceptance

**Token Storage Exploitation**
- Tokens in shared preferences (unencrypted)
- Tokens in application logs
- Tokens in URL parameters
- Backup extraction exposing tokens

**Refresh Token Attacks**
- Refresh tokens with no expiration
- Refresh tokens not bound to devices
- No refresh token rotation
- Stolen refresh tokens enabling persistent access

### 4. Biometric Authentication Bypass

**Implementation Flaws**
- Client-side only biometric verification
- Biometric success bypassed via hooking
- Fallback mechanisms weaker than biometric
- Race conditions in biometric flow

**Physical Attacks**
- Fingerprint spoofing with lifted prints
- Face recognition bypass with photos/videos
- Presentation attack detection failures
- Unconscious victim biometric use

**Root/Jailbreak Exploitation**
- Hooking biometric APIs
- Modifying biometric verification results
- Bypassing device security altogether
- Custom biometric implementations vulnerable

### 5. Authorization Bypass Attacks

**Insecure Direct Object References (IDOR)**
- Changing ID parameters to access others' data
- Predictable resource identifiers
- No ownership verification on server
- Sequential ID enumeration

**Horizontal Privilege Escalation**
- Accessing resources of users at same privilege level
- User A accessing User B's data
- Parameter manipulation (userId=123 → userId=124)
- No user context validation

**Vertical Privilege Escalation**
- Regular user accessing admin functions
- Missing role checks on sensitive endpoints
- Client-side role enforcement only
- Default to privileged access

**Function-Level Access Control Issues**
- No authorization checks on API endpoints
- Hidden/undocumented admin endpoints accessible
- Mobile app bypassed to call APIs directly
- Authorization checks only in UI layer

### 6. Multi-Factor Authentication Bypass

**MFA Implementation Flaws**
- MFA bypass via account recovery
- Race conditions in MFA validation
- Reusable MFA codes
- MFA only required for initial login

**Social Engineering**
- SIM swapping to intercept SMS codes
- Phishing for authenticator codes
- Push notification fatigue attacks
- Recovery code exploitation

**Technical Bypass**
- Session token valid before MFA completion
- MFA step skippable by direct API call
- Backup codes never expire
- MFA binding not enforced

## Attack Scenarios

### Scenario 1: Credential Stuffing Attack

```
Attack Flow:
1. Attacker obtains leaked credentials from data breach
2. Automated tool tries credentials against mobile app API
3. No rate limiting allows 10,000 attempts per minute
4. Matching credentials identified (users reuse passwords)
5. Attacker logs in to multiple accounts
6. Account takeover complete
7. Fraud/data theft begins
```

**Prerequisites:**
- No rate limiting or account lockout
- Weak password policy allows reused passwords
- No MFA or MFA optional
- No breach detection/alerting

**Impact:** Mass account compromise, data theft, financial fraud

### Scenario 2: Session Token Theft via Man-in-the-Middle

```
Attack Flow:
1. User connects to public WiFi
2. Attacker performs MITM attack
3. App sends authentication request
4. Session token transmitted without proper encryption
5. Attacker captures token
6. Attacker uses token to make authenticated requests
7. Access to victim's account without credentials
```

**Prerequisites:**
- Insecure token transmission
- No certificate pinning
- Weak TLS configuration
- Token valid for extended period

**Impact:** Account access, data exposure, unauthorized actions

### Scenario 3: IDOR Exploitation

```
Attack Flow:
1. User authenticates to mobile app
2. App displays "View my orders" → GET /api/orders/1234
3. Attacker intercepts request with proxy
4. Changes request to /api/orders/1235
5. Server returns other user's order (no authorization check)
6. Attacker enumerates all orders: 1-999999
7. Complete database of all orders extracted
```

**Prerequisites:**
- Predictable resource identifiers
- No server-side ownership verification
- No rate limiting on API calls
- Authorization checks missing

**Impact:** Mass data breach, PII exposure, competitive intelligence

### Scenario 4: Biometric Bypass via Frida Hooking

```
Attack Flow:
1. Attacker gains physical access to rooted device
2. Installs Frida framework
3. Hooks biometric authentication method
4. Script always returns "authentication successful"
5. Biometric check bypassed
6. Access to app without valid biometric
7. Account compromise
```

**Prerequisites:**
- Client-side only biometric verification
- No root/jailbreak detection
- No server-side verification of authentication method
- Weak runtime application self-protection (RASP)

**Impact:** Unauthorized access, data theft, fraudulent transactions

### Scenario 5: JWT Algorithm Confusion Attack

```
Attack Flow:
1. Attacker captures valid JWT token
2. Decodes JWT: {"alg":"RS256","typ":"JWT"}
3. Changes algorithm to HS256
4. Signs token with public key as secret
5. Server accepts HS256 and verifies with public key
6. Attacker-modified token validated as legitimate
7. Privilege escalation or extended session achieved
```

**Prerequisites:**
- JWT library accepts multiple algorithms
- No algorithm whitelist enforcement
- Public key accessible
- Weak JWT validation

**Impact:** Token forgery, privilege escalation, persistent unauthorized access

## Attack Chain Analysis

### Phase 1: Reconnaissance

**Attacker Activities:**
- Analyzing authentication endpoints and mechanisms
- Identifying authentication technologies (OAuth, JWT, custom)
- Testing for rate limiting and account lockout
- Mapping authorization structure
- Identifying biometric implementation details

**Tools Used:**
- Burp Suite for API analysis
- Frida for runtime analysis
- APK/IPA decompilation tools
- Network traffic analysis tools

**Duration:** Hours to days

### Phase 2: Vulnerability Identification

**Testing Methods:**
- Automated credential testing
- Token manipulation attempts
- Authorization boundary testing
- Session management analysis
- Biometric bypass attempts

**Common Findings:**
- Missing rate limiting
- Weak password policies
- Authorization bypass vulnerabilities
- Insecure token storage
- Client-side security controls

**Duration:** Days to weeks

### Phase 3: Exploitation

**Attack Execution:**
- Credential stuffing campaigns
- Token theft and manipulation
- IDOR exploitation for data harvesting
- Session hijacking
- Privilege escalation

**Automation:**
- Scripts for mass account compromise
- Automated API abuse
- Token refresh automation
- Data extraction scripts

**Duration:** Minutes to hours once vulnerability confirmed

### Phase 4: Persistence

**Maintaining Access:**
- Stealing refresh tokens for long-term access
- Creating backdoor accounts
- Escalating privileges to admin
- Disabling security notifications
- Maintaining session across security updates

**Duration:** Weeks to months if undetected

## Exploitation Techniques

### 1. Brute Force Automation

```
Conceptual Approach:
- Automated tool sends authentication requests
- Tests common passwords or leaked credentials
- Bypasses rate limiting via distributed requests
- Identifies successful authentications
- Extracts session tokens for access
```

**Success Factors:**
- No CAPTCHA or rate limiting
- Weak password policy
- No account lockout
- Predictable username patterns

### 2. Token Manipulation

```
Conceptual Approach:
- Capture authentication token
- Decode token structure (JWT, custom)
- Modify claims (userId, role, expiration)
- Re-encode token
- Test if server accepts modified token
```

**Common Modifications:**
- User ID changes for impersonation
- Role elevation (user → admin)
- Expiration time extension
- Permission scope expansion

### 3. Authorization Bypass

```
Conceptual Approach:
- Identify resource access patterns
- Test parameter manipulation
- Attempt horizontal traversal (other users)
- Attempt vertical escalation (higher privileges)
- Map all accessible resources
```

**Attack Patterns:**
- Direct object reference manipulation
- Missing function-level checks
- Role parameter injection
- Path traversal in endpoints

### 4. Session Riding

```
Conceptual Approach:
- Identify session token format
- Test for session fixation
- Attempt session hijacking
- Verify session independence
- Test concurrent session handling
```

**Exploitation:**
- Fixed session IDs accepted
- Sessions not bound to IP/device
- No session invalidation on logout
- Concurrent sessions allowed

## Detection Indicators

### Technical Indicators

**Authentication Anomalies:**
- High number of failed login attempts
- Login attempts from unusual locations
- Multiple accounts from same IP
- Unusual login time patterns
- Rapid successive login attempts

**Session Indicators:**
- Session tokens used from multiple IPs simultaneously
- Session activity after logout
- Expired tokens still accepted
- Unusual API access patterns
- Token reuse across devices

**Authorization Indicators:**
- Access to resources outside normal patterns
- Sequential ID enumeration patterns
- Privilege escalation attempts
- Cross-account data access
- Admin function access by regular users

### Behavioral Indicators

**User Account:**
- Password reset requests not initiated by user
- Unexpected account changes
- Unrecognized devices accessing account
- Unusual transaction patterns
- Account accessed during unusual hours

**API Traffic:**
- Spike in authentication requests
- Unusual endpoint access patterns
- High volume of failed authorization checks
- Automated tool signatures in requests
- Proxy/VPN usage patterns

### Application Indicators

**Mobile App:**
- Root/jailbreak detection triggers
- Debugger attachment detected
- Runtime hooking detected
- Modified app signatures
- Biometric bypass attempts

**Backend:**
- Rate limit threshold hits
- Account lockout triggers
- MFA bypass attempts
- Token validation failures
- CORS violation attempts

## Risk Assessment Matrix

### Critical Risk (Immediate Action Required)

- No authentication required for sensitive operations
- Admin functions accessible without authorization
- Passwords stored in plain text
- No session timeout or invalidation
- Complete authorization bypass possible

### High Risk (Urgent Attention Needed)

- Weak password policy (< 8 characters)
- No rate limiting or account lockout
- Client-side only authorization
- IDOR vulnerabilities present
- No MFA implementation

### Medium Risk (Should Address)

- Optional MFA (not enforced)
- Long session timeouts (> 30 minutes)
- Missing re-authentication for sensitive operations
- Weak token generation
- Limited session monitoring

### Low Risk (Monitor and Plan)

- MFA implemented and enforced
- Strong password policy
- Server-side authorization
- Session monitoring active
- Regular security audits

## Defense Indicators

Signs of proper authentication/authorization security:

✅ **Strong Authentication:**
- Enforced password complexity
- Rate limiting and account lockout
- MFA required for all users
- Secure credential transmission
- Regular password rotation

✅ **Robust Session Management:**
- Cryptographically secure token generation
- Appropriate session timeouts
- Session invalidation on logout
- Session binding to device/IP
- Concurrent session management

✅ **Proper Authorization:**
- Server-side enforcement
- User context validation on every request
- Non-predictable resource identifiers
- Function-level access control
- Regular authorization audits

## Key Takeaways

1. **Authentication attacks exploit weak identity verification and credential management**
2. **Authorization bypasses allow access to resources beyond user privileges**
3. **Session management flaws enable persistent unauthorized access**
4. **Biometric authentication requires both client and server-side verification**
5. **Defense requires multiple layers: strong auth + proper sessions + enforced authorization**

## Next Steps

- **[Prevention Guide](./prevention.md)**: Learn how to secure authentication and authorization
- **[Examples](./examples.md)**: See vulnerable vs secure implementations
- **[Interactive Lab](./lab/)**: Practice identifying and exploiting auth vulnerabilities

---

**Remember**: Authentication proves identity, authorization proves permission. Both must be rigorously enforced on the server side.
