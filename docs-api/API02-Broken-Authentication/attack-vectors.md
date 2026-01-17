# API02: Broken Authentication - Attack Vectors

## Table of Contents
- [Understanding Authentication Attack Vectors](#understanding-authentication-attack-vectors)
- [Common Attack Patterns](#common-attack-patterns)
- [Application Flaws That Enable Attacks](#application-flaws-that-enable-attacks)
- [Signs and Symptoms of Vulnerability](#signs-and-symptoms-of-vulnerability)
- [What Attackers Look For](#what-attackers-look-for)
- [Detection Techniques](#detection-techniques)

## Understanding Authentication Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY**  
> This document describes attack concepts at a high level for educational purposes. No exploit code or weaponizable techniques are provided. Understanding these patterns helps developers build better defenses.

An **attack vector** for broken authentication is the method attackers use to bypass, compromise, or abuse authentication mechanisms. Unlike BOLA which focuses on authorization, these attacks target the identity verification process itself.

### The Core Attack Flow

```
1. Reconnaissance
   ↓
   Identify authentication mechanism
   ↓
   Discover weaknesses (weak passwords, no rate limit, JWT flaws)

2. Attack Execution
   ↓
   Exploit identified weakness
   ↓
   Brute force / Token theft / Credential stuffing / Algorithm confusion

3. Access Gained
   ↓
   Obtain valid authentication token
   ↓
   Impersonate legitimate user
```

## Common Attack Patterns

### 1. Credential Stuffing Attacks

**What it is**: Using previously breached username/password pairs to gain access.

**Conceptual Flow**:
```
Attacker obtains leaked credentials:
  - LinkedIn breach: 165M accounts
  - Adobe breach: 153M accounts
  - Yahoo breach: 3 billion accounts
↓
Automated tool tests credentials:
  POST /api/login
  {"username": "user@example.com", "password": "leaked_password"}
↓
If no rate limiting:
  - Test 1000s of credentials per minute
  - Eventually find valid accounts
  - Users reuse passwords across sites
↓
Result: Multiple account compromises
```

**Why It Works**:
- Users reuse passwords across multiple sites
- Leaked credentials from one breach used on other services
- No rate limiting allows high-volume testing
- No account lockout after failed attempts
- No detection of unusual login patterns

**Success Indicators**:
- Multiple successful logins from single IP
- Login attempts using known breached passwords
- Geographic anomalies (login from multiple countries)
- Unusual time patterns (3am logins for daytime user)

### 2. Brute Force Attacks

**What it is**: Systematically trying many passwords until finding the correct one.

**Conceptual Flow**:
```
Target endpoint: POST /api/login
↓
Dictionary attack:
  Try common passwords:
    - "password", "123456", "admin"
    - "company123", "Welcome1"
    - Season+Year (Summer2024)
↓
If no rate limiting:
  Attempts: 1000 passwords/minute
  Time to crack 8-char password: Hours to days
↓
Account compromised
```

**Why It Works**:
- No rate limiting on authentication endpoints
- Weak password policies allow common passwords
- No account lockout mechanism
- No CAPTCHA or challenge-response
- Predictable password patterns

**Attack Variations**:
```
1. Dictionary Attack:
   - Try common passwords
   - Use word lists (rockyou.txt, etc.)

2. Hybrid Attack:
   - Common words + numbers
   - "password123", "admin2024"

3. Targeted Attack:
   - Company name variations
   - User's personal info (birth date, names)
   - Social media mining
```

### 3. JWT Algorithm Confusion Attack

**What it is**: Exploiting JWT implementations that allow algorithm switching.

**Conceptual Flow**:
```
Legitimate JWT (RS256 - asymmetric):
{
  "alg": "RS256",
  "typ": "JWT"
}
{
  "user_id": 1,
  "role": "user"
}
Signed with: Private Key
Verified with: Public Key
↓
Attacker modifies JWT:
{
  "alg": "HS256",  ← Changed to symmetric
  "typ": "JWT"
}
{
  "user_id": 1,
  "role": "admin"  ← Escalated privileges
}
Signed with: Public Key (known to everyone)
↓
If server accepts algorithm change:
  Server verifies using HS256 with public key
  Attacker's signature validates!
↓
Result: Privilege escalation, token forgery
```

**Why It Works**:
- Server doesn't enforce specific algorithm
- Public key used as HMAC secret when algorithm switched
- No algorithm whitelist validation
- Trust in client-provided algorithm parameter

**Vulnerable Code Pattern**:
```python
# VULNERABLE:
jwt.decode(token, key, algorithms=['HS256', 'RS256'])
# Accepts any algorithm from token header

# SECURE:
jwt.decode(token, key, algorithms=['RS256'])
# Only accepts RS256, rejects others
```

### 4. Weak JWT Secret Exploitation

**What it is**: Cracking weak JWT secrets to forge tokens.

**Conceptual Flow**:
```
Capture valid JWT token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.signature
↓
Identify weak secret:
Common secrets:
  - "secret"
  - "secret123"
  - "jwt_secret"
  - Application name
  - Default framework secrets
↓
Brute force secret:
  Try common secrets
  Use automated tools
  Dictionary attack on secret
↓
Secret found: "secret123"
↓
Forge new token:
{
  "user_id": 999,  ← Any user
  "role": "admin"  ← Any role
}
Sign with cracked secret
↓
Result: Complete authentication bypass
```

**Common Weak Secrets**:
- Default values ("secret", "password")
- Application name as secret
- Short secrets (< 32 characters)
- Dictionary words
- Hardcoded in source code

### 5. Token Theft and Replay

**What it is**: Stealing valid tokens and reusing them.

**Conceptual Flow**:
```
Token Theft Methods:
1. XSS Attack:
   → Steal token from localStorage
   → document.cookie or localStorage.getItem()

2. Man-in-the-Middle:
   → Intercept HTTP traffic
   → Extract Authorization header

3. Log Files:
   → Tokens logged in error messages
   → Access logs with tokens in URLs

4. Browser DevTools:
   → User leaves workstation unlocked
   → Inspect Application tab

5. Physical Access:
   → Screenshot of network traffic
   → Shoulder surfing
↓
Stolen token used:
  Authorization: Bearer <stolen_token>
↓
If no additional validation:
  - No IP binding
  - No user-agent checking
  - No expiration
  - No refresh mechanism
↓
Result: Session hijacking, account takeover
```

**Enabling Factors**:
- Tokens stored in localStorage (XSS vulnerable)
- Long-lived tokens (years of validity)
- No token binding to device/IP
- Tokens in URL parameters
- No token revocation on logout

### 6. Session Fixation

**What it is**: Forcing a user to use a known session token.

**Conceptual Flow**:
```
Attacker obtains session token:
  - Creates account
  - Gets valid token
↓
Attacker tricks victim:
  - Send link with embedded token
  - XSS to set token in victim's browser
  - Social engineering
↓
Victim logs in:
  POST /api/login (with attacker's token)
↓
If server doesn't regenerate token:
  Victim now authenticated
  But using attacker's token
  Attacker has access to victim's session
↓
Result: Shared session, account compromise
```

**Why It Works**:
- Server doesn't generate new token on login
- Token accepted from URL parameters
- No session invalidation on login
- Predictable token generation

### 7. Password Reset Exploitation

**What it is**: Exploiting weak password reset mechanisms.

**Conceptual Flow**:
```
Victim requests password reset:
POST /api/password-reset
{"email": "victim@example.com"}
↓
Weak reset token generation:
  - Sequential: token = user_id + timestamp
  - Short token: 6 digits (000000-999999)
  - No expiration
  - Predictable algorithm
↓
Attacker intercepts or guesses token:
  - Brute force short tokens
  - Predict algorithm output
  - Race condition exploitation
↓
Attacker resets password:
POST /api/password-reset/confirm
{
  "token": "guessed_token",
  "new_password": "attacker_password"
}
↓
Result: Account takeover without knowing original password
```

**Vulnerable Patterns**:
- Predictable reset tokens
- No expiration on reset tokens
- Reset token in URL (email leak)
- No rate limiting on reset attempts
- Account enumeration via reset

## Application Flaws That Enable Attacks

### Flaw 1: No Rate Limiting

**The Problem**: Unlimited authentication attempts allowed.

```python
# VULNERABLE
@app.route('/api/login', methods=['POST'])
def login():
    # No rate limiting!
    # Attacker can try unlimited passwords
    username = request.json.get('username')
    password = request.json.get('password')
    
    if authenticate(username, password):
        return jsonify({'token': generate_token(username)})
    return jsonify({'error': 'Invalid credentials'}), 401
```

**Impact**:
- Brute force attacks succeed
- Credential stuffing at scale
- No warning of ongoing attack
- Resource exhaustion

### Flaw 2: Weak Password Policies

**The Problem**: Accepting weak, easily guessable passwords.

```python
# VULNERABLE
def validate_password(password):
    # Only checks length!
    return len(password) >= 6

# Accepts:
# ✗ "123456"
# ✗ "password"
# ✗ "aaaaaa"
```

**Impact**:
- Users choose weak passwords
- Dictionary attacks succeed quickly
- Compromised passwords from breaches work
- Social engineering easier

### Flaw 3: No Token Expiration

**The Problem**: Tokens valid forever.

```python
# VULNERABLE
def create_token(user_id):
    payload = {
        'user_id': user_id
        # No 'exp' (expiration) claim!
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')
```

**Impact**:
- Stolen tokens work indefinitely
- No forced re-authentication
- Compromised tokens never expire
- Cannot revoke access without blacklist

### Flaw 4: Weak JWT Secrets

**The Problem**: Using predictable or weak signing secrets.

```python
# VULNERABLE
SECRET_KEY = "secret"  # ✗ Too short, common word
SECRET_KEY = "MyAppName"  # ✗ Predictable
SECRET_KEY = "12345678"  # ✗ Too simple
SECRET_KEY = app.config['APP_NAME']  # ✗ Based on public info

# Can be cracked in seconds with hashcat
```

**Impact**:
- Attacker can forge any token
- Complete authentication bypass
- Privilege escalation
- Impersonate any user

### Flaw 5: Algorithm Flexibility

**The Problem**: Accepting multiple JWT algorithms.

```python
# VULNERABLE
def verify_token(token):
    # Accepts any algorithm in token header!
    return jwt.decode(
        token,
        public_key,
        algorithms=['HS256', 'RS256', 'none']
    )
```

**Impact**:
- Algorithm confusion attacks
- "none" algorithm bypass
- Symmetric/asymmetric confusion
- Token forgery

## Signs and Symptoms of Vulnerability

### Red Flags in API Design

✗ **No rate limiting on /login endpoint**  
✗ **Tokens never expire (no exp claim)**  
✗ **Passwords < 8 characters accepted**  
✗ **No account lockout after failed attempts**  
✗ **API keys hard-coded in client apps**  
✗ **Tokens in URL parameters**  
✗ **No MFA option available**  
✗ **Logout doesn't invalidate token**  

### Code Smells

```python
# SMELL 1: No expiration
jwt.encode({'user_id': 1}, secret)

# SMELL 2: Weak secret
SECRET = "secret"

# SMELL 3: No rate limiting decorator
@app.route('/api/login')
def login():
    pass

# SMELL 4: Password in plain comparison
if password == "admin":
    pass

# SMELL 5: Multiple algorithms accepted
jwt.decode(token, key, algorithms=['HS256', 'RS256', 'none'])

# SMELL 6: Token in URL
@app.route('/api/reset-password/<token>')
def reset(token):
    pass
```

## What Attackers Look For

### Discovery Phase

1. **API Documentation**: Authentication endpoints, token formats
2. **Login Endpoint**: POST /api/login, /api/auth, /api/token
3. **Rate Limiting**: Send 100 requests, check if blocked
4. **Password Policy**: Try weak passwords (123456, password)
5. **Token Format**: Identify JWT, inspect header/payload
6. **Error Messages**: Verbose errors revealing info

### Testing Phase

Attackers systematically test:

```
✓ Send 1000 login attempts (check rate limiting)
✓ Try common passwords (check password policy)
✓ Decode JWT to inspect structure
✓ Check token expiration (look for exp claim)
✓ Modify JWT algorithm header
✓ Test token after logout (check revocation)
✓ Request password reset (analyze token format)
✓ Test for account enumeration
```

### Exploitation Indicators

**Rate Limiting Test**:
```
100 requests in 10 seconds
→ All processed = No rate limiting ✗
→ HTTP 429 after 10 = Rate limiting ✓
```

**Token Strength**:
```
JWT with "alg": "HS256" and short payload
→ Attempt secret brute force
→ If cracked = Weak secret ✗
```

**Password Policy**:
```
Register with password "123456"
→ Accepted = Weak policy ✗
→ Rejected = Strong policy ✓
```

## Detection Techniques

### For Security Teams

**Automated Testing**:
- Brute force simulation (controlled)
- JWT security analysis tools
- Password policy auditing
- Rate limit testing
- Token expiration verification

**Manual Testing**:
- Create test account
- Analyze JWT structure
- Test password requirements
- Verify rate limiting
- Check token lifetime
- Test logout behavior

**Code Review Checklist**:
- [ ] Rate limiting on all auth endpoints
- [ ] Strong password policy enforcement
- [ ] JWT uses RS256 (not HS256 with weak secret)
- [ ] Tokens have short expiration (15min)
- [ ] Refresh token mechanism present
- [ ] Logout invalidates tokens
- [ ] No sensitive data in JWT payload
- [ ] Secrets stored securely (not in code)

### For Developers

**During Development**:
```python
# Checklist for auth implementation:
def implement_auth():
    # 1. Strong password policy
    assert len(password) >= 12
    assert has_uppercase(password)
    assert has_lowercase(password)
    assert has_number(password)
    assert has_special_char(password)
    
    # 2. Rate limiting
    @limiter.limit("5 per minute")
    def login():
        pass
    
    # 3. Secure JWT
    token = jwt.encode(
        {
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=15)
        },
        private_key,
        algorithm='RS256'
    )
    
    # 4. Token validation
    jwt.decode(
        token,
        public_key,
        algorithms=['RS256'],  # Strict algorithm
        options={'require_exp': True}
    )
```

**Testing Pattern**:
```
For each authentication endpoint:
1. Test with weak passwords (expect rejection)
2. Test 100 failed login attempts (expect rate limit)
3. Test JWT expiration (wait for exp, expect 401)
4. Test logout (token should be invalid)
5. Test algorithm modification (expect rejection)
6. Test token reuse (expect detection)
```

## Prevention Mindset

### Secure by Default

```
Every authentication implementation must answer:
1. Is rate limiting enabled? (5 attempts per minute)
2. Are passwords strong? (12+ chars, complexity)
3. Do tokens expire? (15 min access, 7 day refresh)
4. Is algorithm enforced? (RS256 only)
5. Is secret strong? (256-bit random)
6. Is MFA available? (At least for sensitive ops)
7. Are tokens revoked on logout? (Blacklist or short exp)

Failing any check = Vulnerable
```

### Defense in Depth

```
Layer 1: Strong password policy
Layer 2: Rate limiting (5/min on login)
Layer 3: Account lockout (10 failed attempts)
Layer 4: MFA (TOTP or SMS)
Layer 5: Anomaly detection (unusual locations/times)
Layer 6: Short token expiration (15 minutes)
Layer 7: Secure token storage (httpOnly cookies or secure storage)
```

## Key Takeaways

1. **Rate limiting is essential** - Prevents brute force and credential stuffing
2. **JWT security matters** - Algorithm, secret, expiration all critical
3. **Password policies protect users** - Enforce strong requirements
4. **Token expiration is mandatory** - Short-lived access tokens
5. **MFA adds critical layer** - Significantly reduces risk
6. **Monitor authentication** - Detect attack patterns early
7. **Test thoroughly** - Multiple users, edge cases, attack scenarios

## What's Next?

- **[Prevention](./prevention.md)**: Implement robust authentication mechanisms
- **[Examples](./examples.md)**: See vulnerable and secure code patterns
- **[Lab](./lab/api02-weak-auth-lab/)**: Practice identifying and fixing authentication issues

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
