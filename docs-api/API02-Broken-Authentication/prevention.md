# API02: Broken Authentication - Prevention

## Table of Contents
- [Core Prevention Principles](#core-prevention-principles)
- [Secure Authentication Patterns](#secure-authentication-patterns)
- [JWT Security Best Practices](#jwt-security-best-practices)
- [Rate Limiting Implementation](#rate-limiting-implementation)
- [Password Security](#password-security)
- [Multi-Factor Authentication](#multi-factor-authentication)
- [Testing and Validation](#testing-and-validation)
- [Security Checklist](#security-checklist)

## Core Prevention Principles

### 1. Use Strong Token Generation

**Principle**: Generate cryptographically secure tokens with proper algorithms and secrets.

```python
# ❌ BAD: Weak JWT with HS256 and weak secret
import jwt

SECRET = "secret123"  # Weak secret
token = jwt.encode({'user_id': 1}, SECRET, algorithm='HS256')

# ✅ GOOD: Strong JWT with RS256 and proper expiration
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import jwt

# Generate RSA key pair (do this once, store securely)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Create token with expiration
payload = {
    'user_id': user.id,
    'exp': datetime.utcnow() + timedelta(minutes=15),
    'iat': datetime.utcnow(),
    'jti': str(uuid.uuid4())  # Unique token ID
}

token = jwt.encode(
    payload,
    private_key,
    algorithm='RS256'
)
```

### 2. Implement Rate Limiting

**Principle**: Prevent brute force and credential stuffing with strict rate limits.

```python
# ✅ GOOD: Rate limiting on authentication endpoints
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
@limiter.limit("20 per hour")
def login():
    # Login logic here
    # Only 5 attempts per minute, 20 per hour
    pass

# ❌ BAD: No rate limiting
@app.route('/api/login', methods=['POST'])
def login():
    # Unlimited login attempts!
    pass
```

### 3. Enforce Strong Password Policies

**Principle**: Require passwords that resist brute force and dictionary attacks.

```python
# ✅ GOOD: Comprehensive password validation
import re
from password_strength import PasswordPolicy

policy = PasswordPolicy.from_names(
    length=12,  # Minimum 12 characters
    uppercase=1,  # At least 1 uppercase
    lowercase=1,  # At least 1 lowercase
    numbers=1,  # At least 1 number
    special=1,  # At least 1 special character
    nonletters=1,  # Non-letter characters
)

def validate_password(password):
    """Validate password meets security requirements"""
    # Check policy
    errors = policy.test(password)
    if errors:
        return False, "Password does not meet complexity requirements"
    
    # Check against common passwords
    common_passwords = load_common_passwords()  # 10k most common
    if password.lower() in common_passwords:
        return False, "Password is too common"
    
    # Check against breach database (Have I Been Pwned API)
    if check_password_breach(password):
        return False, "Password found in known data breaches"
    
    return True, "Password is strong"

# ❌ BAD: Weak password validation
def validate_password(password):
    return len(password) >= 6  # Only checks length!
```

### 4. Use Short Token Expiration

**Principle**: Minimize window of opportunity for stolen tokens.

```python
# ✅ GOOD: Short-lived access token with refresh token
def create_tokens(user_id):
    # Access token: 15 minutes
    access_token = jwt.encode(
        {
            'user_id': user_id,
            'type': 'access',
            'exp': datetime.utcnow() + timedelta(minutes=15)
        },
        private_key,
        algorithm='RS256'
    )
    
    # Refresh token: 7 days (stored securely)
    refresh_token = jwt.encode(
        {
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + timedelta(days=7),
            'jti': str(uuid.uuid4())  # Unique ID for blacklisting
        },
        private_key,
        algorithm='RS256'
    )
    
    # Store refresh token hash in database
    store_refresh_token(user_id, hash_token(refresh_token))
    
    return access_token, refresh_token

# ❌ BAD: Long-lived or no expiration
def create_token(user_id):
    token = jwt.encode(
        {'user_id': user_id},  # No expiration!
        SECRET,
        algorithm='HS256'
    )
    return token
```

## Secure Authentication Patterns

### Pattern 1: Complete Login Flow with Rate Limiting

```python
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from werkzeug.security import check_password_hash
import jwt
from datetime import datetime, timedelta

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
@limiter.limit("20 per hour")
def login():
    """Secure login endpoint with all protections"""
    data = request.get_json()
    
    # Validate input
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400
    
    email = data['email'].lower().strip()
    password = data['password']
    
    # Check if account is locked
    if is_account_locked(email):
        log_security_event('login_attempt_locked_account', email=email)
        return jsonify({'error': 'Account is locked. Contact support.'}), 403
    
    # Get user from database
    user = User.query.filter_by(email=email).first()
    
    # Use constant-time comparison to prevent timing attacks
    if not user or not check_password_hash(user.password_hash, password):
        # Record failed attempt
        record_failed_login(email)
        
        # Lock account after 10 failed attempts
        if get_failed_attempts(email) >= 10:
            lock_account(email)
            log_security_event('account_locked', email=email)
        
        # Generic error message (don't reveal if user exists)
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if MFA is enabled
    if user.mfa_enabled:
        # Return temporary token for MFA verification
        mfa_token = create_mfa_token(user.id)
        return jsonify({
            'mfa_required': True,
            'mfa_token': mfa_token
        }), 200
    
    # Clear failed login attempts
    clear_failed_attempts(email)
    
    # Generate tokens
    access_token, refresh_token = create_tokens(user.id)
    
    # Log successful login
    log_security_event('login_success', user_id=user.id, ip=request.remote_addr)
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'expires_in': 900  # 15 minutes
    }), 200
```

### Pattern 2: Secure Password Reset Flow

```python
import secrets
from datetime import datetime, timedelta

@app.route('/api/password-reset/request', methods=['POST'])
@limiter.limit("3 per hour")  # Prevent abuse
def request_password_reset():
    """Request password reset - rate limited"""
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    
    # Always return success to prevent email enumeration
    response = jsonify({
        'message': 'If that email exists, a reset link has been sent.'
    })
    
    user = User.query.filter_by(email=email).first()
    if not user:
        # Still return success, but don't send email
        return response, 200
    
    # Generate cryptographically secure token
    reset_token = secrets.token_urlsafe(32)  # 256 bits
    
    # Hash token before storing
    token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
    
    # Store with expiration
    PasswordReset.create(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    
    # Send email with token
    send_reset_email(user.email, reset_token)
    
    # Log request
    log_security_event('password_reset_requested', user_id=user.id)
    
    return response, 200

@app.route('/api/password-reset/confirm', methods=['POST'])
@limiter.limit("5 per hour")
def confirm_password_reset():
    """Confirm password reset with token"""
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    # Validate new password
    valid, message = validate_password(new_password)
    if not valid:
        return jsonify({'error': message}), 400
    
    # Hash provided token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # Find non-expired reset request
    reset = PasswordReset.query.filter_by(
        token_hash=token_hash
    ).filter(
        PasswordReset.expires_at > datetime.utcnow(),
        PasswordReset.used == False
    ).first()
    
    if not reset:
        return jsonify({'error': 'Invalid or expired reset token'}), 400
    
    # Update password
    user = User.query.get(reset.user_id)
    user.set_password(new_password)
    
    # Mark token as used
    reset.used = True
    reset.used_at = datetime.utcnow()
    db.session.commit()
    
    # Invalidate all existing sessions
    invalidate_all_tokens(user.id)
    
    # Log password change
    log_security_event('password_changed', user_id=user.id)
    
    # Send notification email
    send_password_changed_notification(user.email)
    
    return jsonify({'message': 'Password updated successfully'}), 200
```

### Pattern 3: Token Refresh Mechanism

```python
@app.route('/api/token/refresh', methods=['POST'])
@limiter.limit("10 per hour")
def refresh_token():
    """Refresh access token using refresh token"""
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    
    if not refresh_token:
        return jsonify({'error': 'Refresh token required'}), 400
    
    try:
        # Verify refresh token
        payload = jwt.decode(
            refresh_token,
            public_key,
            algorithms=['RS256'],
            options={'require_exp': True}
        )
        
        # Check token type
        if payload.get('type') != 'refresh':
            return jsonify({'error': 'Invalid token type'}), 401
        
        # Check if token is blacklisted
        if is_token_blacklisted(payload['jti']):
            return jsonify({'error': 'Token has been revoked'}), 401
        
        # Verify token is in database
        token_hash = hash_token(refresh_token)
        if not verify_refresh_token(payload['user_id'], token_hash):
            return jsonify({'error': 'Invalid refresh token'}), 401
        
        # Generate new access token
        new_access_token = jwt.encode(
            {
                'user_id': payload['user_id'],
                'type': 'access',
                'exp': datetime.utcnow() + timedelta(minutes=15)
            },
            private_key,
            algorithm='RS256'
        )
        
        return jsonify({
            'access_token': new_access_token,
            'expires_in': 900
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Refresh token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid refresh token'}), 401
```

## JWT Security Best Practices

### 1. Use Asymmetric Algorithms (RS256)

```python
# ✅ GOOD: RS256 with public/private key pair
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate keys (do once, store securely)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

# Save keys securely
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Sign with private key
token = jwt.encode(payload, private_key, algorithm='RS256')

# Verify with public key (can be distributed)
jwt.decode(token, public_key, algorithms=['RS256'])
```

### 2. Enforce Algorithm in Verification

```python
# ✅ GOOD: Strict algorithm enforcement
def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],  # ONLY RS256 accepted
            options={
                'require_exp': True,  # Require expiration
                'require_iat': True,  # Require issued-at
                'verify_exp': True,  # Verify expiration
                'verify_iat': True,  # Verify issued-at
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthenticationError('Token has expired')
    except jwt.InvalidTokenError:
        raise AuthenticationError('Invalid token')

# ❌ BAD: Accepts multiple algorithms
jwt.decode(token, key, algorithms=['HS256', 'RS256', 'none'])
```

### 3. Include Security Claims

```python
# ✅ GOOD: Comprehensive JWT payload
def create_access_token(user_id, user_email):
    payload = {
        # Standard claims
        'sub': user_id,  # Subject (user ID)
        'iat': datetime.utcnow(),  # Issued at
        'exp': datetime.utcnow() + timedelta(minutes=15),  # Expiration
        'jti': str(uuid.uuid4()),  # JWT ID (unique)
        
        # Custom claims
        'email': user_email,
        'type': 'access',
        
        # Security claims
        'iss': 'your-api.example.com',  # Issuer
        'aud': 'your-client-app',  # Audience
    }
    
    return jwt.encode(payload, private_key, algorithm='RS256')

# Verify all claims
def verify_token(token):
    return jwt.decode(
        token,
        public_key,
        algorithms=['RS256'],
        issuer='your-api.example.com',
        audience='your-client-app',
        options={'require': ['exp', 'iat', 'jti']}
    )
```

### 4. Never Store Sensitive Data in JWT

```python
# ❌ BAD: Sensitive data in JWT (base64 decodable!)
payload = {
    'user_id': 123,
    'email': 'user@example.com',
    'ssn': '123-45-6789',  # ✗ NEVER!
    'credit_card': '4111-1111-1111-1111',  # ✗ NEVER!
    'password': 'hashed_password',  # ✗ NEVER!
}

# ✅ GOOD: Only non-sensitive identifiers
payload = {
    'user_id': 123,
    'email': 'user@example.com',
    'role': 'user',
    'exp': datetime.utcnow() + timedelta(minutes=15)
}
```

## Rate Limiting Implementation

### Flask Implementation with Redis

```python
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

app = Flask(__name__)

# Configure rate limiter with Redis backend
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379/0",
    strategy="fixed-window"
)

# Global rate limit
@limiter.limit("1000 per day;100 per hour")
def default_limit():
    pass

# Specific endpoint limits
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute;20 per hour;50 per day")
def login():
    # Strict limits on authentication
    pass

@app.route('/api/password-reset/request', methods=['POST'])
@limiter.limit("3 per hour;10 per day")
def reset_request():
    # Very strict for password reset
    pass

@app.route('/api/data', methods=['GET'])
@limiter.limit("100 per minute")
def get_data():
    # More lenient for data retrieval
    pass

# Custom key function (rate limit by user ID)
def get_user_id():
    return request.headers.get('X-User-ID', 'anonymous')

@app.route('/api/protected')
@limiter.limit("50 per hour", key_func=get_user_id)
def protected():
    # Rate limit per authenticated user
    pass

# Error handler
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': str(e.description)
    }), 429
```

### Express.js Implementation

```javascript
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');

const redisClient = redis.createClient({
  host: 'localhost',
  port: 6379
});

// Login rate limiter
const loginLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply to login endpoint
app.post('/api/login', loginLimiter, async (req, res) => {
  // Login logic
});

// Password reset limiter (stricter)
const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: 'Too many password reset requests'
});

app.post('/api/password-reset', resetLimiter, async (req, res) => {
  // Password reset logic
});
```

## Password Security

### Password Hashing with Argon2

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize Argon2 hasher
ph = PasswordHasher(
    time_cost=2,  # Number of iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,  # Number of parallel threads
    hash_len=32,  # Length of hash
    salt_len=16  # Length of salt
)

class User:
    def set_password(self, password):
        """Hash and store password"""
        # Validate password first
        valid, message = validate_password(password)
        if not valid:
            raise ValueError(message)
        
        # Hash password
        self.password_hash = ph.hash(password)
    
    def check_password(self, password):
        """Verify password"""
        try:
            # Verify password
            ph.verify(self.password_hash, password)
            
            # Check if rehashing is needed (algorithm updated)
            if ph.check_needs_rehash(self.password_hash):
                self.password_hash = ph.hash(password)
                db.session.commit()
            
            return True
        except VerifyMismatchError:
            return False
```

### Password Breach Detection

```python
import hashlib
import requests

def check_password_breach(password):
    """
    Check if password appears in Have I Been Pwned database
    Uses k-anonymity to preserve privacy
    """
    # Hash password with SHA-1
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    
    # Send first 5 characters to API
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    
    # Query API
    response = requests.get(
        f'https://api.pwnedpasswords.com/range/{prefix}',
        timeout=5
    )
    
    if response.status_code != 200:
        # If API fails, allow password but log
        log_warning('HIBP API unavailable')
        return False
    
    # Check if suffix appears in response
    hashes = (line.split(':') for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return True  # Password found in breach
    
    return False  # Password not found
```

## Multi-Factor Authentication

### TOTP Implementation

```python
import pyotp
import qrcode
from io import BytesIO
import base64

class User:
    def enable_mfa(self):
        """Generate MFA secret and QR code"""
        # Generate secret
        self.mfa_secret = pyotp.random_base32()
        
        # Create TOTP URI
        totp_uri = pyotp.totp.TOTP(self.mfa_secret).provisioning_uri(
            name=self.email,
            issuer_name='Your API'
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        db.session.commit()
        
        return {
            'secret': self.mfa_secret,
            'qr_code': qr_code_base64,
            'uri': totp_uri
        }
    
    def verify_mfa(self, code):
        """Verify MFA code"""
        if not self.mfa_enabled or not self.mfa_secret:
            return False
        
        totp = pyotp.TOTP(self.mfa_secret)
        
        # Verify code (allows 30-second window)
        return totp.verify(code, valid_window=1)

# MFA verification endpoint
@app.route('/api/mfa/verify', methods=['POST'])
@limiter.limit("5 per minute")
def verify_mfa():
    """Verify MFA code and complete login"""
    data = request.get_json()
    mfa_token = data.get('mfa_token')
    mfa_code = data.get('code')
    
    # Verify MFA token
    try:
        payload = jwt.decode(
            mfa_token,
            public_key,
            algorithms=['RS256']
        )
        
        if payload.get('type') != 'mfa':
            return jsonify({'error': 'Invalid token'}), 401
        
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid MFA token'}), 401
    
    # Get user
    user = User.query.get(payload['user_id'])
    
    # Verify MFA code
    if not user.verify_mfa(mfa_code):
        return jsonify({'error': 'Invalid MFA code'}), 401
    
    # Generate access and refresh tokens
    access_token, refresh_token = create_tokens(user.id)
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token
    }), 200
```

## Testing and Validation

### Unit Tests for Authentication

```python
import unittest

class TestAuthentication(unittest.TestCase):
    def test_password_strength_validation(self):
        """Test password policy enforcement"""
        # Weak passwords should be rejected
        weak_passwords = [
            '123456',
            'password',
            'admin',
            'short',
            'alllowercase',
            'ALLUPPERCASE',
            'NoSpecialChar1'
        ]
        
        for pwd in weak_passwords:
            valid, _ = validate_password(pwd)
            self.assertFalse(valid, f"Weak password '{pwd}' was accepted")
        
        # Strong password should be accepted
        strong_pwd = 'MyS3cure!Pass2024'
        valid, _ = validate_password(strong_pwd)
        self.assertTrue(valid)
    
    def test_rate_limiting(self):
        """Test rate limiting on login"""
        # Should allow 5 attempts
        for i in range(5):
            response = self.client.post('/api/login', json={
                'email': 'test@example.com',
                'password': 'wrong'
            })
            self.assertEqual(response.status_code, 401)
        
        # 6th attempt should be rate limited
        response = self.client.post('/api/login', json={
            'email': 'test@example.com',
            'password': 'wrong'
        })
        self.assertEqual(response.status_code, 429)
    
    def test_jwt_expiration(self):
        """Test token expiration"""
        # Create expired token
        token = jwt.encode(
            {
                'user_id': 1,
                'exp': datetime.utcnow() - timedelta(hours=1)
            },
            private_key,
            algorithm='RS256'
        )
        
        # Should reject expired token
        with self.assertRaises(jwt.ExpiredSignatureError):
            jwt.decode(token, public_key, algorithms=['RS256'])
    
    def test_algorithm_enforcement(self):
        """Test JWT algorithm cannot be changed"""
        # Try to create token with HS256
        token = jwt.encode(
            {'user_id': 1, 'alg': 'HS256'},
            'secret',
            algorithm='HS256'
        )
        
        # Should reject when expecting RS256
        with self.assertRaises(jwt.InvalidTokenError):
            jwt.decode(token, public_key, algorithms=['RS256'])
```

## Security Checklist

### Development Phase
- [ ] Rate limiting on all auth endpoints (5/min, 20/hour)
- [ ] Strong password policy (12+ chars, complexity)
- [ ] JWT uses RS256 (not HS256)
- [ ] Tokens expire in 15 minutes
- [ ] Refresh token mechanism implemented
- [ ] MFA option available
- [ ] Password breach checking integrated
- [ ] Account lockout after 10 failed attempts
- [ ] Secure password reset flow
- [ ] No sensitive data in JWT payload

### Code Review Phase
- [ ] Secrets not hardcoded in code
- [ ] Argon2 or bcrypt for password hashing
- [ ] Algorithm strictly enforced in JWT verification
- [ ] All auth endpoints have rate limiting
- [ ] Token expiration always included
- [ ] Logout invalidates tokens
- [ ] Password validation comprehensive
- [ ] No timing attacks in password comparison

### Testing Phase
- [ ] Test with weak passwords (should reject)
- [ ] Test rate limiting (should block after limit)
- [ ] Test JWT expiration (should reject expired)
- [ ] Test algorithm switching (should reject)
- [ ] Test MFA flow (if implemented)
- [ ] Test password reset (secure tokens)
- [ ] Test account lockout (after failed attempts)
- [ ] Test logout (token invalidation)

### Monitoring Phase
- [ ] Log all authentication failures
- [ ] Alert on unusual login patterns
- [ ] Monitor rate limit hits
- [ ] Track MFA adoption rate
- [ ] Alert on password reset spikes
- [ ] Monitor JWT validation failures

## Key Takeaways

1. ✅ **Use RS256 for JWT** - Asymmetric is more secure than HS256
2. ✅ **Short token expiration** - 15 minutes for access tokens
3. ✅ **Implement rate limiting** - 5 attempts/minute on auth endpoints
4. ✅ **Strong password policy** - 12+ chars with complexity
5. ✅ **Use Argon2 for hashing** - Most secure modern algorithm
6. ✅ **Add MFA option** - Significantly increases security
7. ✅ **Check password breaches** - Use Have I Been Pwned API
8. ✅ **Secure password reset** - Cryptographically secure tokens

## What's Next?

- **[Examples](./examples.md)**: See more code examples and patterns
- **[Lab](./lab/api02-weak-auth-lab/)**: Practice fixing authentication vulnerabilities
- **[Overview](./overview.md)**: Review authentication fundamentals

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
