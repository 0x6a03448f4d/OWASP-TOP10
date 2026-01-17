# Broken Authentication - API Examples

## Table of Contents
- [Safe Pseudo-Code Examples](#safe-pseudo-code-examples)
- [Bad vs Good Code Comparisons](#bad-vs-good-code-comparisons)
- [JWT Security Examples](#jwt-security-examples)
- [Rate Limiting Examples](#rate-limiting-examples)
- [Password Security Examples](#password-security-examples)
- [MFA Implementation Examples](#mfa-implementation-examples)

## Safe Pseudo-Code Examples

These examples demonstrate broken authentication vulnerabilities specifically in API contexts without providing exploitable code.

### Example 1: Weak JWT Implementation

**❌ VULNERABLE: Weak Secret and No Expiration**
```python
import jwt

@app.route('/api/login', methods=['POST'])
def login():
    """Login with weak JWT implementation"""
    data = request.json
    user = authenticate(data['username'], data['password'])
    
    if user:
        # VULNERABLE: Weak secret, no expiration
        token = jwt.encode(
            {'user_id': user.id},
            'secret123',  # Weak secret!
            algorithm='HS256'  # Symmetric algorithm
        )
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401
```

**✅ SECURE: Strong JWT with RS256 and Expiration**
```python
import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa

# Load RSA keys (generated once, stored securely)
with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

@app.route('/api/login', methods=['POST'])
def login():
    """Secure login with proper JWT"""
    data = request.json
    user = authenticate(data['username'], data['password'])
    
    if user:
        # Secure JWT implementation
        payload = {
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=15),
            'iat': datetime.utcnow(),
            'jti': str(uuid.uuid4())
        }
        
        token = jwt.encode(
            payload,
            private_key,
            algorithm='RS256'  # Asymmetric algorithm
        )
        
        return jsonify({
            'access_token': token,
            'expires_in': 900
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401
```

### Example 2: No Rate Limiting

**❌ VULNERABLE: Unlimited Login Attempts**
```python
@app.route('/api/login', methods=['POST'])
def login():
    """No rate limiting - vulnerable to brute force"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # No rate limiting!
    # Attacker can try unlimited passwords
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        token = create_token(user.id)
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401
```

**✅ SECURE: Rate Limiting Implemented**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379"
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Max 5 attempts per minute
@limiter.limit("20 per hour")   # Max 20 attempts per hour
def login():
    """Rate limited login endpoint"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # Check if account is locked
    if is_account_locked(username):
        return jsonify({'error': 'Account locked'}), 403
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        # Clear failed attempts on success
        clear_failed_attempts(username)
        token = create_token(user.id)
        return jsonify({'token': token})
    
    # Record failed attempt
    record_failed_login(username)
    
    # Lock account after 10 failed attempts
    if get_failed_attempts(username) >= 10:
        lock_account(username)
    
    return jsonify({'error': 'Invalid credentials'}), 401
```

### Example 3: Weak Password Policy

**❌ VULNERABLE: No Password Validation**
```python
@app.route('/api/register', methods=['POST'])
def register():
    """Accepts any password"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # VULNERABLE: No password strength check!
    # Accepts: "123456", "password", "admin"
    
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User created'}), 201
```

**✅ SECURE: Strong Password Policy**
```python
import re
from password_strength import PasswordPolicy

policy = PasswordPolicy.from_names(
    length=12,
    uppercase=1,
    lowercase=1,
    numbers=1,
    special=1,
)

def check_password_breach(password):
    """Check against Have I Been Pwned database"""
    import hashlib
    import requests
    
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    response = requests.get(
        f'https://api.pwnedpasswords.com/range/{prefix}'
    )
    
    if response.status_code == 200:
        hashes = (line.split(':') for line in response.text.splitlines())
        for hash_suffix, count in hashes:
            if hash_suffix == suffix:
                return True
    return False

@app.route('/api/register', methods=['POST'])
def register():
    """Enforces strong password policy"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # Validate password complexity
    errors = policy.test(password)
    if errors:
        return jsonify({
            'error': 'Password does not meet requirements',
            'requirements': [
                'At least 12 characters',
                'At least 1 uppercase letter',
                'At least 1 lowercase letter',
                'At least 1 number',
                'At least 1 special character'
            ]
        }), 400
    
    # Check against common passwords
    common_passwords = ['123456', 'password', 'admin', 'qwerty']
    if password.lower() in common_passwords:
        return jsonify({
            'error': 'Password is too common'
        }), 400
    
    # Check against breach database
    if check_password_breach(password):
        return jsonify({
            'error': 'Password found in data breach database'
        }), 400
    
    # Create user
    user = User(username=username)
    user.set_password(password)  # Uses Argon2
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User created'}), 201
```

## Bad vs Good Code Comparisons

### Comparison 1: Token Expiration

**❌ BAD: No Expiration**
```python
def create_token(user_id):
    # Token never expires!
    return jwt.encode(
        {'user_id': user_id},
        SECRET_KEY,
        algorithm='HS256'
    )
# If token is stolen, it's valid forever
```

**✅ GOOD: Short Expiration with Refresh Token**
```python
def create_tokens(user_id):
    # Access token: 15 minutes
    access_token = jwt.encode(
        {
            'user_id': user_id,
            'type': 'access',
            'exp': datetime.utcnow() + timedelta(minutes=15),
            'iat': datetime.utcnow()
        },
        private_key,
        algorithm='RS256'
    )
    
    # Refresh token: 7 days
    refresh_token = jwt.encode(
        {
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + timedelta(days=7),
            'jti': str(uuid.uuid4())
        },
        private_key,
        algorithm='RS256'
    )
    
    # Store refresh token in database for revocation
    store_refresh_token(user_id, hash_token(refresh_token))
    
    return access_token, refresh_token
```

### Comparison 2: Password Hashing

**❌ BAD: Weak Hashing**
```python
import hashlib

def set_password(self, password):
    # MD5 is cryptographically broken!
    self.password_hash = hashlib.md5(password.encode()).hexdigest()

def check_password(self, password):
    # Timing attack vulnerable
    return hashlib.md5(password.encode()).hexdigest() == self.password_hash
```

**✅ GOOD: Argon2 with Proper Timing**
```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32
)

def set_password(self, password):
    # Argon2id - Winner of Password Hashing Competition
    self.password_hash = ph.hash(password)

def check_password(self, password):
    try:
        # Constant-time verification
        ph.verify(self.password_hash, password)
        
        # Rehash if parameters changed
        if ph.check_needs_rehash(self.password_hash):
            self.password_hash = ph.hash(password)
            db.session.commit()
        
        return True
    except VerifyMismatchError:
        return False
```

### Comparison 3: Password Reset Tokens

**❌ BAD: Predictable Reset Tokens**
```python
import random

@app.route('/api/password-reset', methods=['POST'])
def reset_password():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    
    if user:
        # VULNERABLE: Predictable token
        reset_token = f"{user.id}-{random.randint(1000, 9999)}"
        # Token: "123-5678" (easily guessable!)
        
        user.reset_token = reset_token
        db.session.commit()
        
        send_email(email, f"Reset token: {reset_token}")
    
    return jsonify({'message': 'If email exists, reset sent'})
```

**✅ GOOD: Cryptographically Secure Tokens**
```python
import secrets
import hashlib
from datetime import datetime, timedelta

@app.route('/api/password-reset/request', methods=['POST'])
@limiter.limit("3 per hour")
def request_reset():
    email = request.json.get('email')
    
    # Always return same message to prevent enumeration
    response = jsonify({
        'message': 'If that email exists, a reset link has been sent'
    })
    
    user = User.query.filter_by(email=email).first()
    
    if user:
        # Generate cryptographically secure token (256 bits)
        reset_token = secrets.token_urlsafe(32)
        
        # Hash before storing (don't store plain token)
        token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
        
        # Store with expiration
        PasswordReset.create(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            used=False
        )
        
        # Send secure link
        reset_link = f"https://example.com/reset?token={reset_token}"
        send_email(email, reset_link)
    
    return response, 200
```

## JWT Security Examples

### Example 1: Algorithm Confusion Prevention

**❌ VULNERABLE: Accepts Multiple Algorithms**
```python
def verify_token(token):
    # Accepts algorithm from token header!
    return jwt.decode(
        token,
        public_key,
        algorithms=['HS256', 'RS256', 'none']
    )
# Attacker can switch algorithm to "none" or "HS256"
```

**✅ SECURE: Strict Algorithm Enforcement**
```python
def verify_token(token):
    try:
        # Only accepts RS256, rejects all others
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],  # Strict enforcement
            options={
                'require_exp': True,
                'require_iat': True,
                'verify_exp': True,
                'verify_iat': True
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthenticationError('Token expired')
    except jwt.InvalidTokenError:
        raise AuthenticationError('Invalid token')
```

### Example 2: Token Revocation on Logout

**❌ VULNERABLE: No Token Revocation**
```python
@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    # Just returns success but token still valid!
    return jsonify({'message': 'Logged out'}), 200

# Token can still be used until expiration
```

**✅ SECURE: Token Blacklisting**
```python
import redis

redis_client = redis.Redis(host='localhost', port=6379, db=0)

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    token = get_jwt_token()
    
    # Decode to get expiration
    payload = jwt.decode(
        token,
        public_key,
        algorithms=['RS256'],
        options={'verify_exp': False}
    )
    
    # Calculate remaining lifetime
    exp_timestamp = payload['exp']
    now_timestamp = datetime.utcnow().timestamp()
    ttl = int(exp_timestamp - now_timestamp)
    
    if ttl > 0:
        # Add token to blacklist with TTL
        jti = payload.get('jti')
        redis_client.setex(f'blacklist:{jti}', ttl, 'revoked')
    
    return jsonify({'message': 'Logged out successfully'}), 200

def is_token_blacklisted(jti):
    """Check if token is blacklisted"""
    return redis_client.exists(f'blacklist:{jti}')

@app.before_request
def check_token_blacklist():
    """Check all requests for blacklisted tokens"""
    if request.endpoint and 'static' not in request.endpoint:
        token = get_jwt_token()
        if token:
            try:
                payload = jwt.decode(
                    token,
                    public_key,
                    algorithms=['RS256']
                )
                if is_token_blacklisted(payload.get('jti')):
                    return jsonify({'error': 'Token revoked'}), 401
            except jwt.InvalidTokenError:
                pass
```

## Rate Limiting Examples

### Example 1: Per-Endpoint Rate Limits

```python
from flask_limiter import Limiter

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379"
)

# Strict limit for authentication
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
@limiter.limit("20 per hour")
@limiter.limit("50 per day")
def login():
    pass

# Very strict for password reset
@app.route('/api/password-reset', methods=['POST'])
@limiter.limit("3 per hour")
@limiter.limit("10 per day")
def password_reset():
    pass

# More lenient for regular API calls
@app.route('/api/data', methods=['GET'])
@limiter.limit("100 per minute")
@limiter.limit("1000 per hour")
def get_data():
    pass
```

### Example 2: Custom Rate Limit Key

```python
def get_user_identifier():
    """Use authenticated user ID or IP address"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if token:
        try:
            payload = jwt.decode(token, public_key, algorithms=['RS256'])
            return f"user:{payload['user_id']}"
        except:
            pass
    
    return f"ip:{request.remote_addr}"

@app.route('/api/protected')
@limiter.limit("50 per hour", key_func=get_user_identifier)
def protected_endpoint():
    """Rate limit per authenticated user"""
    pass
```

## Password Security Examples

### Example 1: Comprehensive Password Validation

```python
import re
from typing import Tuple, List

def validate_password(password: str) -> Tuple[bool, List[str]]:
    """
    Comprehensive password validation
    Returns: (is_valid, list_of_errors)
    """
    errors = []
    
    # Length check
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")
    
    # Character composition
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'[0-9]', password):
        errors.append("Password must contain at least one number")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    # Check for common patterns
    common_patterns = [
        r'(.)\1{2,}',  # Repeated characters (aaa, 111)
        r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk)',  # Sequential letters
        r'(qwerty|asdfgh|zxcvbn)',  # Keyboard patterns
    ]
    
    for pattern in common_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            errors.append("Password contains common patterns")
            break
    
    # Check against common passwords
    common_passwords = load_common_passwords()  # Load from file
    if password.lower() in common_passwords:
        errors.append("Password is too common")
    
    # Check breach database
    if check_password_breach(password):
        errors.append("Password has been found in data breaches")
    
    return len(errors) == 0, errors

# Usage
@app.route('/api/register', methods=['POST'])
def register():
    password = request.json.get('password')
    
    is_valid, errors = validate_password(password)
    
    if not is_valid:
        return jsonify({
            'error': 'Password does not meet requirements',
            'details': errors
        }), 400
    
    # Create user with validated password
    # ...
```

## MFA Implementation Examples

### Example 1: TOTP (Time-Based One-Time Password)

```python
import pyotp
import qrcode
from io import BytesIO
import base64

class User(db.Model):
    # ... other fields ...
    mfa_secret = db.Column(db.String(32))
    mfa_enabled = db.Column(db.Boolean, default=False)
    
    def enable_mfa(self):
        """Enable MFA for user"""
        # Generate secret
        self.mfa_secret = pyotp.random_base32()
        
        # Create provisioning URI
        totp = pyotp.TOTP(self.mfa_secret)
        uri = totp.provisioning_uri(
            name=self.email,
            issuer_name='Your API Name'
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            'secret': self.mfa_secret,
            'qr_code': f'data:image/png;base64,{qr_base64}',
            'uri': uri
        }
    
    def verify_totp(self, token):
        """Verify TOTP token"""
        if not self.mfa_enabled or not self.mfa_secret:
            return False
        
        totp = pyotp.TOTP(self.mfa_secret)
        # Verify with 30-second window
        return totp.verify(token, valid_window=1)

# Enable MFA endpoint
@app.route('/api/mfa/enable', methods=['POST'])
@jwt_required()
def enable_mfa():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Generate MFA setup
    setup_data = user.enable_mfa()
    
    # Don't commit yet - wait for verification
    
    return jsonify({
        'secret': setup_data['secret'],
        'qr_code': setup_data['qr_code']
    }), 200

# Verify and complete MFA setup
@app.route('/api/mfa/verify-setup', methods=['POST'])
@jwt_required()
def verify_mfa_setup():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    token = request.json.get('token')
    
    if user.verify_totp(token):
        user.mfa_enabled = True
        db.session.commit()
        return jsonify({'message': 'MFA enabled successfully'}), 200
    
    return jsonify({'error': 'Invalid token'}), 400

# Login with MFA
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login_with_mfa():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if MFA is enabled
    if user.mfa_enabled:
        # Return MFA challenge token (short-lived)
        mfa_token = jwt.encode(
            {
                'user_id': user.id,
                'type': 'mfa_challenge',
                'exp': datetime.utcnow() + timedelta(minutes=5)
            },
            private_key,
            algorithm='RS256'
        )
        
        return jsonify({
            'mfa_required': True,
            'mfa_token': mfa_token
        }), 200
    
    # No MFA - return tokens
    access_token, refresh_token = create_tokens(user.id)
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token
    }), 200

# Verify MFA and complete login
@app.route('/api/mfa/verify', methods=['POST'])
@limiter.limit("5 per minute")
def verify_mfa_login():
    data = request.json
    mfa_token = data.get('mfa_token')
    totp_code = data.get('code')
    
    # Verify MFA challenge token
    try:
        payload = jwt.decode(
            mfa_token,
            public_key,
            algorithms=['RS256']
        )
        
        if payload.get('type') != 'mfa_challenge':
            return jsonify({'error': 'Invalid token type'}), 401
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'MFA challenge expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    
    # Get user and verify TOTP
    user = User.query.get(payload['user_id'])
    
    if not user.verify_totp(totp_code):
        return jsonify({'error': 'Invalid MFA code'}), 401
    
    # MFA verified - issue tokens
    access_token, refresh_token = create_tokens(user.id)
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token
    }), 200
```

## Key Takeaways

1. ✅ **Use RS256 for JWT** - More secure than HS256
2. ✅ **Implement rate limiting** - Prevent brute force attacks
3. ✅ **Enforce strong passwords** - Minimum 12 characters with complexity
4. ✅ **Short token expiration** - 15 minutes for access tokens
5. ✅ **Use Argon2 for hashing** - Best current algorithm
6. ✅ **Implement MFA** - Adds critical security layer
7. ✅ **Blacklist tokens on logout** - Proper session termination
8. ✅ **Check password breaches** - Use Have I Been Pwned API

## What's Next?

- **[Overview](./overview.md)**: Understand authentication fundamentals
- **[Attack Vectors](./attack-vectors.md)**: Learn attack techniques
- **[Prevention](./prevention.md)**: Best practices for prevention
- **[Lab](./lab/api02-weak-auth-lab/)**: Hands-on practice with authentication

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
