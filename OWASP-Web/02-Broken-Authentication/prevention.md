# Broken Authentication - Prevention

## Secure Authentication Practices

### 1. Strong Password Policies

**Requirements:**
- Minimum 8-12 characters
- Mix of uppercase, lowercase, numbers, special characters
- Check against breached password databases (Have I Been Pwned)
- Enforce password history (prevent reuse)

**Example Implementation:**

```python
import re
from werkzeug.security import generate_password_hash, check_password_hash

def validate_password(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain number"
    if not re.search(r'[!@#$%^&*]', password):
        return False, "Password must contain special character"
    return True, "Password is strong"

# Hash passwords properly
hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
```

### 2. Secure Session Management

**Best Practices:**

```python
import os
import secrets
from flask import Flask, session
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.urandom(32)  # Strong random key

# Configure secure sessions
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Generate secure session IDs
def create_session():
    session_id = secrets.token_urlsafe(32)
    session['id'] = session_id
    session.permanent = True

# Regenerate session ID on privilege change
def regenerate_session():
    old_session = dict(session)
    session.clear()
    session.update(old_session)
    session.modified = True
```

### 3. Implement Brute Force Protection

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Login logic with rate limiting
    pass
```

### 4. Multi-Factor Authentication

Always offer (and encourage) MFA:

```python
import pyotp

def setup_2fa(user):
    secret = pyotp.random_base32()
    user.totp_secret = secret
    return pyotp.totp.TOTP(secret).provisioning_uri(
        user.email, 
        issuer_name="YourApp"
    )

def verify_2fa(user, token):
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(token, valid_window=1)
```

## Security Checklist

- [ ] Use strong password hashing (bcrypt, Argon2, PBKDF2)
- [ ] Implement account lockout after failed attempts
- [ ] Use secure session management
- [ ] Enable HTTPS for all authentication flows
- [ ] Implement session timeout
- [ ] Regenerate session IDs after login
- [ ] Offer multi-factor authentication
- [ ] Monitor for suspicious login attempts
- [ ] Never expose session IDs in URLs
- [ ] Clear sessions on logout
