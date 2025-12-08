# Cryptographic Failures - Prevention

## Table of Contents
- [Core Prevention Principles](#core-prevention-principles)
- [Secure Cryptographic Patterns](#secure-cryptographic-patterns)
- [Password Hashing Best Practices](#password-hashing-best-practices)
- [Data Encryption Guidelines](#data-encryption-guidelines)
- [TLS/HTTPS Configuration](#tlshttps-configuration)
- [Key Management](#key-management)
- [Security Checklist](#security-checklist)

## Core Prevention Principles

### 1. Use Industry-Standard Cryptography

**Principle**: Never implement custom cryptographic algorithms. Use established, peer-reviewed libraries.

```python
# ✅ GOOD: Use established library
from cryptography.fernet import Fernet
import bcrypt

# ❌ BAD: Custom "encryption"
def my_encryption(text):
    return ''.join(chr((ord(c) + 13) % 256) for c in text)  # NOT SECURE!
```

### 2. Hash Passwords, Don't Encrypt Them

**Principle**: Passwords should be hashed with slow, salted algorithms. Never encrypt passwords.

```python
# ✅ GOOD: Bcrypt hashing
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# To verify:
is_valid = bcrypt.checkpw(user_input.encode(), stored_hash)

# ❌ BAD: Encryption (reversible)
from cryptography.fernet import Fernet
encrypted_password = cipher.encrypt(password)  # Wrong approach!
```

### 3. Encrypt Sensitive Data at Rest and in Transit

**Principle**: Protect sensitive data everywhere it exists.

```python
# ✅ GOOD: Encrypt sensitive fields
from cryptography.fernet import Fernet

class User:
    def set_ssn(self, ssn):
        cipher = Fernet(get_encryption_key())
        self.ssn_encrypted = cipher.encrypt(ssn.encode())
    
    def get_ssn(self):
        cipher = Fernet(get_encryption_key())
        return cipher.decrypt(self.ssn_encrypted).decode()

# ❌ BAD: Storing plaintext
class User:
    def set_ssn(self, ssn):
        self.ssn = ssn  # Plaintext in database!
```

### 4. Always Use HTTPS

**Principle**: Never transmit sensitive data over HTTP, even on internal networks.

```python
# ✅ GOOD: Force HTTPS
from flask import Flask, redirect, request

app = Flask(__name__)

@app.before_request
def force_https():
    if not request.is_secure and not app.debug:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

# ❌ BAD: Allowing HTTP
app.run(host='0.0.0.0', port=80)  # No TLS!
```

## Secure Cryptographic Patterns

### Pattern 1: Password Hashing with Bcrypt

```python
import bcrypt

class PasswordManager:
    @staticmethod
    def hash_password(password: str) -> bytes:
        """Hash a password using bcrypt"""
        # Generate salt and hash password
        salt = bcrypt.gensalt(rounds=12)  # 12 rounds = good balance
        return bcrypt.hashpw(password.encode('utf-8'), salt)
    
    @staticmethod
    def verify_password(password: str, hashed: bytes) -> bool:
        """Verify a password against its hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Usage
hashed = PasswordManager.hash_password("user_password")
# Store hashed in database

# Later, verify:
if PasswordManager.verify_password(user_input, stored_hash):
    # Password correct
    grant_access()
```

### Pattern 2: Symmetric Encryption with Fernet

```python
from cryptography.fernet import Fernet
import base64
import os

class DataEncryption:
    def __init__(self):
        # Load key from environment, not hard-coded!
        key = os.environ.get('ENCRYPTION_KEY')
        if not key:
            raise ValueError("ENCRYPTION_KEY not set")
        self.cipher = Fernet(key.encode())
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        encrypted = self.cipher.encrypt(data.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        decoded = base64.b64decode(encrypted_data.encode('utf-8'))
        decrypted = self.cipher.decrypt(decoded)
        return decrypted.decode('utf-8')

# Usage
encryptor = DataEncryption()
encrypted_ssn = encryptor.encrypt("123-45-6789")
# Store encrypted_ssn in database

# Later, decrypt:
original_ssn = encryptor.decrypt(encrypted_ssn)
```

### Pattern 3: Secure Token Generation

```python
import secrets

class TokenGenerator:
    @staticmethod
    def generate_session_token(length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_password_reset_token() -> str:
        """Generate secure password reset token"""
        # 32 bytes = 256 bits of entropy
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate secure API key"""
        return f"sk_{secrets.token_urlsafe(32)}"

# ❌ WRONG: Using random module
import random
token = str(random.randint(100000, 999999))  # Predictable!

# ✅ RIGHT: Using secrets module
token = secrets.token_urlsafe(32)  # Cryptographically secure
```

### Pattern 4: Key Derivation for Encryption

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
    """Derive encryption key from password"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Recommended minimum
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

# Usage for file encryption
password = "user_master_password"
key, salt = derive_key_from_password(password)
# Store salt (not secret), use key for encryption
```

## Password Hashing Best Practices

### Bcrypt Configuration

```python
import bcrypt

# ✅ RECOMMENDED: Bcrypt with appropriate cost factor
def hash_password(password: str) -> str:
    # Cost factor 12 = ~0.5 seconds to hash
    # Increase over time as hardware improves
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()

# Verify password
def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())
```

### Argon2 Configuration (More Secure)

```python
from argon2 import PasswordHasher

# ✅ BEST: Argon2 (winner of Password Hashing Competition)
ph = PasswordHasher(
    time_cost=2,  # Number of iterations
    memory_cost=102400,  # Memory usage in KiB (100 MB)
    parallelism=8,  # Number of parallel threads
    hash_len=32,  # Length of hash in bytes
    salt_len=16  # Length of salt in bytes
)

# Hash password
hash = ph.hash("user_password")

# Verify password
try:
    ph.verify(hash, "user_password")
    # Password correct
except:
    # Password incorrect
    pass
```

### Migration from Weak Hashes

```python
def upgrade_password_hash(user, password):
    """Upgrade from MD5 to bcrypt during login"""
    # Check if using old hash
    if user.password_hash.startswith('md5$'):
        # Verify with old method
        old_hash = hashlib.md5(password.encode()).hexdigest()
        if f'md5${old_hash}' == user.password_hash:
            # Password correct, upgrade to bcrypt
            user.password_hash = bcrypt.hashpw(
                password.encode(), 
                bcrypt.gensalt()
            )
            db.session.commit()
            return True
    else:
        # Use bcrypt verification
        return bcrypt.checkpw(password.encode(), user.password_hash)
    
    return False
```

## Data Encryption Guidelines

### Symmetric Encryption (AES-GCM)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class AESEncryption:
    def __init__(self, key: bytes):
        """Initialize with 256-bit key"""
        self.aesgcm = AESGCM(key)
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> tuple:
        """Encrypt data with AES-GCM"""
        nonce = os.urandom(12)  # 96-bit nonce
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    
    def decrypt(self, nonce: bytes, ciphertext: bytes, 
                associated_data: bytes = None) -> bytes:
        """Decrypt data"""
        return self.aesgcm.decrypt(nonce, ciphertext, associated_data)

# Usage
key = AESGCM.generate_key(bit_length=256)
cipher = AESEncryption(key)

nonce, ciphertext = cipher.encrypt(b"sensitive data")
# Store nonce and ciphertext (nonce is not secret)

plaintext = cipher.decrypt(nonce, ciphertext)
```

### Field-Level Encryption

```python
from cryptography.fernet import Fernet

class EncryptedField:
    """Encrypt specific database fields"""
    
    def __init__(self, key: bytes):
        self.cipher = Fernet(key)
    
    def encrypt_field(self, value: str) -> str:
        """Encrypt a field value"""
        if value is None:
            return None
        return self.cipher.encrypt(value.encode()).decode()
    
    def decrypt_field(self, encrypted: str) -> str:
        """Decrypt a field value"""
        if encrypted is None:
            return None
        return self.cipher.decrypt(encrypted.encode()).decode()

# Example with SQLAlchemy
from sqlalchemy import TypeDecorator, String

class EncryptedString(TypeDecorator):
    impl = String
    
    def __init__(self, key, *args, **kwargs):
        self.cipher = Fernet(key)
        super().__init__(*args, **kwargs)
    
    def process_bind_param(self, value, dialect):
        if value is not None:
            return self.cipher.encrypt(value.encode()).decode()
    
    def process_result_value(self, value, dialect):
        if value is not None:
            return self.cipher.decrypt(value.encode()).decode()
```

## TLS/HTTPS Configuration

### Flask with HTTPS

```python
from flask import Flask
import ssl

app = Flask(__name__)

if __name__ == '__main__':
    # Production: Use proper certificate
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('cert.pem', 'key.pem')
    
    app.run(
        host='0.0.0.0',
        port=443,
        ssl_context=context
    )
```

### Nginx TLS Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;
    
    # Modern TLS configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # Use TLS 1.2 and 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Strong cipher suites
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    
    # HSTS header
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
}
```

### Security Headers

```python
@app.after_request
def set_security_headers(response):
    # Force HTTPS
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self' https:"
    
    return response
```

## Key Management

### Environment Variables (Development/Small Scale)

```python
import os

# ✅ GOOD: Load from environment
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable not set")

# ❌ BAD: Hard-coded
ENCRYPTION_KEY = "hardcoded-key-123"  # NEVER DO THIS!
```

### Configuration File (Separate from Code)

```python
# config.py - NOT in version control
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    DATABASE_ENCRYPTION_KEY = os.environ.get('DB_ENCRYPTION_KEY')

# .gitignore should include config files with secrets
```

### Key Rotation Strategy

```python
from datetime import datetime, timedelta

class KeyRotation:
    def __init__(self):
        self.current_key = load_current_key()
        self.previous_keys = load_previous_keys()
    
    def encrypt(self, data):
        """Always encrypt with current key"""
        return encrypt_with_key(data, self.current_key)
    
    def decrypt(self, data):
        """Try current key first, then previous keys"""
        try:
            return decrypt_with_key(data, self.current_key)
        except:
            # Try previous keys
            for old_key in self.previous_keys:
                try:
                    return decrypt_with_key(data, old_key)
                except:
                    continue
            raise ValueError("Could not decrypt with any available key")
    
    def should_rotate(self):
        """Check if key rotation is due"""
        last_rotation = load_last_rotation_date()
        return datetime.now() - last_rotation > timedelta(days=90)
```

## Security Checklist

### Cryptographic Implementation

- [ ] Using bcrypt, Argon2, or scrypt for password hashing
- [ ] Password hashing includes unique salt per user
- [ ] Encryption uses AES-256-GCM or ChaCha20-Poly1305
- [ ] No use of ECB mode for block ciphers
- [ ] Random number generation uses `secrets` module
- [ ] No hard-coded cryptographic keys in code
- [ ] Keys loaded from secure configuration or key vault

### Data Protection

- [ ] Sensitive data encrypted at rest
- [ ] All data transmitted over HTTPS/TLS
- [ ] TLS 1.2 or higher enforced
- [ ] Weak cipher suites disabled
- [ ] HSTS header implemented
- [ ] No mixed HTTP/HTTPS content
- [ ] Database connection encrypted

### Password Security

- [ ] Passwords never stored in plaintext
- [ ] Passwords never encrypted (only hashed)
- [ ] Password reset tokens cryptographically random
- [ ] Session tokens use cryptographic randomness
- [ ] API keys generated with sufficient entropy

### Key Management

- [ ] No keys in version control
- [ ] Keys stored in environment variables or key vault
- [ ] Different keys for different environments
- [ ] Key rotation policy in place
- [ ] Old keys retained for decryption of legacy data

## What's Next?

- **[Overview](./overview.md)**: Understand what cryptographic failures are
- **[Attack Vectors](./attack-vectors.md)**: Learn how attacks happen
- **[Examples](./examples.md)**: See vulnerable vs secure code
- **[Lab](./lab/weak-hashing-lab/)**: Practice fixing vulnerabilities

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
