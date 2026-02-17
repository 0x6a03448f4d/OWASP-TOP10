# Sensitive Data Exposure - Prevention

## Encryption Best Practices

### 1. Data in Transit

Always use HTTPS/TLS:

```python
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

# Force HTTPS
Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'"
    }
)
```

### 2. Data at Rest

Encrypt sensitive data:

```python
from cryptography.fernet import Fernet
import base64
import os

class SecureStorage:
    def __init__(self):
        # Generate or load encryption key
        key = os.environ.get('ENCRYPTION_KEY') or Fernet.generate_key()
        self.cipher = Fernet(key)
    
    def encrypt_data(self, data):
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data.encode()).decode()

# Usage
storage = SecureStorage()
encrypted = storage.encrypt_data("sensitive info")
```

### 3. Strong Password Hashing

```python
from argon2 import PasswordHasher

ph = PasswordHasher()

# Hash password
hash = ph.hash("user_password")

# Verify password
try:
    ph.verify(hash, "user_password")
    print("Password correct")
except:
    print("Password incorrect")
```

## Security Checklist

- [ ] Use TLS 1.2 or higher
- [ ] Encrypt all sensitive data at rest
- [ ] Use strong encryption algorithms (AES-256)
- [ ] Implement proper key management
- [ ] Disable weak ciphers
- [ ] Use HTTP Strict Transport Security (HSTS)
- [ ] Never log sensitive data
- [ ] Use secure random number generators
