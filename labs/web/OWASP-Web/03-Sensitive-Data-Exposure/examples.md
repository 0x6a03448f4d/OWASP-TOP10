# Sensitive Data Exposure - Examples

## Vulnerable vs Secure

### Example 1: Password Storage

**❌ VULNERABLE:**

```python
# Plain text password storage
users = {
    'alice': 'password123',
    'bob': 'admin456'
}
```

**✅ SECURE:**

```python
from werkzeug.security import generate_password_hash, check_password_hash

users = {
    'alice': generate_password_hash('password123'),
    'bob': generate_password_hash('admin456')
}

# Verify password
if check_password_hash(users['alice'], input_password):
    print("Authenticated")
```

### Example 2: Credit Card Storage

**❌ VULNERABLE:**

```python
# Storing credit card in plain text
user_data = {
    'card_number': '4532-1234-5678-9010',
    'cvv': '123'
}
```

**✅ SECURE:**

```python
from cryptography.fernet import Fernet

# Encrypt sensitive data
key = Fernet.generate_key()
cipher = Fernet(key)

encrypted_card = cipher.encrypt(b'4532-1234-5678-9010')
# Store encrypted_card, never plain text
# Use PCI-compliant tokenization in production
```
