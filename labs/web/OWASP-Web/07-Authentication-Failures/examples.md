# Authentication Examples (2025)

**❌ VULNERABLE:**

```python
# Weak API key storage
api_keys = {
    'user1': 'simple_key_123'
}

@app.route('/api/data')
def api_endpoint():
    key = request.headers.get('X-API-Key')
    if key in api_keys.values():
        return jsonify(data)
```

**✅ SECURE:**

```python
import secrets
import hashlib

# Secure API key generation and validation
class APIAuth:
    def __init__(self):
        self.keys = {}  # Stores hashes, not plain text
    
    def create_key(self, user_id):
        key = f"sk_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        self.keys[key_hash] = {
            'user_id': user_id,
            'created': datetime.now(),
            'scopes': ['read']
        }
        return key  # Show only once
    
    def validate(self, key):
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return key_hash in self.keys

@app.route('/api/data')
def api_endpoint():
    key = request.headers.get('X-API-Key')
    if not api_auth.validate(key):
        return jsonify({'error': 'Invalid API key'}), 401
    return jsonify(data)
```
