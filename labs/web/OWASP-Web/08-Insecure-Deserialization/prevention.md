# Insecure Deserialization - Prevention

## Safe Alternatives

```python
import json

# SECURE: Use JSON instead of pickle
data = {'user': 'alice', 'role': 'admin'}
serialized = json.dumps(data)
deserialized = json.loads(serialized)
```

## Integrity Checks

```python
import hmac
import hashlib
import json
from base64 import b64encode, b64decode

SECRET_KEY = 'your-secret-key'

def sign_data(data):
    json_data = json.dumps(data)
    signature = hmac.new(
        SECRET_KEY.encode(),
        json_data.encode(),
        hashlib.sha256
    ).hexdigest()
    return b64encode(json_data.encode()).decode() + '.' + signature

def verify_data(signed_data):
    try:
        encoded_data, signature = signed_data.split('.')
        json_data = b64decode(encoded_data).decode()
        
        expected_sig = hmac.new(
            SECRET_KEY.encode(),
            json_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if hmac.compare_digest(signature, expected_sig):
            return json.loads(json_data)
    except:
        pass
    return None
```

## Best Practices

- Avoid deserializing untrusted data
- Use JSON instead of binary serialization
- Implement digital signatures
- Use type constraints
- Monitor deserialization activity
- Run deserialization in sandboxed environments
