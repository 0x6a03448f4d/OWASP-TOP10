# Insecure Deserialization - Examples

**❌ VULNERABLE:**

```python
import pickle

@app.route('/session', methods=['POST'])
def load_session():
    session_data = request.cookies.get('session')
    # DANGEROUS: Deserializing untrusted data
    user = pickle.loads(b64decode(session_data))
    return f"Welcome {user.name}"
```

**✅ SECURE:**

```python
import json
from itsdangerous import URLSafeSerializer

serializer = URLSafeSerializer('secret-key')

@app.route('/session', methods=['POST'])
def load_session():
    session_data = request.cookies.get('session')
    # SECURE: Signed serialization
    try:
        user_data = serializer.loads(session_data)
        return f"Welcome {user_data['name']}"
    except:
        return "Invalid session", 401
```
