# API10: Unsafe Consumption of APIs - Prevention

## Validate Third-Party Data

```python
import re

def safe_consume_api():
    data = requests.get('https://third-party.com/data').json()
    
    # Validate structure
    if not isinstance(data, dict) or 'name' not in data:
        raise ValueError("Invalid data structure")
    
    # Validate content
    if not re.match(r'^[a-zA-Z ]+$', data['name']):
        raise ValueError("Invalid name format")
    
    # Safe to use
    return data
```

## Sanitize Before Database

```python
# SECURE: Parameterized query
users = requests.get('https://api.com/users').json()
for user in users:
    cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)",
                   (user['name'], user['email']))
```

## Sanitize Before Rendering

```python
from markupsafe import escape

weather = requests.get('https://weather.com/api').json()
# Escape before rendering
return f"<div>{escape(weather['description'])}</div>"
```

## Verify API Responses

```python
import hmac
import hashlib

def verify_webhook(payload, signature):
    expected = hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("Invalid signature")
```

## Use Safe Parsers

```python
# XML: Disable external entities
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True
)
doc = etree.fromstring(xml_data, parser)
```

## Key Takeaways

1. **Validate**: Check structure and content
2. **Sanitize**: Treat as untrusted input
3. **Parameterize**: Never concatenate into queries
4. **Verify**: Use signatures/certificates
5. **Safe parsers**: Disable dangerous features
