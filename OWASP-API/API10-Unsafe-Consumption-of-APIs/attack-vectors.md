# API10: Unsafe Consumption of APIs - Attack Vectors

## Third-Party Data Injection

### XSS via Weather API

```python
# Vulnerable
weather = requests.get('https://weather-api.com/current').json()
return f"<div>{weather['description']}</div>"  # XSS!

# If weather API compromised:
{"description": "<script>steal_cookies()</script>"}
```

## SQL Injection via External API

```python
# Vulnerable
users = requests.get('https://crm-api.com/users').json()
for user in users:
    db.execute(f"INSERT INTO users VALUES ('{user['name']}')")  # SQLi!

# If CRM API returns:
{"name": "'; DROP TABLE users; --"}
```

## Payment Response Manipulation

```python
# Vulnerable
payment = requests.post('https://payment-api.com/charge', json=order)
if payment.json()['status'] == 'success':  # Trusts response!
    grant_premium_access()

# Attacker intercepts, changes response to:
{"status": "success"}  # Without actually paying
```

## XML Injection from Third-Party

```python
# Vulnerable
xml_data = requests.get('https://partner-api.com/export').text
doc = etree.fromstring(xml_data)  # XXE possible!

# If partner API returns:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

## Deserialization Attack

```python
# Vulnerable
import pickle
data = requests.get('https://data-api.com/export').content
obj = pickle.loads(data)  # Arbitrary code execution!
```

## Key Takeaways

1. **Validate everything**: Never trust third-party data
2. **Sanitize**: Treat as user input
3. **Parameterize**: Use prepared statements
4. **Encode**: Escape before rendering
5. **Verify**: Check signatures/certificates
