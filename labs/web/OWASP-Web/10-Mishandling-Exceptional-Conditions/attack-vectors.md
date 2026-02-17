# Exception Handling Attacks

## Information Disclosure

```python
# Vulnerable: Exposes internal details
try:
    user = db.query(f"SELECT * FROM users WHERE id={user_id}")
except Exception as e:
    return str(e)  # Exposes: "Table 'users' doesn't exist in database 'prod_db'"
```

## DoS via Exception Triggering

```python
# Attacker triggers expensive exceptions repeatedly
# No rate limiting on exception-heavy code path
# Server resources exhausted
```

## Authentication Bypass

```python
# Vulnerable exception handling
try:
    authenticate_user(username, password)
    session['authenticated'] = True
except Exception:
    pass  # Silently fails, user not authenticated
    # But code continues...
    
# If check is missing, unauthenticated user proceeds
```
