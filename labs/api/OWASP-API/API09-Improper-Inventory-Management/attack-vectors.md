# API09: Improper Inventory Management - Attack Vectors

## Old API Version Exploitation

```
# Discover versions
GET /api/v1/users  
GET /api/v2/users
GET /api/v3/users

# v1 has no authentication, v3 requires OAuth
# Attacker uses v1 to bypass security
```

## Undocumented Endpoint Discovery

### Fuzzing
```python
import requests

endpoints = ['admin', 'internal', 'test', 'debug', 'dev', '_internal', 'backup']

for endpoint in endpoints:
    r = requests.get(f'https://api.target.com/{endpoint}')
    if r.status_code == 200:
        print(f"Found: /{endpoint}")
```

### Common Undocumented Endpoints
```
/admin
/internal
/_debug
/test
/staging
/dev
/backup
/metrics
/health
```

## Debug Endpoint Abuse

```
GET /_debug  → Full config dump
GET /metrics → Internal metrics
GET /_internal/users → Admin access
```

## Multiple Version Exploitation

```
v1: No rate limiting
v2: Rate limited
v3: Rate limited + OAuth

Attacker: Uses v1 to bypass rate limits
```

## Shadow API Discovery

```
# Web API: https://api.company.com
# Mobile API: https://m.company.com (less secure)
# Partner API: https://partners.company.com (different auth)
```

## Key Takeaways

1. **Version control**: Sunset old versions
2. **Endpoint inventory**: Know all endpoints
3. **Remove debug**: No debug in production
4. **Unified security**: Same controls on all APIs
5. **Regular scans**: Find undocumented endpoints
