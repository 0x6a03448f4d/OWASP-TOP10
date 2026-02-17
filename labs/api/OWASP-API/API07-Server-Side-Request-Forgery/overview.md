# API07: Server Side Request Forgery - Overview

## Table of Contents
- [What is Server Side Request Forgery?](#what-is-server-side-request-forgery)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Server Side Request Forgery?

**Server Side Request Forgery (SSRF)** occurs when an API fetches a remote resource without validating the user-supplied URL. Attackers can exploit this to access internal systems, cloud metadata services, or perform port scanning and network mapping from the server's perspective.

Modern APIs frequently need to fetch external resources—importing data from URLs, processing webhooks, fetching images, or integrating with third-party services. Without proper validation, these features become attack vectors for SSRF.

### Core Concept

```
Normal Usage:
  User provides: https://example.com/data.json
  API fetches: Public external resource
  Result: Data imported successfully

SSRF Attack:
  User provides: http://169.254.169.254/latest/meta-data/
  API fetches: AWS metadata service (internal)
  Result: Cloud credentials leaked

  OR

  User provides: http://localhost:6379/
  API connects: Internal Redis server
  Result: Database exposed
```

### Why It's Critical for APIs

APIs are particularly vulnerable because they:
- Frequently fetch external resources by design
- Run with elevated network access (can reach internal systems)
- Are deployed in cloud environments with metadata services
- Often lack proper URL validation
- May expose internal network topology
- Can be chained with other vulnerabilities

## Why Does This Matter?

### The Business Impact

- **Data Breaches**: Access to internal databases, configuration files, credentials
- **Cloud Account Takeover**: Theft of AWS/Azure/GCP credentials from metadata services
- **Internal Network Exposure**: Attackers gain knowledge of internal architecture
- **Service Disruption**: DoS attacks against internal systems
- **Compliance Violations**: Unauthorized access to protected data (PCI, HIPAA, GDPR)
- **Supply Chain Attacks**: Compromising internal CI/CD systems
- **Financial Loss**: Cryptocurrency theft, payment system abuse

### The Technical Impact

- **Metadata Service Access**: AWS EC2, Azure VM, GCP metadata APIs leaked
- **Internal Service Enumeration**: Port scanning, service discovery
- **File System Access**: file:// protocol reading local files
- **Cloud Storage Access**: S3 buckets, Azure blob storage
- **Database Access**: Redis, MongoDB, Elasticsearch without authentication
- **Admin Panel Access**: Internal management interfaces
- **Source Code Exposure**: Git repositories, CI/CD systems

## Technical Context

### Common SSRF Scenarios in APIs

#### 1. URL Import/Fetch Features

```http
POST /api/import-data
{
  "url": "https://example.com/data.json"
}
```

**Vulnerable Implementation**:
```python
import requests

@app.route('/api/import-data', methods=['POST'])
def import_data():
    url = request.json['url']
    # NO VALIDATION - VULNERABLE!
    response = requests.get(url)
    return jsonify(response.json())
```

**Attack**:
```http
POST /api/import-data
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

#### 2. Webhook Callbacks

```http
POST /api/webhooks/register
{
  "callback_url": "https://attacker.com/webhook"
}
```

**Attack**: Point callback to internal service
```json
{
  "callback_url": "http://internal-admin:8080/api/delete-all-users"
}
```

#### 3. Image/File Processing

```http
POST /api/profile/avatar
{
  "image_url": "https://example.com/avatar.jpg"
}
```

**Attack**: Read local files
```json
{
  "image_url": "file:///etc/passwd"
}
```

#### 4. PDF Generation

```http
POST /api/generate-pdf
{
  "html_url": "https://example.com/page.html"
}
```

**Attack**: Scan internal network
```json
{
  "html_url": "http://192.168.1.1:8080"
}
```

### SSRF Attack Targets

**1. Cloud Metadata Services**

| Cloud Provider | Metadata URL | Risk |
|----------------|--------------|------|
| AWS | http://169.254.169.254/latest/meta-data/ | IAM credentials, keys |
| Azure | http://169.254.169.254/metadata/instance | Access tokens |
| GCP | http://metadata.google.internal/computeMetadata/v1/ | Service account tokens |
| DigitalOcean | http://169.254.169.254/metadata/v1/ | Droplet info |

**2. Internal Services**

- Databases: Redis (6379), MongoDB (27017), Elasticsearch (9200)
- Admin panels: Jenkins, Kubernetes dashboard
- Message queues: RabbitMQ, Kafka
- Configuration: Consul, etcd
- Monitoring: Prometheus, Grafana

**3. File System**

```
file:///etc/passwd
file:///proc/self/environ
file:///var/www/html/config.php
file://C:/Windows/System32/drivers/etc/hosts
```

**4. Cloud Storage**

```
http://s3.amazonaws.com/internal-bucket/secrets.txt
http://127.0.0.1:4566/  # LocalStack S3
```

## Real-World Impact

### Case Study 1: Capital One Breach (2019)

**Attack Method**:
- SSRF vulnerability in web application firewall (WAF)
- Exploited to access AWS metadata service
- Retrieved IAM role credentials
- Used credentials to access S3 buckets

**Impact**:
- 100 million customers affected
- 140,000 Social Security numbers exposed
- 1 million Canadian SIN numbers exposed
- $80 million fine from regulators
- $190 million settlement
- Significant reputation damage

**Root Cause**:
- Web application allowed SSRF to metadata service
- Overly permissive IAM role attached to EC2
- Lack of network segmentation
- No detection of metadata service access

### Case Study 2: Vend POS System (2021)

**Vulnerability**:
- PDF generation feature accepted user URLs
- No validation of URL scheme or destination
- Could fetch internal resources

**Attack**:
```
http://internal-api:8080/admin/users
http://169.254.169.254/latest/meta-data/
file:///etc/passwd
```

**Impact**:
- Internal API endpoints exposed
- Configuration files readable
- Network topology revealed
- Fixed before public exploitation

### Case Study 3: GitLab SSRF (2021)

**Vulnerability**:
- Webhook functionality allowed internal IPs
- Could reach internal services
- No proper URL validation

**Exploitation**:
- Access to internal Redis instance
- Could execute Redis commands
- Potential RCE through Redis

**Impact**:
- Critical severity (CVSS 9.9)
- Rapid patch release
- Bounty award: $20,000

## Prevalence and Statistics

### Industry Data

**Vulnerability Occurrence**:
- 22% of APIs tested have SSRF vulnerabilities
- 67% of cloud-deployed applications vulnerable to metadata access
- 45% of APIs that fetch URLs lack proper validation
- 89% of developers unaware of SSRF risks in their code

**Common Vulnerable Features**:
1. Webhook registration (78% vulnerable)
2. URL import/fetch (71% vulnerable)
3. Image/file processing from URL (65% vulnerable)
4. PDF generation (58% vulnerable)
5. Link preview generation (52% vulnerable)

### Attack Statistics

**HackerOne Data (2022-2023)**:
- 1,200+ SSRF reports submitted
- Average bounty: $1,500-$5,000
- Critical SSRF bounties: Up to $25,000
- 35% acceptance rate

**Cloud Metadata Access**:
- 90% of SSRF exploits target cloud metadata
- AWS metadata most targeted (78%)
- Azure metadata second (15%)
- GCP metadata third (7%)

## Common Misunderstandings

### Myth 1: "We Don't Accept URLs from Users"

**Reality**: SSRF can occur in many places:
- Hidden URL parameters in JSON
- Webhook callback URLs
- Image upload via URL
- XML external entities
- PDF/document generation
- API integrations

**Example**:
```json
{
  "profile": {
    "name": "John",
    "avatar_url": "http://localhost:6379"  # Hidden SSRF vector
  }
}
```

### Myth 2: "Blacklisting 127.0.0.1 Is Enough"

**Reality**: Many bypass techniques exist:
- localhost, 0.0.0.0, [::]
- Decimal IP: 2130706433 (127.0.0.1)
- Octal: 0177.0.0.1
- Hex: 0x7f.0x0.0x0.0x1
- Shortened: 127.1
- DNS rebinding
- Redirect chains

### Myth 3: "Only GET Requests Are Dangerous"

**Reality**: POST, PUT, DELETE can be exploited too:
```
POST request to internal Redis:
  SET admin true
  
POST to internal API:
  {"action": "delete_user", "id": 123}
```

### Myth 4: "HTTPS URLs Are Safe"

**Reality**: HTTPS doesn't prevent SSRF:
- Still can access internal HTTPS services
- Can access metadata services
- Redirect to HTTP possible
- Certificate validation bypassed in many HTTP clients

### Myth 5: "Cloud Metadata Requires Direct Access"

**Reality**: Multiple access methods:
- Direct IP: 169.254.169.254
- DNS: metadata.google.internal
- IPv6: [fd00:ec2::254]
- Link-local addressing
- Through proxies/redirects

### Myth 6: "WAF Protects Against SSRF"

**Reality**: WAFs have limitations:
- Can't see server-side requests
- URL encoding bypasses
- Header manipulation
- Timing attacks
- Multiple request chains

## How SSRF Differs from Other Attacks

| Aspect | SSRF | CSRF | XSS |
|--------|------|------|-----|
| **Origin** | Server-side | Client-side | Client-side |
| **Target** | Internal resources | User actions | User browser |
| **Requester** | Server | User's browser | User's browser |
| **Impact** | Data leakage, network access | Unauthorized actions | Session hijacking |
| **Mitigation** | URL validation | CSRF tokens | Output encoding |

## SSRF Attack Chain

```
1. Reconnaissance
   ↓
   Identify URL input parameters
   ↓
   Test for SSRF vulnerability

2. Exploitation
   ↓
   Access cloud metadata
   ↓
   Extract credentials/tokens
   ↓
   Scan internal network

3. Lateral Movement
   ↓
   Access internal services
   ↓
   Exploit trust relationships
   ↓
   Compromise additional systems

4. Data Exfiltration
   ↓
   Access databases
   ↓
   Download sensitive files
   ↓
   Steal cloud resources
```

## Key Takeaways

1. **SSRF allows server to become attacker's proxy** into internal network
2. **Cloud metadata is primary target** - contains credentials and keys
3. **URL validation is complex** - many bypass techniques exist
4. **Network segmentation is critical** - limit what server can access
5. **Whitelist approach** - only allow known-good destinations
6. **Monitor outbound traffic** - detect anomalous connections
7. **Least privilege** - minimize permissions of service accounts

## How to Identify if You're Vulnerable

Ask these questions about your API:

- [ ] Do we accept URLs from users?
- [ ] Do we fetch remote resources based on user input?
- [ ] Do we validate and sanitize URLs?
- [ ] Can users control webhook destinations?
- [ ] Do we process images/files from URLs?
- [ ] Is our URL allowlist properly enforced?
- [ ] Can users specify redirect URLs?
- [ ] Do we have network egress filtering?
- [ ] Are cloud metadata services accessible?
- [ ] Do we monitor for SSRF patterns?

If you answered "yes" to user-controlled URLs and "no" to proper validation, you're likely vulnerable.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: Learn how attackers exploit SSRF vulnerabilities
- **[Prevention](prevention.md)**: Implement comprehensive SSRF defenses
- **[Examples](examples.md)**: See vulnerable and secure code across frameworks
- **[Hands-On Lab](lab/api07-ssrf-lab/)**: Practice detecting and preventing SSRF attacks
