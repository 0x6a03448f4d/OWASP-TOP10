# A3:2017 – Sensitive Data Exposure: Code Examples

Each pair below shows a **vulnerable** implementation and the **secure** version of the same thing. The examples cover the controls that matter most for A3: TLS/HTTPS configuration, data-at-rest encryption, password hashing, secure response headers/caching, keeping secrets out of URLs, and log redaction — across Python, Node.js, Java, and server config.

## Table of Contents

- [1. TLS / HTTPS Configuration (Nginx)](#1-tls--https-configuration-nginx)
- [2. Data-at-Rest Encryption (Python)](#2-data-at-rest-encryption-python)
- [3. Password Hashing (Node.js)](#3-password-hashing-nodejs)
- [4. Password Hashing (Java)](#4-password-hashing-java)
- [5. Secure Headers & Caching (Node.js)](#5-secure-headers--caching-nodejs)
- [6. Keeping Secrets Out of URLs](#6-keeping-secrets-out-of-urls)
- [7. Log Redaction (Python)](#7-log-redaction-python)
- [8. TLS Database Connection (Java / Spring)](#8-tls-database-connection-java--spring)
- [Summary Table](#summary-table)
- [Next Steps](#next-steps)

## 1. TLS / HTTPS Configuration (Nginx)

### Vulnerable

```nginx
# Serves the app over plain HTTP - every request is interceptable
server {
    listen 80;
    server_name app.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;   # credentials and cookies in cleartext
    }
}

# If HTTPS exists at all, it also allows obsolete protocols:
#   ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;   # downgradable
#   (no HSTS header, so browsers keep trying HTTP first)
```

### Secure

```nginx
# All HTTP redirected to HTTPS; modern TLS only; HSTS forces future HTTPS
server {
    listen 80;
    server_name app.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate     /etc/ssl/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/app.example.com/privkey.pem;

    ssl_protocols       TLSv1.2 TLSv1.3;          # no SSLv3 / TLS 1.0 / 1.1
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
    }
}
```

## 2. Data-at-Rest Encryption (Python)

### Vulnerable

```python
# Storing sensitive data in plaintext (or "hidden" with Base64 - not encryption)
import base64

def save_ssn(db, user_id, ssn):
    db.execute("UPDATE users SET ssn = %s WHERE id = %s", (ssn, user_id))   # plaintext

def hide_ssn(ssn):
    return base64.b64encode(ssn.encode())   # trivially reversible - NOT protection
```

### Secure

```python
# Encrypt with a key supplied at runtime from a KMS / secret manager
import os
from cryptography.fernet import Fernet

# Never hard-code the key and never store it in the same DB as the data.
cipher = Fernet(os.environ["FIELD_ENCRYPTION_KEY"])

def save_ssn(db, user_id, ssn):
    ciphertext = cipher.encrypt(ssn.encode())   # authenticated encryption
    db.execute("UPDATE users SET ssn_enc = %s WHERE id = %s", (ciphertext, user_id))

def read_ssn(db, user_id):
    row = db.query("SELECT ssn_enc FROM users WHERE id = %s", (user_id,))
    return cipher.decrypt(row["ssn_enc"]).decode()
# A dump of the users table now yields ciphertext an attacker cannot read.
```

## 3. Password Hashing (Node.js)

### Vulnerable

```javascript
const crypto = require('crypto');

// Fast, unsalted hash - cracked almost instantly if the table leaks
function hashPassword(pw) {
    return crypto.createHash('sha1').update(pw).digest('hex');
}

// Storing the password itself would be even worse, but SHA-1 is still broken here.
```

### Secure

```javascript
const bcrypt = require('bcrypt');
const COST = 12;   // work factor - tune so one hash takes a noticeable fraction of a second

async function hashPassword(pw) {
    return bcrypt.hash(pw, COST);   // salt generated and stored inside the hash string
}

async function verifyPassword(pw, stored) {
    return bcrypt.compare(pw, stored);   // constant-time comparison; no "decrypt"
}
// A leaked bcrypt table resists offline cracking by design.
```

## 4. Password Hashing (Java)

### Vulnerable

```java
import java.security.MessageDigest;

// MD5 with no salt - a rainbow table reverses common passwords immediately
String hash(String pw) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] digest = md.digest(pw.getBytes("UTF-8"));
    return java.util.HexFormat.of().formatHex(digest);
}
```

### Secure

```java
// Spring Security - BCryptPasswordEncoder (salted, slow, tunable strength)
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

PasswordEncoder encoder = new BCryptPasswordEncoder(12);   // strength / work factor

String stored = encoder.encode(rawPassword);               // store this
boolean ok    = encoder.matches(rawPassword, stored);      // verify at login
// For memory-hard hashing, Argon2PasswordEncoder is also available in Spring Security.
```

## 5. Secure Headers & Caching (Node.js)

### Vulnerable

```javascript
const express = require('express');
const app = express();

// Sensitive account data returned with no cache controls and no security headers
app.get('/account', (req, res) => {
    res.json(getAccount(req.user));   // may be stored in browser/proxy cache
});
app.listen(3000);   // also served over http:// with no HSTS
```

### Secure

```javascript
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet());                       // HSTS, nosniff, frameguard, referrer-policy, CSP baseline
app.disable('x-powered-by');

app.get('/account', (req, res) => {
    res.set('Cache-Control', 'no-store'); // never cache sensitive responses
    res.set('Referrer-Policy', 'no-referrer');
    res.json(getAccount(req.user));
});
// Terminate TLS in front (or use https) so HSTS from helmet is meaningful.
```

## 6. Keeping Secrets Out of URLs

### Vulnerable

```
# Reset token in the query string -> leaks to logs, history, and Referer
GET /reset-password?token=8f3c1a9e-secret HTTP/1.1

# Server-side (Flask): reads the secret straight from the URL
@app.route('/reset-password')
def reset():
    token = request.args.get('token')   # now recorded in every access log
    ...
```

### Secure

```
# Deliver the token via a POST body (or short-lived, single-use, then discarded)
POST /reset-password HTTP/1.1
Content-Type: application/json

{ "token": "8f3c1a9e-secret" }

# Server-side (Flask): read from the body, not the URL
@app.route('/reset-password', methods=['POST'])
def reset():
    token = request.get_json().get('token')   # not in logs, history, or Referer
    ...   # validate, mark used, enforce short expiry
```

## 7. Log Redaction (Python)

### Vulnerable

```python
import logging

def charge(card_number, cvv, amount):
    # Logs the full PAN and CVV - now sitting in plaintext in the log store
    logging.info(f"charging card={card_number} cvv={cvv} amount={amount}")
    ...
```

### Secure

```python
import logging

def charge(card_number, cvv, amount):
    # Log only non-sensitive identifiers; never the PAN or CVV
    logging.info("charging card=**** last4=%s amount=%s", card_number[-4:], amount)
    ...
# Pair this with a redaction filter so stray sensitive values are scrubbed globally
# (see the Prevention page, Layer 5).
```

## 8. TLS Database Connection (Java / Spring)

### Vulnerable

```properties
# application.properties - database traffic in cleartext across the network
spring.datasource.url=jdbc:postgresql://db.internal:5432/app
# no sslmode -> credentials and query results readable by anyone on the path
```

### Secure

```properties
# application.properties - require TLS and verify the server certificate
spring.datasource.url=jdbc:postgresql://db.internal:5432/app?ssl=true&sslmode=verify-full
spring.datasource.hikari.data-source-properties.sslrootcert=/etc/ssl/db-ca.pem
# "internal" is not "safe" - the DB leg is encrypted and authenticated too
```

## Summary Table

| Concern | Vulnerable | Secure |
|---------|------------|--------|
| Transport | HTTP, obsolete TLS, no HSTS | HTTPS, TLS 1.2/1.3, HSTS preload, redirect |
| At rest | Plaintext / Base64 in DB | Authenticated encryption, key in KMS |
| Passwords | MD5 / SHA-1, unsalted | bcrypt / Argon2, salted, tuned cost |
| Caching | No cache headers on sensitive data | `Cache-Control: no-store` |
| URLs | Token in query string | Token in body/header, short-lived |
| Logging | Full PAN/CVV/tokens logged | Redacted; identifiers only |
| Internal legs | Cleartext DB / service calls | TLS/mTLS, verified certificates |

> Cryptographic algorithm and mode choices (AES-GCM vs ECB, IV handling, cipher suites) are treated in depth in the [Cryptographic Failures](../02-Cryptographic-Failures/examples.md) lesson. Here the focus is on *where* data leaks and the configuration-level fixes that close those paths.

## Next Steps

- **[Overview](./overview.md)**: The concepts and data classification behind these fixes
- **[Attack Vectors](./attack-vectors.md)**: What each secure example defends against
- **[Prevention](./prevention.md)**: The full layered defence strategy
- **[Hands-On Lab](./lab/sensitive-data-exposure/)**: Apply these fixes in a safe, isolated environment

---

*Part of the [OWASP Top 10 Educational Repository](/platform/frontend/index.html)*
