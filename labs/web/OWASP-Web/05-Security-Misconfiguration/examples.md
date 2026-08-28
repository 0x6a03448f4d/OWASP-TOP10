# A5:2021 - Security Misconfiguration: Examples

Each example shows a **❌ vulnerable** configuration and the **✅ secure** version beside it. The changes are small—which is exactly why misconfiguration is so common and so preventable.

## Table of Contents

- [1. Apache: Directory Listing & Banners](#1-apache-directory-listing--banners)
- [2. Nginx: Security Headers & Hidden Files](#2-nginx-security-headers--hidden-files)
- [3. PHP: Error Display and phpinfo](#3-php-error-display-and-phpinfo)
- [4. Python / Flask: Debug Mode](#4-python--flask-debug-mode)
- [5. Python / Django: Production Settings](#5-python--django-production-settings)
- [6. Node / Express: Errors, Headers, CORS](#6-node--express-errors-headers-cors)
- [7. Java / Spring Boot: Actuator & Errors](#7-java--spring-boot-actuator--errors)
- [8. XXE: Parser Configuration (4 languages)](#8-xxe-parser-configuration-4-languages)
- [9. Session Cookie Flags](#9-session-cookie-flags)
- [10. Cloud Storage Bucket Policy](#10-cloud-storage-bucket-policy)
- [Reference: Recommended Security Headers](#reference-recommended-security-headers)

## 1. Apache: Directory Listing & Banners

#### ❌ Vulnerable

```apache
# httpd.conf / apache2.conf
<Directory /var/www/html>
    Options Indexes FollowSymLinks     # Indexes = browsable directory listings
    AllowOverride All
</Directory>
ServerTokens Full                       # "Apache/2.4.29 (Ubuntu) PHP/7.2.10"
ServerSignature On                      # version footer on error pages
TraceEnable On                          # TRACE method available
```

#### ✅ Secure

```apache
<Directory /var/www/html>
    Options -Indexes +FollowSymLinks    # no directory listing
    AllowOverride None
    Require all granted
</Directory>
ServerTokens Prod                        # "Server: Apache" only
ServerSignature Off
TraceEnable Off

# Block sensitive files and VCS metadata
<DirectoryMatch "\.(git|svn)">
    Require all denied
</DirectoryMatch>
<FilesMatch "(^\.env|\.bak$|\.sql$|~$)">
    Require all denied
</FilesMatch>
```

## 2. Nginx: Security Headers & Hidden Files

#### ❌ Vulnerable

```nginx
server {
    listen 80;
    root /var/www/html;
    autoindex on;                        # directory listing exposed
    # no security headers, version banner exposed, dotfiles served
}
```

#### ✅ Secure

```nginx
server {
    listen 443 ssl http2;
    root /var/www/html;
    autoindex off;
    server_tokens off;                   # hide version

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location ~ /\.(?!well-known) { deny all; }      # block .git, .env, dotfiles
    location ~ \.(bak|sql|old|swp)$ { deny all; }
}
```

## 3. PHP: Error Display and phpinfo

#### ❌ Vulnerable

```ini
; php.ini (development values shipped to production)
display_errors = On                      ; stack traces to the browser
display_startup_errors = On
expose_php = On                          ; "X-Powered-By: PHP/7.2.10"
```
```php
// info.php left in web root
<?php phpinfo(); ?>                       // full environment disclosure
```

#### ✅ Secure

```ini
; php.ini (production)
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php/error.log
expose_php = Off

; Restrict what PHP can read/execute
open_basedir = /var/www/html:/tmp
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
; And: delete info.php / any phpinfo() page from the web root
```

## 4. Python / Flask: Debug Mode

#### ❌ Vulnerable

```python
from flask import Flask
app = Flask(__name__)

if __name__ == "__main__":
    # debug=True in production -> interactive Werkzeug console = RCE
    app.run(host="0.0.0.0", port=5000, debug=True)
```

#### ✅ Secure

```python
import os
from flask import Flask, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["APP_SECRET_KEY"]   # required from env
app.config["DEBUG"] = False

@app.errorhandler(500)
def server_error(e):
    app.logger.exception(e)                                # detail to logs only
    return jsonify(error="Internal Server Error"), 500     # generic to client

# Run behind a real WSGI server (gunicorn/uwsgi), never the dev server:
#   gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

## 5. Python / Django: Production Settings

#### ❌ Vulnerable

```python
DEBUG = True
ALLOWED_HOSTS = ["*"]
SECRET_KEY = "django-insecure-hardcoded-key"
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
```

#### ✅ Secure

```python
import os
DEBUG = False
ALLOWED_HOSTS = ["app.example.com"]
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# Transport / cookie hardening
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 63072000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
# Verify with: python manage.py check --deploy
```

## 6. Node / Express: Errors, Headers, CORS

#### ❌ Vulnerable

```javascript
const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors());                          // reflects any origin
// no security headers
// default error handler leaks stack traces when NODE_ENV != production
app.get("/account", (req, res) => res.json(getAccount(req)));
```

#### ✅ Secure

```javascript
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const app = express();

app.disable("x-powered-by");
app.use(helmet());                        // full security-header set

const ALLOWED = new Set(["https://app.example.com"]);
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || ALLOWED.has(origin)),
  credentials: true,
}));

app.get("/account", (req, res) => res.json(getAccount(req)));

// Generic error handler last
app.use((err, req, res, next) => {
  console.error(err);                     // detail to logs
  res.status(500).json({ error: "Internal Server Error" });
});
// Set NODE_ENV=production so the framework suppresses stack traces
```

## 7. Java / Spring Boot: Actuator & Errors

#### ❌ Vulnerable

```properties
# application.properties
management.endpoints.web.exposure.include=*     # exposes /actuator/env, /heapdump...
server.error.include-stacktrace=always          # stack traces in responses
server.error.include-message=always
spring.h2.console.enabled=true                   # dev DB console reachable
```

#### ✅ Secure

```properties
# application.properties
management.endpoints.web.exposure.include=health,info   # minimal, safe set
management.endpoint.health.show-details=never
management.server.port=9001                              # separate, internal-only port
server.error.include-stacktrace=never
server.error.include-message=never
spring.h2.console.enabled=false

# Secure the management endpoints that remain (Spring Security)
# and bind the management port to a private interface only.
```

## 8. XXE: Parser Configuration (4 languages)

XXE is prevented in configuration, not in the request handler. Disable DTDs and external entities in every parser that touches untrusted XML (including SVG, DOCX, and SAML).

#### ❌ Vulnerable (defaults resolve entities)

```
# Python
from lxml import etree
doc = etree.fromstring(user_xml)                 # resolves external entities

// Java
DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
Document doc = db.parse(input);                  // DOCTYPE + entities honoured

// PHP (libxml < 2.9)
$dom = new DOMDocument();
$dom->loadXML($userXml);                          // may load external entities

// Node (libxmljs)
const doc = libxml.parseXml(userXml, { noent: true, dtdload: true });  // dangerous
```

#### ✅ Secure (DTDs / external entities disabled)

```
# Python -- prefer defusedxml
from defusedxml.ElementTree import fromstring
doc = fromstring(user_xml)                        # blocks XXE by design

// Java -- disallow DOCTYPE outright
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setXIncludeAware(false);
Document doc = dbf.newDocumentBuilder().parse(input);

// PHP -- disable the external entity loader
libxml_set_external_entity_loader(null);
$dom = new DOMDocument();
$dom->loadXML($userXml, LIBXML_NONET);

// Node -- do not enable entity/DTD loading
const doc = libxml.parseXml(userXml, { noent: false, dtdload: false, nonet: true });
```

## 9. Session Cookie Flags

#### ❌ Vulnerable

```
Set-Cookie: session=abc123
# no Secure, no HttpOnly, no SameSite
# -> sniffable over HTTP, stealable via XSS, sent cross-site (CSRF)
```

#### ✅ Secure

```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax; Path=/
```
```javascript
// Express example
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: "lax", maxAge: 3600000 },
}));
```

## 10. Cloud Storage Bucket Policy

#### ❌ Vulnerable

```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::app-backups/*"
}
// Public read on a bucket holding backups -> anyone can download everything
```

#### ✅ Secure

```bash
# Block all public access at the account/bucket level
$ aws s3api put-public-access-block --bucket app-backups \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Grant access only to a specific, least-privilege role, and serve
# user downloads through short-lived pre-signed URLs instead of public objects.
```

## Reference: Recommended Security Headers

| Header | Recommended Value | Protects Against |
|--------|-------------------|------------------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Downgrade / SSL-strip |
| `Content-Security-Policy` | `default-src 'self'; object-src 'none'; frame-ancestors 'none'` | XSS, injection, framing |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referrer leakage |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=()` | Feature abuse |
| `Cache-Control` (sensitive pages) | `no-store` | Caching private data |

> Verify quickly from the command line:
> `curl -sI https://app.example.com | grep -Ei 'strict-transport|content-security|x-content-type|x-frame|referrer-policy'`

## Key Takeaways

1. **The secure version is almost always a small config change**—flip debug off, add the header, deny the dotfile.
2. **Set controls centrally** (proxy or middleware) so every response is covered, including errors.
3. **Drive settings from the environment**—no hard-coded secrets, no dev values in production.
4. **XXE is fixed in the parser config**, uniformly across every language and every XML-backed format.
5. **Default cloud storage to private** and serve data through scoped, short-lived access.

## Next Steps

- **[Overview](./overview.md)**: Understand the category and its impact
- **[Attack Vectors](./attack-vectors.md)**: How these misconfigurations are exploited
- **[Prevention](./prevention.md)**: Build a repeatable hardened baseline
- **[Hands-On Lab](./lab/debug-mode-lab/)**: Exploit and fix a debug-mode misconfiguration

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
