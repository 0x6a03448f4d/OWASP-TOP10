# C5: Secure By Default Configurations - Configuration Examples

Each pair below shows an **insecure default** configuration and the **secure default** that replaces it, in the same technology. The goal is a system that is safe out of the box, so a default deployment needs no extra hardening.

## 1. Web Server (nginx)

### Insecure
```nginx
server {
    listen 80;                          # plaintext, no redirect to HTTPS
    server_tokens on;                   # advertises nginx version
    autoindex on;                       # browsable directory listings

    location / {
        root /var/www/html;             # serves .git, .env, backups too
    }
    # all HTTP methods accepted; no security headers
}
```

### Secure
```nginx
server { listen 80; return 301 https://$host$request_uri; }   # force HTTPS

server {
    listen 443 ssl;
    server_tokens off;                  # no version banner
    ssl_protocols TLSv1.2 TLSv1.3;      # modern TLS only
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;

    location / {
        root /var/www/html;
        autoindex off;                  # no directory listing
        limit_except GET POST { deny all; }        # deny-by-default methods
    }
    location ~ /\.(git|env|htaccess) { deny all; return 404; }
    location ~* \.(sql|bak|old|zip)$ { deny all; return 404; }
}
```

## 2. Application Framework (Django)

### Insecure
```python
# settings.py
DEBUG = True                            # tracebacks + debug pages to clients
ALLOWED_HOSTS = ['*']                   # accepts any Host header
SECRET_KEY = 'insecure-default-key'     # shipped default secret

SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0                 # no HSTS
```

### Secure
```python
# settings.py
import os
DEBUG = False                           # off by default in production
ALLOWED_HOSTS = ['app.example.com']     # explicit host allow-list
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']   # injected, never a default

SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
```

## 3. Cloud / IaC (Terraform — AWS S3)

### Insecure
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "app-data"
}
# No public-access block  -> bucket can be made public
# No encryption block     -> objects stored unencrypted
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"                # world-readable
}
```

### Secure
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "app-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true        # private by default
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}
```

## 4. Container (Dockerfile)

### Insecure
```dockerfile
FROM ubuntu:latest                      # full OS, floating tag, runs as root
COPY . /app
COPY .env /app/.env                     # secret baked into an image layer
WORKDIR /app
RUN apt-get update && apt-get install -y python3 curl netcat build-essential
CMD ["python3", "app.py"]               # process runs as root (uid 0)
```

### Secure
```dockerfile
FROM python:3.12-slim@sha256:<digest>   # minimal, patched, pinned by digest
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt   # only what's needed

COPY . .
# no secrets copied in; injected at runtime via env/secret store

RUN useradd --uid 10001 --no-create-home appuser
USER 10001                              # non-root by default
CMD ["python3", "app.py"]
```

## 5. Security Headers (Express middleware)

### Insecure
```javascript
const express = require('express');
const app = express();

// x-powered-by banner left on; no security headers; verbose errors
app.get('/api/me', (req, res) => res.json(loadUser()));
app.listen(3000);
```

### Secure
```javascript
const express = require('express');
const helmet = require('helmet');
const app = express();

app.disable('x-powered-by');            // drop the banner
app.use(helmet());                      // HSTS, nosniff, frameguard, CSP baseline
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));
app.use(helmet.contentSecurityPolicy({
  directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] }
}));

app.get('/api/me', (req, res, next) => {
  try { res.json(loadUser()); } catch (e) { next(e); }
});
app.use((err, req, res, next) => {      // generic error, detail to logs
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});
app.listen(3000);
```

## 6. Kubernetes Workload (Pod securityContext)

### Insecure
```yaml
apiVersion: v1
kind: Pod
metadata: { name: app }
spec:
  containers:
    - name: app
      image: app:latest
      # runs as root, writable root FS, all capabilities, privilege escalation on
```

### Secure
```yaml
apiVersion: v1
kind: Pod
metadata: { name: app }
spec:
  containers:
    - name: app
      image: app@sha256:<digest>
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }   # deny-by-default capabilities
```

## What Changed, and Why

| Layer | Insecure default | Secure default |
|-------|------------------|----------------|
| Web server | Banner on, listing on, all methods, plaintext | Banner off, listing off, scoped methods, HTTPS + headers |
| Framework | Debug on, wildcard hosts, shipped secret | Debug off, host allow-list, injected secret, secure cookies |
| Cloud / IaC | Public-capable, unencrypted bucket | Public access blocked, encryption on |
| Container | Root, full OS, secrets baked in | Non-root, minimal image, runtime secrets |
| Headers | None; banner exposed | HSTS, nosniff, CSP preset; banner removed |
| Kubernetes | Root, all capabilities, writable FS | Non-root, capabilities dropped, read-only FS |

## Next Steps

- **[How to Implement](prevention.md)**: The full secure-by-default strategy and baseline
- **[Threats Addressed](attack-vectors.md)**: How these insecure defaults are exploited
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Fix insecure defaults hands-on
