# API08: Security Misconfiguration - Prevention

## Prevention Strategy Overview

Preventing misconfiguration is less about a single control and more about **making a hardened state the only state that ships**:

1. Define a repeatable, hardened baseline for every layer.
2. Enforce it automatically so environments cannot drift.
3. Disable everything you do not use.
4. Handle errors, headers, CORS, and TLS deliberately.
5. Patch continuously and monitor for drift.

### Core Principles

- **Secure by default**: the deployed default must be the safe one; opting *out* of a control should be explicit and rare.
- **Repeatable, not hand-tuned**: codify configuration so it is identical everywhere and reviewable in version control.
- **Least functionality**: every enabled feature, method, port, and account is attack surface—remove what you don't need.
- **Fail closed and quiet**: on error, deny access and return a generic message; log the detail server-side only.

## 1. Repeatable Hardening Baseline

Treat configuration as code. Capture the intended secure state and apply it identically to every environment.

```yaml
# hardening-baseline.yaml (excerpt) — reviewed, versioned, applied by CI/CD
app:
  debug: false
  detailed_errors: false
  cors_allowed_origins: ["https://app.example.com"]
  cors_allow_credentials: true
server:
  server_tokens: false          # no version banner
  allowed_methods: [GET, POST, PUT, DELETE]  # per-route override, no TRACE
  directory_listing: false
tls:
  min_version: "1.2"
  hsts: "max-age=31536000; includeSubDomains; preload"
datastore:
  bind: "127.0.0.1"
  auth_required: true
```

Enforce it with a configuration-management or IaC tool (Ansible, Terraform, Kubernetes manifests) and a CIS-style benchmark check so any drift fails the pipeline.

## 2. Automated Configuration Management and Scanning

Manual review does not scale. Add automated gates:

```bash
# In CI: fail the build on insecure configuration
# 1) Static config / IaC scanning
checkov -d ./infra            # Terraform/K8s misconfig
tfsec ./infra

# 2) Container image hardening + CVE scan
trivy image myapi:latest --severity HIGH,CRITICAL

# 3) Runtime header / TLS verification against a deployed environment
testssl.sh https://staging.api.example.com
nikto -host https://staging.api.example.com
```

Run these on every pull request and on a schedule against running environments, so newly disclosed issues and configuration drift are caught quickly.

## 3. Disable Unused Features, Methods, and Endpoints

The safest component is the one that isn't running.

```nginx
# nginx: restrict methods and hide the version banner
server_tokens off;

location /api/ {
    limit_except GET POST PUT DELETE {
        deny all;                 # blocks TRACE, CONNECT, WebDAV verbs, etc.
    }
    autoindex off;                # no directory listing
}

# Block access to sensitive dotfiles and backups
location ~ /\.(git|env|htaccess)  { deny all; return 404; }
location ~* \.(sql|bak|old|zip)$  { deny all; return 404; }
```

```yaml
# Spring Boot: expose only safe actuator endpoints, secure the rest
management:
  endpoints:
    web:
      exposure:
        include: health,info      # never env, heapdump, beans in prod
  endpoint:
    health:
      show-details: never
```

Remove sample apps, seeded accounts, unused packages from base images, and any schema/UI (`/swagger-ui`) that should not be public.

## 4. Security Headers on Every Response

Set headers centrally (middleware or the edge proxy) so they apply uniformly—including on error and redirect responses.

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
Cache-Control: no-store            # for sensitive API responses
```

```javascript
// Express: helmet applies a sound baseline in one line
const helmet = require('helmet');
app.use(helmet());
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));
// For a JSON API, a strict CSP is appropriate:
app.use(helmet.contentSecurityPolicy({
  directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] }
}));
```

## 5. Lock Down CORS

Never reflect arbitrary origins. Use an explicit allow-list and only enable credentials when genuinely required.

```javascript
// Express: strict, allow-listed CORS
const cors = require('cors');
const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);

app.use(cors({
  origin: (origin, cb) => {
    // No Origin (same-origin/server-to-server) is allowed; unknown origins are rejected
    if (!origin || ALLOWED.has(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  maxAge: 600
}));
```

Rules of thumb: compare origins for **exact** equality (not `startsWith`/`endsWith`), reject `Origin: null`, and never combine `Access-Control-Allow-Origin: *` with credentials.

## 6. Safe Error Handling

Return a generic body to the client; keep the detail in server logs with a correlation id.

```python
# Flask: generic client error, full detail logged server-side
import logging, uuid
from flask import Flask, jsonify

app = Flask(__name__)
app.config['DEBUG'] = False           # never True in production
log = logging.getLogger('app')

@app.errorhandler(Exception)
def handle_error(e):
    error_id = uuid.uuid4().hex
    log.exception('Unhandled error id=%s', error_id)   # stack trace to logs only
    return jsonify({
        'error': 'Internal server error',
        'error_id': error_id          # client can quote this to support
    }), 500
```

The client learns *that* something failed and an id to reference; it learns nothing about paths, queries, or credentials.

## 7. Patch and Component Management

Misconfiguration and outdated components travel together.

```bash
# Track and update dependencies continuously
npm audit --production            # Node
pip-audit                         # Python
mvn org.owasp:dependency-check-maven:check   # Java

# Rebuild from patched base images regularly; pin digests, not floating tags
FROM python:3.12-slim@sha256:<digest>
```

Automate dependency update PRs (e.g., Dependabot/Renovate), subscribe to advisories for your stack, and rebuild images on a cadence so patches actually reach production.

## 8. TLS Configuration

Serve only modern protocols and ciphers, and enforce HTTPS with HSTS.

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers off;    # modern guidance: let client choose among strong ciphers
ssl_session_tickets off;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Redirect all HTTP to HTTPS
server { listen 80; return 301 https://$host$request_uri; }
```

Automate certificate issuance and renewal (ACME/Let's Encrypt) so certificates never silently expire.

## 9. Secrets and Default Credentials

- Remove every default and sample account before go-live.
- Generate strong, unique credentials per environment; never commit them.
- Store secrets in a manager (Vault, AWS Secrets Manager, cloud KMS) and inject at runtime—never bake them into images or config files.

```bash
# Reject secrets in the repo at commit time
gitleaks detect --source . --redact
```

## 10. Monitoring and Detection

Watch for the signatures of misconfiguration probing and drift.

```python
# Alert on requests to endpoints that should never be publicly hit
SENSITIVE_PATHS = ('/.env', '/.git', '/actuator/env', '/actuator/heapdump',
                   '/swagger', '/debug/pprof', '/backup')

def flag_recon(path, src_ip):
    if any(path.startswith(p) for p in SENSITIVE_PATHS):
        log.warning('Recon attempt path=%s src=%s', path, src_ip)
        send_security_alert(path, src_ip)
```

Also alert on: spikes of 5xx (error-triggering probes), unexpected `TRACE`/`PUT` verbs, new listening ports, and configuration changes outside the pipeline.

## Framework-Specific Hardening

### Flask (Python)

```python
app.config.update(
    DEBUG=False,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

@app.after_request
def secure_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    resp.headers.pop('Server', None)      # drop the banner
    return resp
```

### Express (Node.js)

```javascript
const express = require('express');
const helmet = require('helmet');
const app = express();

app.disable('x-powered-by');              // remove the Express banner
app.use(helmet());
app.use(express.json({ limit: '100kb' })); // bound request size

// Central error handler — no stack traces to the client
app.use((err, req, res, next) => {
  console.error(err);                      // server log only
  res.status(500).json({ error: 'Internal server error' });
});
```

## Key Takeaways

1. **Codify the baseline** — configuration as code applied identically everywhere beats hand-tuning.
2. **Automate the gate** — scan IaC, images, headers, and TLS on every deploy so drift fails fast.
3. **Disable by default** — unused methods, endpoints, accounts, and packages are pure attack surface.
4. **Be deliberate about the big four** — errors, headers, CORS, and TLS are where most API08 findings live.
5. **Patch and watch** — keep components current and alert on recon and configuration drift.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure configuration across frameworks
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Hands-On Lab](lab/api08-misconfig-lab/)**: Practice hardening a misconfigured API
