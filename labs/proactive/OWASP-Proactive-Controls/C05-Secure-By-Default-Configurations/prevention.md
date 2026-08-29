# C5: Secure By Default Configurations - How to Implement

## How to Implement This Control

Implementing Secure By Default Configurations means **making the hardened state the state that ships**, and keeping it that way automatically. The work divides into eleven reinforcing practices.

### Core Principles

- **Secure by default**: the deployed default is the safe one; opting *out* of a control is explicit, reviewed, and rare.
- **Deny by default**: access, features, ports, and methods are off until a specific need turns them on.
- **Least functionality**: every enabled feature, method, port, and account is attack surface—remove what you don't need.
- **Fail closed and quiet**: on error, deny access and return a generic message; keep detail in server logs.

## 1. Establish a Repeatable Hardening Baseline

Capture the intended secure state as code and apply it identically to every environment. Anchor it to a recognized secure baseline such as the **CIS Benchmarks** for your OS, web server, database, cloud, and container platform.

```yaml
# hardening-baseline.yaml (excerpt) — versioned, reviewed, applied by CI/CD
app:
  debug: false
  detailed_errors: false
  cors_allowed_origins: ["https://app.example.com"]
server:
  server_tokens: false                 # no version banner
  allowed_methods: [GET, POST]         # deny-by-default, per-route override
  directory_listing: false
tls:
  min_version: "1.2"
  hsts: "max-age=31536000; includeSubDomains; preload"
datastore:
  bind: "127.0.0.1"
  auth_required: true
cloud:
  block_public_access: true
  encryption_at_rest: true
```

A baseline that lives in version control is reviewable, diffable, and enforceable—unlike a hand-tuned server that only its author understands.

## 2. Ship Secure Defaults in Code and Products You Build

For software your team produces, the default behaviour must be the safe one so that a consumer who does nothing is still safe.

```python
# A configuration object whose defaults are already safe
class Config:
    debug = False                       # off unless explicitly enabled in dev
    session_cookie_secure = True
    session_cookie_httponly = True
    session_cookie_samesite = "Lax"
    cors_allowed_origins = []           # empty = deny; opt in explicitly
    tls_required = True
```

Design libraries and modules so the secure choice requires no extra flag, and any insecure option is a loud, documented opt-out.

## 3. Bring Products You Deploy to a Secure Baseline

Third-party servers, frameworks, and databases you operate must be hardened before they face traffic:

- Remove or disable sample apps, demo pages, and default schemas.
- Change or remove default credentials and sample accounts.
- Turn off features and modules you do not use.
- Confirm private-by-default storage and required authentication.

## 4. Minimize the Attack Surface

The safest component is the one that isn't running.

```nginx
# nginx: hide the banner, restrict methods, block dotfiles and backups
server_tokens off;

location /api/ {
    limit_except GET POST { deny all; }   # deny-by-default for methods
    autoindex off;                        # no directory listing
}
location ~ /\.(git|env|htaccess) { deny all; return 404; }
location ~* \.(sql|bak|old|zip)$ { deny all; return 404; }
```

Remove unused packages from base images, close unused ports, and drop any schema or UI (for example `/swagger-ui`) that should not be public.

## 5. Remove Default Credentials and Enforce Least Privilege

- Ship with **no usable default credential**; force a unique secret at first setup.
- Generate strong, unique credentials per environment; never commit them.
- Grant every identity, service account, and token the **narrowest rights** that work, and widen only on demonstrated need.
- Store secrets in a manager (Vault, cloud KMS, Secrets Manager) and inject at runtime—never bake them into images.

```bash
# Reject secrets committed to the repo at commit time
gitleaks detect --source . --redact
```

## 6. Preset Security Headers by Default

Set headers centrally (middleware or edge proxy) so they apply to every response—including errors and redirects—without per-route effort.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
Cache-Control: no-store            # for sensitive responses
```

```javascript
// Express: one line applies a sound default baseline
const helmet = require('helmet');
app.use(helmet());
```

## 7. Disable Verbose Errors and Debug in Production

Return a generic body to the client; keep the detail in logs with a correlation id.

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
    log.exception('Unhandled error id=%s', error_id)   # trace to logs only
    return jsonify({'error': 'Internal server error',
                    'error_id': error_id}), 500
```

## 8. Secure Cloud and IaC Defaults

Make the template itself safe: private buckets, no public exposure, and encryption on by default. When the module default is secure, every resource created from it inherits safety.

```hcl
# Terraform: a bucket module whose defaults are private + encrypted
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }
}
```

## 9. Automated Configuration Validation and Drift Detection

Manual review does not scale and does not catch drift. Add automated gates so an insecure default fails the pipeline.

```bash
# In CI: fail the build on insecure configuration
checkov -d ./infra                 # IaC misconfiguration (Terraform/K8s)
tfsec ./infra
trivy image myapp:latest --severity HIGH,CRITICAL   # image hardening + CVEs
testssl.sh https://staging.example.com              # TLS/header verification

# Detect drift against the declared IaC state on a schedule
terraform plan -detailed-exitcode   # non-zero exit = drift = alert
```

Run these on every pull request and on a schedule against running environments, so newly disclosed issues and drift are caught quickly.

## 10. Patch the Defaults

Default to current, patched versions—and keep them current.

```dockerfile
# Pin patched base images by digest, not floating tags
FROM python:3.12-slim@sha256:<digest>

# Keep dependencies current with automated update PRs
# npm audit --production
# pip-audit
# Dependabot / Renovate open update PRs automatically
```

## 11. Make the Secure Path the Easy Path

Adoption fails when security is extra work. Give developers a **paved road**:

- Project templates and scaffolds where the secure options are already selected.
- Shared IaC modules whose defaults are private, encrypted, and least-privilege.
- Hardened base images maintained centrally.
- Libraries whose default configuration is safe, with insecure options as loud opt-outs.

When choosing the default is also choosing security, teams get it right without thinking about it—which is the entire point of this control.

## Key Takeaways

1. **Codify a secure baseline** — anchor it to CIS Benchmarks and apply it identically everywhere.
2. **Default to safe in what you build and what you deploy** — both audiences matter.
3. **Deny and minimize by default** — unused features, ports, methods, and accounts are pure attack surface.
4. **Automate validation and drift detection** — a baseline without enforcement silently erodes.
5. **Pave the road** — make the secure option the default option developers reach for.

## Next Steps

- **[Examples](examples.md)**: Insecure vs. secure configuration across the stack
- **[Threats Addressed](attack-vectors.md)**: The failure modes these defaults close
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Build a secure baseline hands-on
