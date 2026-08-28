# A5:2021 - Security Misconfiguration: Prevention

## Table of Contents

- [Defense Strategy: Layered and Repeatable](#defense-strategy-layered-and-repeatable)
- [1. A Repeatable Hardened Baseline](#1-a-repeatable-hardened-baseline)
- [2. Minimal Platform: Remove What You Don't Use](#2-minimal-platform-remove-what-you-dont-use)
- [3. Change Every Default (Credentials and Settings)](#3-change-every-default-credentials-and-settings)
- [4. Generic Error Handling, Debug Off](#4-generic-error-handling-debug-off)
- [5. Security Headers on Every Response](#5-security-headers-on-every-response)
- [6. Disable Directory Listing and Protect Artifacts](#6-disable-directory-listing-and-protect-artifacts)
- [7. Restrictive CORS](#7-restrictive-cors)
- [8. Harden XML Parsers (Prevent XXE)](#8-harden-xml-parsers-prevent-xxe)
- [9. Segmented Architecture](#9-segmented-architecture)
- [10. Patch Management](#10-patch-management)
- [11. Review Cloud and Storage Permissions](#11-review-cloud-and-storage-permissions)
- [12. Automated Configuration Verification](#12-automated-configuration-verification)
- [Hardening Checklist](#hardening-checklist)

## Defense Strategy: Layered and Repeatable

Because misconfiguration spans every layer and reappears with every deployment, there is no single control that fixes it. The goal is a **hardened baseline that is applied identically and automatically everywhere**, then continuously verified. Two principles govern everything below:

- **Secure by default, then explicitly relax**: start from a locked-down configuration and open only what a feature genuinely needs—never the reverse.
- **Codify, don't hand-tune**: a server configured by hand drifts and cannot be reproduced. Configuration belongs in version-controlled scripts, images, and infrastructure-as-code so every environment is provably identical.

## 1. A Repeatable Hardened Baseline

Adopt an industry hardening standard as your starting point rather than inventing one. The **CIS Benchmarks** provide consensus, testable configuration guides for operating systems, web servers, databases, containers, and cloud providers; **DISA STIGs** and vendor hardening guides serve the same role.

Encode the chosen baseline as automation so it is applied the same way every time:

```dockerfile
# Example: build the baseline into an immutable image (Dockerfile)
FROM nginx:1.27-alpine
# Remove default sample site and server tokens
RUN rm -f /usr/share/nginx/html/index.html \
 && rm -rf /etc/nginx/conf.d/default.conf
COPY hardened-nginx.conf /etc/nginx/nginx.conf
COPY security-headers.conf /etc/nginx/snippets/security-headers.conf
# Run as non-root
USER nginx
```

```bash
# Verify the baseline in CI before it can ship
$ docker run --rm -v "$PWD:/project" \
    aquasec/trivy config /project        # scan IaC/Dockerfiles for misconfig
$ inspec exec cis-nginx-baseline         # assert CIS controls pass
```

**Why it works**: an image or IaC template that already passed the benchmark cannot be deployed "half-hardened," and the same artifact runs in dev, staging, and production—eliminating environment drift.

## 2. Minimal Platform: Remove What You Don't Use

Every enabled feature, module, port, sample page, and package is attack surface. Ship the smallest platform that runs your app.

```bash
# Disable unused Apache modules
$ a2dismod autoindex status userdir cgi
# Only enable what you need (e.g. headers, ssl, rewrite)
$ a2enmod headers ssl rewrite

# Remove sample/admin apps and default content
$ rm -rf /var/www/html/manual /var/www/html/test /var/lib/tomcat/webapps/examples
$ rm -f  /var/www/html/info.php   # phpinfo() pages

# Bind services to loopback, expose only what must be public
# postgresql.conf
listen_addresses = 'localhost'
```

Use minimal base images (`-alpine`, `-slim`, distroless), install no build tools in the runtime image, and close every port that is not required.

## 3. Change Every Default (Credentials and Settings)

No default account, key, or sample credential should survive into production.

- Reset or delete every default account (`admin/admin`, database superusers, appliance logins) before exposure.
- Generate secrets at deploy time from a secrets manager (Vault, AWS Secrets Manager, cloud KMS)—never hard-code them or bake them into images.
- Rotate framework secret keys, and require them to be supplied by the environment rather than defaulting to a shipped value.

```python
# Fail fast if a required secret is missing (Python example)
import os
SECRET_KEY = os.environ["APP_SECRET_KEY"]   # KeyError on boot if absent
# Never:  SECRET_KEY = os.environ.get("APP_SECRET_KEY", "dev-secret")
```

## 4. Generic Error Handling, Debug Off

Users see a generic message; full detail goes only to server-side logs. Debug mode is off in every non-development environment.

```
# Django (settings driven entirely by environment)
DEBUG = False
ALLOWED_HOSTS = ["app.example.com"]

# Flask
app.config["DEBUG"] = False
app.config["PROPAGATE_EXCEPTIONS"] = False

# Express: a custom error handler that never leaks internals
app.use((err, req, res, next) => {
  req.log.error(err);                       // full detail to logs
  res.status(500).json({ error: "Internal Server Error" });  // generic to client
});

# PHP (php.ini for production)
display_errors = Off
log_errors = On
error_reporting = E_ALL
```

Provide custom `404`/`500` pages so the server's default (which leaks version/framework) is never shown.

## 5. Security Headers on Every Response

Set protective headers centrally—at the reverse proxy or via middleware—so they apply to *every* response, including errors and redirects.

```nginx
# Nginx: /etc/nginx/snippets/security-headers.conf (included in every server block)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;
# Remove server version banner
server_tokens off;
```

```javascript
// Node/Express: Helmet sets a strong default header set in one line
const helmet = require("helmet");
app.use(helmet({
  contentSecurityPolicy: {
    directives: { defaultSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"] }
  },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }
}));
```

The `always` flag on Nginx `add_header` is essential—without it, headers are dropped on error responses, reopening the gap exactly when an attacker is probing.

## 6. Disable Directory Listing and Protect Artifacts

```apache
# Apache: turn off automatic indexing globally
<Directory /var/www/html>
    Options -Indexes
</Directory>

# Deny access to VCS metadata, dotfiles, and backups
<DirectoryMatch "\.(git|svn|hg)">
    Require all denied
</DirectoryMatch>
<FilesMatch "(^\.env|\.bak$|\.sql$|~$)">
    Require all denied
</FilesMatch>
```

```nginx
# Nginx equivalents
autoindex off;
location ~ /\.(?!well-known) { deny all; }     # block .git, .env, dotfiles
location ~ \.(bak|sql|old|swp)$ { deny all; }
```

Better still: never place the repository or build artifacts inside the web root. Deploy only the compiled/needed files, and keep secrets outside the served tree entirely.

## 7. Restrictive CORS

Allow only an explicit list of trusted origins, and never combine a reflected origin with credentials.

```javascript
// Express: strict allow-list, no wildcard reflection
const ALLOWED = new Set(["https://app.example.com", "https://admin.example.com"]);
const cors = require("cors");
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || ALLOWED.has(origin)),
  credentials: true,
  methods: ["GET", "POST"],
}));
```

```
# Anti-pattern to eliminate:
Access-Control-Allow-Origin: *              # with credentials -> forbidden by browsers
Access-Control-Allow-Origin: <reflected>    # reflecting Origin + credentials -> account theft
```

## 8. Harden XML Parsers (Prevent XXE)

Because XXE is now part of this category, treat safe parser configuration as a mandatory hardening step wherever XML (or XML-backed formats like SVG, DOCX, SAML) is accepted. **Disable DTD processing and external entities.**

```python
# Python: defusedxml, or disable resolution on lxml
from defusedxml.ElementTree import parse          # safe drop-in
# lxml explicit hardening:
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)
```

```java
// Java: disable DOCTYPE entirely (most robust)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

```php
// PHP (libxml < 2.9): explicitly disable network/entity loading
libxml_set_external_entity_loader(null);
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NONET | LIBXML_DTDLOAD);  // no network, controlled DTD
```

Prefer less complex data formats (JSON) where you control the API. When XML is required, the safest configuration is to reject any document containing a `DOCTYPE`.

## 9. Segmented Architecture

Design so that a single misconfiguration cannot expose everything. Segmentation and least privilege contain blast radius:

- Place databases, caches, and internal services on private networks unreachable from the internet; expose only the web tier.
- Use security groups / firewalls / network policies to allow only required flows between tiers.
- Run each service with the least privilege it needs (non-root containers, scoped IAM roles, read-only file systems).
- Keep management planes (admin consoles, metrics, debug tooling) on a separate, authenticated, network-restricted path—never on the public interface.

## 10. Patch Management

Outdated components are a configuration and maintenance failure. Make patching routine and measurable:

- Maintain a software inventory / SBOM so you know what is deployed and can react to new advisories.
- Run software composition analysis (`npm audit`, `pip-audit`, OWASP Dependency-Check, Trivy) in CI and fail builds on known-vulnerable, exploitable dependencies.
- Prefer immutable, frequently rebuilt images so patches flow through automatically rather than being applied by hand.
- Subscribe to advisories for every component in the stack and have a defined SLA for critical fixes.

## 11. Review Cloud and Storage Permissions

```bash
# Enforce "block public access" on object storage (AWS S3 example)
$ aws s3api put-public-access-block --bucket app-backups \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Continuously detect drift back to public
$ prowler aws            # cloud security posture checks
$ aws accessanalyzer ...  # flags resources shared outside the account
```

- Default all storage to private; grant access through scoped, time-limited signed URLs or IAM roles.
- Apply least-privilege IAM—no wildcard `Action: "*"` / `Resource: "*"` policies.
- Enable posture management (CSPM) so a bucket flipped public is caught automatically.

## 12. Automated Configuration Verification

Hardening that is not verified will drift. Make configuration a continuously tested property:

- **In CI/CD**: scan IaC and images (Trivy, Checkov, tfsec) and run benchmark checks (InSpec, OpenSCAP) so misconfiguration blocks the pipeline.
- **Post-deploy**: assert live headers, TLS, and open ports from the outside.
- **Continuously**: schedule scanners (nuclei, ZAP baseline, testssl.sh) and CSPM against production.

```bash
# Example: assert security headers on the live site in a pipeline step
$ curl -sI https://app.example.com | grep -Ei \
    'strict-transport-security|content-security-policy|x-content-type-options|x-frame-options' \
    || { echo "Missing security header"; exit 1; }

# Automated header/TLS grade + baseline scan
$ testssl.sh --quiet https://app.example.com
$ zap-baseline.py -t https://app.example.com
```

## Hardening Checklist

| Area | Control |
|------|---------|
| Baseline | CIS/STIG baseline codified as image/IaC and verified in CI |
| Minimal platform | Unused modules, ports, sample apps, packages removed |
| Defaults | All default credentials changed; secrets from a manager, never hard-coded |
| Errors | Debug off; generic client errors; detail only in logs; custom error pages |
| Headers | HSTS, CSP, nosniff, frame-ancestors, Referrer-Policy on every response |
| Directory/artifacts | Listing off; `.git`/`.env`/backups unreachable; repo outside web root |
| CORS | Explicit origin allow-list; never reflected origin + credentials |
| XML/XXE | DTDs and external entities disabled in every parser |
| Architecture | Tiers segmented; least privilege; management plane isolated |
| Patching | SBOM + SCA in CI; immutable, frequently rebuilt images |
| Cloud | Storage private by default; least-privilege IAM; CSPM enabled |
| Verification | Automated config/header/TLS checks in pipeline and in production |

## Key Takeaways

1. **Start hardened, then relax deliberately**—secure defaults beat trying to lock down an open system later.
2. **Codify configuration** so every environment is identical and drift is impossible to introduce silently.
3. **Set security controls centrally** (headers, errors, CORS) so no response slips through unprotected.
4. **Treat XXE as configuration**—disable DTDs and external entities everywhere XML is parsed.
5. **Verify continuously**—a baseline you do not test will drift back to insecure.

## Next Steps

- **[Overview](./overview.md)**: Understand the category and its impact
- **[Attack Vectors](./attack-vectors.md)**: See exactly what these defenses stop
- **[Examples](./examples.md)**: Copy-ready vulnerable vs. secure configurations
- **[Hands-On Lab](./lab/debug-mode-lab/)**: Practice hardening a misconfigured app

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
