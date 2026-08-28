# CICD-SEC-7: Insecure System Configuration - Configuration Examples

Each pair below shows an **insecure** configuration and the **secure** version for the same CI/CD system. The examples focus on the settings that dominate real CI/CD compromise: anonymous/weak auth, exposed consoles, unpatched plugins, shared runners, cleartext transport, and unauthenticated webhooks.

## Jenkins Controller (Configuration-as-Code)

### Insecure
```yaml
# jenkins.yaml (JCasC) — dangerous posture
jenkins:
  systemMessage: "Build server"
  # "Anyone can do anything": anonymous users get full control
  authorizationStrategy: "unsecured"
  securityRealm: "none"                 # no real login
  slaveAgentPort: 50000                 # agent port left open to the world
  remotingSecurity:
    enabled: false                      # agent protocol not secured
# Script console reachable by anyone who reaches the UI.
# Plugins never pinned; dozens installed, many outdated.
# Served over plain HTTP on :8080, exposed directly to the internet.
```

### Secure
```yaml
# jenkins.yaml (JCasC) — hardened posture
jenkins:
  systemMessage: "Authorized use only"
  securityRealm:
    oic:                                # SSO via OIDC provider (MFA enforced upstream)
      clientId: "${JENKINS_OIDC_CLIENT_ID}"
      # ...issuer, scopes configured centrally
  authorizationStrategy:
    roleBased:                          # least-privilege matrix; anonymous has NOTHING
      roles:
        global:
          - name: "admin"
            permissions: ["Overall/Administer"]
            assignments: ["oidc-group-ci-admins"]
          - name: "developer"
            permissions: ["Overall/Read", "Job/Build"]
            assignments: ["oidc-group-developers"]
  remotingSecurity:
    enabled: true                       # secure controller/agent transport
security:
  scriptApproval:
    approvedSignatures: []              # no blanket script approvals
# Controller runs behind VPN/allow-list, TLS-terminated (HTTPS only).
# /script restricted to break-glass admins; plugins pinned and patched on a cadence.
unclassified:
  location:
    url: "https://ci.internal.example.com/"   # HTTPS, internal hostname
```

> **Why it matters:** the insecure version grants anonymous full control and leaves an RCE-capable script console and open agent port on the public internet. The secure version enforces SSO, least-privilege roles, secured agent transport, and keeps the console private.

## Jenkins Plugin & Patch Hygiene

### Insecure
```
# No inventory, no pinning, no patch cadence:
- 180+ plugins installed, unknown which are actually used
- versions float; "update when something breaks"
- controller core several major releases behind advisories
- no record of installed versions when a new CVE lands
```

### Secure
```
# plugins.txt — explicit, pinned, reviewed set (installed at build time)
configuration-as-code:1.x
role-strategy:x.y
oic-auth:x.y
# ...only plugins actually required, each pinned to a reviewed version

# Patch process:
- weekly check against the Jenkins security advisory feed
- staging controller validates core+plugin updates before promotion
- immutable controller image rebuilt from plugins.txt (redeploy, not in-place patch)
- inventory exported so exposure to any new advisory is answerable immediately
```

## GitLab Self-Managed (Settings)

### Insecure
```
# Permissive, exposed self-managed instance
- sign-up enabled, no email domain restriction  (anyone can register)
- instance reachable directly on the public internet
- two-factor authentication not enforced
- CI_DEBUG_TRACE enabled in shared pipelines (masks nothing, leaks variables)
- project runners: shared, privileged, reused across groups
- webhooks accept events with no secret token
```

### Secure
```yaml
# Hardened self-managed instance
- open registration DISABLED; accounts provisioned via SSO (SAML/OIDC)
- enforce two-factor authentication for all users
- instance behind VPN / IP allow-list; TLS enforced, valid certificate
- .gitlab-ci.yml: CI_DEBUG_TRACE never enabled in production pipelines
  variables:
    CI_DEBUG_TRACE: "false"
- runners: project- or group-scoped, non-privileged, ephemeral
- webhooks require a secret token; signature verified on receipt
- protected branches/tags; least-privilege project and group roles
```

## GitHub Organization & Actions Runners

### Insecure
```yaml
# Loose org and runner posture
- SSO/MFA not enforced for organization members
- self-hosted runners enabled at the org level for ALL repos, including public
- self-hosted runners run fork pull-request workflows (untrusted code)
- runners are long-lived VMs reused across many jobs
- broad cloud role attached to the runner; metadata endpoint reachable
- Actions permissions: read/write token granted to every workflow by default
```

### Secure
```yaml
# Hardened org and runner posture
- enforce SSO + MFA for all members; least-privilege team roles
- self-hosted runners scoped to specific private repos only
- fork/PR workflows never run on self-hosted runners (use isolated hosted runners)
- ephemeral runners: single-use, de-register after one job
    ./config.sh --url <repo> --token <reg-token> --ephemeral
- minimal cloud role; block the metadata endpoint where unused
- default GITHUB_TOKEN set to read-only; elevate per-job only when needed
  permissions:
    contents: read
```

## Runner Container Isolation

### Insecure
```yaml
# docker-compose.yml — a dangerous "convenient" runner
services:
  runner:
    image: my/ci-runner:latest        # floating tag, unpatched base
    privileged: true                  # full host access from any build
    network_mode: host                # flat network, sees everything
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock   # docker socket = host root
      - /:/host                        # entire host filesystem mounted
    user: root                        # builds run as root
```

### Secure
```yaml
# docker-compose.yml — isolated, least-privilege runner
services:
  runner:
    image: my/ci-runner@sha256:<digest>   # pinned, patched base image
    privileged: false                     # no host privilege
    read_only: true                       # immutable root filesystem
    user: "10001:10001"                   # non-root build user
    cap_drop: ["ALL"]                     # drop Linux capabilities
    security_opt: ["no-new-privileges:true"]
    networks: ["ci-isolated"]             # segmented, not host/flat
    # no docker.sock, no host mounts; use a rootless/sandboxed builder instead
networks:
  ci-isolated:
    internal: true                        # no route to production or metadata
```

## Reverse Proxy: Exposure & TLS

### Insecure
```nginx
# nginx — controller open to the world over cleartext
server {
    listen 80;                        # plain HTTP, no TLS
    server_name ci.example.com;       # public DNS name
    location / {
        proxy_pass http://127.0.0.1:8080;   # anyone on the internet reaches it
    }
}
```

### Secure
```nginx
# nginx — TLS-only, allow-listed, private management plane
server { listen 80; return 301 https://$host$request_uri; }   # force HTTPS

server {
    listen 443 ssl;
    server_name ci.internal.example.com;      # internal hostname
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate     /etc/ssl/ci.crt;
    ssl_certificate_key /etc/ssl/ci.key;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        allow 10.0.0.0/8;             # corporate/VPN range only
        allow 192.0.2.10/32;          # bastion
        deny  all;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

## Webhook Verification

### Insecure
```python
# Accepts any POST as a trusted event — an unauthenticated pipeline trigger
@app.route("/github-webhook/", methods=["POST"])
def hook():
    event = request.get_json()
    trigger_build(event)              # no signature check, no source check
    return "ok"
```

### Secure
```python
# Verify HMAC signature and constrain the source before acting
import hmac, hashlib
from flask import request, abort

WEBHOOK_SECRET = get_secret("github_webhook_secret")   # from a secret manager

@app.route("/github-webhook/", methods=["POST"])
def hook():
    raw = request.get_data()
    sent = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(WEBHOOK_SECRET, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sent, expected):        # constant-time compare
        abort(401)
    if request.headers.get("X-GitHub-Event") not in ALLOWED_EVENTS:
        abort(400)                                     # only handled event types
    trigger_build(request.get_json())
    return "ok"
```

## What Changed, and Why

| Misconfiguration | Insecure | Secure |
|------------------|----------|--------|
| Authentication | Anonymous / shared / default logins | SSO + MFA, least-privilege roles, no anonymous |
| Exposure | Console/API on the public internet | VPN / IP allow-list, internal hostnames |
| Patching & plugins | Floating tags, unpinned, unpatched, excessive | Pinned, minimal, patched on a cadence |
| Script/debug modes | Open script console, debug tracing on | Break-glass only, debug off in production |
| Runners | Shared, privileged, flat network, root | Ephemeral, non-privileged, isolated, non-root |
| Transport | Plain HTTP, ignored certs | TLS everywhere, valid certificates, HSTS |
| Webhooks | Unauthenticated, any source | HMAC-verified, source-constrained, least scope |

## Next Steps

- **[Prevention](prevention.md)**: The full layered hardening strategy for CI/CD systems
- **[Attack Vectors](attack-vectors.md)**: How these misconfigurations are discovered and exploited
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP Top 10 CI/CD Security Risks lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
