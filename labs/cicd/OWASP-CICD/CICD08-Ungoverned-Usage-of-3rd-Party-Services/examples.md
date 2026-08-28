# CICD-SEC-8: Ungoverned Usage of 3rd Party Services - Examples

Each pair below shows an **ungoverned** use of a third-party service and the **governed** version of the same thing. The examples focus on the choices that dominate real findings: unpinned third-party Actions, over-scoped Apps and OAuth grants, long-lived tokens handed to SaaS tools, and unrestricted marketplace usage.

## 1. Third-Party GitHub Action Reference

### Ungoverned

```yaml
# .github/workflows/build.yml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-user/awesome-action@v2      # mutable tag, unknown author
      - uses: another/deploy-step@main         # HEAD of a repo you don't control
    # If @v2 or @main is repointed to malicious code, your next build runs it
    # with the job's secrets and workspace in scope.
```

### Governed

```yaml
# .github/workflows/build.yml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      # Third-party step pinned to a full commit SHA (immutable), version in comment
      - uses: some-user/awesome-action@3f1c0a9d6b2e4f8a1c7d5e2b9f0a4c6d8e1b3a5c  # v2.3.1
      # Prefer first-party / vendored copies for anything security-critical
      - uses: our-org/deploy-step@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0    # internal fork
    # Pins are updated only via a reviewed PR from a dependency-update bot.
```

## 2. SCM App / OAuth Scope

### Ungoverned

```yaml
# App authorized "to be safe" — one click grants everything
permissions:
  repositories: all              # every repo in the org
  contents: read-write           # a read-only scanner asking for write
  members: read                  # org-wide membership visibility
  administration: read           # far more than the feature needs
  webhooks: read-write           # can add its own persistence
# Granted once in 2024, never reviewed since.
```

### Governed

```yaml
# App scoped to exactly what the stated feature requires
permissions:
  repositories: [web-app]        # only the repo it serves
  contents: read                 # read-only scanner => read only
  metadata: read
  pull_requests: read            # needed to comment on PRs, nothing more
owner: dev-experience-team
review_by: 2026-07-10            # access expires unless re-justified
# Installation restricted to org admins; approval required to add.
```

## 3. SaaS Tool Credential in CI

### Ungoverned

```yaml
# Long-lived, broad personal access token stored with a third-party SaaS
env:
  COVERAGE_TOKEN: ghp_************************   # classic PAT, "repo" scope, no expiry
steps:
  - run: bash <(curl -s https://cdn.thirdparty.example/uploader.sh)
    # The vendor now stores YOUR broad token; the script is fetched fresh each run.
    # Vendor breach OR script tampering => your secrets and source are exposed.
```

### Governed

```yaml
# No stored static token: exchange a per-run OIDC identity for short-lived access
permissions:
  id-token: write                # allow OIDC token minting for this job only
  contents: read
steps:
  # Pin the uploader to a SHA instead of piping a live-fetched script to bash
  - uses: vendor/coverage-uploader@9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c6  # v4.2.0
    with:
      use-oidc: true             # temporary, minimally-scoped credential
    # Credential is minted per run, expires in minutes, and is scoped to upload only.
```

## 4. Restricting Which Actions/Apps May Run (Org Policy)

### Ungoverned

```yaml
# Org settings
allowed_actions: all             # any Action published anywhere may run
marketplace_apps: "any member may install any app"
# Any developer can pull in any third-party component or authorize any App.
```

### Governed

```yaml
# Org settings
allowed_actions: selected
allow:
  - "actions/*@*"                # first-party
  - "our-org/*@*"                # internal, trusted
  - "verified-vendor/tool@9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c6"  # reviewed + pinned
deny_by_default: true            # anything not listed cannot run
marketplace_apps:
  installation: "org-admin approval required"
  third_party_by_default: denied
```

## 5. Webhook Handling

### Ungoverned

```python
# Inbound webhook triggers a deploy with no verification
@app.route('/webhooks/deploy', methods=['POST'])
def deploy():
    trigger_deploy(request.json['ref'])     # anyone who knows the URL can deploy
    return '', 200
# No signature check => forged or replayed events trigger real deploys.
```

### Governed

```python
import hmac, hashlib
from flask import request, abort

WEBHOOK_SECRET = load_secret('deploy_webhook')   # not hard-coded

@app.route('/webhooks/deploy', methods=['POST'])
def deploy():
    sig = request.headers.get('X-Hub-Signature-256', '')
    expected = 'sha256=' + hmac.new(WEBHOOK_SECRET, request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):   # constant-time verification
        abort(401)
    trigger_deploy(request.json['ref'])
    return '', 200
# Unsigned or tampered events are rejected before any deploy happens.
```

## 6. Access Lifecycle

### Ungoverned

```
Integration added -> works forever.
  - No inventory of who-has-access.
  - No owner, no review date.
  - Deploy keys and bot tokens from finished projects remain, still write-capable.
  - A departed contractor's OAuth app is still authorized org-wide.
```

### Governed

```yaml
# Every grant is inventoried, owned, and expires unless re-justified
- name: legacy-migration-key
  type: deploy-key
  owner: platform-team
  added: 2025-02-01
  review_by: 2025-08-01          # overdue => auto-flagged for revocation
  status: REVOKE (project complete)
# Offboarding a person/project revokes their grants, tokens, and bots.
# Quarterly review reconciles inventory against the platform's actual grants.
```

## What Changed, and Why

| Concern | Ungoverned | Governed |
|---------|------------|----------|
| Component reference | Mutable tag/branch from unknown author | Full commit SHA, verified/first-party preferred |
| App / OAuth scope | Org-wide, read/write, "to be safe" | Specific repos, read-only where possible, owned |
| SaaS credential | Long-lived broad PAT stored with vendor | Short-lived OIDC, minted per run, upload-only |
| Marketplace usage | Anything may run; anyone may install | Org allow-list + admin approval, deny by default |
| Webhooks | Unverified triggers, secrets in payloads | Signature-verified, minimal data out |
| Lifecycle | Granted once, never reviewed | Inventoried, review-dated, revoked on offboard |

## Next Steps

- **[Prevention](prevention.md)**: The full governance lifecycle for third-party services
- **[Attack Vectors](attack-vectors.md)**: How these ungoverned choices are exploited
- **[CI/CD Security Track](/learn/cicd)**: Continue with the rest of the OWASP CI/CD Top 10
- **[Practice](/practice)**: Apply these controls in hands-on exercises
