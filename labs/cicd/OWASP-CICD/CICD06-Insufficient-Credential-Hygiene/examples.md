# CICD-SEC-6: Insufficient Credential Hygiene - Code Examples

Each pair below shows an **insecure** way of handling a CI/CD secret and the **secure** version of the same task. The focus is the mishandling that dominates real findings: secrets in pipeline YAML, static keys, secrets in logs, secrets baked into images, and the absence of scanning.

## 1. Cloud Credentials in Pipeline YAML (GitHub Actions)

### Insecure

```yaml
# .github/workflows/deploy.yml
name: deploy
on: { push: { branches: [main] } }
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to S3
        run: aws s3 sync ./dist s3://prod-assets
        env:
          # Long-lived static keys pasted directly into the workflow file.
          AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
          AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Why it's dangerous**: the keys are committed to version control (and recoverable from history), long-lived, and broadly scoped—anyone who reads the repo owns the account until someone notices and rotates.

### Secure

```yaml
# .github/workflows/deploy.yml — no stored keys at all; OIDC mints a short-lived token
name: deploy
on: { push: { branches: [main] } }
permissions:
  id-token: write        # request an OIDC identity token
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ci-deployer
          aws-region: us-east-1        # role is minted per job, expires in minutes
      - name: Deploy to S3
        run: aws s3 sync ./dist s3://prod-assets
```

**Why it's safe**: nothing is stored to leak. The workflow presents a signed OIDC token; the cloud returns a short-lived credential bound to this repo and branch (see the trust policy in Prevention, section 2).

## 2. Static Secret vs. CI Secret Store (GitLab CI)

### Insecure

```yaml
# .gitlab-ci.yml
deploy:
  script:
    - export DB_PASSWORD="S3cr3tP@ss!"          # hardcoded in the pipeline file
    - export REGISTRY_TOKEN="glpat-abc123def456" # committed for all to see
    - ./deploy.sh
```

**Why it's dangerous**: the secrets live in the repository, are visible to every project member, and persist in history and forks.

### Secure

```yaml
# .gitlab-ci.yml — values come from protected, masked, environment-scoped variables
deploy_prod:
  stage: deploy
  environment: production          # variable visible only to prod deploys
  script:
    - ./deploy.sh                  # DB_PASSWORD / REGISTRY_TOKEN injected at runtime
  # In Settings > CI/CD > Variables: mark each as "Masked" and "Protected",
  # and scope to the "production" environment so test jobs never see them.
```

**Why it's safe**: the secret is stored outside the repo, masked in logs, and only exposed to the specific protected job that needs it.

## 3. Secrets Leaked to Build Logs

### Insecure

```yaml
build:
  script:
    - set -x                                   # traces EVERY expanded variable
    - echo "Using token $DEPLOY_TOKEN"         # explicit print defeats masking
    - curl -H "Authorization: Bearer $DEPLOY_TOKEN" https://api.example.com/deploy
    # Log now contains:  + curl -H 'Authorization: Bearer ghp_ab12...'
```

**Why it's dangerous**: shell tracing and explicit echoes push the raw secret into logs that are retained, forwarded to aggregators, and broadly readable.

### Secure

```yaml
build:
  script:
    - set +x                                   # never trace around secrets
    # Register any dynamically derived secret with the masker:
    - 'echo "::add-mask::$DEPLOY_TOKEN"'       # GitHub Actions masking directive
    # Pass the secret without printing it — let the tool read it from the env:
    - curl --silent -H "Authorization: Bearer $DEPLOY_TOKEN" https://api.example.com/deploy
    # No echo of the value; tracing off; log access restricted to the team.
```

**Why it's safe**: the value never reaches stdout/stderr. Masking is a backstop, not the primary control—the secret is simply never printed.

## 4. Secret Baked into a Container Image

### Insecure

```dockerfile
# Dockerfile
FROM node:20-slim
# ARG/ENV secrets are stored in the image layers forever:
ARG NPM_TOKEN=npm_9f8a7b6c5d4e3f2a1b0c
ENV NPM_TOKEN=$NPM_TOKEN
RUN npm ci
# `docker history` and layer extraction reveal NPM_TOKEN to anyone who pulls the image.
```

**Why it's dangerous**: build-time `ARG`/`ENV` secrets persist in image layers and travel to every registry, laptop, and environment the image reaches.

### Secure

```dockerfile
# Dockerfile — BuildKit secret mount: available for one step, stored in NO layer
# syntax=docker/dockerfile:1
FROM node:20-slim
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN="$(cat /run/secrets/npm_token)" npm ci

# Build command supplies the secret from the environment, not the image:
#   DOCKER_BUILDKIT=1 docker build --secret id=npm_token,env=NPM_TOKEN -t app .
# Runtime config is injected by the orchestrator (K8s Secret / secret manager),
# never baked into the image.
```

**Why it's safe**: the token is mounted only for the `npm ci` step and leaves no trace in the final image; `docker history` shows nothing.

## 5. Over-Shared Token vs. Scoped, Least-Privilege Identity

### Insecure

```
# One "god" token stored once and reused by every pipeline:
#   - policy: AdministratorAccess  ("Action": "*", "Resource": "*")
#   - used by 14 workflows across dev, staging, and prod
# Result: a leak from the lowest-value pipeline compromises everything,
# and rotating it breaks all 14 pipelines at once.
```

### Secure

```json
// Distinct, least-privilege identity per environment/pipeline. Example policy
// for a deploy job that only needs to sync one bucket:
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:PutObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::prod-assets",
      "arn:aws:s3:::prod-assets/*"
    ]
  }]
}
// A leak of THIS credential exposes one bucket, and rotating it affects one pipeline.
```

**Why it's safe**: narrow scope contains the blast radius of any leak and makes rotation a routine, low-risk operation.

## 6. Adding Secret Scanning to the Pipeline

### Insecure (no scanning at all)

```
# No pre-commit hook and no CI gate:
#   a committed secret merges to main, is mirrored and forked,
#   and is discovered by an attacker's scanner before anyone internal notices.
```

### Secure (scan pre-commit AND in CI, full history)

```yaml
# .pre-commit-config.yaml — block secrets before they are committed
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

```yaml
# .github/workflows/secret-scan.yml — fail the build on any detected secret
name: secret-scan
on: [pull_request, push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }             # scan FULL history, not just the tip
      - name: gitleaks
        run: gitleaks detect --source . --redact --exit-code 1
      - name: trufflehog (verified secrets only)
        run: trufflehog git file://. --only-verified --fail
```

**Why it's safe**: leaks are caught pre-commit and again in CI across the whole history, so a secret is blocked or surfaced immediately—before the attacker's scanner finds it.

## What Changed, and Why

| Mishandling | Insecure | Secure |
|-------------|----------|--------|
| Cloud access | Static keys in pipeline YAML | Short-lived OIDC-federated role, per job |
| Storage | Hardcoded in code / YAML | CI secret store or secrets manager, runtime-injected |
| Logs | `set -x` / `echo` print the value | Never printed; masking as backstop |
| Images | Secret in a build `ARG`/`ENV` layer | BuildKit secret mount; runtime injection |
| Scope | One shared admin token | Per-pipeline least-privilege identity |
| Detection | None | gitleaks/trufflehog pre-commit + CI, full history |

## Next Steps

- **[Prevention](prevention.md)**: The full lifecycle strategy for clean, short-lived secrets
- **[Attack Vectors](attack-vectors.md)**: How these mishandled secrets are harvested and reused
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
