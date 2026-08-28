# CICD-SEC-6: Insufficient Credential Hygiene - Prevention

## Prevention Strategy Overview

Preventing credential mishandling is less about one control and more about **shrinking the value and lifetime of every secret** so that a leak is contained and cheap to recover from:

1. Keep secrets out of code and Git entirely.
2. Replace long-lived static keys with short-lived, federated credentials.
3. Scope every secret to the smallest audience that needs it.
4. Rotate on a schedule and immediately on exposure.
5. Prevent secrets from reaching logs and artifacts, and scan continuously to catch what slips through.

### Core Principles

- **A secret you don't store can't leak**: prefer minting a short-lived token at runtime over holding a static one.
- **Assume exposure and design for it**: short lifetimes and narrow scope make any single leak low-impact.
- **Deletion is not remediation**: an exposed secret is compromised until it is *rotated*, not merely removed.
- **Detection must be automated**: scan pre-commit and in CI, because humans never spot a key in a diff or a log.

## 1. Keep Secrets Out of Code and Git

Secrets belong in a secrets manager or the CI platform's secret store, injected at runtime—never typed into code, pipeline YAML, or Dockerfiles.

```yaml
# GitHub Actions: reference a stored secret, never a literal
- name: Deploy
  run: ./deploy.sh
  env:
    DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}   # value lives in the secret store

# Fetch app secrets at runtime from a manager instead of committing them:
export DB_PASSWORD="$(vault kv get -field=password secret/prod/db)"
```

Back this with a policy that no secret is ever committed, and enforce it mechanically with the scanning gates in section 6.

## 2. Prefer Short-Lived, OIDC-Federated Cloud Credentials

The single highest-impact change is to stop storing long-lived static cloud keys and instead have the CI platform exchange a signed OIDC identity token for a short-lived cloud credential, minted per job and expiring in minutes.

```yaml
# GitHub Actions -> AWS via OIDC: no static keys stored anywhere
permissions:
  id-token: write        # allow the workflow to request an OIDC token
  contents: read
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/ci-deployer
      aws-region: us-east-1
      # No AWS_ACCESS_KEY_ID / SECRET stored — a short-lived token is minted
```

```json
// The trust policy ties the role to THIS repo + branch, and nothing else:
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
    "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:acme/app:ref:refs/heads/main" }
  }
}
```

A credential that expires in minutes and is bound to a specific repo and branch is nearly worthless if leaked—there is no long-lived key to harvest.

## 3. Scope Secrets Minimally

Give each secret the smallest possible audience and permission set. Never share one token across every pipeline.

- **Per environment**: separate credentials for dev, staging, and prod, so a dev leak cannot touch prod.
- **Per pipeline/repo**: distinct identities so one leak does not compromise unrelated projects.
- **Per job/step**: inject a secret only into the step that needs it, not the whole job.
- **Least privilege**: the underlying IAM policy grants only the specific actions the job performs—never `"*":"*"`.

```yaml
# GitLab CI: expose a secret only to the deploy job, not the whole pipeline
deploy_prod:
  stage: deploy
  environment: production        # scope the variable to this environment only
  script: ./deploy.sh
  # PROD_TOKEN is a protected, environment-scoped variable — not visible to test jobs
```

## 4. Rotate Regularly and on Exposure

Every static secret needs a defined lifetime and an owner. Rotation must be routine (so it is painless) and immediate whenever exposure is suspected.

```bash
# Rotation checklist for any suspected leak:
# 1. Revoke/rotate the credential at the provider FIRST (invalidate the value)
# 2. Update the secret store with the new value
# 3. THEN clean history/logs (cleanup, not the fix)
# 4. Review provider logs for use of the old credential

aws iam create-access-key  --user-name ci-deployer     # issue new
aws iam update-access-key  --user-name ci-deployer --access-key-id AKIA_OLD --status Inactive
aws iam delete-access-key  --user-name ci-deployer --access-key-id AKIA_OLD
```

Narrow scoping (section 3) is what makes rotation safe: rotating a per-pipeline secret disrupts one pipeline, not the entire organisation.

## 5. Mask and Redact Secrets in Logs; Forbid Echoing

Register every secret with the platform's masker, and prohibit shell tracing and explicit prints of secrets.

```bash
# Do NOT do this — defeats masking and leaks the value:
set -x                                   # traces expanded secrets
echo "token=$API_TOKEN"                  # explicit print

# Instead: keep tracing off around secrets, and register masks explicitly.
# GitHub Actions — add a dynamically derived secret to the masker:
echo "::add-mask::$DERIVED_TOKEN"
# GitLab — mark variables as "Masked" and "Protected" in project settings.
```

Treat masking as a backstop, not a guarantee: the real control is never letting a secret reach stdout/stderr in the first place. Restrict who can read pipeline logs, too.

## 6. Scan Repos and History for Secrets (Pre-Commit and in CI)

Catch leaks before they merge, and continuously afterwards, with dedicated secret scanners such as `gitleaks` or `trufflehog`.

```yaml
# Pre-commit hook: block a secret before it is ever committed
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

```yaml
# CI gate: fail the build on any detected secret, and scan full history
# .github/workflows/secret-scan.yml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }        # full history, not just the tip
- name: gitleaks
  run: gitleaks detect --source . --redact --exit-code 1
- name: trufflehog (verified only)
  run: trufflehog git file://. --only-verified --fail
```

Run scanning on every pull request and on a schedule, and enable any provider-side secret scanning (push protection) your platform offers.

## 7. Purge Leaked Secrets from History AND Rotate

When a secret is found in history, rotation is the fix and history rewriting is cleanup—do both, rotation first.

```bash
# 1) ROTATE the credential at the provider first (see section 4).
# 2) Then remove the value from history so it stops being harvested:
git filter-repo --replace-text <(echo 'AKIAIOSFODNN7EXAMPLE==>REMOVED')
#   (or the BFG Repo-Cleaner) — then force-push and have collaborators re-clone.
# Remember: forks, mirrors, and caches may still hold the old value —
# which is exactly why rotation, not deletion, is the real remediation.
```

## 8. Keep Secrets Out of Artifacts and Images

Never pass secrets as build arguments that persist in image layers; use build-time secret mounts or inject at runtime.

```dockerfile
# Docker BuildKit: secret is mounted for one step and NOT stored in any layer
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN="$(cat /run/secrets/npm_token)" npm ci

# Build without baking anything in:
DOCKER_BUILDKIT=1 docker build --secret id=npm_token,env=NPM_TOKEN .

# Provide runtime config via the orchestrator, not the image:
#   Kubernetes Secret / cloud secret manager injected as env at deploy time.
```

Audit images (`docker history`) and artifacts as part of CI so a baked-in secret fails the build rather than shipping.

## 9. No Standing Human Access to Production Secrets; Ephemeral Runners

- **No standing human access**: production secrets should be reachable only by the automated pipeline identity. Humans get access *just in time*, time-boxed, approved, and audited—not as a permanent grant in the console.
- **Ephemeral runners**: use fresh, single-use build runners so secrets and tokens do not linger in a long-lived worker's memory, disk, or environment between jobs.
- **Isolate by trust level**: run untrusted workloads (for example fork PRs) on runners that never see production secrets.

```bash
# Prefer just-in-time, expiring access over standing grants:
vault write auth/approle/role/deploy secret_id_ttl=10m token_ttl=15m token_max_ttl=20m
# Runner is destroyed after the job; no secret survives to the next build.
```

## 10. Monitoring and Detection

Watch for the signatures of leaked-credential abuse and hygiene drift.

```
# Alert on credential use that shouldn't happen:
- Static key used from a new / unexpected IP or geography
- CI identity performing actions outside its normal set (e.g. iam:CreateAccessKey)
- A credential used AFTER it was supposedly rotated/retired
- Secret-scanner hits on any branch, fork, or build log
- New long-lived access keys created on a CI user
```

Feed provider audit logs (cloud CloudTrail-style logs, registry access logs) and secret-scanner findings into alerting so exposure is caught in minutes, not months.

## Defense-in-Depth Summary

| Failure | Insecure | Secure |
|---------|----------|--------|
| Storage | Hardcoded in code / YAML / Dockerfile | Secrets manager or CI store, injected at runtime |
| Cloud access | Long-lived static keys, broad scope | Short-lived OIDC-federated, repo/branch-bound |
| Scope | One shared token everywhere | Per environment / pipeline / step, least privilege |
| Rotation | Never; deletion treated as the fix | Scheduled + immediate on exposure; rotate, then purge |
| Logs | `set -x` / `echo` leak secrets | Masked, echoing forbidden, log access restricted |
| Detection | None; attacker finds it first | gitleaks/trufflehog pre-commit + CI + monitoring |

## Key Takeaways

1. **Don't store what you can mint** — short-lived OIDC-federated credentials remove the long-lived key attackers harvest.
2. **Scope narrowly** — per-environment, per-pipeline, per-step secrets contain any leak and make rotation painless.
3. **Rotate, then clean up** — an exposed secret is compromised until rotated; purging history is cleanup, not the fix.
4. **Keep secrets out of logs and artifacts** — prevention beats redaction; never bake secrets into images.
5. **Automate detection** — scan pre-commit and in CI, and monitor provider logs for credential abuse.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure secret handling across pipelines
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
