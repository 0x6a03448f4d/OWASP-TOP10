# CICD-SEC-2: Inadequate Identity and Access Management - Code Examples

Each pair below shows an **insecure** identity/access configuration and the **secure** version in the same platform. The examples focus on the failures that dominate real findings: over-permissioned tokens, long-lived static credentials, local accounts that bypass SSO, and standing broad access.

## GitHub Actions

### Insecure
```yaml
# .github/workflows/deploy.yml
permissions: write-all               # every job gets write to everything

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Long-lived static cloud keys stored as secrets, no expiry, no rotation
      - name: Deploy
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: ./deploy.sh
      # A broad, non-expiring PAT reused for cross-repo access
      - run: gh repo clone my-org/another-repo
        env:
          GH_TOKEN: ${{ secrets.ORG_WIDE_PAT }}   # scopes: repo, admin:org
```

### Secure
```yaml
# .github/workflows/deploy.yml
permissions:
  contents: read                     # workflow-wide least-privilege floor

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write                # mint a short-lived OIDC token
    steps:
      - uses: actions/checkout@v4
      # No stored cloud keys: federate to a scoped, short-lived role
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/ci-deploy
          aws-region: us-east-1
      - run: ./deploy.sh
      # For cross-repo access, use a fine-grained, expiring token scoped
      # to the ONE repo needed — not an org-wide PAT.
```

## GitLab CI

### Insecure
```yaml
# .gitlab-ci.yml
deploy:
  stage: deploy
  script:
    # A group-owner PAT with no expiry, pasted into a CI variable,
    # scoped far beyond this project.
    - curl -H "PRIVATE-TOKEN: $GROUP_OWNER_PAT" "$CI_API_V4_URL/projects"
    - ./deploy.sh
  # Uses a shared "deploy" account's credentials for everything downstream.
```

### Secure
```yaml
# .gitlab-ci.yml
deploy:
  stage: deploy
  # Prefer the built-in CI_JOB_TOKEN (scoped to this pipeline) or a
  # project access token with a minimal role and a short expiry.
  id_tokens:
    CLOUD_TOKEN:
      aud: https://cloud.example.com   # OIDC audience for federation
  script:
    - ./federate-and-deploy.sh          # exchanges the OIDC token for
                                        # short-lived, scoped cloud creds
  rules:
    - if: $CI_COMMIT_BRANCH == "main"

# Project Access Token (if a static token is unavoidable):
#   role: Reporter          # least privilege, not Owner/Maintainer
#   scopes: [read_repository]
#   expires_at: 2026-02-01  # never "no expiration"
```

## Jenkins

### Insecure
```groovy
// A local "admin" account outside the IdP, shared over chat, no MFA.
// Anonymous read enabled and anyone can self-register.
jenkins:
  securityRealm: local          // local users, bypasses central SSO
  authorizationStrategy: loggedInUsersCanDoAnything
  allowAnonymousRead: true
  allowSignup: true

// Pipeline uses one global "deploy-bot" credential with admin cloud keys.
withCredentials([string(credentialsId: 'deploy-bot-aws-admin',
                        variable: 'AWS_ADMIN_KEY')]) {
    sh './deploy.sh'
}
```

### Secure
```groovy
// Delegate authentication to the central IdP; no local logins, no signup.
jenkins:
  securityRealm: oidc                    // SSO via central IdP, MFA enforced
  authorizationStrategy: projectMatrix   // explicit least-privilege grants
  allowAnonymousRead: false
  allowSignup: false

// Per-job, least-privilege, short-lived credentials — no shared admin bot.
// Prefer an OIDC/plugin-based exchange for temporary cloud credentials
// scoped to this job; if a stored credential is unavoidable, scope it to
// one task and rotate it on a schedule.
withCredentials([/* scoped, rotated, job-specific credential */]) {
    sh './deploy.sh'
}
// Break-glass local admin (if any): single account, hardware-key MFA,
// alerted on every use, excluded from normal pipelines.
```

## IdP / SSO and Cloud Federation

### Insecure
```json
# Long-lived IAM user with a static access key and admin policy,
# handed to the pipeline and never rotated.
{
  "UserName": "ci-deploy-user",
  "AttachedPolicies": ["AdministratorAccess"],   # far too broad
  "AccessKeys": [{ "Status": "Active", "Age": "540 days" }]  # never rotated
}

# SSO exists, but this service is configured with local auth only,
# so it skips MFA and central logging entirely.
```

### Secure
```json
# No IAM user, no static key: a role assumed via OIDC web identity,
# pinned to the exact repo/branch and granted only what deploy needs.
{
  "RoleName": "ci-deploy",
  "AssumeRolePolicy": {
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"
      }
    }
  },
  "AttachedPolicies": ["ci-deploy-minimal"],   # least privilege, not admin
  "AccessKeys": []                              # none to leak or rotate
}

# Every system (SCM, CI, registry, cloud console) authenticates through
# the central IdP with MFA enforced; no local-only services.
```

## What Changed, and Why

| Failure | Insecure | Secure |
|---------|----------|--------|
| Token scope | `write-all` / org-wide PAT / group-owner token | Least-privilege, per-repo, per-job scope |
| Credential lifetime | Static keys, non-expiring PATs, never rotated | Short-lived OIDC identities; expiry + rotation where static is unavoidable |
| Authentication path | Local accounts bypass SSO/MFA, self-registration on | Central IdP + MFA everywhere, no signup, break-glass only |
| Shared identity | One `deploy-bot`/admin account reused everywhere | Per-workload machine identities, attributable and revocable |
| Cloud access | Pipeline holds `AdministratorAccess` keys | Scoped role assumed via federation, pinned to repo/branch |

## Next Steps

- **[Prevention](prevention.md)**: The full identity-governance strategy across the toolchain
- **[Attack Vectors](attack-vectors.md)**: How these identity gaps are exploited
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP Top 10 CI/CD lessons
- **[Practice](/practice)**: Test your understanding with hands-on challenges
