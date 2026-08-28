# CICD-SEC-2: Inadequate Identity and Access Management - Prevention

## Prevention Strategy Overview

Preventing inadequate IAM is less about a single control and more about **governing every identity—human and machine—consistently across the whole toolchain**:

1. Centralise identity behind one IdP/SSO with MFA everywhere.
2. Give every identity least privilege, scoped to exactly its task.
3. Prefer short-lived, federated credentials (OIDC) over long-lived tokens.
4. Inventory, rotate, and expire machine identities and tokens.
5. Review access continuously and remove what is stale or shared.

### Core Principles

- **One identity source**: every system authenticates through the central IdP; local and bypass accounts are the exception, tightly controlled, and MFA-protected.
- **Least privilege by default**: an identity starts with nothing and is granted only the specific, minimal permissions its role or job requires.
- **Short-lived over standing**: prefer credentials that expire in minutes (OIDC-federated job identities) to tokens that live for months or forever.
- **Govern the machine identities too**: service accounts, bots, deploy keys, and robot tokens need owners, inventory, rotation, and review—just like humans.

## 1. Centralise Identity: SSO + MFA Everywhere

Wire every system in the delivery chain—SCM, CI, registries, secrets manager, cloud—into the central IdP, and enforce MFA. Eliminate or tightly control local accounts.

```yaml
# identity-baseline.yaml (excerpt) — reviewed, versioned, enforced
idp:
  provider: central-sso
  enforce_sso: true
  enforce_mfa: true
systems:
  scm:      { sso: required, local_accounts: deny, self_registration: off }
  ci:       { sso: required, local_admin: break-glass-only }
  registry: { sso: required, basic_auth_users: deny }
  cloud:    { federation: oidc, long_lived_keys: deny }
break_glass:
  accounts: 1
  mfa: hardware-key
  alert_on_use: true
```

Keep at most a single, monitored break-glass account per system, protected with a hardware key, alarmed on use, and excluded from normal workflows.

## 2. Least Privilege for Every Identity

Grant the minimum. Scope tokens to a single repo/project, map roles narrowly, and never reach for admin "to be safe".

```yaml
# GitHub Actions: default the whole workflow to read, elevate per-job
permissions:
  contents: read            # workflow-wide floor

jobs:
  publish:
    permissions:
      contents: read
      packages: write       # only the job that publishes gets write
      id-token: write        # for OIDC federation, below
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
```

```
# GitLab CI: prefer a job token with minimal scope; if a PAT is unavoidable,
# use a project access token scoped to ONE project and ONE role.
# Settings -> Access Tokens:
#   name: publish-images
#   role: Reporter            # not Maintainer/Owner
#   scopes: [read_repository, write_registry]
#   expires: 30 days
```

## 3. Prefer OIDC Federation Over Long-Lived Tokens

The single most effective control against leaked CI credentials is to stop storing long-lived cloud keys at all. Let the pipeline exchange a short-lived, signed identity token for temporary cloud credentials.

```yaml
# GitHub Actions -> AWS via OIDC (no stored access keys)
permissions:
  id-token: write
  contents: read

steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::111122223333:role/ci-deploy
      aws-region: us-east-1
      # No AWS_ACCESS_KEY_ID / secret stored anywhere.
      # AWS trusts GitHub's OIDC token, scoped to this repo + branch.
```

```json
# The cloud-side trust policy pins the exact identity (repo + ref),
# so the role can only be assumed by the intended workflow.
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"
    }
  }
}
```

The credential now lives for minutes, is scoped to one repo and branch, and cannot be replayed after the job ends—removing the leaked-static-key attack entirely.

## 4. Short-Lived, Scoped Tokens With Expiry

Where a token is unavoidable, make it narrow and short-lived, and record an owner.

```
# Every PAT / access token MUST have:
scope:      the single permission set the task needs (never "admin", never "*")
expiry:     the shortest practical lifetime (days, not "never")
owner:      a named human or team accountable for it
storage:    a secrets manager, never a repo/wiki/chat
inventory:  registered in the identity inventory (see section 6)
```

Disable "no expiration" as an option organisation-wide where the platform allows it, and reject tokens without an owner during review.

## 5. Eliminate Shared Accounts and Self-Registration

- **No shared logins**: replace generic "deploy-bot"/"team-svc" accounts with per-human federated access and per-workload machine identities, so every action is attributable and independently revocable.
- **No self-registration**: disable open sign-up on every tool; provision through the IdP and an approval workflow.
- **Narrow default groups**: new members should join a minimal default group, not one with write access to everything.

```yaml
# Jenkins: disable anonymous/self-signup, use SSO + matrix authorization
jenkins:
  securityRealm: oidc            # delegate to the central IdP
  authorizationStrategy: projectMatrix   # explicit per-project grants
  allowAnonymousRead: false
  allowSignup: false
```

## 6. Inventory Every Identity (Human and Machine)

You cannot govern what you cannot see. Maintain a single inventory across SCM, CI, registries, secrets, and cloud.

```bash
# Enumerate machine identities and tokens on a schedule, feed an inventory
gh api /orgs/my-org/actions/secrets                 # CI secrets
gh api "/orgs/my-org/members?role=all"              # human members
gh api /orgs/my-org/outside_collaborators           # external humans
aws iam list-users; aws iam list-roles              # cloud identities
aws iam list-access-keys --user-name ci-user        # long-lived keys (flag these)

# For each identity record: owner, scope, created, last-used, expiry.
```

Flag anything with no owner, no expiry, broad scope, or a stale "last used" date for review or removal.

## 7. Rotate Machine Credentials on a Schedule

Deploy keys, robot tokens, and any remaining static cloud keys must be rotated regularly and automatically.

```
# Example rotation policy, enforced by automation
static_cloud_keys:   rotate every 30 days   (better: eliminate via OIDC)
registry_robot_tokens: rotate every 90 days
scm_deploy_keys:     rotate every 90 days, one key per repo, read-only if possible
alert:               any credential older than its policy age fails a scan
```

## 8. Continuous Access Review and Deprovisioning

Offboarding must reach every plane, and periodic recertification catches what it misses.

```
# Offboarding checklist (automate as much as possible):
[ ] IdP account disabled
[ ] SCM PATs revoked, SSH/deploy keys removed
[ ] CI local accounts and tokens revoked
[ ] Registry tokens revoked
[ ] Cloud access keys deleted, role trust updated
[ ] Group memberships removed across all systems

# Quarterly recertification:
[ ] Each identity re-approved by its owner, or removed
[ ] External collaborators re-justified or expired
[ ] Stale (unused > 90 days) identities disabled
```

## 9. Govern External Collaborators and Integrations

- **Time-box** outside collaborator access; default to read-only and to an expiry date tied to the engagement.
- **Scope third-party integrations** to the minimum permissions, prefer fine-grained apps over broad OAuth scopes, and review installed integrations periodically.
- **Re-justify on a schedule**: any external access that is not re-approved during recertification is removed automatically.

## 10. Consistent RBAC Across the Toolchain

Model roles once and map them consistently everywhere, so an identity that is low-privilege in one system is not accidentally high-privilege in another.

| Role | SCM | CI | Registry | Cloud |
|------|-----|----|----------|-------|
| Developer | Write to own repos | Run jobs, no secret edit | Pull | No standing access |
| Maintainer | Manage one repo | Edit that repo's pipeline | Push to that repo's images | Deploy via scoped OIDC role |
| CI job (machine) | Read one repo | — | Push one package | Assume one least-priv role |
| Admin | Org settings | Global CI config | Registry admin | IAM admin (few, MFA, reviewed) |

## 11. Monitoring and Detection

Watch for the signatures of identity abuse and drift.

```python
# Alert on identity-risk signals
def flag_identity_risk(event):
    if event.type == "token_created" and event.expiry is None:
        alert("Non-expiring token created", event)
    if event.type == "login" and event.account_is_local:
        alert("Local account bypassed SSO", event)
    if event.actor == "shared-bot" and event.new_ip:
        alert("Shared account used from new location", event)
    if event.type == "role_assumed" and event.role == "AdministratorAccess":
        alert("Admin role assumed by pipeline", event)
```

Also alert on: new admin group memberships, new deploy keys or service accounts, external collaborator additions, and any credential used after its owner was offboarded.

## Key Takeaways

1. **Centralise identity** — SSO+MFA on every system, with local and shared accounts eliminated or tightly controlled.
2. **Least privilege, always** — scope every human role and every machine token to exactly its task, never admin-by-default.
3. **Federate, don't store** — prefer short-lived OIDC identities to long-lived keys and PATs.
4. **Inventory, rotate, expire** — machine identities need owners, rotation, and expiry as much as humans do.
5. **Review continuously** — deprovision across every plane and recertify access on a schedule so nothing stale survives.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure IAM in GitHub Actions, GitLab, Jenkins, and IdP/SSO
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP Top 10 CI/CD lessons
- **[Practice](/practice)**: Test your understanding with hands-on challenges
