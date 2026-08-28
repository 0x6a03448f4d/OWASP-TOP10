# CICD-SEC-2: Inadequate Identity and Access Management - Overview

## Table of Contents
- [What is Inadequate Identity and Access Management?](#what-is-inadequate-identity-and-access-management)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Characteristics](#prevalence-and-characteristics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Inadequate Identity and Access Management?

**Inadequate Identity and Access Management (IAM)** is the risk that arises when the many identities—human and machine—spread across the CI/CD ecosystem are too numerous, over-permissioned, stale, or poorly governed. It is not a single misconfigured account; it is the accumulated failure to consistently answer three questions for *every* identity in the pipeline: who or what is this, exactly what may it do, and should it still exist at all?

A modern engineering organisation runs its software supply chain across a fleet of independently administered systems: source control (SCM) such as GitHub, GitLab, or Bitbucket; CI/CD orchestrators such as Jenkins, GitHub Actions, GitLab CI, or CircleCI; artifact and package registries; container registries; secrets managers; and one or more cloud accounts. Each of these has its own notion of users, groups, service accounts, bot accounts, tokens, and roles. When identities are provisioned per-system with no central governance, the result is **identity sprawl**: hundreds or thousands of credentials, each a potential entry point, and no single place that knows who holds what.

> **CICD-SEC-2** is part of the OWASP Top 10 CI/CD Security Risks. It focuses specifically on the *governance of identities and their permissions* across the toolchain—distinct from how secrets are stored (CICD-SEC-6) or how the pipeline itself is configured.

### Core Concept

```
Well-Governed IAM:
  Identity source  -> central IdP/SSO for every system, MFA enforced
  Human accounts   -> federated, group-based, deprovisioned on offboarding
  Machine identity -> one scoped identity per workload, short-lived tokens
  Tokens / PATs    -> narrow scope, expiry set, rotated, inventoried
  Permissions      -> least privilege, consistent RBAC across the toolchain
  External access  -> time-boxed, read-only by default, reviewed
  Reviews          -> periodic access recertification, stale identities removed

Inadequate IAM:
  Identity source  -> local accounts per tool, MFA optional or off
  Human accounts   -> personal logins linger after people leave
  Machine identity -> one shared "ci-bot" reused everywhere, never rotated
  Tokens / PATs    -> broad scope, no expiry, pasted into many places
  Permissions      -> admin "to be safe", inconsistent per system
  External access  -> contractors and integrations with standing write access
  Reviews          -> nobody knows who holds what; nothing is ever removed
```

### Why It's Critical for CI/CD

The CI/CD ecosystem concentrates several conditions that make inadequate IAM especially damaging:

- It is **highly interconnected**. SCM triggers CI, CI pushes to registries, registries feed deployments, deployments run in cloud accounts. A single over-permissioned identity often has reach across several of these links.
- It is **machine-identity heavy**. Pipelines authenticate constantly with tokens and service accounts that no human watches, so an over-scoped or leaked machine credential is rarely noticed the way a suspicious human login might be.
- It **holds the keys to production**. The pipeline exists precisely to change production systems, so an identity that can influence the pipeline can often influence what ships to customers.
- It is **administered in silos**. Different teams own the SCM, the CI system, and the cloud account, so no one has an end-to-end view of the identities that span them.

## Why Does This Matter?

### Business Impact

- **Supply-Chain Compromise**: An attacker who takes over one over-permissioned identity can inject code, tamper with build artifacts, or publish malicious packages that reach every downstream consumer.
- **Production Breach**: CI/CD identities frequently hold cloud credentials; compromising them can mean direct access to production data and infrastructure.
- **Insider and Offboarding Risk**: Stale accounts and personal access tokens that outlive their owners give former employees and contractors a lingering way in.
- **Regulatory and Audit Failure**: Frameworks such as SOC 2, ISO 27001, and PCI-DSS require access reviews, least privilege, and timely deprovisioning; identity sprawl makes these controls impossible to evidence.
- **Loss of Attribution**: Shared accounts and generic bot users destroy the audit trail—after an incident, no one can say which human actually performed an action.

### Technical Impact

- **Lateral Movement Across the Toolchain**: A token scoped far beyond its need lets an attacker pivot SCM → CI → registry → cloud from a single foothold.
- **Privilege Escalation**: Broad group memberships and admin-by-default roles turn a low-value account into a high-value one.
- **Persistence**: Non-expiring PATs, unrotated deploy keys, and forgotten service accounts give attackers durable, quiet re-entry.
- **Bypassed Controls**: Local accounts that sidestep the central IdP also sidestep MFA, conditional access, and centralised logging.
- **Undetectable Abuse**: Machine identities that are never reviewed can be used for weeks without anyone noticing an anomaly.

## Technical Context

### The Identity Landscape of a Pipeline

Before you can govern identities, you have to see them. A typical delivery pipeline authenticates across all of these planes, each with its own identity model:

| System | Identity types | Typical credential |
|--------|----------------|--------------------|
| Source control (SCM) | Users, orgs/teams, bot accounts, deploy keys, apps | Password+MFA, SSH key, PAT, app installation token |
| CI/CD orchestrator | Users, service accounts, runners/agents, pipeline jobs | API token, job token, OIDC identity |
| Artifact / package registry | Users, publish tokens, CI service accounts | API key, registry token |
| Container registry | Robot accounts, pull/push credentials | Robot token, cloud IAM role |
| Secrets manager | App roles, machine identities | Token, role, OIDC binding |
| Cloud account(s) | IAM users, roles, workload identities | Access key, assumed role, federated OIDC |

### Common Failure Patterns

#### 1. Over-Permissioned Service Accounts and CI Tokens

```
# A CI job that only needs to push one image, but the token can do everything
CLOUD_ROLE   = "AdministratorAccess"        # needs: push to one ECR repo
GITHUB_TOKEN = permissions: write-all        # needs: read one repo
REGISTRY_KEY = scope: "read,write,delete,admin"  # needs: write one package
```

**Risk**: If the job, its logs, or its runner are compromised, the attacker inherits everything the token can do—usually far more than the job required.

#### 2. Local Accounts Bypassing Central IdP/SSO

```
# The org uses SSO... except:
jenkins  -> local admin account "admin", not tied to the IdP, no MFA
gitlab   -> a few "break-glass" local users that never got removed
registry -> basic-auth service user shared over chat
```

**Risk**: Local accounts skip MFA, conditional access, and central logging, and they survive offboarding because HR-driven deprovisioning only touches the IdP.

#### 3. Stale and Unused Identities and Tokens

```
PAT "old-migration-script"   last used: 14 months ago   expiry: never
Service account "legacy-ci"  owner left the company      still active
Deploy key on prod repo      added for a 2019 POC         never revoked
```

**Risk**: Every credential that outlives its purpose is pure attack surface with no offsetting benefit—and no one is watching it.

#### 4. Shared Accounts and Generic Bot Users

```
"deploy-bot"  used by 12 engineers and 3 pipelines
"team-svc"    password in a shared vault note, no MFA, no owner
```

**Risk**: Shared identities destroy attribution, cannot be safely rotated (everyone breaks at once), and typically accrue the union of everyone's permissions.

#### 5. Broad, Non-Expiring Personal Access Tokens (PATs)

```
Token scopes: repo, workflow, admin:org, delete_repo, packages   # everything
Expiration:   No expiration
Stored in:    a .env on a laptop, a CI variable, and a wiki page
```

**Risk**: A single leaked PAT with org-wide scope and no expiry is a master key that keeps working indefinitely.

#### 6. Unmanaged External Collaborators

```
outside-collaborator@contractor.example  role: Write on 40 repos
integration "some-saas-app"              scope: read/write code + CI, forever
```

**Risk**: External humans and third-party integrations often receive standing write access that is never time-boxed or reviewed after the engagement ends.

### How These Combine Into an Attack Path

```
Leaked over-scoped PAT (SCM)     -> read + write to many repos
        +
CI service account = admin       -> alter pipeline, read all CI secrets
        +
Registry token can publish       -> push a backdoored artifact
        +
Cloud role = Administrator       -> deploy it and reach production data
        =  full supply-chain compromise from one identity
```

## Real-World Impact

The incidents below are described as **classes of real, repeatedly observed events** rather than any single named breach, so the lessons generalise. Each maps directly to an inadequate-IAM root cause.

### Case Class 1: Leaked CI Token With Excessive Scope

**Failure**:
- A CI/CD pipeline stored a long-lived token whose scope covered the whole SCM organisation, not just the one repository the job used.
- The token was exposed—through a build log, a compromised dependency in the runner, or a misconfigured cache—and was still valid because it had no expiry.

**Impact**: With one credential, an attacker read private source across many projects and, because the token also allowed writes, could tamper with code and pipelines. This pattern recurs across public post-mortems of supply-chain incidents.

**Root Cause**: A machine identity provisioned with organisation-wide scope and no expiration, violating least privilege and short-lived-credential principles.

### Case Class 2: Stale Access After Offboarding

**Failure**:
- A departing employee or contractor retained access because their access lived in *local* tool accounts and personal access tokens that were never linked to the central IdP.
- Deprovisioning disabled the IdP login but left the SCM PAT, the CI local account, and a cloud access key untouched.

**Impact**: Former insiders—or anyone who later obtained their still-valid credentials—kept the ability to reach code and infrastructure long after the working relationship ended.

**Root Cause**: Identities outside central governance, plus no periodic access review to catch what offboarding missed.

### Case Class 3: Shared Bot Account as a Single Point of Failure

**Failure**:
- A single generic "deploy" or "automation" account was reused by many humans and pipelines, protected by a shared password with no MFA.
- Because everyone depended on it, its permissions had grown to the union of every task it had ever performed.

**Impact**: Compromise of that one account yielded broad, high-privilege access, and the shared nature meant the incident could not be attributed to any individual or safely contained without breaking everyone.

**Root Cause**: Shared identity plus permission accumulation plus missing MFA—three inadequate-IAM anti-patterns in one account.

## Prevalence and Characteristics

Inadequate Identity and Access Management is ranked **CICD-SEC-2** in the OWASP Top 10 CI/CD Security Risks precisely because it is both widespread and high-impact. Because identities span every tool in the delivery chain, some form of this weakness appears in the large majority of real environments.

Rather than cite precise figures (which vary by source and year), the defensible picture is:

- Identity sprawl is **the normal state, not the exception**—most organisations have far more machine identities than human ones, and far less visibility into them.
- The most commonly observed sub-issues are **over-permissioned tokens, non-expiring PATs, stale identities that survived offboarding, and local accounts that bypass SSO/MFA**.
- The impact is rated **severe**: because CI/CD identities bridge SCM, build, registry, and cloud, a single over-privileged one can escalate into a full supply-chain or production compromise.

> Note: exact counts of identities and tokens differ wildly between organisations. The durable takeaway is that machine identities vastly outnumber humans, are poorly inventoried, and are where inadequate IAM most often bites.

## Common Misunderstandings

### Myth 1: "We have SSO, so identity is handled"

**Reality**: SSO governs *human* logins to systems that are wired into it. It says nothing about machine identities, tokens, deploy keys, or the local "break-glass" accounts that quietly bypass it. Those are usually where the risk lives.

### Myth 2: "It's just a build bot, it doesn't need tight permissions"

**Reality**: Build identities are among the most powerful in the company—they can change code and push to production. A bot with admin rights is a bigger prize than most human accounts.

### Myth 3: "Tokens are fine as long as they're secret"

**Reality**: Secrets leak—via logs, forks, dependencies, and misconfiguration. Scope and expiry are what limit the blast radius *when* a token leaks, which is why a broad, non-expiring PAT is dangerous regardless of how carefully it is stored.

### Myth 4: "We removed their SSO login when they left"

**Reality**: Offboarding that only touches the IdP leaves behind personal access tokens, local tool accounts, SSH deploy keys, and cloud access keys. Complete deprovisioning has to reach every plane the person could authenticate to.

### Myth 5: "A shared automation account is simpler to manage"

**Reality**: Shared accounts are simpler to *create* and far harder to *govern*. They cannot be attributed, cannot be rotated without breaking everyone, and accumulate permissions until they are a jackpot for an attacker.

### Myth 6: "External collaborators only have access to what they need"

**Reality**: Outside collaborators and third-party integrations are routinely granted standing write access that is never time-boxed and is forgotten once the engagement ends. Their access should be reviewed on a schedule and expire by default.

## How Inadequate IAM Differs from Related CI/CD Risks

| Aspect | Inadequate IAM (CICD-SEC-2) | Insufficient Credential Hygiene (CICD-SEC-6) | Insufficient Flow Control (CICD-SEC-1) |
|--------|-----------------------------|----------------------------------------------|----------------------------------------|
| **Root cause** | Too many / over-scoped / stale identities | Secrets poorly stored, exposed, or unrotated | Missing guardrails on how changes flow to prod |
| **Where it lives** | Identity & permission model of every tool | Secret stores, variables, files, logs | Branch/pipeline/approval configuration |
| **Typical fix** | Least privilege, SSO+MFA, remove stale, OIDC | Vaulting, rotation, scanning for leaks | Required reviews, protected branches, gates |
| **Detection** | Access review, permission audit, identity inventory | Secret scanning, rotation tracking | Pipeline/config review |

## Key Takeaways

1. **Identity sprawl spans the whole toolchain**—SCM, CI, registries, secrets, and cloud each add identities that must be governed together, not in silos.
2. **Machine identities are the bigger risk**—they outnumber humans, hold production-grade power, and are rarely watched.
3. **Scope and expiry limit blast radius**—least privilege and short-lived, narrowly scoped credentials are what save you when something leaks.
4. **Stale is dangerous**—every identity that outlives its purpose is free attack surface; remove and rotate continuously.
5. **Govern centrally and consistently**—SSO+MFA everywhere, no local bypass accounts, no shared logins, and periodic access reviews across every system.

## How to Identify if You're Vulnerable

- [ ] Do you have a single inventory of every human and machine identity across SCM, CI, registries, and cloud?
- [ ] Is every system fronted by the central IdP/SSO with MFA enforced, and are there zero local bypass accounts?
- [ ] Does each CI job, service account, and token have least-privilege scope for exactly its task?
- [ ] Do all personal access tokens have a short expiry and a defined owner?
- [ ] Are machine credentials (keys, deploy keys, robot tokens) rotated on a schedule?
- [ ] Have all shared/generic accounts been eliminated in favour of per-identity access?
- [ ] Does offboarding revoke tokens, local accounts, and cloud keys—not just the SSO login?
- [ ] Is external collaborator and third-party integration access time-boxed and reviewed?
- [ ] Do you prefer short-lived OIDC federation over long-lived PATs for CI-to-cloud access?
- [ ] Do you run periodic access recertification and remove stale identities?

If you answered "no" or "not sure" to several of these, you likely have exploitable identity and access gaps today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers abuse over-permissioned, stale, and shared identities
- **[Prevention](prevention.md)**: Build least-privilege, centrally governed identity across the toolchain
- **[Examples](examples.md)**: Insecure vs. secure IAM in GitHub Actions, GitLab, Jenkins, and IdP/SSO config
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP Top 10 CI/CD lessons
- **[Practice](/practice)**: Test your understanding with hands-on challenges
