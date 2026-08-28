# CICD-SEC-6: Insufficient Credential Hygiene - Overview

## Table of Contents
- [What is Insufficient Credential Hygiene?](#what-is-insufficient-credential-hygiene)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detection](#prevalence-and-detection)
- [Common Misunderstandings](#common-misunderstandings)

## What is Insufficient Credential Hygiene?

**Insufficient Credential Hygiene** (CICD-SEC-6 in the OWASP Top 10 CI/CD Security Risks) is the failure to properly handle the large volume of secrets that flow through a modern engineering pipeline. Every build, test, deploy, and release step needs credentials—cloud keys, registry tokens, database passwords, signing keys, SaaS API tokens—and each of those secrets is created, stored, passed between steps, printed, cached, and eventually (ideally) rotated. When any link in that chain is careless, a secret leaks, lingers, or is over-privileged, and an attacker who obtains it inherits whatever access it grants.

It is important to see this as a *hygiene* problem rather than a single bug. The pipeline is not one place where secrets live; it is a river that secrets travel through. A key hardcoded in a repository, echoed into a build log, baked into a container image, stored as a long-lived static cloud key, and shared across a dozen pipelines is the *same underlying failure* viewed from five different vantage points: nobody owns the full lifecycle of the secret, so it accumulates exposure at every stage.

### Core Concept

```
Good Credential Hygiene:
  Storage      -> secrets in a manager / CI secret store, never in code or Git
  Cloud access -> short-lived OIDC-federated tokens, minted per job
  Scope        -> one secret per environment/pipeline, least privilege
  Rotation     -> rotated on a schedule AND immediately on any exposure
  Logs         -> masked/redacted, echoing secrets forbidden and detected
  Detection    -> repos + history scanned in CI and pre-commit (gitleaks)
  Humans       -> no standing human access to production secrets

Insufficient Hygiene:
  Storage      -> API keys hardcoded in pipeline YAML, Dockerfiles, code
  Cloud access -> long-lived static access keys with broad, unrotated scope
  Scope        -> one god-token shared by every pipeline and repo
  Rotation     -> secret unchanged for years; never rotated after a leak
  Logs         -> secrets printed by debug output and set -x, kept forever
  Detection    -> no scanning; leaks discovered by the attacker first
  Humans       -> every engineer can read prod secrets from the console
```

### Why It's Critical for CI/CD

CI/CD systems concentrate several conditions that make credential mishandling especially damaging:

- They are the **most credential-dense systems** an organisation runs—a single pipeline may touch cloud, registry, artifact repository, database, and a dozen SaaS APIs, so the blast radius of the pipeline's secret store is enormous.
- They are **highly automated and rarely watched in real time**, so a secret printed to a log or committed to a branch can sit exposed for months before anyone notices.
- They **fan out to many destinations**—public and private repos, forks, artifact registries, build caches, and logs—so a secret is copied to far more places than its author imagines.
- They are **trusted by production**: a credential harvested from the pipeline usually works directly against cloud accounts, registries, and prod, with no additional exploitation required.

## Why Does This Matter?

### Business Impact

- **Direct Cloud and Data Breach**: A leaked cloud key or database credential is not a stepping stone—it is often the whole attack. The finder reuses it and reads or destroys production data immediately.
- **Supply-Chain Compromise**: Registry and signing credentials let an attacker publish a malicious build that every downstream consumer trusts, turning one leaked token into thousands of victims.
- **Resource Abuse and Cost**: Harvested cloud keys are routinely used to spin up expensive compute for cryptomining, leaving the victim with the bill.
- **Regulatory and Contractual Fallout**: A leaked credential that exposes personal data triggers GDPR, HIPAA, and PCI-DSS breach obligations regardless of how "small" the mistake felt.
- **Persistent Access**: Long-lived static keys that are never rotated give an attacker durable access that survives password resets and employee departures.

### Technical Impact

- **Credential Reuse Against Production**: The pipeline secret is the same secret production trusts—there is no privilege boundary to cross.
- **Lateral Movement**: An over-shared "god" token grants access far beyond the one job that needed it, letting an attacker pivot across environments and repos.
- **Durable Footholds in Git History**: A secret removed from the latest commit but left in history remains fully recoverable by anyone who can clone the repository.
- **Artifact and Image Poisoning**: Credentials embedded in build artifacts or container images travel wherever those artifacts are distributed, including to untrusted networks.
- **Log-Based Disclosure**: Secrets echoed to build logs are indexed, cached, forwarded to log aggregators, and often readable by anyone with pipeline read access.

## Technical Context

### Where Secrets Leak in CI/CD

#### 1. Hardcoded in Code, Pipeline Definitions, and Dockerfiles

```yaml
# .github/workflows/deploy.yml  (INSECURE)
- name: Deploy
  run: aws s3 sync ./dist s3://prod-assets
  env:
    AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Dockerfile  (INSECURE)
ARG NPM_TOKEN=npm_9f8a...redacted...   # baked into an image layer forever
```

**Risk**: The secret is now in version control and/or image history—copied to every clone, fork, and pull of the image.

#### 2. Committed to Git (and Left in History)

```bash
$ git log -p --all | grep -i "secret\|api_key\|password"
# Removing the file in a later commit does NOT remove it from history:
$ git show <old-commit>:config/prod.env   # secret still fully recoverable
```

**Risk**: Deleting a leaked file "fixes" only the tip of the branch. The value lives on in history until it is both purged *and* rotated.

#### 3. Long-Lived Static Credentials with Broad Scope

```
Static AWS access key, created 3 years ago
  -> policy: AdministratorAccess ("*":"*")
  -> used by 14 pipelines across 3 teams
  -> never rotated, no expiry
```

**Risk**: One leak equals full account compromise, and the key works indefinitely with nothing to force it to expire.

#### 4. Printed to Build Logs / Exposed via Debug

```bash
$ set -x                       # shell tracing prints every expanded variable
$ curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com
+ curl -H 'Authorization: Bearer eyJhbGci...' https://api.example.com
$ echo "DEBUG token=$API_TOKEN"   # explicit echo defeats masking
```

**Risk**: The value is captured in logs that are retained, forwarded to aggregators, and often world-readable within the org.

#### 5. Readable by Any Job Step / Over-Shared

```
All secrets injected as environment variables for the whole job
  -> a compromised test dependency in step 2 reads the DEPLOY_KEY
     that only step 5 actually needed
```

**Risk**: Secrets scoped to the entire job or organisation are readable by unrelated (and potentially malicious) steps and pipelines.

#### 6. Baked into Artifacts and Images

```bash
$ docker history myapp:latest        # layers reveal build-time ARGs
$ tar tf build-artifact.tgz | grep -i env
config/.env.production               # secret shipped inside the artifact
```

**Risk**: Credentials embedded at build time travel with the artifact to registries, developer laptops, and untrusted environments.

### The Many Places a CI/CD Secret Lives

| Location | Typical Hygiene Failure | Consequence |
|----------|-------------------------|-------------|
| Source code / config | Hardcoded key or password | Leaks to every clone and fork |
| Git history | Removed from HEAD but not purged | Fully recoverable indefinitely |
| Pipeline YAML | Plaintext token in the workflow file | Readable by anyone with repo access |
| Build logs | Echoed / traced secret, masking bypassed | Retained and forwarded downstream |
| Environment variables | All secrets exposed to every step | Read by unrelated / malicious steps |
| Artifacts & images | Secret baked into a layer or bundle | Travels wherever the artifact goes |
| Cloud IAM | Long-lived, broad, unrotated static key | Durable full-account compromise on leak |

## Real-World Impact

### Case Study 1: Cloud Keys Committed to Public Repositories (ongoing class)

**Failure**:
- Developers routinely commit long-lived cloud access keys into public source repositories—in application config, test fixtures, notebooks, or pipeline files—often in a "quick fix" commit that is never cleaned up.
- Automated bots continuously scan public code-hosting platforms for credential patterns and use any hit within minutes.

**Impact**:
- Because the keys are long-lived and broadly scoped, finders immediately reuse them to spin up compute for cryptomining or to exfiltrate data—frequently before the developer has finished pushing follow-up commits.

**Root Cause**: Static credentials placed directly in code with no secret scanning to catch them and no short-lived alternative in use. Cloud providers now run their own secret-scanning partnerships and can automatically quarantine exposed keys precisely because this class is so common.

### Case Study 2: Secrets Recoverable from Git History (class)

**Failure**:
- A team notices a secret was committed and "removes" it in a new commit, or deletes the file, believing the problem is solved.
- The secret is never rotated because the working tree looks clean.

**Impact**:
- Anyone who clones the repository—including former contributors, fork owners, and cache/mirror services—can recover the original value from history and use a credential everyone believes is gone.

**Root Cause**: Treating a source-tree deletion as remediation. The durable lesson of this class is that *a leaked secret must be rotated, not merely deleted*—history rewriting reduces exposure but rotation is what actually invalidates the credential.

### Case Study 3: Secrets Leaked Through Build Logs (class)

**Failure**:
- Debug tracing (`set -x`), verbose tool output, or an explicit `echo` prints a secret that the CI platform would otherwise have masked.
- Logs are retained, indexed, and forwarded to a central logging system with broad read access.

**Impact**:
- The credential becomes readable by anyone with log access—often a much larger group than those trusted with the secret—and persists in log storage long after the build.

**Root Cause**: Masking only redacts the exact known value in the exact expected form; tracing and transformations defeat it. The lesson is to prevent secrets reaching logs at all, not to rely solely on redaction.

## Prevalence and Detection

Leaked and mishandled credentials are consistently among the **most common and most quickly exploited** findings in CI/CD and cloud security. Secret-scanning tools flag exposed credentials across a large fraction of active repositories, and automated harvesting means the window between exposure and abuse is frequently minutes, not days.

Rather than cite precise counts (which vary by source and year), the defensible picture is:

- Credential leakage is characterised as **highly prevalent and trivially exploitable**—a valid secret usually needs no exploit at all, just reuse.
- The most commonly observed sub-issues are **hardcoded secrets in code and pipeline files, secrets surviving in Git history, long-lived static keys, and secrets exposed in logs**.
- The impact is rated **high**: a single leaked credential can equal full cloud-account or supply-chain compromise with no further steps.

> Note: exact percentages and leak counts differ between reports and years. Treat any single figure as illustrative; the durable takeaway is that secrets leak constantly, are found fast, and are reused faster.

## Common Misunderstandings

### Myth 1: "The repo is private, so a hardcoded secret is fine"

**Reality**: Private repos are cloned to laptops, forked, mirrored, and made public by accident; contributors leave; access is broad. A secret in code is a secret shared with everyone who ever touches the repo. Keep secrets out of code regardless of visibility.

### Myth 2: "I deleted the secret, so it's gone"

**Reality**: Deleting a file removes it from the current tree, not from Git history, forks, caches, or logs. The only reliable remediation for an exposed secret is to *rotate* it; purging history is a cleanup step, not the fix.

### Myth 3: "The CI platform masks secrets in logs, so echoing is safe"

**Reality**: Masking matches the exact known value. Shell tracing, base64/JSON encoding, partial printing, and error messages routinely emit forms the masker never sees. Prevent secrets from reaching logs; don't rely on redaction to catch them.

### Myth 4: "One powerful token for all pipelines is simpler"

**Reality**: A shared, broadly scoped token means one leak compromises everything and makes rotation terrifying (it breaks every pipeline at once). Scope secrets narrowly per environment and job so a leak is contained and rotation is routine.

### Myth 5: "Static keys are fine as long as they're stored in the secret manager"

**Reality**: A secret manager protects storage, but a long-lived static key still leaks through logs, artifacts, and reuse. Prefer short-lived, OIDC-federated credentials that expire in minutes, so a leaked token is useless almost immediately.

### Myth 6: "We'd notice if a secret leaked"

**Reality**: Without automated secret scanning in CI and pre-commit, leaks are usually discovered by the attacker first. Detection has to be automated and continuous—humans do not spot a key buried in a diff or a log.

## How Insufficient Credential Hygiene Differs from Related CI/CD Risks

| Aspect | Insufficient Credential Hygiene (CICD-SEC-6) | Poisoned Pipeline Execution (CICD-SEC-4) | Insufficient PBAC (CICD-SEC-5) |
|--------|----------------------------------------------|------------------------------------------|--------------------------------|
| **Root cause** | Secrets mishandled across their lifecycle | Untrusted code runs in the pipeline | Pipeline identities over-permissioned |
| **What the attacker gets** | A reusable credential | Execution inside the pipeline | Excess access from a legitimate identity |
| **Typical fix** | Short-lived secrets, scanning, rotation | Isolate/untrust external input | Least-privilege pipeline roles |
| **Detection** | Secret scanning, log/leak monitoring | Pipeline change review, sandboxing | Access review, permission audit |

## Key Takeaways

1. **Secrets have a lifecycle, not a location**—creation, storage, transit, use, logging, and rotation all need hygiene, not just where the secret is "kept."
2. **A leaked credential is often the whole attack**—pipeline secrets are trusted by production, so reuse needs no further exploit.
3. **Deletion is not rotation**—an exposed secret is compromised until it is rotated, regardless of history cleanup.
4. **Short-lived beats well-stored**—OIDC-federated, minutes-long credentials shrink the value of any leak to almost nothing.
5. **Detection must be automated**—scan repos, history, and logs continuously; attackers scan yours already.

## How to Identify if You're Vulnerable

- [ ] Are any credentials hardcoded in code, pipeline YAML, or Dockerfiles today?
- [ ] Has your full Git history (not just HEAD) been scanned for secrets?
- [ ] Do you rely on long-lived static cloud keys instead of short-lived OIDC-federated credentials?
- [ ] Is any single secret shared across many pipelines, repos, or environments?
- [ ] Are secrets scoped to individual steps, or exposed to the whole job?
- [ ] Are secrets masked in logs, and is `echo`/`set -x` of secrets forbidden and detected?
- [ ] Could a secret be baked into a build artifact or container image layer?
- [ ] Is every secret on a rotation schedule, and rotated immediately on suspected exposure?
- [ ] Do humans have standing read access to production secrets?
- [ ] Do you run secret scanning both pre-commit and in CI on every change?

If you answered "yes" to the risky items or "no"/"not sure" to the controls, you likely have exploitable credential-hygiene gaps today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers harvest and reuse leaked credentials
- **[Prevention](prevention.md)**: Build a lifecycle of clean, short-lived, scoped secrets
- **[Examples](examples.md)**: Insecure vs. secure secret handling in real pipelines
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
