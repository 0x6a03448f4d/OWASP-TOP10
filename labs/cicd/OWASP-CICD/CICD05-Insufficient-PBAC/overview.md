# CICD-SEC-5: Insufficient PBAC (Pipeline-Based Access Controls) - Overview

## Table of Contents
- [What is Insufficient PBAC?](#what-is-insufficient-pbac)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Severity](#prevalence-and-severity)
- [Common Misunderstandings](#common-misunderstandings)

## What is Insufficient PBAC?

**Pipeline-Based Access Controls (PBAC)** are the permissions granted to the environment in which a pipeline runs—the runner or agent, and the identity, secrets, and network reach it carries while a job executes. **Insufficient PBAC** is the condition where that execution environment holds access *far beyond* what the specific job in front of it actually needs. The build step that only has to compile code can, in fact, read every organisation secret, assume a wildcard cloud role, reach the production control plane, and leave artefacts behind for the next job that lands on the same machine.

The core problem is that a CI/CD pipeline is a *programmable execution surface*. Anyone who can influence what a job runs—through a pull request, a dependency, a build script, a test—can run their code with whatever privileges the runner happens to hold at that moment. When those standing privileges are broad, a low-trust input is handed high-trust access. Insufficient PBAC is what turns an ordinary code contribution into a path to your secrets, your cloud account, and your other pipelines.

### Core Concept

```
Sufficient (least-privilege) PBAC:
  Runner lifetime   -> ephemeral: fresh VM/container per job, destroyed after
  Secrets in scope  -> only the secrets THIS job needs, for its environment
  Cloud identity    -> short-lived OIDC token, narrowly scoped role, per job
  Network reach     -> segmented: build runners cannot touch prod/control plane
  Trust isolation   -> public and private repos never share a runner
  Cache/artifacts   -> scoped, integrity-checked, cleared between trust levels

Insufficient PBAC:
  Runner lifetime   -> long-lived, non-ephemeral: state persists between jobs
  Secrets in scope  -> a single job can read ALL org/repo secrets
  Cloud identity    -> standing broad IAM role (e.g. wildcard) on the runner
  Network reach     -> build job can reach prod, k8s API, internal networks
  Trust isolation   -> forks/public PRs run on the same runner as prod deploys
  Cache/artifacts   -> shared caches poisoned once, reused by everyone after
```

### Why It's Critical for CI/CD

Pipelines concentrate several conditions that make excessive PBAC uniquely dangerous:

- They run **code that arrives from many trust levels**—maintainers, first-time contributors, forks, and transitive dependencies—often on the *same* infrastructure.
- They hold **the keys to everything downstream**: registry credentials, cloud roles, signing keys, and deploy access all converge on the runner.
- They are **trusted implicitly** by the systems they deploy to, so access obtained inside a pipeline usually needs no further exploit to reach production.
- Their **runners are frequently reused**—non-ephemeral machines retain secrets, caches, and artefacts that outlive the job that created them.

## Why Does This Matter?

### Business Impact

- **Secret and Credential Theft**: A single over-privileged job can harvest every secret present on the runner—cloud keys, registry tokens, signing material—and use them anywhere.
- **Cloud Account Takeover**: A standing broad IAM role attached to a runner means compromising one build equals compromising the cloud account it can assume.
- **Supply-Chain Compromise**: Access to signing keys or the deploy path lets an attacker ship malicious artefacts to real users under your name.
- **Lateral Movement Across Pipelines**: A poisoned shared runner or cache silently taints every higher-trust pipeline that later uses it.
- **Regulatory and Contractual Fallout**: Breaches originating in the build system expose customer data and trigger disclosure, audit, and liability obligations.

### Technical Impact

- **Privilege Escalation**: A low-trust job (fork PR, test) executes with the high-trust standing permissions of the runner it lands on.
- **Control-Plane Access**: Build jobs able to reach the Kubernetes API, cloud metadata service, or deployment tooling can alter production directly.
- **Persistence**: Non-ephemeral runners let an attacker implant backdoors, modified toolchains, or credential stealers that affect all subsequent jobs.
- **Cache and Artifact Poisoning**: Malicious content written to a shared cache or artifact store is consumed as trusted input by later, more privileged runs.
- **Cross-Tenant Exposure**: Shared runners spanning public and private repositories let untrusted code read data belonging to trusted projects.

## Technical Context

### Common Insufficient-PBAC Scenarios

#### 1. A Job That Can Read All Secrets

```yaml
# Every secret is injected into every job's environment, regardless of need.
# A compile step that needs nothing can now read the production deploy key.

env:
  AWS_ACCESS_KEY_ID:     ${{ secrets.AWS_ACCESS_KEY_ID }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  NPM_PUBLISH_TOKEN:     ${{ secrets.NPM_PUBLISH_TOKEN }}
  PROD_DEPLOY_KEY:       ${{ secrets.PROD_DEPLOY_KEY }}
  SIGNING_GPG_KEY:       ${{ secrets.SIGNING_GPG_KEY }}
```

**Risk**: Any code the job runs—including a malicious dependency or a poisoned test—can exfiltrate all of these at once.

#### 2. Standing Broad Cloud Role on the Runner

```
# Self-hosted runner instance profile / attached role
Effect:   Allow
Action:   "*"
Resource: "*"          # every job on this runner inherits full account access
```

**Risk**: The runner's identity is the blast radius. Any job that executes there can act as the whole cloud account, with no per-job scoping.

#### 3. Non-Ephemeral (Reused) Runners

```
Job A (trusted deploy)  -> writes ~/.aws/credentials, docker login token,
                           kubeconfig, build cache to the runner's disk
        (runner is NOT destroyed)
Job B (untrusted PR)    -> lands on the SAME runner, reads the leftover
                           credentials, caches, and workspace from Job A
```

**Risk**: State from a high-trust job persists and is harvested by the next, lower-trust job that reuses the machine.

#### 4. Shared Runners Across Trust Boundaries

```
Public repo (accepts fork PRs)  \
                                 >--- SAME self-hosted runner pool
Private repo (holds prod creds) /
```

**Risk**: Untrusted, attacker-authored code from a public fork executes on infrastructure that also serves the private, production-credentialed pipeline.

#### 5. Build Jobs That Reach the Control Plane

```
# Runner sits inside the production VPC with no network segmentation
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/   # cloud metadata
kubectl --server https://prod-api:6443 get secrets -A                     # cluster API
psql -h prod-db.internal -U app                                           # prod database
```

**Risk**: A step that only had to build software can instead talk directly to production systems and the orchestration control plane.

### Where Excessive Pipeline Access Hides

| Dimension | Over-Broad State | Consequence |
|-----------|------------------|-------------|
| Secrets scope | All org/repo secrets in every job | One job harvests everything |
| Cloud identity | Standing wildcard role on runner | Build compromise = account takeover |
| Runner lifetime | Long-lived, reused between jobs | Credential/artifact carry-over |
| Trust isolation | Public + private share runners | Untrusted code on trusted host |
| Network reach | Runner can hit prod / control plane | Direct production impact |
| Cache / artifacts | Shared, unverified, cross-run | Poisoning persists across pipelines |

## Real-World Impact

### Case Study 1: Poisoned-Pipeline Execution on Over-Privileged Runners (incident class)

**Insufficient PBAC**:
- Public repositories accepted pull-request-triggered pipelines that ran on self-hosted runners holding production secrets and broad cloud roles.
- The pipeline executed build and test scripts taken from the untrusted PR branch itself, with full access to the runner's standing privileges.

**Impact**:
- A crafted pull request modified a build or test step to print, encode, and exfiltrate the environment—cloud keys and deploy tokens included—to an attacker-controlled endpoint.
- Because the runner's role was broad and standing, the stolen identity granted far more than the build ever needed.

**Root Cause**: Untrusted input executed with the runner's excessive standing access, with no per-job scoping or trust isolation. This is the classic Poisoned Pipeline Execution (PPE) outcome amplified by insufficient PBAC.

### Case Study 2: Non-Ephemeral Self-Hosted Runner Reuse (incident class)

**Insufficient PBAC**:
- Self-hosted runners were long-lived: after a trusted job wrote cloud credentials, container-registry logins, and caches to disk, the machine was returned to the pool without being torn down.

**Impact**:
- A subsequent lower-trust job—or a job triggered by a fork—landed on the same machine and read the leftover credentials and workspace, inheriting access it was never granted.
- Attackers who reached one job could also implant persistence (modified tools, cron, credential stealers) that affected every later job on that runner.

**Root Cause**: Reused execution environments that retain state between jobs of different trust levels. Ephemeral, single-use runners eliminate the carry-over entirely.

### Case Study 3: Shared Cache / Artifact Poisoning (incident class)

**Insufficient PBAC**:
- A build cache or artifact repository was writable by low-trust jobs and consumed, unverified, by higher-trust pipelines (including deploy pipelines) as trusted input.

**Impact**:
- Malicious content written once—a tampered dependency, a backdoored binary, a poisoned cache entry—was reused by many downstream runs, silently propagating into artefacts that were then signed and shipped.

**Root Cause**: Shared, cross-trust caches and artifact stores with no integrity verification or trust separation, so a single write influences every later consumer.

## Prevalence and Severity

Insufficient PBAC is entry **CICD-SEC-5** in the OWASP Top 10 CI/CD Security Risks. It is both common and high-impact because the fix requires deliberately scoping access that platforms, by default, make easy to grant broadly.

Rather than cite precise figures (which vary by source and year), the defensible picture is:

- Excessive pipeline access is **widespread**: standing broad cloud roles, all-secrets-everywhere injection, and reused self-hosted runners are common defaults teams never revisit.
- The most damaging patterns are **non-ephemeral runners, shared runners across trust boundaries, and unscoped secrets/roles**.
- The impact is rated **severe**: outcomes range from full secret theft to cloud-account takeover and supply-chain compromise, frequently with no memory-corruption exploit—just abuse of granted access.

> Note: exact incident counts differ between reports. The durable takeaway is that the runner's standing privileges define the blast radius of every job it runs—so those privileges, not the job's intent, are what an attacker inherits.

## Common Misunderstandings

### Myth 1: "Only trusted people can trigger our pipelines"

**Reality**: Pull requests, forks, dependencies, and test fixtures all inject code into the pipeline. The trigger may be a stranger's PR or a transitive package—the runner cannot tell the difference and runs it with whatever access it holds.

### Myth 2: "Secrets are safe because they're encrypted at rest"

**Reality**: Encryption protects storage, not use. Once a secret is injected into a job's environment, any code that job runs can read it in plaintext. The question is *which jobs* receive it—scope, not encryption.

### Myth 3: "A self-hosted runner is fine to reuse—we control it"

**Reality**: A reused runner accumulates credentials, caches, and workspaces across jobs. Controlling the host does not stop one job from reading what a previous, higher-trust job left behind. Ephemerality is the control.

### Myth 4: "One runner pool is simpler; trust boundaries add overhead"

**Reality**: Sharing a runner between public (fork-triggered) and private (production-credentialed) work places untrusted code on trusted infrastructure. The overhead of separate pools is trivial next to a cloud-account breach.

### Myth 5: "A broad cloud role is easier than maintaining scoped ones"

**Reality**: A standing wildcard role makes the runner's identity the whole account. Short-lived, per-job OIDC tokens scoped to exactly what the job needs are both safer and, once set up, no harder to operate.

### Myth 6: "The build environment is throwaway, so access there doesn't matter"

**Reality**: The build environment is the most trusted point in the software lifecycle—it can sign and ship code. Access there matters *more*, not less, than access in production.

## How Insufficient PBAC Differs from Related CI/CD Risks

| Aspect | Insufficient PBAC (CICD-SEC-5) | Poisoned Pipeline Execution (CICD-SEC-4) | Insufficient Credential Hygiene (CICD-SEC-6) |
|--------|--------------------------------|------------------------------------------|----------------------------------------------|
| **Root cause** | Runner holds access beyond the job's need | Attacker injects code into the pipeline | Secrets sprawl, over-broad or stale credentials |
| **What it governs** | Blast radius of a running job | How malicious code gets executed | How secrets are created, stored, rotated |
| **Typical fix** | Least privilege, ephemeral + isolated runners | Separate untrusted input from privileged execution | Scope, short-lived tokens, rotation, no plaintext |
| **Relationship** | Amplifies PPE: broad access = bigger blast | Often the delivery mechanism for PBAC abuse | Overlaps on secret scoping and OIDC |

## Key Takeaways

1. **The runner's privileges are the job's privileges**—whatever the execution environment holds, the code it runs inherits.
2. **Scope everything to the job**—secrets, cloud roles, and network reach should match what one job needs, not the whole organisation.
3. **Ephemeral beats reused**—a fresh, single-use runner per job removes credential and artifact carry-over.
4. **Isolate by trust level**—public and private, build and deploy, must not share runners or caches.
5. **Prefer short-lived identities**—OIDC tokens scoped per job beat standing broad cloud roles every time.

## How to Identify if You're Vulnerable

- [ ] Can a single job read secrets it does not need (all org/repo secrets injected everywhere)?
- [ ] Are any runners non-ephemeral—reused across jobs without being destroyed?
- [ ] Do public/fork-triggered pipelines share a runner pool with private, credentialed pipelines?
- [ ] Does any runner carry a standing broad cloud role (wildcard actions/resources)?
- [ ] Can a build job reach production, the cloud metadata service, or the cluster control plane?
- [ ] Are caches or artifacts writable by low-trust jobs and consumed unverified by high-trust ones?
- [ ] Do you use short-lived OIDC credentials, or long-lived static cloud keys stored as secrets?
- [ ] Are build and deploy responsibilities split across separately scoped runners?
- [ ] Are workspaces and caches cleared between runs of different trust levels?
- [ ] Is runner network access segmented from sensitive internal systems?

If you answered "yes" to the risk questions or "no" to the control questions, your runners likely grant far more than any single job requires.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers abuse over-privileged runners and shared state
- **[Prevention](prevention.md)**: Least-privilege, ephemeral, isolated pipeline access
- **[Examples](examples.md)**: Insecure vs. secure runner and secret scoping across platforms
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
