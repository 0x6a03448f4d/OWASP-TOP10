# CICD-SEC-9: Improper Artifact Integrity Validation - Overview

## Table of Contents
- [What is Improper Artifact Integrity Validation?](#what-is-improper-artifact-integrity-validation)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Improper Artifact Integrity Validation?

**Improper Artifact Integrity Validation** occurs when a delivery pipeline consumes and ships an artifact—source, a dependency, a container image, a build output, an IaC plan—without verifying that it is exactly the artifact that was *supposed* to be produced, by the process that was supposed to produce it. Every step in a CI/CD pipeline is a hand-off: source moves from SCM to the CI runner, dependencies are pulled from registries, build outputs are pushed to an artifact store, and a deployer pulls those outputs into production. Wherever a hand-off happens with **no integrity check**, an attacker who can influence the resource in transit or at rest can substitute a malicious version, and the pipeline will faithfully build, sign off on, and deploy it.

The risk is not a bug in any single tool. It is the **absence of a verifiable chain of custody** across the whole software supply chain. A pipeline can be perfectly configured, fully patched, and still ship a backdoor—because at no point did anything ask "is this artifact the one we trust, and can I prove how it was built?"

### Core Concept

```
Integrity-Validated Pipeline:
  Dependencies -> pulled by content digest, checksum/signature verified
  Build inputs -> source commit verified, hermetic/isolated build
  Build output -> signed (cosign) + provenance attestation generated (SLSA)
  Registry     -> image referenced by immutable digest, not a moving tag
  Deploy gate  -> admission controller verifies signature + provenance
  Result       -> only artifacts with a proven origin ever run

No Integrity Validation:
  Dependencies -> pulled by floating version/tag, no checksum enforced
  Build inputs -> whatever is on the runner disk, trusted implicitly
  Build output -> unsigned, no record of how it was built
  Registry     -> image referenced by mutable tag (":latest", ":prod")
  Deploy gate  -> runs whatever the tag currently points at
  Result       -> a swapped artifact deploys with no alarm
```

### Where the Hand-offs Are

Artifacts change hands many times, and each arrow below is a place integrity can be lost:

```
Developer -> SCM -> CI runner -> dependency registries
                        |
                        v
                  build outputs -> artifact registry / cache
                        |
                        v
                     CD / deployer -> production cluster
```

If a signature is generated at build time but never *verified* at deploy time, integrity validation is still "improper"—producing evidence is worthless unless something enforces it.

### Why It's Critical in CI/CD

- The pipeline is **trusted by default**: whatever it outputs is treated as legitimate and shipped straight to production, often with no human in the loop.
- Artifacts are **referenced by mutable names** (tags, "latest", branch names) far more often than by immutable content digests, so the same reference can silently point at different bytes over time.
- Artifacts are **reused across stages and caches**—a poisoned dependency or a tampered intermediate image propagates into every downstream build.
- A single compromised artifact is **replicated at scale**: it is pulled by every environment and, for shipped software, by every customer.

## Why Does This Matter?

### Business Impact

- **Downstream Supply-Chain Breach**: A tampered build output shipped to customers turns your release channel into a malware distribution channel—the SolarWinds-class scenario.
- **Production Compromise**: A swapped image deployed to your own cluster gives an attacker code execution inside your infrastructure with the privileges the workload holds.
- **Loss of Trust and Attestation**: Customers, auditors, and regulators increasingly require provenance (SLSA, executive supply-chain mandates); an unverifiable chain of custody fails those requirements.
- **Silent, Long-Dwell Compromise**: Because nothing flags the swap, a malicious artifact can run in production for months before discovery, widening blast radius and remediation cost.

### Technical Impact

- **Arbitrary Code in Production**: The injected artifact runs with whatever access the deployed workload has—service accounts, cloud roles, secrets.
- **Persistence and Lateral Movement**: A backdoored base image or dependency re-poisons future builds, surviving redeploys and spreading across services.
- **Cache and Registry Poisoning**: A tampered intermediate (build cache, mirror, internal registry) is trusted implicitly by every consumer.
- **Undetectable Drift**: Without content-addressed references, deployed bytes can diverge from reviewed source with no diff to catch it.

## Technical Context

### Common Failure Scenarios

#### 1. No Signing or Verification of Build Outputs and Images

```bash
# Build and push, with nothing proving what was built
docker build -t registry.example.com/api:prod .
docker push registry.example.com/api:prod
# Deployer later pulls "api:prod" and runs it. No signature is
# produced and none is checked -- any push to that tag ships.
```

**Risk**: Anyone who can write to the registry (or intercept the push/pull) can substitute a malicious image and it deploys unchallenged.

#### 2. Trusting Artifacts by Mutable Tag Instead of Content Digest

```dockerfile
# Mutable -- ":latest" can point at different bytes tomorrow
FROM node:18

# Immutable -- pinned to exact content, cannot be swapped
FROM node:18@sha256:0d1f3c9e...<full-digest>
```

**Risk**: A tag is a pointer, not the content. Re-tagging, a compromised upstream, or a registry MITM changes what the "same" reference resolves to.

#### 3. No Provenance / Attestation of How an Artifact Was Built

```
# The artifact exists, but there is no signed record of:
#   - which source commit it was built from
#   - which builder / workflow produced it
#   - which build parameters and dependencies were used
# Without provenance you cannot distinguish a legitimate build
# from one an attacker produced on their own machine.
```

**Risk**: You can verify *a* signature yet still have no idea whether the signed thing came from your trusted pipeline or an attacker's laptop.

#### 4. Unverified Artifacts Pulled from Caches, Mirrors, and Build Stages

```bash
# Dependency pulled by floating range, no lockfile hash enforced
pip install requests            # resolves to whatever the index serves now
npm install                     # ignores integrity if lockfile absent/stale

# Multi-stage build trusts an intermediate image implicitly
COPY --from=builder /out/app /app/app   # 'builder' assumed clean
```

**Risk**: Package mirrors, internal proxies, and build caches are hand-offs too; if their contents aren't checksum/signature-verified, a poisoned entry flows straight into the build.

#### 5. Deployment Accepting Unsigned Images / Unvalidated IaC

```bash
# Cluster admits any image, signed or not
kubectl apply -f deploy.yaml    # no admission policy on image provenance

# Infrastructure applied with no plan review / no state integrity check
terraform apply -auto-approve   # applies whatever the plan resolved to
```

**Risk**: The final gate—where you could still refuse an untrusted artifact—waves everything through.

### Where Integrity Is Lost in the Pipeline

| Hand-off | Typical Failure | Consequence |
|----------|-----------------|-------------|
| SCM → CI | Unverified commit/tag, no signed source | Build runs attacker-modified source |
| Registry → CI | Dependencies by floating version, no hash | Poisoned dependency compiled in |
| CI → artifact store | Output unsigned, no provenance emitted | Origin unprovable, swap undetectable |
| Store → CD | Referenced by mutable tag, not digest | "Same" reference resolves to new bytes |
| CD → production | No admission/deploy-time verification | Unsigned/untrusted artifact runs |
| Any cache/mirror | Intermediate trusted implicitly | One poisoned entry serves everyone |

## Real-World Impact

The incidents below are described as **classes** of build-and-artifact tampering. Specific figures are omitted deliberately; the durable lesson is the mechanism, not a statistic.

### Case Class 1: Build-System Compromise and Signed Backdoor Distribution

**Failure**:
- An attacker gains a foothold in the build environment and injects malicious code *during* the build, after source review but before the artifact is signed and released.
- Because the tampering happens inside the trusted build step, the resulting artifact is signed with the vendor's legitimate key and distributed through the normal update channel.

**Impact**:
- Every downstream consumer that trusts the vendor's signature installs the backdoored build, because the signature is genuine—it attests the bytes, not the integrity of the process that produced them.

**Root Cause**: Signing proved the artifact came from the vendor's pipeline but *nothing proved the pipeline itself had not been tampered with*. This is the SolarWinds-class pattern: integrity validation stopped at "is it signed?" and never asked "was it built hermetically from the reviewed source, and can we independently attest that?" It is the reason build-time **provenance** (SLSA) exists alongside signing.

### Case Class 2: Mutable-Tag / Registry Substitution

**Failure**:
- Deployments reference container images by a moving tag (for example `:latest` or `:prod`) rather than by content digest.
- An attacker with push access, a compromised CI token, or a position to tamper with a registry/mirror re-points that tag at a malicious image.

**Impact**:
- The next rollout—or an autoscaling event that pulls the image afresh—runs the substituted image. Nothing in the deploy config changed, so no review catches it.

**Root Cause**: Trust placed in a mutable pointer instead of immutable content, with no signature verification at admission time to reject an unexpected image.

### Case Class 3: Poisoned Dependency / Cache Entry Consumed Without Verification

**Failure**:
- A build resolves dependencies from a public index, an internal mirror, or a shared build cache without enforcing pinned hashes or publisher signatures.
- A malicious or tampered package version (typosquat, hijacked maintainer account, poisoned cache) is served and compiled into the artifact.

**Impact**:
- The malicious code executes during the build (and/or at runtime), and because the final artifact is treated as trusted, it ships downstream.

**Root Cause**: Dependency and cache hand-offs were consumed on trust; no checksum/lockfile-hash or signature verification gated what entered the build.

## Prevalence and Detectability

Improper Artifact Integrity Validation appears in the **OWASP Top 10 CI/CD Security Risks** as **CICD-SEC-9**. It is common because signing and, especially, *verification* and *provenance* are still frequently treated as optional maturity add-ons rather than default gates.

Rather than cite precise counts, the defensible picture is:

- Producing artifacts is universal; **verifying** them end-to-end is not—many pipelines sign nothing, and many that sign never check the signature at deploy time.
- Reference-by-mutable-tag is the norm, so the **content that runs is rarely pinned** to what was reviewed.
- Impact is rated **severe**: a single unverified hand-off can lead to arbitrary code in production or a downstream supply-chain breach.
- The gap is **readily detectable**—you can inspect whether images are digest-pinned, whether signatures are verified at admission, and whether provenance is generated and checked.

> Note: exact breach counts and percentages vary by source and year. Treat any single figure as illustrative; the durable takeaway is that unverified hand-offs are common and that the fix is an enforceable chain of custody, not a one-off scan.

## Common Misunderstandings

### Myth 1: "Our artifact is signed, so its integrity is validated"

**Reality**: Signing only helps if something *verifies* the signature before use, against a trusted identity, at every hand-off. A signature that is generated and never checked—or checked against no expected signer—adds nothing. Signing also attests the bytes, not the build; that is why provenance matters too.

### Myth 2: "We pull `:latest`, which is always the newest good build"

**Reality**: A tag is a mutable pointer. "Newest" can mean "whatever was pushed last, by anyone with access, including an attacker." Only a content digest is a stable identity for specific bytes.

### Myth 3: "Provenance is the same as a signature"

**Reality**: A signature says "these bytes came from this key." Provenance/attestation (SLSA, in-toto) says "these bytes were produced by *this builder*, from *this source*, with *these inputs*." You need both: authenticity of the artifact *and* integrity of how it was built.

### Myth 4: "It's built inside our CI, so the output is trustworthy"

**Reality**: The build environment itself is an attack surface (see Poisoned Pipeline Execution). Trust must be *proven* with an attestation tied to a hardened, isolated build—not assumed because the runner is "ours."

### Myth 5: "Scanning the image for vulnerabilities covers this"

**Reality**: A vulnerability scan asks "does this contain known-bad packages?" Integrity validation asks "is this the exact artifact my trusted pipeline produced?" A cleanly scanning image can still be a substituted, backdoored one.

### Myth 6: "Verifying at the registry is enough"

**Reality**: Integrity must hold at *every* hand-off, and the final, non-negotiable gate is deploy/admission time. If the cluster will run an unsigned or unattested image, earlier checks can be bypassed by going straight to the last step.

## How This Differs from Related CI/CD Risks

| Aspect | Improper Artifact Integrity Validation (CICD-SEC-9) | Poisoned Pipeline Execution (CICD-SEC-4) | Insufficient Credential Hygiene (CICD-SEC-6) |
|--------|------------------------------------------------------|-------------------------------------------|-----------------------------------------------|
| **Root cause** | Hand-offs consumed without proving integrity/provenance | Attacker-controlled input executes in the pipeline | Secrets exposed, over-scoped, or unrotated |
| **Where it lives** | Every artifact hand-off (SCM→CI→registry→CD) | Build/job definition and execution | Credential storage and access |
| **Typical fix** | Sign + attest, pin by digest, verify at admission | Isolate/sandbox builds, control pipeline inputs | Scope, vault, rotate, use short-lived OIDC |
| **Detection** | Check for digest pinning, signature + provenance enforcement | Review triggers and untrusted-input paths | Secret scanning, access audits |

## Key Takeaways

1. **Integrity is a chain, not a checkpoint**—every hand-off from SCM to production must verify the artifact it receives.
2. **Sign *and* verify**—evidence that is produced but never enforced protects nothing.
3. **Pin content, not names**—reference artifacts by immutable digest, never by a mutable tag.
4. **Prove the build, not just the bytes**—generate and check provenance/attestations (SLSA, in-toto), because SolarWinds-class attacks produce genuinely signed backdoors.
5. **Enforce at admission**—the deploy gate must refuse anything that is not signed and attested by a trusted identity.

## How to Identify if You're Vulnerable

- [ ] Are build outputs and container images cryptographically signed (for example with cosign/Sigstore)?
- [ ] Are those signatures *verified* before the artifact is used or deployed—against an expected signer identity?
- [ ] Is build provenance generated (SLSA) and checked, so you know which source and builder produced each artifact?
- [ ] Are images and dependencies referenced by immutable digest rather than a mutable tag?
- [ ] Are dependency hashes / lockfile integrity enforced, and are mirrors and caches verified too?
- [ ] Does an admission controller (or deploy gate) reject unsigned or unattested artifacts in production?
- [ ] Is IaC/config validated (plan reviewed, state integrity protected) before it is applied?
- [ ] Are signing keys protected—keyless/OIDC or KMS-backed—so an attacker cannot simply sign their own artifact?
- [ ] Do you have an end-to-end record (SBOM + attestations) linking deployed bytes back to reviewed source?

If you answered "no" or "not sure" to several of these, an attacker who reaches any one hand-off can likely ship a malicious artifact to production today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers tamper with artifacts at each hand-off
- **[Prevention](prevention.md)**: Build an enforceable, end-to-end chain of custody
- **[Examples](examples.md)**: Insecure vs. secure signing, provenance, and digest pinning
- **[CI/CD Security Track](/learn/cicd)**: Continue with the other OWASP CI/CD Top 10 risks
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
