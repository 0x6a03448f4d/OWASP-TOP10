# CICD-SEC-9: Improper Artifact Integrity Validation - Attack Vectors

## Table of Contents
- [Understanding Artifact Integrity Attacks](#understanding-artifact-integrity-attacks)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Hand-off Failures](#chaining-hand-off-failures)

## Understanding Artifact Integrity Attacks

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in pipelines you own or are authorised to test.

An artifact-integrity attack does not require breaking cryptography or finding an application bug. It requires finding **one hand-off where nothing checks the artifact** and substituting a malicious version there. The pipeline's own trust does the rest: it builds, promotes, and deploys the attacker's artifact exactly as if it were legitimate, because there is no step that would ever say no.

The attacker's objective in this category is to get malicious bytes into a place the pipeline trusts, so that:

- The malicious artifact is **consumed by the build** (poisoned dependency, cache, or base image), or
- The malicious artifact is **promoted and deployed** (swapped image, re-pointed tag, tampered build output), and
- No signature check, digest pin, or provenance verification exists to reject it.

### Core Attack Flow

```
1. Locate an unverified hand-off
   |
   v  SCM->CI, dep pull, cache, registry push/pull, deploy admission
2. Position to influence the artifact
   |
   v  push access, compromised token, MITM, poisoned mirror/cache
3. Substitute or tamper
   |
   v  swap image, re-point tag, inject dependency, edit build output
4. Let trust carry it
   |
   v  pipeline builds/promotes/deploys the artifact with no integrity gate
5. Execute in production / downstream
   |
   v  arbitrary code runs; malicious release reaches consumers
```

## Common Attack Patterns

### 1. Mutable-Tag Substitution

Deployments reference an image by a moving tag, so re-pointing the tag changes what runs—no config diff, no review.

```bash
# Deploy manifest trusts a mutable tag
image: registry.example.com/api:prod

# Attacker with push access re-points the tag to a malicious image
docker tag malicious:local registry.example.com/api:prod
docker push registry.example.com/api:prod
# Next rollout / autoscale pull runs the attacker's image
```

**Payoff**: code execution in production with the workload's identity and secrets, invisible to anyone reviewing the (unchanged) manifest.

### 2. Unsigned-Image Deployment

The cluster admits any image regardless of origin, so an attacker only needs to get an image into the registry (or MITM the pull).

```bash
# No admission policy verifies a signature, so this succeeds:
kubectl set image deploy/api api=registry.example.com/api@sha256:<attacker-digest>
# The digest is "valid" -- it just isn't YOUR artifact, and nothing checks.
```

**Payoff**: the last possible gate (admission) waves the artifact through; earlier controls become moot.

### 3. Poisoned Dependency Consumed Without Hash Verification

The build resolves packages by a floating range with no enforced integrity, so a hijacked or typosquatted version is compiled in.

```
# requirements.txt with no hashes -> index decides what you get
requests>=2

# A hijacked release or dependency-confusion package resolves and installs;
# its setup/postinstall runs in the build with the runner's privileges.
```

**Payoff**: code execution during the build and a backdoor baked into the artifact—then shipped as "trusted output."

### 4. Build-Cache and Mirror Poisoning

Shared caches and internal mirrors are hand-offs trusted implicitly. Tamper with the cache once and every consumer inherits it.

```
# Attacker writes a malicious entry keyed like a legitimate cache hit
# (dependency cache, layer cache, remote build cache).
# Subsequent builds "restore" the poisoned artifact instead of rebuilding,
# with no checksum comparison against a trusted source.
```

**Payoff**: broad, quiet distribution—one poisoned entry serves many pipelines and survives across builds.

### 5. Intermediate / Multi-Stage Artifact Tampering

Multi-stage builds and stage-to-stage promotions trust the previous stage's output without re-verifying it.

```dockerfile
# Stage 'builder' output is copied on faith
COPY --from=builder /out/app /app/app
# If 'builder' pulled a tampered base or dependency, the tampering
# is carried into the final image unchecked.
```

**Payoff**: a compromise early in the graph propagates to the released artifact with no gate between stages.

### 6. In-Transit Substitution (MITM on Push/Pull)

Without signature verification, an attacker positioned between the pipeline and a registry/mirror can swap bytes in flight.

```
# Pull over a channel that isn't integrity-checked end-to-end:
GET /v2/api/blobs/sha256:<expected>   ->  attacker returns different bytes
# If nothing verifies the content against a trusted signature, it is used.
```

**Payoff**: the consumer runs substituted content while believing it pulled the intended artifact.

### 7. Build-System Compromise Producing a Signed Backdoor

The most damaging pattern: the attacker tampers *inside* the trusted build, so the malicious output is signed with the real key.

```
# Malicious step injected into the build environment adds code
# AFTER source review but BEFORE signing/release.
# The release is signed with the legitimate key and distributed normally.
# Consumers verify the signature -> it passes -> backdoor installed.
```

**Payoff**: a genuinely signed malicious release—the SolarWinds-class outcome. Signing alone cannot detect it; only build **provenance** tied to a hermetic build can.

### 8. Provenance-Free Promotion

An artifact is promoted from build to deploy with no attestation of origin, so an artifact built anywhere is indistinguishable from one built by the trusted pipeline.

```
# Promotion step: "if it's in the 'approved' registry, ship it."
# An attacker who can write to that registry -- or produce a look-alike
# artifact -- is promoted identically, because origin is never proven.
```

**Payoff**: an attacker-built artifact rides the promotion path to production.

### 9. Unvalidated IaC / Config Applied to Production

Infrastructure and config are artifacts too. Applied without plan review or state-integrity protection, tampered IaC changes the environment directly.

```bash
# Tampered module / plan applied with no gate
terraform apply -auto-approve
# A modified module source or poisoned provider mirror alters
# security groups, IAM, or image references with no verification.
```

**Payoff**: the attacker rewrites the environment (open ingress, over-broad roles, swapped images) with no artifact-integrity check to stop it.

### 10. Signature Present but Never Verified

Some pipelines *sign* artifacts yet never enforce the check, or verify against no expected identity—so the signature is decorative.

```bash
# Artifact is signed at build time... and consumed with:
docker pull registry.example.com/api@sha256:<digest>   # no cosign verify
# Any image (signed by anyone, or unsigned) is accepted identically.
```

**Payoff**: the organisation believes it is protected while the enforcement step that would matter does not exist.

## Chaining Hand-off Failures

Individually small gaps combine into full compromise:

```
Compromised CI token (from a leaked secret)
        +
Registry accepts pushes to a mutable ":prod" tag
        +
Cluster admits images with no signature verification
        =  attacker pushes a malicious image, re-points the tag,
           and the next rollout runs it -- no code bug required
```

Another common chain—the SolarWinds-class shape:

```
Foothold in the build environment (Poisoned Pipeline Execution)
        -> inject code during the build, before signing
        -> artifact is signed with the legitimate key
        -> consumers verify only the signature (no provenance)
        =  a genuinely signed backdoor is distributed and trusted
```

## Key Takeaways

1. **Attackers hunt for the one unverified hand-off**—they don't need to break every step, only the weakest link in the chain.
2. **Mutable tags are the easiest target**—re-pointing a tag changes production with no visible diff.
3. **Signing without verification protects nothing**—and verifying without provenance can't catch a build-time backdoor.
4. **Caches, mirrors, and intermediate stages are hand-offs too**—poison one and it serves everyone downstream.
5. **Admission time is the last line**—if the cluster runs unsigned/unattested artifacts, every earlier control can be skipped.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build an enforceable, end-to-end chain of custody
- **[Code Examples](examples.md)**: See insecure vs. secure signing, provenance, and digest pinning
- **[CI/CD Security Track](/learn/cicd)**: Continue with the other OWASP CI/CD Top 10 risks
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
