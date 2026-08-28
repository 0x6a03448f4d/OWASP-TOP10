# K02: Supply Chain Vulnerabilities - Prevention

## Prevention Strategy Overview

Securing the supply chain is less about a single control and more about **making "trusted, known, and verifiable" the only thing that ships**:

1. Start from minimal, trusted base images and rebuild them regularly.
2. Pin every artifact by immutable digest so what you tested is what runs.
3. Scan for known CVEs in CI *and* re-check at admission.
4. Sign images and attach provenance, then verify signatures before running.
5. Generate an SBOM so you always know what is inside.
6. Restrict sources to an allow-list and enforce it with admission control.

### Core Principles

- **Trust must be provable**: for any running Pod you should be able to show who built the image, from what, and that it was not tampered with.
- **Pin, don't float**: mutable tags are pointers that can move; immutable digests cannot.
- **Shift left, enforce right**: scan and sign in CI, but make admission control the gate that actually blocks bad artifacts.
- **Least trust, least privilege**: allow-list registries, run as non-root, and treat every third-party chart and operator as untrusted until vetted.

## 1. Minimal, Trusted Base Images

Smaller trusted bases carry fewer CVEs and fewer usable binaries for an attacker.

```dockerfile
# Prefer distroless or a slim, verified base; pin by digest
FROM gcr.io/distroless/static-debian12@sha256:<digest>
# No shell, no package manager, no extra binaries to abuse.

# If you need a shell during build, use a multi-stage build and copy only
# the final artifact into the distroless runtime stage.
```

Rebuild on a cadence (and on advisory) so patches actually reach production; a base that was clean at build accumulates CVEs over time.

## 2. Pin Every Image by Digest

Reference artifacts by immutable digest, never by a moving tag, in both Dockerfiles and manifests.

```yaml
# Manifest: pin the exact artifact
spec:
  containers:
    - name: app
      image: registry.example.com/app@sha256:9f2c...e1a7   # immutable
      # NOT: registry.example.com/app:latest

# Enforce immutable tags in the registry so a tag cannot be repushed.
```

Digest pinning guarantees the artifact you scanned, signed, and tested is byte-for-byte the one the kubelet pulls.

## 3. Scan Images in CI and at Admission

Scan early to fail fast, and scan again at the gate so nothing slips in out of band.

```bash
# In CI: fail the build on high/critical CVEs
trivy image --exit-code 1 --severity HIGH,CRITICAL registry.example.com/app@sha256:<digest>
grype registry.example.com/app@sha256:<digest> --fail-on high

# At admission: re-scan or require a passing scan attestation before scheduling.
```

CI scanning catches issues before merge; admission-time enforcement catches images that were built elsewhere, pulled directly, or introduced after the pipeline ran.

## 4. Sign Images and Verify Provenance

Signing proves origin and integrity; verification at admission makes it enforceable.

```bash
# Sign at the end of the pipeline (keyless / Sigstore or with a managed key)
cosign sign registry.example.com/app@sha256:<digest>

# Attach build provenance (SLSA / in-toto attestation)
cosign attest --predicate provenance.json \
  --type slsaprovenance registry.example.com/app@sha256:<digest>

# Verify anywhere before trusting the artifact
cosign verify registry.example.com/app@sha256:<digest>
```

Aim for higher SLSA levels over time: signed provenance that ties the artifact to a specific, tamper-evident build.

## 5. Generate and Store an SBOM

An SBOM answers "what is inside?"—essential for responding when a new CVE lands on a component you ship.

```bash
# Produce an SBOM (CycloneDX or SPDX) for each image
syft registry.example.com/app@sha256:<digest> -o cyclonedx-json > sbom.json

# Attach it as a signed attestation so it travels with the image
cosign attest --predicate sbom.json --type cyclonedx \
  registry.example.com/app@sha256:<digest>
```

Store SBOMs so that when the next widely-exploited library advisory drops, you can query which images—and which running Pods—are affected in minutes, not days.

## 6. Private Registries and Source Allow-Lists

Restrict where images may come from and mirror trusted upstreams internally.

```yaml
# Allow only trusted registries; block arbitrary public pulls
allowed_registries:
  - registry.example.com          # your private registry
  - internal-mirror.example.com   # vetted, mirrored upstream images

# Mirror/curate upstream images into the private registry rather than
# pulling straight from public registries at deploy time.
```

This removes typosquatting and arbitrary-public-image risk: if it is not from an allowed source, it does not run.

## 7. Admission Control to Enforce Policy

Admission control is the gate that makes signing, scanning, and allow-listing real—block anything that fails.

```yaml
# Kyverno: require signed images from a trusted registry (verifyImages)
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "registry.example.com/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/example/*"
                    issuer: "https://token.actions.githubusercontent.com"
```

```
# Gatekeeper/OPA can complement this by rejecting disallowed registries
# and mutable tags (deny image: *:latest, deny non-allow-listed registries).
```

Set policies to *enforce* (not just audit) once teams have adopted signing, so unsigned, unscanned, mutable-tag, or untrusted-registry images are rejected at the door.

## 8. Vet Helm Charts and Operators

- Treat third-party charts and operators as untrusted dependencies: review what they deploy, especially RBAC (ClusterRoles/bindings) and the images they pull.
- Pin chart versions and the images they reference by digest; never `helm install` straight from an unvetted URL.
- Mirror trusted charts into an internal repository and update them deliberately.

```bash
# Verify a chart's provenance before installing (provenance file / signature)
helm pull trusted/app --version 1.4.2 --verify
# Review rendered manifests before applying
helm template trusted/app --version 1.4.2 | less
```

## 9. Keep Secrets Out of Image Layers

Never bake credentials into an image; inject them at runtime instead.

```yaml
# Do NOT do this:
# COPY .env /app/.env
# ENV API_TOKEN=...

# Instead, mount from a secret manager at runtime:
envFrom:
  - secretRef:
      name: app-secrets        # sourced from Vault / cloud secret manager
```

```bash
# Catch secrets before they are committed or built in
gitleaks detect --source . --redact
trivy image --scanners secret registry.example.com/app@sha256:<digest>
```

Remember that secrets in published layers are permanent—removing them from a later build does not scrub earlier image history.

## 10. Run as Non-Root with a Hardened Runtime

Even a trusted image should run with least privilege so a foothold has little room to escalate.

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

Build images that support this (a non-root `USER` in the Dockerfile, no reliance on writing to the root filesystem) so the hardened runtime is the default, not a special case.

## 11. Monitoring and Detection

Watch for the signatures of supply chain problems and drift.

```
# Alert on policy violations and risky pulls
- image pulled from a non-allow-listed registry
- Pod admitted with a mutable tag (should be blocked, alert if seen)
- signature verification failures at admission
- new CRITICAL CVE matches an SBOM of a running image
- unexpected outbound connections from a workload (possible miner / C2)
```

Continuously re-evaluate running images against new advisories using your stored SBOMs, and alert when a freshly disclosed CVE affects something already deployed.

## Key Takeaways

1. **Start minimal and trusted** — distroless/slim bases, rebuilt regularly, carry fewer CVEs and fewer tools to abuse.
2. **Pin by digest** — immutable references remove the silent-swap vector that mutable tags create.
3. **Scan and sign** — scanning finds known CVEs, signing proves provenance; use both, in CI and at admission.
4. **Know what's inside** — an SBOM turns the next big advisory into a fast query instead of a blind rebuild.
5. **Enforce at the gate** — admission control that blocks unsigned, unscanned, mutable-tag, or untrusted images is what makes the rest real.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure Dockerfiles, manifests, and policies
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply this hardening in hands-on exercises
