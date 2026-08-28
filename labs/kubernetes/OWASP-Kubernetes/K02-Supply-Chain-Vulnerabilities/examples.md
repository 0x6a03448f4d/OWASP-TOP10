# K02: Supply Chain Vulnerabilities - Code Examples

Each pair below shows an **insecure** artifact and the **secure** version of the same thing. The examples focus on the supply chain controls that matter most: hardened Dockerfiles, digest-pinned manifests, signing and verification, SBOMs, and admission policies that block unsigned or untrusted images.

## 1. Dockerfile Hardening

### Insecure

```dockerfile
# Mutable, bloated base; runs as root; secrets baked in
FROM ubuntu:latest

RUN apt-get update && apt-get install -y python3 curl build-essential
COPY . /app
COPY .env /app/.env                 # secrets baked into a layer (permanent)
ENV API_TOKEN=sk_live_abc123        # visible in image history forever

WORKDIR /app
# No USER -> container runs as root (UID 0)
CMD ["python3", "server.py"]
```

### Secure

```dockerfile
# Multi-stage build: build tools stay out of the final image
FROM python:3.12-slim@sha256:<digest> AS build
WORKDIR /src
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt \
    --target /install
COPY . .

# Minimal, digest-pinned distroless runtime; no shell, no package manager
FROM gcr.io/distroless/python3-debian12@sha256:<digest>
WORKDIR /app
COPY --from=build /install /usr/lib/python3/dist-packages
COPY --from=build /src/server.py /app/server.py

USER 10001                          # non-root
# No secrets in the image; injected at runtime via the platform
ENTRYPOINT ["python3", "server.py"]
```

Secrets are removed from the image entirely, the runtime is minimal and pinned, dependencies are hash-verified, and the container runs as a non-root user.

## 2. Image Reference in the Manifest

### Insecure

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:latest        # mutable tag -> can resolve to a new digest
          imagePullPolicy: Always     # "Always" does not make :latest immutable
```

### Secure

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: registry.example.com/app@sha256:9f2c...e1a7   # immutable digest
          imagePullPolicy: IfNotPresent
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      # container-level hardening
```

Pinning by digest guarantees the exact artifact you scanned, signed, and tested is what the kubelet runs—no silent tag swap.

## 3. CI Pipeline: Scan, Sign, SBOM

### Insecure

```yaml
# .github-ci (illustrative) — build and push, no scanning, no signing
steps:
  - run: docker build -t registry.example.com/app:latest .
  - run: docker push registry.example.com/app:latest
  # No CVE gate, no SBOM, no signature. Whatever built is trusted implicitly.
```

### Secure

```yaml
# Build to a digest, scan, generate an SBOM, sign, and attest
steps:
  - run: |
      docker build -t registry.example.com/app:build .
      docker push registry.example.com/app:build
      DIGEST=$(crane digest registry.example.com/app:build)
      echo "IMG=registry.example.com/app@${DIGEST}" >> "$GITHUB_ENV"

  - run: trivy image --exit-code 1 --severity HIGH,CRITICAL "$IMG"   # CVE gate

  - run: syft "$IMG" -o cyclonedx-json > sbom.json                   # SBOM

  - run: cosign sign "$IMG"                                          # sign (keyless)

  - run: |
      cosign attest --predicate sbom.json --type cyclonedx "$IMG"
      cosign attest --predicate provenance.json \
        --type slsaprovenance "$IMG"                                 # provenance
```

The pipeline fails on serious CVEs, records exactly what is inside the image (SBOM), and produces a verifiable signature and provenance attestation tied to the digest.

## 4. Admission Control: Block Unsigned / Untrusted Images

### Insecure

```
# No admission policy. The cluster runs any image from any registry,
# signed or not, scanned or not, mutable tag or not.
```

### Secure (Kyverno)

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: supply-chain-guardrails
spec:
  validationFailureAction: Enforce
  rules:
    # a) Only allow images from trusted registries
    - name: allowed-registries
      match: { any: [ { resources: { kinds: [Pod] } } ] }
      validate:
        message: "Images must come from registry.example.com"
        pattern:
          spec:
            containers:
              - image: "registry.example.com/*"

    # b) Require a valid signature (keyless / Sigstore)
    - name: require-signature
      match: { any: [ { resources: { kinds: [Pod] } } ] }
      verifyImages:
        - imageReferences: [ "registry.example.com/*" ]
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/example/*"
                    issuer: "https://token.actions.githubusercontent.com"
```

### Secure (Gatekeeper / OPA — reject mutable tags)

```rego
package k8ssupplychain

violation[{"msg": msg}] {
  input.review.object.kind == "Pod"
  c := input.review.object.spec.containers[_]
  not contains(c.image, "@sha256:")            # must be pinned by digest
  msg := sprintf("image %q is not pinned by digest", [c.image])
}
```

With these policies set to *Enforce*, a Pod referencing an untrusted registry, an unsigned image, or a mutable tag is rejected before it is ever scheduled.

## 5. Verifying Before You Trust

### Insecure

```bash
# Deploy straight from a public URL / unknown image, no checks
kubectl run app --image=docker.io/someuser/app:latest
```

### Secure

```bash
# Verify signature and inspect the SBOM before rollout
cosign verify registry.example.com/app@sha256:9f2c...e1a7
cosign verify-attestation --type cyclonedx registry.example.com/app@sha256:9f2c...e1a7

# Re-scan the exact digest against current advisories
trivy image --severity HIGH,CRITICAL registry.example.com/app@sha256:9f2c...e1a7
```

## What Changed, and Why

| Weakness | Insecure | Secure |
|----------|----------|--------|
| Base image | `ubuntu:latest`, bloated, root | Digest-pinned distroless, non-root, multi-stage |
| Image reference | Mutable tag (`:latest`) | Immutable digest (`@sha256:...`) |
| Secrets | Baked into layers / `ENV` | Injected at runtime, scanned for at build |
| CVEs | Never scanned | Trivy/Grype gate in CI and at admission |
| Provenance | Unsigned, unknown origin | Cosign signature + SLSA/in-toto attestation |
| Contents | Unknown | SBOM (Syft/CycloneDX) stored and attested |
| Enforcement | None | Kyverno/Gatekeeper block unsigned/untrusted/mutable |

## Next Steps

- **[Prevention](prevention.md)**: The full supply chain hardening strategy
- **[Attack Vectors](attack-vectors.md)**: How these weaknesses are exploited
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply these controls in hands-on exercises
