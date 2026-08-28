# CICD-SEC-9: Improper Artifact Integrity Validation - Code Examples

Each pair below shows an **insecure** configuration and the **secure** version for the same hand-off. The examples focus on the controls that matter most for artifact integrity: signing and verifying, build provenance, digest pinning, dependency integrity, and deploy-time admission.

## 1. Sign and Verify a Container Image (GitHub Actions + cosign)

### Insecure

```yaml
name: build
on: { push: { branches: [main] } }
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build and push (mutable tag, no signature)
        run: |
          docker build -t registry.example.com/api:prod .
          docker push registry.example.com/api:prod
          # No signature is produced. Anyone who can push to :prod
          # can substitute the image and nothing will notice.
```

### Secure

```yaml
name: build
on: { push: { branches: [main] } }
permissions:
  id-token: write        # OIDC identity for keyless signing
  packages: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build and capture the digest
        id: build
        run: |
          docker build -t registry.example.com/api:build .
          docker push registry.example.com/api:build
          DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' \
                   registry.example.com/api:build | cut -d@ -f2)
          echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"
      - uses: sigstore/cosign-installer@v3
      - name: Sign the DIGEST keylessly (no long-lived key)
        run: |
          cosign sign --yes \
            registry.example.com/api@${{ steps.build.outputs.digest }}
```

```bash
# Consumer / deploy step -- verification is the control that matters
cosign verify \
  --certificate-identity-regexp '^https://github.com/acme/api/.github/workflows/build.yml@.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  registry.example.com/api@sha256:<digest>  || exit 1   # fail closed
```

## 2. Generate and Verify SLSA Build Provenance

### Insecure

```bash
# The pipeline pushes an artifact with NO record of how it was built.
# A signature (if any) proves the bytes, not the process -- a build-time
# backdoor (SolarWinds-class) would be signed and shipped identically.
docker push registry.example.com/api:prod
```

### Secure

```bash
# Emit an in-toto SLSA provenance attestation for the exact digest...
cosign attest --yes \
  --predicate provenance.slsa.json \
  --type slsaprovenance \
  registry.example.com/api@sha256:<digest>

# ...and REQUIRE it (source + builder) before deploying.
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/acme/api/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  registry.example.com/api@sha256:<digest>  || exit 1
```

> Provenance answers "which source and which builder produced this?" A bare signature cannot. Requiring provenance is what defends against build-system compromise.

## 3. Reference by Immutable Digest, Not a Mutable Tag

### Insecure

```yaml
# Dockerfile -- base image can change under you
FROM python:3.12-slim

# Kubernetes -- ":prod" is a moving pointer
spec:
  containers:
    - name: api
      image: registry.example.com/api:prod
```

### Secure

```yaml
# Dockerfile -- pinned to exact bytes
FROM python:3.12-slim@sha256:0d1f3c9e<...full-digest...>

# Kubernetes -- deploy the exact artifact that was signed + attested
spec:
  containers:
    - name: api
      image: registry.example.com/api@sha256:9a7b2f1c<...full-digest...>
```

## 4. Deploy-Time Admission: Only Signed + Attested Images Run

### Insecure

```bash
# No policy -- the cluster runs whatever is referenced, signed or not.
kubectl apply -f deploy.yaml
```

### Secure

```yaml
# Sigstore policy-controller: enforce signature + provenance at admission
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: require-signed-attested
spec:
  images:
    - glob: "registry.example.com/**"
  authorities:
    - keyless:
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subjectRegExp: '^https://github.com/acme/.+/.github/workflows/.+'
      attestations:
        - name: slsa-provenance
          predicateType: slsaprovenance
# Unsigned or unattested images are DENIED admission -- fail closed.
```

The same policy can be written with Kyverno (`verifyImages`) or OPA/Gatekeeper. Whatever the engine, admission is the last, non-negotiable gate.

## 5. Enforce Dependency Integrity in the Build

### Insecure

```bash
# Python -- floating range, no hashes: the index decides what you get
pip install requests

# Node -- non-reproducible install, integrity not enforced
npm install
```

### Secure

```bash
# Python -- pinned versions with pinned hashes, verified on install
# requirements.lock:
#   requests==2.32.3 --hash=sha256:<hash>
pip install --require-hashes -r requirements.lock

# Node -- install strictly from the integrity-checked lockfile
npm ci        # aborts if package-lock.json integrity does not match

# Go -- verify module checksums against the checksum database
go mod verify
```

## 6. Verify a Signed Build Blob (Non-Container Artifact)

### Insecure

```bash
# Download a release artifact and use it directly -- no integrity check
curl -O https://artifacts.example.com/app-1.4.2.tar.gz
tar xzf app-1.4.2.tar.gz && ./install.sh    # trusts whatever was served
```

### Secure

```bash
# Verify the detached signature against the expected signer BEFORE use
cosign verify-blob \
  --certificate app-1.4.2.tar.gz.pem \
  --signature  app-1.4.2.tar.gz.sig \
  --certificate-identity-regexp '^https://github.com/acme/app/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  app-1.4.2.tar.gz  || { echo "integrity check failed"; exit 1; }
tar xzf app-1.4.2.tar.gz && ./install.sh
```

## 7. Validate IaC Before Applying

### Insecure

```bash
# Applies whatever the plan resolves to, from possibly-tampered modules
terraform apply -auto-approve
```

### Secure

```bash
terraform init -lockfile=readonly     # enforce provider checksums (.terraform.lock.hcl)
terraform plan -out tfplan            # produce the exact, reviewable plan
terraform show -json tfplan > tfplan.json
conftest test tfplan.json             # policy-as-code gate (OPA/Rego)
terraform apply tfplan                # apply ONLY the reviewed, gated plan
```

## What Changed, and Why

| Hand-off | Insecure | Secure |
|----------|----------|--------|
| Image publish | Push to mutable tag, unsigned | Sign the digest keylessly; verify against signer identity |
| Build origin | No record of how it was built | SLSA provenance generated and required |
| Reference | Mutable tag (`:prod`, `:latest`) | Immutable `@sha256:` digest |
| Deploy | Cluster runs anything | Admission policy: signed + attested only |
| Dependencies | Floating versions, no hashes | `--require-hashes` / `npm ci` / `go mod verify` |
| IaC | `apply -auto-approve` | Locked plan + policy gate, apply reviewed plan |

## Next Steps

- **[Prevention](prevention.md)**: The full end-to-end chain-of-custody strategy
- **[Attack Vectors](attack-vectors.md)**: How these hand-offs are exploited
- **[CI/CD Security Track](/learn/cicd)**: Continue with the other OWASP CI/CD Top 10 risks
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
