# CICD-SEC-9: Improper Artifact Integrity Validation - Prevention

## Prevention Strategy Overview

Preventing improper artifact integrity validation means building an **enforceable chain of custody**: at every hand-off, the consumer refuses anything it cannot cryptographically tie back to a trusted origin. The goal is not "we sign our images"—it is "nothing runs unless it is signed, attested, pinned, and verified."

1. Sign every artifact and container image, and **verify the signature before use**.
2. Generate build **provenance** and check it, so origin—not just authenticity—is proven.
3. Reference artifacts by **immutable digest**, never a mutable tag.
4. Verify at **every hand-off** and, non-negotiably, at deploy/admission time.
5. Protect signing keys and keep an end-to-end record (SBOM + attestations).

### Core Principles

- **Verify, don't trust**: producing a signature or attestation is worthless unless a consumer enforces it and fails closed.
- **Content over names**: an immutable digest identifies specific bytes; a tag is a pointer that can move.
- **Prove the build, not just the bytes**: provenance defends against build-time tampering that a bare signature cannot detect.
- **Defence in depth across hand-offs**: the deploy gate is the last line, but earlier checks stop poison entering the build at all.

## 1. Sign Artifacts and Images (Sigstore / cosign)

Sign build outputs and container images as part of the pipeline. Keyless signing with Sigstore ties the signature to a short-lived, OIDC-issued identity, so there is no long-lived key to steal.

```bash
# Keyless signing in CI (identity comes from the workflow's OIDC token)
COSIGN_EXPERIMENTAL=1 cosign sign \
  registry.example.com/api@sha256:<digest>

# Sign a generic build artifact (blob) too
cosign sign-blob --yes app.tar.gz --output-signature app.tar.gz.sig \
  --output-certificate app.tar.gz.pem
```

Sign the **digest**, not a tag—so the signature is bound to specific bytes.

## 2. Verify Signatures Before Use and at Deploy Time

Signing is half the control; the enforced half is verification against an *expected identity*. Fail closed if it does not match.

```bash
# Verify keyless signature against the exact workflow identity + issuer
cosign verify \
  --certificate-identity-regexp '^https://github.com/acme/api/.github/workflows/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  registry.example.com/api@sha256:<digest>   || exit 1   # fail the deploy
```

Verifying against "any valid signature" is not enough—pin the signer identity so an attacker's own valid signature is rejected.

## 3. Generate and Check Build Provenance (SLSA / in-toto)

Provenance is a signed statement of *how* an artifact was built—source, builder, parameters, materials. It is what defends against SolarWinds-class build tampering, which produces a genuinely signed backdoor.

```bash
# Attach an in-toto SLSA provenance attestation to the image
cosign attest --yes \
  --predicate provenance.slsa.json \
  --type slsaprovenance \
  registry.example.com/api@sha256:<digest>

# At deploy time, verify the attestation, not just a signature
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/acme/api/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  registry.example.com/api@sha256:<digest>  || exit 1
```

Aim for a higher SLSA build level: a hardened, isolated builder that emits provenance automatically, so the attestation reflects a build an attacker cannot quietly alter.

### 3b. Policy-as-Code on the Attestation

Verifying the signature is not the same as approving the *contents* of the provenance. Enforce a policy over it.

```
# Example checks a policy engine should enforce on the provenance:
#   - builder ID == our trusted builder
#   - source repo == expected repo, on an allowed branch/tag
#   - build was triggered by an allowed event
#   - materials (dependencies) all resolve to pinned digests
# Reject the artifact if any assertion fails.
```

## 4. Pin by Immutable Digest, Not Mutable Tag

Everywhere an artifact is referenced—base images, deploy manifests, IaC—use the content digest so the reference cannot silently change.

```dockerfile
# Dockerfile: pin the base image by digest
FROM python:3.12-slim@sha256:<digest>

# Kubernetes manifest: reference the app image by digest
image: registry.example.com/api@sha256:<digest>   # not "api:prod"
```

Let automation (Renovate/Dependabot with digest pinning) update digests via reviewed pull requests, so pinning does not mean going stale.

## 5. Enforce Verification at Admission / Deploy

The cluster is the last gate. Use an admission controller so **only signed and attested images run**; unsigned or unexpected artifacts are denied.

```yaml
# Sigstore policy-controller ClusterImagePolicy (excerpt)
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
        - name: must-have-slsa-provenance
          predicateType: slsaprovenance
```

Equivalent policies can be expressed with Kyverno or OPA/Gatekeeper. The key property: **fail closed**—no signature/attestation, no admission.

## 6. Verify Dependencies, Caches, and Mirrors

Dependency and cache hand-offs need integrity checks too, or a poisoned entry enters the build before you ever sign anything.

```bash
# Python: enforce hashes from a locked, hashed requirements file
pip install --require-hashes -r requirements.lock

# Node: install strictly from the integrity-checked lockfile
npm ci                     # fails if package-lock integrity doesn't match

# Go: verify module checksums against the checksum database
go mod verify

# Cache restores should be keyed and integrity-checked, not trusted blindly.
```

Prefer an internal proxy that records and enforces checksums, and treat mirror contents as untrusted until verified.

## 7. Protect the Signing Identity

- Prefer **keyless signing** (Sigstore + workflow OIDC): identities are short-lived, so there is no durable private key to exfiltrate.
- If you must hold keys, keep them in a **KMS/HSM** and sign via the KMS API—the private key never leaves the boundary.
- Scope who/what can sign to the specific trusted workflow identity, and record signatures in a transparency log (Rekor) for auditability.

```bash
# Signing with a KMS-held key (private key never exported)
cosign sign --key awskms:///alias/artifact-signing \
  registry.example.com/api@sha256:<digest>
```

## 8. Validate IaC and Config Before Applying

Infrastructure and config are artifacts. Gate them like any other output.

```bash
# Produce a reviewable plan, verify module/provider integrity, then apply
terraform init -lockfile=readonly     # enforce .terraform.lock.hcl checksums
terraform plan -out tfplan            # human/policy review of the exact plan
conftest test tfplan.json             # policy-as-code gate (OPA)
terraform apply tfplan                # apply ONLY the reviewed plan
```

Protect remote state integrity (locking, restricted access) so the "current state" an apply trusts cannot be tampered with.

## 9. Reproducible Builds and SBOM

- **Reproducible builds** let an independent rebuild produce the same digest—so provenance can be corroborated, not just asserted.
- Generate an **SBOM** per artifact and attach it as a signed attestation, giving a verifiable inventory that ties deployed bytes to known components.

```bash
# Generate an SBOM and attach it as a signed attestation
syft registry.example.com/api@sha256:<digest> -o spdx-json > sbom.spdx.json
cosign attest --yes --predicate sbom.spdx.json --type spdxjson \
  registry.example.com/api@sha256:<digest>
```

## 10. Monitoring and Chain-of-Custody Auditing

Watch for the signatures of integrity failures and gaps in coverage.

```
# Alert-worthy signals:
#   - admission denials for unsigned/unattested images (probing or drift)
#   - deployments referencing a tag instead of a digest
#   - pushes to release tags from outside the trusted workflow identity
#   - artifacts in the registry with no matching Rekor transparency entry
#   - provenance whose source/builder does not match policy
```

Periodically reconcile "what is running" against "what has valid signatures + provenance," so an artifact that slipped past a gap is caught after the fact.

## End-to-End: What a Verified Pipeline Looks Like

| Hand-off | Control | Fails closed if… |
|----------|---------|------------------|
| SCM → CI | Verify signed commit/tag; hermetic build | Source identity/signature invalid |
| Dependencies | Hash-pinned installs, verified mirror | Checksum/lockfile mismatch |
| CI → registry | Sign digest + emit SLSA provenance + SBOM | (produces the evidence) |
| Registry → CD | Reference by digest; verify signature | Signer identity not trusted |
| CD → production | Admission policy: signed + attested only | No/invalid signature or provenance |
| IaC apply | Locked plan + policy-as-code gate | Plan/module integrity or policy fails |

## Key Takeaways

1. **Verification is the control, not signing** — enforce signatures against an expected identity and fail closed.
2. **Provenance defends the build** — SLSA/in-toto attestations catch the signed-backdoor (SolarWinds-class) case a bare signature cannot.
3. **Pin digests everywhere** — base images, deploy manifests, and IaC referenced by content, not by movable tags.
4. **Gate at admission** — the cluster must refuse anything unsigned or unattested; that is the non-negotiable last line.
5. **Protect keys and keep records** — keyless/OIDC or KMS signing, SBOMs, and transparency logs make the chain of custody auditable end to end.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure signing, provenance, and digest pinning
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[CI/CD Security Track](/learn/cicd)**: Continue with the other OWASP CI/CD Top 10 risks
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
