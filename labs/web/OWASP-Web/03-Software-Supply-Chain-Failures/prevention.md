# Software Supply Chain Failures - Prevention

## Table of Contents
- [Defense in Depth for the Supply Chain](#defense-in-depth-for-the-supply-chain)
- [1. Inventory and SBOM](#1-inventory-and-sbom-cyclonedx--spdx)
- [2. Pin and Verify Dependencies](#2-pin-and-verify-dependencies-lockfiles--hashes)
- [3. Provenance and Artifact Signing](#3-provenance-and-artifact-signing-slsa-sigstore--cosign)
- [4. Private Registries and Dependency-Confusion Defense](#4-private-registries-and-dependency-confusion-defense)
- [5. Automated Dependency and Vulnerability Scanning](#5-automated-dependency-and-vulnerability-scanning-sca)
- [6. Harden CI/CD](#6-harden-cicd)
- [7. Subresource Integrity for Third-Party Scripts](#7-subresource-integrity-for-third-party-scripts)
- [8. Verify and Pin Container Base Images](#8-verify-and-pin-container-base-images)
- [9. Update and Patch Cadence](#9-update-and-patch-cadence)
- [Defense Summary](#defense-summary)

## Defense in Depth for the Supply Chain

No single control secures the supply chain, because the chain fails at many independent points. The goal is **layered assurance**: know what you ship, pin it to immutable identifiers, verify its origin, resolve it from controlled sources, scan it continuously, build it in a hardened pipeline, and constrain what runs in the browser. Each layer below closes a distinct class of attack from the previous page.

## 1. Inventory and SBOM (CycloneDX / SPDX)

You cannot defend what you cannot enumerate. A **Software Bill of Materials** is a machine-readable list of every component (direct and transitive) in a build. Generate one automatically on every build, store it as an artifact, and query it the moment a new upstream compromise is announced.

```
# Generate a CycloneDX SBOM from a project's dependencies
$ npm install -g @cyclonedx/cyclonedx-npm
$ cyclonedx-npm --output-format JSON --output-file sbom.json

# Language-agnostic SBOM from a filesystem or container image (Syft)
$ syft dir:. -o spdx-json=sbom.spdx.json
$ syft registry:myapp:1.4.2 -o cyclonedx-json=image-sbom.json
```

```yaml
# In CI: produce and retain the SBOM as a build artifact on every run
- name: Generate SBOM
  run: syft dir:. -o cyclonedx-json=sbom.json
- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.json
```

> When the next widely-used package is compromised, an SBOM turns "are we affected?" from a week of investigation into a single query across stored bills of materials.

## 2. Pin and Verify Dependencies (Lockfiles + Hashes)

Floating version ranges let a hijacked release enter silently. Pin to exact versions *and* verify content hashes, then install strictly from the lockfile so a mismatch fails the build.

### Node / npm
```
# Commit package-lock.json (it records exact versions + integrity hashes).
# In CI, install strictly from the lockfile -- fails if it drifts:
$ npm ci                      # NOT `npm install`
# Block install-time script execution for untrusted trees:
$ npm ci --ignore-scripts
```

### Python / pip
```
# requirements.txt pinned to exact versions AND hashes
flask==3.0.0 --hash=sha256:3661b5c1...e2f9
requests==2.31.0 --hash=sha256:942c5a7...b1c4

# Refuse to install anything whose hash is not listed:
$ pip install --require-hashes -r requirements.txt
```

### Java / Maven
```xml
<!-- Pin exact versions (no ranges) and enforce it in the build -->
<dependency>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
  <version>2.17.1</version>   <!-- exact, not [2.0,) -->
</dependency>
```
```
# Verify artifact checksums/signatures on download
$ mvn --strict-checksums verify
```

### Go
```
# go.sum records expected hashes; verify the module cache against it:
$ go mod verify
# GONOSUMCHECK / disabling the checksum DB defeats this -- keep it on.
```

## 3. Provenance and Artifact Signing (SLSA, Sigstore / cosign)

A signature proves *who* published an artifact; **provenance** proves *what* was built, *from which source*, and *by which pipeline*. Together they detect a swapped or build-time-injected artifact even when the publisher's identity checks out. The **SLSA** framework defines increasing levels of build integrity; **Sigstore/cosign** provides keyless signing and verification.

```
# Sign a container image and its provenance attestation (keyless, via OIDC)
$ cosign sign --yes myregistry/myapp@sha256:9c1f...ab
$ cosign attest --predicate provenance.json \
    --type slsaprovenance myregistry/myapp@sha256:9c1f...ab
```

```
# Consumers VERIFY before deploy -- fail closed if it does not check out
$ cosign verify \
    --certificate-identity-regexp 'https://github.com/acme/.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    myregistry/myapp@sha256:9c1f...ab
```

```
# npm packages can carry build provenance published from CI:
$ npm publish --provenance --access public
# Consumers can then confirm the package was built from the stated source.
```

## 4. Private Registries and Dependency-Confusion Defense

Defeat confusion and typosquatting by controlling *where* names resolve. Scope internal packages, force private-registry precedence, and do not let public fallback silently win.

### npm scoped registry
```
# .npmrc -- the @acme scope ALWAYS comes from the private registry
@acme:registry=https://npm.internal.acme.com/
//npm.internal.acme.com/:_authToken=${NPM_TOKEN}
# Do not publish internal names to the public registry; reserve the scope.
```

### Python index control
```
# Pull ONLY from the trusted internal index; do not merge with PyPI blindly.
$ pip install --index-url https://pypi.internal.acme.com/simple \
              --no-deps -r requirements.txt
# Avoid --extra-index-url with public PyPI for internal names (confusion risk).
```

### Practical rules
- **Reserve your namespaces/scopes** on public registries so an attacker cannot claim them.
- **Pin the source**: internal names resolve to the private registry only.
- **Allowlist** which external packages are permitted; block unknown names by policy.
- **Proxy** public registries through an internal mirror that caches, scans, and quarantines new versions.

## 5. Automated Dependency and Vulnerability Scanning (SCA)

Software Composition Analysis continuously matches your components against known-vulnerability and malicious-package data, and gates merges on the result.

```
# Native package-manager audits
$ npm audit --audit-level=high
$ pip-audit -r requirements.txt

# Ecosystem-agnostic vulnerability scanning (OSV / Trivy / Grype)
$ osv-scanner --lockfile package-lock.json
$ trivy fs --scanners vuln,secret .
$ grype dir:.
```

```yaml
# Gate pull requests on SCA (GitHub Actions example)
name: sca
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Vulnerability scan (fail on high+)
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
          grype dir:. --fail-on high
```

Also enable automated update PRs (Dependabot / Renovate) so patches arrive quickly—paired with pinning and review so updates are adopted deliberately, not blindly.

## 6. Harden CI/CD

Treat the pipeline as production infrastructure, because it produces the trusted artifact and holds the keys.

- **Least-privilege, ephemeral credentials**: prefer short-lived OIDC-federated tokens over long-lived static secrets.
- **Pin third-party actions/steps by commit SHA**, not by mutable tag.
- **Scope permissions** per job to the minimum required.
- **Isolated, ephemeral runners**: fresh environment per job; avoid reused self-hosted runners for untrusted code.
- **Protected branches and pipelines**: required reviews, no direct pushes, signed commits/tags.
- **Never print secrets to logs**; mask them and keep build logs access-controlled.
- **Block install scripts** for untrusted dependency trees in CI.

```yaml
# Least-privilege token + SHA-pinned actions + OIDC for cloud (GitHub Actions)
permissions:
  contents: read            # default to read-only
  id-token: write           # only to mint a short-lived OIDC token

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1 pinned by SHA
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502  # v4.0.2 pinned
        with:
          role-to-assume: arn:aws:iam::111122223333:role/ci-deploy   # short-lived, scoped
          aws-region: us-east-1
      - run: npm ci --ignore-scripts
```

## 7. Subresource Integrity for Third-Party Scripts

For any script or stylesheet loaded from another origin, add a Subresource Integrity (`integrity`) hash. The browser refuses to execute the resource if its content does not match—so a compromised CDN cannot silently swap in a skimmer. Back it with a strict Content-Security-Policy.

```html
<!-- Browser executes this ONLY if the file's hash matches -->
<script src="https://cdn.example.com/lib@1.2.3/lib.min.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"
        referrerpolicy="no-referrer"></script>
```

```
# Generate the SRI hash for a file you intend to pin
$ cat lib.min.js | openssl dgst -sha384 -binary | openssl base64 -A
# Prefix the output with "sha384-" in the integrity attribute.
```

```
# Enforce integrity and restrict script origins with CSP
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://cdn.example.com;
  require-sri-for script style;
  object-src 'none'; base-uri 'none'
```

**Note**: SRI requires a specific, immutable file version. It is incompatible with CDN URLs that serve "latest"—which is exactly the mutable behavior you want to avoid.

## 8. Verify and Pin Container Base Images

Pin base images by **digest** (immutable), not by tag (mutable). Prefer minimal/distroless bases, scan images, and verify signatures before deploy.

```dockerfile
# Pin by digest so the base cannot change under you
FROM node:20.11.1-bookworm-slim@sha256:8b1e...c0a2
# ...build steps...

# Prefer a minimal runtime with no shell / package manager to abuse
FROM gcr.io/distroless/nodejs20-debian12@sha256:5f3d...9ab1
```

```
# Scan the built image and verify its signature in the pipeline
$ trivy image --severity HIGH,CRITICAL myapp@sha256:9c1f...ab
$ cosign verify myregistry/base@sha256:5f3d...9ab1   # fail closed on mismatch
```

## 9. Update and Patch Cadence

Pinning without a plan to move forward causes rot; auto-updating without review invites hijacks. Balance the two:
- Run SCA continuously and triage **high/critical** findings on a defined SLA.
- Let bots (Dependabot/Renovate) open update PRs; a human reviews the diff and changelog before merge.
- Watch for suspicious signals: a sudden new maintainer, an added obfuscated dependency, a large unexplained size change, or a release that skips the source repository.
- Re-generate the SBOM and re-scan on every merged update.

## Defense Summary

| Layer | Control | Attack it closes |
|-------|---------|------------------|
| Inventory | SBOM (CycloneDX/SPDX) | Unknown/transitive exposure during an incident |
| Dependencies | Lockfiles + hash verification | Silent hijacked releases, tampered downloads |
| Origin | Provenance + signing (SLSA/cosign) | Swapped or build-injected artifacts |
| Resolution | Private registry precedence, scoped names | Dependency confusion, typosquatting |
| Scanning | SCA (osv/trivy/grype, audits) | Known-vulnerable and malicious components |
| Build | Hardened, least-privilege CI/CD | Pipeline compromise, secret theft |
| Browser | SRI + strict CSP | Compromised third-party scripts (skimming) |
| Containers | Digest-pinned, scanned, minimal bases | Poisoned base images |

## Best Practices Checklist
- Generate and store an SBOM on every build.
- Install from lockfiles with hash verification; never floating ranges in production.
- Sign artifacts and publish provenance; verify before deploy.
- Reserve namespaces; resolve internal names from a private registry first.
- Run SCA in CI and gate merges on high/critical findings.
- Use least-privilege, ephemeral CI credentials; pin actions by SHA.
- Add SRI to every third-party script/stylesheet; enforce a strict CSP.
- Pin container bases by digest; scan and verify images.
- Enforce publisher 2FA; review dependency updates before adopting them.
- Prefer reproducible builds so source and artifact can be compared.

## Next Steps

- **[Examples](examples.html)**: Copy-ready vulnerable vs. secure snippets for each control.
- **[Attack Vectors](attack-vectors.html)**: The patterns these defenses close.
- **[Overview](overview.html)**: Concepts, impact, and relationship to A06:2021.
- **[Hands-On Lab](./lab/software-supply-chain-failures/)**: Apply these defenses to a deliberately vulnerable pipeline.
