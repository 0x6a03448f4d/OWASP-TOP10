# SAS-6: Insecure Third-Party Dependencies - Prevention

## Prevention Strategy Overview

You cannot review every transitive package by hand, so the goal is to make **a known, minimal, scanned, and pinned dependency set the only thing that ships**—and to bound what any single bad package can do:

1. Know exactly what you deploy (inventory / SBOM).
2. Scan it continuously and gate builds on the results (SCA).
3. Pin versions with integrity hashes so nothing is silently swapped.
4. Minimize the tree and vet where packages come from.
5. Patch on a cadence and bound blast radius with least-privilege roles.

### Core Principles

- **Assume you did not write it**: most of the shipped code is third-party—treat the tree, not the handler, as the attack surface.
- **Visibility first**: you cannot patch or defend a dependency you cannot see; an SBOM is the foundation.
- **Deterministic builds**: the same inputs must produce the same, verified artifact every time.
- **Bound the blast radius**: assume a dependency will be compromised eventually, and make sure it inherits as little privilege and reach as possible.

## 1. Maintain a Dependency Inventory / SBOM

Generate a Software Bill of Materials for every function and layer, on every build, and store it as a release artifact. You cannot respond to the next advisory without knowing where the package lives.

```
# Generate an SBOM (CycloneDX) per ecosystem, in CI:
# Node
npx @cyclonedx/cyclonedx-npm --output-file sbom.json
# Python
cyclonedx-py requirements -o sbom.json
# Language-agnostic, also scans built artifacts / images:
syft packages dir:. -o cyclonedx-json > sbom.json

# Keep the SBOM with the release so "are we affected by CVE-X?"
# is a lookup, not an investigation.
```

## 2. Software-Composition Analysis (SCA) in CI and Pre-Deploy

Manual awareness does not scale. Gate the build on automated scanning, and re-scan deployed artifacts on a schedule so newly disclosed CVEs are caught against code already in production.

```
# In CI: fail the build on known-vulnerable dependencies
# Node
npm audit --audit-level=high
# Python
pip-audit -r requirements.txt --strict
# Java
mvn org.owasp:dependency-check-maven:check
# Multi-ecosystem SCA (also scans layers/images/SBOMs)
snyk test --severity-threshold=high
grype sbom:sbom.json --fail-on high

# Schedule the same scans against what is DEPLOYED, so a CVE disclosed
# after release still pages someone.
```

> Treat SCA like tests: a failing scan blocks the merge. An "audit later" backlog is how known-vulnerable code reaches production.

## 3. Pin Versions and Verify Integrity Hashes

Floating ranges let a compromised upstream release enter silently. Commit a lockfile with integrity hashes and install from it deterministically.

```
# Node: install ONLY from the committed lockfile, exact + hashed
npm ci                      # not `npm install`; fails if lockfile is out of sync
# package-lock.json pins each package with an integrity (sha512) hash.

# Python: require hashes for every package
pip install --require-hashes -r requirements.txt
# requirements.txt with hashes:
#   requests==2.32.3 \
#     --hash=sha256:<digest>

# Java (Gradle): verify dependency checksums/signatures
#   gradle/verification-metadata.xml enables dependency verification.
```

Rules of thumb: no floating `latest` in production manifests, commit the lockfile, and let CI fail if the lockfile and manifest disagree.

## 4. Minimize the Dependency Tree

The safest dependency is the one you did not add. Serverless rewards small functions—fewer packages mean less attack surface, smaller bundles, and faster cold starts.

```
# See the real tree before adding anything:
npm ls --all            # full transitive tree
pipdeptree              # Python transitive tree

# Prefer:
#  - the standard library over a micro-package
#  - one focused library over a broad framework you use 5% of
#  - tree-shaking / bundling to drop unused code from the artifact
esbuild handler.js --bundle --tree-shaking=true --platform=node --outfile=dist/handler.js

# Split large functions so each ships only the deps it needs.
```

## 5. Vet Provenance and Pull from Trusted Registries

Stop typosquatting and dependency confusion at the source: control which registry resolves which names, and scope internal packages.

```
# Scope internal packages to your private registry (blocks confusion):
# .npmrc
@myco:registry=https://registry.internal.myco.com/
//registry.internal.myco.com/:_authToken=${NPM_TOKEN}

# Pin the public registry explicitly and use a proxy/mirror you control
registry=https://registry.internal.myco.com/npm-proxy/

# Python: index-url to your private index, extra-index-url avoided for
# internal names so the public PyPI cannot shadow them.
# pip.conf
[global]
index-url = https://pypi.internal.myco.com/simple/
```

Also: verify a package's real name and repository before adding it, prefer packages with active maintenance and provenance/signing, and use lockfiles so a name always resolves to the same verified artifact.

## 6. Disable or Audit Install Scripts

Install-time scripts run arbitrary code on your build host. Turn them off by default and allow-list only the few that genuinely need to build native code.

```
# Node: refuse to run lifecycle scripts during install
npm ci --ignore-scripts
# or project-wide, .npmrc:
ignore-scripts=true

# When a package truly needs a build step, allow-list it explicitly
# and review that script.

# Python: prefer wheels (no build step) and constrain builds
pip install --only-binary=:all: -r requirements.txt --require-hashes
```

## 7. Scan Lambda Layers and Container Images

Layers and images are dependencies too—and easy to forget. Scan their contents, not just the function's manifest, and rebuild them on a cadence.

```
# Scan the built artifact / layer directory
grype dir:./layer-build --fail-on high
trivy fs ./layer-build --severity HIGH,CRITICAL

# For container-image functions, scan the image
trivy image myfunc:latest --severity HIGH,CRITICAL

# Version and rebuild shared layers regularly; do not let a layer
# become a permanent home for a stale, vulnerable library.
```

## 8. Patch and Update on a Cadence

Automate update PRs and keep runtimes current, so patches actually reach deployed functions rather than sitting in a backlog.

```
# Automated dependency-update PRs (Dependabot / Renovate)
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule: { interval: "weekly" }
  - package-ecosystem: "pip"
    directory: "/"
    schedule: { interval: "weekly" }

# Keep the function on a SUPPORTED runtime; migrate off deprecated ones:
#   nodejs14.x / python3.7  ->  a current, patched runtime.
```

## 9. Bound the Blast Radius (Least Privilege + Egress)

Assume a dependency will eventually be compromised. Least-privilege roles and monitored egress decide whether that is an incident or a catastrophe (see SAS-4).

```
# Scope the execution role to exactly what the function needs — no wildcards:
{
  "Effect": "Allow",
  "Action": ["dynamodb:GetItem"],
  "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Orders"
}
# NOT  "Action": "*"  on  "Resource": "*"

# Restrict outbound network paths (VPC + egress controls) so a malicious
# dependency cannot freely reach an attacker endpoint, and alert on
# unexpected egress destinations.
```

## 10. Monitoring and Detection

Watch for the signatures of a dependency behaving badly—at build time and at runtime.

```
# Build-time signals:
#  - install scripts attempting network access
#  - a lockfile change that adds an unexpected transitive package
#  - a package name that differs from the intended one by one character

# Runtime signals (per-function):
#  - egress to a destination the function never normally contacts
#  - reads of the credential endpoint followed by unusual API calls
#  - a spike in invocations/cost (possible abusive workload) — ties to SAS-8

# Alert on new dependencies entering the tree, and diff SBOMs between releases.
```

## Ecosystem-Specific Hardening

### Node.js (npm)

```
# .npmrc
ignore-scripts=true
@myco:registry=https://registry.internal.myco.com/
audit-level=high

# CI
npm ci --ignore-scripts        # deterministic, no lifecycle scripts
npm audit --audit-level=high   # gate the build
```

### Python (pip)

```
# Deterministic, hash-verified, wheels-only install
pip install --require-hashes --only-binary=:all: -r requirements.txt
# Gate the build
pip-audit -r requirements.txt --strict
# Pin the private index so internal names cannot be shadowed
#   index-url = https://pypi.internal.myco.com/simple/
```

## Key Takeaways

1. **Inventory everything** — an SBOM per function and layer turns the next advisory into a lookup, not a scramble.
2. **Gate on SCA** — scan in CI and on a schedule against what is deployed; a failing scan blocks the merge.
3. **Pin and verify** — committed lockfiles with integrity hashes, installed via `npm ci` / `--require-hashes`, stop silent swaps.
4. **Minimize and vet** — fewer packages from trusted, scoped registries, with install scripts off, shrink the surface.
5. **Bound the damage** — least-privilege roles and monitored egress ensure a bad dependency cannot own the account.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure package config, lockfiles, CI, and layers
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
