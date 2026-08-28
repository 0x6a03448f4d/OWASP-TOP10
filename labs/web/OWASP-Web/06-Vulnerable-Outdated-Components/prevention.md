# A06:2021 – Vulnerable and Outdated Components: Prevention

## Table of Contents

- [Defense Philosophy](#defense-philosophy)
- [Layer 1: Know What You Have (Inventory & SBOM)](#layer-1-know-what-you-have-inventory--sbom)
- [Layer 2: Scan Continuously (SCA)](#layer-2-scan-continuously-sca)
- [Layer 3: Enforce in CI/CD](#layer-3-enforce-in-cicd)
- [Layer 4: Patch on a Cadence, with Tests](#layer-4-patch-on-a-cadence-with-tests)
- [Layer 5: Reduce the Attack Surface](#layer-5-reduce-the-attack-surface)
- [Layer 6: Trusted, Signed Sources](#layer-6-trusted-signed-sources)
- [Layer 7: Container & OS Package Hygiene](#layer-7-container--os-package-hygiene)
- [Layer 8: Monitor Advisories & EOL](#layer-8-monitor-advisories--end-of-life)
- [Layer 9: Virtual Patching as a Stopgap](#layer-9-virtual-patching-as-a-stopgap)
- [Implementation Checklist](#implementation-checklist)

## Defense Philosophy

You cannot write your way out of this category—you have to *operate* your way out of it. The winning organization is not the one with zero vulnerable components (impossible, since new advisories appear daily) but the one that **knows what it runs, learns about new flaws quickly, and deploys fixes before attackers arrive.** Every layer below shortens the window between disclosure and remediation.

```
Goal: minimize  T(exposure) = T(deploy fix) - T(disclosure)

KNOW      -- an accurate, automated inventory (SBOM) of every component
SEE       -- continuous SCA that maps advisories to your inventory
GATE      -- CI/CD that blocks new/known-critical vulnerabilities
FIX       -- a tested, risk-based patching cadence (days for critical)
SHRINK    -- fewer dependencies, no dead code, minimal images
TRUST     -- official, signed sources with integrity verification
STOPGAP   -- WAF / virtual patch to buy time, never as the fix
```

## Layer 1: Know What You Have (Inventory & SBOM)

You cannot patch what you cannot see. The foundation of this entire category is a complete, continuously-updated inventory of every component—direct and transitive—on both client and server. Modern practice is to generate a machine-readable **Software Bill of Materials (SBOM)** as a build artifact.

### Generate an SBOM (CycloneDX / SPDX)

```
# Node.js -> CycloneDX SBOM
$ npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Python -> CycloneDX SBOM
$ pip install cyclonedx-bom
$ cyclonedx-py requirements -i requirements.txt -o sbom.json

# Java / Maven -> CycloneDX SBOM
$ mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom

# From a built container image (any language) with Syft
$ syft myorg/webapp:1.4.2 -o cyclonedx-json=sbom.json
```

Store the SBOM alongside each release. When the next Log4Shell-class advisory drops, answering "are we affected, and where?" becomes a query against your SBOMs instead of a multi-week scramble.

### Enumerate the full tree, not just direct deps

```
$ npm ls --all               # entire dependency tree, incl. transitive
$ pipdeptree                 # Python dependency tree
$ mvn dependency:tree        # Maven dependency tree
$ ./gradlew dependencies     # Gradle dependency tree
```

## Layer 2: Scan Continuously (SCA)

Software Composition Analysis (SCA) tools compare your inventory against vulnerability databases (NVD/CVE, GitHub Advisories/GHSA, OSV). Run them locally, in CI, and on a schedule against already-released software (because new advisories land against components you already shipped).

### Native, zero-install scanners per ecosystem

```
# Node.js
$ npm audit                          # report
$ npm audit --audit-level=high       # fail threshold
$ npm audit fix                      # auto-apply safe fixes

# Python
$ pip install pip-audit
$ pip-audit -r requirements.txt

# Java / Maven -- OWASP Dependency-Check
$ mvn org.owasp:dependency-check-maven:check

# Multi-ecosystem, lockfile-aware
$ osv-scanner --lockfile package-lock.json
$ trivy fs .                         # filesystem + deps + secrets
```

### OWASP Dependency-Check in a Maven build

```xml
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <version>9.0.9</version>
  <configuration>
    <!-- fail the build on CVSS 7.0+ (High/Critical) -->
    <failBuildOnCVSS>7</failBuildOnCVSS>
  </configuration>
  <executions>
    <execution><goals><goal>check</goal></goals></execution>
  </executions>
</plugin>
```

## Layer 3: Enforce in CI/CD

Scanning that only produces a report is easy to ignore. Wire the scanners into the pipeline so a new critical vulnerability *blocks the merge*, and schedule a daily re-scan of the main branch to catch advisories published after a release.

### GitHub Actions: block PRs on known-vulnerable deps

```yaml
name: dependency-scan
on:
  pull_request:
  schedule:
    - cron: '0 6 * * *'      # daily re-scan of already-merged code
jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: OSV scan (fails on vulnerable deps)
        uses: google/osv-scanner-action@v1
        with:
          scan-args: |-
            --lockfile=package-lock.json
      - name: Trivy filesystem scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          severity: HIGH,CRITICAL
          exit-code: '1'      # non-zero => pipeline fails
```

### Enable automated dependency-update PRs (Dependabot)

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: npm
    directory: "/"
    schedule: { interval: daily }
    open-pull-requests-limit: 10
  - package-ecosystem: pip
    directory: "/"
    schedule: { interval: weekly }
  - package-ecosystem: docker
    directory: "/"
    schedule: { interval: weekly }
  - package-ecosystem: github-actions
    directory: "/"
    schedule: { interval: weekly }
```

Dependabot (or Renovate) opens pull requests that bump vulnerable/outdated dependencies. Combined with a good test suite (Layer 4), these PRs can be reviewed and merged routinely instead of accumulating.

## Layer 4: Patch on a Cadence, with Tests

Detection is worthless without timely remediation. Define a **risk-based patching SLA** and—critically—invest in automated tests so upgrades are safe to apply, removing the "fear of breakage" that stalls patching.

### Example remediation SLA

| Severity | Internet-facing SLA | Internal SLA |
|----------|---------------------|--------------|
| Critical (actively exploited) | 24–72 hours | 7 days |
| Critical / High | 7 days | 30 days |
| Medium | 30 days | 90 days |
| Low | Next release cycle | Next release cycle |

### Pin versions, then upgrade deliberately with a lockfile

```
# Commit lockfiles so builds are reproducible and auditable:
package-lock.json  /  yarn.lock          (Node)
poetry.lock  /  requirements.txt (pinned) (Python)
Gemfile.lock                              (Ruby)

# Install EXACTLY the locked versions in CI/production:
$ npm ci                     # not "npm install"
$ pip install -r requirements.txt --require-hashes

# Upgrade on purpose, run the full test suite, then commit the new lock:
$ npm update some-lib && npm test
$ npm install some-lib@4.2.1 && npm test
```

### Fix a vulnerable transitive dependency

```json
// package.json -- force a patched transitive version via overrides
{
  "overrides": {
    "qs": "6.5.3"            // pull the fixed version up the tree
  }
}
```

```
# Python: constrain a transitive dep explicitly
# constraints.txt
urllib3>=1.26.18
$ pip install -r requirements.txt -c constraints.txt
```

## Layer 5: Reduce the Attack Surface

Every dependency you remove is a dependency you never have to patch. The smallest, simplest dependency set is the most secure one.

```
# Find and remove unused dependencies (Node)
$ npx depcheck
Unused dependencies: moment, left-pad, request
$ npm uninstall moment left-pad request

# Prefer the standard library or a tiny, well-maintained lib over a
# sprawling framework when the task is small.

# Remove unused features, sample apps, docs, and demo endpoints that
# ship enabled by default (overlaps with A05 Security Misconfiguration).
```

- **Audit before adding**: check a prospective dependency's maintenance status, release cadence, and open advisories before you take it on.
- **Avoid "utility soup"**: many trivial micro-dependencies multiply your transitive surface for little benefit.
- **Delete dead code paths**: an unused but present component is still exploitable if reachable.

## Layer 6: Trusted, Signed Sources

Obtain components only from official package repositories over secure links, and verify integrity. This blocks the "untrusted source" and tampering vectors.

```
# Node: enforce integrity + reproducible installs
$ npm ci                              # honors integrity hashes in lockfile
# .npmrc
audit=true
fund=false
# Optionally pin the registry and require 2FA-published packages via policy

# Python: require hashes so a swapped artifact fails the install
# requirements.txt
Django==4.2.11 \
  --hash=sha256:....  # install aborts if the download doesn't match

# Java: verify artifact signatures / checksums; use an internal proxy
# repository (e.g. Nexus/Artifactory) that curates and scans upstream.
```

> **Note on 2025.** Signature verification, provenance, and using a curated internal proxy repository are where this classic category shades into the broader *Software Supply Chain Failures* topic of the 2025 edition. For A06:2021, the essential rule is simpler: never install from unofficial mirrors or unverified archives, and verify what you download.

## Layer 7: Container & OS Package Hygiene

Container images freeze OS packages at build time. Without deliberate hygiene, an image that was clean at release accumulates known CVEs as advisories pile up against its frozen packages.

```dockerfile
# Use minimal, current base images and pin by digest
FROM node:20.11.1-slim@sha256:....    # small, specific, reproducible
# or "distroless" images that ship no shell/package manager at all

# Update OS packages during build, then drop privileges
RUN apt-get update && apt-get upgrade -y \
 && rm -rf /var/lib/apt/lists/*
USER 10001                            # never run as root
```

```
# Scan the image in CI and fail on HIGH/CRITICAL
$ trivy image --severity HIGH,CRITICAL --exit-code 1 myorg/webapp:1.4.2

# REBUILD regularly so base-image patches actually reach production;
# a never-rebuilt image is an ever-aging one.
```

## Layer 8: Monitor Advisories & End-of-Life

Patching reacts to advisories; you must therefore *receive* them. Subscribe to the relevant feeds and track the support lifecycle of every runtime and framework so you migrate off end-of-life software **before** it stops receiving fixes.

- **Subscribe** to GitHub Security Advisories (GHSA) for your repos, the NVD/CVE feeds, and vendor security bulletins for your runtimes.
- **Enable GitHub Dependabot alerts** so advisories are matched to your repositories automatically.
- **Track EOL dates** (a resource like `endoflife.date` is useful) for the OS, language runtime, database, and major frameworks; schedule migrations ahead of the cutoff.
- **Assign ownership**: someone must be responsible for triaging incoming advisories against the inventory.

```
# Quick EOL sanity checks
Node 16  -> end-of-life: migrate to an active LTS
Python 3.8 approaching EOL -> plan the move to a supported minor
Ubuntu 18.04 -> out of standard support -> rebuild on a current LTS
```

## Layer 9: Virtual Patching as a Stopgap

Sometimes a fixed version is not yet available, or an emergency upgrade cannot be tested in time. A WAF or gateway rule can **temporarily** block the known exploit pattern—buying hours or days while you deploy the real fix.

```
# Conceptual WAF virtual patch for the Log4Shell-class payload:
SecRule REQUEST_HEADERS|ARGS "@rx \$\{jndi:" \
  "id:1001,phase:2,deny,status:403,msg:'Block JNDI lookup pattern'"

# Rate-limit or block the specific vulnerable path until patched.
```

> **Virtual patching is a tourniquet, not a cure.** WAF rules are bypassable and version-specific. Deploy one to reduce immediate risk, but keep the real remediation—upgrading the component—on the critical path. Never close the ticket on the WAF rule alone.

## Implementation Checklist

- [ ] An SBOM is generated automatically for every build and stored with the release.
- [ ] The full dependency tree (direct + transitive) is enumerable on demand.
- [ ] SCA (npm audit / pip-audit / OWASP Dependency-Check / OSV / Trivy) runs on every build.
- [ ] CI blocks merges on new High/Critical vulnerabilities and re-scans main daily.
- [ ] Dependabot or Renovate opens automated update PRs; they are reviewed regularly.
- [ ] A written, risk-based remediation SLA exists and is measured.
- [ ] Automated tests give the team confidence to upgrade dependencies routinely.
- [ ] Lockfiles are committed; production installs use exact, hash-verified versions.
- [ ] Unused dependencies, features, and demo endpoints have been removed.
- [ ] All components come from official, signed sources; integrity is verified.
- [ ] Container base images are minimal, pinned, scanned, and rebuilt on a cadence.
- [ ] Advisory feeds are subscribed to and EOL dates are tracked with an owner.
- [ ] Virtual patching is available as a documented stopgap—never the final fix.

## Key Takeaways

1. **Inventory first.** An SBOM is the single highest-leverage control; you cannot defend what you cannot see.
2. **Automate detection.** Continuous SCA in CI turns a manual audit into a background guarantee.
3. **Make patching cheap and routine.** Tests plus automated update PRs remove the fear that stalls upgrades.
4. **Speed beats perfection.** A defined, short SLA for critical fixes closes the exploitation window that attackers depend on.
5. **Shrink and verify.** Fewer dependencies, minimal images, and trusted signed sources reduce both the surface and the risk of tampering.

## Next Steps

- **[Overview](./overview.md)**: The category, its impact, and how it is defined
- **[Attack Vectors](./attack-vectors.md)**: How attackers find and exploit known-vulnerable components
- **[Examples](./examples.md)**: Vulnerable vs. secure dependency management, side by side
- **[Hands-On Lab](./lab/outdated-library-lab/)**: Detect, patch, and re-scan an outdated library

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
