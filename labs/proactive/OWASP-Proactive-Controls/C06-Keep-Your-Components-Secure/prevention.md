# C6: Keep Your Components Secure - How to Implement

## Table of Contents
- [The Implementation Model](#the-implementation-model)
- [Step 1: Build an Inventory / SBOM](#step-1-build-an-inventory--sbom)
- [Step 2: Run SCA in CI and Continuously](#step-2-run-sca-in-ci-and-continuously)
- [Step 3: Pin Versions with Integrity Hashes](#step-3-pin-versions-with-integrity-hashes)
- [Step 4: Source from Trusted Origins](#step-4-source-from-trusted-origins)
- [Step 5: Monitor and Automate Updates](#step-5-monitor-and-automate-updates)
- [Step 6: Patch on a Cadence](#step-6-patch-on-a-cadence)
- [Step 7: Minimize and Retire](#step-7-minimize-and-retire)
- [Step 8: Secure the Pipeline and Provenance](#step-8-secure-the-pipeline-and-provenance)
- [Step 9: Scan Containers and Base Images](#step-9-scan-containers-and-base-images)
- [Step 10: Virtual Patching as a Stopgap](#step-10-virtual-patching-as-a-stopgap)
- [A Maturity Path](#a-maturity-path)

## The Implementation Model

Implementing this control means turning the ten core practices into automated, repeatable steps that run without heroics. The organising idea is a pipeline: **see everything, verify what enters, watch continuously, and update on a rhythm**. Nothing below relies on a human remembering to check—each step is wired into tooling that fails loudly when something is wrong.

> **First principle**: you cannot secure what you cannot see. Every other step assumes you have a complete, current inventory. Start there.

## Step 1: Build an Inventory / SBOM

Generate a **Software Bill of Materials** that lists every component—direct *and* transitive—with name, version, license, and origin. Produce it automatically as a build artifact so it is always current, and store it where incident responders can query it.

- Use a standard format (**CycloneDX** or **SPDX**) so tools can consume it.
- Generate from the resolved dependency graph, not the hand-written manifest, so transitive components are included.
- Produce an SBOM per build and attach it to the release; keep history so you can answer "which past releases shipped component X?"

```
# Generate a CycloneDX SBOM
# Node
npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Python
cyclonedx-py environment --output-format json --outfile sbom.json

# From a container image or filesystem (language-agnostic)
syft dir:. -o cyclonedx-json=sbom.json
syft myapp:1.4.2 -o spdx-json=sbom.spdx.json
```

## Step 2: Run SCA in CI and Continuously

**Software Composition Analysis** matches your components against vulnerability databases. Run it two ways: as a *gate* in CI that fails a build introducing a critical issue, and *continuously* against already-deployed artifacts, because new advisories land daily against code you already shipped.

- **In CI**: fail the pipeline on new high/critical findings; allow a reviewed, time-boxed exception process for false positives or unreachable code.
- **Continuously**: re-scan the SBOMs of deployed releases on a schedule so a newly disclosed CVE against an unchanged release still raises an alert.

```
# Native package-manager auditors
npm audit --audit-level=high
pip-audit --strict

# OWASP Dependency-Check (multi-ecosystem, CI-friendly)
dependency-check --project myapp --scan . --failOnCVSS 7

# Snyk (SaaS SCA)
snyk test --severity-threshold=high

# Trivy / Grype scan the SBOM or the image directly
trivy fs --severity HIGH,CRITICAL .
grype sbom:sbom.json --fail-on high
```

## Step 3: Pin Versions with Integrity Hashes

Commit lockfiles so every build resolves to the exact same bytes, and so a tampered artifact is rejected by its integrity hash. Floating ranges (`^`, `~`, `latest`) are fine in the manifest for humans, but the lockfile is what actually installs—and it must be committed and enforced.

- **Node**: commit `package-lock.json`; install in CI with `npm ci` (fails if lockfile and manifest disagree), which enforces the recorded `integrity` hashes.
- **Python**: commit `poetry.lock` / `Pipfile.lock`, or a `requirements.txt` with `--hash` entries, and install with `--require-hashes`.
- **Java**: avoid version ranges; pin exact versions and use the Maven **Enforcer** plugin plus dependency locking / a verified `dependency-check` gate.

## Step 4: Source from Trusted Origins

Only install components from official, trusted registries, and verify their integrity. This is where you defeat dependency confusion, typosquatting, and malicious packages.

- **Use a single, controlled source**: proxy public registries through an internal artifact repository (Artifactory, Nexus, GitHub Packages) so you control what enters.
- **Scope internal packages**: publish private packages under an org scope/namespace (`@yourorg/...`) and configure the registry so those names *never* resolve to the public registry—this is the primary dependency-confusion defense.
- **Verify exact names**: match the official package name character-for-character before adding it; do not trust a name pasted from a tutorial.
- **Delay adoption**: prefer versions that have been public for a cooldown period over brand-new releases, to dodge just-published malicious versions.
- **Verify signatures / provenance** where the ecosystem supports it (for example npm provenance / Sigstore attestations).

## Step 5: Monitor and Automate Updates

Subscribe your codebase to advisory feeds and let automation open the update pull requests. This closes the disclosure-to-patch gap that attackers race you on.

- **Feeds**: track the GitHub Advisory Database (GHSA) and NVD; most SCA tools map your components to these automatically.
- **Automated PRs**: enable **Dependabot** or **Renovate** to open update PRs, grouped and scheduled so they are reviewable rather than overwhelming.
- **Alert routing**: send critical advisories to a channel a human actually watches, with the affected service named from your SBOM.

```
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule: { interval: "weekly" }
    open-pull-requests-limit: 10
  - package-ecosystem: "pip"
    directory: "/"
    schedule: { interval: "weekly" }
  - package-ecosystem: "maven"
    directory: "/"
    schedule: { interval: "weekly" }
```

## Step 6: Patch on a Cadence

Updating is a routine, not a fire drill. Define a regular cadence for normal updates and a fast lane for emergencies, and put automated tests behind both so upgrades are safe to merge.

- **Routine cadence**: a recurring window (for example weekly) to review and merge the automated update PRs while changes are small.
- **Emergency path**: a documented, fast process for critical advisories—who decides, how it is tested, how fast it ships.
- **Test coverage**: rely on your CI test suite so a dependency bump that breaks behaviour is caught before merge, removing the fear that keeps teams on old versions.
- **Prefer patch/minor** for speed; schedule and test major upgrades deliberately rather than deferring them until an incident forces a multi-version jump.

## Step 7: Minimize and Retire

Every dependency you do not need is attack surface you did not have to carry. Actively shrink the tree.

- **Remove unused dependencies**: use tools like `depcheck` (Node), `deptry`/`pip-autoremove` (Python), or the Maven dependency plugin's `analyze` goal to find and drop unreferenced libraries.
- **Prefer smaller, well-maintained libraries** over sprawling ones that drag in large transitive trees.
- **Track EOL**: know the end-of-life dates of runtimes and major dependencies (resources like *endoflife.date* help), and schedule replacement *before* support ends—an EOL component will never receive a fix.

## Step 8: Secure the Pipeline and Provenance

Your build system is one of the most privileged places in your estate and a prime supply-chain target. Harden it and prove what it produced.

- **Least-privilege CI**: scope build credentials tightly; do not expose long-lived registry or cloud tokens to arbitrary build steps.
- **Protect signing keys**: keep artifact-signing keys in a managed KMS/HSM, not in the repo or plain CI variables.
- **Generate provenance**: adopt the **SLSA** framework—produce signed provenance attesting how, from what source, and by which builder an artifact was created, so consumers can verify it.
- **Sign your artifacts** (for example with Sigstore/cosign) and publish the SBOM alongside each release.

## Step 9: Scan Containers and Base Images

Treat the OS layer as dependencies too. A clean application on a stale base image is still vulnerable.

- **Start minimal**: use small, well-maintained base images (distroless or slim variants) to cut the number of OS packages you inherit.
- **Scan images in CI** with Trivy or Grype and fail on high/critical OS-package findings.
- **Rebuild regularly**: base images get patched upstream, so rebuild and redeploy on a schedule rather than pinning to a tag that never moves.
- **Pin by digest** (`image@sha256:...`) for reproducibility, and update the digest deliberately when you rebuild.

```
# Fail a build on vulnerable OS or app packages in the image
trivy image --severity HIGH,CRITICAL --exit-code 1 myapp:1.4.2
grype myapp:1.4.2 --fail-on high
```

## Step 10: Virtual Patching as a Stopgap

Sometimes you cannot upgrade immediately—a fix is not yet released, or the upgrade is a major, risky change. A **virtual patch** (a WAF rule or runtime filter that blocks the known exploit pattern) can reduce exposure while you prepare the real fix.

- Use it to *buy time*, never as the permanent remedy—the vulnerable code is still there.
- Track every virtual patch as an open item with a deadline for the real upgrade.
- Combine with monitoring so attempts to exploit the blocked pattern are logged and alerted.

## A Maturity Path

| Level | What is in place |
|-------|------------------|
| **1 - Reactive** | Lockfiles committed; someone runs `npm audit` occasionally. |
| **2 - Gated** | SCA runs in CI and fails builds on critical findings; Dependabot/Renovate open update PRs. |
| **3 - Visible** | SBOM generated per build; deployed releases re-scanned continuously; trusted-source proxy enforced. |
| **4 - Hardened** | Scoped internal packages, container scanning, EOL tracking, and a defined patch cadence with an emergency lane. |
| **5 - Assured** | Signed artifacts with SLSA provenance, verified signatures on ingest, and drift/exception governance across the fleet. |

## Implementation Checklist

- [ ] SBOM (CycloneDX/SPDX) generated automatically per build, covering transitive components.
- [ ] SCA gate in CI fails builds on high/critical findings.
- [ ] Deployed releases re-scanned continuously against new advisories.
- [ ] Lockfiles committed and enforced (`npm ci`, hashed requirements, pinned Maven).
- [ ] Public registries proxied through a controlled internal repository.
- [ ] Internal packages scoped so they cannot resolve to the public registry.
- [ ] Dependabot/Renovate opening scheduled update PRs.
- [ ] Regular patch cadence plus a documented emergency path.
- [ ] Unused dependencies removed; EOL components tracked and scheduled for replacement.
- [ ] Container base images minimal, scanned, and rebuilt regularly.
- [ ] Build pipeline hardened; artifacts signed with SLSA provenance.
- [ ] Virtual patches tracked as temporary, with a real-fix deadline.

## Next Steps

- **[Overview](overview.md)**: What this control is and why it matters
- **[Threats Addressed](attack-vectors.md)**: The failure modes these steps close
- **[Examples](examples.md)**: Insecure vs. secure configuration across Node, Python, and Java
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply component security hands-on
