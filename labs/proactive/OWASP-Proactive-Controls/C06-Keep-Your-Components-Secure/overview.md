# C6: Keep Your Components Secure - Overview

## Table of Contents
- [What is this control?](#what-is-this-control)
- [Why This Control Matters](#why-this-control-matters)
- [Core Practices](#core-practices)
- [The Component Lifecycle](#the-component-lifecycle)
- [Real-World Incident Classes](#real-world-incident-classes)
- [Common Misunderstandings](#common-misunderstandings)

## What is this control?

**Keep Your Components Secure** is the proactive control of managing the security of every first- and third-party component your software depends on, across its **entire lifecycle**—from the moment you choose it, through every release you ship, to the day you retire it. A modern application is mostly code you did not write: frameworks, libraries, runtimes, base images, and the long tail of *transitive* dependencies those pull in. This control is the discipline of knowing exactly what those components are, keeping them patched, sourcing them safely, and removing them when they are no longer needed.

This is the defensive counterpart to **Vulnerable and Outdated Components** (OWASP Top 10 A06) and to the broader category of **software supply-chain risk**. That risk category is what happens when a known-vulnerable, unmaintained, or maliciously altered dependency ends up running in production; this control is the set of habits that stop that from happening—inventory, scanning, patching, trusted sourcing, and continuous monitoring. The governing principle is **you cannot secure what you cannot see**: everything starts with a complete, accurate inventory.

### Core Concept

```
Unmanaged components (invisible, drifting, trusted blindly):
  Inventory     -> nobody knows the full dependency tree
  Sourcing      -> packages pulled from any registry, unverified
  Versions      -> floating ranges, no lockfile, no pinning
  Patching      -> updated only when something breaks
  Monitoring    -> CVEs noticed from the news, if at all
  Footprint     -> unused libraries left installed "just in case"
  End of life   -> abandoned dependencies still shipped

Managed components (inventoried, verified, patched, watched):
  Inventory     -> SBOM lists every direct and transitive component
  Sourcing      -> trusted official registries, integrity verified
  Versions      -> pinned in a lockfile with integrity hashes
  Patching      -> regular cadence, tested, plus emergency path
  Monitoring    -> automated CVE/advisory alerts (Dependabot/Renovate)
  Footprint     -> unused dependencies removed, surface minimized
  End of life   -> EOL components tracked and replaced ahead of time
```

### Two audiences: what you build and what you consume

The control applies in two directions, and both matter:

- **Components you consume**: the frameworks, libraries, container base images, and runtimes you pull into your application must be inventoried, sourced from trusted origins, pinned, scanned, and patched. If one of them ships a critical CVE, you need to know within hours which of your services is affected.
- **Components you produce**: the packages, images, and services your team publishes are themselves someone else's dependency. Securing your build pipeline, signing your artifacts, and publishing an SBOM and provenance protects everyone downstream from you.

## Why This Control Matters

### Business Impact of Getting It Right

- **The dominant breach root cause**: a large share of the code in any product is third-party, and known-vulnerable dependencies are one of the most common and most exploited entry points. Managing them removes an enormous slice of real-world risk.
- **Hours, not weeks, to respond**: when the next internet-wide dependency emergency lands, an organisation with an SBOM and SCA knows in minutes which systems are affected. One without spends days grepping through build files under pressure.
- **Regulatory and contractual alignment**: SBOMs and supply-chain assurance are increasingly mandated (for example by government software-procurement rules), and customers now ask for them in security questionnaires.
- **Lower long-term cost**: small, frequent, tested updates are far cheaper than a forced emergency upgrade across many major versions during an active incident.

### Technical Impact

- **Known-vulnerable code is caught before release**: SCA in CI blocks a build that pulls in a dependency with a critical advisory, instead of shipping it.
- **Transitive risk becomes visible**: most vulnerable components arrive indirectly; an SBOM and a resolved lockfile expose the full tree, not just what you typed into a manifest.
- **Malicious packages are kept out**: trusted sourcing, integrity hashes, and dependency-confusion defenses stop typosquatted or hijacked packages from ever being installed.
- **Attack surface shrinks**: removing unused dependencies deletes whole classes of vulnerability that could never be triggered because the code is gone.

## Core Practices

Keep Your Components Secure is made of a set of reinforcing habits:

- **Maintain an inventory / SBOM**: produce and keep current a Software Bill of Materials listing every component—*direct and transitive*—with name, version, and origin.
- **Run Software Composition Analysis (SCA)**: use tools such as OWASP Dependency-Check, `npm audit`, `pip-audit`, Snyk, and Trivy/Grype in CI *and* continuously against what is already deployed.
- **Patch and update on a cadence**: schedule regular, tested dependency updates, with a fast emergency path for critical advisories.
- **Remove unused dependencies**: minimize the footprint—every library you do not need is attack surface you did not have to carry.
- **Source from trusted, official registries**: obtain components from official sources and verify integrity and signatures; defend against dependency confusion, typosquatting, and malicious packages.
- **Pin versions with integrity hashes**: commit lockfiles (`package-lock.json`, `poetry.lock`, Maven ranges resolved) so builds are reproducible and tamper-evident.
- **Monitor CVE and advisory feeds**: watch GHSA and NVD, and automate alerts and update PRs with Dependabot or Renovate.
- **Secure the build pipeline and provenance**: protect CI/CD, sign artifacts, and generate provenance following a framework like SLSA.
- **Scan containers and base images**: treat the OS packages in your images as dependencies too, and rebuild on updated bases.
- **Track end-of-life components**: know which dependencies and runtimes are approaching EOL and replace them before they stop receiving patches.
- **Use virtual patching as a stopgap**: when an immediate upgrade is impossible, a WAF or runtime rule can buy time—never as the permanent fix.

## The Component Lifecycle

This control is best understood as covering a component from selection to retirement. Each stage has its own safeguard.

| Lifecycle stage | Unmanaged (risk) | Managed (this control) |
|-----------------|------------------|------------------------|
| Selection | Grab any package that works | Prefer maintained, reputable, trusted-source components |
| Acquisition | Install from any registry, unverified | Official registry, integrity hash / signature verified |
| Declaration | Floating version ranges, no lockfile | Pinned versions committed in a lockfile |
| Build | Unprotected CI pulls fresh each time | Hardened pipeline, provenance, reproducible build |
| Operation | Deployed and forgotten | Continuously scanned against advisory feeds |
| Maintenance | Update only when it breaks | Regular tested cadence + emergency patch path |
| Retirement | Unused / EOL libraries left in place | Unused removed, EOL replaced ahead of time |

## Real-World Incident Classes

These are recurring *classes* of incident that this control is designed to prevent. They are described as patterns, not as specific vulnerabilities, and no CVE numbers are invented.

### Class 1: Critical flaw in a ubiquitous library (Log4Shell-class)

A single, extremely widely used logging library disclosed a critical remote-code-execution flaw. Because the library was buried deep in the transitive dependency trees of countless applications, most organisations could not even answer "are we affected?" for days. Teams with a current SBOM and SCA answered in minutes and patched first. This class is the canonical argument for inventory plus continuous scanning.

### Class 2: Dependency confusion

An attacker publishes a package to a *public* registry using the same name as an organisation's *internal* private package, with a higher version number. Misconfigured tooling prefers the public one and pulls attacker code straight into the build. Defenses are trusted-source configuration, scoped/namespaced internal packages, and pinned lockfiles.

### Class 3: Typosquatting and malicious packages

Attackers publish packages whose names are near-misses of popular ones (a transposed letter, a hyphen), or they compromise the credentials of a legitimate maintainer and push a malicious release. Installing one runs attacker code at install time. Defenses are careful sourcing, integrity verification, and holding back automatic adoption of brand-new versions.

### Class 4: Compromised build pipeline

Rather than attacking a package, adversaries compromise the build or update infrastructure of a trusted vendor and ship a tainted-but-signed artifact to all of that vendor's customers. This is why securing your own pipeline and generating provenance (SLSA) matters—you are a link in someone else's supply chain.

## Common Misunderstandings

### Myth 1: "We only need to track what's in our manifest"

**Reality**: the large majority of components are *transitive*—pulled in by your dependencies' dependencies. Only a resolved lockfile and an SBOM show the real tree, and that is where most vulnerabilities live.

### Myth 2: "If it isn't broken, don't update it"

**Reality**: an unchanged dependency is not a stable one—the world's knowledge of its flaws grows over time. A library that was "fine" last year may have three critical advisories today. Staying current on a cadence is cheaper and safer than a forced emergency jump.

### Myth 3: "Popular packages are safe packages"

**Reality**: popularity increases blast radius, not safety. The most impactful supply-chain events target widely used libraries precisely because so many victims inherit the flaw at once.

### Myth 4: "A scan at release is enough"

**Reality**: new vulnerabilities are disclosed daily against code you already shipped. Scanning must be *continuous* against deployed artifacts, not a one-time gate.

### Myth 5: "A WAF rule fixed it"

**Reality**: virtual patching buys time; it does not remove the vulnerable code. Treat it as a stopgap and still schedule the real upgrade.

## How This Control Relates to Vulnerable and Outdated Components

| Aspect | Vulnerable & Outdated Components (the risk) | Keep Your Components Secure (the control) |
|--------|---------------------------------------------|-------------------------------------------|
| **Nature** | A known-flawed dependency left running | The practices that stop that from happening |
| **Default posture** | Unknown and unmanaged until it bites | Inventoried, pinned, scanned, patched |
| **Effort model** | Someone must notice the CVE in the news | Automation surfaces and PRs the fix |
| **Failure mode** | Blind to transitive and supply-chain risk | Continuous visibility across the lifecycle |

## Key Takeaways

1. **You cannot secure what you cannot see**—an SBOM covering direct and transitive components comes first.
2. **Scan continuously, not just at release**—SCA belongs in CI and against everything deployed.
3. **Source and pin deliberately**—trusted registries, integrity hashes, and lockfiles keep malicious and drifting components out.
4. **Patch on a cadence with an emergency lane**—small frequent updates beat a crisis upgrade.
5. **Minimize and retire**—remove unused dependencies and replace EOL components before they lose support.

## Self-Assessment Checklist

- [ ] Do you have a current SBOM listing every direct and transitive component with versions?
- [ ] Does SCA (Dependency-Check, npm audit, pip-audit, Snyk, Trivy/Grype) run in CI and fail builds on critical findings?
- [ ] Are you also scanning what is already deployed, continuously?
- [ ] Are versions pinned in committed lockfiles with integrity hashes?
- [ ] Are components pulled only from trusted, official registries, with signatures/integrity verified?
- [ ] Are you defended against dependency confusion (scoped internal packages, source pinning)?
- [ ] Do Dependabot/Renovate or equivalent open update PRs automatically?
- [ ] Do you patch on a defined cadence, with a fast path for critical advisories?
- [ ] Have unused dependencies been removed to minimize footprint?
- [ ] Are container base images scanned and rebuilt on updates?
- [ ] Is your build pipeline hardened, with signed artifacts and provenance (SLSA)?
- [ ] Do you track EOL dates for runtimes and key dependencies?

## Next Steps

- **[Threats Addressed](attack-vectors.md)**: What vulnerable, outdated, and compromised components lead to
- **[How to Implement](prevention.md)**: Build inventory, scanning, patching, and trusted sourcing
- **[Examples](examples.md)**: Insecure vs. secure component management across Node, Python, and Java
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply component security hands-on
