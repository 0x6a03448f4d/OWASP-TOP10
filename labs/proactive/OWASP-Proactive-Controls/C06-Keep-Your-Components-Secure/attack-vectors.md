# C6: Keep Your Components Secure - Threats Addressed

## Table of Contents
- [What This Control Defends Against](#what-this-control-defends-against)
- [The Threats, One by One](#the-threats-one-by-one)
- [How Attackers Find Vulnerable Components](#how-attackers-find-vulnerable-components)
- [Threat-to-Safeguard Mapping](#threat-to-safeguard-mapping)

## What This Control Defends Against

Keeping components secure is a **defensive** discipline. To see why each practice exists, it helps to look at what goes wrong when components are left unmanaged. The threats below are the concrete failure modes that a vulnerable, outdated, or compromised dependency creates. This page enumerates them; the [How to Implement](prevention.md) page gives the countermeasures.

> These are threat *classes* and patterns. Real internet-wide events (Log4Shell-class RCE, dependency-confusion, typosquatting and malicious-package campaigns, and compromised-build-pipeline incidents) are referenced by class, not by invented CVE numbers.

## The Threats, One by One

### 1. Remote Code Execution through a known-vulnerable library

The highest-impact outcome. A dependency ships a flaw that lets an attacker execute arbitrary code—often reachable with a single crafted request. Because the vulnerable code runs with your application's privileges, a single unpatched library can mean full server compromise.

- **Trigger**: an outdated framework, parser, serializer, or logging library with a published RCE advisory.
- **Why it persists**: the flaw is usually *transitive*—nobody chose the library directly, so nobody is watching it.
- **Illustrative class**: the Log4Shell-class event, where a ubiquitous logging library's flaw exposed a vast number of applications at once.

### 2. Exploitation of publicly known, unpatched vulnerabilities

Once a CVE is public, exploit code and automated scanners follow within hours. Any service still running the affected version is a target of opportunity for mass, indiscriminate scanning—no sophistication required.

- **Trigger**: a gap between disclosure and your patch cadence.
- **Impact**: SQL injection, path traversal, deserialization, auth bypass—whatever the component's advisory describes, now weaponized against you.

### 3. Malicious code execution from a compromised package (supply-chain)

The dependency is not merely buggy—it is hostile. An attacker publishes or hijacks a package so that installing or importing it runs their code. Payloads commonly steal environment variables and tokens, open reverse shells, or inject backdoors.

- **Trigger**: a hijacked maintainer account, a malicious new maintainer, or an install-time script in a tainted release.
- **Blast radius**: every project that installs the poisoned version, including via transitive pulls.

### 4. Dependency confusion / substitution

An attacker publishes a package on a *public* registry with the same name as your *internal* private package and a higher version. Build tooling that checks the public registry first happily pulls the attacker's code into your pipeline and production.

- **Trigger**: unscoped internal package names plus registry resolution that prefers the highest version anywhere.
- **Impact**: attacker code executes inside your trusted build environment—often the most privileged place in your estate.

### 5. Typosquatting and brandjacking

Attackers register packages whose names are near-misses of popular ones—a swapped letter, an added hyphen, a plausible scope. A developer's typo or a copy-paste from a bad tutorial installs the malicious look-alike.

- **Trigger**: manual installs without verifying the exact, official package name.
- **Impact**: install-time or runtime code execution, credential theft.

### 6. Compromised build and distribution pipeline

Instead of attacking a package on a registry, the adversary compromises the vendor's build or update infrastructure and ships a *signed, trusted-looking* artifact that is nonetheless malicious. Customers who trust the vendor inherit the backdoor.

- **Trigger**: weak CI/CD security, unprotected signing keys, no provenance.
- **Impact**: mass distribution of tainted software to everyone downstream—the reason provenance (SLSA) and pipeline hardening matter for what *you* publish, too.

### 7. Vulnerable operating-system and base-image packages

Your container base image is a bundle of components as well. An old base image drags in outdated OpenSSL, glibc, curl, and shell utilities—each a potential vulnerability that ships with every deploy even if your application code is clean.

- **Trigger**: pinning to a base image tag that is never rebuilt, or a bloated image full of unused OS packages.
- **Impact**: exploitable OS-level flaws and a needlessly large attack surface inside the container.

### 8. Abandoned and end-of-life (EOL) components

A component whose maintainers have stopped work will never receive a fix. When a vulnerability is found in it, there is no patch to apply—you are exposed until you rip it out and replace it, which is slow under pressure.

- **Trigger**: depending on an unmaintained library or an EOL runtime/framework version.
- **Impact**: permanent exposure with no upstream remedy; forced, risky migration during an incident.

### 9. Blindness to transitive dependencies

Not an exploit itself but the condition that makes all the others worse. Most components are pulled in indirectly. Without a resolved lockfile and an SBOM, you literally cannot answer "do we use this vulnerable library?"—so you cannot respond when it matters.

- **Trigger**: no SBOM, no lockfile, tracking only what is in the manifest.
- **Impact**: days of manual investigation during an emergency instead of an instant, authoritative answer.

### 10. Integrity drift and unpinned versions

When versions float (`^1.2.0`, `latest`) and no integrity hash is enforced, two builds of the "same" commit can contain different code—and a registry compromise can slip an altered artifact into your build unnoticed.

- **Trigger**: no committed lockfile, no integrity hashes, mutable tags.
- **Impact**: non-reproducible builds and a silent path for tampered code to enter production.

## How Attackers Find Vulnerable Components

You are not usually singled out; you are found in bulk. The reconnaissance is cheap and automated:

- **Version banners and fingerprints**: response headers, error pages, JavaScript bundle contents, and default files reveal exact framework and library versions.
- **Public advisory feeds**: attackers watch the same GHSA/NVD feeds you do—disclosure is a starting gun, and mass scanning begins immediately.
- **Exposed manifests and source maps**: leaked `package-lock.json`, `composer.lock`, or source maps hand over your exact dependency list.
- **Registry monitoring**: adversaries scrape registries for internal-looking package names to target with dependency confusion, and for popular names to typosquat.
- **Commodity scanners**: off-the-shelf tools match your fingerprint against a database of known-vulnerable versions in seconds.

## Threat-to-Safeguard Mapping

| Threat | Primary safeguard in this control |
|--------|-----------------------------------|
| RCE via known-vulnerable library | SCA in CI + patch cadence + continuous scanning |
| Exploitation of public CVEs | Advisory monitoring (GHSA/NVD) + Dependabot/Renovate |
| Malicious / compromised package | Trusted sourcing + integrity verification + delayed adoption |
| Dependency confusion | Scoped internal packages + source pinning + lockfiles |
| Typosquatting | Verify exact official name + integrity hashes |
| Compromised build pipeline | Pipeline hardening + artifact signing + provenance (SLSA) |
| Vulnerable base-image packages | Container scanning (Trivy/Grype) + minimal images + rebuilds |
| Abandoned / EOL components | EOL tracking + planned replacement |
| Transitive blindness | SBOM covering direct + transitive components |
| Integrity drift / unpinned versions | Committed lockfiles with integrity hashes |

## Next Steps

- **[Overview](overview.md)**: What this control is and why it matters
- **[How to Implement](prevention.md)**: The countermeasures for every threat above
- **[Examples](examples.md)**: Insecure vs. secure component management in code
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply component security hands-on
