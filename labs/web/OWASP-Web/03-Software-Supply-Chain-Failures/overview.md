# Software Supply Chain Failures - Overview

## Table of Contents
- [What Are Software Supply Chain Failures?](#what-are-software-supply-chain-failures)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)
- [Relationship to A06:2021](#relationship-to-a062021)

## What Are Software Supply Chain Failures?

**Software Supply Chain Failures** occur when an attacker compromises any of the people, code, tools, or infrastructure that a piece of software depends on *before* it reaches production—so that malicious or vulnerable code is delivered through channels the victim already trusts. The application team may write flawless code and still ship a backdoor, because the compromise lives in a dependency, a build server, a signing key, a container base image, or a script loaded from a third-party CDN.

This is the defining shift of the 2025 edition. The 2021 Top 10 addressed one slice of the problem under **A06:2021 – Vulnerable and Outdated Components**, which focused on running dependencies with known vulnerabilities. The 2025 category **subsumes and greatly expands** that scope: it is no longer only "are your libraries patched?" but "can you trust every link in the chain that produced and delivered your software?"

### The Software Supply Chain

```
SOURCE  -->  DEPENDENCIES  -->  BUILD  -->  PACKAGE  -->  DISTRIBUTE  -->  DEPLOY  -->  RUN
  |             |               |            |             |               |          |
 SCM         registries       CI/CD       artifact       registry       runtime    browser /
 commits     (npm, PyPI,      runners,    signing        / CDN /         hosts /    third-party
 & PRs       Maven, etc.)    build steps  & provenance   mirrors         clusters   scripts

A trust failure at ANY node ships attacker-controlled code to everyone downstream.
```

Concretely, a modern application is assembled far more than it is written. A typical service pulls in hundreds to thousands of packages once transitive (nested) dependencies are resolved, builds them on shared automation, packages them into container images layered on other people's base images, and—on the web tier—loads analytics, tag managers, and payment widgets directly from third-party domains at runtime. Each of those is a trust relationship an attacker can target.

### The Failure Classes

- **Vulnerable / outdated dependencies**: shipping components with known, published vulnerabilities (the classic A06:2021 case).
- **Malicious packages, typosquatting, and dependency confusion**: packages that are hostile by design—named to imitate a popular library, or to shadow an internal package name so the public one is installed instead.
- **Compromised maintainer accounts / hijacked packages**: a legitimate, trusted package taken over through a phished or stolen credential, then republished with malware.
- **Compromised build systems and CI/CD pipelines**: poisoned runners, malicious build steps, and leaked pipeline secrets that let an attacker inject code *during* the build—after review, before signing.
- **Unsigned / unverified artifacts and lack of provenance**: no cryptographic evidence of *what* was built, *from what source*, and *by whom*, so a swapped artifact is indistinguishable from the real one.
- **Poisoned container base images**: a compromised or malicious base layer that every image built `FROM` it inherits.
- **Compromised third-party scripts and CDNs**: web-skimming ("Magecart"-style) code injected into a script the page loads at runtime from someone else's server.
- **Insecure package registries**: registries or mirrors that permit account takeover, name reuse after deletion, or unauthenticated publishing.

## Why Does This Matter?

Supply chain compromise is uniquely valuable to attackers because it is a **force multiplier**: one successful intrusion at an upstream provider is inherited automatically by everyone who trusts that provider. It also bypasses most traditional defenses—the malicious code arrives signed, from an expected source, through the normal update mechanism, and is often installed by automation with elevated privileges.

### Business Impact
- **Mass, simultaneous compromise**: a single poisoned update can reach thousands of downstream organizations at once, as the SolarWinds class of incident demonstrated.
- **Loss of customer trust and brand damage**: customers hold the vendor responsible even when the root cause was an upstream dependency.
- **Regulatory and contractual exposure**: breach-notification laws (GDPR and others) and payment rules (PCI DSS) apply regardless of whether the malicious code was yours.
- **Direct financial theft**: web-skimmers harvest live payment-card data at checkout; malicious packages steal cloud credentials, tokens, and crypto-wallet keys.
- **Software-liability pressure**: procurement increasingly requires a Software Bill of Materials (SBOM) and provenance attestations; not having them blocks sales and renewals.

### Technical Impact
- **Remote code execution during install or build**: package lifecycle hooks (npm `postinstall`, Python `setup.py`) and build steps run arbitrary code on developer and CI machines.
- **Secret and credential theft**: CI/CD runners hold cloud keys, signing keys, and registry tokens—prime targets once a build step is attacker-controlled.
- **Persistence and lateral movement**: a backdoor in a widely deployed component gives long-lived access across many hosts and networks.
- **Data exfiltration at runtime**: compromised third-party browser scripts read form fields, tokens, and DOM content directly from victims' sessions.
- **Undetectable-by-signature delivery**: because artifacts are validly signed by the compromised publisher, endpoint and gateway controls treat them as trusted.

## Technical Context

### Where Trust Can Break in the Chain

| Stage | What you trust | How it fails | Attacker payoff |
|-------|----------------|--------------|-----------------|
| Source (SCM) | Commits and pull requests | Stolen developer creds, malicious PR, tampered branch | Code enters "legitimately" |
| Dependencies | Public registries | Typosquat, dependency confusion, hijacked package | Malicious code auto-installed |
| Build (CI/CD) | Runners and build steps | Poisoned runner, leaked secrets, malicious step | Inject after review, before signing |
| Package / sign | Signing keys, provenance | Stolen key, no provenance, unsigned artifact | Malicious artifact looks authentic |
| Distribute | Registries, CDNs, mirrors | Registry takeover, CDN/script compromise | Swap or skim at delivery |
| Container base | Base images | Poisoned or outdated base layer | Every child image inherits it |
| Runtime (web) | Third-party scripts | Magecart-style injection | Live data theft from users |

### Why Transitive Dependencies Amplify the Risk

Your direct dependencies are only the top of an iceberg. Each one pulls in its own dependencies, which pull in theirs, often several levels deep. You may vet the ten packages you chose and still install a thousand you never evaluated.

```
your-app
└── trusted-framework        (you reviewed this)
    └── helper-lib            (you did not)
        └── tiny-utility      (nobody reviewed this)
            └── COMPROMISED    <-- one hijacked leaf reaches your production
```

A compromise at a deep, obscure, widely-reused leaf package can therefore affect an enormous number of applications that have no idea they depend on it. This is exactly why an inventory (SBOM) matters: you cannot defend, or even assess, what you do not know you are shipping.

### Dependency Confusion, Concretely

Many organizations use internal package names (for example `@acme/auth-client` or `acme-internal-utils`) that exist only in a private registry. If the build tool is configured to consult the public registry as well, an attacker can publish a package with the *same name* and a *higher version number* to the public registry. Default "highest version wins" resolution then pulls the attacker's public package into internal builds—no typo or human error required.

## Real-World Impact

The incidents below are referenced as **illustrative classes** of failure. Specific figures vary by source and are deliberately omitted; the durable lesson is the *mechanism*, not a precise statistic.

### Class 1: Build-System Compromise (SolarWinds-style)
**Mechanism**: Attackers gained access to a vendor's build pipeline and inserted malicious code into the software *during the build*, so the tampered update was compiled, signed with the vendor's legitimate certificate, and distributed through the normal update channel. Customers who installed a properly signed update from a trusted vendor received a backdoor.

**Lesson**: Code review and code signing are insufficient on their own if the build environment itself is untrusted. This is the canonical argument for build integrity, provenance (SLSA), and hardened, ephemeral runners.

### Class 2: Compromised CI Uploader / Leaked Secrets (Codecov-style)
**Mechanism**: A widely-used CI helper script was modified so that, when it ran inside customers' pipelines, it exfiltrated environment variables—which routinely contain cloud keys, registry tokens, and other secrets—to an attacker-controlled endpoint.

**Lesson**: Anything executed in CI can read your pipeline secrets. Least-privilege, short-lived credentials and verifying the integrity of third-party CI tooling are essential.

### Class 3: Maintainer Account Hijack (ua-parser-js / coa-style)
**Mechanism**: An attacker took over a legitimate maintainer's registry account (through credential theft or phishing) and published new, malicious versions of very popular packages. Auto-updating consumers pulled malware that stole credentials and installed miners.

**Lesson**: Popularity is not safety. Pin versions, require publisher 2FA, and do not blindly auto-update to the newest release.

### Class 4: Malicious Insider / Protestware (event-stream-style)
**Mechanism**: A widely-depended-upon package was handed off to a new "maintainer" who added a malicious transitive dependency targeting a specific downstream application. The payload was obfuscated and narrowly targeted, so it evaded casual inspection.

**Lesson**: Maintainer turnover and social-engineering of trust are real attack vectors. Review dependency *changes*, not just initial selection.

### Class 5: Long-Game Backdoor via Social Engineering (xz-utils-style)
**Mechanism**: An attacker spent a long period building trust as a helpful contributor to a low-profile but critical open-source project, eventually gaining maintainer rights and introducing a carefully hidden backdoor into release artifacts (not obvious in the source repository).

**Lesson**: Trust in open source is a process, not a one-time check. Reproducible builds and scrutiny of release artifacts (not just source) are defenses against build-time-only payloads.

### Class 6: Web-Skimming via Third-Party Scripts (Magecart-style)
**Mechanism**: Attackers compromised a third-party script (analytics, chat, or a shared library on a CDN) that many e-commerce sites loaded directly into their checkout pages. The injected code silently copied payment-card fields as customers typed them and sent the data to an attacker's server.

**Lesson**: Any script you load from another origin runs with full access to your page. Subresource Integrity (SRI), a strict Content-Security-Policy, and minimizing third-party scripts are the front-line defenses.

## Prevalence and Statistics

Supply chain attacks have moved from rare, headline events to a routine, industrialized category. Automated campaigns publish malicious packages to public registries continuously, and dependency-confusion and typosquatting are now standard techniques in commodity tooling.

Rather than cite precise counts (which differ widely by source and year), the defensible picture is:
- The overwhelming majority of a modern application's code is **third-party**, so most of your attack surface is code you did not write.
- Malicious-package publication to public registries is **continuous and automated**, not occasional.
- The category is **hard to detect** with signature-based tools because payloads arrive validly signed through trusted channels.
- Impact ranges from **developer-machine compromise** (install hooks) through **CI secret theft** up to **mass downstream compromise** (poisoned updates).

> Note: treat any single percentage or breach count as illustrative. The durable takeaway is that third-party and build-time code dominate your risk, and that trust in the chain must be verified, not assumed.

## Common Misunderstandings

### Myth 1: "We passed code review, so our software is safe."
**Reality**: Review covers the source you can see. Build-system compromise, hijacked dependencies, and malicious release artifacts inject code *after* review or *outside* the repository entirely.

### Myth 2: "The package is popular and has millions of downloads, so it's trustworthy."
**Reality**: Popularity makes a package a *better* target. Several high-impact incidents hijacked packages precisely because they were widely used and auto-updated.

### Myth 3: "A signature means the artifact is safe."
**Reality**: A signature proves who signed it, not that the signer's build was clean. If the signing key or build system is compromised, malware is signed too. You need *provenance* (what was built, from what source, by which pipeline), not just a signature.

### Myth 4: "Pinning versions is enough."
**Reality**: Pinning defeats surprise auto-updates, but a pinned version can still be a hijacked release, and a mutable tag (like `latest`) or an unpinned CI action can still change under you. Pin to immutable identifiers (hashes/digests) and verify them.

### Myth 5: "This is just the old 'outdated components' problem renamed."
**Reality**: Outdated components (A06:2021) are one subset. The 2025 category adds malicious/hostile packages, build and CI/CD compromise, provenance, container base images, and runtime third-party scripts.

### Myth 6: "Third-party scripts on our website are the vendor's responsibility."
**Reality**: A script you embed runs in *your* users' browsers with access to *your* page. If the vendor is compromised, your customers' data is stolen from your site. SRI and CSP put that risk back under your control.

## Relationship to A06:2021 – Vulnerable and Outdated Components

A06:2021 asked one question: are you running components with known vulnerabilities and keeping them patched? That question remains valid and is fully contained within the 2025 category. What changed is the *threat model*: attackers no longer wait for you to run an old, vulnerable version—they actively poison the supply itself.

| Aspect | A06:2021 (Vulnerable & Outdated Components) | A03:2025 (Software Supply Chain Failures) |
|--------|--------------------------------------------|-------------------------------------------|
| Core question | Is my dependency patched? | Can I trust the whole chain that produced and delivered my software? |
| Threat | Passive: known CVE in an old version | Active: malicious packages, hijacks, build/CI compromise |
| Scope | Running dependencies | Source, dependencies, build, signing, distribution, base images, runtime scripts |
| Key defense | Patch cadence, SCA | SCA + SBOM + provenance/signing + hardened CI/CD + registry controls + SRI |

## Key Takeaways

1. **Most of your code is someone else's.** Your risk lives largely in dependencies, build tooling, and third-party scripts—not just your source.
2. **Trust must be verified, not assumed.** Signatures prove identity; provenance proves origin and build integrity. Prefer both.
3. **The build system is production.** A compromised CI/CD pipeline injects code after review and signs it as authentic—harden it accordingly.
4. **Know what you ship.** An SBOM turns "we think we're not affected" into a searchable, defensible answer during the next incident.
5. **Pin to immutable identifiers.** Hashes and digests, private-registry precedence, and scoped names defeat confusion, typosquatting, and silent mutation.
6. **The browser tier counts.** SRI and CSP contain the runtime third-party-script risk that traditional dependency scanning never sees.

## How to Identify if You're Exposed

Ask these questions about your software and its pipeline:
- [ ] Can you produce a complete, current SBOM for what is running in production?
- [ ] Are all dependencies resolved from a lockfile pinned to hashes, not floating ranges?
- [ ] Do internal package names resolve to your private registry *first*, with public fallback controlled?
- [ ] Are build artifacts signed and accompanied by provenance (for example SLSA / Sigstore)?
- [ ] Do CI/CD runners use short-lived, least-privilege credentials and pinned, SHA-referenced actions?
- [ ] Are container base images pinned by digest and scanned, not pulled from mutable tags like `latest`?
- [ ] Does every third-party `<script>`/`<link>` carry a Subresource Integrity hash, backed by a CSP?
- [ ] Do you scan dependencies (SCA) continuously and have a defined patch cadence?

Several "no" or "not sure" answers indicate meaningful supply chain exposure today.

## Next Steps

- **[Attack Vectors](attack-vectors.html)**: How attackers poison each link in the chain, with concrete patterns.
- **[Prevention](prevention.html)**: Layered defenses—SBOM, pinning, provenance, hardened CI/CD, SRI.
- **[Examples](examples.html)**: Vulnerable vs. secure across npm, pip, CI/CD, Maven, containers, and SRI.
- **[Hands-On Lab](./lab/software-supply-chain-failures/)**: Practice identifying and hardening a vulnerable supply chain in a safe, isolated environment.
