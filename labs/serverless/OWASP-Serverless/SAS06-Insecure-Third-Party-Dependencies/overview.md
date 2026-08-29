# SAS-6: Insecure Third-Party Dependencies - Overview

## Table of Contents
- [What are Insecure Third-Party Dependencies?](#what-are-insecure-third-party-dependencies)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What are Insecure Third-Party Dependencies?

**Insecure Third-Party Dependencies** occur when a serverless function pulls in external code—npm, PyPI, Maven, or Gradle packages, plus their transitive dependencies—that is vulnerable, malicious, unmaintained, or simply unaccounted for. The function's own code may be a few dozen lines, yet the deployment package it runs is dominated by libraries the author never wrote and often never read. When one of those libraries carries a known CVE, is typosquatted, or is hijacked upstream, the flaw ships to production inside your function and executes with your function's privileges.

Serverless makes this the defining risk rather than a peripheral one. A function is, by design, a **small piece of glue code**: it parses an event, calls a managed service, and returns. To do that it reaches for a SDK, a validation library, a date helper, a parser, a logging shim—each of which drags in a tree of transitive dependencies. The ratio of "code you wrote" to "code you shipped" is often 1:1000. Your real attack surface is that tree, not your handler.

### Core Concept

```
Secure Dependency Posture:
  Inventory     -> SBOM lists every direct AND transitive package + version
  Provenance    -> packages pulled from a trusted, scoped registry
  Pinning       -> exact versions + integrity hashes in a committed lockfile
  Scanning      -> SCA (npm audit / pip-audit / Snyk) gates every build
  Minimalism    -> only the packages the function actually needs
  Install scripts-> disabled or reviewed; no arbitrary code at build time
  Blast radius  -> least-privilege function role limits what a bad dep can reach

Insecure Dependency Posture:
  Inventory     -> nobody knows what is actually deployed in the .zip / layer
  Provenance    -> `npm install <name>` from whatever resolves first
  Pinning       -> floating ranges (^, ~, "latest"); no lockfile in CI
  Scanning      -> no SCA; CVEs discovered only after disclosure (or breach)
  Minimalism    -> hundreds of transitive packages for a 30-line handler
  Install scripts-> postinstall runs unreviewed code during build/deploy
  Blast radius  -> over-privileged role: a bad dep inherits the whole account
```

### The Serverless Twist

The property that makes this category distinct from a generic "vulnerable components" finding is **where the dependency runs and what it inherits**. A compromised library inside a traditional monolith is bounded by that host. A compromised library inside a Lambda function runs with the function's **IAM execution role**, its environment variables (which frequently hold secrets), and its network egress. If that role is over-privileged—as they very often are (see SAS-4)—a single malicious transitive package can read secrets, assume other roles, touch storage, and pivot into the wider cloud account. The dependency is not just running your logic; it is holding your credentials.

### Why It's Critical for Serverless

- Functions are **dependency-heavy by nature**: glue code that stitches together SDKs and helpers, so the third-party surface dwarfs the first-party code.
- Deployment is **opaque**: the running artifact is a zipped bundle or a shared Lambda layer that is easy to build once and forget, so nobody re-checks what versions are actually live.
- The **runtime is managed and short-lived**: you do not patch a server; a vulnerable library is only fixed by rebuilding and redeploying, which rarely happens on a security cadence.
- The **credentials are ambient**: the execution role and env vars are available to any code in the process, so a malicious dependency exfiltrates them with a single line at import time.

## Why Does This Matter?

### Business Impact

- **Account Compromise**: A malicious or vulnerable dependency inheriting an over-privileged role can escalate from one function to the whole cloud account—data, infrastructure, and billing.
- **Data Exfiltration**: Libraries with runtime access to env vars and the execution role can quietly ship secrets and customer data to an attacker endpoint.
- **Supply-Chain Breach**: A single hijacked upstream package propagates to every function that depends on it, across every team, in one release cycle.
- **Compliance Failure**: Shipping known-vulnerable components with no SBOM or patch process is itself an audit finding under SOC 2, PCI-DSS, and emerging supply-chain regulation.
- **Denial-of-Wallet**: A dependency that spins up crypto-mining or abusive workloads inside your functions turns pay-per-use billing into a runaway invoice (ties to SAS-8).

### Technical Impact

- **Remote Code Execution**: An unpatched CVE in a parser, deserializer, or template library bundled in the function or a layer gives an attacker code execution in the function's context.
- **Credential Theft at Runtime**: Malicious code reads `process.env` / `os.environ` and the container credential endpoint, exfiltrating the role's temporary keys.
- **Build-Time Compromise**: An `npm postinstall` (or `pip` build) script runs arbitrary code on the CI/CD host during install—before the function ever deploys.
- **Privilege Escalation and Pivot**: With the function's role in hand, the dependency assumes other roles or calls services the function never legitimately uses.
- **Expanded Attack Surface**: Every transitive package is more code that can carry a flaw; large trees make review and patching intractable.

## Technical Context

### Where Insecure Dependencies Come From

| Source | What Goes Wrong | Serverless Consequence |
|--------|-----------------|------------------------|
| Known-vulnerable versions | A direct or transitive package has a published CVE that is never patched | Public exploit runs in the function's context (RCE, DoS) |
| Malicious / typosquatted packages | A lookalike name (`reqeusts`, `crossenv`) or a hijacked maintainer account ships attacker code | Steals env/role credentials at import or runtime |
| Install-time scripts | `postinstall`/build hooks execute arbitrary code during install | Compromises the CI/CD build host and the artifact it produces |
| Large dependency trees | Hundreds of transitive packages nobody has audited | Attack surface and patch burden grow beyond what can be tracked |
| Bundled libs in Lambda layers | A shared layer pins an old, vulnerable library used by many functions | One stale layer makes a whole fleet exploitable at once |
| Outdated runtimes | The function runs a deprecated, unpatched language runtime | Runtime-level CVEs remain unfixed under every function |
| No deployment visibility | Nobody knows which versions are actually live | Vulnerable code lingers because no one can see it is there |

### The Dependency Iceberg

Direct dependencies are the tip; transitive dependencies are the mass below the waterline. A handler that declares three packages can easily resolve to several hundred.

```
# A "small" Node function's declared dependencies:
package.json  -> 3 direct deps

# What actually ships in the deployment bundle:
node_modules/ -> 312 packages, 1,900 files
              -> you wrote 0 of them
              -> you reviewed 0 of them
              -> each runs with the function's IAM role

# A single vulnerable or malicious package anywhere in that tree
# is a vulnerable or malicious package IN YOUR FUNCTION.
```

### How a Bad Dependency Becomes an Account Breach

```
1. A transitive package is hijacked/typosquatted or carries a known CVE.
        v
2. It is bundled into the function's .zip or a shared Lambda layer.
        v
3. At import (or when the CVE is triggered) the code runs INSIDE the function,
   with the function's environment variables and execution role.
        v
4. It reads AWS_* env creds / the container credentials endpoint and the role's
   temporary keys.
        v
5. If the role is over-privileged (SAS-4), it assumes other roles, reads S3,
   scans DynamoDB, and pivots across the account.
```

### Install-Time vs. Runtime Execution

Two distinct moments matter, and defenses differ for each:

- **Install/build time**: `npm install` or `pip install` can run lifecycle scripts (`preinstall`, `install`, `postinstall`) that execute on your build host—stealing CI secrets or tampering with the artifact before deploy.
- **Function runtime**: once deployed, any imported module runs when the function initializes or handles an event, with access to the live role and environment.

## Real-World Impact

The examples below are described as **incident classes**—repeatedly observed patterns—rather than specific fabricated CVE numbers, because the durable lesson is the pattern, not any single advisory.

### Case Class 1: Malicious npm Package in the Dependency Tree (event-stream-class)

**Weakness**:
- A widely used, low-attention npm package changes maintainership, and a new maintainer introduces malicious code—often buried in a fresh transitive dependency rather than the top-level package.
- Downstream projects, including serverless functions, pull the update automatically because they use floating version ranges and no integrity pinning.

**Impact**:
- The injected code runs wherever the package is loaded. In a function, that means it executes with the execution role and can read environment secrets and credentials—classes of this attack have targeted exactly such secrets.

**Root Cause**: Implicit trust in transitive maintainers, floating versions, and no lockfile/hash verification, so a single upstream change silently propagated everywhere.

### Case Class 2: Typosquatting and Dependency-Confusion Waves

**Weakness**:
- Attackers publish packages whose names resemble popular ones (`crossenv` vs `cross-env`) or that match a company's *internal* package names on the public registry at a higher version.
- A mistyped name, or a resolver that prefers the public registry, installs the attacker's package into the build.

**Impact**:
- Repeated, well-documented waves of typosquatted and dependency-confusion packages have shipped credential-stealing payloads via install scripts—executing on build hosts and in the resulting artifacts.

**Root Cause**: Unscoped installs from an untrusted registry with install scripts enabled, and no verification that a name resolves to the intended source.

### Case Class 3: Unpatched Known-Vulnerable Library Bundled in a Layer

**Weakness**:
- A shared Lambda layer bundles a parsing/serialization library with a public advisory. Many functions depend on the layer and inherit the vulnerable version.
- No SCA scans the layer contents, and the layer is rarely rebuilt.

**Impact**:
- An attacker who can reach an affected code path triggers the public exploit and gains code execution inside every function that uses the layer—then leverages the execution role to go further.

**Root Cause**: Vulnerable code centralized in an unscanned, stale layer, multiplying a single unpatched dependency across a whole fleet.

## Prevalence and Statistics

Insecure third-party dependencies are a durable entry in both the OWASP Serverless Top 10 (as SAS-6) and the broader OWASP Top 10 lineage (as "Vulnerable and Outdated Components"). Software-composition studies consistently find that the majority of a modern application's code—often well over 80%—is third-party, and that a large share of scanned projects contain at least one known-vulnerable dependency.

Rather than cite precise counts (which vary by source and year), the defensible picture is:

- Most of what a serverless function ships is code the team did not write, so the dependency tree is the dominant attack surface.
- Known-vulnerable transitive dependencies are **extremely common and easy to detect** with SCA—yet frequently go unpatched because nobody owns the update cadence.
- Supply-chain attacks (malicious/typosquatted/hijacked packages) have grown into a **recurring, industrialized** class of incident against public registries.

> Note: exact percentages differ between reports. Treat any single figure as illustrative; the durable takeaway is that dependencies are the majority of your code, they are routinely vulnerable, and in serverless they run with your function's credentials.

## Common Misunderstandings

### Myth 1: "My function is tiny, so my attack surface is tiny"

**Reality**: The handler is tiny; the shipped bundle is not. A 30-line function routinely deploys hundreds of transitive packages, and every one runs with the function's role.

### Myth 2: "I only use popular, trusted packages"

**Reality**: You directly chose a few trusted packages; you implicitly trust everyone in their transitive tree. Popular packages have been hijacked, and their dependencies change maintainers without your knowledge.

### Myth 3: "npm audit / pip-audit once was enough"

**Reality**: New CVEs are disclosed continuously against versions you already shipped. Scanning must run on every build and on a schedule against what is deployed, not once at the start of a project.

### Myth 4: "The managed platform patches my dependencies"

**Reality**: The provider patches the underlying infrastructure and, on a schedule, the base runtime. It does not patch the libraries *you* bundled—those are only fixed when you rebuild and redeploy.

### Myth 5: "A vulnerable dependency is harmless if I do not call the vulnerable function"

**Reality**: Malicious packages run at *import* and via install scripts regardless of whether you call them, and reachability of a CVE is hard to prove. Presence in the tree is the risk.

### Myth 6: "Lockfiles are just for reproducible builds"

**Reality**: A committed lockfile with integrity hashes, installed via `npm ci` or `--require-hashes`, is also a security control—it prevents a silently swapped or tampered package from entering your artifact.

## How SAS-6 Differs from Related Issues

| Aspect | Insecure Third-Party Dependencies (SAS-6) | Over-Privileged Roles (SAS-4) | Event-Data Injection (SAS-1) |
|--------|--------------------------------------------|-------------------------------|-------------------------------|
| **Root cause** | Vulnerable/malicious external code in the bundle or layer | Function role grants more than it needs | Untrusted event data reaches a sink |
| **What it does** | Runs attacker/vulnerable code with the function's identity | Widens what any compromise can reach | Executes attacker intent in your logic |
| **Typical fix** | Inventory, scan, pin, minimize, patch, vet sources | Least-privilege, scoped IAM policies | Validate/parameterize input |
| **Relationship** | The way in | The blast radius multiplier | A different way in |

## Key Takeaways

1. **Your dependencies are your code**—in serverless, most of what ships is third-party, so the tree is your real attack surface.
2. **A bad dependency inherits your role**—it runs with the function's IAM credentials and environment, so blast radius is set by SAS-4.
3. **Transitive is the danger zone**—you vet direct deps but implicitly trust hundreds you never see.
4. **Install scripts run before deploy**—a malicious package can compromise the build host, not just the runtime.
5. **Visibility precedes defense**—without an SBOM and continuous SCA, vulnerable code lingers because no one can see it.

## How to Identify if You're Vulnerable

- [ ] Do you have a current inventory / SBOM of every direct *and transitive* dependency actually deployed?
- [ ] Does SCA (npm audit, pip-audit, Snyk, OWASP Dependency-Check) gate every build and run on a schedule against what is live?
- [ ] Are versions pinned with integrity hashes in a committed lockfile, installed via `npm ci` / `--require-hashes`?
- [ ] Do you minimize dependencies (small functions, tree-shaking) rather than pulling in broad frameworks?
- [ ] Do you vet package provenance and pull from a trusted, scoped registry (guarding against dependency confusion)?
- [ ] Do you patch/update dependencies and runtimes on a defined cadence, not just at project start?
- [ ] Do you scan Lambda layers and container images, not just `package.json`?
- [ ] Are install scripts disabled or reviewed (`--ignore-scripts`) in CI?
- [ ] Is the function's execution role least-privilege, so a bad dependency's blast radius is bounded?
- [ ] Do you monitor runtime egress so a dependency exfiltrating data is visible?

If you answered "no" or "not sure" to several of these, a vulnerable or malicious dependency may already be deployed with your functions' credentials.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers exploit CVEs and malicious packages inside functions
- **[Prevention](prevention.md)**: Build inventory, scanning, pinning, and least-privilege defenses
- **[Examples](examples.md)**: Vulnerable vs. secure package config, lockfiles, CI scanning, and layers
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
