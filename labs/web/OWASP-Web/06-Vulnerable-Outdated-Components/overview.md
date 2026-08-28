# A06:2021 – Vulnerable and Outdated Components: Overview

## Table of Contents

- [What Are Vulnerable and Outdated Components?](#what-are-vulnerable-and-outdated-components)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)
- [A Note on the 2025 Edition](#a-note-on-the-2025-edition)
- [Self-Assessment](#self-assessment)

## What Are Vulnerable and Outdated Components?

**A06:2021 – Vulnerable and Outdated Components** is the risk of building and running software on top of third-party code that has *known* security flaws, or that is so old it is no longer maintained or patched. The vulnerability is rarely in the code your team wrote—it is in the libraries, frameworks, runtimes, operating-system packages, and container base images you assembled the application from.

A modern web application is mostly *other people's code*. A typical Node.js or Java service pulls in tens of direct dependencies, which in turn pull in hundreds or thousands of **transitive** (nested) dependencies. Add the language runtime, the web server, the OS packages in the container, and the base image itself, and the majority of the bytes running in production were never written—or reviewed—by the team that deployed them. When any one of those components has a published vulnerability, the application inherits it.

OWASP defines this category around a handful of concrete conditions. You are likely vulnerable if:

- You **do not know the versions** of all the components you use—both direct dependencies and the transitive ones they drag in—on both client and server side.
- The software is **vulnerable, unsupported, or out of date**: the OS, web/application server, database, APIs, runtimes, libraries, and container images.
- You **do not scan for vulnerabilities regularly** and do not subscribe to security advisories for the components you use.
- You **do not fix or upgrade the platform, frameworks, and dependencies** in a risk-based, timely fashion—common when patching is a quarterly or annual task on a change-controlled system.
- Developers **do not test compatibility** of updated, upgraded, or patched libraries, so upgrades stall out of fear of breakage.
- You **do not secure the component configurations** (which overlaps with A05:2021 – Security Misconfiguration).
- Components are obtained from **untrusted or unofficial sources** rather than from official, signed repositories.

> The defining word is **known**. This category is not about zero-days. It is about vulnerabilities that already have a public advisory, a CVE or GHSA identifier, a patched version, and—very often—a working public exploit. The defender's job is not research; it is *inventory and hygiene*.

### Core Concept

```
Your application code           ~5% of what runs in production
     |
     +-- Direct dependencies    the libraries you chose (package.json, pom.xml)
             |
             +-- Transitive deps the libraries THEY chose (often 10-50x more)
     |
     +-- Language runtime        Node, Python, JVM, .NET, PHP, Ruby
     |
     +-- OS packages             openssl, glibc, curl, zlib in the container
     |
     +-- Base image              debian:buster, node:14, alpine:3.9 ...

A KNOWN vulnerability in ANY layer becomes YOUR vulnerability.
"I never call that function" is not a defence if it is reachable.
```

## Why Does This Matter?

### Business Impact

- **Full System Compromise from a One-Line Dependency**: A single vulnerable logging or serialization library can hand an attacker remote code execution across every service that includes it—regardless of how well your own code is written.
- **Mass, Automated Exploitation**: Because these flaws are public and widespread, attackers scan the entire internet for them within hours of disclosure. You are not being individually targeted; you are being swept up.
- **Regulatory and Contractual Exposure**: Breaches traced to unpatched, publicly-known vulnerabilities are difficult to defend to regulators, insurers, and customers, because "a patch existed and was not applied" reads as negligence under GDPR, HIPAA, and PCI-DSS.
- **Supply-Chain Trust Damage**: If your product ships a vulnerable component to *your* customers, you become the vector for *their* breach.
- **Emergency, Unplanned Work**: A critical advisory in a ubiquitous library forces every team to drop planned work and patch under time pressure—expensive and error-prone.

### Technical Impact

- **Remote Code Execution (RCE)**: The highest-impact class—deserialization flaws, expression-language injection, and template-engine bugs in popular libraries frequently yield full RCE.
- **Information Disclosure**: Memory-safety bugs in cryptographic or parsing libraries can leak keys, session tokens, and private data.
- **Denial of Service**: Algorithmic-complexity and decompression bugs let a tiny request exhaust CPU or memory.
- **Authentication and Access-Control Bypass**: Vulnerabilities in auth frameworks or JWT libraries can undermine controls the application relies on entirely.
- **Privilege Escalation and Lateral Movement**: A vulnerable OS package inside a container can be the first hop toward the host or the wider cluster.

## Technical Context

### Direct vs. Transitive Dependencies

The single most important idea in this category is that you are responsible for code you never explicitly chose. A dependency you list is a **direct** dependency. Everything *it* requires, and everything those require, are **transitive** dependencies. Most published vulnerabilities that affect real applications live in the transitive layer—precisely because teams are not looking there.

```
$ npm ls express
myapp@1.0.0
└─┬ express@4.17.1          <- direct dependency (you chose this)
  ├─┬ body-parser@1.19.0    <- transitive (express chose it)
  │ ├── qs@6.7.0            <- transitive (body-parser chose it)
  │ └── raw-body@2.4.0
  ├── cookie@0.4.0
  └── ... dozens more

A CVE in qs is YOUR problem even though you never typed "qs".
```

### How a Component Becomes "Known-Vulnerable"

| Stage | What Happens | Defender's Window |
|-------|--------------|-------------------|
| Discovery | A researcher or maintainer finds a flaw in a library | Not yet public |
| Disclosure | A CVE/GHSA is published; a fixed version is released | The clock starts |
| Weaponization | Proof-of-concept and exploit code appear publicly | Often hours to days |
| Mass scanning | Automated bots scan the internet for the vulnerable version | Days to weeks |
| Exploitation | Unpatched instances are compromised | Ongoing for years |

The gap an attacker exploits is the time between *disclosure* (a fix exists) and *your deployment of that fix*. Organizations that patch in days close the window; those that patch quarterly leave it open for months.

### Where Vulnerable Components Hide

| Layer | Examples | How Version Is Declared |
|-------|----------|-------------------------|
| Application libraries | Express, Spring, Django, jQuery, Log4j | package.json, pom.xml, requirements.txt |
| Frameworks | Rails, Laravel, Struts, Angular | Lockfiles / manifests |
| Language runtime | Node, CPython, JVM, PHP, Ruby | Base image tag, .nvmrc, runtime.txt |
| OS packages | openssl, glibc, bash, curl, zlib | Container / VM package manager |
| Base image | debian, alpine, ubuntu, distroless | Dockerfile FROM line |
| Client-side assets | Bundled JS libs, CDN-loaded scripts | package.json, `<script>` tags |

### Why Patching Is Harder Than It Sounds

- **Fear of breakage**: A major-version upgrade can change APIs. Without automated tests, teams cannot upgrade with confidence, so they don't.
- **Transitive pinning**: You may want a patched `qs`, but your direct dependency pins the vulnerable one. Fixing it may require upgrading the parent or using an override.
- **Unmaintained components**: Some libraries have no patched version because the project is abandoned (end-of-life). The only fix is replacement.
- **Inventory blindness**: You cannot patch what you do not know you have. Without an accurate component inventory, advisories cannot be matched to assets.

## Real-World Impact

The incidents below are well-known, publicly documented event *classes*. They are referenced by their commonly-used names to illustrate the pattern; specific figures vary by source and are omitted deliberately.

### Case Class 1: Critical RCE in a Ubiquitous Utility Library (the "Log4Shell" class)

**The pattern**: A widely-embedded Java logging library was found to evaluate attacker-controlled input in a way that led to remote code execution. Because the library was a transitive dependency of an enormous number of applications and appliances, most affected operators did not even know they were running it.

**Why it was so damaging**:

- The vulnerable code was reachable simply by getting the application to *log* a hostile string—a username, a User-Agent, a chat message.
- Mass internet-wide scanning began almost immediately after disclosure.
- Countless organizations had no inventory that could answer "do we use this, and where?"—turning patching into a frantic scavenger hunt.

**The lesson**: The bug was in a transitive dependency almost nobody had chosen consciously. An accurate component inventory (SBOM) turned a multi-week emergency into a targeted, one-day patch for the organizations that had one.

### Case Class 2: Framework RCE Left Unpatched (the "Struts" class)

**The pattern**: A popular web application framework disclosed a critical remote-code-execution flaw and released a fixed version. Organizations that did not apply the update in a timely fashion—in some documented breaches, months after the fix was available—were compromised through the known, public flaw.

**The lesson**: This is the archetypal A06 breach. There was no zero-day, no sophisticated adversary—only a public patch that was not applied on any reasonable cadence. Slow, un-prioritized patching converts a solved problem into a catastrophic one.

### Case Class 3: Memory-Safety Bug in a Core Crypto Library (the "Heartbleed" class)

**The pattern**: A memory-handling flaw in an extremely widely-used TLS/cryptography library allowed remote attackers to read chunks of server memory—potentially exposing private keys, session tokens, and user data—with no authentication and no trace in typical logs.

**The lesson**: The most foundational, "obviously trustworthy" components are still just components. They must be inventoried, monitored for advisories, and patched like everything else—and the blast radius of a flaw in a near-universal library is correspondingly enormous.

### Case Class 4: Deserialization RCE in a Data-Binding Library

**The pattern**: Libraries that deserialize untrusted data (converting JSON/XML/binary back into objects) have repeatedly shipped "gadget chain" vulnerabilities that let crafted input instantiate dangerous objects and achieve code execution. New gadget chains are found periodically, so a component that was "safe" last year may need patching this year.

**The lesson**: Vulnerability status is not static. A component you cleared once must be continuously re-checked against new advisories.

## Prevalence and Statistics

In the OWASP Top 10 2021, **Vulnerable and Outdated Components ranked #6 (A06)**. Notably, it was one of the few categories ranked primarily from a community survey rather than mapped CVE data—the OWASP community rated it a top concern even though it is inherently difficult to test for automatically at scale. It moved up from #9 in the 2017 edition.

Rather than cite precise percentages (which differ between reports and years), the defensible picture is:

- The **overwhelming majority of applications** ship with at least one dependency that has a known vulnerability—most commonly deep in the transitive tree.
- The problem is **widespread and easy to detect** with software composition analysis, yet remains prevalent because detection and *remediation* are different problems.
- The **exploitability and impact** range from trivial to critical, with the RCE-in-a-common-library class representing some of the highest-impact events in the history of web security.

> Note: treat any single headline figure as illustrative. The durable takeaway is that nearly every non-trivial application has known-vulnerable components right now, most of them transitive, and the differentiator between organizations is not whether they *have* them but how fast they *find and fix* them.

## Common Misunderstandings

### Myth 1: "We wrote secure code, so we're fine"

**Reality**: Most of what runs in production is not your code. A flawless application can still be fully compromised through a vulnerable library it never explicitly imported.

### Myth 2: "We don't call the vulnerable function, so it can't hurt us"

**Reality**: Reachability is hard to prove and easy to get wrong. Frameworks call libraries in non-obvious ways, and "unreachable" code becomes reachable after a refactor. Assume a vulnerable component is exploitable unless you have strong, ongoing evidence otherwise.

### Myth 3: "If it isn't broken, don't upgrade"

**Reality**: A component that works perfectly can still be publicly vulnerable. "Works" and "secure" are independent properties. Staying on an old version to avoid change is exactly how the Struts-class breaches happened.

### Myth 4: "Our dependencies are our vendors' problem"

**Reality**: You ship and operate the composed system. Regulators and customers hold *you* accountable for the vulnerabilities in the product you deliver, whoever originally wrote the code.

### Myth 5: "We scanned once and it was clean"

**Reality**: New advisories are published every day against components you already have. A clean scan is a snapshot, not a guarantee. Scanning must be continuous and must re-evaluate existing dependencies against new advisories.

### Myth 6: "Only direct dependencies matter"

**Reality**: The majority of impactful vulnerabilities live in transitive dependencies—the ones nobody chose on purpose and few teams even enumerate.

### Myth 7: "A newer version is always safer"

**Reality**: Usually true, but not automatically. Pulling components from unofficial mirrors, or grabbing an unvetted "latest," can introduce a malicious or backdoored build. Obtain components from official, signed sources and verify integrity—newness is not the same as trustworthiness.

## A Note on the 2025 Edition

> **Edition context.** This lesson teaches the **2021** category as written: the narrower risk of using components with *known* vulnerabilities or that are outdated/unsupported. In the OWASP Top 10 **2025** edition, this concern was broadened and renamed into a larger **Software Supply Chain Failures** category, which also covers threats such as malicious packages, dependency-confusion and typosquatting attacks, compromised build pipelines, and CI/CD integrity. Those broader supply-chain topics are covered in a separate lesson on this platform. Here we stay focused on the classic "known-vulnerable and outdated components" problem, which remains a core part of the 2025 category.

## Self-Assessment

Ask these questions about your application and delivery pipeline:

- [ ] Can you produce a complete, current list of every component—direct and transitive—in the running system, with exact versions?
- [ ] Do you generate a Software Bill of Materials (SBOM) as part of your build?
- [ ] Does software composition analysis (SCA) run automatically on every build and block on critical findings?
- [ ] Are you subscribed to advisories (CVE/GHSA/vendor) for the components and runtimes you depend on?
- [ ] Do you have a defined, risk-based patching cadence—and can you patch a critical advisory in days, not quarters?
- [ ] Do automated tests give you the confidence to upgrade dependencies routinely?
- [ ] Have you removed unused dependencies, features, and files to shrink the attack surface?
- [ ] Are your OS packages and container base images patched and rebuilt regularly, not frozen at build time?
- [ ] Do you obtain all components from official, signed sources and verify their integrity?
- [ ] Do you have a plan for components that are end-of-life or unmaintained (replacement, not just patching)?

If you answered "no" or "not sure" to several of these, you almost certainly have exploitable, known-vulnerable components in production today.

## Next Steps

- **[Attack Vectors](./attack-vectors.md)**: How attackers find and exploit known-vulnerable components
- **[Prevention](./prevention.md)**: Build a layered program of inventory, scanning, and timely patching
- **[Examples](./examples.md)**: Vulnerable vs. secure dependency management across ecosystems
- **[Hands-On Lab](./lab/outdated-library-lab/)**: Practice identifying and remediating an outdated library

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
