# Software and Data Integrity Failures - Overview

## Table of Contents

- [What Are Software and Data Integrity Failures?](#what-are-software-and-data-integrity-failures)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)
- [How This Differs From Related Categories](#how-this-differs-from-related-categories)
- [Self-Assessment](#self-assessment)

## What Are Software and Data Integrity Failures?

**Software and Data Integrity Failures** occur when code, infrastructure, or data is trusted without verifying that it has not been tampered with. The core question this category asks is simple: *"How do you know that the software you are running, and the data you are about to act on, are exactly what you expect—and not something an attacker substituted along the way?"* When the answer is "we assume it's fine," you have an integrity failure.

This was a **new category introduced in the OWASP Top 10 2021**, ranked **A08:2021**. It rose to prominence because modern applications are assembled, built, and updated through long automated pipelines—package managers, CI/CD systems, CDNs, container registries, and auto-updaters—each of which is an opportunity for an attacker to inject or alter code and data. The 2017 category *A8:2017 Insecure Deserialization* was folded into this broader theme, because deserializing untrusted data is fundamentally another way of trusting data whose integrity was never checked.

At its core, integrity failures happen when a system:

- **Trusts external code without verification**: pulling plugins, libraries, modules, or scripts from repositories, registries, or CDNs without integrity checks (checksums, signatures, or Subresource Integrity).
- **Runs an insecure build or deployment pipeline**: a CI/CD system whose configuration, credentials, or artifacts can be modified by an unauthorized party, allowing malicious code to be injected into an otherwise-trusted release.
- **Auto-updates without verifying the update**: downloading and applying updates over an untrusted channel, or without checking a digital signature, so an attacker can serve a malicious "update."
- **Deserializes untrusted data**: reconstructing objects, tokens, or state from attacker-controllable bytes without validating structure, type, or authenticity.
- **Trusts signed-looking data that isn't actually verified**: cookies, tokens, or serialized state that are decoded and acted upon without checking a signature or integrity tag.

### Core Concept

```
Integrity means: the artifact you use == the artifact the trusted author produced

TRUSTED SOURCE  --(build / publish / sign)-->  ARTIFACT  --(transport)-->  YOUR SYSTEM

An integrity failure is any point on that path where an attacker can
substitute or modify the artifact AND your system cannot detect it:

  Source        -> compromised dependency / typosquatted package
  Build         -> tampered CI/CD pipeline injects code into the release
  Transport     -> unsigned update served over an attacker-controlled channel
  Consumption   -> untrusted serialized data deserialized into live objects

SECURE  = verify a cryptographic signature / hash before trusting anything
FAILURE = "it came from the expected URL, so it must be genuine"
```

## Why Does This Matter?

Integrity failures are dangerous because they subvert the *chain of trust* that everything else depends on. Authentication, access control, and encryption all assume the code enforcing them is genuine. If an attacker can alter the code or the data that drives a decision, every downstream control can be bypassed at once. A single compromised build or malicious update can reach every customer of a product simultaneously.

### The Business Impact

- **Mass, simultaneous compromise**: A poisoned update or build reaches thousands of downstream organizations in one push—the defining feature of supply-chain attacks.
- **Loss of customer trust**: When your own signed software delivers malware, the damage to reputation is severe and long-lasting.
- **Regulatory and contractual fallout**: Breaches originating in the software supply chain trigger notification duties and have driven government mandates such as SBOM (Software Bill of Materials) requirements.
- **Incident cost and cleanup**: Determining *which* releases were tampered with, and reissuing trusted artifacts, is slow and expensive.
- **Legal liability**: Downstream victims of a compromised release increasingly pursue the vendor whose pipeline failed.

### The Technical Impact

- **Remote code execution**: Insecure deserialization and malicious updates commonly lead directly to code execution on the server or endpoint.
- **Persistent backdoors**: Injected build-time code can install long-lived, hard-to-detect access.
- **Privilege escalation**: Auto-updaters and installers frequently run with high privileges, so a malicious update inherits them.
- **Data tampering**: Trusting client-supplied serialized state (prices, roles, entitlements) lets attackers rewrite server-side decisions.
- **Lateral movement**: A single compromised CI/CD credential often unlocks source, artifacts, and deployment across an entire organization.

## Technical Context

### The Four Faces of Integrity Failure

OWASP groups several distinct problems under this one category because they share a single root cause—**trusting an artifact whose integrity was never verified**. It helps to see them as four faces of the same flaw:

| Face | What is trusted blindly | Typical failure | Verification that fixes it |
|------|-------------------------|-----------------|----------------------------|
| Dependencies | Third-party packages / plugins / CDN scripts | No checksum, lockfile, or SRI; typosquat pulled in | Pinned hashes, lockfiles, SRI, verified registries |
| Build / CI-CD | The pipeline that produces releases | Weak access control lets code be injected pre-release | Least privilege, code review, signed provenance |
| Updates | Auto-downloaded software updates | Update applied without signature verification | Digital signatures verified before install |
| Serialized data | Objects / tokens / state from untrusted input | Deserialized without validation or a signature | Safe formats, schema validation, HMAC/signing |

### Why Signatures and Hashes Are the Answer

Integrity is a solved problem *in theory*: a cryptographic hash detects any modification, and a digital signature additionally proves *who* produced the artifact. The failures in this category are almost never a failure of the math—they are a failure to actually **perform the check**, or to perform it correctly.

```
Hash (integrity only):
  publisher computes  sha256(artifact) = H
  consumer recomputes sha256(downloaded) and compares to a TRUSTED copy of H
  -> detects tampering, but only if H itself is delivered securely

Signature (integrity + authenticity):
  publisher signs   sign(privKey, sha256(artifact)) = S
  consumer verifies verify(pubKey, artifact, S)
  -> detects tampering AND proves it came from the holder of privKey

Common mistake: downloading the hash/signature from the SAME channel as the
artifact, so an attacker who controls the channel simply replaces both.
```

### Where Integrity Checks Belong

```
Developer machine  -> commit signing, verified dependencies
        |
Source repository  -> protected branches, mandatory review
        |
CI/CD pipeline     -> isolated runners, least-privilege secrets, pinned actions
        |
Build artifact     -> reproducible build + signed provenance (e.g. SLSA-style)
        |
Registry / CDN     -> signed packages, immutable tags, SRI for browser assets
        |
Consumer / update  -> verify signature BEFORE executing or installing
```

## Real-World Impact

> The cases below are described as **incident classes**—well-documented patterns that have recurred across the industry. They illustrate mechanisms; treat specific figures as approximate and confirm details against primary sources before citing them.

### Incident Class 1: Build-Pipeline / Supply-Chain Compromise ("SolarWinds-class")

**Mechanism**: Attackers gained access to a software vendor's build environment and injected malicious code *during the build*, so the finished, digitally signed product shipped the backdoor to customers as a legitimate update.

**Why it worked**: Customers verified that the update was signed by the genuine vendor—and it was, because the compromise happened *before* signing, inside the trusted pipeline. Signing at the end of an untrusted build proves authorship, not innocence.

**Lesson**: Integrity must extend to the build system itself (provenance, isolated runners, tamper-evident artifacts), not just the final signature.

### Incident Class 2: Malicious / Compromised Package in a Public Registry

**Mechanism**: An attacker publishes a malicious package (typosquatting a popular name) or takes over a legitimate maintainer's account and pushes a poisoned version. Projects that pull "latest" without pinned, verified versions install it automatically.

**Why it worked**: Dependency resolution trusted the registry name and version range with no verification of who published that specific build or whether it matched a known-good hash.

**Lesson**: Pin versions to verified hashes (lockfiles), prefer signed packages, and monitor for dependency confusion and account-takeover patterns.

### Incident Class 3: Insecure Auto-Update Channel

**Mechanism**: An application checks for updates over an attacker-influenceable channel (plain HTTP, or HTTPS without signature verification) and installs whatever it receives. An on-path attacker serves a malicious binary that the updater applies—often with elevated privileges.

**Why it worked**: The updater treated "downloaded from the update URL" as equivalent to "produced by the vendor." No signature bound the artifact to the vendor's key.

**Lesson**: Every update must carry a signature that the client verifies against a pinned public key before execution.

### Incident Class 4: Insecure Deserialization Leading to RCE

**Mechanism**: An application accepts serialized objects (Java, PHP, Python pickle, .NET, or a signed-but-unverified token) from a client and reconstructs them. A crafted payload triggers "gadget chains" during deserialization that execute attacker-controlled code.

**Why it worked**: Native deserializers instantiate arbitrary types and run their lifecycle methods. Feeding them untrusted bytes hands the attacker a foothold in the object graph.

**Lesson**: Never deserialize untrusted data with native object deserializers. Use data-only formats, validate against a schema, and sign serialized state you must round-trip through a client.

### Incident Class 5: Tampered Client-Side State Trusted Server-Side

**Mechanism**: An application stores state (a price, a role, a discount, a user ID) in a cookie, hidden field, or client-held token, then trusts it on return without verifying an integrity tag. The user edits the value.

**Why it worked**: The server treated a client-held value as authoritative. Without an HMAC or server-side lookup, tampering is undetectable.

**Lesson**: Do not trust client-held state. Keep authoritative state server-side, or bind client state with a verified signature (HMAC) and check it on every request.

## Prevalence and Statistics

### OWASP Top 10 2021 Data

- **A08:2021** — a **new category** in the 2021 edition.
- It **absorbed A8:2017 Insecure Deserialization**, broadening it from a single technique to a family of integrity problems.
- It is one of the categories driven by **community survey input** rather than raw incidence alone, reflecting industry concern about supply-chain risk that data-driven scanning tends to under-count.

> Note: exact incidence and CWE-mapping figures differ between OWASP's published tables and later summaries. Treat any single percentage as illustrative; the durable point is that integrity failures are high-impact and, because they exploit trust rather than a code bug, are frequently missed by scanners.

### Representative CWE Mappings

- **CWE-502**: Deserialization of Untrusted Data
- **CWE-345**: Insufficient Verification of Data Authenticity
- **CWE-353**: Missing Support for Integrity Check
- **CWE-494**: Download of Code Without Integrity Check
- **CWE-565**: Reliance on Cookies without Validation and Integrity Checking
- **CWE-829**: Inclusion of Functionality from Untrusted Control Sphere
- **CWE-830**: Inclusion of Web Functionality from an Untrusted Source
- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes

## Common Misunderstandings

### Myth 1: "It's served over HTTPS, so its integrity is guaranteed"

**Reality**: TLS protects the artifact *in transit* against a network eavesdropper. It says nothing about whether the file on the server is genuine, whether the build that produced it was clean, or whether the CDN was compromised. Integrity of the artifact requires a signature or a hash verified against a trusted source—independent of the transport.

### Myth 2: "The update is signed, so we're safe"

**Reality**: A signature only proves the artifact came from the signing key—*after* whatever produced it. If the build pipeline was compromised (Incident Class 1), the malicious code is signed by the genuine key. Signing is necessary but not sufficient; the build environment must be trustworthy too.

### Myth 3: "Deserialization is just parsing"

**Reality**: Parsing JSON into a plain data structure is not the danger. *Native object deserialization* reconstructs live objects, invokes constructors and magic methods, and can trigger gadget chains that run code. The risk is executing behavior implied by untrusted bytes, not reading data.

### Myth 4: "We only use popular, well-known packages"

**Reality**: Popularity is a target, not a defense. Account takeover, malicious maintainer handoff, and typosquatting all exploit trusted names. Without pinned, verified versions you inherit every change the upstream ships—including a compromised one.

### Myth 5: "Signing a token means the data inside it is trustworthy"

**Reality**: Only if you actually *verify* the signature with the correct key and algorithm on every use. A large class of failures comes from decoding a token and trusting its claims without verification—or accepting an attacker-chosen algorithm (for example "none").

### Myth 6: "This is the same thing as using vulnerable components (A06)"

**Reality**: A06 is about running components with *known* vulnerabilities. A08 is about not being able to prove a component (or build, or update, or data) is *genuine and unmodified* in the first place. A perfectly up-to-date dependency can still be a supply-chain compromise.

## How This Differs From Related Categories

This platform covers integrity from several angles across editions. Keep them distinct:

| Lesson | Altitude / Focus | Use this lesson when… |
|--------|------------------|------------------------|
| **A08:2021 (this lesson)** | Verifying integrity: signing, CI/CD integrity, update verification, deserialization-as-integrity | You are asking "can I prove this code/data is genuine and unmodified?" |
| **A8:2017 Insecure Deserialization** | The deserialization technique in depth (gadget chains, format specifics) | You want the deep mechanics of object deserialization attacks. |
| **2025 Software Supply Chain Failures** | The end-to-end supply chain as a first-class category (SBOM, provenance, ecosystem risk) | You are governing the whole dependency and build ecosystem at scale. |
| **A06:2021 Vulnerable & Outdated Components** | Running components with *known* CVEs | The component is genuine but out of date / known-vulnerable. |

This lesson stays at the **2021 integrity-failures altitude**: the act of *verifying* what you run and consume. Where deserialization or supply-chain topics run deeper, we cross-reference rather than duplicate.

## Self-Assessment

Ask these questions about your own systems:

- [ ] Do you verify a cryptographic signature or pinned hash before applying any auto-update?
- [ ] Are all dependencies pinned to verified versions via a committed lockfile?
- [ ] Do browser-loaded CDN scripts carry Subresource Integrity (SRI) hashes?
- [ ] Is your CI/CD pipeline access-controlled, with mandatory review and least-privilege secrets?
- [ ] Are build artifacts produced in isolated runners with tamper-evident provenance?
- [ ] Do you ever deserialize untrusted input with a native object deserializer (pickle, Java, PHP, BinaryFormatter)?
- [ ] Is every token/cookie carrying server-relevant state integrity-protected and verified on each use?
- [ ] Are hashes/signatures delivered through a *different*, trusted channel than the artifact itself?
- [ ] Can you enumerate exactly which packages, plugins, and CDNs your application trusts?
- [ ] Do you have a plan to reissue trusted artifacts if a release is found to be tampered with?

If you answered "no" or "not sure" to several of these, you likely have exploitable integrity gaps today.

## Key Takeaways

1. ✅ **Verify before you trust** — signatures and hashes, checked against a trusted source, for every artifact.
2. ✅ **Extend integrity to the build** — a signature on a compromised build still ships malware.
3. ✅ **Never auto-update without signature verification** against a pinned key.
4. ✅ **Pin and verify dependencies** — lockfiles, verified registries, and SRI for browser assets.
5. ✅ **Do not deserialize untrusted data** with native deserializers; use safe formats and validation.
6. ✅ **Do not trust client-held state** without a verified integrity tag.

## Next Steps

- **[Attack Vectors](./attack-vectors.md)**: How attackers exploit missing integrity verification
- **[Prevention](./prevention.md)**: Layered defenses—signing, secure CI/CD, SRI, safe deserialization
- **[Examples](./examples.md)**: Vulnerable vs. secure code and configuration
- **[Lab](./lab/unsigned-update-lab/)**: Hands-on practice

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
