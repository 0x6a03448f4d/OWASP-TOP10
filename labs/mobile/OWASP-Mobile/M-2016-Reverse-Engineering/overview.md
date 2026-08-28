# M9:2016 Reverse Engineering - Overview

## Table of Contents
- [What is Reverse Engineering?](#what-is-reverse-engineering)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [What Attackers Extract](#what-attackers-extract)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Reality](#prevalence-and-reality)
- [Common Misunderstandings](#common-misunderstandings)

## What is Reverse Engineering?

**Reverse Engineering (M9:2016)** is the analysis of a shipped mobile application binary to understand how it works from the inside. An attacker who never saw your source code takes the `.apk`, `.aab`, or `.ipa` you published, pulls it apart, and recovers source-equivalent code, strings, resources, algorithms, cryptographic keys, API endpoints, and business logic. The app you distribute *is* the documentation of how it works—reverse engineering is just reading it.

This is fundamentally different from a server-side vulnerability. On the server, code runs on hardware you control and an attacker sees only the inputs and outputs. On mobile, **the client runs on the attacker's device**. They own the CPU, the memory, the debugger, the network stack, and the operating system. Anything the app contains—every byte of code and data needed to run—is, by definition, in the attacker's hands. Reverse engineering is not an exotic exploit; it is the default state of any binary you ship to a device you do not control.

> **The core truth of M9:** Any secret, key, algorithm, or logic that ships inside the client can be recovered. Obfuscation raises the cost and time of that recovery—it never makes it impossible. The only reliable protection for a secret is to not put it in the client at all.

### Core Concept

```
What you ship (the binary)          What the attacker recovers
---------------------------         ----------------------------------
Compiled Dalvik/ART bytecode   ->  Readable Java/Kotlin via jadx/apktool
Compiled Swift/Obj-C (Mach-O)  ->  Class layouts, selectors, pseudo-code
Native .so / dylib (ARM)       ->  Disassembly + decompiled C via Ghidra/IDA
Strings & resources            ->  API keys, URLs, feature flags, messages
Embedded assets / config       ->  Certificates, models, DRM material
"Hidden" endpoints             ->  Full map of the backend attack surface
Anti-tamper / crypto logic     ->  Understood, then bypassed or reimplemented
```

### Reverse Engineering vs. Related Categories

M9 (2016) overlaps with, but is distinct from, its neighbours in the 2016 Mobile Top 10:

- **M9 Reverse Engineering** is about an attacker *understanding* the binary—the analysis step.
- **M8 Code Tampering** is about an attacker *modifying* the binary and re-running it (patched APKs, method hooking). Reverse engineering is almost always the reconnaissance phase that makes tampering possible.
- **M10 Extraneous Functionality** is hidden backdoors, test code, and debug switches left in the shipped app—which reverse engineering is exactly how attackers find.

In the modern 2024 list these ideas are folded into **M7: Insufficient Binary Protections**, but the 2016 framing keeps reverse engineering as its own discipline, which is useful because the analysis workflow is a distinct skill set from the tampering that follows it.

## Why Does This Matter?

### Business Impact

- **Secret and Key Theft**: Hardcoded API keys, third-party credentials, and backend tokens extracted from the binary let an attacker impersonate your app, run up your cloud bills, or abuse paid third-party services on your account.
- **Intellectual Property Loss**: Proprietary algorithms, pricing/ranking logic, matching engines, and machine-learning models can be lifted wholesale and cloned by a competitor.
- **Piracy and DRM Bypass**: License checks, subscription gates, and content-protection (DRM) schemes implemented in the client are located and disabled, enabling free access to paid content and features.
- **Fraud at Scale**: Understanding the request-signing scheme or anti-abuse logic lets attackers script fake accounts, forged in-app purchases, or game-economy exploits far faster than a human could.
- **Attack-Surface Mapping**: Recovered endpoints, parameter names, and undocumented features become the blueprint for attacking the *server*—reverse engineering the client is often step one of a backend breach.

### Technical Impact

- **Credential and Endpoint Disclosure**: Base URLs, staging hosts, and admin/debug endpoints hidden in the app are trivially recovered from strings.
- **Cryptographic Compromise**: Symmetric keys, IVs, and custom "encryption" baked into the client are extracted, making any client-side encryption reversible by anyone.
- **Control Bypass**: Root/jailbreak detection, certificate pinning, and anti-debugging can be located in the decompiled code and then patched out or hooked at runtime.
- **Protocol Reconstruction**: The exact wire format, HMAC/signature scheme, and header requirements are reverse engineered, letting attackers craft valid requests without the app.
- **Amplified Follow-On Attacks**: Everything learned feeds injection, authentication bypass, and business-logic attacks against the backend.

## Technical Context

### Why Mobile Binaries Are So Readable

Mobile app formats were designed for portability and quick loading, not secrecy. That makes them unusually friendly to analysis:

#### Android
- An `.apk` is just a ZIP archive. Unzip it and you have `classes.dex` (bytecode), `resources.arsc`, `AndroidManifest.xml`, native `lib/*/*.so` files, and every asset.
- Dalvik/ART bytecode is **high-level and well-documented**. It retains method boundaries, type information, and—unless stripped—the original class, method, and field names. Tools like `jadx` reconstruct near-original Java/Kotlin.
- Even after R8/ProGuard renaming, the *structure* and string constants survive; only names are scrambled.

#### iOS
- An `.ipa` is also a ZIP. Inside is a Mach-O binary plus `Info.plist`, asset catalogs, and resources.
- Objective-C runtime metadata (class names, method selectors, protocols) is embedded so the runtime can do dynamic dispatch—which means `class-dump`-style tools can enumerate the full class interface.
- Swift is somewhat harder (name mangling, less runtime metadata), but symbol names, string literals, and control flow are still recoverable with Ghidra, Hopper, or IDA.
- App Store binaries are FairPlay-encrypted, but that layer is stripped the moment the app runs on a device the attacker controls (a decrypted dump from memory).

### The Analysis Toolchain

| Purpose | Android | iOS | Native code |
|---------|---------|-----|-------------|
| Unpack / repackage | apktool, unzip | unzip | — |
| Decompile to source | jadx, jadx-gui | Hopper, IDA (pseudo-code) | Ghidra, IDA, Hopper |
| Enumerate classes | jadx, dexdump | class-dump, Hopper | nm, objdump |
| Disassemble | baksmali (smali) | otool, Hopper | Ghidra, objdump |
| Extract strings/assets | strings, unzip, aapt | strings, otool -s | strings |
| Inspect binary metadata | aapt dump, apkanalyzer | otool -L, otool -l | readelf, file |

### Static vs. Dynamic Analysis

Reverse engineering (M9) is primarily **static**: reading the binary at rest. It pairs naturally with dynamic analysis (running the app under a debugger or instrumentation framework like Frida) to confirm findings and defeat runtime checks—but the defining activity of M9 is recovering understanding from the shipped artifact without needing the source.

```
Static analysis                     Dynamic analysis
------------------------            -----------------------------------
Read decompiled code                Attach lldb/gdb, step through code
grep the binary for strings         Hook methods with Frida at runtime
Follow crypto key derivation        Dump the derived key from memory
Map endpoints from constants        Observe live traffic via a proxy
Locate the pinning check            Bypass the check by hooking it
```

## What Attackers Extract

When an analyst opens your binary, these are the high-value targets they look for first:

#### 1. Hardcoded Secrets and API Keys
Static API keys, OAuth client secrets, third-party service tokens (maps, analytics, payment, SMS), and cloud access keys embedded as string constants. These are the single most common and most damaging finding.

#### 2. Encryption Keys and Algorithms
Symmetric keys, IVs, salts, and custom encoding/"encryption" routines. If the client can decrypt it, so can the attacker—the key is right there.

#### 3. Hidden and Undocumented Endpoints
Base URLs, staging/QA hosts, internal admin routes, and feature endpoints not exposed in the UI. These map the backend attack surface.

#### 4. Feature Flags and Business Logic
Client-side gating for premium features, A/B flags, pricing logic, fraud thresholds, and rules an attacker can flip or replicate.

#### 5. Anti-Tamper and Detection Logic
Root/jailbreak detection, emulator detection, debugger checks, and certificate-pinning code—located so they can be bypassed.

#### 6. Proprietary Algorithms and DRM
Request-signing/HMAC schemes, matching/ranking engines, licensing checks, and content-protection logic that represent competitive IP.

```
# A recovered secret is often this blunt:
const val MAPS_API_KEY = "AIzaSyD-EXAMPLE-key-not-real-000000000"
private val hmacSecret = "sup3r-s3cr3t-signing-key"
private const val BASE_URL = "https://internal-admin.api.example.com/v3/"
```

## Real-World Impact

The examples below are described as **incident classes**—patterns repeatedly observed by security researchers—rather than specific attributed breaches, to avoid overstating any single case.

### Incident Class 1: Harvesting Hardcoded Keys from Public Apps

**Pattern**:
- Researchers and automated scanners routinely download large numbers of apps from public stores and grep the extracted binaries for key-shaped strings (cloud access keys, payment tokens, SMS/email provider secrets).
- A meaningful fraction of scanned apps ship at least one live, privileged credential in plain sight.

**Impact**: Attackers use the recovered keys to run up cloud costs, send spam/SMS on the developer's account, read third-party data, or pivot into backend systems the key was over-privileged for.

**Root Cause**: Treating the client binary as a private place to store a secret. It never is.

### Incident Class 2: Client-Side License and Subscription Bypass

**Pattern**:
- An app decides "is this user premium?" or "is this license valid?" locally, in client code.
- An analyst decompiles the app, finds the boolean check, and either patches it (M8) or replicates a valid response, unlocking paid features for free.

**Impact**: Direct revenue loss and large-scale piracy of premium tiers.

**Root Cause**: Entitlement decisions made on the client instead of being enforced and verified server-side.

### Incident Class 3: Reconstructing the Request-Signing Scheme

**Pattern**:
- To stop trivial API abuse, an app signs requests with an HMAC using a key baked into the binary.
- Reverse engineers recover the key and the exact signing algorithm, then script perfectly valid requests without the app—defeating the anti-automation control entirely.

**Impact**: Automated account creation, scraping, fake engagement, and economy abuse at machine speed.

**Root Cause**: Relying on a client-held secret to prove "this request came from our real app." Client attestation, not a shipped key, is the real answer.

### Incident Class 4: Pinning and Root-Detection Bypass as a Stepping Stone

**Pattern**:
- Certificate pinning and root/jailbreak detection are implemented in-app to protect traffic and integrity.
- An analyst locates both checks in the decompiled code and disables them (patch or runtime hook), then observes and tampers with all traffic freely.

**Impact**: Full visibility into the app's protocol, which then enables the follow-on attacks above.

**Root Cause**: Treating client-side checks as a security boundary rather than as friction. They slow an attacker; they do not stop one.

## Prevalence and Reality

Reverse engineering is best understood not as a vulnerability that some apps have and others do not, but as a **capability that always exists** against any shipped binary. The relevant questions are how much it costs an attacker and what they gain when they succeed.

- Every native mobile app is decompilable to some degree. There is no configuration that makes a binary unreadable to a determined analyst.
- The tooling is **mature, free, and widely taught**—jadx, apktool, Ghidra, and Frida are standard and require no exotic skill to run.
- The impact depends almost entirely on **what you put in the client**. An app that ships no secrets and enforces every decision server-side has little to lose to reverse engineering; an app that hardcodes keys and gates features locally has everything to lose.

> Note: rather than cite a single "percentage of apps that leak keys" figure—which varies widely by dataset and year—treat the durable takeaway as this: decompilation is universal and cheap, so design as if every line of your client code and every embedded byte is public.

## Common Misunderstandings

### Myth 1: "Our code is compiled, so it can't be read"

**Reality**: Compilation is not encryption. Dalvik bytecode and Mach-O binaries decompile to readable, source-equivalent code with free tools in minutes.

### Myth 2: "We obfuscated it, so it's secure"

**Reality**: Obfuscation renames symbols and tangles control flow to *slow* an analyst. It is defense-in-depth, not a boundary. String constants, embedded keys, and behaviour still leak, and deobfuscation is a well-trodden path. Obfuscation raises cost; it does not create secrecy.

### Myth 3: "The key is safe because it's split up / XOR'd / Base64'd"

**Reality**: Any transformation the client can reverse at runtime, an attacker can reverse too—by reading the code or by dumping the reconstructed value from memory. Encoding is not protection.

### Myth 4: "It's in a native `.so`, so it's hidden"

**Reality**: Native code raises the bar (you need Ghidra/IDA instead of jadx) but is fully disassemblable and decompilable. It is a speed bump, not a vault.

### Myth 5: "Certificate pinning and root detection protect the app"

**Reality**: Both are valuable friction, but both live in client code that the attacker controls and can locate and bypass. They deter casual attackers and raise cost; they are not a guarantee.

### Myth 6: "iOS App Store encryption protects my binary"

**Reality**: FairPlay encryption is transparent to the running app, so a decrypted copy is dumped from memory on a jailbroken device. It stops casual copying from the store, not analysis.

## How Reverse Engineering Differs from Related Issues

| Aspect | Reverse Engineering (M9) | Code Tampering (M8) | Insecure Data Storage (M2) |
|--------|--------------------------|---------------------|----------------------------|
| **Attacker action** | Read and understand the binary | Modify and re-run the binary | Read data the app persisted |
| **Primary target** | Code, keys, logic, endpoints | Control flow, checks, integrity | Files, databases, keychains |
| **Typical outcome** | Secret theft, IP loss, recon | Bypassed checks, cracked apps | Leaked user/session data |
| **Core defense** | Don't ship secrets/logic client-side | Integrity checks + server enforcement | Encrypt at rest, use platform stores |

## Key Takeaways

1. **The client is fully readable.** Assume every byte you ship—code, strings, assets—is public the moment it leaves your build server.
2. **Compilation and obfuscation are speed bumps, not walls.** They raise attacker cost; they never make recovery impossible.
3. **Secrets belong on the server.** The only reliable protection for a key or sensitive algorithm is to never put it in the client.
4. **Enforce decisions server-side.** Entitlements, license checks, and anti-abuse logic must be validated where the attacker cannot rewrite them.
5. **Reverse engineering is reconnaissance.** It is usually step one for tampering, fraud, and backend attacks—shrinking what the client reveals shrinks all of those.

## How to Identify if You're Exposed

- [ ] Does the app contain any API key, token, or credential that is more than a low-value public identifier?
- [ ] Is any encryption key, IV, or salt hardcoded in the client?
- [ ] Are any premium/entitlement/license decisions made purely in client code?
- [ ] Do any "hidden" or admin/staging endpoints appear as string constants in the binary?
- [ ] Does the security of any feature depend on an attacker *not* reading the code?
- [ ] If you decompiled your own release build right now, what would you be embarrassed to find?
- [ ] Are root/jailbreak, pinning, and debugger checks treated as your *only* defense rather than as friction?
- [ ] Is R8/ProGuard (Android) enabled and are symbols/debug info stripped from release builds?

If you answered "yes" to the client-side-secret questions or "no" to the enforcement questions, reverse engineering is a live risk for you today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: The tools and workflow attackers use to pull a binary apart
- **[Prevention](prevention.md)**: A layered strategy built on the assumption that the client is public
- **[Examples](examples.md)**: Vulnerable vs. secure code in Kotlin/Java and Swift
- **[Mobile Top 10](/learn/mobile)**: Return to the full mobile learning path
- **[Practice](/practice)**: Apply these techniques in guided exercises
