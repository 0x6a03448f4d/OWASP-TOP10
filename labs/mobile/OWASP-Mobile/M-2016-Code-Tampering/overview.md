# M8:2016 Code Tampering - Overview

## Table of Contents
- [What is Code Tampering?](#what-is-code-tampering)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Code Tampering?

**Code Tampering** is when an attacker modifies a mobile application's binary, its resources, or its behaviour *in memory* on a device they control—then runs the altered app to make it do something the developer never intended. Because the app executes on hardware the attacker fully owns (usually rooted or jailbroken), every byte of the code, every asset, and every value in RAM is reachable and rewritable. The trust boundary that a server enjoys simply does not exist on the client.

This is the eighth risk in the **OWASP Mobile Top 10 (2016)**. It captures a family of techniques: **repackaging** (decompile, patch, resign, redistribute a trojanized app), **binary patching** (flip a single check—license, root, or "premium" flag), **resource and asset modification**, and **runtime manipulation** (hooking methods, editing memory, and rewriting return values while the app runs). The unifying idea is that the shipped artifact is not the artifact that runs.

> **Core principle:** any logic, secret, or security decision that lives only on the device can be observed and changed. Code tampering is not a bug in one function—it is the consequence of trusting a runtime you do not control.

### Core Concept

```
The developer ships:            The attacker runs:

  signed APK / IPA               repackaged APK / patched IPA
  isPremium() -> false           isPremium() -> true      (binary patch)
  isRooted()  -> true            isRooted()  -> false     (hook return value)
  license check enforced         license check NOP-ed out (smali edit)
  key stays in memory            key dumped via Frida hook
  server response respected      response rewritten in transit / in RAM

  ---------------------------------------------------------------
  Same icon, same name, DIFFERENT behaviour. The signature is the
  only thing that changed for the user; often they never notice.
```

### The Four Faces of Tampering

- **Repackaging**: unzip the APK/IPA, decompile to smali or Objective-C/Swift metadata, patch the code or resources, rebuild, *re-sign with the attacker's own key*, and distribute the trojanized app through third-party stores, sideloading, or phishing.
- **Binary / bytecode patching**: flip a specific decision—a license gate, a subscription flag, an integrity check—by editing smali, DEX, or the compiled Mach-O/ELF directly (often just turning a conditional branch into a no-op).
- **Resource and asset modification**: swap images, strings, config files, feature-flag JSON, ad identifiers, or pinned certificates bundled in the app.
- **Runtime instrumentation**: attach a dynamic tool (Frida, Xposed, Cydia Substrate, objection) to hook methods, dump arguments and keys, edit memory, and change return values *without ever modifying the file on disk*.

## Why Does This Matter?

### Business Impact

- **Revenue loss**: paywalls, subscriptions, in-app purchases, and license checks are bypassed when the enforcing logic lives on the client. A single cracked build can circulate to thousands of users.
- **Trojanized distribution**: attackers repackage a popular app with malware (banking overlays, spyware, ad-fraud SDKs) and lure users to install the "free" or "modded" version—damaging the brand the malware borrows.
- **Fraud and abuse**: game economies, referral bonuses, loyalty points, and rate limits enforced only in the app are trivially gamed at scale.
- **Intellectual-property theft**: proprietary algorithms, embedded keys, and business logic are extracted and reused.
- **Regulatory and safety exposure**: a tampered health, finance, or automotive app that bypasses safety or compliance checks creates real-world and legal risk.

### Technical Impact

- **Security-control bypass**: root/jailbreak detection, certificate pinning, biometric gates, and anti-fraud checks are disabled by hooking their return values.
- **Secret extraction**: hardcoded API keys, encryption keys, and tokens are dumped by hooking crypto and networking functions at the moment they are used in cleartext.
- **Data exfiltration and injection**: injected code inside a repackaged app can read local storage, intercept input, and beacon out user data.
- **Logic subversion**: any client-side decision—"is this user allowed?", "is this transaction valid?"—can be forced to the attacker's preferred answer.

## Technical Context

### Why the Client Cannot Be Trusted

On a rooted Android device or a jailbroken iPhone, the attacker has privileges equal to or greater than the app itself. They can read the app's memory, attach a debugger, load their own libraries into the process, replace system frameworks, and rewrite the binary on disk. No check the app performs is authoritative, because the code performing the check can itself be patched or hooked away.

```
Trust reality on a device the attacker controls:

  App code            -> readable, patchable, re-signable
  App memory          -> readable and writable at runtime
  System APIs         -> hookable / replaceable
  "Secure" checks     -> only as strong as the code that runs them
  The user's identity -> may be the attacker themselves

  => The ONLY value that is authoritative is one your SERVER
     computes and enforces on infrastructure YOU control.
```

### 1. Repackaging an Android APK

```bash
# Conceptual flow (tools shown for understanding, not instruction)
apktool d target.apk            # decode resources + smali
# ... edit smali so a check returns the attacker's preferred value ...
apktool b target -o patched.apk # rebuild
# re-sign with an attacker-generated key (original signing key is unknown)
apksigner sign --ks attacker.keystore patched.apk
```

**Key fact**: the attacker cannot reproduce the developer's signing key, so the repackaged app carries a *different* signature. That difference is the single most reliable server-side and on-device signal that an app was repackaged.

### 2. Binary Patching a Check

```smali
# A license/premium gate in smali often looks like a branch:
    invoke-static {}, Lcom/app/License;->isPremium()Z
    move-result v0
    if-eqz v0, :locked          # attacker flips/removes this branch
    # ... premium feature ...

# Or in a native (Mach-O/ELF) function, one comparison is
# rewritten so the "denied" path is never taken.
```

### 3. Runtime Hooking (No File Change)

```javascript
// Frida: force a root check to report "not rooted" at runtime
Java.perform(function () {
  var Sec = Java.use('com.app.security.RootCheck');
  Sec.isDeviceRooted.implementation = function () {
    return false;               // return value rewritten in memory
  };
});
```

Frida (Android + iOS), Xposed and its successors (LSPosed), Cydia Substrate, and objection let an attacker intercept any method, read its arguments, replace its body, and dump data—while the on-disk binary and signature stay untouched. This defeats naive integrity checks that only hash the file.

### 4. Memory Patching and Return-Value Modification

Tools in the "GameGuardian" class scan process memory for a value (score, coins, health), then rewrite it directly. More generally, an attacker locates a decision variable or a function's return register and edits it in place, changing behaviour with no persistent modification at all.

### Where Tampering Attacks the App

| Target | Technique | Attacker goal |
|--------|-----------|---------------|
| DEX / smali bytecode | Repackage, patch, re-sign | Flip a flag, inject code, redistribute |
| Native library (.so / Mach-O) | Binary patch a comparison/branch | Bypass a check compiled to native |
| Bundled resources / assets | Edit strings, config, pinned certs | Change behaviour, defeat pinning |
| Running process (methods) | Frida / Xposed / Substrate hook | Rewrite return values, dump secrets |
| Process memory | Memory scan & edit | Change scores, coins, decision flags |
| Signing identity | Re-sign with attacker key | Make the tampered app installable |

## Real-World Impact

To stay honest, the cases below describe well-documented **classes** of incident rather than inventing specific CVEs or figures. Each is a recurring, widely reported pattern in mobile security.

### Class 1: Repackaged "Modded" Apps and Games

**Pattern**: A popular paid app or game is decompiled, its license or in-app-purchase check is patched out, and a "MOD"/"cracked"/"premium unlocked" build is posted to third-party stores and file-sharing sites.

- **How**: Client-side entitlement logic (`isPremium`, purchase verification, license validation) is flipped or removed, then the app is re-signed and redistributed.
- **Impact**: Direct revenue loss for the developer; users of the mod are exposed to whatever else the repackager added.
- **Root cause**: The entitlement decision was made and trusted on the device instead of being validated server-side against a receipt.

### Class 2: Trojanized Banking and Utility Apps

**Pattern**: Malware authors take a legitimate app, inject a malicious SDK or overlay component, re-sign it, and distribute it via phishing or lookalike stores. The app still works, so the victim does not suspect it.

- **How**: Repackaging injects code that harvests credentials (overlay attacks), reads SMS/OTPs, or silently commits ad fraud.
- **Impact**: Account takeover, financial theft, and reputational damage to the impersonated brand.
- **Root cause**: No on-device repackaging/signature check and no server-side attestation that the client is the genuine, unmodified app.

### Class 3: Runtime Bypass of Client-Side Security Checks

**Pattern**: On a rooted/jailbroken device, an attacker uses Frida or Xposed to defeat root detection and certificate pinning, then intercepts and modifies the app's traffic and behaviour.

- **How**: Detection and pinning methods are hooked to return "safe" values; crypto functions are hooked to dump keys and plaintext.
- **Impact**: Full visibility into the app's protocol, extraction of embedded secrets, and the ability to forge or replay requests.
- **Root cause**: Treating client-side detection as an authoritative control rather than a cost-raising signal.

### Class 4: Game-Economy and Anti-Cheat Evasion

**Pattern**: Memory editors and hooking frameworks change in-game currency, stats, or unlock flags that the game trusts locally.

- **Impact**: Broken multiplayer fairness, devalued in-app purchases, and a degraded experience for honest players.
- **Root cause**: Authoritative game state kept on the client instead of the server.

## Prevalence and Detectability

Code tampering is **ubiquitous wherever an app has value worth extracting**—paid apps, games, finance, streaming, and anything with embedded secrets. The tooling (apktool, Frida, Xposed/LSPosed, objection, memory editors) is mature, free, and well documented, so the barrier to entry is low.

Rather than cite invented statistics, the defensible picture is:

- OWASP rates the **exploitability** as difficult in the sense that it requires a device the attacker controls, but **routine** for anyone motivated—the skills and tools are commodity.
- The **detectability** of the vulnerability (a client that trusts itself) is easy: if a valuable decision is made on-device with no server check, it is tamperable.
- The **impact** ranges from lost revenue to full malware distribution and secret theft.

> Note: exact crack rates and malware counts vary by report and year. The durable takeaway is that a determined attacker *will* tamper with an app that runs on their device—so the control that matters is the one enforced where they have no privileges: your server.

## Common Misunderstandings

### Myth 1: "We check for root/jailbreak, so we're protected"

**Reality**: The root check is code, and code on the attacker's device can be hooked to return "not rooted." Detection raises cost and filters casual users; it is not a boundary.

### Myth 2: "The app is signed, so it can't be modified"

**Reality**: An attacker simply re-signs with their own key after modifying it. Signing proves who built *this* copy, not that it is *your* copy—unless something verifies the signing certificate against the value you expect.

### Myth 3: "Obfuscation makes the app tamper-proof"

**Reality**: Obfuscation raises the time and skill needed to understand and patch code. It never makes tampering impossible—it makes it more expensive. That is valuable defense-in-depth, not a guarantee.

### Myth 4: "Our integrity check hashes the binary, so hooking won't work"

**Reality**: Runtime hooking (Frida/Xposed) changes behaviour *in memory* without altering the file, so a file-hash check sees a pristine binary. And the integrity check itself can be hooked.

### Myth 5: "It only matters for games and paid apps"

**Reality**: Any app with secrets, entitlements, anti-fraud logic, or a valuable protocol is a target. Banking, streaming, healthcare, and enterprise apps are repackaged and hooked constantly.

### Myth 6: "If we make the client strong enough, we don't need server checks"

**Reality**: There is no client strong enough on hardware the attacker owns. Client protections buy time and raise cost; only server-side enforcement is authoritative.

## How Code Tampering Relates to Neighbouring Risks

| Aspect | M8 Code Tampering (2016) | Reverse Engineering (M9:2016) | Insufficient Binary Protections (M7:2024) |
|--------|--------------------------|-------------------------------|-------------------------------------------|
| **Focus** | Changing how the app runs | Understanding how the app works | Missing hardening that enables both |
| **Attacker action** | Patch, re-sign, hook, edit memory | Decompile, analyse, read secrets | Exploits weak/absent anti-tamper |
| **Typical outcome** | Bypassed checks, trojan, fraud | Leaked logic, extracted keys | Faster, cheaper tampering |
| **Primary defense** | Server-side enforcement + integrity | Keep secrets off the client | Obfuscation, detection, attestation |

The 2024 revision of the Mobile Top 10 merged tampering and reverse-engineering concerns into **M7: Insufficient Binary Protections**. The underlying lesson is unchanged: the client is untrusted.

## Key Takeaways

1. **The client is fully controlled by the attacker**—binary, resources, and memory are all rewritable on a rooted/jailbroken device.
2. **Every on-device security decision is bypassable** by patching or hooking the code that makes it.
3. **Signing proves the builder, not the origin**—a repackaged app is validly signed by the attacker's key.
4. **Client protections raise cost; the server enforces truth**—keep secrets and enforcement server-side.
5. **Detection, obfuscation, and attestation are defense-in-depth**, valuable together and insufficient alone.

## How to Identify if You're Vulnerable

- [ ] Are any entitlement or "premium" decisions made and trusted purely on the device?
- [ ] Are purchases/licenses validated against a server-side receipt, or only checked locally?
- [ ] Do you verify the app's own signing certificate at runtime and reject unexpected values?
- [ ] Would a hooked root/jailbreak or pinning check silently pass and go unnoticed?
- [ ] Are any API keys, encryption keys, or secrets embedded in the binary or resources?
- [ ] Does your backend attest the client (Play Integrity / DeviceCheck / App Attest) before trusting it?
- [ ] Is authoritative state (balances, scores, permissions) stored and enforced server-side?
- [ ] Do you have telemetry that flags tampered/hooked/emulated clients rather than blocking silently?
- [ ] Is sensitive native logic obfuscated to raise the cost of patching?

If you answered "no" or "not sure" to several of these—especially the server-side ones—a determined user can already bypass your client-side controls.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers repackage, patch, hook, and edit apps
- **[Prevention](prevention.md)**: Server-side enforcement plus layered client hardening
- **[Examples](examples.md)**: Vulnerable vs. secure code in Kotlin/Java and Swift
- **[Mobile Security Track](/learn/mobile)**: Continue the OWASP Mobile Top 10 lessons
- **[Practice](/practice)**: Apply these concepts in hands-on challenges
