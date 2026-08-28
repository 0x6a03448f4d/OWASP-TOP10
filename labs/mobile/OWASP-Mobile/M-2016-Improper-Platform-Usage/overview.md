# M1:2016 Improper Platform Usage - Overview

## Table of Contents
- [What is Improper Platform Usage?](#what-is-improper-platform-usage)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Improper Platform Usage?

**Improper Platform Usage** is the top risk in the OWASP Mobile Top 10 (2016). It covers every case where an app *misuses a mobile operating-system feature* or *fails to use a platform-provided security control correctly*. The mobile OS ships a rich set of safety mechanisms—permission models, the Keychain and Keystore, secure IPC, App Transport Security, biometric APIs, WebView sandboxing—and this category is what happens when the app fights, ignores, or misapplies them instead of leaning on them.

The distinguishing idea is **direction**. The platform already offers the secure way to do a thing; the app takes a different, weaker path. It stores a secret in `SharedPreferences` instead of the Keystore. It exports an Activity that should have stayed private. It disables App Transport Security to make a cleartext call work. It gates a screen with a biometric callback that returns a boolean instead of unlocking a real cryptographic key. Each of these is not an exotic bug—it is the platform's guardrail being bypassed by the developer's own configuration or code.

### Core Concept

```
Correct Platform Usage:
  Permissions  -> request the minimum, at the moment of use, degrade gracefully
  IPC          -> components not exported unless required, protected by permissions
  Secrets      -> Keychain / Keystore, hardware-backed, correct accessibility flag
  Biometrics   -> unlock a cryptographic key; result bound to a real operation
  Transport    -> App Transport Security on; cleartext disallowed by default
  WebView      -> JS disabled unless needed; no broad native bridge; file access off
  Backup       -> sensitive data excluded from cloud/local backup

Improper Platform Usage:
  Permissions  -> over-request; custom permission with signature -> normal
  IPC          -> exported Activity/Service/Receiver reachable by any app
  Secrets      -> SharedPreferences / UserDefaults / plist in plaintext
  Biometrics   -> callback returns true/false, no key, trivially bypassed
  Transport    -> ATS disabled globally; usesCleartextTraffic = true
  WebView      -> addJavascriptInterface + file access + loadUrl(untrusted)
  Backup       -> allowBackup = true, tokens land in adb backup / iCloud
```

### Why It's Critical for Mobile

Mobile concentrates several conditions that make platform misuse especially damaging:

- The device is **physically in the user's (or attacker's) hands**. Lost, stolen, and second-hand phones mean local storage and backups are a real, routine threat model—not a theoretical one.
- Many devices are **rooted or jailbroken**, or run malware sharing the same device. On-device attackers can read world-readable files, call exported components, and inspect memory.
- The **platform is the security boundary**. Unlike a server you fully control, a mobile app runs inside an OS sandbox whose controls only protect you if you opt into them correctly.
- Apps are **shipped as binaries to millions of devices**. A misconfiguration in the manifest or `Info.plist` is copied to every install and cannot be quietly hot-fixed at the edge.

## Why Does This Matter?

### Business Impact

- **Credential and Token Theft**: Secrets in `SharedPreferences`/`UserDefaults`, in plist files, or in cloud backups are recoverable from a lost, stolen, or backed-up device—handing over sessions and API keys.
- **Account Takeover via IPC**: An exported component or unprotected Intent lets a malicious app on the same device invoke privileged actions, bypass a login screen, or redirect an authenticated flow.
- **Data Interception**: Disabling App Transport Security or allowing cleartext traffic exposes traffic to interception on hostile Wi-Fi.
- **Regulatory and Contractual Fallout**: Health, financial, and personal data leaked through platform misuse triggers GDPR, HIPAA, and PCI-DSS obligations, fines, and app-store rejection.
- **Reputation and Store Standing**: Apple and Google actively reject or remove apps that misuse permissions, weaken ATS without justification, or leak data—so the flaw is also a distribution risk.

### Technical Impact

- **Local Data Disclosure**: Plaintext secrets and world-readable files are read directly on rooted/jailbroken devices or extracted from backups.
- **Privilege Escalation across Apps**: Exported Services/Receivers and weak custom-permission `protectionLevel` let untrusted apps reach privileged code.
- **Intent Redirection / Confused Deputy**: A component that forwards an attacker-supplied Intent performs actions on the attacker's behalf with the app's privileges.
- **Authentication Bypass**: Biometric gates with no cryptographic binding are defeated by hooking the callback; a lock screen that guards nothing real falls to a one-line Frida hook.
- **Remote Code / Data Bridge via WebView**: A JavaScript bridge combined with untrusted content or file access can expose native methods and local files to a web attacker.

## Technical Context

### Common Improper-Platform-Usage Scenarios

#### 1. Exported Components and Unprotected Intents (Android)

```xml
<!-- Any app on the device can launch this Activity directly -->
<activity android:name=".TransferActivity" android:exported="true" />

<!-- Receiver with no permission: any app can broadcast to it -->
<receiver android:name=".AdminReceiver" android:exported="true">
    <intent-filter><action android:name="com.app.DO_ADMIN"/></intent-filter>
</receiver>
```

**Risk**: A component that has an `intent-filter` is exported by default (pre-Android 12) and reachable by any installed app, allowing screen bypass, privileged actions, or an Intent-redirection confused-deputy attack.

#### 2. Insecure Local Storage of Secrets

```
// Android: token in plaintext SharedPreferences
prefs.edit().putString("auth_token", token).apply()

// iOS: token in UserDefaults (a plist, unencrypted at rest)
UserDefaults.standard.set(token, forKey: "auth_token")
```

**Risk**: Neither store is meant for secrets. Both are recoverable from backups and from the file system on a compromised device. The platform provides the Keystore/Keychain precisely so this never has to happen.

#### 3. Weak Keychain / Keystore Usage (iOS & Android)

```
// iOS: item survives even without a passcode and is included in backups
kSecAttrAccessible: kSecAttrAccessibleAlways   // wrong accessibility flag

// Android: software-backed key, no user-authentication requirement
KeyGenParameterSpec.Builder(...)               // isStrongBoxBacked not requested
    .setUserAuthenticationRequired(false)      // key usable with no unlock
```

**Risk**: The secret is stored in the right place but with the wrong policy—overly permissive accessibility, no hardware backing, or no requirement that the device be unlocked—so it survives conditions it should not.

#### 4. Biometric Authentication Without Cryptographic Binding

```kotlin
// The gate is only a boolean callback — nothing is unlocked
BiometricPrompt(activity, executor, object : AuthenticationCallback() {
    override fun onAuthenticationSucceeded(result: AuthenticationResult) {
        showSecrets()   // no CryptoObject; a hook forcing 'succeeded' wins
    }
})
```

**Risk**: If the biometric result does not unlock a Keystore/Keychain key that is actually required to decrypt data or sign a request, the check protects nothing and is bypassed by instrumentation.

#### 5. Ignoring App Transport Security / Allowing Cleartext

```xml
<!-- iOS Info.plist: ATS turned off globally -->
<key>NSAppTransportSecurity</key>
<dict><key>NSAllowsArbitraryLoads</key><true/></dict>

<!-- Android manifest: cleartext HTTP permitted app-wide -->
<application android:usesCleartextTraffic="true" />
```

**Risk**: The platform defaults to HTTPS-only for a reason. Turning the guardrail off globally to fix one endpoint exposes all traffic to interception and tampering.

#### 6. WebView Misconfiguration

```kotlin
webView.settings.javaScriptEnabled = true
webView.settings.allowFileAccess = true            // file:// reachable from JS
webView.addJavascriptInterface(NativeBridge(), "android")  // native methods to JS
webView.loadUrl(untrustedUrl)                      // attacker content + bridge
```

**Risk**: A native JavaScript bridge exposed to untrusted content lets a web attacker call app methods; enabling file access lets loaded pages read local files.

### Layers Where Platform Misuse Hides

| Surface | Typical Improper Usage | Consequence |
|---------|------------------------|-------------|
| Permissions | Over-requesting; custom permission with wrong `protectionLevel` | Excess access, privilege escalation |
| IPC / components | Exported Activity/Service/Receiver; unprotected Intent | Screen bypass, Intent redirection |
| Secure storage | SharedPreferences/UserDefaults/plist for secrets; wrong accessibility | Credential and token theft |
| Biometrics | Callback-only gate, no `CryptoObject` | Authentication bypass |
| Transport | ATS disabled; `usesCleartextTraffic` | Interception, tampering |
| WebView | JS bridge + file access + untrusted content | Native bridge abuse, file read |
| Backup / clipboard | `allowBackup=true`; secrets on the pasteboard | Data exfiltration off-device |

## Real-World Impact

### Case Study 1: Exported-Component Screen Bypass (incident class)

**Improper Usage**:
- Apps declared internal Activities as exported (often implicitly, by attaching an `intent-filter` without setting `android:exported="false"`), leaving post-login or internal screens directly launchable.
- Deep-link and internal-navigation Activities forwarded a caller-supplied Intent without validation.

**Impact**:
- A second, malicious app on the same device launched the internal screen directly, skipping the authentication step, or triggered a privileged action.
- Intent-redirection ("confused deputy") variants let the malicious app reach otherwise-protected internal components through the vulnerable app's privileges.

**Root Cause**: Relying on default export behaviour and forwarding untrusted Intents—using IPC without the platform's protection mechanisms. Android 12+ now forces an explicit `exported` value specifically because of this pattern.

### Case Study 2: Secrets in Insecure Local Storage and Backups (incident class)

**Improper Usage**:
- Session tokens, API keys, and PII were written to `SharedPreferences`, `UserDefaults`, or app plist/SQLite files in plaintext.
- Android manifests left `allowBackup="true"` (the historical default), so those files were extractable via `adb backup`; iOS items used Keychain accessibility that kept them in backups.

**Impact**:
- Researchers and analysts repeatedly recovered credentials from device images, from unencrypted backups, and from the file system on rooted/jailbroken devices—no network attack required.

**Root Cause**: Using general-purpose preference stores for secrets and leaving backup flags at permissive defaults, instead of the Keystore/Keychain with a backup-excluding policy.

### Case Study 3: Biometric Gates With No Cryptographic Binding (incident class)

**Improper Usage**:
- Apps gated sensitive screens on the *success callback* of `BiometricPrompt` / `LocalAuthentication` without tying that success to unlocking a Keystore/Keychain key.

**Impact**:
- On rooted/jailbroken devices, instrumentation frameworks hooked the callback (or the `evaluatePolicy` result) to force "authenticated," exposing the protected data with no biometric ever presented.

**Root Cause**: Treating biometrics as a UI decision rather than as a key-unlock operation—ignoring the platform's `CryptoObject`/keychain-bound design that makes the result tamper-resistant.

## Prevalence and Statistics

Improper Platform Usage sits at **M1** in the OWASP Mobile Top 10 (2016) because it is both the broadest and one of the most frequently observed mobile categories. It is an umbrella that touches permissions, IPC, storage, transport, biometrics, and WebViews—so some form of it appears in the majority of mobile assessments.

Rather than cite precise breach counts (which vary by source), the defensible picture is:

- Platform misuse is characterised as **highly prevalent and easily detectable**—static analysis of the manifest/`Info.plist` and a quick storage inspection surface it routinely.
- The most commonly observed sub-issues are **insecure local storage of secrets, exported/unprotected components, disabled transport security, and biometric checks with no cryptographic binding**.
- The impact is rated **moderate to severe**: from local data disclosure up to authentication bypass and cross-app privilege escalation.

> Note: exact percentages differ between reports and years. Treat any single figure as illustrative; the durable takeaway is that platform misuse is common, cheap to find with static tooling, and often trivially exploitable on a compromised device.

## Common Misunderstandings

### Myth 1: "The sandbox already protects my files"

**Reality**: The app sandbox protects data from *other apps on a healthy device*. It does nothing against a rooted/jailbroken device, a physical extraction, or a backup. Secrets still belong in the Keystore/Keychain, not in plain files.

### Myth 2: "It's only exported so my other app can call it"

**Reality**: "Exported" means *every* app can call it, not just yours. Cross-app calls between your own apps should be gated by a `signature`-level custom permission, not left open.

### Myth 3: "The biometric prompt succeeded, so the user is authenticated"

**Reality**: A success callback is a UI event, not a security boundary. Unless success unlocks a cryptographic key that is actually required to proceed, the check is bypassed by hooking the callback.

### Myth 4: "We had to disable ATS to talk to our backend"

**Reality**: Global `NSAllowsArbitraryLoads` weakens every connection. If a single legacy endpoint truly needs an exception, scope it with a per-domain ATS exception—never turn the platform default off app-wide.

### Myth 5: "UserDefaults / SharedPreferences is basically local, so it's fine"

**Reality**: Both are unencrypted key-value stores backed by files that land in backups and are readable on compromised devices. They are for preferences, not secrets.

### Myth 6: "A JavaScript bridge is convenient and our WebView only loads our site"

**Reality**: Redirects, mixed content, ad/analytics frames, and open-redirect bugs routinely pull untrusted content into a WebView. Any exposed native bridge then becomes reachable by that content.

## How Improper Platform Usage Differs from Related Mobile Risks

| Aspect | M1 Improper Platform Usage | M2 Insecure Data Storage | M3 Insecure Communication |
|--------|---------------------------|--------------------------|---------------------------|
| **Root cause** | Misusing / ignoring a platform control | Sensitive data persisted unsafely | Data in transit unprotected |
| **Where it lives** | Manifest/plist, IPC, Keystore/Keychain, WebView, biometric code | Files, DBs, caches, logs | TLS setup, pinning, cleartext |
| **Typical fix** | Use the platform control correctly | Encrypt / don't store | Enforce TLS, validate certs |
| **Overlap** | Umbrella—often the cause behind M2/M3 | Storage-specific slice | Transport-specific slice |

M1 is deliberately broad: an insecure-storage or insecure-communication finding is frequently *also* an improper-platform-usage finding, because the underlying mistake was declining the platform's correct mechanism.

## Key Takeaways

1. **Lean on the platform, don't fight it**—the OS ships permissions, secure storage, secure IPC, ATS, and biometric binding so you don't have to reinvent them.
2. **The device is a hostile environment**—design for lost, stolen, rooted, and backed-up phones, not just the happy path.
3. **Secrets go in the Keystore/Keychain** with correct accessibility and hardware backing—never in preferences, plists, or backups.
4. **Don't export what doesn't need exporting**, and protect required cross-app IPC with signature-level permissions.
5. **Bind biometrics to a key**—a boolean callback is not authentication.

## How to Identify if You're Vulnerable

- [ ] Does every component set `android:exported` explicitly, and are only the components that must be public exported?
- [ ] Are cross-app-only components protected by a `signature`-level custom permission?
- [ ] Are all secrets in the Keystore/Keychain (not SharedPreferences, UserDefaults, or plist)?
- [ ] Is the Keychain accessibility flag `WhenUnlockedThisDeviceOnly` (or stricter), and are Android keys hardware-backed and user-auth-bound?
- [ ] Does biometric success unlock a required `CryptoObject`/keychain key rather than just returning true?
- [ ] Is App Transport Security left on (no global `NSAllowsArbitraryLoads`) and cleartext traffic disallowed on Android?
- [ ] Are WebViews free of unnecessary JavaScript bridges, with file access disabled and only trusted content loaded?
- [ ] Is `android:allowBackup` set to `false` (or backups configured to exclude secrets), and are secrets kept off the clipboard?
- [ ] Do you request the minimum permissions, at point of use, and degrade gracefully when denied?

If you answered "no" or "not sure" to several of these, you likely have exploitable platform misuse today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers find and exploit platform misuse
- **[Prevention](prevention.md)**: Use the platform's controls the way they were designed
- **[Examples](examples.md)**: Vulnerable vs. secure code in Kotlin/Java and Swift
- **[Mobile Learning Path](/learn/mobile)**: Continue the OWASP Mobile Top 10
- **[Practice](/practice)**: Test your understanding with hands-on challenges
