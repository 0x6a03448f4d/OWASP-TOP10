# M9:2016 Reverse Engineering - Prevention

## Prevention Strategy Overview

You cannot prevent reverse engineering—any binary on a device you do not control can be analysed. What you *can* do is make reverse engineering **pointless** by ensuring that a fully-read client reveals nothing dangerous, and make it **expensive** with layered friction so casual attackers give up.

The strategy has one primary pillar and several supporting ones:

1. **Design the client to hold no secrets and enforce no security decisions** (the only reliable protection).
2. Raise attacker cost with obfuscation, symbol stripping, and native isolation (defense-in-depth, not a boundary).
3. Add runtime friction—pinning, root/jailbreak and debugger detection, integrity checks—knowing these are speed bumps.
4. Use platform hardening and app attestation to distinguish genuine clients server-side.
5. Verify by decompiling your own release builds and watching for abuse.

**The one rule that matters most:** Assume the client is fully public. If a control&rsquo;s security depends on an attacker not reading the code, it is already broken. Everything below is either &ldquo;move it server-side&rdquo; or &ldquo;raise the cost of the inevitable.&rdquo;

### Core Principles

- **No secrets in the client**: keys, tokens, and sensitive algorithms live on the server, not in the binary.
- **Server-side enforcement**: entitlements, license, and anti-abuse decisions are validated where the attacker cannot rewrite them.
- **Obfuscation is friction, not secrecy**: use it to raise cost, never to protect a secret.
- **Defense in depth**: many layers of friction beat one &ldquo;unbreakable&rdquo; control (there is no such control).

## 1. Keep Secrets and Logic Off the Client (Primary Defense)

The single highest-impact control. If a secret is never in the binary, no amount of reverse engineering recovers it.

```
// BAD: the secret ships in the app and is recovered in minutes
val apiSecret = "sup3r-s3cr3t-signing-key"
val signature = hmacSha256(apiSecret, requestBody)   // done on-device

// GOOD: the client holds no secret; the server owns the sensitive step
//  - The app authenticates the USER (OAuth/OIDC) and sends the request
//  - The server holds the signing/HMAC key and performs privileged actions
//  - Third-party API calls that need a secret are PROXIED through your backend
```

Practical rules:

- **Proxy third-party APIs** that require a secret key through your own backend; the app calls your server, your server calls the vendor with the secret.
- **Never hardcode** cloud access keys, payment secrets, or admin tokens. If a value must be privileged, it must be server-side.
- **Public identifiers are fine** (a publishable client ID, a map key locked to your bundle ID with usage restrictions) — but restrict them at the provider so a stolen copy is useless elsewhere.

## 2. Enforce Every Security Decision Server-Side

A client-side `if (isPremium)` is a suggestion, not a control. Make the server the authority.

```
// BAD: the client decides entitlement, then unlocks locally
if (user.isPremium) { unlockPremiumContent() }   // patchable / hookable

// GOOD: the server decides; the client only renders what it is granted
//  1. Client asks the server for the content/feature
//  2. Server checks the entitlement against its own records
//  3. Server returns the content ONLY if entitled
// The premium bytes never reach an unentitled device.
```

Design so that even a fully cracked client (all checks forced to `true`) still cannot obtain data or actions the server would not grant to that user.

## 3. Obfuscation: Raise the Cost, Honestly

Obfuscation renames symbols, removes debug metadata, and can tangle control flow and strings. It genuinely slows analysis and deters casual attackers—but it protects *nothing* that must be reconstructed at runtime. Use it as a layer, never as the reason a secret is &ldquo;safe.&rdquo;

#### Android: R8 / ProGuard

```
// build.gradle (app) — enable R8 shrinking, obfuscation, and optimisation
android {
    buildTypes {
        release {
            minifyEnabled true            // R8: shrink + obfuscate
            shrinkResources true          // strip unused resources
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}
```

```
# proguard-rules.pro — keep what the runtime needs, obfuscate the rest.
# Do NOT add broad -keep rules that defeat obfuscation for your own code.
-keepattributes SourceFile,LineNumberTable   # keep for de-obfuscating crash reports
-renamesourcefileattribute SourceFile        # but hide real file names
# (Retrace maps stack traces back with the mapping.txt kept OFF-device.)
```

#### iOS

Swift/Obj-C have no first-party obfuscator, but you can strip symbols, avoid descriptive names for sensitive routines, and use commercial hardening if the risk justifies it.

```
# Xcode build settings for release
STRIP_INSTALLED_PRODUCT = YES
DEPLOYMENT_POSTPROCESSING = YES
STRIP_STYLE = all
DEBUG_INFORMATION_FORMAT = dwarf-with-dsym   # keep symbols OFF-device in the dSYM
GCC_GENERATE_DEBUGGING_SYMBOLS = NO          # for release
```

**Be honest with yourself:** if you find yourself relying on obfuscation to protect a key, you have the wrong design. Obfuscation buys time against tampering and IP cloning; it does not make a shipped secret secret.

## 4. Strip Symbols and Debug Information

Debug symbols, verbose logs, and source file names hand the analyst a free map. Remove them from release builds and keep the mapping/symbol files off the device, in your build infrastructure, for crash de-obfuscation.

```
# Android: ensure no debug flags survive to release
#   android:debuggable is false in the release manifest (default)
#   remove verbose logging in release (e.g. via a ProGuard rule stripping Log.d/v)
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
}

# Native: strip the .so
llvm-strip --strip-all libnative.so
```

## 5. String and Asset Encryption (Defense-in-Depth)

Encrypting embedded strings/assets stops a plain `strings` grep and raises the bar—but remember the decryption key and routine also ship, so a determined analyst recovers the plaintext by reading the code or dumping memory. Treat this as friction that thins out low-effort scanning, not as protection for a real secret.

```
// Reasonable use: obscure non-critical constants so bulk grep-scanning misses them.
// UNreasonable use: "encrypting" an API secret and believing it is now safe.
// If losing the value would hurt, it should not be in the client at all.
```

## 6. Certificate Pinning (Done Carefully)

Pinning stops trivial traffic interception and raises the cost of protocol analysis. It lives in client code and can be bypassed by a skilled attacker—but it meaningfully deters the casual ones and protects ordinary users on hostile networks.

```
// Android: pin via network_security_config.xml (declarative, robust)
<network-security-config>
  <domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set>
      <pin digest="SHA-256">BASE64_PRIMARY_SPKI_PIN=</pin>
      <pin digest="SHA-256">BASE64_BACKUP_SPKI_PIN=</pin>   <!-- always pin a backup -->
    </pin-set>
  </domain-config>
</network-security-config>
```

Pin to the SPKI (public key), always ship a backup pin to survive rotation, and pair pinning with server-side controls so a bypass on one device does not equal a breach.

## 7. Runtime Integrity: Root/Jailbreak & Debugger Detection

These add friction and let you react (degrade functionality, alert, refuse high-risk actions) when the environment looks hostile. They are trivially located in the binary and bypassable, so treat their result as a **signal to the server**, not a client-side gate.

```
// Report the signal server-side; let the SERVER decide how to respond.
// A bypassed check on a cracked device then still can't unlock server-enforced actions.
val posture = mapOf(
    "rooted"   to RootDetector.isLikelyRooted(),
    "debugger" to Debug.isDebuggerConnected(),
    "emulator" to EmulatorDetector.isLikelyEmulator()
)
api.reportDevicePosture(posture)   // server weighs risk; never trust blindly
```

## 8. App Attestation (The Server-Side Answer to &ldquo;Is This My App?&rdquo;)

Attestation is the legitimate replacement for a client-held &ldquo;prove you&rsquo;re the real app&rdquo; secret. The platform vouches for the app&rsquo;s integrity to *your server*, cryptographically, without shipping a secret you have to hide.

- **Android**: Play Integrity API — the server requests and verifies an integrity verdict about the app, device, and licensing.
- **iOS**: App Attest / DeviceCheck — a hardware-backed key attests the genuine app instance to your server.

```
// Flow (both platforms):
// 1. Client requests an attestation/integrity token from the OS
// 2. Client sends the token to YOUR server
// 3. Server verifies the token with the platform's verification service
// 4. Server treats requests from unverified clients as untrusted
// No secret ships in the app; the trust decision is made server-side.
```

## 9. Native Isolation for Sensitive Logic

Moving genuinely sensitive routines into a native `.so` raises the analysis cost (machine-code decompilation instead of bytecode). It is a legitimate *friction* layer for IP and anti-tamper logic—but it is still recoverable, so never let it be the sole protection for a true secret.

## 10. Verify: Reverse Engineer Your Own Build

The most reliable check is to do to your release build exactly what an attacker would.

```
# Decompile your own release APK and grep for anything that shouldn't be there
jadx -d out/ app-release.apk
grep -rEin 'password|secret|api[_-]?key|token|BEGIN .*PRIVATE KEY' out/
strings app-release.apk | grep -Ei 'https?://|AIza|sk_live|AKIA'

# Confirm release hygiene
aapt dump badging app-release.apk | grep -i debuggable    # expect: none
# iOS: class-dump / strings your release .app and review the output
```

Automate this in CI as a release gate: fail the build if secret-shaped strings, debug flags, or unexpected endpoints appear. Also add secret-scanning to your repository (so keys never reach the build in the first place) and monitor the backend for the abuse signatures that reverse engineering enables (impossible request signatures, entitlement mismatches, credential reuse).

## Defense Layer Summary

| Layer | What it does | Stops a determined attacker? |
| --- | --- | --- |
| No secrets in client | Removes the prize entirely | **Yes** — nothing to steal |
| Server-side enforcement | Decisions can&rsquo;t be rewritten | **Yes** — the real boundary |
| App attestation | Server verifies genuine client | Strongly — hard to forge |
| Obfuscation / stripping | Slows and deters analysis | No — raises cost only |
| String/asset encryption | Defeats bulk grep scanning | No — key ships too |
| Certificate pinning | Blocks casual MITM | No — bypassable client-side |
| Root/debug detection | Signals a hostile environment | No — friction / signal only |
| Native isolation | Raises decompilation cost | No — still recoverable |

The first two rows are boundaries. Everything below them is friction. A serious app uses friction generously *and* gets the boundaries right—never friction instead of boundaries.

## Key Takeaways

1. **Make reverse engineering pointless before you make it hard** — ship no secrets and enforce decisions server-side.
2. **Obfuscation, stripping, and encryption raise cost, not secrecy** — use them as layers, never as the reason a secret is safe.
3. **Pinning and root/debug detection are friction and signals** — valuable, bypassable, never a sole control.
4. **Attestation replaces the client secret** — let the platform prove app integrity to your server.
5. **Test like the attacker** — decompile your own release build in CI and fail on secrets, debug flags, and stray endpoints.

## Next Steps

- **Code Examples**: Vulnerable vs. secure patterns in Kotlin/Java and Swift
- **Attack Vectors**: Understand exactly what you are defending against
- **Mobile Top 10**: Return to the full mobile learning path
- **Practice**: Apply these techniques in guided exercises
