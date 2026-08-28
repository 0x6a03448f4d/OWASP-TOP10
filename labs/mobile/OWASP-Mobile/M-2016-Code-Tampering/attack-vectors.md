# M8:2016 Code Tampering - Attack Vectors

## Table of Contents
- [Understanding Tampering Attack Vectors](#understanding-tampering-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Static Tampering (On Disk)](#static-tampering-on-disk)
- [Runtime Tampering (In Memory)](#runtime-tampering-in-memory)
- [Chaining Tampering Techniques](#chaining-tampering-techniques)

## Understanding Tampering Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are described so you can understand, detect, and defend against them on apps you own or are authorised to test. Tool names are given for context, not as step-by-step instructions.

Code tampering splits into two families. **Static** tampering modifies the app *on disk*—the attacker rewrites bytecode, native code, or resources and re-signs the result. **Runtime** tampering modifies the app *while it runs*—the attacker attaches an instrumentation framework and changes methods, return values, and memory with no persistent file change. Both require a device the attacker controls, and both target the same weak point: a decision the app trusts itself to make.

The attacker's objective in this category is usually one of:

- Flip a specific check—license, entitlement, root/jailbreak, pinning—to the answer they want.
- Inject code into a repackaged app to steal data, show overlays, or commit ad fraud.
- Observe and rewrite secrets and traffic by hooking crypto, storage, and networking.
- Edit authoritative-looking state (coins, scores, flags) directly in memory.

### Core Attack Flow

```
1. Acquire & Analyse
   ↓
   Pull the APK/IPA, decompile (apktool/jadx/Hopper), locate the target check
2. Choose a Method
   ↓
   Static patch (edit + re-sign)   OR   Runtime hook (Frida/Xposed)
3. Modify
   ↓
   Flip a branch / NOP a check / replace a method / edit memory
4. Run & Verify
   ↓
   Confirm the check now passes; dump any secrets exposed in the process
5. Distribute or Exploit
   ↓
   Redistribute the trojanized app, or use the bypass to forge/replay requests
```

## Static Tampering (On Disk)

### 1. Repackaging / Trojanizing an App

The attacker unpacks a legitimate app, adds or alters code, rebuilds, and re-signs with their own key. The result looks and behaves like the original but carries the attacker's changes.

```bash
# Conceptual repackaging pipeline
apktool d legit.apk -o work         # decode DEX -> smali, extract resources
#   inject a malicious component / patch a check inside work/smali/...
apktool b work -o trojan.apk        # rebuild
zipalign -p 4 trojan.apk out.apk
apksigner sign --ks attacker.jks out.apk   # NEW signature, attacker's key
```

**Payoff**: a working, installable clone with credential-stealing overlays, spyware, or ad-fraud SDKs added—distributed via third-party stores, sideloading, or phishing links to "modded"/"premium" versions.

### 2. Smali / Bytecode Patching a Check

Many client-side gates compile to a single conditional branch. Removing or inverting it defeats the check.

```smali
# BEFORE (enforces the gate):
    invoke-static {}, Lcom/app/License;->isPremium()Z
    move-result v0
    if-eqz v0, :cond_locked      # if not premium, jump to locked path

# AFTER (attacker forces "premium"):
    const/4 v0, 0x1              # hardcode true
    # branch removed / made unreachable -> feature always unlocks
```

**Payoff**: paywalls, trial limits, and feature flags are unlocked without any server interaction—because none was required.

### 3. Native Binary Patching (.so / Mach-O)

When logic is compiled to native code, the attacker patches the machine instructions directly—typically turning a comparison or its branch into a no-op so the "denied" path is never taken.

```asm
# Disassembly sketch of a native license check
  cmp   w0, #0          ; result of validateLicense()
  b.eq  denied          ; attacker rewrites this branch to a NOP
  ; ... allowed path always executes ...
```

**Payoff**: even logic moved into C/C++ "for safety" is bypassed; native code raises cost but is still patchable.

### 4. Resource, Asset, and Config Modification

```
# Values shipped inside the app are all editable:
res/values/strings.xml     -> endpoints, feature copy
assets/config.json         -> {"premium": false} -> {"premium": true}
assets/pinned_cert.pem     -> replaced with attacker's CA to defeat pinning
res/raw/flags.json         -> toggle experiments / unlock content
```

**Payoff**: behaviour changes with no code edit at all; replacing a bundled pinned certificate is a common way to enable traffic interception.

### 5. Re-Signing With an Attacker Key

Every static modification invalidates the original signature, so the attacker signs with a key they generate. The app installs fine because the OS only requires *a* valid signature, not *your* signature—unless something explicitly verifies the signing certificate.

```
# The tell-tale of repackaging:
Original build  -> signed by DEVELOPER cert (known SHA-256 fingerprint)
Tampered build  -> signed by ATTACKER cert (different fingerprint)
# A runtime or server-side check of the cert fingerprint catches this.
```

## Runtime Tampering (In Memory)

### 6. Method Hooking With Frida

Frida injects a JavaScript engine into the running process and lets the attacker replace any method's implementation on the fly—no file change, so file-hash integrity checks see nothing wrong.

```javascript
// Defeat root detection AND certificate pinning at runtime
Java.perform(function () {
  // 1) Root check -> always "clean"
  var Root = Java.use('com.app.security.RootCheck');
  Root.isDeviceRooted.implementation = function () { return false; };

  // 2) Dump a key the moment it is used
  var Crypto = Java.use('com.app.crypto.KeyManager');
  Crypto.getAesKey.implementation = function () {
    var k = this.getAesKey();
    console.log('[+] AES key: ' + k);   // exfiltrate secret
    return k;
  };
});
```

**Payoff**: detection and pinning silently pass; secrets and plaintext are dumped as the app uses them.

### 7. Xposed / LSPosed and Cydia Substrate Modules

Framework-level hooking (Xposed and its successor LSPosed on Android, Cydia Substrate/`MobileSubstrate` on iOS) lets an attacker ship a reusable module that hooks a target app every time it launches—persisting the bypass without touching the APK/IPA.

```java
// Xposed-style hook: force a "subscribed" verdict
XposedHelpers.findAndHookMethod(
  "com.app.billing.Subscription", classLoader,
  "isActive",
  new XC_MethodReplacement() {
    protected Object replaceHookedMethod(MethodHookParam p) {
      return true;          // always subscribed
    }
  });
```

### 8. objection (Frida-Powered Automation)

objection wraps Frida with ready-made commands, lowering the skill bar: one command disables SSL pinning, another attempts to bypass root/jailbreak detection, others dump the keychain or heap.

```
objection -g com.app explore
# within the session:
android sslpinning disable
android root disable
ios jailbreak disable
ios keychain dump
```

**Payoff**: common client-side defenses fall to a handful of prebuilt commands—no custom scripting required.

### 9. Memory Scanning and Editing

Tools in the GameGuardian class let an attacker search process memory for a known value and overwrite it. Any locally trusted number—coins, health, a remaining-trial counter, a boolean decision—can be rewritten in place.

```
# Conceptual: find and rewrite an in-memory value
search value == 100      (current coins)
spend some, search again == 95   (narrow candidates)
edit remaining match     -> 999999
```

**Payoff**: instant manipulation of any authoritative-looking value the app keeps client-side.

### 10. Dynamic Return-Value and Argument Modification

Beyond replacing whole methods, an attacker intercepts a call, inspects and edits its arguments on the way in, and rewrites its return value on the way out—e.g. forcing a server-response parser to see `"entitled": true` even when the real response said otherwise.

```javascript
// Rewrite a parsed response flag after the network call returns
var Resp = Java.use('com.app.net.EntitlementResponse');
Resp.isEntitled.implementation = function () { return true; };
```

**Payoff**: even when the server sends the correct answer, a purely client-side *reaction* to that answer can be overridden. (This is exactly why the server must *enforce*, not merely *inform*.)

### 11. Hooking Crypto and Auth to Exfiltrate Keys

Encryption and signing must operate on plaintext keys and data at some point. By hooking the crypto provider, an attacker captures keys, IVs, and plaintext at exactly that moment—regardless of how the key was stored.

```javascript
// Hook the standard cipher to capture everything it processes
var Cipher = Java.use('javax.crypto.Cipher');
Cipher.doFinal.overload('[B').implementation = function (data) {
  console.log('[cipher] in : ' + bytesToHex(data));
  var out = this.doFinal(data);
  console.log('[cipher] out: ' + bytesToHex(out));
  return out;
};
```

**Payoff**: embedded or derived keys are recovered even from hardware-backed stores, because the plaintext is observed *in use*, not at rest.

## Chaining Tampering Techniques

Real attacks combine steps. A common analysis-to-crack chain:

```
Root the device                 -> full control of the process
        +
Frida: disable root detection   -> app believes it is on a clean device
        +
objection: disable SSL pinning  -> traffic now visible in an intercepting proxy
        +
Hook crypto / entitlement       -> dump keys, force "premium" = true
        =  full protocol visibility + bypassed monetisation, no server needed
```

A common distribution chain:

```
Decompile popular app           -> locate license check
        -> smali-patch the check out
        -> inject ad-fraud / overlay SDK
        -> re-sign with attacker key
        -> publish as "MOD / premium unlocked"
        =  trojanized app harvesting users at scale
```

## Key Takeaways

1. **Static and runtime tampering attack the same weakness**—a decision the app trusts itself to make.
2. **Re-signing defeats "it's signed"**—unless the signing certificate is explicitly verified.
3. **Hooking beats file-hash integrity checks**—memory changes leave the on-disk binary pristine.
4. **Commodity tools lower the bar**—Frida, LSPosed, and objection turn expert techniques into one-liners.
5. **Informing the client is not enforcing**—a correct server response can be overridden in memory, so the server must act on the decision itself.

## Next Steps

- **[Prevention Guide](prevention.md)**: Server-side enforcement and layered client hardening
- **[Code Examples](examples.md)**: Vulnerable vs. secure integrity and detection code
- **[Overview](overview.md)**: What code tampering is and why the client is untrusted
- **[Mobile Security Track](/learn/mobile)**: Continue the OWASP Mobile Top 10 lessons
- **[Practice](/practice)**: Apply these concepts in hands-on challenges
