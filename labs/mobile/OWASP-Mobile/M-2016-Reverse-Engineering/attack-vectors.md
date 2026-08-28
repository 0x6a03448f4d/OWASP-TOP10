# M9:2016 Reverse Engineering - Attack Vectors

## Table of Contents

- [Understanding the Reverse Engineering Workflow](#understanding)
- [Core Attack Flow](#core-attack-flow)
- [Android Analysis Workflow](#android-workflow)
- [iOS Analysis Workflow](#ios-workflow)
- [Native Library Analysis](#native-libs)
- [Extraction Targets in Detail](#extraction-targets)
- [Dynamic Analysis and Bypasses](#dynamic)
- [Chaining into Full Compromise](#chaining)

## Understanding the Reverse Engineering Workflow

**⚠️ EDUCATIONAL PURPOSE ONLY** — the tools and commands below are shown so you can analyse and harden apps you own or are explicitly authorised to test. Decompiling and modifying software you do not own may violate licences and law.

Reverse engineering is not a single exploit; it is a **methodical analysis pipeline**. The attacker takes your published artifact, unpacks it, converts machine-oriented code back into human-readable form, searches it for anything valuable, and then confirms findings by running the app under instrumentation. Because the binary contains everything needed to run the app, this pipeline is guaranteed to succeed to *some* depth—the only variable is how much time it takes.

The analyst&rsquo;s goals in this category are usually:

- Recover source-equivalent code to understand what the app does.
- Extract secrets, keys, endpoints, and business logic embedded in the client.
- Locate protective checks (pinning, root detection, license gates) in order to bypass them.
- Map the backend attack surface for follow-on attacks.

### Core Attack Flow

```
1. Obtain
   &darr;
   Pull the .apk / .aab / .ipa from the device or store
2. Unpack
   &darr;
   Unzip; separate bytecode, native libs, resources, assets
3. Decompile / Disassemble
   &darr;
   Bytecode -> Java/Kotlin (jadx); Mach-O/.so -> pseudo-code (Ghidra/IDA)
4. Search
   &darr;
   Grep strings and code for keys, URLs, flags, crypto, checks
5. Confirm (dynamic)
   &darr;
   Attach a debugger / Frida; dump runtime values; bypass checks
6. Weaponise
   &darr;
   Reuse secrets, replicate protocols, patch the app, attack the backend
```

## Android Analysis Workflow

### 1. Obtain and Unpack the APK

The APK can be pulled straight off a device with `adb`, then treated as the ZIP archive it is.

```
# Find the installed package and its APK path
adb shell pm list packages | grep example
adb shell pm path com.example.app
# package:/data/app/com.example.app-1/base.apk

# Pull it to the workstation
adb pull /data/app/com.example.app-1/base.apk .

# It's just a ZIP: list the contents
unzip -l base.apk
# classes.dex, classes2.dex, resources.arsc, AndroidManifest.xml,
# lib/arm64-v8a/libnative.so, assets/, res/ ...
```

### 2. Decompile to Java/Kotlin with jadx

`jadx` converts Dalvik bytecode back into readable Java (and reconstructs much Kotlin). This is usually the very first and most productive step.

```
# Decompile everything to a source tree
jadx -d out/ base.apk

# Or open interactively to browse classes and search
jadx-gui base.apk

# The output is near-original source:
#   out/sources/com/example/app/Config.java
#   out/resources/AndroidManifest.xml
```

### 3. Rebuild-Capable Disassembly with apktool

`apktool` decodes resources and produces `smali` (a human-readable assembly of Dalvik bytecode). Unlike jadx, its output can be *edited and rebuilt*—the bridge from M9 (understanding) to M8 (tampering).

```
# Decode resources + smali
apktool d base.apk -o base_decoded/

# Human-readable manifest, strings, and smali:
#   base_decoded/AndroidManifest.xml
#   base_decoded/res/values/strings.xml
#   base_decoded/smali/com/example/app/Config.smali

# After editing, rebuild and re-sign (this is the tampering step)
apktool b base_decoded/ -o patched.apk
```

### 4. Extract Strings, Secrets, and Endpoints

A large share of findings come from simply searching for constant strings—no decompiler required.

```
# Raw strings across the whole binary
strings base.apk | grep -Ei 'api|key|secret|token|https?://'

# Search the decompiled source tree for high-value patterns
grep -rEn 'AIza[0-9A-Za-z_-]{20,}'     out/     # Google API key shape
grep -rEn '(api|secret|hmac|private)[_-]?key' out/
grep -rEn 'https?://[a-zA-Z0-9.-]+'    out/     # endpoints, hidden hosts

# Inspect resources and the manifest for keys stored as XML values
aapt dump strings base.apk
aapt dump xmltree base.apk AndroidManifest.xml
```

### 5. Read the Manifest for the Attack Surface

The manifest is a map of exported components, permissions, deep links, and debug flags.

```
# Look for:
#  android:exported="true"          -> components reachable by other apps
#  android:debuggable="true"        -> app can be debugged as shipped
#  <data android:scheme="...">      -> deep-link entry points
#  usesCleartextTraffic="true"      -> plaintext HTTP allowed
#  <meta-data> ... api_key ...      -> keys stored in the manifest
```

## iOS Analysis Workflow

### 1. Obtain and Decrypt the Binary

App Store binaries are FairPlay-encrypted, but the encryption is transparent to the running process. On a device the analyst controls, a decrypted image is dumped from memory; a self-distributed or enterprise `.ipa` may already be unencrypted.

```
# An .ipa is a ZIP; the Mach-O binary lives in Payload/App.app/
unzip -l App.ipa
# Payload/MyApp.app/MyApp        <- the Mach-O executable
# Payload/MyApp.app/Info.plist
# Payload/MyApp.app/Assets.car

# Check whether the binary is still encrypted (cryptid 1 = encrypted)
otool -l Payload/MyApp.app/MyApp | grep -A4 LC_ENCRYPTION_INFO
```

### 2. Enumerate Classes and Selectors

Objective-C keeps class/method metadata in the binary for the runtime, so the full interface can be listed. Tools like `class-dump`, and the class browsers inside Hopper and IDA, reconstruct header-style declarations.

```
# List Objective-C classes, methods, and properties
class-dump Payload/MyApp.app/MyApp > headers.txt

# Inspect shared libraries and load commands
otool -L Payload/MyApp.app/MyApp        # linked frameworks/dylibs
otool -l Payload/MyApp.app/MyApp        # load commands, segments
```

### 3. Decompile with Hopper, IDA, or Ghidra

For the actual logic—especially Swift, whose metadata is thinner—a decompiler produces pseudo-code from the Mach-O.

```
# Ghidra: import the Mach-O, auto-analyze, read the decompiler pane
# Hopper: open the binary -> pseudo-code view per function
# IDA:    load, run auto-analysis, use Hex-Rays for C-like output

# Swift name demangling makes symbols readable again
swift demangle '_$s5MyApp10LicenseKeyV8validateSbyF'
# -> MyApp.LicenseKey.validate() -> Swift.Bool
```

### 4. Extract Strings and Plists

```
# Strings from the executable and from Objective-C string sections
strings Payload/MyApp.app/MyApp | grep -Ei 'key|secret|token|https?://'
otool -s __TEXT __cstring Payload/MyApp.app/MyApp

# Property lists and bundled config often hold URLs and identifiers
plutil -p Payload/MyApp.app/Info.plist
```

## Native Library Analysis

Moving logic into a native `.so` (Android JNI) or C/C++ within the iOS binary raises the bar—you need a machine-code decompiler rather than a bytecode one—but it does not hide anything.

```
# Identify and inspect the native library
file lib/arm64-v8a/libnative.so
readelf -d lib/arm64-v8a/libnative.so      # dynamic symbols, dependencies
nm -D    lib/arm64-v8a/libnative.so        # exported symbols (JNI entry points)
strings  lib/arm64-v8a/libnative.so | grep -Ei 'key|http'

# Decompile the machine code
#   Ghidra: import .so -> auto-analyze -> decompiler pane shows C
#   IDA + Hex-Rays: pseudo-code for each function
#   objdump -d for raw ARM disassembly
objdump -d lib/arm64-v8a/libnative.so | less
```

JNI function names follow a predictable `Java_package_Class_method` pattern, so an analyst can jump straight from the Java call site to the native implementation. A key XOR-decoded in C is just as recoverable as one in Kotlin—it takes longer, not forever.

## Extraction Targets in Detail

### 1. Hardcoded API Keys and Secrets

```
# Common shapes an analyst greps for:
grep -rEn 'AIza[0-9A-Za-z_-]{20,}'  out/    # Google API key
grep -rEn 'sk_live_[0-9A-Za-z]{20,}' out/   # secret-key style tokens
grep -rEn 'AKIA[0-9A-Z]{16}'        out/    # cloud access key id shape
grep -rEn 'eyJ[A-Za-z0-9_-]+\.'     out/    # embedded JWTs
```

**Payoff**: immediate impersonation of the app or abuse of third-party services on the developer&rsquo;s account.

### 2. Endpoints and Hidden Hosts

```
grep -rEn 'https?://[a-zA-Z0-9.-]+' out/ | sort -u
# reveals prod, staging, QA, and admin hosts, plus path structure
```

**Payoff**: a map of the backend, including endpoints never shown in the UI.

### 3. Encryption Keys and Custom Crypto

Look for `SecretKeySpec`, `IvParameterSpec`, `AES`, `Cipher.getInstance`, hardcoded byte arrays, and home-grown XOR/Base64 &ldquo;encryption.&rdquo; Because the key and algorithm are both present, the scheme is fully reversible.

### 4. Feature Flags and License Checks

Boolean methods like `isPremium()`, `isLicensed()`, `hasFeature("x")` that return a client-side decision are prime targets to replicate or (in M8) patch.

### 5. Protective Controls to Bypass

Certificate-pinning setup, `RootBeer`/custom root checks, jailbreak file probes, and debugger detection are located precisely so they can be neutralised.

## Dynamic Analysis and Bypasses

Static reading tells the analyst *where* a check lives; dynamic instrumentation confirms values and disables the check at runtime. Frida is the standard tool on both platforms.

```
// Frida: hook a client-side license check and force it to pass
Java.perform(function () {
  var Lic = Java.use('com.example.app.LicenseManager');
  Lic.isPremium.implementation = function () {
    console.log('[*] isPremium() called - forcing true');
    return true;                        // bypass the client-side gate
  };
});
```

```
# Attach Frida to a running app and load the script
frida -U -n MyApp -l bypass.js
# -U = USB device, -n = attach by process name

# Dump a key that the app reconstructs at runtime, straight from memory
frida -U -n MyApp -l dump-key.js
# (hook the crypto init and print the SecretKeySpec bytes)
```

The lesson of the dynamic step is decisive: even a key that is *derived* or *decoded* at runtime (rather than stored as a plain constant) is recoverable, because the finished value must exist in memory for the app to use it—and the attacker owns that memory.

## Chaining into Full Compromise

Reverse engineering is rarely the end goal; it is the reconnaissance that makes everything else cheap.

```
Decompile app (jadx)              -> find hardcoded HMAC signing key
        +
Read endpoint constants           -> recover the request-signing algorithm
        =  script valid, signed requests without the app (bot/fraud at scale)
```

Another common chain, from analysis to tampering:

```
Locate isLicensed() in decompiled code   -> confirm with Frida hook
        -> edit the smali to force `return true` (apktool)
        -> rebuild + re-sign the APK (M8 Code Tampering)
        =  a cracked build with all premium features unlocked
```

And from client analysis to backend breach:

```
Grep strings -> find staging/admin host + an embedded token
        -> token is over-privileged, works against production API
        -> enumerate the newly-discovered endpoints
        =  data exposure with no server-side bug of your own writing
```

## Key Takeaways

1. **The workflow is deterministic, not clever**—unpack, decompile, grep, confirm. It always succeeds to some depth.
2. **Strings alone leak a lot**—keys, URLs, and flags fall out of `strings` and `grep` before any decompiler is opened.
3. **Native and obfuscated code slow the analyst, not stop them**—Ghidra and Frida handle both routinely.
4. **Runtime values are recoverable**—derived or decoded keys still land in memory the attacker controls.
5. **Analysis feeds tampering and backend attacks**—M9 is the front door to M8, fraud, and server-side compromise.

## Next Steps

- **Prevention Guide**: Design so that a fully-read client reveals nothing dangerous
- **Code Examples**: Vulnerable vs. secure patterns in Kotlin/Java and Swift
- **Mobile Top 10**: Return to the full mobile learning path
- **Practice**: Apply these techniques in guided exercises
