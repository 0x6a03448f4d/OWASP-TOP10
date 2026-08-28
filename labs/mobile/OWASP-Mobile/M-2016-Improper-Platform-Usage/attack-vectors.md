# M1:2016 Improper Platform Usage - Attack Vectors

## Table of Contents
- [Understanding Platform-Misuse Attack Vectors](#understanding-platform-misuse-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Platform Misuse](#chaining-platform-misuse)

## Understanding Platform-Misuse Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in apps you own or are authorised to test.

Improper Platform Usage is rarely exploited by a remote payload. It is exploited by an attacker who **already has a foothold on the device**—a malicious app installed alongside yours, a rooted/jailbroken handset, a lost or stolen phone, or a backup pulled off a laptop. From that position the attacker simply uses the doors the app left open: an exported component, a plaintext token file, a biometric callback with nothing behind it.

The attacker's goal in this category is usually one of:

- Read secrets the app stored in the wrong place (preferences, plists, backups, clipboard).
- Reach a component that should have been private (exported Activity/Service/Receiver, unprotected Intent).
- Defeat a control the app implemented against the platform's design (a biometric gate with no key, a WebView bridge, disabled ATS).

### Core Attack Flow

```
1. Position
   ↓
   Install a co-located app, root/jailbreak, or obtain the device / a backup
2. Inspect
   ↓
   Read the manifest / Info.plist, dump storage, list exported components
3. Exploit
   ↓
   Call the exported component, read the plaintext secret, hook the callback
4. Escalate / Exfiltrate
   ↓
   Bypass auth, act as a confused deputy, pull tokens off-device
```

## Common Attack Patterns

### 1. Invoking Exported Components

A malicious app enumerates the target's exported components and calls them directly, skipping whatever UI flow was assumed to precede them.

```bash
# A co-located app (or adb) launches an internal Activity directly:
adb shell am start -n com.victim.app/.TransferActivity \
    --es amount 5000 --es to attacker_account

# Or in code, from the malicious app:
val i = Intent().setClassName("com.victim.app", "com.victim.app.TransferActivity")
i.putExtra("amount", "5000")
startActivity(i)   # login/confirmation screen never runs
```

**Payoff**: privileged actions or internal screens reached with no authentication, because the component trusted the fact that it was reached at all.

### 2. Intent Redirection (Confused Deputy)

An exported component extracts an Intent from its extras and blindly forwards it, so the attacker borrows the victim app's privileges to reach its protected internals.

```kotlin
// Vulnerable app forwards an attacker-supplied Intent:
val forward = intent.getParcelableExtra<Intent>("next")
startActivity(forward)   // attacker points 'next' at a protected component

// Malicious caller:
val inner = Intent().setClassName("com.victim.app", "com.victim.app.InternalAdmin")
val outer = Intent().setClassName("com.victim.app", "com.victim.app.Router")
outer.putExtra("next", inner)
startActivity(outer)
```

**Payoff**: access to non-exported, protected components via the vulnerable app—the classic confused-deputy escalation.

### 3. Reading Secrets from Insecure Storage

On a rooted/jailbroken device or from a backup, the attacker reads the files the app used instead of secure storage.

```bash
# Android: SharedPreferences XML is plaintext
adb shell run-as com.victim.app cat \
    /data/data/com.victim.app/shared_prefs/auth.xml
# → <string name="auth_token">eyJhbGciOi...</string>

# iOS: UserDefaults / app plist read from the container
plutil -p ~/Library/.../com.victim.app/Library/Preferences/com.victim.app.plist
```

**Payoff**: session tokens, API keys, and PII recovered with a file read—no exploit, no network.

### 4. Extracting Data via Backups

If backup flags are permissive, the attacker never needs root—just the device unlocked once, or an existing backup.

```bash
# Android: allowBackup=true lets adb pull an app backup
adb backup -f out.ab com.victim.app
# unpack out.ab → shared_prefs, databases, files with secrets intact

# iOS: Keychain items with kSecAttrAccessibleAlways ride along in backups
```

**Payoff**: full app data lifted off-device without rooting, because the platform's backup exclusion was never configured.

### 5. Bypassing a Biometric Gate With No Key

When biometric success only flips a boolean, instrumentation forces success without any biometric.

```javascript
// Frida: force the success path on Android
BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded.implementation = ...

// Or on iOS, override the LocalAuthentication result:
LAContext.evaluatePolicy   // hooked to call the reply with (true, nil)
```

**Payoff**: the "protected" screen opens with no fingerprint or face presented, because nothing cryptographic was ever unlocked.

### 6. Abusing a WebView JavaScript Bridge

Once untrusted content loads in a WebView that exposes a native bridge, that content calls app methods.

```html
// Native side exposed a bridge:
webView.addJavascriptInterface(NativeBridge(), "android")

// Attacker-controlled page (reached via redirect / mixed content) runs:
<script>
  // Any method annotated @JavascriptInterface is now callable:
  android.getAuthToken();
  android.readFile('/data/data/com.victim.app/shared_prefs/auth.xml');
</script>
```

**Payoff**: native functionality and, with file access enabled, local files exposed to a web attacker.

### 7. Intercepting Cleartext / ATS-Disabled Traffic

When the app allows cleartext or globally disables App Transport Security, an on-path attacker reads and rewrites traffic.

```bash
# On a hostile network, plain HTTP is trivially captured:
tcpdump -i any -A 'tcp port 80'

# ATS disabled globally means even 'https' endpoints may accept
# weak TLS / self-signed certs the platform would normally reject.
```

**Payoff**: credential and data interception, response tampering, and downgrade—because the platform's transport guardrail was switched off.

### 8. Harvesting the Clipboard / Pasteboard

Secrets copied to a shared clipboard are readable by other apps (and, historically, across devices via universal clipboard).

```kotlin
// Any app can poll the global clipboard:
val text = clipboardManager.primaryClip?.getItemAt(0)?.text  // Android
UIPasteboard.general.string                                   // iOS
```

**Payoff**: passwords, OTPs, and tokens the app placed on the clipboard are silently read by a background app.

### 9. Exploiting Weak Custom-Permission protectionLevel

A custom permission declared as `normal` is auto-granted to any app that requests it, so it protects nothing.

```xml
<!-- Victim declares a weak custom permission -->
<permission android:name="com.victim.app.PRIV"
            android:protectionLevel="normal" />

<!-- Malicious app simply requests it and is granted at install -->
<uses-permission android:name="com.victim.app.PRIV" />
```

**Payoff**: the "protected" component is reachable anyway, because `normal` (or `dangerous`) is not `signature`.

### 10. TapJacking / Overlay Attacks

A malicious overlay draws on top of the victim app so the user's taps land on hidden, sensitive controls.

```
// Malicious app draws a transparent overlay over the victim's screen;
// the user thinks they are tapping a game, but taps a
// "Confirm transfer" / "Grant permission" button underneath.
```

**Payoff**: the user is tricked into confirming privileged actions—mitigated by `filterTouchesWhenObscured`, which the vulnerable app did not set.

## Chaining Platform Misuse

Individually minor issues combine into full compromise:

```
allowBackup=true                 -> pull app data with 'adb backup'
        +
Token stored in SharedPreferences -> token sits in that backup in plaintext
        +
No cryptographic session binding  -> replay the token from another device
        =  account takeover, no root and no server bug required
```

Another common chain:

```
Exported Router Activity          -> accept an attacker-supplied Intent
        -> Intent redirection reaches an internal admin component
        -> that component reads a secret from insecure storage
        -> WebView bridge / cleartext channel exfiltrates it off-device
```

## Key Takeaways

1. **The attacker starts on the device**—co-located apps, root, theft, and backups are the threat model, not a remote payload.
2. **Exported components and forwarded Intents are prime targets**—anything reachable by other apps must assume a hostile caller.
3. **Insecure storage and permissive backups are free loot**—plaintext secrets are read directly, no exploit needed.
4. **Controls built against the platform fall to a hook**—a biometric gate with no key, or a WebView bridge, is bypassed with one line of instrumentation.
5. **Small issues chain**—a backup flag plus a plaintext token plus a replayable session equals account takeover.

## Next Steps

- **[Prevention Guide](prevention.md)**: Use the platform's controls the way they were designed
- **[Code Examples](examples.md)**: See secure Kotlin/Java and Swift side by side
- **[Mobile Learning Path](/learn/mobile)**: Continue the OWASP Mobile Top 10
- **[Practice](/practice)**: Test your understanding with hands-on challenges
