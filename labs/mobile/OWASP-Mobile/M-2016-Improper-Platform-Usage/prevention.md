# M1:2016 Improper Platform Usage - Prevention

## Prevention Strategy Overview

Preventing improper platform usage is less about adding controls and more about **using the ones the OS already provides, exactly as designed**:

1. Request the least privilege the app can function with.
2. Keep components private; protect any required IPC with signatures.
3. Store secrets in the Keystore/Keychain with the right policy.
4. Bind biometrics to a real cryptographic operation.
5. Keep transport security, backup, and WebView defaults on the safe setting.

### Core Principles

- **Use the platform, don't reinvent it**: the OS control is hardware-backed, reviewed, and maintained—your custom substitute is not.
- **Assume a hostile device**: design for lost, stolen, rooted, and backed-up phones and co-located malware.
- **Least privilege everywhere**: every permission, exported component, and enabled feature is attack surface—drop what you don't need.
- **Fail closed**: if secure storage, biometrics, or attestation is unavailable, deny the sensitive action rather than falling back to an insecure path.

## 1. Request the Minimum Permissions

Only declare permissions the app genuinely uses, request them at the point of use, and handle denial gracefully.

```xml
<!-- Android: declare only what you use; scope down where possible -->
<uses-permission android:name="android.permission.CAMERA" />
<!-- Prefer scoped storage / photo picker over broad storage permissions -->
```

```kotlin
// Android: request at point of use, degrade gracefully on denial
if (checkSelfPermission(CAMERA) != PERMISSION_GRANTED) {
    requestPermissions(arrayOf(CAMERA), REQ_CAM)   // explain why first
}
// iOS: request the specific permission only when the feature is invoked;
// provide a clear NSCameraUsageDescription string in Info.plist.
```

Prefer privacy-preserving platform APIs (Android photo picker, iOS limited-photo access, one-time location) so you never hold a broad permission you don't need.

## 2. Don't Export Components; Protect Required IPC

Set `android:exported` explicitly on every component. Keep it `false` unless another app must reach it, and protect legitimate cross-app IPC with a `signature`-level permission.

```xml
<!-- Internal component: not reachable by other apps -->
<activity android:name=".TransferActivity" android:exported="false" />

<!-- Cross-app IPC restricted to apps signed with the same key -->
<permission android:name="com.app.permission.PRIV"
            android:protectionLevel="signature" />
<service android:name=".SyncService"
         android:exported="true"
         android:permission="com.app.permission.PRIV" />
```

When you must forward an Intent, validate its target: never call `startActivity()` on an attacker-supplied Intent, and set component/package explicitly to prevent Intent redirection.

## 3. Store Secrets in the Keystore / Keychain

Never place secrets in `SharedPreferences`, `UserDefaults`, or plist files. Use the platform secure store with a strict accessibility policy.

```swift
// iOS Keychain: device-only, requires unlock, excluded from backups
let query: [String: Any] = [
    kSecClass as String:            kSecClassGenericPassword,
    kSecAttrAccount as String:      "auth_token",
    kSecValueData as String:        tokenData,
    kSecAttrAccessible as String:   kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)
```

```kotlin
// Android: hardware-backed key via the Keystore + EncryptedSharedPreferences
val key = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
val secure = EncryptedSharedPreferences.create(
    context, "secure_prefs", key,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
```

Prefer `ThisDeviceOnly` accessibility on iOS and hardware/StrongBox backing on Android, so keys never leave the device and never ride along in a backup.

## 4. Bind Biometrics to a Cryptographic Operation

A biometric prompt must unlock a Keystore/Keychain key that is actually required to proceed—so a forced "success" is useless without the key.

```kotlin
// Android: gate on a CryptoObject, not just the callback
val cipher = getKeystoreCipher()               // key requires user auth
biometricPrompt.authenticate(
    promptInfo,
    BiometricPrompt.CryptoObject(cipher)       // only unlocked on real auth
)
// onAuthenticationSucceeded -> use result.cryptoObject.cipher to decrypt.
// Build the key with setUserAuthenticationRequired(true).
```

```swift
// iOS: bind the secret to biometrics via access control
let acl = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    .biometryCurrentSet, nil)                   // invalidated if biometrics change
// Store/read the item with kSecAttrAccessControl = acl so the value is
// only released after a successful Face ID / Touch ID evaluation.
```

Using `.biometryCurrentSet` / re-validating the key set means enrolling a new fingerprint or face invalidates the binding—closing an enrolment-swap bypass.

## 5. Keep App Transport Security On / Disallow Cleartext

Leave the platform transport defaults in place. If a single legacy endpoint truly needs an exception, scope it—never disable protection globally.

```xml
<!-- iOS: no global NSAllowsArbitraryLoads; scope a single legacy domain -->
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSExceptionDomains</key>
  <dict><key>legacy.example.com</key><dict>
    <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.2</string>
  </dict></dict>
</dict>
```

```xml
<!-- Android: disallow cleartext; pin trust with a network security config -->
<application android:usesCleartextTraffic="false"
             android:networkSecurityConfig="@xml/network_security_config" />
```

## 6. Harden WebViews

Enable only what the WebView needs, avoid native bridges, and never expose one to untrusted content.

```kotlin
webView.settings.javaScriptEnabled = false      // enable only if truly required
webView.settings.allowFileAccess = false        // no file:// from web content
webView.settings.allowFileAccessFromFileURLs = false
webView.settings.allowUniversalAccessFromFileURLs = false
// If a bridge is unavoidable, restrict it and load only trusted, verified URLs:
webView.addJavascriptInterface(SafeBridge(), "native")   // minimal @JavascriptInterface surface
webView.webViewClient = AllowlistWebViewClient()          // block off-origin navigation
```

On iOS prefer `WKWebView` (out-of-process), avoid `WKScriptMessageHandler` bridges for untrusted pages, and disable `allowFileAccessFromFileURLs`-style behaviours.

## 7. Lock Down Backups

Keep secrets out of cloud and local backups.

```xml
<!-- Android: disable backup, or exclude sensitive files precisely -->
<application android:allowBackup="false"
             android:fullBackupContent="@xml/backup_rules" />
```

On iOS, store secrets in the Keychain with a `ThisDeviceOnly` accessibility flag (excluded from backups) and set the "do not back up" resource attribute on any sensitive files you must keep on disk.

## 8. Protect Against Clipboard and TapJacking Leaks

```kotlin
// Android: mark sensitive clipboard content, and clear it promptly
val clip = ClipData.newPlainText("otp", code).apply {
    description.extras = PersistableBundle().apply {
        putBoolean("android.content.extra.IS_SENSITIVE", true)
    }
}
// Guard sensitive views against overlay/tapjacking:
sensitiveButton.filterTouchesWhenObscured = true
```

On iOS, use `UIPasteboard` with `expirationDate`/local-only options for sensitive copies, and avoid placing passwords or tokens on the general pasteboard at all.

## 9. Detect a Compromised Platform State

For high-value flows, verify the platform is in a trustworthy state before releasing secrets.

```
// Android: Play Integrity API attests device/app integrity server-side
// iOS: DeviceCheck / App Attest binds a key to a genuine device+app
// Use these signals to gate sensitive actions, not just a local
// root/jailbreak heuristic (which is easily defeated on its own).
```

Treat these as defence-in-depth: they raise the cost of on-device attacks but do not replace correct storage, IPC, and biometric binding.

## 10. Verify With Platform Tooling

```bash
# Static analysis of the manifest / Info.plist and code
mobsf            # Mobile Security Framework: manifest, storage, ATS, WebView checks
apkanalyzer manifest print app.apk    # inspect exported components / flags

# Dynamic checks on a test device
adb backup -f out.ab com.your.app     # confirm no secrets are extractable
frida -U -n YourApp                    # test biometric / storage bypass resistance
```

Run these on every release so a regression—an accidentally exported component, a re-enabled cleartext flag—is caught before it ships.

## Platform-Specific Hardening

### Android

```xml
<application
    android:allowBackup="false"
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config">

    <activity android:name=".MainActivity" android:exported="true" />   <!-- launcher -->
    <activity android:name=".InternalActivity" android:exported="false" />
</application>
<!-- Target a recent SDK so exported must be explicit and scoped storage applies -->
```

### iOS

```xml
<!-- Info.plist: ATS left on (no NSAllowsArbitraryLoads); purpose strings present -->
<key>NSCameraUsageDescription</key><string>Scan documents</string>
<!-- Store secrets in Keychain with WhenUnlockedThisDeviceOnly + access control -->
<!-- Prefer WKWebView; avoid script-message bridges to untrusted content -->
```

## Key Takeaways

1. **Use the platform control, correctly configured** — Keystore/Keychain, signature permissions, ATS, and CryptoObject exist so you don't improvise.
2. **Least privilege and least export** — request minimal permissions and keep components private by default.
3. **Bind, don't boolean** — biometrics must unlock a key, not just fire a callback.
4. **Keep the safe defaults** — don't disable ATS globally, don't allow cleartext, don't allow backup of secrets.
5. **Verify every release** — static and dynamic tooling catches an accidentally exported component or re-enabled flag before it ships.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure Kotlin/Java and Swift
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Mobile Learning Path](/learn/mobile)**: Continue the OWASP Mobile Top 10
- **[Practice](/practice)**: Test your understanding with hands-on challenges
