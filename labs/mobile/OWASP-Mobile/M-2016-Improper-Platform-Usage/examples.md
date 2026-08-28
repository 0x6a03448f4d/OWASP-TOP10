# M1:2016 Improper Platform Usage - Code Examples

Each pair below shows a **vulnerable** use of a platform feature and the **secure** version, in Kotlin/Java (Android) and Swift (iOS), plus the matching manifest / `Info.plist` configuration. The examples focus on the misuses that dominate real mobile findings: exported components, insecure secret storage, biometric gates with no key, disabled transport security, and WebView bridges.

## 1. Exported Components (Android manifest)

### Vulnerable
```xml
<!-- AndroidManifest.xml -->
<!-- Implicitly exported because it has an intent-filter and no explicit flag -->
<activity android:name=".TransferActivity">
    <intent-filter>
        <action android:name="com.app.TRANSFER"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>

<!-- Custom permission that protects nothing: normal is auto-granted -->
<permission android:name="com.app.permission.PRIV"
            android:protectionLevel="normal" />
<service android:name=".SyncService" android:exported="true"
         android:permission="com.app.permission.PRIV" />
```

### Secure
```xml
<!-- AndroidManifest.xml -->
<!-- Internal screen: explicitly not exported -->
<activity android:name=".TransferActivity" android:exported="false" />

<!-- Only the launcher is public -->
<activity android:name=".MainActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>

<!-- Cross-app IPC restricted to apps signed with the same key -->
<permission android:name="com.app.permission.PRIV"
            android:protectionLevel="signature" />
<service android:name=".SyncService" android:exported="true"
         android:permission="com.app.permission.PRIV" />
```

## 2. Intent Handling (Kotlin) — Avoiding Redirection

### Vulnerable
```kotlin
// Router forwards a caller-supplied Intent verbatim (confused deputy)
class RouterActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val next = intent.getParcelableExtra<Intent>("next")
        startActivity(next)          // attacker points 'next' at an internal component
    }
}
```

### Secure
```kotlin
// Never trust an Intent from another app; resolve targets yourself
class RouterActivity : AppCompatActivity() {
    private val allowed = mapOf("home" to HomeActivity::class.java,
                                "help" to HelpActivity::class.java)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val dest = intent.getStringExtra("dest")
        allowed[dest]?.let { startActivity(Intent(this, it)) }   // fixed set only
    }
}
```

## 3. Secret Storage (Kotlin, Android)

### Vulnerable
```kotlin
// Token written to plaintext SharedPreferences — recoverable from backups/root
val prefs = getSharedPreferences("auth", MODE_PRIVATE)
prefs.edit().putString("auth_token", token).apply()
```

### Secure
```kotlin
// EncryptedSharedPreferences backed by a hardware-backed Keystore master key
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val secure = EncryptedSharedPreferences.create(
    context, "secure_auth", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
secure.edit().putString("auth_token", token).apply()   // encrypted at rest
```

## 4. Secret Storage (Swift, iOS)

### Vulnerable
```swift
// UserDefaults is an unencrypted plist — included in backups, readable on device
UserDefaults.standard.set(token, forKey: "auth_token")
```

### Secure
```swift
// Keychain, device-only, requires unlock, excluded from backups
func storeToken(_ data: Data) -> Bool {
    let query: [String: Any] = [
        kSecClass as String:          kSecClassGenericPassword,
        kSecAttrAccount as String:    "auth_token",
        kSecValueData as String:      data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary)             // avoid duplicate errors
    return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
}
```

## 5. Biometric Authentication (Kotlin, Android)

### Vulnerable
```kotlin
// Gate is only a boolean callback — a hook forcing 'succeeded' wins
BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        revealSecrets()          // no CryptoObject; nothing is actually unlocked
    }
}).authenticate(promptInfo)
```

### Secure
```kotlin
// Key requires user authentication; biometric unlocks the cipher that decrypts data
val spec = KeyGenParameterSpec.Builder("token_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)             // must authenticate to use key
    .setInvalidatedByBiometricEnrollment(true)       // new fingerprint invalidates key
    .build()
// ... generate key in AndroidKeyStore, build cipher ...

BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        val cipher = result.cryptoObject!!.cipher!!  // only usable after real auth
        val token = decryptToken(cipher)             // fails without genuine biometric
        useToken(token)
    }
}).authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
```

## 6. Biometric Authentication (Swift, iOS)

### Vulnerable
```swift
// Only checks the boolean reply — no secret bound to the result
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                       localizedReason: "Unlock") { success, _ in
    if success { self.revealSecrets() }   // evaluatePolicy result is hookable
}
```

### Secure
```swift
// Secret is stored under a biometric-bound access control; the value is only
// released by the Keychain after a successful Face ID / Touch ID evaluation.
func storeBiometricToken(_ data: Data) {
    let acl = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .biometryCurrentSet, nil)!            // invalidated if biometrics change
    let query: [String: Any] = [
        kSecClass as String:          kSecClassGenericPassword,
        kSecAttrAccount as String:    "bio_token",
        kSecValueData as String:      data,
        kSecAttrAccessControl as String: acl
    ]
    SecItemAdd(query as CFDictionary, nil)
}
// Reading the item triggers the biometric prompt inside the Keychain itself —
// there is no boolean to hook; without a genuine match, no data is returned.
```

## 7. Transport Security (Info.plist & manifest)

### Vulnerable
```xml
<!-- iOS Info.plist: App Transport Security disabled everywhere -->
<key>NSAppTransportSecurity</key>
<dict><key>NSAllowsArbitraryLoads</key><true/></dict>

<!-- AndroidManifest.xml: cleartext HTTP allowed app-wide -->
<application android:usesCleartextTraffic="true" />
```

### Secure
```xml
<!-- iOS Info.plist: ATS on; scope one legacy domain only if unavoidable -->
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSExceptionDomains</key>
  <dict><key>legacy.example.com</key><dict>
    <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.2</string>
  </dict></dict>
</dict>

<!-- AndroidManifest.xml: cleartext off; trust anchored by a network config -->
<application android:usesCleartextTraffic="false"
             android:networkSecurityConfig="@xml/network_security_config" />
```

## 8. WebView Configuration (Kotlin, Android)

### Vulnerable
```kotlin
webView.settings.javaScriptEnabled = true
webView.settings.allowFileAccess = true                     // file:// reachable
webView.addJavascriptInterface(NativeBridge(), "android")   // native methods to JS
webView.loadUrl(untrustedUrl)                               // attacker content + bridge
```

### Secure
```kotlin
webView.settings.javaScriptEnabled = false                  // enable only if required
webView.settings.allowFileAccess = false
webView.settings.allowFileAccessFromFileURLs = false
webView.settings.allowUniversalAccessFromFileURLs = false
// No addJavascriptInterface unless essential; if used, keep the surface minimal.
webView.webViewClient = object : WebViewClient() {
    override fun shouldOverrideUrlLoading(v: WebView, r: WebResourceRequest): Boolean {
        return r.url.host !in setOf("app.example.com")      // block off-origin nav
    }
}
webView.loadUrl("https://app.example.com/")                 // trusted origin only
```

## 9. Backup Flag (Android manifest)

### Vulnerable
```xml
<!-- App data (including secret files) extractable via 'adb backup' -->
<application android:allowBackup="true" />
```

### Secure
```xml
<!-- No backup of app data, or exclude sensitive files precisely -->
<application android:allowBackup="false"
             android:fullBackupContent="@xml/backup_rules" />
<!-- res/xml/backup_rules.xml: <exclude domain="sharedpref" path="secure_auth.xml"/> -->
```

## What Changed, and Why

| Platform Misuse | Vulnerable | Secure |
|-----------------|-----------|--------|
| Exported components | Implicit export; `normal` custom permission | Explicit `exported=false`; `signature` permission |
| Intent handling | Forwards attacker-supplied Intent | Resolves targets from a fixed allow-list |
| Secret storage | SharedPreferences / UserDefaults plaintext | Keystore / Keychain, device-only, encrypted |
| Biometrics | Boolean callback, nothing unlocked | Bound to a `CryptoObject` / access-control key |
| Transport | ATS off / `usesCleartextTraffic=true` | ATS on, scoped exceptions; cleartext off |
| WebView | JS bridge + file access + untrusted URL | No bridge, file access off, trusted origin |
| Backup | `allowBackup=true` | `allowBackup=false` / exclude secrets |

## Next Steps

- **[Prevention](prevention.md)**: The full platform-usage hardening strategy
- **[Attack Vectors](attack-vectors.md)**: How these misuses are exploited
- **[Mobile Learning Path](/learn/mobile)**: Continue the OWASP Mobile Top 10
- **[Practice](/practice)**: Test your understanding with hands-on challenges
