# M08: Security Misconfiguration - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Secure Configuration Practices](#secure-configuration-practices)
- [Production Build Configuration](#production-build-configuration)
- [Permission Management](#permission-management)
- [Network Security Settings](#network-security-settings)
- [Debug Features and Development Settings](#debug-features-and-development-settings)
- [Platform-Specific Configurations](#platform-specific-configurations)
- [Testing and Validation](#testing-and-validation)
- [Prevention Checklist](#prevention-checklist)

## Prevention Strategy Overview

Preventing security misconfigurations requires comprehensive attention across all deployment phases:

```
Design → Configure → Build → Test → Deploy → Monitor
   ↓         ↓         ↓       ↓       ↓        ↓
Minimal   Secure    Release  Security Production Continuous
Permissions Config  Hardening Testing  Lockdown  Auditing
```

### Core Principles

1. **Principle of Least Privilege**: Request only necessary permissions
2. **Secure by Default**: All configurations should be production-ready
3. **Defense in Depth**: Multiple layers of security controls
4. **Environment Separation**: Clear distinction between dev/staging/production
5. **Minimal Attack Surface**: Disable all unnecessary features
6. **Continuous Validation**: Regular security audits and testing

## Secure Configuration Practices

### ✅ Minimize App Permissions

**Android - Request Only Required Permissions**:
```xml
<!-- AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.secureapp">
    
    <!-- ✅ GOOD: Only request necessary permissions -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    
    <!-- ❌ AVOID: Don't request unnecessary permissions -->
    <!-- <uses-permission android:name="android.permission.READ_CONTACTS" /> -->
    <!-- <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" /> -->
    
    <!-- Request runtime permissions for sensitive data -->
    <application>
        <!-- App content -->
    </application>
</manifest>
```

**iOS - Minimize Info.plist Permissions**:
```xml
<!-- Info.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- ✅ GOOD: Only request necessary permissions with clear descriptions -->
    <key>NSCameraUsageDescription</key>
    <string>This app requires camera access to scan QR codes for authentication</string>
    
    <!-- ❌ AVOID: Don't request permissions you don't need -->
    <!-- <key>NSLocationAlwaysUsageDescription</key> -->
    <!-- <string>Generic location access</string> -->
</dict>
</plist>
```

### ✅ Disable Backup for Sensitive Data

**Android - Backup Rules**:
```xml
<!-- AndroidManifest.xml -->
<application
    android:allowBackup="true"
    android:fullBackupContent="@xml/backup_rules"
    android:dataExtractionRules="@xml/data_extraction_rules">
</application>

<!-- res/xml/backup_rules.xml -->
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <!-- Include only non-sensitive data -->
    <include domain="sharedpref" path="app_preferences.xml"/>
    
    <!-- Exclude sensitive data -->
    <exclude domain="sharedpref" path="secure_prefs.xml"/>
    <exclude domain="database" path="user_credentials.db"/>
    <exclude domain="file" path="keys/"/>
</full-backup-content>

<!-- res/xml/data_extraction_rules.xml (Android 12+) -->
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="secure_prefs.xml"/>
        <exclude domain="database" path="user_credentials.db"/>
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="secure_prefs.xml"/>
    </device-transfer>
</data-extraction-rules>
```

**iOS - Exclude from iCloud Backup**:
```swift
import Foundation

class SecureFileManager {
    // Exclude sensitive files from iCloud backup
    func excludeFromBackup(url: URL) throws {
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        
        var mutableURL = url
        try mutableURL.setResourceValues(resourceValues)
    }
    
    // Create secure directory excluded from backups
    func createSecureDirectory() throws -> URL {
        let fileManager = FileManager.default
        let documentsPath = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let securePath = documentsPath.appendingPathComponent("secure", isDirectory: true)
        
        if !fileManager.fileExists(atPath: securePath.path) {
            try fileManager.createDirectory(at: securePath, withIntermediateDirectories: true)
        }
        
        try excludeFromBackup(url: securePath)
        return securePath
    }
}
```

### ✅ Configure Secure File Permissions

**Android - Set Proper File Modes**:
```java
import android.content.Context;
import java.io.File;
import java.io.FileOutputStream;

public class SecureFileHandler {
    // Create file with secure permissions (MODE_PRIVATE)
    public void createSecureFile(Context context, String filename, byte[] data) 
            throws Exception {
        // ✅ GOOD: Use MODE_PRIVATE for sensitive files
        FileOutputStream fos = context.openFileOutput(
            filename, 
            Context.MODE_PRIVATE  // Only accessible by this app
        );
        
        fos.write(data);
        fos.close();
        
        // Additional hardening: restrict file permissions
        File file = new File(context.getFilesDir(), filename);
        file.setReadable(false, false);  // No world-readable
        file.setReadable(true, true);    // Owner-only readable
        file.setWritable(false, false);  // No world-writable
        file.setWritable(true, true);    // Owner-only writable
    }
}
```

## Production Build Configuration

### ✅ Android ProGuard/R8 Configuration

**proguard-rules.pro**:
```proguard
# Enable aggressive optimization for production
-optimizationpasses 5
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose

# Remove logging in production
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# Obfuscate sensitive classes
-keep class com.example.app.models.** { *; }
-keepclassmembers class com.example.app.security.** {
    !private <fields>;
    !private <methods>;
}

# Remove debug utilities
-assumenosideeffects class com.example.app.debug.** {
    *;
}

# Protect against reflection attacks
# Keep annotations for reflection-based frameworks (Retrofit, Gson, Room, Dagger)
-keepattributes *Annotation*
# Keep generic signatures for proper type inference
-keepattributes Signature
# Preserve inner classes for proper serialization
-keepattributes InnerClasses
# Keep enclosing method info for debugging anonymous classes
-keepattributes EnclosingMethod
```

**build.gradle (App Module)**:
```gradle
android {
    buildTypes {
        debug {
            // Debug configuration
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
            
            // Enable code optimization
            crunchPngs true
            
            // Signing configuration (use secure key management)
            signingConfig signingConfigs.release
        }
    }
    
    // Additional security configurations
    buildFeatures {
        buildConfig true
    }
    
    // Disable test orchestrator in production
    testOptions {
        execution 'ANDROIDX_TEST_ORCHESTRATOR'
    }
}
```

### ✅ iOS Build Configuration

**Build Settings (Xcode)**:
```swift
// Compiler flags for production
// Set in Xcode Build Settings or xcconfig file

// Release configuration
SWIFT_OPTIMIZATION_LEVEL = -O
SWIFT_COMPILATION_MODE = wholemodule
ENABLE_BITCODE = YES
DEAD_CODE_STRIPPING = YES
STRIP_INSTALLED_PRODUCT = YES
COPY_PHASE_STRIP = YES

// Security hardening
ENABLE_HARDENED_RUNTIME = YES
ENABLE_CODE_SIGNING_CHECKS = YES

// Remove debug symbols
DEBUG_INFORMATION_FORMAT = dwarf-with-dsym
DEPLOYMENT_POSTPROCESSING = YES
STRIP_STYLE = all
```

**Conditional Compilation**:
```swift
class AppConfiguration {
    static func configureForProduction() {
        #if DEBUG
        // Development settings
        Logger.enabled = true
        NetworkMonitor.verbose = true
        #else
        // ✅ Production settings
        Logger.enabled = false
        NetworkMonitor.verbose = false
        
        // Disable developer tools
        disableDebugFeatures()
        #endif
    }
    
    private static func disableDebugFeatures() {
        // Prevent debugging tools
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib : [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        
        sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        if (info.kp_proc.p_flag & P_TRACED) != 0 {
            // Debugger detected - handle appropriately
            exit(0)
        }
    }
}
```

## Permission Management

### ✅ Runtime Permission Requests

**Android - Proper Permission Handling**:
```java
import android.Manifest;
import android.content.pm.PackageManager;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

public class PermissionManager {
    private static final int REQUEST_CAMERA = 1001;
    
    // ✅ GOOD: Request permission with clear justification
    public void requestCameraPermission(Activity activity) {
        // Check if permission is already granted
        if (ContextCompat.checkSelfPermission(activity, 
                Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            // Permission granted, proceed
            initializeCamera();
            return;
        }
        
        // Show rationale if needed
        if (ActivityCompat.shouldShowRequestPermissionRationale(
                activity, Manifest.permission.CAMERA)) {
            // Show explanation to user
            showPermissionRationale(activity);
        } else {
            // Request permission
            ActivityCompat.requestPermissions(
                activity,
                new String[]{Manifest.permission.CAMERA},
                REQUEST_CAMERA
            );
        }
    }
    
    // Handle permission result
    public void onRequestPermissionsResult(
            int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == REQUEST_CAMERA) {
            if (grantResults.length > 0 && 
                grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                initializeCamera();
            } else {
                // Permission denied - gracefully degrade
                showPermissionDeniedMessage();
            }
        }
    }
}
```

**iOS - Permission Request Best Practices**:
```swift
import AVFoundation
import Photos

class PermissionManager {
    // ✅ GOOD: Request permission with proper error handling
    func requestCameraPermission(completion: @escaping (Bool) -> Void) {
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        
        switch status {
        case .authorized:
            completion(true)
            
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                DispatchQueue.main.async {
                    completion(granted)
                }
            }
            
        case .denied, .restricted:
            // Guide user to settings
            showPermissionDeniedAlert()
            completion(false)
            
        @unknown default:
            completion(false)
        }
    }
    
    private func showPermissionDeniedAlert() {
        let alert = UIAlertController(
            title: "Camera Access Required",
            message: "Please enable camera access in Settings to use this feature.",
            preferredStyle: .alert
        )
        
        alert.addAction(UIAlertAction(title: "Settings", style: .default) { _ in
            if let settingsUrl = URL(string: UIApplication.openSettingsURLString) {
                UIApplication.shared.open(settingsUrl)
            }
        })
        
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        
        // Present alert
    }
}
```

### ✅ Remove Dangerous Permissions

**Android - Avoid Over-Privileged Configurations**:
```xml
<!-- AndroidManifest.xml -->

<!-- ❌ DANGEROUS: Don't use unless absolutely necessary -->
<!-- <uses-permission android:name="android.permission.READ_SMS" /> -->
<!-- <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" /> -->
<!-- <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" /> -->
<!-- <uses-permission android:name="android.permission.READ_CONTACTS" /> -->
<!-- <uses-permission android:name="android.permission.RECORD_AUDIO" /> -->

<!-- ✅ GOOD: Use scoped storage (Android 10+) -->
<application android:requestLegacyExternalStorage="false">
    <!-- Use MediaStore or Storage Access Framework -->
</application>
```

## Network Security Settings

### ✅ Network Security Configuration

**Android - Enforce HTTPS**:
```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- ✅ GOOD: Block cleartext traffic -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    
    <!-- Production API with certificate pinning -->
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.production.example.com</domain>
        <pin-set expiration="2025-12-31">
            <!-- Primary certificate -->
            <pin digest="SHA-256">base64EncodedPrimaryPin==</pin>
            <!-- Backup certificate -->
            <pin digest="SHA-256">base64EncodedBackupPin==</pin>
        </pin-set>
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </domain-config>
    
    <!-- Debug config (only for development builds) -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
            <certificates src="system" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>

<!-- Reference in AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config">
</application>
```

**iOS - App Transport Security**:
```xml
<!-- Info.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- ✅ GOOD: Enforce strong TLS -->
    <key>NSAppTransportSecurity</key>
    <dict>
        <!-- Don't allow arbitrary loads -->
        <key>NSAllowsArbitraryLoads</key>
        <false/>
        
        <!-- Specific domain configuration -->
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
                
                <!-- Certificate pinning -->
                <key>NSPinnedDomains</key>
                <dict>
                    <key>api.example.com</key>
                    <array>
                        <string>sha256/primaryCertHash==</string>
                        <string>sha256/backupCertHash==</string>
                    </array>
                </dict>
            </dict>
        </dict>
    </dict>
</dict>
</plist>
```

### ✅ Implement Certificate Pinning

**Android - OkHttp Certificate Pinning**:
```java
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;

public class SecureNetworkClient {
    public OkHttpClient createSecureClient() {
        // ✅ GOOD: Pin certificates for critical domains
        CertificatePinner certificatePinner = new CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
            .build();
        
        return new OkHttpClient.Builder()
            .certificatePinner(certificatePinner)
            .build();
    }
}
```

**iOS - URLSession Certificate Pinning**:
```swift
import Foundation
import Security

class CertificatePinner: NSObject, URLSessionDelegate {
    private let pinnedCertificates: Set<Data>
    
    init(certificateNames: [String]) {
        var certificates = Set<Data>()
        
        for name in certificateNames {
            if let path = Bundle.main.path(forResource: name, ofType: "cer"),
               let certData = try? Data(contentsOf: URL(fileURLWithPath: path)) {
                certificates.insert(certData)
            }
        }
        
        self.pinnedCertificates = certificates
        super.init()
    }
    
    func urlSession(_ session: URLSession,
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Validate certificate chain
        if validateServerTrust(serverTrust) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    private func validateServerTrust(_ serverTrust: SecTrust) -> Bool {
        guard let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            return false
        }
        
        let serverCertData = SecCertificateCopyData(serverCertificate) as Data
        return pinnedCertificates.contains(serverCertData)
    }
}
```

## Debug Features and Development Settings

### ✅ Disable Debug Features in Production

**Android - Remove Debug Capabilities**:
```xml
<!-- AndroidManifest.xml -->
<application
    android:debuggable="false"
    android:allowBackup="false"
    android:usesCleartextTraffic="false">
    
    <!-- Remove test providers in production -->
    <!-- <provider android:authorities="com.example.test.provider" /> -->
</application>
```

**Build-Time Debug Feature Control**:
```java
public class DebugConfig {
    // ✅ GOOD: Use BuildConfig for debug features
    public static void initialize() {
        if (BuildConfig.DEBUG) {
            // Enable debug tools only in debug builds
            Timber.plant(new Timber.DebugTree());
            StrictMode.enableDefaults();
            LeakCanary.install();
        } else {
            // Production: disable all debug features
            disableDebugging();
        }
    }
    
    private static void disableDebugging() {
        // Disable loggers
        Logger.disable();
        
        // Remove crash reporting for debug builds
        // Enable production crash reporting
        FirebaseCrashlytics.getInstance().setCrashlyticsCollectionEnabled(true);
    }
}
```

**iOS - Conditional Debug Code**:
```swift
class DebugManager {
    static func configure() {
        #if DEBUG
        // Development only features
        enableDebugLogging()
        setupNetworkDebugging()
        #else
        // ✅ Production configuration
        disableAllDebugFeatures()
        enableProductionMonitoring()
        #endif
    }
    
    private static func disableAllDebugFeatures() {
        // Disable console logging
        // Disable network inspection
        // Enable crash reporting
        // Enable analytics
    }
    
    private static func enableProductionMonitoring() {
        // Configure Firebase/Crashlytics
        // Setup performance monitoring
        // Enable security monitoring
    }
}
```

### ✅ Secure WebView Configuration

**Android - Hardened WebView**:
```java
import android.webkit.WebSettings;
import android.webkit.WebView;

public class SecureWebViewConfig {
    public void configureSecureWebView(WebView webView) {
        WebSettings settings = webView.getSettings();
        
        // ✅ GOOD: Disable dangerous features
        settings.setJavaScriptEnabled(false);  // Only enable if necessary
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        
        // Disable geolocation
        settings.setGeolocationEnabled(false);
        
        // Clear cache
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        settings.setDatabaseEnabled(false);
        settings.setDomStorageEnabled(false);
        
        // Enable safe browsing
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            settings.setSafeBrowsingEnabled(true);
        }
        
        // Disable debugging
        WebView.setWebContentsDebuggingEnabled(false);
    }
}
```

**iOS - Secure WKWebView**:
```swift
import WebKit

class SecureWebViewConfig {
    func createSecureWebView() -> WKWebView {
        let configuration = WKWebViewConfiguration()
        
        // ✅ GOOD: Disable dangerous features
        configuration.preferences.javaScriptEnabled = false  // Only enable if needed
        configuration.allowsInlineMediaPlayback = false
        configuration.mediaTypesRequiringUserActionForPlayback = .all
        
        // Data detector types (minimize)
        configuration.dataDetectorTypes = []
        
        // Disable JavaScript in main frame
        if #available(iOS 14.0, *) {
            configuration.defaultWebpagePreferences.allowsContentJavaScript = false
        }
        
        let webView = WKWebView(frame: .zero, configuration: configuration)
        
        // Additional security
        webView.allowsBackForwardNavigationGestures = false
        webView.allowsLinkPreview = false
        
        return webView
    }
}
```

## Platform-Specific Configurations

### ✅ Android-Specific Security

**Prevent Screenshots and Screen Recording**:
```java
import android.view.WindowManager;
import androidx.appcompat.app.AppCompatActivity;

public class SecureActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // ✅ GOOD: Prevent screenshots for sensitive screens
        getWindow().setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        );
        
        setContentView(R.layout.activity_secure);
    }
}
```

**Secure Activity Export**:
```xml
<!-- AndroidManifest.xml -->
<activity
    android:name=".SecureActivity"
    android:exported="false">  <!-- ✅ Don't expose unless necessary -->
    
    <!-- If must export, require permissions -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
    </intent-filter>
</activity>

<!-- For exported components, use permissions -->
<activity
    android:name=".PublicActivity"
    android:exported="true"
    android:permission="com.example.app.permission.ACCESS_ACTIVITY">
</activity>

<!-- Define custom permission -->
<permission
    android:name="com.example.app.permission.ACCESS_ACTIVITY"
    android:protectionLevel="signature" />
```

**Content Provider Security**:
```xml
<!-- AndroidManifest.xml -->
<provider
    android:name=".SecureContentProvider"
    android:authorities="com.example.app.provider"
    android:exported="false"
    android:grantUriPermissions="false"
    android:readPermission="com.example.app.permission.READ_DATA"
    android:writePermission="com.example.app.permission.WRITE_DATA">
</provider>
```

### ✅ iOS-Specific Security

**Disable Pasteboard Access**:
```swift
import UIKit

class SecureTextField: UITextField {
    // ✅ GOOD: Disable copy/paste for sensitive fields
    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
        if action == #selector(copy(_:)) ||
           action == #selector(paste(_:)) ||
           action == #selector(cut(_:)) ||
           action == #selector(select(_:)) ||
           action == #selector(selectAll(_:)) {
            return false
        }
        return super.canPerformAction(action, withSender: sender)
    }
}
```

**Configure Data Protection**:
```swift
import Foundation

class DataProtectionManager {
    // ✅ GOOD: Use appropriate data protection levels
    func createFileWithProtection(data: Data, filename: String) throws {
        let fileManager = FileManager.default
        let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let fileURL = documentsURL.appendingPathComponent(filename)
        
        // Write with complete protection
        try data.write(
            to: fileURL,
            options: [.completeFileProtection]
        )
    }
    
    // Set protection on existing file
    func setFileProtection(url: URL) throws {
        try (url as NSURL).setResourceValue(
            URLFileProtection.complete,
            forKey: .fileProtectionKey
        )
    }
}
```

**Disable Screenshot Prevention**:
```swift
import UIKit

class SecureViewController: UIViewController {
    private var secureField: UITextField!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // ✅ GOOD: Hide sensitive content in app switcher
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(willResignActive),
            name: UIApplication.willResignActiveNotification,
            object: nil
        )
        
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(didBecomeActive),
            name: UIApplication.didBecomeActiveNotification,
            object: nil
        )
    }
    
    @objc private func willResignActive() {
        // Hide sensitive content
        secureField.isSecureTextEntry = true
        secureField.text = ""
        
        // Or add blur overlay
        addBlurOverlay()
    }
    
    @objc private func didBecomeActive() {
        removeBlurOverlay()
    }
    
    private func addBlurOverlay() {
        let blurEffect = UIBlurEffect(style: .light)
        let blurView = UIVisualEffectView(effect: blurEffect)
        blurView.frame = view.bounds
        blurView.tag = 999
        view.addSubview(blurView)
    }
    
    private func removeBlurOverlay() {
        view.subviews.first(where: { $0.tag == 999 })?.removeFromSuperview()
    }
}
```

## Testing and Validation

### ✅ Automated Configuration Testing

**Static Analysis Script**:
```bash
#!/bin/bash
# check_security_config.sh

echo "Running security configuration checks..."

# Android checks
if [ -f "AndroidManifest.xml" ]; then
    echo "Checking Android configuration..."
    
    # Check debuggable flag
    if grep -q 'android:debuggable="true"' AndroidManifest.xml; then
        echo "❌ ERROR: debuggable=true in manifest"
        exit 1
    fi
    
    # Check backup settings
    if grep -q 'android:allowBackup="true"' AndroidManifest.xml; then
        if ! grep -q 'android:fullBackupContent' AndroidManifest.xml; then
            echo "⚠️  WARNING: Backup enabled without rules"
        fi
    fi
    
    # Check cleartext traffic
    if grep -q 'android:usesCleartextTraffic="true"' AndroidManifest.xml; then
        echo "❌ ERROR: Cleartext traffic allowed"
        exit 1
    fi
    
    # Check exported components
    exported_count=$(grep -c 'android:exported="true"' AndroidManifest.xml || true)
    if [ "$exported_count" -gt 0 ]; then
        echo "⚠️  WARNING: $exported_count exported components found"
    fi
fi

# iOS checks
if [ -f "Info.plist" ]; then
    echo "Checking iOS configuration..."
    
    # Check ATS settings
    if grep -q "NSAllowsArbitraryLoads.*true" Info.plist; then
        echo "❌ ERROR: Arbitrary loads allowed"
        exit 1
    fi
fi

echo "✅ Configuration checks passed"
```

### ✅ Runtime Configuration Validation

**Android - Runtime Security Checks**:
```java
public class SecurityValidator {
    public static void validateSecurityConfig(Context context) {
        List<String> issues = new ArrayList<>();
        
        // Check if app is debuggable
        if (isDebuggable(context)) {
            issues.add("App is debuggable");
        }
        
        // Check if running on rooted device
        if (isDeviceRooted()) {
            issues.add("Device is rooted");
        }
        
        // Check backup settings
        ApplicationInfo appInfo = context.getApplicationInfo();
        if ((appInfo.flags & ApplicationInfo.FLAG_ALLOW_BACKUP) != 0) {
            issues.add("Backup is enabled");
        }
        
        // Report issues
        if (!issues.isEmpty()) {
            Log.w("Security", "Configuration issues: " + issues);
            // In production: report to monitoring
        }
    }
    
    private static boolean isDebuggable(Context context) {
        return (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }
    
    private static boolean isDeviceRooted() {
        String[] paths = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su"
        };
        
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }
}
```

### ✅ MobSF Integration for CI/CD

```yaml
# .github/workflows/security-scan.yml
name: Security Configuration Scan

on:
  pull_request:
    branches: [ main ]

jobs:
  mobsf-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Build APK
        run: ./gradlew assembleRelease
      
      - name: Run MobSF Scan
        uses: fundacaocerti/mobsf-action@v1
        with:
          INPUT_FILE_NAME: app/build/outputs/apk/release/app-release.apk
          SCAN_TYPE: apk
          
      - name: Check for misconfigurations
        run: |
          # Parse MobSF output for configuration issues
          python scripts/check_mobsf_results.py
```

## Prevention Checklist

### Pre-Development
- [ ] Define minimal permission set required
- [ ] Plan environment-specific configurations
- [ ] Document security requirements
- [ ] Review platform security guidelines

### Development Phase
- [ ] Request only necessary permissions
- [ ] Implement proper permission handling
- [ ] Configure secure network settings
- [ ] Disable debug features for production
- [ ] Exclude sensitive data from backups
- [ ] Set appropriate file permissions
- [ ] Configure secure WebView settings
- [ ] Implement certificate pinning

### Build Configuration
- [ ] Enable ProGuard/R8 for Android
- [ ] Remove debug symbols
- [ ] Disable debugging in release builds
- [ ] Configure code obfuscation
- [ ] Remove test code from production
- [ ] Validate signing configuration

### Testing Phase
- [ ] Run static analysis tools (MobSF, QARK)
- [ ] Verify permission requests
- [ ] Test on rooted/jailbroken devices
- [ ] Validate network security configuration
- [ ] Check for exported components
- [ ] Verify backup exclusions
- [ ] Test certificate pinning

### Pre-Deployment
- [ ] Final security scan
- [ ] Verify no debug flags
- [ ] Confirm production configuration
- [ ] Review all exported components
- [ ] Validate signing certificates
- [ ] Check third-party library configurations

### Post-Deployment
- [ ] Monitor for configuration issues
- [ ] Track permission usage
- [ ] Regular security audits
- [ ] Update certificates before expiration
- [ ] Review and update configurations

## Quick Reference: Dos and Don'ts

### ✅ DO
- Request minimal permissions
- Use platform security features
- Disable debugging in production
- Implement certificate pinning
- Exclude sensitive data from backups
- Use secure file permissions
- Configure network security properly
- Regularly audit configurations
- Use environment-specific builds
- Enable code obfuscation

### ❌ DON'T
- Request unnecessary permissions
- Enable debugging in production
- Allow cleartext traffic
- Export components unnecessarily
- Include sensitive data in backups
- Use world-readable file permissions
- Allow arbitrary SSL certificates
- Skip security testing
- Use same config for dev and prod
- Ignore static analysis warnings

## Additional Resources

- **Android Security Best Practices**: https://developer.android.com/training/articles/security-tips
- **iOS Security Guide**: https://support.apple.com/guide/security/welcome/web
- **OWASP Mobile Security Testing Guide**: https://mobile-security.gitbook.io/
- **Android Network Security Configuration**: https://developer.android.com/training/articles/security-config
- **Certificate Pinning Best Practices**: https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning

---

**Remember**: Security misconfigurations are one of the most common vulnerabilities. Regular audits and validation are essential.

*Part of OWASP Mobile Top 10 - Educational Repository*
