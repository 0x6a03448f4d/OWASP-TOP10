# M08: Security Misconfiguration - Attack Vectors

## Table of Contents
- [Attack Methodology Overview](#attack-methodology-overview)
- [Configuration Analysis Attacks](#configuration-analysis-attacks)
- [Permission Exploitation](#permission-exploitation)
- [Network Configuration Attacks](#network-configuration-attacks)
- [Debug Feature Exploitation](#debug-feature-exploitation)
- [Attack Tools and Techniques](#attack-tools-and-techniques)

## Attack Methodology Overview

Attackers targeting security misconfigurations follow a systematic approach:

```
1. Reconnaissance (App Analysis)
   ↓
2. Configuration Extraction (Manifest, Info.plist)
   ↓
3. Debug Feature Detection (Logging, Error Messages)
   ↓
4. Permission Enumeration (Granted Capabilities)
   ↓
5. Network Analysis (TLS Settings, Cleartext)
   ↓
6. Exploitation (Leverage Weak Configurations)
```

### Attack Timeline

- **Initial Analysis**: Minutes (extract and analyze configuration)
- **Vulnerability Discovery**: Hours (identify misconfigurations)
- **Exploitation**: Minutes to days (depending on vulnerability)

## Configuration Analysis Attacks

### Attack Vector 1: Manifest/Info.plist Analysis

**Technique**: Examining application configuration files for security weaknesses.

**Android - AndroidManifest.xml Analysis**:
```xml
<!-- Attackers extract and analyze AndroidManifest.xml -->
<application
    android:debuggable="true"  <!-- VULNERABLE: Debug enabled -->
    android:allowBackup="true"  <!-- VULNERABLE: Backups enabled -->
    android:usesCleartextTraffic="true">  <!-- VULNERABLE: HTTP allowed -->
    
    <activity android:exported="true">  <!-- VULNERABLE: Exposed activity -->
        <!-- Activity accessible from other apps -->
    </activity>
</application>
```

**iOS - Info.plist Analysis**:
```xml
<!-- Attackers examine Info.plist for weak settings -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>  <!-- VULNERABLE: Allows HTTP connections -->
</dict>
```

**What Attackers Look For**:
- Debug flags enabled
- Backup configurations
- Exported components
- Cleartext traffic allowances
- Weak App Transport Security settings
- Unnecessary permissions

### Attack Vector 2: Debug Mode Exploitation

**Technique**: Leveraging debug features left enabled in production.

**Information Disclosure Through Logs**:
```
// Attackers monitor logcat for sensitive information
adb logcat | grep -i "password\|token\|api\|secret"

// Common debug outputs:
D/API: Request URL: https://api.example.com/user/12345/profile
D/API: Auth Token: eyJhbGciOiJIUzI1NiIs...
D/Database: SQL Query: SELECT * FROM users WHERE id=12345
E/Auth: Login failed for user: admin@example.com
```

**Stack Trace Analysis**:
- Detailed error messages expose internal structure
- File paths reveal code organization
- Database queries show schema
- API endpoints disclosed

**Example Attack Flow**:
```
1. Install app with debug enabled
2. Monitor application logs
3. Collect API endpoints, tokens, database queries
4. Map internal application structure
5. Exploit discovered information
```

### Attack Vector 3: Insecure Build Configuration

**Technique**: Exploiting development configurations in production builds.

**Common Issues**:
- Source maps included in release builds
- Development endpoints not removed
- Test accounts/credentials present
- Debug symbols not stripped
- Obfuscation disabled

**ProGuard/R8 Not Configured**:
```
// Without obfuscation, decompiled code is readable
public class ApiClient {
    private String apiKey = "sk_live_12345...";
    public String getSecretEndpoint() {
        return "https://api.example.com/admin/secret";
    }
}
```

## Permission Exploitation

### Attack Vector 4: Excessive Permissions

**Technique**: Exploiting overly permissive app permissions.

**Android Permission Abuse**:
```xml
<!-- App requests unnecessary dangerous permissions -->
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
<uses-permission android:name="android.permission.CAMERA"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
```

**Attack Scenarios**:
1. **Data Harvesting**: App collects contacts, location unnecessarily
2. **Malware Vector**: Malicious updates abuse existing permissions
3. **Privacy Violations**: Tracking user without clear purpose
4. **Cross-App Attacks**: Accessing shared storage of other apps

### Attack Vector 5: Exported Components

**Technique**: Accessing improperly exported app components.

**Vulnerable Exported Activity**:
```xml
<activity 
    android:name=".AdminActivity"
    android:exported="true">  <!-- VULNERABLE: No protection -->
    <!-- Any app can launch this admin activity -->
</activity>
```

**Exploitation**:
```bash
# Launch exported activity from another app or adb
adb shell am start -n com.example.app/.AdminActivity

# Access exported content provider
adb shell content query --uri content://com.example.provider/sensitive_data
```

**What Can Be Exploited**:
- Activities (UI screens)
- Services (background tasks)
- Broadcast Receivers (event handlers)
- Content Providers (data storage)

## Network Configuration Attacks

### Attack Vector 6: Cleartext Traffic Interception

**Technique**: Intercepting unencrypted HTTP traffic.

**Vulnerable Network Configuration**:
```xml
<!-- Android: Allows HTTP traffic -->
<application
    android:usesCleartextTraffic="true">
```

**Attack Process**:
```
1. User connects to public WiFi
2. Attacker performs ARP spoofing
3. All traffic routed through attacker
4. HTTP requests captured in cleartext
5. Credentials, tokens, data stolen
```

**Captured Traffic Example**:
```http
GET /api/user/profile HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Cookie: session=abc123def456
```

### Attack Vector 7: Weak TLS Configuration

**Technique**: Exploiting weak SSL/TLS settings.

**Vulnerable iOS ATS Configuration**:
```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>  <!-- Disables ATS completely -->
</dict>
```

**Attacks Enabled**:
- Man-in-the-middle attacks
- Downgrade attacks to weak ciphers
- Certificate validation bypass
- Traffic interception and modification

### Attack Vector 8: Missing Certificate Pinning

**Technique**: Bypassing TLS with custom certificates.

**Attack Setup**:
```
1. Install proxy certificate on device (Burp, Charles)
2. Configure proxy settings
3. App trusts any certificate (no pinning)
4. All HTTPS traffic decrypted by proxy
5. Modify requests/responses at will
```

## Debug Feature Exploitation

### Attack Vector 9: WebView Debug Mode

**Technique**: Accessing WebView debugging interfaces.

**Vulnerable WebView Configuration**:
```java
// VULNERABLE: WebView debugging enabled in production
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    WebView.setWebContentsDebuggingEnabled(true);
}
```

**Exploitation**:
```
1. Connect device to computer
2. Open Chrome DevTools (chrome://inspect)
3. Access WebView content
4. Inspect DOM, execute JavaScript
5. Extract tokens, manipulate UI, bypass controls
```

### Attack Vector 10: Backup Data Extraction

**Technique**: Extracting application data from device backups.

**Vulnerable Backup Configuration**:
```xml
<!-- Android: Backup enabled for sensitive data -->
<application
    android:allowBackup="true"
    android:fullBackupContent="true">
```

**Extraction Process**:
```bash
# Create backup
adb backup -f app.ab com.example.app

# Convert to tar
java -jar abe.jar unpack app.ab app.tar

# Extract files
tar -xf app.tar

# Access application data
cd apps/com.example.app/
cat shared_prefs/credentials.xml
sqlite3 databases/app.db
```

**What's Exposed**:
- Shared preferences (credentials, tokens)
- Databases (user data, cached content)
- Files (documents, images, configs)
- Cache (temporary sensitive data)

## Attack Tools and Techniques

### Configuration Analysis Tools

| Tool | Purpose | Platform |
|------|---------|----------|
| **apktool** | Decode APK resources and manifest | Android |
| **aapt** | Android Asset Packaging Tool | Android |
| **plistutil** | Parse iOS plists | iOS |
| **MobSF** | Automated misconfiguration detection | Both |
| **Drozer** | Android security assessment | Android |

### Network Analysis Tools

| Tool | Purpose | Platform |
|------|---------|----------|
| **Burp Suite** | MITM proxy, TLS testing | Both |
| **mitmproxy** | HTTP/HTTPS interception | Both |
| **Wireshark** | Network packet analysis | Both |
| **Charles Proxy** | SSL proxying | Both |

### Permission Analysis

```bash
# Android: List app permissions
adb shell dumpsys package com.example.app | grep permission

# Check for dangerous permissions
adb shell pm list permissions -d -g

# iOS: Analyze entitlements
codesign -d --entitlements - /path/to/App.app
```

## Real-World Attack Scenarios

### Scenario 1: Debug Information Leakage

```
1. Download app from Play Store
2. Install on rooted device
3. Enable logcat monitoring
4. Use app normally
5. Observe debug logs exposing:
   - API endpoints
   - Authentication tokens
   - User IDs and data
   - Internal server errors
6. Use information to attack backend
```

### Scenario 2: Cleartext Traffic Exploitation

```
1. Set up rogue WiFi access point
2. User connects mobile device
3. App makes HTTP requests (cleartext enabled)
4. Capture authentication credentials
5. Capture API keys and tokens
6. Replay requests to backend
7. Access user account
```

### Scenario 3: Exported Component Abuse

```
1. Analyze AndroidManifest.xml
2. Find exported admin activity
3. Create malicious app
4. Launch exported admin activity
5. Bypass authentication
6. Access administrative functions
7. Modify app data or behavior
```

## Detection and Monitoring

### Indicators of Misconfiguration Exploitation

**Application Level**:
- Unusual activity patterns from debug endpoints
- Excessive permission usage
- Unexpected component activation
- Abnormal network traffic patterns

**Network Level**:
- HTTP traffic from production app
- SSL/TLS errors or warnings
- Certificate pinning failures
- Unusual API endpoint access

**Device Level**:
- Backup access attempts
- ADB connections to production devices
- Exported component access from external apps

## Mitigation Overview

Understanding these attack vectors is crucial for defense:

1. **Disable debug features** in release builds
2. **Enforce HTTPS** and proper TLS configuration
3. **Minimize permissions** to only what's necessary
4. **Secure exported components** with proper permissions
5. **Disable backups** for sensitive data
6. **Implement certificate pinning** for critical connections
7. **Strip debug symbols** from production builds
8. **Regular configuration audits** using automated tools

For detailed prevention strategies, see [Prevention](./prevention.md).

---

**Remember**: Misconfigurations are low-hanging fruit for attackers. Proper configuration is essential.

*Part of OWASP Mobile Top 10 - Educational Repository*
