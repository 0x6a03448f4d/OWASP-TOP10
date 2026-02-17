# M01: Improper Credential Usage - Attack Vectors

## Table of Contents
- [Attack Methodology Overview](#attack-methodology-overview)
- [Static Analysis Attacks](#static-analysis-attacks)
- [Dynamic Analysis Attacks](#dynamic-analysis-attacks)
- [Storage Exploitation](#storage-exploitation)
- [Network-Based Attacks](#network-based-attacks)
- [Attack Tools and Techniques](#attack-tools-and-techniques)

## Attack Methodology Overview

Attackers targeting mobile application credentials typically follow a systematic approach:

```
1. Reconnaissance
   ↓
2. Binary Acquisition (Download APK/IPA)
   ↓
3. Static Analysis (Decompile, search for secrets)
   ↓
4. Dynamic Analysis (Runtime inspection)
   ↓
5. Storage Analysis (Local file examination)
   ↓
6. Network Analysis (Traffic interception)
   ↓
7. Exploitation (Use discovered credentials)
```

### Attack Timeline

- **Initial Access**: Minutes (download app from store)
- **Decompilation**: Seconds to minutes
- **Credential Discovery**: Minutes to hours
- **Exploitation**: Immediate to days (depending on target)

## Static Analysis Attacks

### Attack Vector 1: Binary Decompilation

**Technique**: Reverse engineering the mobile application binary to extract source code.

**Android APK Process**:
```
1. Download APK from Google Play or third-party source
2. Extract APK (it's just a ZIP file)
3. Use dex2jar to convert DEX to JAR
4. Use JD-GUI or similar to decompile Java bytecode
5. Search for strings, API keys, passwords
```

**iOS IPA Process**:
```
1. Download IPA from App Store (with tools)
2. Extract IPA contents
3. Use class-dump or Hopper to analyze binary
4. Extract embedded resources and plist files
5. Search for hardcoded secrets
```

**What Attackers Look For**:
- API keys in string constants
- Base64 encoded credentials
- Hardcoded passwords
- Database connection strings
- OAuth client secrets
- Encryption keys

**Example Discovery Pattern**:
```java
// Attacker searches decompiled code for patterns like:
private static final String API_KEY = "AIzaSy...";
private static final String SECRET = "sk_live_...";
String password = "admin123";
```

### Attack Vector 2: String Analysis

**Technique**: Extracting all strings from the compiled binary without full decompilation.

**Simple String Extraction**:
```bash
# Android
strings app.apk | grep -i "key\|secret\|password\|token\|api"

# iOS
strings MyApp.app/MyApp | grep -i "key\|secret\|password\|token\|api"
```

**What's Found**:
- Cleartext credentials
- API endpoints with embedded tokens
- Database URLs with credentials
- Service account information

### Attack Vector 3: Resource File Analysis

**Technique**: Examining configuration and resource files embedded in the app.

**Target Files**:

**Android**:
- `res/values/strings.xml` - Often contains API keys
- `assets/config.json` - Configuration with credentials
- `AndroidManifest.xml` - May contain metadata with secrets
- `res/raw/*` - Resource files with embedded data

**iOS**:
- `Info.plist` - Configuration including API keys
- `Assets.car` - Compiled asset catalog
- `*.bundle` - Resource bundles
- Configuration JSON/XML files

**Example Vulnerable Resource**:
```xml
<!-- strings.xml -->
<resources>
    <string name="api_key">AIzaSyDxVW...</string>
    <string name="db_password">MySecretPass123</string>
</resources>
```

### Attack Vector 4: Version Control Leakage

**Technique**: Finding credentials in version control history or development artifacts.

**Common Mistakes**:
- Git repositories accidentally included in release builds
- `.git` folder in Android assets
- Development configurations not removed
- Test credentials left in code

## Dynamic Analysis Attacks

### Attack Vector 5: Runtime Memory Inspection

**Technique**: Examining application memory during execution to find credentials.

**Tools Used**:
- Frida (Dynamic instrumentation)
- Objection (Mobile security testing)
- Xposed Framework (Android runtime hooking)
- Cycript (iOS runtime inspection)

**What's Captured**:
- Credentials loaded into memory
- Decrypted tokens during use
- Session tokens in active use
- API keys accessed at runtime

**Conceptual Attack Flow**:
```
1. Install app on rooted/jailbroken device
2. Attach Frida to running process
3. Hook authentication functions
4. Capture credentials when app uses them
5. Log all sensitive data to file
```

### Attack Vector 6: Log File Analysis

**Technique**: Examining application and system logs for leaked credentials.

**Log Sources**:

**Android**:
- Logcat output (`adb logcat`)
- Application-specific log files
- Crash reports

**iOS**:
- Console logs
- OSLog entries
- Crash logs

**Common Logging Mistakes**:
```java
// Developers accidentally log credentials
Log.d("Auth", "API Key: " + apiKey);
Log.d("Login", "Password: " + password);
System.out.println("Token: " + authToken);
```

**Attacker Technique**:
```bash
# Monitor logs for sensitive data
adb logcat | grep -i "password\|token\|key\|secret"
```

## Storage Exploitation

### Attack Vector 7: Insecure Local Storage

**Technique**: Accessing credentials stored in application data directories.

**Android Storage Locations**:
```
/data/data/[package-name]/shared_prefs/     # SharedPreferences (XML)
/data/data/[package-name]/databases/        # SQLite databases
/data/data/[package-name]/files/            # Internal storage files
/sdcard/Android/data/[package-name]/        # External storage
```

**iOS Storage Locations**:
```
/var/mobile/Containers/Data/Application/[UUID]/Library/Preferences/
/var/mobile/Containers/Data/Application/[UUID]/Documents/
/var/mobile/Containers/Data/Application/[UUID]/Library/Caches/
```

**Example Vulnerable Storage**:
```xml
<!-- Shared Preferences storing credentials in plain text -->
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="username">john@example.com</string>
    <string name="password">MyPassword123</string>
    <string name="api_token">eyJhbGciOiJIUzI1...</string>
</map>
```

### Attack Vector 8: Device Backup Exploitation

**Technique**: Extracting credentials from device backups.

**Android Backup**:
```bash
# Create backup
adb backup -f backup.ab com.example.app

# Extract backup
java -jar abe.jar unpack backup.ab backup.tar

# Extract tar and search for credentials
tar -xf backup.tar
grep -r "password\|key\|token" apps/
```

**iOS Backup**:
- iCloud backups can be downloaded
- iTunes backups stored locally
- Backups may be unencrypted
- Can be parsed with tools like iBackup Viewer

**What's Found**:
- Entire app data directory
- Shared preferences/UserDefaults
- SQLite databases
- Files with cached credentials

### Attack Vector 9: Rooted/Jailbroken Device Access

**Technique**: Using elevated privileges to access protected storage.

**Android (Rooted)**:
```bash
# Access app data directly
adb shell
su
cd /data/data/com.example.app
cat shared_prefs/credentials.xml
sqlite3 databases/app.db "SELECT * FROM users;"
```

**iOS (Jailbroken)**:
```bash
# SSH into device
ssh root@device-ip
cd /var/mobile/Containers/Data/Application/
# Search through app directories
grep -r "password" .
```

## Network-Based Attacks

### Attack Vector 10: Man-in-the-Middle (MITM)

**Technique**: Intercepting network traffic to capture credentials in transit.

**Setup Process**:
```
1. Configure proxy (Burp Suite, Charles, mitmproxy)
2. Install proxy certificate on device
3. Route device traffic through proxy
4. Capture HTTP/HTTPS traffic
5. Search for credentials in requests
```

**What's Captured**:
- Authentication headers with tokens
- API keys in URL parameters
- Credentials in POST bodies
- OAuth tokens during flow

**Example Vulnerable Request**:
```http
POST /api/login HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
    "username": "user@example.com",
    "password": "PlainTextPassword123",
    "api_key": "hardcoded_key_12345"
}
```

### Attack Vector 11: DNS Spoofing for Credential Theft

**Technique**: Redirecting API calls to attacker-controlled servers.

**Process**:
```
1. Control network (rogue WiFi, compromised router)
2. Spoof DNS for API endpoints
3. Redirect traffic to fake server
4. Capture credentials sent to fake API
5. Forward to real API (or not)
```

## Attack Tools and Techniques

### Reconnaissance Tools

| Tool | Purpose | Platform |
|------|---------|----------|
| **apktool** | Decode Android APK resources | Android |
| **dex2jar** | Convert DEX to JAR | Android |
| **JD-GUI** | Java decompiler | Android |
| **Jadx** | Android decompiler | Android |
| **class-dump** | Objective-C header extraction | iOS |
| **Hopper** | Binary disassembler | iOS |
| **strings** | Extract printable strings | Both |

### Dynamic Analysis Tools

| Tool | Purpose | Platform |
|------|---------|----------|
| **Frida** | Dynamic instrumentation | Both |
| **Objection** | Mobile security toolkit | Both |
| **Xposed** | Runtime hooking framework | Android |
| **Cycript** | Runtime inspection | iOS |
| **Mobile Security Framework (MobSF)** | Automated analysis | Both |

### Network Analysis Tools

| Tool | Purpose | Platform |
|------|---------|----------|
| **Burp Suite** | HTTP proxy and testing | Both |
| **Charles Proxy** | HTTP/HTTPS debugging | Both |
| **mitmproxy** | Interactive MITM proxy | Both |
| **Wireshark** | Network protocol analyzer | Both |

## Attack Prevention Awareness

### Early Detection Indicators

**Signs an app may be under attack**:
- Unusual API traffic patterns
- Requests from unexpected geolocations
- Multiple failed authentication attempts
- Token reuse across devices
- Abnormal endpoint access patterns

### Attacker Skill Levels

**Script Kiddie** (Low Skill):
- Uses automated tools (MobSF)
- Searches for obvious hardcoded secrets
- Limited bypass capabilities

**Intermediate Attacker**:
- Decompiles and analyzes code
- Uses Frida for dynamic analysis
- Can bypass basic protections

**Advanced Attacker**:
- Full reverse engineering capability
- Custom tool development
- Bypasses obfuscation and integrity checks
- Sophisticated exploitation techniques

## Real-World Attack Scenarios

### Scenario 1: API Key Harvesting

```
1. Attacker downloads popular shopping app
2. Decompiles APK using JADX
3. Finds hardcoded API key in Constants.java
4. Uses key to scrape product database
5. Sells data to competitors
```

### Scenario 2: Account Takeover

```
1. User installs app on rooted Android device
2. Malware on device scans app storage
3. Finds plaintext credentials in SharedPreferences
4. Malware sends credentials to C2 server
5. Attacker accesses user account
```

### Scenario 3: Mass Credential Theft

```
1. Researcher finds OAuth client secret in app
2. Uses secret to implement fake OAuth client
3. Harvests access tokens from phishing campaign
4. Accesses thousands of user accounts
5. Public disclosure after responsible disclosure period
```

## Mitigation Overview

Understanding these attack vectors is the first step to defense:

1. **Eliminate hardcoded credentials** entirely
2. **Use platform keychains** for credential storage
3. **Implement certificate pinning** for network security
4. **Enable proper logging** controls (no sensitive data)
5. **Use runtime protection** against dynamic analysis
6. **Implement integrity checks** to detect tampering
7. **Monitor for abnormal usage** patterns

For detailed prevention strategies, see [Prevention](./prevention.md).

---

**Remember**: Attackers only need to find one vulnerability. Defenders must protect against all attack vectors.

*Part of OWASP Mobile Top 10 - Educational Repository*
