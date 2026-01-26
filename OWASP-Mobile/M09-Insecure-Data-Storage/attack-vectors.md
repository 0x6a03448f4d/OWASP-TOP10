# M09: Insecure Data Storage - Attack Vectors

## Table of Contents
- [Attack Methodology Overview](#attack-methodology-overview)
- [Physical Access Attacks](#physical-access-attacks)
- [Backup Extraction Attacks](#backup-extraction-attacks)
- [Rooted/Jailbroken Device Attacks](#rooted-jailbroken-device-attacks)
- [Malware-Based Attacks](#malware-based-attacks)
- [Forensic Analysis Attacks](#forensic-analysis-attacks)
- [Attack Tools and Techniques](#attack-tools-and-techniques)

## Attack Methodology Overview

Attackers targeting insecure data storage typically follow this approach:

```
1. Access Acquisition (Device, Backup, or Malware)
   ↓
2. Storage Location Enumeration (Find data storage paths)
   ↓
3. Data Extraction (Copy files, databases, preferences)
   ↓
4. Data Analysis (Parse and identify sensitive information)
   ↓
5. Exploitation (Use extracted data for further attacks)
```

### Attack Timeline

- **Physical Access**: Seconds to minutes for unlocked device
- **Backup Extraction**: Minutes to hours
- **Data Analysis**: Minutes to hours depending on volume
- **Exploitation**: Immediate to days depending on data type

### Attacker Profiles

| Attacker Type | Capability | Motivation | Typical Targets |
|--------------|-----------|-----------|-----------------|
| Opportunist Thief | Basic | Financial gain | Banking, payment apps |
| Stalker/Domestic Abuser | Basic to Moderate | Personal information | Messaging, location apps |
| Corporate Spy | Advanced | Trade secrets | Business, email apps |
| Law Enforcement | Advanced | Evidence gathering | All apps |
| Cybercriminal | Advanced | Identity theft, fraud | Financial, social apps |
| State Actor | Expert | Intelligence, surveillance | All sensitive apps |

## Physical Access Attacks

### Attack Vector 1: Unlocked Device Access

**Technique**: Direct access to an unlocked or poorly secured device.

**Attack Process**:
```
1. Obtain physical device (theft, borrowing, shoulder surfing PIN)
2. Access device if unlocked or bypass weak lock screen
3. Navigate to app's storage location
4. Use file manager or development tools
5. Extract sensitive data
```

**Android Example**:
```bash
# Attacker uses ADB on unlocked device with USB debugging
adb shell

# Navigate to app's data directory
cd /data/data/com.example.app/

# List all files and directories
ls -R

# Common vulnerable locations:
# SharedPreferences: /data/data/com.example.app/shared_prefs/
# Databases: /data/data/com.example.app/databases/
# Files: /data/data/com.example.app/files/
# Cache: /data/data/com.example.app/cache/

# Extract database
cat databases/userdata.db

# Read SharedPreferences
cat shared_prefs/user_settings.xml
```

**iOS Example**:
```bash
# Using a jailbroken device or debugging tools
# Navigate to app container
cd /var/mobile/Containers/Data/Application/{UUID}/

# List files
ls -la

# Common vulnerable locations:
# UserDefaults: Library/Preferences/
# Documents: Documents/
# Databases: Library/Application Support/
# Cache: Library/Caches/

# Read plist files (UserDefaults)
plutil -p Library/Preferences/com.example.app.plist
```

**What Attackers Find**:
- User credentials stored in plain text
- Authentication tokens and session IDs
- Personal information (names, emails, addresses)
- Private messages and communications
- Financial data (account numbers, transactions)
- Location history
- App-specific sensitive data

### Attack Vector 2: Lost or Stolen Device

**Technique**: Exploiting devices that are lost, stolen, or temporarily unattended.

**Attack Scenarios**:

**Scenario 1: Weak Lock Screen**:
```
Device stolen → Weak PIN (1234, 0000) → Device unlocked
    ↓
Install file manager app → Browse app data directories
    ↓
Extract unencrypted databases and files → Data compromised
```

**Scenario 2: Disabled Lock Screen**:
```
User disabled lock for convenience → Device stolen → Immediate access
    ↓
Use built-in file explorer → Access app data → Sensitive data exposed
```

**Real-World Example**:
A healthcare app stored patient records in plain text SQLite database:
```sql
-- File: /data/data/com.health.app/databases/patients.db
-- Accessible via simple file read

SELECT * FROM patients;
-- Returns:
-- patient_id | name | dob | ssn | diagnosis | medications
-- 12345 | John Doe | 1980-05-15 | 123-45-6789 | Hypertension | Lisinopril
```

### Attack Vector 3: Borrowed Device Exploitation

**Technique**: Temporary access to someone else's device.

**Attack Process**:
```
1. Borrow device legitimately ("Can I make a call?")
2. Quickly enable USB debugging or install file manager
3. Navigate to target app's data directory
4. Copy sensitive files to cloud storage or email
5. Delete evidence of access
6. Return device
```

**Time Required**: 2-5 minutes for skilled attacker

## Backup Extraction Attacks

### Attack Vector 4: Android ADB Backup

**Technique**: Extracting app data through Android Debug Bridge backup functionality.

**Prerequisites**:
- Physical device access (even briefly)
- USB debugging enabled OR ability to enable it

**Attack Process**:
```bash
# 1. Enable USB debugging if not already enabled
# Settings → About Phone → Tap Build Number 7 times
# Settings → Developer Options → Enable USB Debugging

# 2. Connect device to computer
adb devices

# 3. Create backup of specific app
adb backup -f backup.ab -noapk com.example.app

# Device shows backup confirmation (user may approve without reading)

# 4. Convert backup to tar format
# Using Android Backup Extractor (ABE)
java -jar abe.jar unpack backup.ab backup.tar

# 5. Extract tar file
tar -xvf backup.tar

# 6. Navigate to app data
cd apps/com.example.app/
```

**Example Extracted Data**:
```
apps/com.example.app/
├── db/
│   ├── messages.db          # Unencrypted SQLite database
│   └── userdata.db          # Contains user profile data
├── sp/
│   └── preferences.xml      # SharedPreferences with tokens
└── f/
    ├── profile_picture.jpg
    └── sensitive_document.pdf
```

**Vulnerable Data Found**:
```xml
<!-- preferences.xml -->
<map>
    <string name="auth_token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</string>
    <string name="user_email">victim@example.com</string>
    <string name="api_key">sk_live_51H7h8dK2eZvN9vZpQ</string>
    <boolean name="remember_me">true</boolean>
</map>
```

### Attack Vector 5: iOS iTunes Backup

**Technique**: Extracting app data from iTunes/Finder backups.

**Prerequisites**:
- Physical device access to create backup
- OR access to computer with existing backups

**Attack Process**:
```bash
# 1. Create unencrypted backup
# Connect iPhone to Mac/PC
# iTunes/Finder → Backup → Uncheck "Encrypt Backup" → Backup Now

# 2. Locate backup on computer
# Mac: ~/Library/Application Support/MobileSync/Backup/
# Windows: %APPDATA%\Apple Computer\MobileSync\Backup\

# 3. Use iBackup Viewer or similar tool to extract app data
# Or manually parse backup files

# 4. Find app's data in backup
# Apps are stored with hash-based filenames
# Use Manifest.db to map files to apps
sqlite3 Manifest.db

SELECT fileID, relativePath FROM Files 
WHERE relativePath LIKE '%com.example.app%';

# 5. Extract specific files
# Copy files using fileID from Manifest
```

**Example SQL Query on Backup**:
```sql
-- Directly query app's database from backup
sqlite3 {fileID_hash}

SELECT * FROM users;
-- name | email | phone | credit_card | cvv
-- John Doe | john@email.com | +1234567890 | 4532-****-****-1234 | 123
```

### Attack Vector 6: iCloud Backup Exploitation

**Technique**: Accessing app data through iCloud backups.

**Attack Scenarios**:

**Scenario 1: Compromised iCloud Account**:
```
Phish iCloud credentials → Access iCloud.com
    ↓
Download device backup → Extract using iBackup tools
    ↓
Access app data including sensitive information
```

**Scenario 2: Shared Family Account**:
```
Family member with iCloud access → Download backups
    ↓
Extract other family members' app data → Privacy violation
```

## Rooted/Jailbroken Device Attacks

### Attack Vector 7: Rooted Android Device Exploitation

**Technique**: Using root access to bypass Android's app sandboxing.

**Attack Process**:
```bash
# 1. Root device (Magisk, SuperSU, etc.)
# Many guides available online for popular devices

# 2. Install root file explorer (e.g., Root Explorer)
# Available on Play Store or third-party sources

# 3. Grant root permissions to file explorer
su

# 4. Navigate to any app's data directory
cd /data/data/

# 5. List all installed apps
ls

# 6. Access target app
cd com.banking.app/

# 7. Read all files with root privileges
cat shared_prefs/account_prefs.xml
sqlite3 databases/transactions.db
.dump

# 8. Copy sensitive data
cp -r /data/data/com.banking.app/ /sdcard/stolen_data/
```

**Example Exploitation**:
```bash
# Banking app with unencrypted database
cd /data/data/com.bank.app/databases/

sqlite3 accounts.db
SELECT * FROM transactions ORDER BY date DESC LIMIT 10;

# Output reveals:
# - Account numbers
# - Transaction amounts
# - Merchant names
# - Timestamps
# - Balance information
```

**Root Detection Bypass**:
```
App implements root detection → Attacker uses Magisk Hide
    ↓
Root hidden from app → App runs normally
    ↓
Attacker uses root file explorer → Data extracted anyway
```

### Attack Vector 8: Jailbroken iOS Exploitation

**Technique**: Jailbreaking iOS to access app data outside sandbox.

**Attack Process**:
```bash
# 1. Jailbreak device (checkra1n, unc0ver, etc.)

# 2. Install SSH server (Cydia)
# Install OpenSSH from Cydia

# 3. SSH into device
ssh root@192.168.1.100
# Default password: alpine (often unchanged)

# 4. Navigate to app containers
cd /var/mobile/Containers/Data/Application/

# 5. Find target app (use grep or app UUID)
find . -name "*.app" | grep -i "targetapp"

# 6. Access app's data
cd {UUID}/Library/Preferences/
cat com.example.app.plist

# 7. Read database files
cd ../Application\ Support/
sqlite3 messages.db
```

**Keychain Access on Jailbroken Device**:
```bash
# Even Keychain can be accessed on jailbroken iOS
# Using keychain dumper tools

# Download and run keychain_dumper
./keychain_dumper

# Output includes:
# - Saved passwords
# - Authentication tokens
# - Certificate private keys
# - Secure notes
```

## Malware-Based Attacks

### Attack Vector 9: Malicious App Data Theft

**Technique**: Installing malware that exploits Android permissions to access data.

**Attack Flow**:
```
User installs malicious app → Requests storage permissions
    ↓
Granted permissions → Scans external storage
    ↓
Finds app data on SD card → Exfiltrates to attacker server
```

**Example Android Malware**:
```java
// Malicious app code
public class DataThief extends Service {
    @Override
    public void onCreate() {
        // Search external storage for app databases
        File externalStorage = Environment.getExternalStorageDirectory();
        searchForDatabases(externalStorage);
    }
    
    private void searchForDatabases(File dir) {
        File[] files = dir.listFiles();
        for (File file : files) {
            if (file.getName().endsWith(".db") || 
                file.getName().endsWith(".xml")) {
                // Exfiltrate file to attacker server
                exfiltrateData(file);
            }
        }
    }
}
```

### Attack Vector 10: Privilege Escalation via Exploits

**Technique**: Using OS vulnerabilities to gain root access and bypass sandboxing.

**Attack Scenarios**:
```
Unpatched device with known exploit → Malware exploits vulnerability
    ↓
Gains root privileges → Accesses all app data
    ↓
Exfiltrates data without user knowledge
```

## Forensic Analysis Attacks

### Attack Vector 11: Mobile Forensic Tools

**Technique**: Using professional forensic software to extract data.

**Common Forensic Tools**:
- **Cellebrite UFED**: Industry-standard forensic tool
- **Oxygen Forensics**: Mobile forensic software
- **Magnet AXIOM**: Digital forensics platform
- **XRY**: Mobile forensic tool
- **Autopsy**: Open-source forensic tool

**Forensic Extraction Process**:
```
1. Connect device to forensic workstation
2. Create forensic image of device storage
3. Parse file systems and databases
4. Extract and decrypt (if possible) data
5. Generate comprehensive report
```

**What Can Be Recovered**:
- All unencrypted databases and files
- Deleted data (if not securely wiped)
- Cache files
- Temporary files
- Log files
- Screenshot captures

**Example Forensic Report Finding**:
```
App: Banking Application v2.3.1
Location: /data/data/com.bank.app/

Findings:
- SQLite database "accounts.db" contains:
  * 15 account numbers (UNENCRYPTED)
  * 247 transaction records (UNENCRYPTED)
  * 3 saved beneficiaries with account details
  
- SharedPreferences "session.xml" contains:
  * Valid authentication token (expires in 30 days)
  * User email and phone number
  * Last login timestamp
  
- File "pin.txt" contains:
  * 4-digit PIN in plain text

Risk Level: CRITICAL
```

### Attack Vector 12: Memory Forensics

**Technique**: Extracting sensitive data from device memory/RAM.

**Attack Process**:
```
1. Capture memory dump from running device
2. Use memory forensic tools (Volatility, etc.)
3. Search for sensitive data patterns
4. Extract keys, passwords, tokens from memory
```

**Example Memory Extraction**:
```bash
# Capture memory dump
adb shell su -c "dd if=/dev/mem of=/sdcard/memory.dump"

# Pull to computer
adb pull /sdcard/memory.dump

# Search for patterns
strings memory.dump | grep -E "token|password|key"

# Find:
# "auth_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
# "password":"MySecretPass123"
# "encryption_key":"AES256_KEY_HERE"
```

## Attack Tools and Techniques

### Essential Tools for Attackers

**Android Tools**:
```
1. ADB (Android Debug Bridge) - Official Google tool
   - Device access and backup creation
   
2. Android Backup Extractor (ABE) - Open source
   - Convert .ab backups to readable format
   
3. SQLite Browser - Open source
   - View and query SQLite databases
   
4. Root Explorer - File manager for rooted devices
   - Full filesystem access
   
5. Frida - Dynamic instrumentation
   - Runtime app manipulation
   
6. jadx - Decompiler
   - Reverse engineer APKs
```

**iOS Tools**:
```
1. iBackup Viewer/Extractor - Commercial/Free
   - Extract data from iTunes backups
   
2. checkra1n/unc0ver - Jailbreak tools
   - Remove iOS restrictions
   
3. Filza - File manager for jailbroken iOS
   - Access app containers
   
4. SSH/Cydia - Remote access tools
   - Command-line device access
   
5. keychain_dumper - Keychain extraction
   - Extract keychain items
```

**Cross-Platform Tools**:
```
1. Cellebrite UFED - Commercial forensic tool
   - Professional data extraction
   
2. DB Browser for SQLite - Open source
   - Database analysis
   
3. Wireshark - Network analyzer
   - Monitor data transmission
   
4. Burp Suite - Web proxy
   - Intercept API communications
```

### Attack Techniques Summary

| Technique | Complexity | Equipment | Time | Success Rate |
|-----------|-----------|-----------|------|--------------|
| Unlocked device access | Low | None | Seconds | 95% |
| ADB backup | Low | Computer + USB | Minutes | 85% |
| iTunes backup | Low | Computer | Minutes | 90% |
| Root/Jailbreak | Medium | Computer | Hours | 70% |
| Forensic tools | High | Specialized equipment | Hours | 95% |
| Malware | Medium | Remote access | Varies | 60% |
| Memory forensics | High | Root access + tools | Hours | 50% |

### Detection and Evasion

**How Attackers Avoid Detection**:
```
1. Use legitimate-looking backup tools
2. Access data during normal use (borrowed device)
3. Hide root access with Magisk Hide
4. Clear forensic evidence after extraction
5. Use cloud services for exfiltration (looks like normal traffic)
6. Operate on user's own device (no device changes visible)
```

**Common Attacker Mistakes**:
```
1. Leaving USB debugging enabled (traces)
2. Forgetting to delete backup files
3. Setting improper file permissions after root access
4. Triggering anti-forensic alerts
5. Network anomalies during data exfiltration
```

### Real-World Attack Scenario

**Complete Attack Example: Banking App Data Theft**

```
Phase 1: Opportunity
- Victim leaves phone on restaurant table
- Attacker borrows phone ("Is this yours? Let me help you find the owner")

Phase 2: Rapid Extraction (< 3 minutes)
1. Enable USB debugging while appearing to "help"
2. Connect to attacker's hidden device (laptop in bag)
3. Run: adb backup -f bank.ab com.bank.app
4. Victim approves backup (thinks it's a system notification)
5. Backup saved, device returned

Phase 3: Data Extraction (later)
1. Convert backup: java -jar abe.jar unpack bank.ab bank.tar
2. Extract: tar -xvf bank.tar
3. Open database: sqlite3 apps/com.bank.app/db/accounts.db
4. Query: SELECT * FROM accounts;

Phase 4: Exploitation
- Account numbers, balances revealed
- Authentication tokens extracted
- Use tokens to access account via API
- Transfer funds or sell credentials
```

## Defense Awareness

Understanding these attack vectors helps developers implement proper defenses:

1. **Encrypt all sensitive data** at rest
2. **Use platform secure storage** (Keychain/KeyStore)
3. **Exclude sensitive data from backups**
4. **Implement root/jailbreak detection**
5. **Clear sensitive data from memory**
6. **Use Data Protection API** (iOS)
7. **Implement EncryptedSharedPreferences** (Android)
8. **Encrypt databases** with SQLCipher
9. **Minimize data storage** - don't store what you don't need
10. **Implement data expiration** - clear old sensitive data

---

**Next Steps**: Learn how to protect against these attacks in [Prevention](./prevention.md)

*Part of OWASP Mobile Top 10 - Educational Repository*
