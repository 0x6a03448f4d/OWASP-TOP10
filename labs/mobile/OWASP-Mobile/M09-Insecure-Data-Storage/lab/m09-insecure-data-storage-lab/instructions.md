# Lab Instructions: M09 - Insecure Data Storage

## Introduction

Welcome to the Insecure Data Storage lab! In this hands-on exercise, you'll discover how mobile applications often store sensitive data in unprotected ways, making it vulnerable to extraction by attackers with physical device access, malware, or through backup files.

**Time Required**: 30-45 minutes  
**Difficulty**: Beginner to Intermediate

## Learning Objectives

By completing this lab, you will:
1. Identify insecure data storage patterns in mobile applications
2. Understand how attackers extract data from devices
3. Learn the difference between encoding and encryption
4. Recognize the risks of logging sensitive information
5. Implement secure data storage solutions

---

## Part 1: Setup and Exploration (5 minutes)

### Task 1.1: Start the Lab

```bash
# Navigate to the lab directory
cd OWASP-Mobile/M09-Insecure-Data-Storage/lab/m09-insecure-data-storage-lab/

# Start the application
docker-compose up
```

### Task 1.2: Access the Application

Open your web browser and navigate to: `http://localhost:5109`

You should see the lab interface with multiple vulnerability demonstrations.

### Task 1.3: Observe Startup Messages

Look at the terminal output when the application starts. Notice:
- The warnings about intentional vulnerabilities
- The list of insecure storage patterns demonstrated
- The simulated mobile app backend running

**Question**: What does this tell you about real mobile apps that have similar patterns?

---

## Part 2: Unencrypted Database Storage (10 minutes)

### Task 2.1: Login with Plain Text Credentials

This simulates how many mobile apps store user credentials.

1. In **Exercise 1**, use the pre-filled credentials:
   - Username: `john_doe`
   - Password: `Password123!`
2. Click **"Login"**
3. Observe the response

**Questions to Answer**:
- What information is returned in the login response?
- Is the authentication token secure?
- Where would this token be stored on a real mobile device?

### Task 2.2: View the Database (Attacker Perspective)

1. Click **"View Database (Attacker View)"**
2. Examine the exported data carefully

**Vulnerability Analysis**:

What you're seeing simulates accessing an unencrypted SQLite database on a mobile device. On a real device, an attacker would:

```bash
# Android (with ADB access or rooted device)
adb shell
su
cd /data/data/com.app.package/databases/
sqlite3 users.db
.dump

# iOS (jailbroken device)
ssh root@device-ip
cd /var/mobile/Containers/Data/Application/{UUID}/Library/Application Support/
sqlite3 app.db
.dump
```

**What's Exposed**:
- Passwords stored in plain text
- Social Security Numbers (SSN)
- Credit card numbers
- CVV codes (should NEVER be stored!)
- API keys
- Personal email and phone numbers

**Critical Findings**:
1. How many users' complete financial information is exposed?
2. What's the PCI-DSS compliance status of this app?
3. What regulatory violations exist (GDPR, CCPA, HIPAA)?

### Task 2.3: Reflection Questions

1. **Impact**: If this were a real banking app with 1 million users, what would be the potential damage?
2. **Attack Scenario**: How quickly could an attacker extract this data from a stolen phone?
3. **Defense**: What should be done instead?

**Answer**: 
- Database should be encrypted with SQLCipher
- Passwords should NEVER be stored (only hashed on server)
- CVV should NEVER be stored (PCI-DSS requirement)
- Use Android KeyStore / iOS Keychain for sensitive data

---

## Part 3: SharedPreferences / UserDefaults Vulnerabilities (10 minutes)

### Task 3.1: Save Sensitive Data in Preferences

Mobile apps often use SharedPreferences (Android) or UserDefaults (iOS) for storing app settings. Many mistakenly store sensitive data here.

1. In **Exercise 2**, observe the pre-filled fields
2. Click **"Save Preferences"**
3. Note the warning about unencrypted storage

**Real-World Files**:

**Android** - SharedPreferences stored as XML:
```
/data/data/com.app.package/shared_prefs/preferences.xml
```

**iOS** - UserDefaults stored as plist:
```
/Library/Preferences/com.app.bundle.plist
```

### Task 3.2: Extract Preferences (Attack Simulation)

1. Click **"Extract Preferences (Attacker)"**
2. Examine the extracted data

**Attack Scenario**:

This simulates an attacker with physical device access:

```bash
# Android - Reading SharedPreferences
adb shell
su
cat /data/data/com.app/shared_prefs/preferences.xml

# iOS - Reading UserDefaults (jailbroken)
ssh root@device
plutil -p /var/mobile/Containers/Data/Application/{UUID}/Library/Preferences/com.app.plist
```

**What's Exposed**:
- Active authentication tokens
- API keys
- Saved payment methods
- Any data marked "Remember Me"

### Task 3.3: Load Preferences

1. Click **"Load Preferences"**
2. Notice how easily the data is retrieved

**Questions**:
1. How long would it take an attacker to extract this data?
2. What if the device is rooted/jailbroken?
3. Are these preferences included in backups?

**Answers**:
- Extraction time: Seconds to minutes
- Rooted/jailbroken devices: All protections bypassed
- Backups: Yes, included in ADB/iTunes backups by default!

### Task 3.4: Secure Alternative

**What should be done instead**:

**Android** - Use EncryptedSharedPreferences:
```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedPrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
```

**iOS** - Use Keychain:
```swift
let token = "auth_token".data(using: .utf8)!
KeychainManager.save(key: "auth_token", data: token)
```

---

## Part 4: Insecure File Storage (8 minutes)

### Task 4.1: Write Sensitive Data to File

1. In **Exercise 3**, observe the pre-filled content with sensitive data
2. Click **"Write File"**
3. Note where the file would be stored

**Real-World Storage Locations**:

**Android**:
```
Internal: /data/data/com.app/files/
External: /sdcard/Android/data/com.app/
```

**iOS**:
```
Documents: /Documents/
Library: /Library/Application Support/
Cache: /Library/Caches/
```

### Task 4.2: Read File

1. Click **"Read File"**
2. Observe how easily the content is accessed

**Attack Techniques**:
- Physical device access
- Malware with storage permissions
- Backup extraction
- SD card removal (Android external storage)

### Task 4.3: Experiment

Try writing different types of sensitive data:
- API keys
- Session tokens
- User credentials
- Private messages
- Location history

**Questions**:
1. Where would these files appear on a real device?
2. Can other apps access them?
3. Are they included in backups?

---

## Part 5: Logging Sensitive Data (7 minutes)

### Task 5.1: View Application Logs

1. In **Exercise 4**, click **"View Application Logs"**
2. Carefully read each log entry

**What You'll Find**:
- Passwords in DEBUG logs
- Authentication tokens in INFO logs
- Credit card numbers in processing logs
- CVV codes in DEBUG logs
- API keys exposed

**Real-World Log Access**:

**Android - Logcat**:
```bash
adb logcat | grep -i "password\|token\|credit\|ssn"
```

**iOS - Console Logs**:
```bash
# Xcode Console or device logs
# Third-party crash reporting tools
```

### Task 5.2: Identify the Risks

**Questions**:
1. What sensitive information is logged?
2. Who can access these logs?
3. Where do logs persist?

**Answers**:
- All credentials, tokens, payment data exposed
- Any app during development, crash reporting services, system logs
- Device storage, cloud crash reporters, analytics platforms

### Task 5.3: Real-World Impact

**Logging Dangers**:
1. **Development Logs**: Often forgotten and shipped to production
2. **Crash Reporters**: Sensitive data sent to third-party services
3. **Analytics**: User data logged for tracking
4. **System Logs**: Android Logcat readable by all apps (pre-Android 4.1)

**Secure Practice**:
```kotlin
// ❌ NEVER do this
Log.d("Auth", "Password: $password")

// ✅ Do this instead
Log.d("Auth", "Login attempt for user ID: ${user.id}")
// NO sensitive data in logs!
```

---

## Part 6: Backup Vulnerabilities (5 minutes)

### Task 6.1: Create Backup

1. In **Exercise 5**, click **"Create Backup"**
2. Read what's included in the backup

**Real-World Backup Extraction**:

**Android - ADB Backup**:
```bash
# Create backup
adb backup -f app.ab com.example.app

# Convert to readable format
java -jar abe.jar unpack app.ab app.tar
tar -xvf app.tar

# All app data is now accessible!
```

**iOS - iTunes/iCloud Backup**:
```bash
# Backups location
~/Library/Application Support/MobileSync/Backup/

# Extract with tools
iBackup Viewer, iMazing, etc.

# Or manually parse
sqlite3 Manifest.db
```

### Task 6.2: Understand the Risk

**What's in Backups**:
- All SharedPreferences/UserDefaults
- All database files
- All internal files
- App cache
- Screenshots (iOS)

**Attack Scenarios**:
1. **Stolen Computer**: Backups on computer accessible
2. **Cloud Account Compromise**: iCloud/Google backup accessible
3. **Forensic Analysis**: Backup extraction tools widely available
4. **Insider Threat**: Family members with device/computer access

### Task 6.3: Prevention

**Android** - Exclude from backups:
```xml
<application
    android:allowBackup="false"
    android:fullBackupContent="@xml/backup_rules">
</application>
```

**iOS** - Exclude files:
```swift
var resourceValues = URLResourceValues()
resourceValues.isExcludedFromBackup = true
try fileURL.setResourceValues(resourceValues)
```

---

## Part 7: False Security - Encoding vs Encryption (8 minutes)

### Task 7.1: Base64 Encoding Test

Many developers mistakenly think Base64 is encryption!

1. In **Exercise 6**, the field has `MySecretPassword123`
2. Click **"Encode with Base64"**
3. Copy the encoded string
4. Decode it manually

**Decode Test**:
```bash
# Copy the encoded string from the output
echo "TXlTZWNyZXRQYXNzd29yZDEyMw==" | base64 -d

# Result: MySecretPassword123
```

**Reality Check**: Base64 is encoding, NOT encryption!
- Trivially reversible
- No key required
- Provides ZERO security
- Common misconception in mobile apps

### Task 7.2: Weak XOR Encryption

1. Click **"Try XOR Encryption"**
2. Observe the result

**XOR Weakness**:
```
Text XOR Key = Encrypted
Encrypted XOR Key = Text (decrypted!)
```

If the key is known or static, XOR provides no security.

### Task 7.3: Common "Encryption" Mistakes

**❌ NOT Encryption**:
- Base64 encoding
- XOR with static key
- ROT13
- Simple character substitution
- Reversible obfuscation

**✅ Real Encryption**:
- AES-256-GCM
- ChaCha20-Poly1305
- RSA (for key exchange)
- With proper key management!

---

## Part 8: Summary and Remediation (5 minutes)

### Task 8.1: View Vulnerability Summary

1. In the last section, click **"Show All Vulnerabilities"**
2. Review the complete list
3. Read the recommendations

### Task 8.2: Create Your Security Checklist

Based on what you've learned, create a checklist for your mobile apps:

**Data Storage Security Checklist**:

- [ ] Database encrypted with SQLCipher or equivalent
- [ ] Using EncryptedSharedPreferences (Android) or Keychain (iOS)
- [ ] No passwords stored locally (only server-side hashes)
- [ ] No PII stored unnecessarily
- [ ] Credit card data follows PCI-DSS (no CVV storage!)
- [ ] Files encrypted with platform APIs
- [ ] Sensitive data excluded from backups
- [ ] No sensitive data in application logs
- [ ] Authentication tokens have expiration
- [ ] Root/jailbreak detection implemented
- [ ] Regular security audits performed
- [ ] Penetration testing completed

### Task 8.3: Remediation Plan

For each vulnerability, know the fix:

| Vulnerability | Solution |
|--------------|----------|
| Unencrypted database | SQLCipher with key in KeyStore/Keychain |
| Plain text preferences | EncryptedSharedPreferences / Keychain |
| Insecure files | EncryptedFile API / Data Protection |
| Logged sensitive data | Remove all sensitive logging |
| Unencrypted backups | Exclude sensitive data programmatically |
| Base64 "encryption" | Use AES-256-GCM with proper key management |

---

## Part 9: Advanced Challenge (Optional)

### Challenge 1: Full Attack Simulation

Simulate a complete attack chain:
1. Login to get auth token
2. Extract token from preferences
3. Use token to access user data
4. Create backup with all data
5. Extract sensitive information

### Challenge 2: Secure Implementation

Design a secure storage architecture:
1. What data absolutely must be stored locally?
2. How would you encrypt each type?
3. Where would encryption keys be stored?
4. How would you handle key rotation?
5. How would you clear data on logout?

### Challenge 3: Compliance Check

Review the exposed data against regulations:
1. **GDPR**: What violations exist?
2. **PCI-DSS**: Payment data compliance issues?
3. **HIPAA**: If this were health data, what's the impact?
4. **CCPA**: California privacy law compliance?

---

## Key Takeaways

### Critical Lessons

1. **Assume Device Compromise**: Design storage assuming the device will be compromised
2. **Encrypt Everything Sensitive**: Use platform-provided encryption APIs
3. **Minimize Storage**: Don't store what you don't absolutely need
4. **Never Log Sensitive Data**: Logs are dangerous and often overlooked
5. **Exclude from Backups**: Sensitive data shouldn't be in backups
6. **Encoding ≠ Encryption**: Base64, XOR, obfuscation are NOT security
7. **Use Platform Security**: KeyStore/Keychain are designed for this
8. **Regular Audits**: Security testing should be continuous

### Common Mistakes to Avoid

❌ Storing passwords locally  
❌ Using SharedPreferences/UserDefaults for sensitive data  
❌ Unencrypted databases  
❌ Logging credentials or tokens  
❌ Including sensitive data in backups  
❌ Thinking Base64 is encryption  
❌ Storing credit card CVV (NEVER!)  
❌ Assuming rooted/jailbroken devices are rare  

### Best Practices

✅ Use EncryptedSharedPreferences (Android) or Keychain (iOS)  
✅ Encrypt databases with SQLCipher  
✅ Implement data expiration  
✅ Clear sensitive data on logout  
✅ Exclude sensitive files from backups  
✅ Use proper encryption (AES-256)  
✅ Store encryption keys in KeyStore/Keychain  
✅ Implement root/jailbreak detection  

---

## Additional Resources

### Recommended Reading
- [OWASP Mobile Security Testing Guide - Data Storage](https://mobile-security.gitbook.io/mobile-security-testing-guide/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [iOS Security Guide](https://support.apple.com/guide/security/welcome/web)
- [PCI-DSS Mobile Payment Guidance](https://www.pcisecuritystandards.org/)

### Tools for Testing
- **Android**: ADB, SQLite Browser, jadx, Frida
- **iOS**: iMazing, iBackup Viewer, Hopper, Frida
- **Cross-platform**: MobSF, Objection, Drozer

### Next Steps
1. Review the [Prevention Guide](../../prevention.md)
2. Study the [Secure Examples](../../examples.md)
3. Practice on your own apps
4. Implement security testing in CI/CD

---

## Cleanup

When you're done with the lab:

```bash
# Stop the application
docker-compose down

# Remove created files (optional)
rm -f users.db preferences.json backup_*.json cache_*.json
```

---

**Congratulations!** You've completed the Insecure Data Storage lab. You now understand how mobile apps store data insecurely and how to fix these critical vulnerabilities.

*Part of OWASP Mobile Top 10 - Educational Repository*
