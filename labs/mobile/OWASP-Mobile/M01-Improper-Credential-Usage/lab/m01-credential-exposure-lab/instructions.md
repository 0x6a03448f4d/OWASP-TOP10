# Lab Instructions: M01 - Improper Credential Usage

## Introduction

Welcome to the Improper Credential Usage lab! In this hands-on exercise, you'll discover how mobile applications can expose credentials through various insecure practices.

**Time Required**: 30-45 minutes  
**Difficulty**: Beginner

## Learning Objectives

By completing this lab, you will:
1. Identify hardcoded credentials in application code
2. Understand the risks of insecure credential storage
3. Learn how logs can leak sensitive information
4. Implement secure credential management practices

---

## Part 1: Setup and Exploration (5 minutes)

### Task 1.1: Start the Lab

```bash
# Navigate to the lab directory
cd OWASP-Mobile/M01-Improper-Credential-Usage/lab/m01-credential-exposure-lab/

# Start the application
docker-compose up
```

### Task 1.2: Access the Application

Open your web browser and navigate to: `http://localhost:5100`

You should see the lab interface with multiple vulnerability demonstrations.

---

## Part 2: Discovering Hardcoded Credentials (10 minutes)

### Task 2.1: Simulate Application Decompilation

1. Click the **"Decompile App (Simulation)"** button
2. Observe what credentials are discovered

**Questions to Answer**:
- What types of credentials were found hardcoded?
- What is the risk level of each exposed credential?
- How easy was it to extract these credentials?

### Task 2.2: Examine the Source Code

Open `app/server.py` and locate the following:

```python
# Lines 14-19
# NOTE: These are FAKE credentials for educational demonstration only
API_KEY = "AIzaSyDxVW2E9vZpQN7h8dK2eZvN9vZpQN7h8d"  # FAKE
API_SECRET = "sk_test_FAKE51H7h8dK2eZvN9vZpQN7h8dK2eZv"  # FAKE
DATABASE_URL = "mysql://admin:MySecretPassword123@db.example.com:3306/userdb"  # FAKE
```

**Vulnerability**: These credentials are hardcoded directly in the source code.

**Impact**: 
- Anyone who decompiles the app gets full access to your API and database
- Cannot rotate credentials without releasing a new app version
- Same credentials used across all app installations

**Reflection Questions**:
1. Why is hardcoding credentials dangerous?
2. How could an attacker use these credentials?
3. What alternatives exist for managing API keys?

---

## Part 3: Configuration Endpoint Exposure (10 minutes)

### Task 3.1: Fetch App Configuration

1. Click **"Fetch App Configuration"**
2. Review the JSON response displayed

**Questions to Answer**:
- What sensitive information is included in the configuration?
- Who could intercept this request?
- What happens if this traffic is not encrypted?

### Task 3.2: Analyze the Configuration Endpoint

Review the `/api/config` endpoint in `server.py` (lines 43-58):

```python
@app.route('/api/config')
def get_config():
    config = {
        "api_endpoint": "https://api.example.com",
        "api_key": API_KEY,  # VULNERABLE!
        "api_secret": API_SECRET,  # VULNERABLE!
        "features": {...}
    }
    return jsonify(config)
```

**Vulnerability**: API credentials sent to the client application.

**Attack Scenario**:
1. Attacker uses a proxy (Burp Suite, Charles) to intercept traffic
2. Captures the /api/config response
3. Extracts API credentials
4. Uses credentials to access backend services directly

**Best Practice**: 
- Never send credentials to the client
- Server should use credentials on behalf of authenticated users
- Use short-lived, user-specific access tokens

---

## Part 4: Insecure Storage Methods (10 minutes)

### Task 4.1: Test Different Storage Methods

1. Enter a test email and password
2. Try each storage method:
   - **Plain Text**: See how easily credentials are accessible
   - **Base64**: Understand why encoding ≠ encryption
   - **Secure**: Learn the proper approach

### Task 4.2: Understand Storage Vulnerabilities

**Plain Text Storage**:
```python
# SharedPreferences (Android) or UserDefaults (iOS)
users_storage[email] = {
    "password": password,  # Directly readable!
    ...
}
```

**Why It's Vulnerable**:
- Files are plain XML or plist
- Accessible on rooted/jailbroken devices
- Included in device backups
- Malware can read app storage

**Base64 "Encoding"**:
```python
encoded = base64.b64encode(password.encode()).decode()
```

**Why It's Still Vulnerable**:
- Base64 is encoding, NOT encryption
- Trivially reversible: `base64.b64decode(encoded)`
- Provides zero security
- Creates false sense of protection

**Secure Storage** (The Right Way):

**Android**:
```java
// Use KeyStore + EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val securePrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
```

**iOS**:
```swift
// Use Keychain
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: key,
    kSecValueData as String: valueData,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)
```

---

## Part 5: Log-Based Credential Leakage (5 minutes)

### Task 5.1: Review Application Logs

1. Click **"View Application Logs"**
2. Identify what sensitive information is being logged

### Task 5.2: Understand the Risk

Review the logging code in `server.py`:

```python
# Line 77
logger.info(f"Login attempt - Email: {email}, Password: {password}")

# Line 85
logger.info(f"Login successful - Token: {token}")
```

**Vulnerability**: Credentials written to application logs.

**How Attackers Exploit This**:

**Android**:
```bash
# Anyone with USB debugging can read logs
adb logcat | grep "password\|token\|key"
```

**iOS**:
```bash
# Logs accessible on jailbroken devices
tail -f /var/log/syslog | grep "password"
```

**Real-World Impact**:
- Logs included in crash reports sent to analytics services
- Third-party logging libraries may upload logs to cloud
- Development builds accidentally shipped with debug logging
- Logs persisted on device storage

**Secure Logging Practice**:
```python
# Never log sensitive data
logger.info(f"Login attempt for user: {email}")  # OK
logger.info(f"Login successful")  # OK

# Sanitize if absolutely necessary
sanitized_email = email.split('@')[0][:3] + "***"
logger.info(f"Login attempt for: {sanitized_email}")
```

---

## Part 6: Admin Credential Exposure (5 minutes)

### Task 6.1: Access Admin Credentials

1. Click **"Access Admin Credentials"**
2. Observe the exposed information

### Task 6.2: Understand Privilege Escalation

```python
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin@1234"
```

**Attack Chain**:
1. Attacker decompiles app → finds admin credentials
2. Uses credentials to access admin panel
3. Gains full control over backend systems
4. Accesses all user data
5. Can modify or delete data
6. Complete system compromise

---

## Part 7: Implementing Secure Practices (10 minutes)

### Task 7.1: Fix Hardcoded Credentials

**Current (Vulnerable)**:
```python
API_KEY = "hardcoded_key_here"
```

**Secure Alternative**:
```python
class SecureApiClient:
    def __init__(self):
        # Fetch from backend after user authentication
        self.api_key = self.fetch_user_specific_key()
    
    def fetch_user_specific_key(self):
        # Server generates short-lived key for authenticated user
        response = requests.post(
            "/api/request-key",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        return response.json()["temporary_key"]
```

### Task 7.2: Fix Storage

**Current (Vulnerable)**:
```python
# Plain text storage
prefs.putString("password", password)
```

**Secure Alternative**:

**Android**:
```java
// Use EncryptedSharedPreferences
SharedPreferences prefs = getEncryptedSharedPreferences(context);
prefs.edit().putString("auth_token", token).apply();

// Better: Use KeyStore for keys, tokens only, never store passwords
```

**iOS**:
```swift
// Use Keychain
KeychainManager.storeCredential(key: "auth_token", value: token)
```

### Task 7.3: Fix Logging

**Current (Vulnerable)**:
```python
logger.info(f"Password: {password}")
```

**Secure Alternative**:
```python
# Option 1: Don't log sensitive operations
# No logging for authentication events in production

# Option 2: Sanitize if logging is required
def sanitize_log(message):
    # Remove sensitive patterns
    sanitized = re.sub(r'password[=:]\s*\S+', 'password=***', message, flags=re.IGNORECASE)
    sanitized = re.sub(r'token[=:]\s*\S+', 'token=***', sanitized, flags=re.IGNORECASE)
    return sanitized

logger.info(sanitize_log(message))
```

---

## Part 8: Testing Your Understanding (5 minutes)

### Quiz Questions

1. **What's wrong with using Base64 for password storage?**
   - [ ] It's too slow
   - [x] It's encoding, not encryption
   - [ ] It's not supported on mobile
   - [ ] It uses too much storage

2. **Where should API keys be stored in a mobile app?**
   - [ ] Hardcoded in the app
   - [ ] In SharedPreferences/UserDefaults
   - [ ] In a configuration file
   - [x] Fetched from backend after authentication

3. **What's the most secure way to store credentials on Android?**
   - [ ] Plain SharedPreferences
   - [ ] Base64 encoded in a file
   - [x] Android KeyStore with EncryptedSharedPreferences
   - [ ] SQLite database

4. **Why is logging credentials dangerous?**
   - [x] Logs are accessible via adb/debugging
   - [x] Logs may be included in crash reports
   - [x] Third-party services may collect logs
   - [ ] Logging uses too much storage

---

## Part 9: Cleanup

### Stop the Lab

```bash
# Press Ctrl+C in the terminal where docker-compose is running
# Or in a new terminal:
docker-compose down
```

---

## Key Takeaways

✅ **Never hardcode credentials** in mobile app source code  
✅ **Use platform-provided secure storage** (KeyStore/Keychain)  
✅ **Never log sensitive information** (passwords, tokens, keys)  
✅ **Fetch credentials from backend** rather than embedding them  
✅ **Use encryption, not encoding** for sensitive data  
✅ **Implement certificate pinning** for network communications  
✅ **Assume the device is compromised** when designing security  
✅ **Regular security audits** of credential handling  

---

## Further Learning

1. **Review Documentation**:
   - [overview.md](../overview.md) - Deep dive into the vulnerability
   - [attack-vectors.md](../attack-vectors.md) - How attackers exploit this
   - [prevention.md](../prevention.md) - Comprehensive prevention guide
   - [examples.md](../examples.md) - Code examples

2. **Practice**:
   - Try to extract credentials from a real Android APK using apktool
   - Set up certificate pinning in a sample app
   - Implement KeyStore-based credential storage

3. **Explore Tools**:
   - **MobSF**: Automated mobile security testing
   - **jadx**: Android decompiler
   - **Frida**: Dynamic instrumentation
   - **Burp Suite**: Network traffic analysis

---

**Remember**: Mobile apps are untrusted clients. Design your security architecture accordingly.

*Part of OWASP Mobile Top 10 - Educational Repository*
