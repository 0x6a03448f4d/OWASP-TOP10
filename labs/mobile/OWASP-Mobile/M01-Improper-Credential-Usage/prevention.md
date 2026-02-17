# M01: Improper Credential Usage - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Secure Credential Storage](#secure-credential-storage)
- [Development Best Practices](#development-best-practices)
- [Architecture and Design](#architecture-and-design)
- [Testing and Validation](#testing-and-validation)
- [Prevention Checklist](#prevention-checklist)

## Prevention Strategy Overview

Preventing credential exposure requires a defense-in-depth approach across the entire application lifecycle:

```
Design → Development → Testing → Deployment → Monitoring
   ↓          ↓          ↓          ↓            ↓
 Secure    No Hardcoded  Automated  Secure      Anomaly
 Design    Credentials   Testing   Distribution Detection
```

### Core Principles

1. **Never Trust the Client**: Assume the device is compromised
2. **Minimize Credential Storage**: Only store what's absolutely necessary
3. **Use Platform Security**: Leverage OS-provided secure storage
4. **Encrypt Everything**: Multiple layers of encryption
5. **Short-Lived Tokens**: Implement token rotation
6. **Monitor and Alert**: Detect abnormal credential usage

## Secure Credential Storage

### ✅ Use Platform Keychain/KeyStore

**Android - KeyStore**:
```java
// Store credentials securely using Android KeyStore
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SecureCredentialStorage {
    private static final String KEY_ALIAS = "MyKeyAlias";
    
    // Generate and store a key
    public void generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            
        keyGenerator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(false)
            .build());
            
        keyGenerator.generateKey();
    }
    
    // Encrypt and store credentials
    public void storeCredential(String credential) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        
        SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
        
        Cipher cipher = Cipher.getInstance(
            "AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(credential.getBytes());
        
        // Store encrypted data and IV
        SharedPreferences prefs = getEncryptedSharedPreferences();
        prefs.edit()
            .putString("encrypted_credential", Base64.encodeToString(encrypted, Base64.DEFAULT))
            .putString("iv", Base64.encodeToString(iv, Base64.DEFAULT))
            .apply();
    }
    
    // Use EncryptedSharedPreferences for additional security
    private SharedPreferences getEncryptedSharedPreferences() throws Exception {
        MasterKey masterKey = new MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build();
            
        return EncryptedSharedPreferences.create(
            context,
            "secure_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }
}
```

**iOS - Keychain**:
```swift
import Security

class SecureCredentialStorage {
    // Store credential in iOS Keychain
    func storeCredential(key: String, value: String) -> Bool {
        guard let valueData = value.data(using: .utf8) else {
            return false
        }
        
        // Delete any existing item
        deleteCredential(key: key)
        
        // Create query
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: valueData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    // Retrieve credential from Keychain
    func retrieveCredential(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let credential = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return credential
    }
    
    // Delete credential
    func deleteCredential(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}
```

### ✅ Implement Encrypted Shared Preferences

**Android - EncryptedSharedPreferences**:
```java
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

public class SecurePreferences {
    public static SharedPreferences getEncryptedPrefs(Context context) 
            throws Exception {
        MasterKey masterKey = new MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build();
        
        return EncryptedSharedPreferences.create(
            context,
            "secure_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }
    
    // Usage
    public void saveToken(String token) throws Exception {
        SharedPreferences prefs = getEncryptedPrefs(context);
        prefs.edit().putString("auth_token", token).apply();
    }
}
```

## Development Best Practices

### ✅ Never Hardcode Credentials

**❌ WRONG - Hardcoded API Key**:
```java
public class ApiClient {
    // NEVER DO THIS!
    private static final String API_KEY = "sk_live_51H7h8dK2eZv...";
    private static final String SECRET = "your_secret_here";
}
```

**✅ CORRECT - Runtime Configuration**:
```java
public class ApiClient {
    private String apiKey;
    
    public ApiClient() {
        // Fetch from secure backend on app launch
        this.apiKey = fetchApiKeyFromServer();
    }
    
    private String fetchApiKeyFromServer() {
        // Authenticate user first
        // Server generates short-lived API key
        // Return encrypted key to app
        return serverResponse.getEncryptedApiKey();
    }
}
```

### ✅ Use Environment-Specific Configuration

**Build Configuration (Android)**:
```gradle
// build.gradle
android {
    buildTypes {
        debug {
            buildConfigField "String", "API_URL", '"https://dev-api.example.com"'
            // Never put real credentials here - they end up in APK
        }
        release {
            buildConfigField "String", "API_URL", '"https://api.example.com"'
            // Fetch actual credentials at runtime from server
        }
    }
}
```

### ✅ Implement Secure Logging

**❌ WRONG - Logging Credentials**:
```java
// NEVER DO THIS!
Log.d("Auth", "Password: " + password);
Log.d("API", "Token: " + authToken);
System.out.println("API Key: " + apiKey);
```

**✅ CORRECT - Sanitized Logging**:
```java
public class SecureLogger {
    public static void logAuth(String message) {
        if (BuildConfig.DEBUG) {
            // Even in debug, never log full credentials
            Log.d("Auth", message.replaceAll("password=.*", "password=***"));
        }
        // Production: no logging of auth events
    }
    
    public static String sanitize(String input) {
        // Mask sensitive data
        return input.replaceAll(
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", 
            "***@***.***"
        );
    }
}
```

### ✅ Disable Backup for Sensitive Data

**Android - Exclude from Backups**:
```xml
<!-- AndroidManifest.xml -->
<application
    android:allowBackup="false"
    android:fullBackupContent="@xml/backup_rules">
    
<!-- backup_rules.xml -->
<full-backup-content>
    <exclude domain="sharedpref" path="secure_prefs.xml"/>
    <exclude domain="database" path="sensitive.db"/>
</full-backup-content>
```

**iOS - Exclude from iCloud Backup**:
```swift
func excludeFromBackup(url: URL) {
    var resourceValues = URLResourceValues()
    resourceValues.isExcludedFromBackup = true
    try? url.setResourceValues(resourceValues)
}
```

## Architecture and Design

### ✅ Implement Token Rotation

**Short-Lived Access Tokens**:
```java
public class TokenManager {
    private static final int TOKEN_LIFETIME_MINUTES = 15;
    
    public void refreshTokenIfNeeded() {
        Token currentToken = getStoredToken();
        
        if (currentToken.isExpired() || currentToken.willExpireSoon()) {
            // Use refresh token to get new access token
            Token newToken = authService.refreshToken(currentToken.getRefreshToken());
            
            // Store new token securely
            storeTokenSecurely(newToken);
        }
    }
    
    private boolean willExpireSoon(Token token) {
        long expiryTime = token.getExpiryTimestamp();
        long currentTime = System.currentTimeMillis();
        long buffer = TimeUnit.MINUTES.toMillis(2); // 2-minute buffer
        
        return (expiryTime - currentTime) < buffer;
    }
}
```

### ✅ Use Certificate Pinning

**Android - Network Security Config**:
```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <pin digest="SHA-256">base64encodedpinhash1==</pin>
            <pin digest="SHA-256">base64encodedpinhash2==</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**iOS - Certificate Pinning**:
```swift
class PinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, 
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let policies = [SecPolicy.create(SecPolicyIdentifier.SSL, hostname: challenge.protectionSpace.host)]
        SecTrustSetPolicies(serverTrust, policies as CFTypeRef)
        
        // Validate against pinned certificates
        if validatePinnedCertificate(serverTrust) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

### ✅ Implement Proper Session Management

```java
public class SessionManager {
    private static final long SESSION_TIMEOUT = TimeUnit.HOURS.toMillis(1);
    
    public boolean isSessionValid() {
        long lastActivity = getLastActivityTime();
        long currentTime = System.currentTimeMillis();
        
        if (currentTime - lastActivity > SESSION_TIMEOUT) {
            // Session expired, clear credentials
            clearSession();
            return false;
        }
        
        // Update last activity
        updateLastActivityTime(currentTime);
        return true;
    }
    
    public void clearSession() {
        // Remove all stored credentials
        secureStorage.deleteAll();
        // Clear app state
        clearAppState();
    }
}
```

## Testing and Validation

### ✅ Automated Security Scanning

**Static Analysis Tools**:
- **MobSF (Mobile Security Framework)**: Automated binary analysis
- **QARK**: Android-specific vulnerability scanner
- **Checkmarx**: Commercial SAST tool
- **SonarQube**: Code quality and security

**Integration Example**:
```bash
# Run MobSF scan in CI/CD pipeline
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# API scan
curl -F "file=@app-release.apk" http://localhost:8000/api/v1/upload
```

### ✅ Manual Security Testing

**Testing Checklist**:
1. Decompile APK/IPA and search for hardcoded credentials
2. Check all string resources and configuration files
3. Analyze local storage for plaintext credentials
4. Intercept network traffic for credential leakage
5. Review logs for sensitive data exposure
6. Test on rooted/jailbroken devices
7. Analyze backup files

### ✅ Dynamic Analysis Testing

```bash
# Example Frida script to detect hardcoded secrets
frida -U -f com.example.app -l detect_secrets.js

# detect_secrets.js
Java.perform(function() {
    // Hook string operations
    var String = Java.use("java.lang.String");
    String.equals.implementation = function(other) {
        var result = this.equals(other);
        if (this.value && this.value.length > 10) {
            console.log("[String Comparison] " + this.value);
        }
        return result;
    };
});
```

## Prevention Checklist

### Development Phase
- [ ] No credentials hardcoded in source code
- [ ] No credentials in string resources
- [ ] No credentials in configuration files
- [ ] Using platform KeyStore/Keychain for storage
- [ ] Encryption implemented for sensitive data
- [ ] Logging doesn't include sensitive information
- [ ] Environment variables not containing secrets in builds

### Testing Phase
- [ ] Static analysis tools passing with no credential issues
- [ ] Dynamic analysis shows no credential exposure
- [ ] Decompiled app contains no discoverable secrets
- [ ] Network traffic properly encrypted
- [ ] Local storage encrypted
- [ ] Backup exclusions working
- [ ] Certificate pinning functional

### Deployment Phase
- [ ] Production builds remove debug logging
- [ ] Backup exclusions configured
- [ ] Certificate pinning enabled
- [ ] Token rotation implemented
- [ ] Session timeout configured
- [ ] API keys rotatable without app update
- [ ] Monitoring and alerting active

### Ongoing Maintenance
- [ ] Regular security audits
- [ ] Dependency vulnerability scanning
- [ ] Certificate rotation planning
- [ ] Incident response plan ready
- [ ] Token rotation tested regularly
- [ ] User credential breach monitoring

## Quick Reference: Dos and Don'ts

### ✅ DO
- Use platform-provided secure storage (Keychain/KeyStore)
- Implement certificate pinning
- Use short-lived, rotatable tokens
- Encrypt all stored credentials
- Implement proper session management
- Use automated security scanning
- Monitor for credential abuse
- Have a credential rotation strategy

### ❌ DON'T
- Hardcode API keys, passwords, or secrets
- Store credentials in plain text
- Log sensitive information
- Use weak or deprecated encryption
- Trust the client device
- Include credentials in version control
- Store credentials in app backups
- Use long-lived credentials

## Additional Resources

- **OWASP Mobile Security Testing Guide**: Detailed testing procedures
- **Android Security Best Practices**: Official Android security documentation
- **iOS Security Guide**: Apple's security implementation guide
- **NIST Mobile Device Security**: Government security standards

---

**Remember**: Defense in depth is essential. Implement multiple layers of protection.

*Part of OWASP Mobile Top 10 - Educational Repository*
