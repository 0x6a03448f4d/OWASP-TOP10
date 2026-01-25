# M01: Improper Credential Usage - Examples

## Table of Contents
- [Vulnerable Examples](#vulnerable-examples)
- [Secure Examples](#secure-examples)
- [Common Patterns](#common-patterns)
- [Framework-Specific Examples](#framework-specific-examples)

## Vulnerable Examples

### ❌ Example 1: Hardcoded API Key

**Vulnerable Code (Android - Java)**:
```java
public class ApiClient {
    // VULNERABLE: API key hardcoded in source code
    private static final String API_KEY = "AIzaSyDxVW2E9vZpQN7h8dK2eZvN9vZpQN7h8d";
    private static final String API_SECRET = "sk_live_51H7h8dK2eZvN9vZpQN7h8";
    
    public Response makeApiCall(String endpoint) {
        HttpClient client = new HttpClient();
        client.addHeader("X-API-Key", API_KEY);
        client.addHeader("X-API-Secret", API_SECRET);
        return client.get(endpoint);
    }
}
```

**Why It's Vulnerable**:
- API keys are embedded in compiled bytecode
- Anyone can decompile the APK and extract keys
- Keys can't be rotated without app update
- Same keys used for all app installations

### ❌ Example 2: Plain Text Password Storage

**Vulnerable Code (Android - Java)**:
```java
public class LoginManager {
    private SharedPreferences prefs;
    
    public void saveCredentials(String username, String password) {
        // VULNERABLE: Storing password in plain text
        prefs.edit()
            .putString("username", username)
            .putString("password", password)
            .apply();
    }
    
    public boolean login() {
        String username = prefs.getString("username", "");
        String password = prefs.getString("password", "");
        return authenticate(username, password);
    }
}
```

**Why It's Vulnerable**:
- SharedPreferences stored as XML in plain text
- Accessible on rooted devices
- Included in device backups
- No encryption protection

### ❌ Example 3: Logging Sensitive Information

**Vulnerable Code (Android - Java)**:
```java
public class AuthService {
    public void login(String email, String password) {
        // VULNERABLE: Logging credentials
        Log.d("Auth", "Attempting login for: " + email);
        Log.d("Auth", "Password: " + password);
        
        try {
            Response response = api.login(email, password);
            Log.d("Auth", "Auth token: " + response.getToken());
        } catch (Exception e) {
            Log.e("Auth", "Login failed: " + e.getMessage());
        }
    }
}
```

**Why It's Vulnerable**:
- Credentials visible in Logcat
- Logs may be included in crash reports
- Third-party monitoring tools capture logs
- Logs persisted on device

### ❌ Example 4: Credentials in Configuration Files

**Vulnerable Code (Android - XML)**:
```xml
<!-- res/values/config.xml -->
<!-- VULNERABLE: API credentials in resource files -->
<resources>
    <string name="api_key">AIzaSyDxVW2E9vZpQN7h8dK2eZv</string>
    <string name="api_secret">secret_key_12345</string>
    <string name="database_url">mysql://admin:password@db.example.com</string>
</resources>
```

**Why It's Vulnerable**:
- Easily extracted from APK
- No encryption
- Version controlled with app
- Can't be changed without app update

### ❌ Example 5: Weak Encryption

**Vulnerable Code (iOS - Swift)**:
```swift
class CredentialStorage {
    // VULNERABLE: Using simple Base64 encoding (not encryption)
    func savePassword(_ password: String) {
        let encodedData = password.data(using: .utf8)?.base64EncodedString()
        UserDefaults.standard.set(encodedData, forKey: "password")
    }
    
    func getPassword() -> String? {
        guard let encoded = UserDefaults.standard.string(forKey: "password"),
              let data = Data(base64Encoded: encoded),
              let password = String(data: data, encoding: .utf8) else {
            return nil
        }
        return password
    }
}
```

**Why It's Vulnerable**:
- Base64 is encoding, not encryption
- Trivially reversible
- Provides no security
- False sense of protection

## Secure Examples

### ✅ Example 1: Using Android KeyStore

**Secure Code (Android - Java)**:
```java
public class SecureCredentialManager {
    private static final String KEY_ALIAS = "MySecureKeyAlias";
    
    // Generate encryption key in KeyStore
    private void generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            
        keyGenerator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build());
            
        keyGenerator.generateKey();
    }
    
    // Securely store credentials
    public void storeCredential(String key, String value) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        
        SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        
        // Store encrypted data using EncryptedSharedPreferences
        getEncryptedPrefs()
            .edit()
            .putString(key + "_value", Base64.encodeToString(encrypted, Base64.DEFAULT))
            .putString(key + "_iv", Base64.encodeToString(iv, Base64.DEFAULT))
            .apply();
    }
}
```

### ✅ Example 2: Using iOS Keychain

**Secure Code (iOS - Swift)**:
```swift
class KeychainManager {
    // Store credential securely in iOS Keychain
    func storeCredential(key: String, value: String) -> Bool {
        guard let valueData = value.data(using: .utf8) else {
            return false
        }
        
        // Delete existing item first
        deleteCredential(key: key)
        
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

### ✅ Example 3: Runtime API Key Fetching

**Secure Code (Android - Kotlin)**:
```kotlin
class SecureApiClient(private val context: Context) {
    private var apiKey: String? = null
    
    // Fetch API key from server at runtime
    suspend fun initialize() {
        try {
            // Authenticate user first
            val authToken = getStoredAuthToken()
            
            // Request API key from backend
            val response = apiService.requestApiKey(authToken)
            
            // Store encrypted API key
            storeApiKeySecurely(response.apiKey)
            
            this.apiKey = response.apiKey
        } catch (e: Exception) {
            Log.e("SecureApiClient", "Failed to fetch API key", e)
            throw SecurityException("Could not initialize secure client")
        }
    }
    
    private fun storeApiKeySecurely(key: String) {
        val encryptedPrefs = EncryptedSharedPreferences.create(
            context,
            "api_prefs",
            getMasterKey(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        
        encryptedPrefs.edit()
            .putString("api_key", key)
            .putLong("key_timestamp", System.currentTimeMillis())
            .apply()
    }
}
```

### ✅ Example 4: Secure Logging

**Secure Code (Android - Kotlin)**:
```kotlin
object SecureLogger {
    private const val TAG = "SecureApp"
    
    // Sanitize sensitive data before logging
    fun logAuth(message: String) {
        if (BuildConfig.DEBUG) {
            // Even in debug, sanitize sensitive data
            val sanitized = sanitizeMessage(message)
            Log.d(TAG, sanitized)
        }
        // In production, consider using proper logging service
    }
    
    private fun sanitizeMessage(message: String): String {
        var sanitized = message
        
        // Remove potential passwords
        sanitized = sanitized.replace(
            Regex("password[\"']?\\s*[:=]\\s*[\"']?[^\"'\\s,}]+", RegexOption.IGNORE_CASE),
            "password=***"
        )
        
        // Remove potential tokens
        sanitized = sanitized.replace(
            Regex("token[\"']?\\s*[:=]\\s*[\"']?[^\"'\\s,}]+", RegexOption.IGNORE_CASE),
            "token=***"
        )
        
        // Remove potential email addresses
        sanitized = sanitized.replace(
            Regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"),
            "***@***.***"
        )
        
        return sanitized
    }
}
```

### ✅ Example 5: Token Rotation

**Secure Code (Kotlin)**:
```kotlin
class TokenManager(private val context: Context) {
    private val secureStorage = SecureStorage(context)
    
    companion object {
        private const val TOKEN_LIFETIME_MILLIS = 15 * 60 * 1000 // 15 minutes
        private const val REFRESH_BUFFER_MILLIS = 2 * 60 * 1000  // 2 minutes
    }
    
    suspend fun getValidToken(): String {
        val token = secureStorage.getToken()
        
        if (token == null || isTokenExpired(token)) {
            return refreshToken()
        }
        
        // Proactively refresh if nearing expiration
        if (isTokenNearExpiry(token)) {
            lifecycleScope.launch {
                refreshToken()
            }
        }
        
        return token.accessToken
    }
    
    private fun isTokenExpired(token: Token): Boolean {
        return System.currentTimeMillis() >= token.expiryTime
    }
    
    private fun isTokenNearExpiry(token: Token): Boolean {
        val timeUntilExpiry = token.expiryTime - System.currentTimeMillis()
        return timeUntilExpiry < REFRESH_BUFFER_MILLIS
    }
    
    private suspend fun refreshToken(): String {
        val currentToken = secureStorage.getToken()
        val refreshToken = currentToken?.refreshToken 
            ?: throw SecurityException("No refresh token available")
        
        try {
            val newToken = apiService.refreshAccessToken(refreshToken)
            secureStorage.storeToken(newToken)
            return newToken.accessToken
        } catch (e: Exception) {
            // Refresh failed, require re-authentication
            clearTokens()
            throw AuthenticationRequiredException()
        }
    }
}
```

## Common Patterns

### Pattern 1: Backend-Provided Configuration

**Concept**: Never ship credentials with the app. Fetch them after authentication.

```kotlin
// App startup flow
class AppInitializer {
    suspend fun initialize() {
        // 1. User authenticates
        val userToken = authenticateUser()
        
        // 2. Fetch app configuration from backend
        val config = backendService.getAppConfig(userToken)
        
        // 3. Store configuration securely
        secureStorage.storeConfig(config)
        
        // 4. Initialize app with fetched configuration
        initializeServices(config)
    }
}
```

### Pattern 2: Certificate Pinning

**Concept**: Prevent man-in-the-middle attacks by pinning certificates.

```kotlin
class SecureNetworkClient {
    fun createOkHttpClient(): OkHttpClient {
        val certificatePinner = CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
            .build()
        
        return OkHttpClient.Builder()
            .certificatePinner(certificatePinner)
            .build()
    }
}
```

### Pattern 3: Biometric Authentication

**Concept**: Require biometric authentication to access stored credentials.

```kotlin
class BiometricCredentialAccess(private val activity: FragmentActivity) {
    fun accessCredentials(onSuccess: (String) -> Unit, onFailure: () -> Unit) {
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    // Biometric verified, access credentials
                    val credential = secureStorage.getCredential()
                    onSuccess(credential)
                }
                
                override fun onAuthenticationFailed() {
                    onFailure()
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate to access account")
            .setSubtitle("Use your fingerprint or face")
            .setNegativeButtonText("Cancel")
            .build()
        
        biometricPrompt.authenticate(promptInfo)
    }
}
```

## Framework-Specific Examples

### React Native

```javascript
// Using react-native-keychain
import * as Keychain from 'react-native-keychain';

// Store credentials
async function storeCredentials(username, password) {
  try {
    await Keychain.setGenericPassword(username, password, {
      accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_ANY,
      accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  } catch (error) {
    console.error('Failed to store credentials', error);
  }
}

// Retrieve credentials
async function getCredentials() {
  try {
    const credentials = await Keychain.getGenericPassword();
    if (credentials) {
      return {
        username: credentials.username,
        password: credentials.password
      };
    }
  } catch (error) {
    console.error('Failed to retrieve credentials', error);
  }
  return null;
}
```

### Flutter

```dart
// Using flutter_secure_storage
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureCredentialManager {
  final storage = FlutterSecureStorage();
  
  // Store credential
  Future<void> storeCredential(String key, String value) async {
    await storage.write(
      key: key,
      value: value,
      aOptions: AndroidOptions(encryptedSharedPreferences: true),
      iOptions: IOSOptions(accessibility: IOSAccessibility.first_unlock_this_device),
    );
  }
  
  // Retrieve credential
  Future<String?> getCredential(String key) async {
    return await storage.read(key: key);
  }
  
  // Delete credential
  Future<void> deleteCredential(String key) async {
    await storage.delete(key: key);
  }
}
```

## Comparison: Vulnerable vs Secure

| Aspect | ❌ Vulnerable | ✅ Secure |
|--------|--------------|----------|
| **Storage** | SharedPreferences (plain) | KeyStore + EncryptedSharedPrefs |
| **API Keys** | Hardcoded in code | Fetched from backend at runtime |
| **Passwords** | Plain text or Base64 | Never stored (use tokens) |
| **Tokens** | Long-lived, no rotation | Short-lived with auto-rotation |
| **Logging** | Credentials in logs | Sanitized or no logging |
| **Backup** | Included in backups | Excluded from backups |
| **Network** | HTTP, no pinning | HTTPS with certificate pinning |

---

**Key Principle**: Assume the app binary and device storage are compromised. Design accordingly.

*Part of OWASP Mobile Top 10 - Educational Repository*
