# M10: Insufficient Cryptography - Examples

## Table of Contents
- [Vulnerable Examples](#vulnerable-examples)
- [Secure Examples](#secure-examples)
- [Common Patterns](#common-patterns)
- [Framework-Specific Examples](#framework-specific-examples)
- [Migration Examples](#migration-examples)

## Vulnerable Examples

### ❌ Example 1: Hard-Coded Encryption Key (Android)

**Vulnerable Code**:
```java
public class InsecureCrypto {
    // VULNERABLE: Hard-coded key extractable via reverse engineering
    private static final String SECRET_KEY = "MyHardCodedKey16"; // 16 bytes for AES-128
    private static final String ALGORITHM = "AES";
    
    public static String encrypt(String data) throws Exception {
        // VULNERABLE: Using hard-coded key
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.encodeToString(encrypted, Base64.DEFAULT);
    }
    
    public static String decrypt(String encryptedData) throws Exception {
        // VULNERABLE: Same hard-coded key for all users
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        
        byte[] decoded = Base64.decode(encryptedData, Base64.DEFAULT);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
}
```

**Why It's Vulnerable**:
- Hard-coded key visible in decompiled code
- Same key used for all app installations
- No key rotation possible without app update
- Attacker can decompile APK and extract key in minutes

**Attack Demonstration**:
```bash
# Decompile APK
$ jadx vulnerable-app.apk -d decompiled/

# Search for the key
$ grep -r "MyHardCodedKey16" decompiled/
# Found in: decompiled/sources/com/app/InsecureCrypto.java

# Decrypt all user data using extracted key
$ python3 << EOF
from Crypto.Cipher import AES
import base64

key = b"MyHardCodedKey16"
encrypted_data = "..." # Extracted from device

cipher = AES.new(key, AES.MODE_ECB)
decrypted = cipher.decrypt(base64.b64decode(encrypted_data))
print(decrypted)  # Reveals sensitive user data!
EOF
```

---

### ❌ Example 2: DES Encryption (Android)

**Vulnerable Code**:
```java
public class WeakEncryption {
    private static final String SECRET_KEY = "MySecret"; // 8 bytes for DES
    
    public static byte[] encryptDES(byte[] data) throws Exception {
        // VULNERABLE: DES has only 56-bit effective key (broken since 1999)
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
}
```

**Why It's Vulnerable**:
- DES uses 56-bit keys (plus 8 parity bits)
- Can be brute-forced in hours with modern hardware
- ECB mode preserves patterns in data
- Completely deprecated and insecure

**Time to Crack**: ~22 hours on cloud infrastructure (~$100 cost)

---

### ❌ Example 3: MD5 Password Hashing (Android)

**Vulnerable Code**:
```java
public class InsecureAuth {
    
    public static String hashPassword(String password) {
        try {
            // VULNERABLE: MD5 is broken, no salt, fast computation
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            
            // Convert to hex
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
            
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static boolean verifyPassword(String password, String storedHash) {
        // VULNERABLE: Timing attack possible, weak hash
        return hashPassword(password).equals(storedHash);
    }
}
```

**Why It's Vulnerable**:
- MD5 has known collision attacks
- No salt means rainbow table attacks work
- Fast computation enables billions of guesses per second
- Same password always produces same hash

**Attack Result**:
```bash
# Extract password hash from database
$ adb pull /data/data/com.app/databases/users.db
$ sqlite3 users.db "SELECT username, password FROM users;"
# john_doe|5f4dcc3b5aa765d61d8327deb882cf99

# Crack using rainbow table (instant)
$ echo "5f4dcc3b5aa765d61d8327deb882cf99" | hashcat -m 0 -a 0 - rockyou.txt
# Result: "password" (found in milliseconds)
```

---

### ❌ Example 4: ECB Mode Encryption (iOS)

**Vulnerable Code**:
```swift
class WeakCrypto {
    
    // VULNERABLE: Hard-coded key
    private let key = "MySecretKey12345".data(using: .utf8)!
    
    func encryptECB(_ data: Data) -> Data? {
        // VULNERABLE: ECB mode preserves patterns
        var encryptedData = Data(count: data.count + kCCBlockSizeAES128)
        var numBytesEncrypted: size_t = 0
        
        let cryptStatus = key.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                encryptedData.withUnsafeMutableBytes { encryptedBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),  // VULNERABLE: ECB mode!
                        keyBytes.baseAddress,
                        key.count,
                        nil,  // No IV in ECB mode
                        dataBytes.baseAddress,
                        data.count,
                        encryptedBytes.baseAddress,
                        encryptedData.count,
                        &numBytesEncrypted
                    )
                }
            }
        }
        
        guard cryptStatus == kCCSuccess else { return nil }
        encryptedData.count = numBytesEncrypted
        return encryptedData
    }
}
```

**Why It's Vulnerable**:
- ECB mode encrypts identical blocks identically
- Patterns in plaintext visible in ciphertext
- No initialization vector (IV)
- Hard-coded key

**Visual Demonstration**: The famous "ECB Penguin" - encrypting an image with ECB mode still shows the image pattern.

---

### ❌ Example 5: Weak Random Number Generation (Android)

**Vulnerable Code**:
```java
public class WeakRandom {
    
    public static String generateSessionToken() {
        // VULNERABLE: Math.random() is NOT cryptographically secure
        long token = (long) (Math.random() * Long.MAX_VALUE);
        return String.valueOf(token);
    }
    
    public static byte[] generateIV() {
        // VULNERABLE: Predictable seed
        Random random = new Random(System.currentTimeMillis());
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }
    
    public static String generatePassword() {
        // VULNERABLE: Weak randomness for security-critical operation
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder password = new StringBuilder();
        Random random = new Random();
        
        for (int i = 0; i < 8; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }
        
        return password.toString();
    }
}
```

**Why It's Vulnerable**:
- `Math.random()` uses linear congruential generator (predictable)
- `Random(System.currentTimeMillis())` has predictable seed
- Attacker can predict future random values
- Session tokens can be guessed

---

### ❌ Example 6: Base64 "Encryption" (Android & iOS)

**Vulnerable Code**:
```java
public class FakeEncryption {
    
    // VULNERABLE: Base64 is encoding, NOT encryption!
    public static String "encrypt"(String data) {
        return Base64.encodeToString(data.getBytes(), Base64.DEFAULT);
    }
    
    public static String "decrypt"(String encoded) {
        byte[] decoded = Base64.decode(encoded, Base64.DEFAULT);
        return new String(decoded);
    }
}
```

**Why It's Vulnerable**:
- Base64 is trivially reversible encoding
- Provides ZERO security
- Common misconception among developers

**Attack**:
```bash
$ echo "dXNlcm5hbWU6cGFzc3dvcmQ=" | base64 -d
username:password  # Instantly "decrypted"
```

---

### ❌ Example 7: Simple XOR "Encryption"

**Vulnerable Code**:
```java
public class XORCrypto {
    
    private static final String KEY = "SECRET";
    
    // VULNERABLE: XOR cipher is extremely weak
    public static byte[] xorEncrypt(byte[] data) {
        byte[] key = KEY.getBytes();
        byte[] output = new byte[data.length];
        
        for (int i = 0; i < data.length; i++) {
            output[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        
        return output;
    }
    
    // Decryption is same as encryption (XOR property)
    public static byte[] xorDecrypt(byte[] encrypted) {
        return xorEncrypt(encrypted);  // Same operation
    }
}
```

**Why It's Vulnerable**:
- Vulnerable to known-plaintext attacks
- Key recovery with ciphertext-only attack
- Frequency analysis reveals patterns
- Not a secure encryption algorithm

**Attack**:
```python
# If attacker knows any plaintext, they can recover the key
ciphertext = b"\x1e\x00\x0c\x12\x1d"
known_plaintext = b"Hello"

# XOR to get key
key = bytes([c ^ p for c, p in zip(ciphertext, known_plaintext)])
print(f"Key: {key}")  # Reveals "SECRET"

# Now decrypt all data with recovered key!
```

---

## Secure Examples

### ✅ Example 1: Android KeyStore with AES-GCM

**Secure Implementation**:
```java
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class SecureCrypto {
    
    private static final String KEY_ALIAS = "MyAppKey";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    
    /**
     * Generate AES key in Android KeyStore
     * Hardware-backed when available
     */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        );
        
        KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setRandomizedEncryptionRequired(true)
        .build();
        
        keyGenerator.init(keySpec);
        return keyGenerator.generateKey();
    }
    
    /**
     * Get existing key from KeyStore or generate new one
     */
    public static SecretKey getKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            return generateKey();
        }
        
        return (SecretKey) keyStore.getKey(KEY_ALIAS, null);
    }
    
    /**
     * Encrypt data using AES-GCM
     * Returns Base64-encoded: IV + ciphertext + auth tag
     */
    public static String encrypt(String plaintext) throws Exception {
        SecretKey key = getKey();
        
        // Generate random IV for each encryption
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        
        // Combine IV + ciphertext for storage
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        
        return Base64.encodeToString(combined, Base64.NO_WRAP);
    }
    
    /**
     * Decrypt data using AES-GCM
     */
    public static String decrypt(String encryptedData) throws Exception {
        SecretKey key = getKey();
        
        byte[] combined = Base64.decode(encryptedData, Base64.NO_WRAP);
        
        // Extract IV and ciphertext
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] ciphertext = new byte[combined.length - GCM_IV_LENGTH];
        
        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, ciphertext, 0, ciphertext.length);
        
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }
}
```

**Why It's Secure**:
- ✅ Uses AES-256 (strong algorithm)
- ✅ GCM mode provides authenticated encryption
- ✅ Key stored in Android KeyStore (hardware-backed)
- ✅ Unique IV generated for each encryption
- ✅ No hard-coded secrets
- ✅ Proper error handling

**Usage**:
```java
// Encrypt sensitive data
String sensitiveData = "Credit Card: 4532-1234-5678-9010";
String encrypted = SecureCrypto.encrypt(sensitiveData);
// Store encrypted data

// Later, decrypt
String decrypted = SecureCrypto.decrypt(encrypted);
```

---

### ✅ Example 2: iOS Keychain with CryptoKit

**Secure Implementation**:
```swift
import Foundation
import CryptoKit
import Security

class SecureCrypto {
    
    private static let keyIdentifier = "com.app.encryptionKey"
    
    /**
     * Generate and store encryption key in Keychain
     */
    static func generateKey() throws -> SymmetricKey {
        let key = SymmetricKey(size: .bits256)
        
        let keyData = key.withUnsafeBytes { Data($0) }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keyIdentifier,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete existing key if present
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CryptoError.keyGenerationFailed
        }
        
        return key
    }
    
    /**
     * Retrieve key from Keychain
     */
    static func getKey() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keyIdentifier,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecItemNotFound {
            return try generateKey()
        }
        
        guard status == errSecSuccess,
              let keyData = result as? Data else {
            throw CryptoError.keyRetrievalFailed
        }
        
        return SymmetricKey(data: keyData)
    }
    
    /**
     * Encrypt using AES-GCM (authenticated encryption)
     */
    static func encrypt(_ plaintext: String) throws -> String {
        let key = try getKey()
        let data = Data(plaintext.utf8)
        
        let sealedBox = try AES.GCM.seal(data, using: key)
        
        // Combined contains: nonce + ciphertext + tag
        guard let combined = sealedBox.combined else {
            throw CryptoError.encryptionFailed
        }
        
        return combined.base64EncodedString()
    }
    
    /**
     * Decrypt using AES-GCM
     */
    static func decrypt(_ encrypted: String) throws -> String {
        let key = try getKey()
        
        guard let combined = Data(base64Encoded: encrypted) else {
            throw CryptoError.invalidData
        }
        
        let sealedBox = try AES.GCM.SealedBox(combined: combined)
        let decrypted = try AES.GCM.open(sealedBox, using: key)
        
        guard let plaintext = String(data: decrypted, encoding: .utf8) else {
            throw CryptoError.decryptionFailed
        }
        
        return plaintext
    }
}

enum CryptoError: Error {
    case keyGenerationFailed
    case keyRetrievalFailed
    case encryptionFailed
    case decryptionFailed
    case invalidData
}
```

**Why It's Secure**:
- ✅ Uses AES-256-GCM (authenticated encryption)
- ✅ Key stored in iOS Keychain with device-only access
- ✅ CryptoKit provides modern, secure cryptography
- ✅ Automatic nonce generation
- ✅ No hard-coded secrets

---

### ✅ Example 3: bcrypt Password Hashing (Android)

**Secure Implementation**:
```java
import org.mindrot.jbcrypt.BCrypt;

public class SecurePasswordHasher {
    
    // Cost factor: 2^12 = 4,096 iterations
    // Increase over time as hardware improves
    private static final int BCRYPT_COST = 12;
    
    /**
     * Hash password using bcrypt
     * Automatically includes random salt
     */
    public static String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(BCRYPT_COST));
    }
    
    /**
     * Verify password against bcrypt hash
     * Constant-time comparison prevents timing attacks
     */
    public static boolean verifyPassword(String password, String hashedPassword) {
        try {
            return BCrypt.checkpw(password, hashedPassword);
        } catch (IllegalArgumentException e) {
            // Invalid hash format
            return false;
        }
    }
    
    /**
     * Check if password hash needs rehashing
     * (if cost factor has been increased)
     */
    public static boolean needsRehash(String hashedPassword) {
        try {
            String costString = hashedPassword.substring(4, 6);
            int currentCost = Integer.parseInt(costString);
            return currentCost < BCRYPT_COST;
        } catch (Exception e) {
            return true;  // Rehash if can't parse
        }
    }
}
```

**Why It's Secure**:
- ✅ bcrypt is designed for password hashing
- ✅ Automatically generates random salt (unique per password)
- ✅ Computationally expensive (resistant to brute force)
- ✅ Constant-time comparison
- ✅ Future-proof (can increase cost factor)

**Usage**:
```java
// Registration: Hash password
String password = "UserPassword123!";
String hash = SecurePasswordHasher.hashPassword(password);
// Store hash in database: $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW

// Login: Verify password
if (SecurePasswordHasher.verifyPassword(password, storedHash)) {
    // Authentication successful
}

// Periodic check: Rehash if cost factor increased
if (SecurePasswordHasher.needsRehash(storedHash)) {
    String newHash = SecurePasswordHasher.hashPassword(password);
    // Update database with new hash
}
```

---

### ✅ Example 4: Secure Random Generation (Android & iOS)

**Android - Secure Implementation**:
```java
import java.security.SecureRandom;
import android.util.Base64;

public class SecureRandomGenerator {
    
    private static final SecureRandom secureRandom = new SecureRandom();
    
    /**
     * Generate cryptographically secure random bytes
     */
    public static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
    
    /**
     * Generate secure session token
     */
    public static String generateSessionToken() {
        byte[] tokenBytes = generateRandomBytes(32); // 256 bits
        return Base64.encodeToString(tokenBytes, Base64.URL_SAFE | Base64.NO_WRAP);
    }
    
    /**
     * Generate random IV for AES-GCM
     */
    public static byte[] generateIV() {
        return generateRandomBytes(12); // 96-bit IV for GCM
    }
    
    /**
     * Generate random salt for password hashing
     */
    public static byte[] generateSalt() {
        return generateRandomBytes(32); // 256-bit salt
    }
    
    /**
     * Generate secure random password
     */
    public static String generatePassword(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        StringBuilder password = new StringBuilder(length);
        
        for (int i = 0; i < length; i++) {
            int index = secureRandom.nextInt(chars.length());
            password.append(chars.charAt(index));
        }
        
        return password.toString();
    }
}
```

**iOS - Secure Implementation**:
```swift
import Security
import Foundation

class SecureRandomGenerator {
    
    /**
     * Generate cryptographically secure random bytes
     */
    static func generateRandomBytes(count: Int) -> Data? {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        
        guard status == errSecSuccess else {
            return nil
        }
        
        return Data(bytes)
    }
    
    /**
     * Generate secure session token
     */
    static func generateSessionToken() -> String? {
        guard let data = generateRandomBytes(count: 32) else {
            return nil
        }
        
        return data.base64EncodedString()
    }
    
    /**
     * Generate random salt for password hashing
     */
    static func generateSalt() -> Data? {
        return generateRandomBytes(count: 32)
    }
    
    /**
     * Generate secure random password
     */
    static func generatePassword(length: Int) -> String? {
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
        let charsArray = Array(chars)
        
        guard let randomData = generateRandomBytes(count: length) else {
            return nil
        }
        
        var password = ""
        for byte in randomData {
            let index = Int(byte) % charsArray.count
            password.append(charsArray[index])
        }
        
        return password
    }
}
```

---

### ✅ Example 5: Certificate Pinning (iOS)

**Secure Implementation**:
```swift
import Foundation

class SecureNetworking: NSObject, URLSessionDelegate {
    
    private let pinnedCertificates: Set<Data>
    
    init(certificateNames: [String]) {
        var certificates = Set<Data>()
        
        for name in certificateNames {
            if let path = Bundle.main.path(forResource: name, ofType: "cer"),
               let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
                certificates.insert(data)
            }
        }
        
        self.pinnedCertificates = certificates
        super.init()
    }
    
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // Only handle server trust challenges
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        // Evaluate trust
        var secresult = SecTrustResultType.invalid
        let status = SecTrustEvaluate(serverTrust, &secresult)
        
        guard status == errSecSuccess else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get server certificate
        guard let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data
        
        // Check if certificate is pinned
        if pinnedCertificates.contains(serverCertificateData) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

// Usage
let networking = SecureNetworking(certificateNames: ["api_cert", "backup_cert"])
let session = URLSession(configuration: .default,
                        delegate: networking,
                        delegateQueue: nil)

// All requests through this session will use certificate pinning
session.dataTask(with: URL(string: "https://api.example.com")!) { data, response, error in
    // Handle response
}.resume()
```

---

## Common Patterns

### Pattern 1: Encrypted SharedPreferences (Android)

**Secure Pattern**:
```java
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

public class SecurePreferences {
    
    public static SharedPreferences getEncryptedPreferences(Context context) {
        try {
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
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to create encrypted preferences", e);
        }
    }
}

// Usage
SharedPreferences prefs = SecurePreferences.getEncryptedPreferences(context);
prefs.edit()
    .putString("auth_token", token)
    .apply();
```

---

### Pattern 2: File Encryption (Android)

**Secure Pattern**:
```java
import androidx.security.crypto.EncryptedFile;
import androidx.security.crypto.MasterKey;

public class SecureFileStorage {
    
    public static void writeEncryptedFile(Context context, String filename, byte[] data) {
        try {
            MasterKey masterKey = new MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();
            
            File file = new File(context.getFilesDir(), filename);
            
            EncryptedFile encryptedFile = new EncryptedFile.Builder(
                context,
                file,
                masterKey,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build();
            
            try (FileOutputStream outputStream = encryptedFile.openFileOutput()) {
                outputStream.write(data);
            }
            
        } catch (Exception e) {
            throw new RuntimeException("File encryption failed", e);
        }
    }
    
    public static byte[] readEncryptedFile(Context context, String filename) {
        try {
            MasterKey masterKey = new MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();
            
            File file = new File(context.getFilesDir(), filename);
            
            EncryptedFile encryptedFile = new EncryptedFile.Builder(
                context,
                file,
                masterKey,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build();
            
            try (FileInputStream inputStream = encryptedFile.openFileInput()) {
                return inputStream.readAllBytes();
            }
            
        } catch (Exception e) {
            throw new RuntimeException("File decryption failed", e);
        }
    }
}
```

---

## Framework-Specific Examples

### React Native - Secure Storage

```javascript
// Install: npm install react-native-keychain
import * as Keychain from 'react-native-keychain';

// Store credentials securely
async function storeCredentials(username, password) {
  await Keychain.setGenericPassword(username, password, {
    accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    service: 'com.app.auth'
  });
}

// Retrieve credentials
async function getCredentials() {
  try {
    const credentials = await Keychain.getGenericPassword({
      service: 'com.app.auth'
    });
    if (credentials) {
      return {
        username: credentials.username,
        password: credentials.password
      };
    }
    return null;
  } catch (error) {
    console.error('Keychain error:', error);
    return null;
  }
}
```

---

### Flutter - Secure Storage

```dart
// Add dependency: flutter_secure_storage
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureStorage {
  final storage = FlutterSecureStorage();
  
  // Store data securely
  Future<void> storeToken(String token) async {
    await storage.write(
      key: 'auth_token',
      value: token,
      iOptions: IOSOptions(
        accessibility: IOSAccessibility.first_unlock_this_device,
      ),
      aOptions: AndroidOptions(
        encryptedSharedPreferences: true,
      ),
    );
  }
  
  // Retrieve data
  Future<String?> getToken() async {
    return await storage.read(key: 'auth_token');
  }
  
  // Delete data
  Future<void> deleteToken() async {
    await storage.delete(key: 'auth_token');
  }
}
```

---

## Migration Examples

### Migrating from MD5 to bcrypt

**Migration Strategy**:
```java
public class PasswordMigration {
    
    // Old: MD5 hashing
    private String oldHashPassword(String password) {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return bytesToHex(md.digest(password.getBytes()));
    }
    
    // New: bcrypt hashing
    private String newHashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(12));
    }
    
    // During login: Migrate from old to new hash
    public boolean loginAndMigrate(String username, String password) {
        User user = database.getUser(username);
        
        // Check if using old hash format
        if (user.passwordHash.length() == 32) {  // MD5 is 32 hex chars
            // Verify against old hash
            if (oldHashPassword(password).equals(user.passwordHash)) {
                // Successful login - migrate to bcrypt
                String newHash = newHashPassword(password);
                database.updatePasswordHash(username, newHash);
                return true;
            }
        } else {
            // Already using bcrypt
            return BCrypt.checkpw(password, user.passwordHash);
        }
        
        return false;
    }
}
```

---

### Migrating from Hard-Coded Key to KeyStore

**Migration Strategy**:
```java
public class KeyMigration {
    
    private static final String OLD_KEY = "HardCodedKey1234";
    
    // Step 1: Decrypt data with old key
    public byte[] decryptWithOldKey(byte[] encryptedData) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(OLD_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(encryptedData);
    }
    
    // Step 2: Encrypt with new KeyStore key
    public byte[] encryptWithNewKey(byte[] plaintext) throws Exception {
        SecretKey newKey = SecureCrypto.getKey(); // From KeyStore
        // Use AES-GCM encryption (from earlier example)
        return SecureCrypto.encrypt(new String(plaintext)).getBytes();
    }
    
    // Migration function
    public void migrateData(Context context) {
        SQLiteDatabase db = context.openOrCreateDatabase("app.db", 0, null);
        Cursor cursor = db.rawQuery("SELECT id, encrypted_data FROM secrets", null);
        
        while (cursor.moveToNext()) {
            int id = cursor.getInt(0);
            byte[] oldEncrypted = cursor.getBlob(1);
            
            try {
                // Decrypt with old key
                byte[] plaintext = decryptWithOldKey(oldEncrypted);
                
                // Re-encrypt with new key
                byte[] newEncrypted = encryptWithNewKey(plaintext);
                
                // Update database
                db.execSQL("UPDATE secrets SET encrypted_data = ? WHERE id = ?",
                          new Object[]{newEncrypted, id});
                
            } catch (Exception e) {
                Log.e("Migration", "Failed to migrate record " + id, e);
            }
        }
        
        cursor.close();
        db.close();
    }
}
```

---

**Summary**: Always use platform-provided secure cryptography APIs, never implement custom algorithms, and store keys securely in KeyStore/Keychain.

**Related Documentation**:
- [Overview](overview.md) - Understanding insufficient cryptography
- [Attack Vectors](attack-vectors.md) - How weak crypto is exploited
- [Prevention](prevention.md) - Secure implementation guide
- [Lab](lab/) - Hands-on practice
