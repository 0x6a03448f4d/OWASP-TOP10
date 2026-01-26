# M10: Insufficient Cryptography - Prevention

## Table of Contents
- [Strong Cryptographic Algorithms](#strong-cryptographic-algorithms)
- [Proper Key Management](#proper-key-management)
- [Android KeyStore Implementation](#android-keystore-implementation)
- [iOS Keychain Implementation](#ios-keychain-implementation)
- [Secure Random Number Generation](#secure-random-number-generation)
- [Password Hashing Best Practices](#password-hashing-best-practices)
- [Certificate Pinning](#certificate-pinning)
- [Cryptographic Best Practices](#cryptographic-best-practices)
- [Security Testing and Validation](#security-testing-and-validation)

## Strong Cryptographic Algorithms

### Recommended Algorithms (2024)

**Symmetric Encryption**:
| Use Case | Algorithm | Mode | Key Size | Status |
|----------|-----------|------|----------|--------|
| Data at rest | AES | GCM | 256-bit | ✅ Recommended |
| Data at rest | ChaCha20 | Poly1305 | 256-bit | ✅ Recommended |
| Legacy support | AES | CBC | 256-bit | ⚠️ Acceptable with proper IV |
| Streaming | AES | CTR | 256-bit | ✅ Recommended |

**Asymmetric Encryption**:
| Algorithm | Key Size | Use Case | Status |
|-----------|----------|----------|--------|
| RSA | 2048-bit | Key exchange, signatures | ✅ Minimum |
| RSA | 4096-bit | High-security scenarios | ✅ Recommended |
| ECDSA | 256-bit (P-256) | Signatures | ✅ Recommended |
| EdDSA | 256-bit (Ed25519) | Signatures | ✅ Recommended |
| ECDH | 256-bit (X25519) | Key exchange | ✅ Recommended |

**Cryptographic Hashing**:
| Algorithm | Output Size | Use Case | Status |
|-----------|-------------|----------|--------|
| SHA-256 | 256-bit | General hashing | ✅ Recommended |
| SHA-384 | 384-bit | High security | ✅ Recommended |
| SHA-512 | 512-bit | High security | ✅ Recommended |
| SHA-3 | 256/512-bit | Modern alternative | ✅ Recommended |
| BLAKE2 | 256/512-bit | Fast hashing | ✅ Recommended |

**Password Hashing**:
| Algorithm | Parameters | Use Case | Status |
|-----------|------------|----------|--------|
| Argon2id | m=64MB, t=3, p=4 | Modern apps | ✅ Best choice |
| bcrypt | Cost factor 12+ | Widely supported | ✅ Recommended |
| scrypt | N=2^14, r=8, p=1 | Alternative | ✅ Acceptable |
| PBKDF2-SHA256 | 100,000+ iterations | Legacy support | ⚠️ Minimum |

### ❌ Deprecated Algorithms to Avoid

**Never Use**:
```
❌ DES (56-bit key) - Broken since 1999
❌ 3DES (Sweet32 attack) - Deprecated 2023
❌ RC4 (biased keystream) - Broken 2015
❌ MD5 (collision attacks) - Broken 2004
❌ SHA-1 (SHAttered attack) - Deprecated 2017
❌ ECB mode (pattern preservation) - Fundamentally flawed
❌ Custom/proprietary algorithms - Security through obscurity
```

### Algorithm Selection Guide

**✅ Secure: AES-256-GCM**
```java
// Android - Correct algorithm selection
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
// AES: Strong algorithm
// GCM: Authenticated encryption (detects tampering)
// NoPadding: GCM doesn't need padding
```

**✅ Secure: ChaCha20-Poly1305**
```swift
// iOS - Modern alternative to AES
import CryptoKit

let key = SymmetricKey(size: .bits256)
let nonce = try! ChaChaPoly.Nonce(data: nonceData)
let sealedBox = try! ChaChaPoly.seal(data, using: key, nonce: nonce)
```

**❌ Insecure: DES/ECB**
```java
// NEVER DO THIS!
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
// DES: 56-bit key, broken
// ECB: Preserves patterns, weak
// PKCS5: Vulnerable to padding oracle attacks in ECB/CBC
```

## Proper Key Management

### Key Management Principles

**Fundamental Rules**:
1. **Never hard-code keys** in source code
2. **Never derive keys from weak passwords** without proper KDF
3. **Never store keys in plain text**
4. **Never transmit keys in the clear**
5. **Never use the same key for multiple purposes**
6. **Always use platform key storage** (KeyStore/Keychain)
7. **Always rotate keys periodically**
8. **Always have a key revocation strategy**

### Key Storage Hierarchy

```
Best to Worst Key Storage:

1. ✅ Hardware Security Module (HSM)
   └─ Secure Element / TEE / Secure Enclave
   
2. ✅ Platform KeyStore with Hardware Backing
   ├─ Android: KeyStore (StrongBox on supported devices)
   └─ iOS: Keychain (Secure Enclave on A7+ chips)

3. ⚠️ Platform KeyStore without Hardware Backing
   ├─ Software-based encryption
   └─ Better than nothing, but vulnerable on rooted/jailbroken devices

4. ❌ Encrypted SharedPreferences/UserDefaults
   └─ Master key still needs secure storage

5. ❌ Plain Text SharedPreferences/UserDefaults
   └─ Completely insecure

6. ❌ Hard-Coded in Application
   └─ Trivially extractable
```

### Key Derivation

**✅ Secure: PBKDF2 with High Iterations**
```java
// Derive encryption key from user password
public static SecretKey deriveKeyFromPassword(String password, byte[] salt) {
    try {
        PBEKeySpec spec = new PBEKeySpec(
            password.toCharArray(),
            salt,
            100000,  // Iterations (adjust based on device performance)
            256      // Key length in bits
        );
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        
        return new SecretKeySpec(keyBytes, "AES");
        
    } catch (Exception e) {
        throw new RuntimeException("Key derivation failed", e);
    }
}

// Generate cryptographically secure random salt
public static byte[] generateSalt() {
    byte[] salt = new byte[32]; // 256-bit salt
    new SecureRandom().nextBytes(salt);
    return salt;
}
```

**✅ Secure: Argon2 (Modern Alternative)**
```kotlin
// Kotlin - Using Argon2 for key derivation
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

fun deriveKeyArgon2(password: String, salt: ByteArray): ByteArray {
    val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        .withSalt(salt)
        .withParallelism(4)
        .withMemoryAsKB(65536)  // 64 MB
        .withIterations(3)
        .build()
    
    val generator = Argon2BytesGenerator()
    generator.init(parameters)
    
    val key = ByteArray(32)  // 256-bit key
    generator.generateBytes(password.toCharArray(), key)
    
    return key
}
```

**❌ Insecure: MD5-based Key Derivation**
```java
// NEVER DO THIS!
public static SecretKey weakKeyDerivation(String password) {
    // MD5 is broken, no salt, only 128-bit output
    byte[] keyBytes = MessageDigest.getInstance("MD5").digest(password.getBytes());
    return new SecretKeySpec(keyBytes, "AES");
}
```

## Android KeyStore Implementation

### Basic KeyStore Usage

**✅ Generating and Storing Keys in KeyStore**
```java
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SecureKeyManager {
    private static final String KEY_ALIAS = "MySecureKey";
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    
    /**
     * Generate AES key in Android KeyStore
     * Hardware-backed on supported devices
     */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        );
        
        KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setUserAuthenticationRequired(false)  // Set true for biometric protection
        .setRandomizedEncryptionRequired(true)  // Enforce unique IVs
        .build();
        
        keyGenerator.init(keySpec);
        return keyGenerator.generateKey();
    }
    
    /**
     * Retrieve existing key from KeyStore
     */
    public static SecretKey getKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);
        
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            return generateKey();
        }
        
        return (SecretKey) keyStore.getKey(KEY_ALIAS, null);
    }
    
    /**
     * Delete key from KeyStore
     */
    public static void deleteKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);
        keyStore.deleteEntry(KEY_ALIAS);
    }
}
```

### Encryption with KeyStore Key

**✅ AES-GCM Encryption**
```java
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import android.util.Base64;

public class SecureEncryption {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int GCM_IV_LENGTH = 12;   // bytes (96 bits)
    
    /**
     * Encrypt data using AES-GCM with KeyStore key
     */
    public static String encrypt(String plaintext, SecretKey key) throws Exception {
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
     * Decrypt data using AES-GCM with KeyStore key
     */
    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
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

### Hardware-Backed Key Attestation

**✅ Verify Hardware Backing**
```java
import android.security.keystore.KeyInfo;
import javax.crypto.SecretKeyFactory;

public static boolean isKeyHardwareBacked(SecretKey key) throws Exception {
    SecretKeyFactory factory = SecretKeyFactory.getInstance(
        key.getAlgorithm(),
        "AndroidKeyStore"
    );
    
    KeyInfo keyInfo = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
    
    // Check if key is hardware-backed
    boolean isInsideSecureHardware = keyInfo.isInsideSecureHardware();
    
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        // Check for StrongBox (dedicated HSM)
        int securityLevel = keyInfo.getSecurityLevel();
        boolean isStrongBox = (securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX);
        
        Log.d("KeySecurity", "Hardware-backed: " + isInsideSecureHardware);
        Log.d("KeySecurity", "StrongBox: " + isStrongBox);
        
        return isStrongBox || isInsideSecureHardware;
    }
    
    return isInsideSecureHardware;
}
```

### Biometric-Protected Keys

**✅ Require Biometric Authentication**
```java
public static SecretKey generateBiometricProtectedKey() throws Exception {
    KeyGenerator keyGenerator = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES,
        "AndroidKeyStore"
    );
    
    KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
        "BiometricKey",
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
    )
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .setUserAuthenticationRequired(true);  // Require authentication
    
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        // Set authentication timeout (0 = every use)
        builder.setUserAuthenticationParameters(0, 
            KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
    } else {
        builder.setUserAuthenticationValidityDurationSeconds(-1); // Every use
    }
    
    keyGenerator.init(builder.build());
    return keyGenerator.generateKey();
}
```

## iOS Keychain Implementation

### Basic Keychain Usage

**✅ Storing Data in Keychain**
```swift
import Security
import Foundation

class KeychainManager {
    
    /**
     * Save data to iOS Keychain with strong protection
     */
    static func save(key: String, data: Data) -> Bool {
        // Delete any existing item
        delete(key: key)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            // This ensures data is only accessible when device is unlocked
            // and doesn't sync to iCloud or other devices
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    /**
     * Retrieve data from Keychain
     */
    static func load(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            return nil
        }
        
        return result as? Data
    }
    
    /**
     * Delete data from Keychain
     */
    static func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        
        SecItemDelete(query as CFDictionary)
    }
}
```

### Secure Enclave Protection

**✅ Generate Key in Secure Enclave**
```swift
import Security
import CryptoKit

class SecureEnclaveKeyManager {
    
    /**
     * Generate encryption key in Secure Enclave (iOS 11+)
     * Hardware-backed, cannot be exported
     */
    static func generateSecureEnclaveKey() throws -> SecKey {
        guard SecureEnclave.isAvailable else {
            throw KeyGenerationError.secureEnclaveNotAvailable
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: "com.app.securekey".data(using: .utf8)!,
                kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    [.privateKeyUsage, .biometryCurrentSet],  // Require biometric
                    nil
                )!
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        return privateKey
    }
    
    /**
     * Encrypt data using Secure Enclave key
     */
    static func encrypt(data: Data, using key: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw EncryptionError.publicKeyExtractionFailed
        }
        
        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(
            publicKey,
            .eciesEncryptionStandardX963SHA256AESGCM,
            data as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        
        return encrypted
    }
    
    /**
     * Decrypt data using Secure Enclave key (requires biometric)
     */
    static func decrypt(data: Data, using key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(
            key,
            .eciesEncryptionStandardX963SHA256AESGCM,
            data as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        
        return decrypted
    }
}
```

### Modern CryptoKit Implementation

**✅ Using CryptoKit for Encryption (iOS 13+)**
```swift
import CryptoKit
import Foundation

class ModernEncryption {
    
    /**
     * Generate symmetric key and store in Keychain
     */
    static func generateAndStoreKey(identifier: String) throws -> SymmetricKey {
        let key = SymmetricKey(size: .bits256)
        
        // Convert key to Data for storage
        let keyData = key.withUnsafeBytes { Data($0) }
        
        // Store in Keychain
        guard KeychainManager.save(key: identifier, data: keyData) else {
            throw KeyStorageError.keychainSaveFailed
        }
        
        return key
    }
    
    /**
     * Retrieve key from Keychain
     */
    static func loadKey(identifier: String) throws -> SymmetricKey {
        guard let keyData = KeychainManager.load(key: identifier) else {
            throw KeyStorageError.keyNotFound
        }
        
        return SymmetricKey(data: keyData)
    }
    
    /**
     * Encrypt using AES-GCM (authenticated encryption)
     */
    static func encrypt(data: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.seal(data, using: key)
        
        // combined contains nonce + ciphertext + tag
        guard let combined = sealedBox.combined else {
            throw EncryptionError.sealedBoxCreationFailed
        }
        
        return combined
    }
    
    /**
     * Decrypt using AES-GCM
     */
    static func decrypt(data: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        let decrypted = try AES.GCM.open(sealedBox, using: key)
        
        return decrypted
    }
    
    /**
     * Encrypt using ChaCha20-Poly1305 (alternative to AES)
     */
    static func encryptChaCha(data: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try ChaChaPoly.seal(data, using: key)
        return sealedBox.combined
    }
    
    /**
     * Hash data using SHA-256
     */
    static func hash(data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
```

## Secure Random Number Generation

### Android Secure Random

**✅ Using SecureRandom**
```java
import java.security.SecureRandom;

public class SecureRandomGenerator {
    
    /**
     * Generate cryptographically secure random bytes
     */
    public static byte[] generateSecureRandomBytes(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }
    
    /**
     * Generate secure random token (e.g., for session IDs)
     */
    public static String generateSecureToken(int byteLength) {
        byte[] randomBytes = generateSecureRandomBytes(byteLength);
        return Base64.encodeToString(randomBytes, Base64.URL_SAFE | Base64.NO_WRAP);
    }
    
    /**
     * Generate random IV for AES-GCM
     */
    public static byte[] generateIV() {
        return generateSecureRandomBytes(12); // 96-bit IV for GCM
    }
    
    /**
     * Generate random salt for password hashing
     */
    public static byte[] generateSalt() {
        return generateSecureRandomBytes(32); // 256-bit salt
    }
}
```

**❌ Insecure: Using Math.random()**
```java
// NEVER DO THIS!
public static String generateWeakToken() {
    // Math.random() is NOT cryptographically secure!
    return String.valueOf(Math.random() * Long.MAX_VALUE);
}

// NEVER DO THIS!
public static byte[] generateWeakIV() {
    byte[] iv = new byte[16];
    Random random = new Random(System.currentTimeMillis()); // Predictable seed!
    random.nextBytes(iv);
    return iv;
}
```

### iOS Secure Random

**✅ Using SecRandomCopyBytes**
```swift
import Security

class SecureRandomGenerator {
    
    /**
     * Generate cryptographically secure random bytes
     */
    static func generateSecureBytes(count: Int) -> Data? {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        
        guard status == errSecSuccess else {
            return nil
        }
        
        return Data(bytes)
    }
    
    /**
     * Generate secure random token
     */
    static func generateToken(byteCount: Int = 32) -> String? {
        guard let data = generateSecureBytes(count: byteCount) else {
            return nil
        }
        
        return data.base64EncodedString()
    }
    
    /**
     * Generate random salt for password hashing
     */
    static func generateSalt() -> Data? {
        return generateSecureBytes(count: 32)
    }
}
```

**✅ Using CryptoKit (iOS 13+)**
```swift
import CryptoKit

extension Data {
    /**
     * Generate cryptographically secure random data
     */
    static func secureRandom(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
}

// Usage
let randomNonce = Data.secureRandom(count: 12)
let randomSalt = Data.secureRandom(count: 32)
let sessionToken = Data.secureRandom(count: 32).base64EncodedString()
```

## Password Hashing Best Practices

### bcrypt Implementation

**✅ Android: Using bcrypt**
```java
// Add dependency: implementation 'org.mindrot:jbcrypt:0.4'
import org.mindrot.jbcrypt.BCrypt;

public class PasswordHasher {
    
    private static final int BCRYPT_COST_FACTOR = 12; // 2^12 = 4,096 iterations
    
    /**
     * Hash password using bcrypt
     */
    public static String hashPassword(String password) {
        // BCrypt automatically generates salt
        return BCrypt.hashpw(password, BCrypt.gensalt(BCRYPT_COST_FACTOR));
    }
    
    /**
     * Verify password against bcrypt hash
     */
    public static boolean verifyPassword(String password, String hashedPassword) {
        try {
            return BCrypt.checkpw(password, hashedPassword);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
    
    /**
     * Check if hash needs rehashing (increase cost factor over time)
     */
    public static boolean needsRehash(String hashedPassword) {
        // Extract cost factor from hash
        String costString = hashedPassword.substring(4, 6);
        int currentCost = Integer.parseInt(costString);
        
        return currentCost < BCRYPT_COST_FACTOR;
    }
}
```

**✅ iOS: Using CommonCrypto for PBKDF2**
```swift
import CommonCrypto
import Foundation

class PasswordHasher {
    
    /**
     * Hash password using PBKDF2-SHA256
     */
    static func hashPassword(_ password: String, salt: Data? = nil) -> (hash: String, salt: String)? {
        let saltData = salt ?? SecureRandomGenerator.generateSalt()!
        
        guard let passwordData = password.data(using: .utf8) else {
            return nil
        }
        
        var derivedKeyData = Data(repeating: 0, count: 32) // 256-bit output
        
        let derivationStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            saltData.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password,
                    passwordData.count,
                    saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    saltData.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    100000, // Iterations
                    derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    derivedKeyData.count
                )
            }
        }
        
        guard derivationStatus == kCCSuccess else {
            return nil
        }
        
        return (
            hash: derivedKeyData.base64EncodedString(),
            salt: saltData.base64EncodedString()
        )
    }
    
    /**
     * Verify password against hash and salt
     */
    static func verifyPassword(_ password: String, hash: String, salt: String) -> Bool {
        guard let saltData = Data(base64Encoded: salt),
              let result = hashPassword(password, salt: saltData) else {
            return false
        }
        
        return result.hash == hash
    }
}
```

### Argon2 Implementation

**✅ Using Argon2 (Modern Best Practice)**
```kotlin
// Kotlin - Add dependency: implementation 'org.bouncycastle:bcprov-jdk15on:1.70'
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.util.Base64

object Argon2Hasher {
    
    private const val SALT_LENGTH = 32
    private const val HASH_LENGTH = 32
    private const val ITERATIONS = 3
    private const val MEMORY_KB = 65536 // 64 MB
    private const val PARALLELISM = 4
    
    /**
     * Hash password using Argon2id
     */
    fun hashPassword(password: String): String {
        val salt = ByteArray(SALT_LENGTH)
        SecureRandom().nextBytes(salt)
        
        val hash = hashWithSalt(password, salt)
        
        // Encode as: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
        val encoded = StringBuilder()
        encoded.append("\$argon2id\$v=19\$")
        encoded.append("m=$MEMORY_KB,t=$ITERATIONS,p=$PARALLELISM\$")
        encoded.append(Base64.getEncoder().encodeToString(salt)).append("\$")
        encoded.append(Base64.getEncoder().encodeToString(hash))
        
        return encoded.toString()
    }
    
    /**
     * Verify password against Argon2 hash
     */
    fun verifyPassword(password: String, encodedHash: String): Boolean {
        val parts = encodedHash.split("$")
        if (parts.size != 6) return false
        
        val salt = Base64.getDecoder().decode(parts[4])
        val expectedHash = Base64.getDecoder().decode(parts[5])
        val actualHash = hashWithSalt(password, salt)
        
        return MessageDigest.isEqual(expectedHash, actualHash)
    }
    
    private fun hashWithSalt(password: String, salt: ByteArray): ByteArray {
        val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt)
            .withParallelism(PARALLELISM)
            .withMemoryAsKB(MEMORY_KB)
            .withIterations(ITERATIONS)
            .build()
        
        val generator = Argon2BytesGenerator()
        generator.init(parameters)
        
        val hash = ByteArray(HASH_LENGTH)
        generator.generateBytes(password.toCharArray(), hash)
        
        return hash
    }
}
```

## Certificate Pinning

### SSL/TLS Certificate Pinning

**✅ Android: Network Security Config**
```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <!-- Pin backup certificate too -->
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

```xml
<!-- AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
```

**✅ iOS: Certificate Pinning with URLSession**
```swift
class PinnedURLSessionDelegate: NSObject, URLSessionDelegate {
    
    let pinnedCertificates: [Data]
    
    init(pinnedCertificateNames: [String]) {
        var certificates: [Data] = []
        
        for name in pinnedCertificateNames {
            if let path = Bundle.main.path(forResource: name, ofType: "cer"),
               let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
                certificates.append(data)
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
        var secresult = SecTrustResultType.invalid
        let status = SecTrustEvaluate(serverTrust, &secresult)
        
        guard status == errSecSuccess else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Check against pinned certificates
        if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
            let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data
            
            for pinnedCertificate in pinnedCertificates {
                if serverCertificateData == pinnedCertificate {
                    completionHandler(.useCredential, URLCredential(trust: serverTrust))
                    return
                }
            }
        }
        
        // Certificate not pinned - reject connection
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}

// Usage
let delegate = PinnedURLSessionDelegate(pinnedCertificateNames: ["api_certificate"])
let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
```

## Cryptographic Best Practices

### Complete Secure Implementation Checklist

**Algorithm Selection**:
- ✅ Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption
- ✅ Use RSA-2048+ or ECC-256+ for asymmetric encryption
- ✅ Use SHA-256+ for hashing (not for passwords)
- ✅ Use bcrypt/Argon2/scrypt for password hashing
- ❌ Never use DES, 3DES, RC4, MD5, SHA-1, or ECB mode

**Key Management**:
- ✅ Store keys in Android KeyStore or iOS Keychain
- ✅ Use hardware-backed storage when available
- ✅ Generate keys with platform APIs (KeyGenerator, SecKeyCreateRandomKey)
- ✅ Derive keys with PBKDF2/Argon2 (100,000+ iterations)
- ✅ Use unique keys per user/device/purpose
- ✅ Rotate keys periodically
- ❌ Never hard-code keys
- ❌ Never store keys in SharedPreferences/UserDefaults
- ❌ Never transmit keys in cleartext

**Random Number Generation**:
- ✅ Use SecureRandom (Android) or SecRandomCopyBytes (iOS)
- ✅ Generate unique IV/nonce for each encryption
- ✅ Use sufficient entropy (256-bit salt)
- ❌ Never use Math.random() or Random with predictable seeds
- ❌ Never reuse IVs/nonces

**Implementation**:
- ✅ Use platform cryptographic APIs
- ✅ Keep cryptographic libraries updated
- ✅ Implement proper error handling
- ✅ Clear sensitive data from memory after use
- ✅ Validate all cryptographic operations
- ❌ Never implement custom cryptography
- ❌ Never ignore cryptographic errors
- ❌ Never trust client-side encryption alone

## Security Testing and Validation

### Static Analysis Tests

```bash
# Check for weak algorithms
$ grep -r "DES\|MD5\|SHA1\|ECB" app/src/

# Check for hard-coded keys
$ grep -r "SecretKeySpec\|AES.*=.*\"" app/src/

# Check for weak random
$ grep -r "Math.random\|Random(" app/src/
```

### Dynamic Analysis Tests

```bash
# Use Frida to hook crypto functions
$ frida -U -f com.app -l crypto-hooks.js

# Monitor TLS connections
$ mitmproxy --mode transparent

# Check certificate pinning
$ objection -g com.app explore
> android sslpinning disable
```

### Compliance Validation

- ✅ FIPS 140-2/140-3 validation for cryptographic modules
- ✅ NIST SP 800-175B algorithm compliance
- ✅ PCI-DSS cryptography requirements
- ✅ HIPAA encryption standards
- ✅ GDPR data protection requirements

---

**Related Documentation**:
- [Overview](overview.md) - Understanding insufficient cryptography
- [Attack Vectors](attack-vectors.md) - How weak crypto is exploited
- [Examples](examples.md) - Code examples and patterns
- [Lab](lab/) - Hands-on practice exercises
