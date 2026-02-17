# M09: Insecure Data Storage - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Android Secure Storage](#android-secure-storage)
- [iOS Secure Storage](#ios-secure-storage)
- [Database Encryption](#database-encryption)
- [File Encryption](#file-encryption)
- [Backup Protection](#backup-protection)
- [Additional Security Measures](#additional-security-measures)

## Prevention Strategy Overview

Securing data storage on mobile devices requires a multi-layered approach:

```
Defense Layer 1: Minimize Data Storage
    ↓
Defense Layer 2: Use Platform Secure Storage (Keychain/KeyStore)
    ↓
Defense Layer 3: Encrypt Databases and Files
    ↓
Defense Layer 4: Exclude Sensitive Data from Backups
    ↓
Defense Layer 5: Clear Data When No Longer Needed
    ↓
Defense Layer 6: Implement Additional Protections
```

### Core Principles

1. **Minimize Storage**: Don't store what you don't absolutely need
2. **Use Platform APIs**: Leverage built-in secure storage mechanisms
3. **Encrypt Everything**: Assume device will be compromised
4. **Exclude from Backups**: Sensitive data should never be in backups
5. **Implement Expiration**: Automatically clear old sensitive data
6. **Defense in Depth**: Multiple security layers

## Android Secure Storage

### 1. Android Keystore System

**Purpose**: Securely store cryptographic keys in hardware-backed storage.

**✅ Secure Implementation**:

```java
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeystoreManager {
    private static final String KEY_ALIAS = "MyAppEncryptionKey";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    
    /**
     * Generate a new encryption key in Android Keystore
     */
    public SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, 
            ANDROID_KEYSTORE
        );
        
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        // Require user authentication for key use
        .setUserAuthenticationRequired(true)
        .setUserAuthenticationValidityDurationSeconds(300) // 5 minutes
        .build();
        
        keyGenerator.init(keyGenParameterSpec);
        return keyGenerator.generateKey();
    }
    
    /**
     * Retrieve existing key from Keystore
     */
    public SecretKey getKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            return generateKey();
        }
        
        return (SecretKey) keyStore.getKey(KEY_ALIAS, null);
    }
}
```

**Key Benefits**:
- Hardware-backed security on supported devices
- Keys never leave secure hardware
- Can require biometric authentication
- Resistant to extraction even on rooted devices

### 2. EncryptedSharedPreferences

**Purpose**: Encrypted key-value storage (replacement for plain SharedPreferences).

**✅ Secure Implementation**:

```kotlin
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SecurePreferences(context: Context) {
    
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    
    private val sharedPreferences = EncryptedSharedPreferences.create(
        context,
        "secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
    
    /**
     * Store authentication token securely
     */
    fun saveAuthToken(token: String) {
        sharedPreferences.edit()
            .putString("auth_token", token)
            .apply()
    }
    
    /**
     * Retrieve authentication token
     */
    fun getAuthToken(): String? {
        return sharedPreferences.getString("auth_token", null)
    }
    
    /**
     * Store user credentials (for "Remember Me" feature)
     */
    fun saveCredentials(email: String, encryptedPassword: String) {
        sharedPreferences.edit()
            .putString("user_email", email)
            .putString("user_password", encryptedPassword)
            .apply()
    }
    
    /**
     * Clear all sensitive data
     */
    fun clearAll() {
        sharedPreferences.edit().clear().apply()
    }
}
```

**Usage Example**:
```kotlin
// In your Activity or Fragment
val securePrefs = SecurePreferences(context)

// Save token
securePrefs.saveAuthToken("eyJhbGciOiJIUzI1NiIs...")

// Retrieve token
val token = securePrefs.getAuthToken()

// Clear on logout
securePrefs.clearAll()
```

**❌ Insecure - Plain SharedPreferences**:
```kotlin
// NEVER do this for sensitive data
val prefs = getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
prefs.edit()
    .putString("auth_token", token)  // STORED IN PLAIN TEXT!
    .apply()
```

### 3. EncryptedFile API

**Purpose**: Encrypt individual files transparently.

**✅ Secure Implementation**:

```kotlin
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File

class SecureFileStorage(private val context: Context) {
    
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    
    /**
     * Write encrypted file
     */
    fun writeEncryptedFile(filename: String, data: ByteArray) {
        val file = File(context.filesDir, filename)
        
        val encryptedFile = EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
        
        encryptedFile.openFileOutput().use { output ->
            output.write(data)
        }
    }
    
    /**
     * Read encrypted file
     */
    fun readEncryptedFile(filename: String): ByteArray {
        val file = File(context.filesDir, filename)
        
        val encryptedFile = EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
        
        return encryptedFile.openFileInput().use { input ->
            input.readBytes()
        }
    }
}
```

**Usage Example**:
```kotlin
val storage = SecureFileStorage(context)

// Write sensitive document
val sensitiveData = "User's private information".toByteArray()
storage.writeEncryptedFile("user_data.enc", sensitiveData)

// Read it back
val decrypted = storage.readEncryptedFile("user_data.enc")
val originalData = String(decrypted)
```

### 4. Room Database with SQLCipher

**Purpose**: Encrypt entire SQLite database.

**✅ Secure Implementation**:

**build.gradle**:
```gradle
dependencies {
    implementation "androidx.room:room-runtime:2.5.0"
    implementation "net.zetetic:android-database-sqlcipher:4.5.4"
    implementation "androidx.sqlite:sqlite-ktx:2.3.0"
    kapt "androidx.room:room-compiler:2.5.0"
}
```

**Database Setup**:
```kotlin
import android.util.Base64
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SupportFactory
import java.security.SecureRandom

@Database(entities = [User::class, Transaction::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun userDao(): UserDao
    abstract fun transactionDao(): TransactionDao
}

class DatabaseManager(private val context: Context) {
    
    /**
     * Create encrypted database
     */
    fun createEncryptedDatabase(): AppDatabase {
        // Generate or retrieve encryption key from Keystore
        val passphrase = getOrCreateDatabaseKey()
        val factory = SupportFactory(SQLiteDatabase.getBytes(passphrase))
        
        return Room.databaseBuilder(
            context,
            AppDatabase::class.java,
            "app_database"
        )
        .openHelperFactory(factory)
        .build()
    }
    
    /**
     * Get database encryption key from secure storage
     */
    private fun getOrCreateDatabaseKey(): CharArray {
        val securePrefs = SecurePreferences(context)
        var key = securePrefs.getDatabaseKey()
        
        if (key == null) {
            // Generate new 256-bit key
            key = generateSecureRandomKey()
            securePrefs.saveDatabaseKey(key)
        }
        
        return key.toCharArray()
    }
    
    private fun generateSecureRandomKey(): String {
        val random = SecureRandom()
        val bytes = ByteArray(32) // 256 bits
        random.nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }
}
```

**Entity Example**:
```kotlin
@Entity(tableName = "users")
data class User(
    @PrimaryKey val id: Int,
    val email: String,
    val name: String,
    val encryptedPhone: String  // Additional field-level encryption if needed
)
```

## iOS Secure Storage

### 1. Keychain Services

**Purpose**: Securely store small pieces of sensitive data (passwords, tokens, keys).

**✅ Secure Implementation**:

```swift
import Security
import Foundation

class KeychainManager {
    
    /**
     * Save data to Keychain with security attributes
     */
    static func save(key: String, data: Data) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete any existing item
        SecItemDelete(query as CFDictionary)
        
        // Add new item
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
        
        if status == errSecSuccess {
            return result as? Data
        }
        return nil
    }
    
    /**
     * Delete item from Keychain
     */
    static func delete(key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
    
    /**
     * Save with biometric protection
     */
    static func saveWithBiometric(key: String, data: Data) -> Bool {
        var error: Unmanaged<CFError>?
        
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,  // Requires biometric authentication
            &error
        ) else {
            return false
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access
        ]
        
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
}
```

**Usage Example**:
```swift
// Save authentication token
let token = "eyJhbGciOiJIUzI1NiIs...".data(using: .utf8)!
KeychainManager.save(key: "auth_token", data: token)

// Retrieve token
if let tokenData = KeychainManager.load(key: "auth_token") {
    let tokenString = String(data: tokenData, encoding: .utf8)
}

// Delete on logout
KeychainManager.delete(key: "auth_token")

// Save with biometric protection
KeychainManager.saveWithBiometric(key: "sensitive_data", data: data)
```

**Keychain Accessibility Levels**:
```swift
// Choose based on your security requirements:

// Most secure - requires device unlock, not backed up
kSecAttrAccessibleWhenUnlockedThisDeviceOnly

// Secure - requires device unlock, backed up to iCloud Keychain
kSecAttrAccessibleWhenUnlocked

// Less secure - accessible after first unlock
kSecAttrAccessibleAfterFirstUnlock

// Least secure - always accessible (avoid for sensitive data)
kSecAttrAccessibleAlways
```

### 2. Data Protection API

**Purpose**: File-level encryption tied to device lock state.

**✅ Secure Implementation**:

```swift
import Foundation

class SecureFileManager {
    
    /**
     * Write file with data protection
     */
    static func writeSecureFile(filename: String, data: Data) -> Bool {
        let fileURL = getDocumentsDirectory().appendingPathComponent(filename)
        
        do {
            try data.write(
                to: fileURL,
                options: [.completeFileProtection]  // NSDataWritingFileProtectionComplete
            )
            return true
        } catch {
            print("Error writing secure file: \(error)")
            return false
        }
    }
    
    /**
     * Write file with complete data protection
     */
    static func writeFileWithProtection(filename: String, data: Data, 
                                       protection: FileProtectionType) -> Bool {
        let fileURL = getDocumentsDirectory().appendingPathComponent(filename)
        
        do {
            try data.write(to: fileURL)
            
            // Set protection level
            try FileManager.default.setAttributes(
                [.protectionKey: protection],
                ofItemAtPath: fileURL.path
            )
            return true
        } catch {
            print("Error: \(error)")
            return false
        }
    }
    
    /**
     * Read protected file
     */
    static func readSecureFile(filename: String) -> Data? {
        let fileURL = getDocumentsDirectory().appendingPathComponent(filename)
        return try? Data(contentsOf: fileURL)
    }
    
    private static func getDocumentsDirectory() -> URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }
}
```

**Data Protection Levels**:
```swift
// Complete protection - file encrypted, inaccessible when locked
FileProtectionType.complete

// Complete unless already open - can continue using if opened before lock
FileProtectionType.completeUnlessOpen

// Complete until first user authentication - accessible after first unlock
FileProtectionType.completeUntilFirstUserAuthentication

// None - no protection (avoid for sensitive data)
FileProtectionType.none
```

**Usage Example**:
```swift
// Save sensitive user data with complete protection
let userData = try! JSONEncoder().encode(user)
SecureFileManager.writeSecureFile(filename: "user_profile.json", data: userData)

// Read it back
if let data = SecureFileManager.readSecureFile(filename: "user_profile.json") {
    let user = try! JSONDecoder().decode(User.self, from: data)
}
```

### 3. Core Data with Encryption

**Purpose**: Encrypt Core Data persistent store.

**✅ Secure Implementation**:

```swift
import CoreData

class CoreDataManager {
    
    lazy var persistentContainer: NSPersistentContainer = {
        let container = NSPersistentContainer(name: "AppModel")
        
        // Get store description
        guard let description = container.persistentStoreDescriptions.first else {
            fatalError("Failed to retrieve persistent store description")
        }
        
        // Enable file protection
        description.setOption(
            FileProtectionType.complete as NSObject,
            forKey: NSPersistentStoreFileProtectionKey
        )
        
        // Load persistent stores
        container.loadPersistentStores { storeDescription, error in
            if let error = error as NSError? {
                fatalError("Unresolved error \(error)")
            }
        }
        
        return container
    }()
    
    var context: NSManagedObjectContext {
        return persistentContainer.viewContext
    }
}
```

### 4. Encrypted UserDefaults Alternative

**Purpose**: Secure alternative to UserDefaults for sensitive data.

**✅ Secure Implementation**:

```swift
import Foundation
import CryptoKit

class SecureUserDefaults {
    
    private let key: SymmetricKey
    
    init() {
        // Get or create encryption key from Keychain
        if let keyData = KeychainManager.load(key: "userdefaults_key") {
            self.key = SymmetricKey(data: keyData)
        } else {
            self.key = SymmetricKey(size: .bits256)
            let keyData = key.withUnsafeBytes { Data($0) }
            _ = KeychainManager.save(key: "userdefaults_key", data: keyData)
        }
    }
    
    /**
     * Save encrypted value
     */
    func set(_ value: String, forKey key: String) {
        guard let data = value.data(using: .utf8) else { return }
        
        do {
            let encrypted = try AES.GCM.seal(data, using: self.key)
            let combined = encrypted.combined
            UserDefaults.standard.set(combined, forKey: key)
        } catch {
            print("Encryption error: \(error)")
        }
    }
    
    /**
     * Retrieve and decrypt value
     */
    func string(forKey key: String) -> String? {
        guard let combined = UserDefaults.standard.data(forKey: key) else {
            return nil
        }
        
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: combined)
            let decrypted = try AES.GCM.open(sealedBox, using: self.key)
            return String(data: decrypted, encoding: .utf8)
        } catch {
            print("Decryption error: \(error)")
            return nil
        }
    }
    
    /**
     * Remove value
     */
    func removeObject(forKey key: String) {
        UserDefaults.standard.removeObject(forKey: key)
    }
}
```

## Database Encryption

### SQLCipher for Cross-Platform Encryption

**Purpose**: Industry-standard SQLite encryption.

**Android with SQLCipher**:
```kotlin
// Already covered in Android Room Database section above
```

**iOS with SQLCipher**:
```swift
import SQLCipher

class DatabaseManager {
    
    private var database: OpaquePointer?
    
    func openEncryptedDatabase() -> Bool {
        let fileURL = try! FileManager.default
            .url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: false)
            .appendingPathComponent("encrypted.db")
        
        // Open database
        if sqlite3_open(fileURL.path, &database) != SQLITE_OK {
            print("Error opening database")
            return false
        }
        
        // Set encryption key
        let key = getOrCreateEncryptionKey()
        let keyString = key as NSString
        
        if sqlite3_key(database, keyString.utf8String, Int32(keyString.length)) != SQLITE_OK {
            print("Error setting encryption key")
            return false
        }
        
        // Verify key is correct
        if sqlite3_exec(database, "SELECT count(*) FROM sqlite_master;", nil, nil, nil) != SQLITE_OK {
            print("Error: Invalid encryption key")
            return false
        }
        
        return true
    }
    
    private func getOrCreateEncryptionKey() -> String {
        if let keyData = KeychainManager.load(key: "database_key"),
           let key = String(data: keyData, encoding: .utf8) {
            return key
        }
        
        // Generate new key
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        
        if status == errSecSuccess {
            let key = Data(bytes).base64EncodedString()
            _ = KeychainManager.save(key: "database_key", data: key.data(using: .utf8)!)
            return key
        }
        
        fatalError("Failed to generate encryption key")
    }
}
```

## File Encryption

### Custom File Encryption

**Android AES Encryption**:
```kotlin
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.SecretKey

class FileEncryption(private val secretKey: SecretKey) {
    
    private val transformation = "AES/GCM/NoPadding"
    private val ivSize = 12
    private val tagSize = 128
    
    /**
     * Encrypt file
     */
    fun encryptFile(inputFile: File, outputFile: File) {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        
        val iv = cipher.iv
        
        inputFile.inputStream().use { input ->
            outputFile.outputStream().use { output ->
                // Write IV first
                output.write(iv)
                
                // Encrypt and write data
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    val encrypted = cipher.update(buffer, 0, bytesRead)
                    if (encrypted != null) {
                        output.write(encrypted)
                    }
                }
                
                // Write final block
                val finalBlock = cipher.doFinal()
                if (finalBlock != null) {
                    output.write(finalBlock)
                }
            }
        }
    }
    
    /**
     * Decrypt file
     */
    fun decryptFile(inputFile: File, outputFile: File) {
        inputFile.inputStream().use { input ->
            // Read IV
            val iv = ByteArray(ivSize)
            input.read(iv)
            
            val cipher = Cipher.getInstance(transformation)
            val spec = GCMParameterSpec(tagSize, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            
            outputFile.outputStream().use { output ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    val decrypted = cipher.update(buffer, 0, bytesRead)
                    if (decrypted != null) {
                        output.write(decrypted)
                    }
                }
                
                val finalBlock = cipher.doFinal()
                if (finalBlock != null) {
                    output.write(finalBlock)
                }
            }
        }
    }
}
```

## Backup Protection

### Android Backup Exclusion

**AndroidManifest.xml**:
```xml
<application
    android:allowBackup="false"
    android:fullBackupContent="@xml/backup_rules">
    <!-- App components -->
</application>
```

**res/xml/backup_rules.xml**:
```xml
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <!-- Exclude all SharedPreferences -->
    <exclude domain="sharedpref" path="." />
    
    <!-- Exclude specific database -->
    <exclude domain="database" path="sensitive_data.db" />
    
    <!-- Exclude all files directory -->
    <exclude domain="file" path="." />
    
    <!-- Include only specific non-sensitive data -->
    <include domain="file" path="cache/" />
</full-backup-content>
```

### iOS Backup Exclusion

**Exclude files from backup**:
```swift
func excludeFromBackup(url: URL) {
    var resourceValues = URLResourceValues()
    resourceValues.isExcludedFromBackup = true
    
    do {
        var mutableURL = url
        try mutableURL.setResourceValues(resourceValues)
    } catch {
        print("Error excluding from backup: \(error)")
    }
}

// Usage
let fileURL = getDocumentsDirectory().appendingPathComponent("sensitive.db")
excludeFromBackup(url: fileURL)
```

**In Keychain - use device-only accessibility**:
```swift
// Data won't be included in iCloud Keychain backup
kSecAttrAccessibleWhenUnlockedThisDeviceOnly
```

## Additional Security Measures

### 1. Data Minimization

```kotlin
// ❌ Don't do this - storing unnecessary data
data class User(
    val id: String,
    val email: String,
    val password: String,  // NEVER store passwords
    val creditCard: String,  // Don't store full card numbers
    val ssn: String,  // Don't store SSN
    val fullTransactionHistory: List<Transaction>  // Too much data
)

// ✅ Do this - minimize stored data
data class User(
    val id: String,
    val email: String,
    // Password never stored, only hash on server
    val lastFourCardDigits: String,  // Only last 4 digits
    // Recent transactions only, older ones fetched from server
    val recentTransactions: List<Transaction>
)
```

### 2. Data Expiration

```kotlin
class SessionManager(private val securePrefs: SecurePreferences) {
    
    fun saveSession(token: String, expiresIn: Long) {
        val expiryTime = System.currentTimeMillis() + (expiresIn * 1000)
        securePrefs.saveAuthToken(token)
        securePrefs.saveTokenExpiry(expiryTime)
    }
    
    fun getValidToken(): String? {
        val token = securePrefs.getAuthToken()
        val expiry = securePrefs.getTokenExpiry()
        
        if (System.currentTimeMillis() > expiry) {
            // Token expired, clear it
            clearSession()
            return null
        }
        
        return token
    }
    
    fun clearSession() {
        securePrefs.clearAll()
    }
}
```

### 3. Secure Memory Clearing

```kotlin
// Clear sensitive data from memory
fun clearSensitiveData(data: CharArray) {
    Arrays.fill(data, '0')
}

fun clearSensitiveData(data: ByteArray) {
    Arrays.fill(data, 0.toByte())
}

// Usage
val password = "secret123".toCharArray()
// Use password...
clearSensitiveData(password)  // Clear from memory when done
```

### 4. Screenshot Protection

**Android**:
```kotlin
// Prevent screenshots in activities with sensitive data
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    
    // Prevent screenshots
    window.setFlags(
        WindowManager.LayoutParams.FLAG_SECURE,
        WindowManager.LayoutParams.FLAG_SECURE
    )
    
    setContentView(R.layout.activity_main)
}
```

**iOS**:
```swift
// Blur screen when app enters background
func applicationWillResignActive(_ application: UIApplication) {
    // Add blur effect
    let blurEffect = UIBlurEffect(style: .light)
    let blurView = UIVisualEffectView(effect: blurEffect)
    blurView.frame = window!.frame
    blurView.tag = 100  // Tag for later removal
    window?.addSubview(blurView)
}

func applicationDidBecomeActive(_ application: UIApplication) {
    // Remove blur effect
    window?.viewWithTag(100)?.removeFromSuperview()
}
```

### 5. Root/Jailbreak Detection

**Android Root Detection**:
```kotlin
class SecurityChecker {
    
    fun isDeviceRooted(): Boolean {
        return checkBuildTags() || 
               checkSuBinary() || 
               checkSuperuserApk() ||
               checkRootManagementApps()
    }
    
    private fun checkBuildTags(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }
    
    private fun checkSuBinary(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )
        
        return paths.any { File(it).exists() }
    }
    
    private fun checkSuperuserApk(): Boolean {
        return try {
            context.packageManager.getPackageInfo("com.noshufou.android.su", 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }
    
    private fun checkRootManagementApps(): Boolean {
        val packages = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser"
        )
        
        return packages.any { packageExists(it) }
    }
    
    private fun packageExists(packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }
}
```

**iOS Jailbreak Detection**:
```swift
import Foundation
import UIKit

class SecurityChecker {
    
    static func isJailbroken() -> Bool {
        return checkCydiaInstalled() ||
               checkSuspiciousFiles() ||
               checkWriteAccess() ||
               checkFork()
    }
    
    private static func checkCydiaInstalled() -> Bool {
        return UIApplication.shared.canOpenURL(URL(string: "cydia://")!)
    }
    
    private static func checkSuspiciousFiles() -> Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/"
        ]
        
        return paths.contains { FileManager.default.fileExists(atPath: $0) }
    }
    
    private static func checkWriteAccess() -> Bool {
        let testString = "Jailbreak Test"
        let testPath = "/private/jailbreak_test.txt"
        
        do {
            try testString.write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true  // Should not be able to write here
        } catch {
            return false
        }
    }
    
    private static func checkFork() -> Bool {
        // Note: fork() requires importing Darwin
        // On iOS, fork() will fail on non-jailbroken devices
        // This is a simplified check - production code should handle carefully
        #if canImport(Darwin)
        import Darwin
        let result = fork()
        if result >= 0 {
            return true  // fork() should fail on non-jailbroken devices
        }
        #endif
        return false
    }
}
```

## Security Checklist

### Before Release

- [ ] All sensitive data encrypted at rest
- [ ] Using platform secure storage (Keychain/KeyStore)
- [ ] Databases encrypted with SQLCipher or equivalent
- [ ] Sensitive files excluded from backups
- [ ] No sensitive data in logs
- [ ] Screenshot protection implemented for sensitive screens
- [ ] Data expiration mechanisms in place
- [ ] Sensitive data cleared from memory after use
- [ ] Root/jailbreak detection implemented
- [ ] Security testing completed
- [ ] Penetration testing performed
- [ ] Compliance requirements verified (GDPR, HIPAA, PCI-DSS)

### Code Review Questions

1. What sensitive data does this app store?
2. Is each piece of sensitive data encrypted?
3. Are we using the appropriate encryption method?
4. Is the encryption key stored securely?
5. Is sensitive data excluded from backups?
6. Do we clear sensitive data when no longer needed?
7. Have we tested on rooted/jailbroken devices?
8. Are we compliant with relevant regulations?

---

**Next Steps**: See real code examples in [Examples](./examples.md) and practice in the [Lab](./lab/m09-insecure-data-storage-lab/)

*Part of OWASP Mobile Top 10 - Educational Repository*
