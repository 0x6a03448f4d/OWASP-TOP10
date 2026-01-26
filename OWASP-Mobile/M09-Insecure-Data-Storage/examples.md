# M09: Insecure Data Storage - Examples

## Table of Contents
- [Vulnerable Examples](#vulnerable-examples)
- [Secure Examples](#secure-examples)
- [Common Patterns](#common-patterns)
- [Framework-Specific Examples](#framework-specific-examples)
- [Migration Examples](#migration-examples)

## Vulnerable Examples

### ❌ Example 1: Plain Text SharedPreferences (Android)

**Vulnerable Code**:
```java
public class LoginManager {
    private SharedPreferences prefs;
    
    public LoginManager(Context context) {
        // VULNERABLE: Using default SharedPreferences
        this.prefs = context.getSharedPreferences("user_prefs", Context.MODE_PRIVATE);
    }
    
    public void saveUserCredentials(String email, String password) {
        // VULNERABLE: Storing credentials in plain text
        prefs.edit()
            .putString("user_email", email)
            .putString("user_password", password)  // PASSWORD IN PLAIN TEXT!
            .apply();
    }
    
    public void saveAuthToken(String token) {
        // VULNERABLE: Token stored unencrypted
        prefs.edit()
            .putString("auth_token", token)
            .apply();
    }
    
    public void saveApiKey(String apiKey) {
        // VULNERABLE: API key accessible to anyone with device access
        prefs.edit()
            .putString("api_key", apiKey)
            .apply();
    }
}
```

**Why It's Vulnerable**:
- SharedPreferences stored as XML in `/data/data/com.app/shared_prefs/user_prefs.xml`
- Completely readable on rooted devices
- Included in ADB backups by default
- Accessible via simple `adb backup` command
- No encryption whatsoever

**Attack Result**:
```xml
<!-- /data/data/com.app/shared_prefs/user_prefs.xml -->
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="user_email">john.doe@email.com</string>
    <string name="user_password">MySecretPassword123</string>
    <string name="auth_token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</string>
    <string name="api_key">sk_live_51H7h8dK2eZvN9vZpQ</string>
</map>
```

### ❌ Example 2: Unencrypted UserDefaults (iOS)

**Vulnerable Code**:
```swift
class UserManager {
    let defaults = UserDefaults.standard
    
    func saveCredentials(email: String, password: String) {
        // VULNERABLE: Storing sensitive data in UserDefaults
        defaults.set(email, forKey: "user_email")
        defaults.set(password, forKey: "user_password")  // PLAIN TEXT PASSWORD!
        defaults.synchronize()
    }
    
    func saveAuthToken(_ token: String) {
        // VULNERABLE: Token in plain text
        defaults.set(token, forKey: "auth_token")
    }
    
    func saveCreditCard(number: String, cvv: String) {
        // VULNERABLE: Payment data unencrypted
        defaults.set(number, forKey: "card_number")
        defaults.set(cvv, forKey: "card_cvv")
    }
}
```

**Why It's Vulnerable**:
- Stored as property list file: `Library/Preferences/com.app.plist`
- Readable on jailbroken devices
- Included in iTunes/iCloud backups
- No encryption applied
- Accessible via simple tools

**Attack Result**:
```bash
# On jailbroken device or from backup
plutil -p com.app.plist

{
  "user_email" => "victim@email.com"
  "user_password" => "SecretPass123"
  "auth_token" => "eyJhbGciOiJIUzI1NiIs..."
  "card_number" => "4532123456781234"
  "card_cvv" => "123"
}
```

### ❌ Example 3: Unencrypted SQLite Database (Android)

**Vulnerable Code**:
```kotlin
class DatabaseHelper(context: Context) : SQLiteOpenHelper(
    context, 
    "userdata.db",  // VULNERABLE: Unencrypted database
    null, 
    1
) {
    override fun onCreate(db: SQLiteDatabase) {
        // VULNERABLE: Sensitive data in plain text database
        db.execSQL("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                email TEXT,
                password TEXT,
                ssn TEXT,
                credit_card TEXT,
                cvv TEXT,
                api_key TEXT
            )
        """)
    }
    
    fun saveUser(email: String, password: String, ssn: String, 
                 cardNumber: String, cvv: String, apiKey: String) {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("email", email)
            put("password", password)  // PLAIN TEXT!
            put("ssn", ssn)  // HIGHLY SENSITIVE!
            put("credit_card", cardNumber)  // PCI-DSS VIOLATION!
            put("cvv", cvv)
            put("api_key", apiKey)
        }
        db.insert("users", null, values)
    }
}
```

**Why It's Vulnerable**:
- SQLite database stored unencrypted at `/data/data/com.app/databases/userdata.db`
- Trivial to access on rooted devices
- Included in backups
- Standard SQLite tools can open it
- All data in plain text

**Attack Result**:
```bash
# On rooted device
adb shell
su
cd /data/data/com.app/databases/
sqlite3 userdata.db

sqlite> SELECT * FROM users;
1|john@email.com|Password123|123-45-6789|4532123456781234|123|sk_live_51H7...
```

### ❌ Example 4: Files on External Storage (Android)

**Vulnerable Code**:
```kotlin
class FileManager(private val context: Context) {
    
    fun saveUserData(userData: String) {
        // VULNERABLE: Writing to external storage
        val file = File(
            Environment.getExternalStorageDirectory(),
            "MyApp/userdata.txt"
        )
        
        file.parentFile?.mkdirs()
        file.writeText(userData)  // WORLD-READABLE!
    }
    
    fun saveBackup(backupData: String) {
        // VULNERABLE: SD card storage
        val file = File(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
            "app_backup.json"
        )
        file.writeText(backupData)
    }
}
```

**Why It's Vulnerable**:
- External storage is world-readable
- Any app with `READ_EXTERNAL_STORAGE` permission can access
- Persists even after app uninstall
- Easily accessible via USB connection
- No protection whatsoever

### ❌ Example 5: Logging Sensitive Data

**Vulnerable Code**:
```java
public class AuthenticationService {
    private static final String TAG = "AuthService";
    
    public void login(String email, String password) {
        // VULNERABLE: Logging credentials
        Log.d(TAG, "Login attempt for: " + email);
        Log.d(TAG, "Password: " + password);  // PASSWORD IN LOGS!
        
        try {
            String authToken = authenticate(email, password);
            Log.d(TAG, "Authentication successful. Token: " + authToken);  // TOKEN IN LOGS!
            
            saveToken(authToken);
        } catch (Exception e) {
            Log.e(TAG, "Login failed: " + e.getMessage(), e);
        }
    }
    
    public void processPayment(String cardNumber, String cvv) {
        // VULNERABLE: Logging payment data
        Log.d(TAG, "Processing payment for card: " + cardNumber);  // CARD NUMBER IN LOGS!
        Log.d(TAG, "CVV: " + cvv);  // CVV IN LOGS!
    }
}
```

**Why It's Vulnerable**:
- Logs visible in Logcat to all apps during development
- Logs may be sent to crash reporting services
- May persist in log files on device
- Third-party analytics SDKs may capture logs

### ❌ Example 6: Base64 "Encryption" (Common Anti-Pattern)

**Vulnerable Code**:
```kotlin
class "SecureStorage" {  // NOT SECURE!
    
    fun savePassword(password: String) {
        // VULNERABLE: Base64 is encoding, NOT encryption
        val "encrypted" = Base64.encodeToString(
            password.toByteArray(), 
            Base64.DEFAULT
        )
        
        val prefs = context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE)
        prefs.edit().putString("password", "encrypted").apply()
    }
    
    fun getPassword(): String {
        val prefs = context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE)
        val "encrypted" = prefs.getString("password", "")
        
        // VULNERABLE: Trivially reversible
        return String(Base64.decode("encrypted", Base64.DEFAULT))
    }
}
```

**Why It's Vulnerable**:
- Base64 is encoding, not encryption
- Reversible with single command: `echo "encodedString" | base64 -d`
- Provides zero security
- False sense of security

## Secure Examples

### ✅ Example 1: EncryptedSharedPreferences (Android)

**Secure Code**:
```kotlin
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SecureStorage(private val context: Context) {
    
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    
    private val encryptedPrefs = EncryptedSharedPreferences.create(
        context,
        "secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
    
    fun saveAuthToken(token: String) {
        encryptedPrefs.edit()
            .putString("auth_token", token)
            .apply()
    }
    
    fun getAuthToken(): String? {
        return encryptedPrefs.getString("auth_token", null)
    }
    
    fun clearAll() {
        encryptedPrefs.edit().clear().apply()
    }
}

// Usage
val storage = SecureStorage(context)
storage.saveAuthToken("eyJhbGciOiJIUzI1NiIs...")
val token = storage.getAuthToken()
```

**Why It's Secure**:
- Both keys and values encrypted
- Uses Android Keystore for key management
- Hardware-backed encryption on supported devices
- Transparent encryption/decryption

### ✅ Example 2: iOS Keychain (iOS)

**Secure Code**:
```swift
import Security
import Foundation

class KeychainManager {
    
    enum KeychainError: Error {
        case duplicateEntry
        case unknown(OSStatus)
    }
    
    static func save(key: String, data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        if status == errSecDuplicateItem {
            // Update existing item
            let attributesToUpdate: [String: Any] = [
                kSecValueData as String: data
            ]
            
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: key
            ]
            
            SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
        } else if status != errSecSuccess {
            throw KeychainError.unknown(status)
        }
    }
    
    static func load(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        return status == errSecSuccess ? result as? Data : nil
    }
    
    static func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// Usage
let token = "eyJhbGciOiJIUzI1NiIs...".data(using: .utf8)!
try? KeychainManager.save(key: "auth_token", data: token)

if let tokenData = KeychainManager.load(key: "auth_token") {
    let tokenString = String(data: tokenData, encoding: .utf8)
}

KeychainManager.delete(key: "auth_token")
```

**Why It's Secure**:
- Hardware-backed encryption
- Isolated storage per app
- Can require biometric authentication
- Not included in backups (with proper accessibility level)

### ✅ Example 3: Encrypted SQLite Database (Android)

**Secure Code**:
```kotlin
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SupportFactory

@Database(entities = [User::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun userDao(): UserDao
}

class SecureDatabaseManager(private val context: Context) {
    
    fun createDatabase(): AppDatabase {
        // Get encryption key from secure storage
        val passphrase = getOrCreateDatabaseKey()
        val factory = SupportFactory(SQLiteDatabase.getBytes(passphrase))
        
        return Room.databaseBuilder(
            context,
            AppDatabase::class.java,
            "encrypted_db"
        )
        .openHelperFactory(factory)
        .build()
    }
    
    private fun getOrCreateDatabaseKey(): CharArray {
        val secureStorage = SecureStorage(context)
        var key = secureStorage.getDatabaseKey()
        
        if (key == null) {
            key = generateSecureKey()
            secureStorage.saveDatabaseKey(key)
        }
        
        return key.toCharArray()
    }
    
    private fun generateSecureKey(): String {
        val random = SecureRandom()
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }
}

@Entity(tableName = "users")
data class User(
    @PrimaryKey val id: Int,
    val email: String,
    val phoneNumber: String
)

@Dao
interface UserDao {
    @Query("SELECT * FROM users WHERE id = :userId")
    fun getUser(userId: Int): User?
    
    @Insert
    fun insert(user: User)
}

// Usage
val dbManager = SecureDatabaseManager(context)
val database = dbManager.createDatabase()
val userDao = database.userDao()

userDao.insert(User(1, "user@email.com", "+1234567890"))
```

**Why It's Secure**:
- Entire database encrypted with SQLCipher
- Encryption key stored in Android Keystore
- Transparent encryption/decryption
- Industry-standard AES-256 encryption

### ✅ Example 4: iOS Core Data with Encryption

**Secure Code**:
```swift
import CoreData

class CoreDataManager {
    
    static let shared = CoreDataManager()
    
    lazy var persistentContainer: NSPersistentContainer = {
        let container = NSPersistentContainer(name: "AppModel")
        
        guard let description = container.persistentStoreDescriptions.first else {
            fatalError("Failed to get persistent store description")
        }
        
        // Enable file protection
        description.setOption(
            FileProtectionType.complete as NSObject,
            forKey: NSPersistentStoreFileProtectionKey
        )
        
        // Exclude from backup
        description.setOption(
            true as NSNumber,
            forKey: NSPersistentStoreRemoveStoreOnCleanup
        )
        
        container.loadPersistentStores { storeDescription, error in
            if let error = error {
                fatalError("Failed to load store: \(error)")
            }
        }
        
        return container
    }()
    
    var context: NSManagedObjectContext {
        return persistentContainer.viewContext
    }
    
    func saveContext() {
        if context.hasChanges {
            do {
                try context.save()
            } catch {
                print("Error saving context: \(error)")
            }
        }
    }
}

// Usage
let context = CoreDataManager.shared.context

let user = User(context: context)
user.email = "user@email.com"
user.phoneNumber = "+1234567890"

CoreDataManager.shared.saveContext()
```

**Why It's Secure**:
- File-level encryption with Data Protection
- Encrypted when device locked
- Excluded from backups (with proper configuration)

### ✅ Example 5: Secure File Storage (Android)

**Secure Code**:
```kotlin
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File

class SecureFileManager(private val context: Context) {
    
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    
    fun writeEncryptedFile(filename: String, content: String) {
        val file = File(context.filesDir, filename)
        
        val encryptedFile = EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
        
        encryptedFile.openFileOutput().use { output ->
            output.write(content.toByteArray())
        }
    }
    
    fun readEncryptedFile(filename: String): String {
        val file = File(context.filesDir, filename)
        
        val encryptedFile = EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
        
        return encryptedFile.openFileInput().use { input ->
            input.readBytes().toString(Charset.defaultCharset())
        }
    }
}

// Usage
val fileManager = SecureFileManager(context)
fileManager.writeEncryptedFile("sensitive_data.txt", "Confidential information")
val content = fileManager.readEncryptedFile("sensitive_data.txt")
```

### ✅ Example 6: Secure File Storage (iOS)

**Secure Code**:
```swift
import Foundation
import CryptoKit

class SecureFileManager {
    
    static func writeProtectedFile(filename: String, data: Data) throws {
        let fileURL = getDocumentsDirectory().appendingPathComponent(filename)
        
        // Write with complete file protection
        try data.write(
            to: fileURL,
            options: [.completeFileProtection, .atomic]
        )
        
        // Exclude from backup
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try fileURL.setResourceValues(resourceValues)
    }
    
    static func readProtectedFile(filename: String) throws -> Data {
        let fileURL = getDocumentsDirectory().appendingPathComponent(filename)
        return try Data(contentsOf: fileURL)
    }
    
    private static func getDocumentsDirectory() -> URL {
        FileManager.default.urls(
            for: .documentDirectory, 
            in: .userDomainMask
        )[0]
    }
}

// Usage
let sensitiveData = "Confidential information".data(using: .utf8)!
try? SecureFileManager.writeProtectedFile(filename: "data.txt", data: sensitiveData)

if let data = try? SecureFileManager.readProtectedFile(filename: "data.txt") {
    let content = String(data: data, encoding: .utf8)
}
```

## Common Patterns

### Pattern 1: Session Token Management

**❌ Insecure**:
```kotlin
// Storing session token in SharedPreferences
val prefs = getSharedPreferences("app", Context.MODE_PRIVATE)
prefs.edit().putString("session_token", token).apply()
```

**✅ Secure**:
```kotlin
// Using EncryptedSharedPreferences with expiration
class SessionManager(context: Context) {
    private val secureStorage = SecureStorage(context)
    
    fun saveSession(token: String, expiresIn: Long) {
        val expiryTime = System.currentTimeMillis() + (expiresIn * 1000)
        secureStorage.saveAuthToken(token)
        secureStorage.saveTokenExpiry(expiryTime)
    }
    
    fun getValidToken(): String? {
        val token = secureStorage.getAuthToken() ?: return null
        val expiry = secureStorage.getTokenExpiry()
        
        if (System.currentTimeMillis() > expiry) {
            clearSession()
            return null
        }
        
        return token
    }
    
    fun clearSession() {
        secureStorage.clearAll()
    }
}
```

### Pattern 2: User Profile Data

**❌ Insecure**:
```swift
// Storing profile in UserDefaults
let defaults = UserDefaults.standard
defaults.set(email, forKey: "email")
defaults.set(phone, forKey: "phone")
defaults.set(address, forKey: "address")
```

**✅ Secure**:
```swift
// Store non-sensitive data in UserDefaults, sensitive in Keychain
struct UserProfile: Codable {
    let userId: String
    let displayName: String
    // Sensitive data stored separately in Keychain
}

class ProfileManager {
    func saveProfile(_ profile: UserProfile, phone: String) {
        // Non-sensitive data in UserDefaults
        if let encoded = try? JSONEncoder().encode(profile) {
            UserDefaults.standard.set(encoded, forKey: "profile")
        }
        
        // Sensitive data in Keychain
        if let phoneData = phone.data(using: .utf8) {
            try? KeychainManager.save(key: "user_phone", data: phoneData)
        }
    }
    
    func loadProfile() -> (profile: UserProfile?, phone: String?) {
        var profile: UserProfile?
        if let data = UserDefaults.standard.data(forKey: "profile") {
            profile = try? JSONDecoder().decode(UserProfile.self, from: data)
        }
        
        var phone: String?
        if let phoneData = KeychainManager.load(key: "user_phone") {
            phone = String(data: phoneData, encoding: .utf8)
        }
        
        return (profile, phone)
    }
}
```

### Pattern 3: Caching API Responses

**❌ Insecure**:
```kotlin
// Caching sensitive data in plain text file
fun cacheResponse(endpoint: String, response: String) {
    val file = File(context.cacheDir, "${endpoint.hashCode()}.json")
    file.writeText(response)
}
```

**✅ Secure**:
```kotlin
// Encrypted cache with TTL
class SecureCache(private val context: Context) {
    private val fileManager = SecureFileManager(context)
    
    data class CacheEntry(
        val data: String,
        val timestamp: Long,
        val ttl: Long
    )
    
    fun cache(key: String, data: String, ttlSeconds: Long = 3600) {
        val entry = CacheEntry(data, System.currentTimeMillis(), ttlSeconds * 1000)
        val json = Gson().toJson(entry)
        fileManager.writeEncryptedFile("cache_$key", json)
    }
    
    fun get(key: String): String? {
        return try {
            val json = fileManager.readEncryptedFile("cache_$key")
            val entry = Gson().fromJson(json, CacheEntry::class.java)
            
            if (System.currentTimeMillis() - entry.timestamp > entry.ttl) {
                delete(key)
                null
            } else {
                entry.data
            }
        } catch (e: Exception) {
            null
        }
    }
    
    fun delete(key: String) {
        File(context.filesDir, "cache_$key").delete()
    }
}
```

## Framework-Specific Examples

### React Native Secure Storage

**✅ Secure - Using react-native-keychain**:
```javascript
import * as Keychain from 'react-native-keychain';

// Save credentials
async function saveCredentials(username, password) {
  await Keychain.setGenericPassword(username, password, {
    accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

// Retrieve credentials
async function getCredentials() {
  const credentials = await Keychain.getGenericPassword();
  if (credentials) {
    return {
      username: credentials.username,
      password: credentials.password,
    };
  }
  return null;
}

// Clear credentials
async function clearCredentials() {
  await Keychain.resetGenericPassword();
}
```

### Flutter Secure Storage

**✅ Secure - Using flutter_secure_storage**:
```dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureStorageService {
  final storage = FlutterSecureStorage();
  
  Future<void> saveAuthToken(String token) async {
    await storage.write(
      key: 'auth_token',
      value: token,
      aOptions: AndroidOptions(
        encryptedSharedPreferences: true,
      ),
      iOptions: IOSOptions(
        accessibility: KeychainAccessibility.first_unlock_this_device,
      ),
    );
  }
  
  Future<String?> getAuthToken() async {
    return await storage.read(key: 'auth_token');
  }
  
  Future<void> deleteAll() async {
    await storage.deleteAll();
  }
}
```

### Xamarin Secure Storage

**✅ Secure - Using Xamarin.Essentials**:
```csharp
using Xamarin.Essentials;

public class SecureStorageService
{
    public async Task SaveAuthTokenAsync(string token)
    {
        await SecureStorage.SetAsync("auth_token", token);
    }
    
    public async Task<string> GetAuthTokenAsync()
    {
        return await SecureStorage.GetAsync("auth_token");
    }
    
    public void ClearAll()
    {
        SecureStorage.RemoveAll();
    }
}
```

## Migration Examples

### Migrating from Plain to Encrypted Storage

**Android Migration**:
```kotlin
class StorageMigration(private val context: Context) {
    
    fun migrateToEncryptedStorage() {
        val oldPrefs = context.getSharedPreferences("old_prefs", Context.MODE_PRIVATE)
        val secureStorage = SecureStorage(context)
        
        // Migrate auth token
        oldPrefs.getString("auth_token", null)?.let { token ->
            secureStorage.saveAuthToken(token)
        }
        
        // Migrate other sensitive data
        oldPrefs.getString("api_key", null)?.let { key ->
            secureStorage.saveApiKey(key)
        }
        
        // Clear old data
        oldPrefs.edit().clear().apply()
        
        // Mark migration complete
        secureStorage.setMigrationComplete(true)
    }
    
    fun isMigrationNeeded(): Boolean {
        val secureStorage = SecureStorage(context)
        return !secureStorage.isMigrationComplete()
    }
}

// In Application onCreate()
val migration = StorageMigration(this)
if (migration.isMigrationNeeded()) {
    migration.migrateToEncryptedStorage()
}
```

**iOS Migration**:
```swift
class StorageMigration {
    
    static func migrateToKeychain() {
        let defaults = UserDefaults.standard
        
        // Migrate auth token
        if let token = defaults.string(forKey: "auth_token") {
            let tokenData = token.data(using: .utf8)!
            try? KeychainManager.save(key: "auth_token", data: tokenData)
            defaults.removeObject(forKey: "auth_token")
        }
        
        // Migrate API key
        if let apiKey = defaults.string(forKey: "api_key") {
            let keyData = apiKey.data(using: .utf8)!
            try? KeychainManager.save(key: "api_key", data: keyData)
            defaults.removeObject(forKey: "api_key")
        }
        
        // Mark migration complete
        defaults.set(true, forKey: "keychain_migration_complete")
    }
    
    static func isMigrationNeeded() -> Bool {
        return !UserDefaults.standard.bool(forKey: "keychain_migration_complete")
    }
}

// In AppDelegate
if StorageMigration.isMigrationNeeded() {
    StorageMigration.migrateToKeychain()
}
```

## Key Takeaways

### Do's ✅
- Use EncryptedSharedPreferences (Android) or Keychain (iOS)
- Encrypt databases with SQLCipher
- Use Data Protection API for files (iOS)
- Exclude sensitive data from backups
- Implement data expiration
- Clear sensitive data on logout
- Use hardware-backed encryption when available

### Don'ts ❌
- Never store passwords in plain text
- Don't use Base64 as encryption
- Avoid SharedPreferences/UserDefaults for sensitive data
- Don't write sensitive data to external storage
- Never log sensitive information
- Don't trust obfuscation as security
- Avoid storing unnecessary sensitive data

---

**Next Step**: Practice these concepts in the [Lab](./lab/m09-insecure-data-storage-lab/)

*Part of OWASP Mobile Top 10 - Educational Repository*
