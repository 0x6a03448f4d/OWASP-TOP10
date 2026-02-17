# M04: Insufficient Input/Output Validation - Examples

## Table of Contents
- [SQL Injection Examples](#sql-injection-examples)
- [Command Injection Examples](#command-injection-examples)
- [Path Traversal Examples](#path-traversal-examples)
- [XSS in WebView Examples](#xss-in-webview-examples)
- [Integer Overflow Examples](#integer-overflow-examples)
- [Comprehensive Security Patterns](#comprehensive-security-patterns)

## SQL Injection Examples

### Example 1: Authentication Bypass

**❌ Vulnerable Code (Android):**
```java
public boolean authenticateUser(String username, String password) {
    SQLiteDatabase db = dbHelper.getReadableDatabase();
    
    // VULNERABLE - String concatenation
    String query = "SELECT * FROM users WHERE username = '" + username + 
                   "' AND password = '" + password + "'";
    
    Cursor cursor = db.rawQuery(query, null);
    boolean authenticated = cursor.getCount() > 0;
    cursor.close();
    return authenticated;
}

// Attack: username = "admin' --"
// Query becomes: SELECT * FROM users WHERE username = 'admin' --' AND password = ''
// Comment removes password check, authenticates as admin
```

**✅ Secure Code (Android):**
```java
public boolean authenticateUser(String username, String password) {
    SQLiteDatabase db = dbHelper.getReadableDatabase();
    
    // SECURE - Parameterized query
    String query = "SELECT * FROM users WHERE username = ? AND password = ?";
    Cursor cursor = db.rawQuery(query, new String[]{username, password});
    
    boolean authenticated = cursor.getCount() > 0;
    cursor.close();
    return authenticated;
}

// Even with malicious input, it's treated as literal string
// username = "admin' --" looks for user with that exact username
```

**✅ Even Better - Use Query Builder:**
```java
public boolean authenticateUser(String username, String password) {
    SQLiteDatabase db = dbHelper.getReadableDatabase();
    
    String[] columns = {"id"};
    String selection = "username = ? AND password = ?";
    String[] selectionArgs = {username, password};
    
    Cursor cursor = db.query("users", columns, selection, selectionArgs, 
                             null, null, null, "1");
    
    boolean authenticated = cursor.getCount() > 0;
    cursor.close();
    return authenticated;
}
```

### Example 2: Data Extraction

**❌ Vulnerable Code (iOS):**
```swift
func searchUsers(query: String) -> [User] {
    var users: [User] = []
    
    // VULNERABLE - String interpolation
    let sql = "SELECT * FROM users WHERE name LIKE '%\(query)%'"
    
    var statement: OpaquePointer?
    if sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK {
        while sqlite3_step(statement) == SQLITE_ROW {
            // Process results
        }
    }
    sqlite3_finalize(statement)
    return users
}

// Attack: query = "%' UNION SELECT password FROM users WHERE '1'='1"
// Extracts all passwords
```

**✅ Secure Code (iOS):**
```swift
func searchUsers(query: String) -> [User] {
    var users: [User] = []
    
    // SECURE - Parameterized query
    let sql = "SELECT * FROM users WHERE name LIKE ?"
    let searchPattern = "%\(query)%"
    
    var statement: OpaquePointer?
    if sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK {
        sqlite3_bind_text(statement, 1, searchPattern, -1, nil)
        
        while sqlite3_step(statement) == SQLITE_ROW {
            // Process results safely
        }
    }
    sqlite3_finalize(statement)
    return users
}
```

## Command Injection Examples

### Example 3: File Processing

**❌ Vulnerable Code:**
```java
public void convertImage(String filename) {
    try {
        // VULNERABLE - User input directly in command
        String command = "convert " + filename + " output.png";
        Runtime.getRuntime().exec(command);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// Attack: filename = "image.jpg; rm -rf /"
// Executes: convert image.jpg; rm -rf / output.png
// Deletes all files!
```

**✅ Secure Code - Option 1 (Validation):**
```java
public void convertImage(String filename) throws SecurityException {
    // Validate filename
    if (!filename.matches("^[a-zA-Z0-9._-]+\\.(jpg|png|gif)$")) {
        throw new SecurityException("Invalid filename");
    }
    
    // Use array form to prevent shell injection
    try {
        ProcessBuilder pb = new ProcessBuilder("convert", filename, "output.png");
        pb.start();
    } catch (IOException e) {
        throw new RuntimeException("Conversion failed", e);
    }
}
```

**✅ Secure Code - Option 2 (Native API):**
```java
public void convertImage(String filename) {
    // BEST - Use native image processing library instead
    try {
        Bitmap bitmap = BitmapFactory.decodeFile(filename);
        // Process with Android APIs
        FileOutputStream fos = new FileOutputStream("output.png");
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, fos);
        fos.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}
```

## Path Traversal Examples

### Example 4: File Download

**❌ Vulnerable Code:**
```java
@GetMapping("/download")
public ResponseEntity<Resource> downloadFile(@RequestParam String filename) {
    // VULNERABLE - No path validation
    File file = new File("/app/files/" + filename);
    Resource resource = new FileSystemResource(file);
    return ResponseEntity.ok(resource);
}

// Attack: filename = "../../../etc/passwd"
// Downloads: /app/files/../../../etc/passwd → /etc/passwd
```

**✅ Secure Code:**
```java
@GetMapping("/download")
public ResponseEntity<Resource> downloadFile(@RequestParam String filename) 
        throws IOException {
    
    // Define base directory
    File baseDir = new File("/app/files");
    File requestedFile = new File(baseDir, filename);
    
    // Get canonical paths
    String basePath = baseDir.getCanonicalPath();
    String filePath = requestedFile.getCanonicalPath();
    
    // Verify file is within base directory
    if (!filePath.startsWith(basePath + File.separator)) {
        throw new SecurityException("Path traversal attempt detected");
    }
    
    // Additional validation
    if (!requestedFile.exists() || !requestedFile.isFile()) {
        throw new FileNotFoundException("File not found");
    }
    
    Resource resource = new FileSystemResource(requestedFile);
    return ResponseEntity.ok(resource);
}
```

### Example 5: File Upload (iOS)

**❌ Vulnerable Code:**
```swift
func saveUploadedFile(filename: String, data: Data) {
    // VULNERABLE - Direct path construction
    let filePath = documentsDirectory + "/" + filename
    try? data.write(to: URL(fileURLWithPath: filePath))
}

// Attack: filename = "../../../Library/Preferences/com.app.plist"
// Overwrites app preferences
```

**✅ Secure Code:**
```swift
func saveUploadedFile(filename: String, data: Data) throws {
    // Validate filename
    let allowedCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
    guard filename.unicodeScalars.allSatisfy({ allowedCharacters.contains($0) }) else {
        throw FileError.invalidFilename
    }
    
    // Get documents directory
    guard let documentsURL = FileManager.default.urls(
        for: .documentDirectory, 
        in: .userDomainMask
    ).first else {
        throw FileError.directoryNotFound
    }
    
    // Create safe file URL
    let fileURL = documentsURL.appendingPathComponent(filename)
    
    // Verify path is within documents directory
    let documentPath = documentsURL.standardizedFileURL.path
    let filePath = fileURL.standardizedFileURL.path
    
    guard filePath.hasPrefix(documentPath) else {
        throw FileError.pathTraversal
    }
    
    // Save file
    try data.write(to: fileURL)
}
```

## XSS in WebView Examples

### Example 6: WebView Data Display

**❌ Vulnerable Code (Android):**
```java
public void displayUserProfile(String username, String bio) {
    String html = "<html><body>" +
                  "<h1>Welcome " + username + "</h1>" +
                  "<p>Bio: " + bio + "</p>" +
                  "</body></html>";
    
    // VULNERABLE - No encoding
    webView.loadData(html, "text/html", "UTF-8");
}

// Attack: username = "<script>alert(document.cookie)</script>"
// Executes JavaScript in WebView
```

**✅ Secure Code (Android):**
```java
import org.owasp.encoder.Encode;

public void displayUserProfile(String username, String bio) {
    // SECURE - HTML encoding
    String safeUsername = Encode.forHtml(username);
    String safeBio = Encode.forHtml(bio);
    
    String html = "<html><body>" +
                  "<h1>Welcome " + safeUsername + "</h1>" +
                  "<p>Bio: " + safeBio + "</p>" +
                  "</body></html>";
    
    webView.loadData(html, "text/html", "UTF-8");
}

// Attack input gets encoded: &lt;script&gt;alert(document.cookie)&lt;/script&gt;
// Displayed as text, not executed
```

**✅ Better Approach - Template with Encoding:**
```java
public void displayUserProfile(String username, String bio) {
    // Load template
    String template = loadAssetAsString("profile_template.html");
    
    // Encode data
    String safeUsername = Encode.forHtml(username);
    String safeBio = Encode.forHtml(bio);
    
    // Replace placeholders
    String html = template
        .replace("{{username}}", safeUsername)
        .replace("{{bio}}", safeBio);
    
    webView.loadDataWithBaseURL(null, html, "text/html", "UTF-8", null);
}
```

### Example 7: JavaScript Bridge

**❌ Vulnerable Code:**
```java
class JavaScriptInterface {
    @JavascriptInterface
    public void processData(String data) {
        // VULNERABLE - Executing user data
        webView.loadUrl("javascript:updateUI('" + data + "')");
    }
}

// Attack: data = "'); maliciousFunction(); //'"
// Executes: javascript:updateUI(''); maliciousFunction(); //')
```

**✅ Secure Code:**
```java
import org.owasp.encoder.Encode;
import org.json.JSONObject;

class JavaScriptInterface {
    @JavascriptInterface
    public void processData(String data) {
        // SECURE - Use JSON and encoding
        try {
            JSONObject json = new JSONObject();
            json.put("data", data); // Automatically escaped
            
            String safeJson = json.toString();
            
            // Pass as JSON, not string concatenation
            webView.evaluateJavascript(
                "updateUI(" + safeJson + ")", 
                null
            );
        } catch (JSONException e) {
            Log.e("JS", "Error creating JSON", e);
        }
    }
}
```

## Integer Overflow Examples

### Example 8: E-Commerce Calculation

**❌ Vulnerable Code:**
```java
public int calculateTotal(int price, int quantity) {
    // VULNERABLE - No overflow check
    return price * quantity;
}

// Attack: price = 1000000, quantity = 3000
// Result: Overflow, wraps to negative number
// User pays negative amount (gets money back!)
```

**✅ Secure Code - Option 1:**
```java
public int calculateTotal(int price, int quantity) {
    // SECURE - Check for overflow
    try {
        return Math.multiplyExact(price, quantity);
    } catch (ArithmeticException e) {
        throw new IllegalArgumentException("Calculation overflow", e);
    }
}
```

**✅ Secure Code - Option 2:**
```java
public long calculateTotal(int price, int quantity) {
    // SECURE - Use larger type
    long total = (long) price * (long) quantity;
    
    // Verify result is within acceptable range
    if (total > Integer.MAX_VALUE) {
        throw new IllegalArgumentException("Total exceeds maximum value");
    }
    
    return total;
}
```

**✅ Secure Code - Option 3 (Manual Check):**
```java
public int calculateTotal(int price, int quantity) {
    // SECURE - Manual overflow check
    if (quantity > 0 && price > Integer.MAX_VALUE / quantity) {
        throw new IllegalArgumentException("Calculation would overflow");
    }
    
    return price * quantity;
}
```

### Example 9: Age Verification

**❌ Vulnerable Code:**
```java
public boolean isAdult(String ageStr) {
    // VULNERABLE - No validation
    int age = Integer.parseInt(ageStr);
    return age >= 18;
}

// Attack: ageStr = "2147483647"
// Or: ageStr = "-5" (underflow attack on subsequent calculations)
```

**✅ Secure Code:**
```java
public boolean isAdult(String ageStr) {
    try {
        int age = Integer.parseInt(ageStr);
        
        // SECURE - Range validation
        if (age < 0 || age > 150) {
            throw new IllegalArgumentException("Invalid age");
        }
        
        return age >= 18;
    } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Age must be a valid number");
    }
}
```

## Comprehensive Security Patterns

### Example 10: Complete Input Validation Framework

**Validation Utility Class:**
```java
public class SecurityValidator {
    
    // Username validation
    private static final Pattern USERNAME_PATTERN = 
        Pattern.compile("^[a-zA-Z0-9_]{3,20}$");
    
    public static String validateUsername(String username) {
        if (username == null || !USERNAME_PATTERN.matcher(username).matches()) {
            throw new ValidationException("Invalid username format");
        }
        return username;
    }
    
    // Email validation
    private static final Pattern EMAIL_PATTERN = 
        Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$");
    
    public static String validateEmail(String email) {
        if (email == null || !EMAIL_PATTERN.matcher(email).matches()) {
            throw new ValidationException("Invalid email format");
        }
        return email.toLowerCase();
    }
    
    // Integer range validation
    public static int validateIntRange(String value, int min, int max, String fieldName) {
        try {
            int num = Integer.parseInt(value);
            if (num < min || num > max) {
                throw new ValidationException(
                    fieldName + " must be between " + min + " and " + max
                );
            }
            return num;
        } catch (NumberFormatException e) {
            throw new ValidationException(fieldName + " must be a valid number");
        }
    }
    
    // String length validation
    public static String validateLength(String value, int minLen, int maxLen, 
                                       String fieldName) {
        if (value == null) {
            throw new ValidationException(fieldName + " cannot be null");
        }
        if (value.length() < minLen || value.length() > maxLen) {
            throw new ValidationException(
                fieldName + " length must be between " + minLen + " and " + maxLen
            );
        }
        return value;
    }
    
    // Alphanumeric validation
    private static final Pattern ALPHANUMERIC = 
        Pattern.compile("^[a-zA-Z0-9]+$");
    
    public static String validateAlphanumeric(String value, String fieldName) {
        if (value == null || !ALPHANUMERIC.matcher(value).matches()) {
            throw new ValidationException(
                fieldName + " must contain only letters and numbers"
            );
        }
        return value;
    }
    
    // File name validation
    private static final Pattern SAFE_FILENAME = 
        Pattern.compile("^[a-zA-Z0-9._-]+$");
    
    public static String validateFilename(String filename) {
        if (filename == null || !SAFE_FILENAME.matcher(filename).matches()) {
            throw new ValidationException("Invalid filename");
        }
        if (filename.contains("..")) {
            throw new ValidationException("Filename cannot contain '..'");
        }
        return filename;
    }
}
```

### Example 11: Secure API Request Handler

**Complete Secure Implementation:**
```java
public class SecureUserAPI {
    
    private final UserRepository userRepo;
    private final InputValidator validator;
    private final OutputEncoder encoder;
    
    // User registration with comprehensive validation
    public User registerUser(UserRequest request) {
        // Validate all inputs
        String username = SecurityValidator.validateUsername(request.getUsername());
        String email = SecurityValidator.validateEmail(request.getEmail());
        int age = SecurityValidator.validateIntRange(
            request.getAge(), 0, 150, "Age"
        );
        String bio = SecurityValidator.validateLength(
            request.getBio(), 0, 500, "Bio"
        );
        
        // Check for existing user with parameterized query
        if (userRepo.existsByUsername(username)) {
            throw new ConflictException("Username already exists");
        }
        
        // Create user with validated data
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setAge(age);
        user.setBio(bio);
        
        return userRepo.save(user);
    }
    
    // Search with SQL injection prevention
    public List<User> searchUsers(String query) {
        // Validate search query
        String validatedQuery = SecurityValidator.validateLength(
            query, 1, 100, "Search query"
        );
        
        // Use parameterized query through repository
        return userRepo.searchByName(validatedQuery);
    }
    
    // Get user profile with encoding for display
    public UserProfileResponse getUserProfile(String userId) {
        // Validate user ID
        String validatedId = SecurityValidator.validateAlphanumeric(
            userId, "User ID"
        );
        
        User user = userRepo.findById(validatedId)
            .orElseThrow(() -> new NotFoundException("User not found"));
        
        // Encode output for safe display
        UserProfileResponse response = new UserProfileResponse();
        response.setUsername(encoder.encodeForHTML(user.getUsername()));
        response.setEmail(encoder.encodeForHTML(user.getEmail()));
        response.setBio(encoder.encodeForHTML(user.getBio()));
        
        return response;
    }
}
```

### Example 12: Secure File Operations

**Complete File Handler:**
```java
public class SecureFileHandler {
    
    private final File baseDirectory;
    private final Set<String> allowedExtensions;
    
    public SecureFileHandler(String basePath) throws IOException {
        this.baseDirectory = new File(basePath).getCanonicalFile();
        this.allowedExtensions = Set.of("jpg", "png", "pdf", "txt");
        
        if (!baseDirectory.exists()) {
            baseDirectory.mkdirs();
        }
    }
    
    public File getFile(String filename) throws IOException, SecurityException {
        // Validate filename
        String validatedFilename = SecurityValidator.validateFilename(filename);
        
        // Validate extension
        String extension = getExtension(validatedFilename);
        if (!allowedExtensions.contains(extension.toLowerCase())) {
            throw new SecurityException("File type not allowed");
        }
        
        // Create file reference
        File file = new File(baseDirectory, validatedFilename);
        
        // Get canonical path
        String canonicalPath = file.getCanonicalPath();
        String basePath = baseDirectory.getCanonicalPath();
        
        // Verify file is within base directory
        if (!canonicalPath.startsWith(basePath + File.separator)) {
            throw new SecurityException("Path traversal attempt detected");
        }
        
        return file;
    }
    
    public void saveFile(String filename, byte[] data) throws IOException {
        File file = getFile(filename);
        
        // Validate file size
        if (data.length > 10 * 1024 * 1024) { // 10MB limit
            throw new IllegalArgumentException("File too large");
        }
        
        // Write file securely
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }
    
    private String getExtension(String filename) {
        int lastDot = filename.lastIndexOf('.');
        if (lastDot == -1) {
            return "";
        }
        return filename.substring(lastDot + 1);
    }
}
```

## Testing Examples

### Example 13: Unit Tests for Validation

```java
public class SecurityValidatorTest {
    
    @Test
    public void testUsernameValidation_Valid() {
        assertEquals("validuser", SecurityValidator.validateUsername("validuser"));
        assertEquals("user123", SecurityValidator.validateUsername("user123"));
        assertEquals("user_name", SecurityValidator.validateUsername("user_name"));
    }
    
    @Test(expected = ValidationException.class)
    public void testUsernameValidation_TooShort() {
        SecurityValidator.validateUsername("ab");
    }
    
    @Test(expected = ValidationException.class)
    public void testUsernameValidation_TooLong() {
        SecurityValidator.validateUsername("a".repeat(25));
    }
    
    @Test(expected = ValidationException.class)
    public void testUsernameValidation_SpecialChars() {
        SecurityValidator.validateUsername("user@123");
    }
    
    @Test(expected = ValidationException.class)
    public void testUsernameValidation_SQLInjection() {
        SecurityValidator.validateUsername("' OR '1'='1");
    }
    
    @Test(expected = ValidationException.class)
    public void testUsernameValidation_XSS() {
        SecurityValidator.validateUsername("<script>alert(1)</script>");
    }
    
    @Test
    public void testIntegerRange_Valid() {
        assertEquals(25, SecurityValidator.validateIntRange("25", 0, 100, "Age"));
        assertEquals(0, SecurityValidator.validateIntRange("0", 0, 100, "Age"));
        assertEquals(100, SecurityValidator.validateIntRange("100", 0, 100, "Age"));
    }
    
    @Test(expected = ValidationException.class)
    public void testIntegerRange_BelowMin() {
        SecurityValidator.validateIntRange("-1", 0, 100, "Age");
    }
    
    @Test(expected = ValidationException.class)
    public void testIntegerRange_AboveMax() {
        SecurityValidator.validateIntRange("101", 0, 100, "Age");
    }
}
```

## Quick Reference

### Vulnerable vs Secure Patterns

| Vulnerability | ❌ Vulnerable | ✅ Secure |
|--------------|--------------|-----------|
| SQL Injection | String concatenation | Parameterized queries |
| Command Injection | `Runtime.exec(cmd + input)` | `ProcessBuilder` with validation |
| Path Traversal | `new File(path + filename)` | Canonicalize + validate path |
| XSS | Direct HTML insertion | HTML encoding |
| Integer Overflow | `price * quantity` | `Math.multiplyExact()` |
| Input Validation | No validation | Whitelist regex + range checks |

## Key Takeaways

1. **Always validate on server-side, client-side is for UX only**
2. **Use parameterized queries, never concatenate SQL**
3. **Whitelist allowed input patterns**
4. **Encode output based on context**
5. **Canonicalize file paths and validate boundaries**
6. **Check for integer overflow in calculations**
7. **Use safe APIs instead of system commands**
8. **Test with malicious inputs**

## Next Steps

- **[Interactive Lab](./lab/)**: Practice identifying and fixing validation vulnerabilities
- **[Back to Overview](./overview.md)**: Review core concepts
- **[Attack Vectors](./attack-vectors.md)**: Understand attack methods
- **[Prevention](./prevention.md)**: Comprehensive security guide

---

**Remember**: Never trust user input. Validate everything, encode all output, use safe APIs.
