# M04: Insufficient Input/Output Validation - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Input Validation Best Practices](#input-validation-best-practices)
- [Output Encoding Techniques](#output-encoding-techniques)
- [Secure Coding Patterns](#secure-coding-patterns)
- [Implementation Guidelines](#implementation-guidelines)
- [Testing and Verification](#testing-and-verification)

## Prevention Strategy Overview

Preventing input/output validation vulnerabilities requires a defense-in-depth approach:

```
Defense Layers:
1. Input Validation → Whitelist acceptable input
2. Parameterization → Use prepared statements
3. Output Encoding → Context-aware encoding
4. Least Privilege → Minimize permissions
5. Security Testing → Regular validation testing
```

### Core Principles

1. **Never trust user input** - All external data is potentially malicious
2. **Validate on server-side** - Client validation is for UX only
3. **Whitelist over blacklist** - Define what's allowed, not what's forbidden
4. **Context-aware encoding** - Encode based on where data is used
5. **Fail securely** - Invalid input should be rejected, not processed

## Input Validation Best Practices

### 1. Validation Strategies

**Whitelist Validation (Preferred):**
```python
# Define allowed characters/patterns
allowed_username_pattern = r'^[a-zA-Z0-9_]{3,20}$'

def validate_username(username):
    if not re.match(allowed_username_pattern, username):
        raise ValueError("Invalid username format")
    return username
```

**Type Validation:**
```python
def validate_age(age_str):
    try:
        age = int(age_str)
        if not (0 < age < 150):
            raise ValueError("Age out of range")
        return age
    except ValueError:
        raise ValueError("Age must be a valid number")
```

**Length Validation:**
```python
def validate_input_length(data, max_length=100):
    if len(data) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")
    return data
```

### 2. SQL Injection Prevention

**✅ ALWAYS Use Parameterized Queries:**

**Android (SQLite):**
```java
// SECURE - Parameterized query
String query = "SELECT * FROM users WHERE username = ? AND password = ?";
Cursor cursor = db.rawQuery(query, new String[]{username, password});

// SECURE - Using query builder
SQLiteDatabase db = dbHelper.getReadableDatabase();
String[] columns = {"id", "username", "email"};
String selection = "username = ?";
String[] selectionArgs = {username};
Cursor cursor = db.query("users", columns, selection, selectionArgs, null, null, null);
```

**iOS (Core Data / SQLite):**
```swift
// SECURE - Parameterized predicate
let fetchRequest = NSFetchRequest<User>(entityName: "User")
fetchRequest.predicate = NSPredicate(format: "username == %@ AND password == %@", 
                                     username, password)

// SECURE - SQLite with binding
let query = "SELECT * FROM users WHERE username = ? AND password = ?"
var statement: OpaquePointer?
sqlite3_prepare_v2(db, query, -1, &statement, nil)
sqlite3_bind_text(statement, 1, username, -1, nil)
sqlite3_bind_text(statement, 2, password, -1, nil)
```

**❌ NEVER Concatenate SQL:**
```java
// VULNERABLE - String concatenation
String query = "SELECT * FROM users WHERE username = '" + username + "'";
// Attacker input: ' OR '1'='1
```

### 3. Command Injection Prevention

**Avoid System Command Execution:**
```java
// AVOID if possible
Runtime.getRuntime().exec("ls " + filename); // VULNERABLE

// PREFERRED - Use native APIs
File directory = new File(path);
File[] files = directory.listFiles();
```

**If System Commands Required:**
```java
// Whitelist validation
private boolean isValidFilename(String filename) {
    return filename.matches("^[a-zA-Z0-9._-]+$");
}

// Use command arrays (prevents shell injection)
if (isValidFilename(filename)) {
    ProcessBuilder pb = new ProcessBuilder("cat", filename);
    pb.redirectErrorStream(true);
    Process process = pb.start();
}
```

### 4. Path Traversal Prevention

**Secure File Access:**
```java
// Validate and canonicalize paths
public File getSecureFile(String userFilename) throws IOException {
    // Define base directory
    File baseDir = new File("/app/data/userfiles");
    
    // Create file object
    File userFile = new File(baseDir, userFilename);
    
    // Get canonical paths
    String basePath = baseDir.getCanonicalPath();
    String filePath = userFile.getCanonicalPath();
    
    // Verify file is within base directory
    if (!filePath.startsWith(basePath + File.separator)) {
        throw new SecurityException("Path traversal attempt detected");
    }
    
    return userFile;
}
```

**iOS Secure File Access:**
```swift
func getSecureFile(filename: String) throws -> URL {
    // Get documents directory
    guard let documentsDir = FileManager.default.urls(for: .documentDirectory, 
                                                      in: .userDomainMask).first else {
        throw FileError.invalidDirectory
    }
    
    // Create file URL
    let fileURL = documentsDir.appendingPathComponent(filename)
    
    // Resolve canonical path
    let canonicalPath = fileURL.standardizedFileURL.path
    let basePath = documentsDir.standardizedFileURL.path
    
    // Verify within bounds
    guard canonicalPath.hasPrefix(basePath) else {
        throw FileError.pathTraversal
    }
    
    return fileURL
}
```

### 5. XML/JSON Validation

**Disable Dangerous XML Features:**
```java
// Disable XXE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(inputStream);
```

**JSON Schema Validation:**
```java
// Define schema
String schema = """
{
  "type": "object",
  "properties": {
    "username": {"type": "string", "minLength": 3, "maxLength": 20},
    "email": {"type": "string", "format": "email"},
    "age": {"type": "integer", "minimum": 0, "maximum": 150}
  },
  "required": ["username", "email"],
  "additionalProperties": false
}
""";

// Validate JSON against schema
JSONObject jsonSchema = new JSONObject(schema);
JSONObject jsonSubject = new JSONObject(userInput);
Schema validationSchema = SchemaLoader.load(jsonSchema);
validationSchema.validate(jsonSubject); // Throws if invalid
```

### 6. Integer Overflow Prevention

**Safe Integer Operations:**
```java
// Check for overflow before arithmetic
public int safeAdd(int a, int b) throws ArithmeticException {
    if (a > 0 && b > Integer.MAX_VALUE - a) {
        throw new ArithmeticException("Integer overflow");
    }
    if (a < 0 && b < Integer.MIN_VALUE - a) {
        throw new ArithmeticException("Integer underflow");
    }
    return a + b;
}

// Or use built-in methods (Java 8+)
int result = Math.addExact(quantity, additionalItems); // Throws on overflow

// For multiplication
long totalPrice = Math.multiplyExact((long)price, (long)quantity);
if (totalPrice > Integer.MAX_VALUE) {
    throw new ArithmeticException("Price calculation overflow");
}
```

**Swift Safe Arithmetic:**
```swift
// Use overflow operators to detect
let (sum, overflow) = quantity.addingReportingOverflow(additionalItems)
if overflow {
    throw CalculationError.integerOverflow
}

// Or use checked arithmetic
guard let total = Int(exactly: price * quantity) else {
    throw CalculationError.integerOverflow
}
```

### 7. Regular Expression Safety

**Prevent ReDoS (Regular Expression Denial of Service):**
```java
// VULNERABLE - Catastrophic backtracking
String vulnerable = "^(a+)+$";
// Input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" causes exponential time

// SECURE - Simple, efficient pattern
String secure = "^[a-zA-Z0-9]{3,20}$";

// Set timeout for regex execution
Pattern pattern = Pattern.compile(regex);
Matcher matcher = pattern.matcher(input);
matcher.usePattern(pattern);
// In practice, use simple patterns and limit input length
```

## Output Encoding Techniques

### 1. HTML Encoding

**Prevent XSS in WebViews:**
```java
// Android - Use TextUtils for HTML encoding
public String encodeForHTML(String input) {
    return TextUtils.htmlEncode(input);
}

// Or use OWASP Java Encoder
import org.owasp.encoder.Encode;
String safe = Encode.forHtml(userInput);
webView.loadData(template.replace("{{USER_DATA}}", safe), "text/html", "UTF-8");
```

**iOS HTML Encoding:**
```swift
extension String {
    func htmlEncoded() -> String {
        guard let data = self.data(using: .utf8) else { return self }
        let options: [NSAttributedString.DocumentReadingOptionKey: Any] = [
            .documentType: NSAttributedString.DocumentType.html,
            .characterEncoding: String.Encoding.utf8.rawValue
        ]
        guard let attributedString = try? NSAttributedString(data: data, 
                                                              options: options, 
                                                              documentAttributes: nil) else {
            return self
        }
        return attributedString.string
    }
}
```

### 2. JavaScript Context Encoding

**Safe JavaScript Data Injection:**
```java
// Encode for JavaScript context
import org.owasp.encoder.Encode;
String jsData = Encode.forJavaScript(userInput);
webView.loadUrl("javascript:processData('" + jsData + "')");

// Better: Use postMessage API
String json = new JSONObject()
    .put("data", userInput)
    .toString();
webView.evaluateJavascript("window.postMessage(" + json + ", '*')", null);
```

### 3. URL Encoding

**Encode URL Parameters:**
```java
// Java/Android
String encoded = URLEncoder.encode(userInput, "UTF-8");
String url = "https://api.example.com/search?q=" + encoded;

// iOS/Swift
let encoded = userInput.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
let url = "https://api.example.com/search?q=\(encoded ?? "")"
```

### 4. SQL Encoding (Defense in Depth)

**Note:** Use parameterized queries primarily, encoding as additional layer:
```java
// Escape special SQL characters (backup defense only)
public String escapeSql(String input) {
    return input.replace("'", "''")
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_");
}
```

## Secure Coding Patterns

### 1. Input Validation Framework

**Create Reusable Validators:**
```java
public class InputValidator {
    
    public static String validateUsername(String username) {
        if (username == null || !username.matches("^[a-zA-Z0-9_]{3,20}$")) {
            throw new ValidationException("Invalid username format");
        }
        return username;
    }
    
    public static String validateEmail(String email) {
        if (email == null || !email.matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
            throw new ValidationException("Invalid email format");
        }
        return email;
    }
    
    public static int validateIntRange(String value, int min, int max) {
        try {
            int num = Integer.parseInt(value);
            if (num < min || num > max) {
                throw new ValidationException("Value out of range");
            }
            return num;
        } catch (NumberFormatException e) {
            throw new ValidationException("Invalid number format");
        }
    }
}
```

### 2. Centralized Encoding Utilities

```java
public class EncodingUtils {
    
    public static String forHTML(String input) {
        return Encode.forHtml(input);
    }
    
    public static String forJavaScript(String input) {
        return Encode.forJavaScript(input);
    }
    
    public static String forURL(String input) {
        try {
            return URLEncoder.encode(input, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 not supported", e);
        }
    }
    
    public static String forSQL(String input) {
        // Note: Use parameterized queries instead
        return input.replace("'", "''");
    }
}
```

### 3. Safe WebView Configuration

**Android WebView Security:**
```java
WebView webView = findViewById(R.id.webview);
WebSettings settings = webView.getSettings();

// Disable JavaScript if not needed
settings.setJavaScriptEnabled(false);

// If JavaScript needed, configure safely
settings.setJavaScriptEnabled(true);
settings.setAllowFileAccess(false);
settings.setAllowContentAccess(false);
settings.setAllowFileAccessFromFileURLs(false);
settings.setAllowUniversalAccessFromFileURLs(false);

// Implement secure JavaScript interface
webView.addJavascriptInterface(new SafeJavaScriptInterface(), "Android");

class SafeJavaScriptInterface {
    @JavascriptInterface
    public String getData(String input) {
        // Validate input before processing
        String validated = InputValidator.validateInput(input);
        return processData(validated);
    }
}
```

**iOS WKWebView Security:**
```swift
let configuration = WKWebViewConfiguration()

// Disable JavaScript if not needed
configuration.preferences.javaScriptEnabled = false

// If JavaScript needed, configure message handlers safely
let contentController = WKUserContentController()
contentController.add(self, name: "messageHandler")
configuration.userContentController = contentController

let webView = WKWebView(frame: .zero, configuration: configuration)

// Handle messages with validation
func userContentController(_ userContentController: WKUserContentController, 
                          didReceive message: WKScriptMessage) {
    guard let body = message.body as? [String: Any],
          let action = body["action"] as? String else {
        return
    }
    
    // Validate action
    let validatedAction = validateAction(action)
    processAction(validatedAction)
}
```

## Implementation Guidelines

### 1. Validation Checklist

**For Every Input:**
- [ ] Validate data type
- [ ] Check length constraints
- [ ] Validate format (regex, schema)
- [ ] Check range constraints
- [ ] Whitelist allowed characters
- [ ] Sanitize special characters
- [ ] Validate on server-side

### 2. Encoding Checklist

**For Every Output:**
- [ ] Identify context (HTML, JS, URL, SQL)
- [ ] Apply context-appropriate encoding
- [ ] Use established encoding libraries
- [ ] Test with XSS payloads
- [ ] Validate encoded output

### 3. Code Review Checklist

**Security Review Points:**
- [ ] No string concatenation in SQL queries
- [ ] All user input validated server-side
- [ ] Output encoded based on context
- [ ] No system command execution with user input
- [ ] File paths canonicalized and validated
- [ ] Integer operations checked for overflow
- [ ] Regular expressions are efficient
- [ ] Error messages don't leak sensitive data

## Testing and Verification

### 1. Input Fuzzing

**Test Cases:**
```
# SQL Injection
' OR '1'='1
'; DROP TABLE users--
' UNION SELECT password--

# XSS
<script>alert(1)</script>
"><script>alert(1)</script>
javascript:alert(1)

# Path Traversal
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
....//....//....//

# Command Injection
; ls -la
| whoami
`cat /etc/passwd`

# XML/JSON
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
{"key": "value\", \"admin\": true, \"key2\": \""}

# Integer Overflow
2147483647
-2147483648

# Buffer Overflow
A x 10000 characters
```

### 2. Automated Testing

**Security Testing Tools:**
- OWASP ZAP - Automated vulnerability scanning
- Burp Suite - Manual and automated testing
- SQLMap - SQL injection testing
- Frida - Dynamic instrumentation
- MobSF - Mobile security framework

### 3. Unit Tests for Validation

```java
@Test
public void testUsernameValidation() {
    // Valid inputs
    assertTrue(InputValidator.isValidUsername("user123"));
    assertTrue(InputValidator.isValidUsername("test_user"));
    
    // Invalid inputs
    assertFalse(InputValidator.isValidUsername("user@123")); // Special chars
    assertFalse(InputValidator.isValidUsername("ab")); // Too short
    assertFalse(InputValidator.isValidUsername("a".repeat(30))); // Too long
    assertFalse(InputValidator.isValidUsername("'; DROP TABLE users--")); // SQLi attempt
}

@Test
public void testSQLInjectionPrevention() {
    String maliciousInput = "' OR '1'='1";
    
    // Should safely handle in parameterized query
    List<User> users = userDao.findByUsername(maliciousInput);
    
    // Should return empty or specific user, not all users
    assertTrue(users.isEmpty() || users.size() == 1);
}
```

## Quick Reference Guide

### Input Validation

| Input Type | Validation Method |
|-----------|------------------|
| Username | Regex: `^[a-zA-Z0-9_]{3,20}$` |
| Email | Regex + DNS check |
| Phone | Regex for format, length check |
| Number | Parse + range check |
| Date | Parse with strict format |
| File path | Canonicalize + boundary check |
| URL | Parse + whitelist domain |

### Output Encoding

| Context | Encoding Method |
|---------|----------------|
| HTML | `Encode.forHtml()` |
| JavaScript | `Encode.forJavaScript()` |
| URL | `URLEncoder.encode()` |
| SQL | Parameterized queries (not encoding) |
| XML | XML library encoding |
| JSON | JSON library serialization |

## Key Takeaways

1. **Validate all input on server-side, never trust client**
2. **Use parameterized queries for database operations**
3. **Encode output based on context (HTML, JS, URL)**
4. **Whitelist acceptable input patterns**
5. **Canonicalize and validate file paths**
6. **Use safe APIs instead of system commands**
7. **Test with malicious inputs regularly**
8. **Implement defense-in-depth**

## Resources

**Libraries:**
- [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/)
- [OWASP Validation Regex Repository](https://owasp.org/www-community/OWASP_Validation_Regex_Repository)

**Tools:**
- [OWASP ZAP](https://www.zaproxy.org/)
- [Burp Suite](https://portswigger.net/burp)
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

## Next Steps

- **[Examples](./examples.md)**: See vulnerable vs secure code implementations
- **[Interactive Lab](./lab/)**: Practice input validation attacks and defenses

---

**Remember**: Defense-in-depth: validate input, encode output, use safe APIs, test thoroughly.
