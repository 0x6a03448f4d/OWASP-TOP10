# M04: Insufficient Input/Output Validation - Overview

## Table of Contents
- [What is Insufficient Input/Output Validation?](#what-is-insufficient-inputoutput-validation)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Insufficient Input/Output Validation?

**Insufficient Input/Output Validation** occurs when mobile applications fail to properly validate, sanitize, and encode data coming into the application (input) or going out to users/systems (output). This vulnerability allows attackers to inject malicious data that can compromise the app, its users, or backend systems.

Mobile apps receive input from multiple sources:
- User input (forms, search boxes, file uploads)
- URL schemes and deep links
- QR codes and NFC data
- Push notifications and webhooks
- API responses and third-party data
- Clipboard and shared data
- Intent/URL parameters (Android/iOS)

### Core Concept

Input validation ensures data meets expected format and constraints before processing:

```
Input Source → Validation → Sanitization → Processing → Output Encoding
     ↓              ↓            ↓              ↓              ↓
  Untrusted    Check Format  Remove Bad    Safe Use    Prevent XSS
   Data         & Type        Characters    of Data     & Injection
```

### Key Vulnerability Points

1. **SQL Injection**: Unvalidated input in database queries
2. **Cross-Site Scripting (XSS)**: Unescaped output in WebViews
3. **Command Injection**: Unsanitized input in system commands
4. **Path Traversal**: Unvalidated file paths
5. **XML/JSON Injection**: Malformed data parsing
6. **Deep Link Exploitation**: Unvalidated URL scheme parameters
7. **Intent Injection** (Android): Malicious intent data
8. **Deserialization Attacks**: Unsafe object deserialization

## Why Does This Matter?

### The Business Impact

- **Data Breaches**: SQL injection exposing entire databases
- **Account Takeover**: XSS stealing credentials and session tokens
- **System Compromise**: Command injection enabling remote code execution
- **Reputation Damage**: Public disclosure of injection vulnerabilities
- **Compliance Violations**: PCI-DSS, GDPR requirements for data validation
- **Financial Loss**: Fraud via manipulated transactions

### For Users

- Personal data exposure through SQL injection
- Account compromise via stolen credentials
- Malware installation through WebView exploits
- Financial fraud from manipulated payment data
- Privacy violations from data exfiltration
- Device compromise in severe cases

## Technical Context

### Common Injection Types

**1. SQL Injection**
```
User Input: admin' OR '1'='1
Query: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='...'
Result: Authentication bypass
```

**2. Cross-Site Scripting (XSS)**
```
User Input: <script>alert(document.cookie)</script>
WebView Display: Executes JavaScript, steals cookies
Result: Session hijacking
```

**3. Path Traversal**
```
User Input: ../../etc/passwd
File Access: app/data/../../etc/passwd
Result: Unauthorized file access
```

**4. Deep Link Injection**
```
Malicious Link: myapp://transfer?amount=1000&to=attacker
App: Executes transfer without validation
Result: Unauthorized transaction
```

### Attack Surface

Mobile apps have unique input vectors:

```
External Inputs:
├── User Interface (Text fields, forms)
├── Deep Links/URL Schemes
├── QR Codes
├── NFC Tags
├── Push Notifications
├── Shared Intents (Android)
├── Universal Links (iOS)
├── Clipboard Data
├── File Imports
└── API Responses

Each requires validation!
```

## Real-World Impact

### Notable Incidents

**Mobile Banking SQL Injection (2022)**
- Unvalidated input in transaction search
- Attacker extracted customer database
- 500,000 records compromised
- Impact: $8M fine, regulatory action

**E-Commerce XSS in WebView (2023)**
- Product description field allowed HTML
- Attacker injected credential-stealing script
- 50,000+ users affected
- Impact: Payment credentials stolen, app removed from store

**Ride-Sharing Deep Link Exploit (2021)**
- Deep link parameters not validated
- Attacker manipulated ride destination and price
- Free rides and wrong destinations
- Impact: $500K fraud, emergency patch

**Healthcare App Path Traversal (2022)**
- File download feature allowed ../ in filename
- Accessed patient records outside authorized scope
- HIPAA violation
- Impact: $2.5M fine, mandatory security audit

### Financial Impact

- Average cost of injection attack: $3.2M
- SQL injection accounts for 65% of data breaches
- XSS vulnerabilities present in 40% of mobile apps
- Mean time to detect injection attack: 197 days

## Prevalence and Statistics

### Current State (2024)

- **78%** of mobile apps have at least one input validation vulnerability
- **42%** vulnerable to SQL injection (when using local SQLite)
- **53%** vulnerable to XSS in WebViews
- **31%** have path traversal vulnerabilities
- **67%** don't validate deep link parameters
- **89%** don't sanitize data from third-party APIs

### Industry Breakdown

**Finance/Banking:**
- 34% have SQL injection vulnerabilities
- 56% validate input but not output
- High compliance requirements driving improvements

**E-Commerce:**
- 71% vulnerable to XSS
- 43% have deep link validation issues
- Payment processing requires strict validation

**Healthcare:**
- 45% have input validation gaps
- HIPAA compliance requires comprehensive validation
- Legacy integrations create challenges

**Social Media:**
- 82% vulnerable to XSS
- User-generated content is major challenge
- Rich media handling creates attack surface

## Common Misunderstandings

### Myth vs Reality

**Myth**: "We use HTTPS, so we're protected from injection"
**Reality**: HTTPS only encrypts transmission. It doesn't validate or sanitize data content.

**Myth**: "Input validation on the client-side is enough"
**Reality**: Client-side validation is for UX. Security validation must happen server-side as clients can be bypassed.

**Myth**: "We use an ORM, so SQL injection is impossible"
**Reality**: ORMs reduce risk but don't eliminate it. Raw queries, dynamic queries, and ORM misuse can still lead to SQL injection.

**Myth**: "Mobile apps don't have XSS issues"
**Reality**: WebViews are common in mobile apps and are highly vulnerable to XSS if not properly secured.

**Myth**: "We only accept data from our own API"
**Reality**: APIs can be called by attackers. All data from any source should be validated, including your own API.

### What This Isn't

- ❌ Just about SQL injection
- ❌ Only a server-side concern
- ❌ Solved by using prepared statements alone
- ❌ Only about malicious users

### What This Is

- ✅ Validating ALL input from ANY source
- ✅ Encoding/escaping ALL output to users
- ✅ Defense in depth across client and server
- ✅ Protecting against both malicious and accidental bad data
- ✅ Type checking, format validation, and boundary checking

## Key Vulnerability Categories

### 1. Database Injection

**Characteristics:**
- Unvalidated input used in SQL queries
- Dynamic query construction
- Insufficient use of parameterized queries
- ORM misuse with raw queries

**Impact:** Complete database compromise, data theft, data modification

### 2. Cross-Site Scripting (XSS)

**Characteristics:**
- Unescaped user input displayed in WebViews
- HTML/JavaScript injection in hybrid apps
- Insufficient Content Security Policy
- document.write() with user data

**Impact:** Session theft, phishing, credential harvesting, malware distribution

### 3. Path Traversal

**Characteristics:**
- Unvalidated file paths
- Directory traversal sequences (../)
- Insufficient path canonicalization
- Missing access control on file operations

**Impact:** Unauthorized file access, data exposure, system file reading

### 4. Command Injection

**Characteristics:**
- User input in system commands
- Shell command execution
- Insufficient escaping of special characters
- exec() or system() with user data

**Impact:** Remote code execution, system compromise, data theft

### 5. Deep Link Injection

**Characteristics:**
- Unvalidated URL scheme parameters
- Missing authorization on deep link actions
- Intent injection on Android
- Universal Link exploitation on iOS

**Impact:** Unauthorized actions, CSRF, data manipulation, phishing

### 6. Deserialization Vulnerabilities

**Characteristics:**
- Deserializing untrusted data
- Insufficient type validation
- Allowing arbitrary class instantiation
- Missing integrity checks

**Impact:** Remote code execution, object injection, denial of service

## Input Validation Principles

### 1. Trust Boundary

```
Everything outside your application is untrusted:
- User input
- File contents
- Network data
- URL parameters
- Intent extras
- Clipboard data
- QR codes
- API responses (even your own API!)
```

### 2. Validation Layers

```
Client-Side Validation:
└── For user experience (immediate feedback)

Server-Side Validation:
└── For security (cannot be bypassed)

Database Layer:
└── For data integrity (constraints, types)
```

### 3. Validation Types

**Whitelisting (Preferred):**
- Define what IS allowed
- Reject everything else
- Example: Only allow [a-zA-Z0-9]

**Blacklisting (Avoid):**
- Define what IS NOT allowed
- Allow everything else  
- Easy to bypass, incomplete protection

## Output Encoding Principles

### Context-Specific Encoding

Different contexts require different encoding:

```
HTML Context: &lt; &gt; &amp; &quot; &#x27;
JavaScript Context: \x3C \x3E \x26 \x22 \x27
URL Context: %3C %3E %26 %22 %27
SQL Context: '' (escape single quotes)
Command Context: Avoid or use libraries
```

## Key Takeaways

1. **Validate ALL input from ANY source - never trust external data**
2. **Server-side validation is mandatory - client-side is for UX only**
3. **Use whitelisting over blacklisting when possible**
4. **Encode output based on context (HTML, JavaScript, URL, SQL)**
5. **Use parameterized queries/prepared statements for database access**
6. **Validate deep links and URL scheme parameters**
7. **Implement Content Security Policy in WebViews**
8. **Sanitize data from third-party APIs and services**

## Next Steps

After understanding the overview, proceed to:
1. **[Attack Vectors](./attack-vectors.md)** - Learn how injection attacks work
2. **[Prevention](./prevention.md)** - Implement proper input/output validation
3. **[Examples](./examples.md)** - See vulnerable vs secure code
4. **[Interactive Lab](./lab/)** - Practice exploiting and fixing validation issues

---

**Remember**: All input is evil until proven innocent. Validate, sanitize, and encode everywhere.
