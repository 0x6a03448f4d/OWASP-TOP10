# OWASP Top 10 - Complete Reference Guide

> Comprehensive guide to OWASP Top 10 vulnerabilities across all categories: Web, API, Mobile, and LLM.
> 
> **For interactive web version, see:** [index.html](index.html)

---

## 📚 About OWASP Top 10

The OWASP (Open Web Application Security Project) Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the **most critical security risks** to different types of applications.

This repository covers **four major OWASP Top 10 categories:**

1. **Web Application Security** - Traditional web vulnerabilities
2. **API Security** - REST and GraphQL API-specific risks  
3. **Mobile Security** - Mobile application vulnerabilities
4. **LLM Security** - Large Language Model specific risks (NEW)

---

## 🌐 OWASP Web Application Security Risks (2021)

### 1. Broken Access Control
**Risk Level:** CRITICAL | **Rank:** #1 | **CWE Mappings:** 34

Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.

**Common Vulnerabilities:**
- Bypassing access control checks by modifying the URL, internal application state, or HTML page
- Allowing the primary key to be changed to another user's record
- Elevation of privilege (acting as a user without being logged in or acting as an admin)
- Metadata manipulation (replaying or tampering JWT tokens or cookies)
- CORS misconfiguration allows unauthorized API access

**How to Prevent:**
- Deny by default except for public resources
- Implement access control mechanisms once and re-use throughout the application
- Model access controls should enforce record ownership
- Unique application business limit requirements should be enforced by domain models
- Disable web server directory listing
- Log access control failures, alert admins when appropriate
- Rate limit API and controller access to minimize the harm from automated attack tooling
- JWT tokens should be invalidated on the server after logout

**Example Attack:**
```sql
-- URL: https://example.com/app/accountInfo?acct=12345
-- Attacker modifies 'acct' parameter:
https://example.com/app/accountInfo?acct=67890
-- Now accessing another user's account information
```

**Lab:** See `OWASP-Web/01-Broken-Access-Control/`

---

### 2. Cryptographic Failures
**Risk Level:** HIGH | **Rank:** #2 | **Previously:** Sensitive Data Exposure

The first thing is to determine the protection needs of data in transit and at rest. Passwords, credit card numbers, health records, personal information, and business secrets require extra protection, mainly if that data falls under privacy laws or regulations.

**Common Vulnerabilities:**
- Data transmitted in clear text (HTTP, SMTP, FTP)
- Old or weak cryptographic algorithms used
- Default crypto keys in use
- Missing or improper encryption
- User agent (browser) security directives or headers missing or not properly set
- Server certificate and trust chain not properly validated

**How to Prevent:**
- Classify data processed, stored, or transmitted
- Apply controls per classification
- Don't store sensitive data unnecessarily
- Encrypt all sensitive data at rest
- Ensure up-to-date and strong algorithms and keys; use proper key management
- Encrypt all data in transit with secure protocols (TLS)
- Disable caching for responses containing sensitive data
- Use authenticated encryption instead of just encryption

**Example Weak Code:**
```python
# BAD: Using deprecated algorithm
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)

# GOOD: Using strong algorithm
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM)
```

**Lab:** See `OWASP-Web/02-Cryptographic-Failures/`

---

### 3. Injection
**Risk Level:** HIGH | **Rank:** #3 | **CWE Mappings:** 33

An application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized. Hostile data is used within object-relational mapping (ORM) search parameters to extract additional, sensitive records.

**Common Vulnerabilities:**
- SQL Injection
- NoSQL Injection  
- OS Command Injection
- LDAP Injection
- Expression Language (EL) or Object Graph Navigation Library (OGNL) Injection

**How to Prevent:**
- Use safe API which avoids use of interpreter entirely
- Use positive server-side input validation
- For any residual dynamic queries, escape special characters
- Use LIMIT and other SQL controls within queries
- Use parameterized queries/prepared statements
- Never concatenate user input directly into queries

**SQL Injection Example:**
```python
# VULNERABLE CODE
username = request.GET['username']
query = f"SELECT * FROM users WHERE username = '{username}'"
results = db.execute(query)

# Attacker input: admin' OR '1'='1
# Results in: SELECT * FROM users WHERE username = 'admin' OR '1'='1'

# SECURE CODE
username = request.GET['username']
query = "SELECT * FROM users WHERE username = %s"
results = db.execute(query, (username,))
```

**Lab:** See `OWASP-Web/03-Injection/`

---

### 4. Insecure Design
**Risk Level:** HIGH | **Rank:** #4 | **NEW in 2021**

Insecure design is a broad category representing different weaknesses, expressed as "missing or ineffective control design." One of the factors that contribute to insecure design is the lack of business risk profiling inherent in the software or system being developed.

**Common Issues:**
- Missing or ineffective control design
- Failure to model threats
- Missing security requirements
- Insufficient security in design patterns
- Lack of security principles in architecture

**How to Prevent:**
- Establish and use a secure development lifecycle with AppSec professionals
- Establish and use a library of secure design patterns or paved road ready to use components
- Use threat modeling for critical authentication, access control, business logic, and key flows
- Integrate security language and controls into user stories
- Integrate plausibility checks at each tier of your application
- Write unit and integration tests to validate that all critical flows are resistant to the threat model
- Segregate tier layers on the system and network layers depending on the exposure and protection needs
- Design tenants robustly across all tiers

**Examples:**
- A credential recovery workflow might include "questions and answers," which is prohibited by NIST 800-63b
- A cinema chain allows group booking discounts and has a maximum of fifteen attendees before requiring a deposit. Attackers could threat model this flow and test if they could book six hundred seats

**Lab:** See `OWASP-Web/04-Insecure-Design/`

---

### 5. Security Misconfiguration
**Risk Level:** HIGH | **Rank:** #5 | **Very Common**

The application might be vulnerable if the application is:
- Missing appropriate security hardening across any part of the application stack
- Improperly configured permissions on cloud services
- Unnecessary features enabled or installed
- Default accounts and their passwords still enabled and unchanged
- Error handling reveals stack traces or other overly informative error messages
- Latest security features are disabled or not configured securely

**How to Prevent:**
- A repeatable hardening process makes it fast and easy to deploy another environment that is properly locked down
- A minimal platform without any unnecessary features, components, documentation, and samples
- A task to review and update configurations appropriate to all security notes, updates, and patches
- A segmented application architecture provides effective and secure separation between components or tenants
- Sending security directives to clients (e.g., Security Headers)
- An automated process to verify the effectiveness of configurations in all environments

**Common Misconfigurations:**
```xml
<!-- BAD: Verbose error messages -->
<customErrors mode="Off"/>

<!-- GOOD: Custom error pages -->
<customErrors mode="On" defaultRedirect="~/Error"/>
```

**Lab:** See `OWASP-Web/05-Security-Misconfiguration/`

---

### 6. Vulnerable and Outdated Components
**Risk Level:** HIGH | **Rank:** #6

You are likely vulnerable if you do not know the versions of all components you use. This includes components you directly use as well as nested dependencies. If the software is vulnerable, unsupported, or out of date.

**Common Issues:**
- Using components with known vulnerabilities (CVEs)
- Not scanning for vulnerabilities regularly
- Not upgrading the underlying platform, frameworks, and dependencies in a timely fashion
- Software developers do not test compatibility of updated, upgraded, or patched libraries
- Not securing components' configurations

**How to Prevent:**
- Remove unused dependencies, unnecessary features, components, files, and documentation
- Continuously inventory versions of both client-side and server-side components and their dependencies
- Monitor sources like Common Vulnerability and Exposures (CVE) and National Vulnerability Database (NVD)
- Use tools like OWASP Dependency Check, retire.js, etc.
- Only obtain components from official sources over secure links
- Monitor for libraries and components that are unmaintained or do not create security patches

**Tools:**
- OWASP Dependency-Check
- Snyk
- npm audit
- pip-audit
- GitHub Dependabot

**Lab:** See `OWASP-Web/06-Vulnerable-Components/`

---

### 7. Identification and Authentication Failures
**Risk Level:** HIGH | **Rank:** #7 | **Previously:** Broken Authentication

Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.

**Common Vulnerabilities:**
- Permits automated attacks such as credential stuffing
- Permits brute force or other automated attacks
- Permits default, weak, or well-known passwords
- Uses weak or ineffective credential recovery
- Uses plain text, encrypted, or weakly hashed passwords
- Missing or ineffective multi-factor authentication
- Exposes session identifier in the URL
- Does not rotate session identifier after successful login
- Does not properly invalidate session IDs

**How to Prevent:**
- Implement multi-factor authentication
- Do not ship or deploy with any default credentials
- Implement weak password checks
- Align password length, complexity, and rotation policies with NIST 800-63b guidelines
- Limit or increasingly delay failed login attempts
- Use a server-side, secure, built-in session manager
- Session IDs should not be in the URL
- Session IDs should timeout and be invalidated after logout

**Example Secure Login:**
```python
# Secure authentication implementation
from werkzeug.security import check_password_hash
from flask_login import login_user
import pyotp

def authenticate(username, password, mfa_code):
    user = User.query.filter_by(username=username).first()
    
    # Check password
    if not user or not check_password_hash(user.password_hash, password):
        # Log failed attempt
        log_failed_login(username)
        return False
    
    # Check MFA
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(mfa_code):
        return False
    
    # Successful login
    login_user(user)
    return True
```

**Lab:** See `OWASP-Web/07-Authentication-Failures/`

---

### 8. Software and Data Integrity Failures
**Risk Level:** HIGH | **Rank:** #8 | **NEW in 2021**

Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs).

**Common Vulnerabilities:**
- Applications that update without integrity verification
- Insecure deserialization
- CI/CD pipeline without proper access control
- Auto-update functionality where updates are downloaded without verification
- SolarWinds Orion attack - supply chain attack

**How to Prevent:**
- Use digital signatures or similar mechanisms to verify software or data is from expected source and has not been altered
- Ensure libraries and dependencies, such as npm or Maven, are consuming trusted repositories
- Use software supply chain security tool such as OWASP Dependency Check or OWASP CycloneDX
- Ensure there is a review process for code and configuration changes
- Ensure your CI/CD pipeline has proper segregation, configuration, and access control
- Don't send unsigned or unencrypted serialized data to untrusted clients

**Insecure Deserialization Example:**
```python
# VULNERABLE: Pickle deserialization
import pickle
data = pickle.loads(user_input)  # DANGEROUS!

# SECURE: Use JSON with validation
import json
from marshmallow import Schema, fields

class UserSchema(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)

data = json.loads(user_input)
validated_data = UserSchema().load(data)
```

**Lab:** See `OWASP-Web/08-Software-Data-Integrity/`

---

### 9. Security Logging and Monitoring Failures
**Risk Level:** MEDIUM | **Rank:** #9

Returning to the OWASP Top 10 2021, this category helps detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected.

**Common Issues:**
- Auditable events not logged (logins, failed logins, high-value transactions)
- Warnings and errors generate no, inadequate, or unclear log messages
- Logs of applications and APIs are not monitored for suspicious activity
- Logs only stored locally
- Appropriate alerting thresholds and escalation processes not in place
- Penetration testing and scans do not trigger alerts

**How to Prevent:**
- Ensure all login, access control, and server-side input validation failures can be logged with sufficient user context
- Ensure logs are generated in a format that log management solutions can easily consume
- Ensure log data is encoded correctly to prevent injections or attacks on the logging systems
- Ensure high-value transactions have an audit trail with integrity controls
- DevSecOps teams should establish effective monitoring and alerting
- Establish or adopt an incident response and recovery plan

**What to Log:**
```python
import logging

logger = logging.getLogger(__name__)

# Log authentication events
logger.info(f"Successful login: user={username}, ip={ip_address}")
logger.warning(f"Failed login attempt: user={username}, ip={ip_address}")

# Log authorization failures
logger.warning(f"Unauthorized access attempt: user={username}, resource={resource}")

# Log security events
logger.error(f"SQL Injection attempt detected: user={username}, input={user_input}")

# Log high-value transactions
logger.info(f"Transaction: user={username}, amount={amount}, type={type}")
```

**Lab:** See `OWASP-Web/09-Security-Logging-Failures/`

---

### 10. Server-Side Request Forgery (SSRF)
**Risk Level:** MEDIUM | **Rank:** #10 | **NEW in 2021**

SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.

**Common Vulnerabilities:**
- Accessing internal services behind firewall
- Scanning internal network
- Reading local files using file:// protocol
- Accessing cloud metadata services
- Bypassing other security controls

**How to Prevent:**
- Sanitize and validate all client-supplied input data
- Enforce the URL schema, port, and destination with a positive allow list
- Disable HTTP redirections
- Be aware of URL consistency to avoid attacks such as DNS rebinding
- Do not deploy other security relevant services on front systems
- Use network segmentation to separate resource access
- For frontends with dedicated and manageable user groups, use network encryption on independent systems

**SSRF Attack Example:**
```python
# VULNERABLE CODE
import requests
url = request.GET['url']
response = requests.get(url)  # Can access internal services!

# Attacker input: http://localhost:8080/admin
# Or: http://169.254.169.254/latest/meta-data/  (AWS metadata)

# SECURE CODE
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']

url = request.GET['url']
parsed = urlparse(url)

# Validate schema
if parsed.scheme not in ['http', 'https']:
    raise ValueError("Invalid URL schema")

# Validate host
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("Host not allowed")

response = requests.get(url, allow_redirects=False, timeout=5)
```

**Lab:** See `OWASP-Web/10-SSRF/`

---

## 🔌 OWASP API Security Top 10 (2023)

### API1: Broken Object Level Authorization (BOLA)

APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues. Object level authorization checks should be considered in every function that accesses a data source using an ID from the user.

**Example:**
```
GET /api/users/123/orders
# Attacker changes to different user ID:
GET /api/users/456/orders
```

**Prevention:**
- Implement a proper authorization mechanism
- Use random and unpredictable values as GUIDs for records' IDs
- Write tests to evaluate the vulnerability
- Don't rely on user input for authorization decisions

**Lab:** See `OWASP-API/API01-Broken-Object-Level-Authorization/`

---

### API2: Broken Authentication

Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or to exploit implementation flaws to assume other user's identities temporarily or permanently.

**Prevention:**
- Know all the possible flows to authenticate to the API
- Don't reinvent the wheel in authentication, use standards
- Implement multi-factor authentication
- Implement anti-brute force mechanisms
- Implement weak-password checks
- Use the API keys - they should not be used for user authentication

**Lab:** See `OWASP-API/API02-Broken-Authentication/`

---

### API3: Broken Object Property Level Authorization

This category combines API3:2019 Excessive Data Exposure and API6:2019 - Mass Assignment, focusing on the root cause: the lack of or improper authorization validation at the object property level.

**Prevention:**
- Avoid using generic methods like `to_json()` and `to_dict()`
- Define specific schemas for the data you need to return
- If you need to support old API versions, implement a mechanism to properly map properties
- Enforce response data schema
- Keep returned data structures to the bare minimum

**Lab:** See `OWASP-API/API03-Broken-Object-Property-Level-Authorization/`

---

### API4: Unrestricted Resource Consumption

Satisfying API requests requires resources such as network bandwidth, CPU, memory, and storage. The amount of resources required to satisfy a request greatly depends on the user input and endpoint business logic.

**Prevention:**
- Define and enforce a maximum size on all incoming parameters and payloads
- Limit how often a client can call the API within a defined timeframe (rate limiting)
- Add proper server-side validation for query string and request body parameters
- Define and enforce maximum size for data elements
- Set maximum execution time for operations

**Lab:** See `OWASP-API/API04-Unrestricted-Resource-Consumption/`

---

### API5: Broken Function Level Authorization

Complex access control policies with different hierarchies, groups, and roles, and an unclear separation between administrative and regular functions, tend to lead to authorization flaws.

**Prevention:**
- Deny all access by default
- Implement proper role-based access control (RBAC)
- Make sure administrative functions have separate controllers
- Implement automated testing to cover functional authorization

**Lab:** See `OWASP-API/API05-Broken-Function-Level-Authorization/`

---

### API6: Unrestricted Access to Sensitive Business Flows

APIs vulnerable to this risk expose a business flow without compensating for how the functionality could harm the business if used excessively in an automated manner.

**Prevention:**
- Identify business flows that might harm the business if excessively used
- Choose protection mechanisms based on business and technical needs
- Implement rate limiting per user and per business flow
- Add CAPTCHA for sensitive operations
- Monitor and analyze API traffic patterns

**Lab:** See `OWASP-API/API06-Unrestricted-Access-Sensitive-Business-Flows/`

---

### API7: Server Side Request Forgery

Server-Side Request Forgery (SSRF) flaws can occur when an API is fetching a remote resource without validating the user-supplied URI.

**Prevention:**
- Isolate the resource fetching mechanism in your network
- Validate and sanitize all user-supplied information
- Enforce URL schema, port, and destination with a positive allow list
- Disable HTTP redirections
- Use a well-tested URL parser to avoid URL parsing inconsistencies

**Lab:** See `OWASP-API/API07-Server-Side-Request-Forgery/`

---

### API8: Security Misconfiguration

APIs and the systems supporting them typically contain complex configurations meant to make them more customizable. Software and DevOps engineers can miss these configurations, or don't follow security best practices.

**Prevention:**
- Review configurations across the entire API stack
- Implement repeatable hardening process
- Remove unnecessary features and frameworks
- Implement segmented application architecture
- Have an automated process to continuously assess configurations
- Ensure API can only be accessed by specified HTTP verbs

**Lab:** See `OWASP-API/API08-Security-Misconfiguration/`

---

### API9: Improper Inventory Management

APIs tend to expose more endpoints than traditional web applications, making proper documentation important. Proper inventory of hosts and deployed API versions are also important.

**Prevention:**
- Inventory all API hosts
- Document all aspects of your API
- Generate documentation automatically
- Use API gateway for versioning
- Implement proper decommissioning strategy for old API versions
- Implement additional external protections for older versions

**Lab:** See `OWASP-API/API09-Improper-Inventory-Management/`

---

### API10: Unsafe Consumption of APIs

Developers tend to trust data received from third-party APIs more than user input. This is especially true for APIs offered by well-known companies.

**Prevention:**
- Validate and properly sanitize data received from integrated APIs
- Maintain an allow list of known locations where third-party services may redirect
- Don't blindly follow redirects
- Implement timeouts for service mesh calls
- Be aware of potential security implications of using third-party services

**Lab:** See `OWASP-API/API10-Unsafe-Consumption-of-APIs/`

---

## 📱 OWASP Mobile Top 10 (2024)

### M1: Improper Credential Usage

Improper credential usage vulnerability refers to the mishandling, storage, or transmission of sensitive user credentials (such as passwords, API keys, tokens) in mobile applications.

**Prevention:**
- Never hardcode credentials in source code
- Use platform-provided secure storage (iOS Keychain, Android KeyStore)
- Implement certificate pinning
- Use OAuth 2.0 for authentication
- Encrypt sensitive data before storage

**Lab:** See `OWASP-Mobile/M01-Improper-Credential-Usage/`

---

### M2: Inadequate Supply Chain Security

Mobile apps often rely on third-party libraries and components. Attackers may compromise these components to introduce vulnerabilities.

**Prevention:**
- Maintain inventory of all third-party components
- Regularly scan for vulnerabilities
- Use only trusted sources for dependencies
- Implement code signing and verification
- Monitor security advisories

**Lab:** See `OWASP-Mobile/M02-Inadequate-Supply-Chain-Security/`

---

### M3: Insecure Authentication/Authorization

Weak authentication or authorization mechanisms that can be bypassed or exploited.

**Prevention:**
- Implement strong authentication mechanisms
- Use biometric authentication where appropriate
- Implement proper session management
- Validate all authorization server-side
- Use OAuth 2.0 or similar standards

**Lab:** See `OWASP-Mobile/M03-Insecure-Authentication-Authorization/`

---

### M4: Insufficient Input/Output Validation

Failure to properly validate inputs and outputs can lead to injection attacks and data corruption.

**Prevention:**
- Validate all inputs on server-side
- Use parameterized queries
- Implement output encoding
- Sanitize data from external sources
- Use content security policies

**Lab:** See `OWASP-Mobile/M04-Insufficient-Input-Output-Validation/`

---

### M5: Insecure Communication

Unencrypted or weakly encrypted data transmission exposes sensitive information.

**Prevention:**
- Use TLS 1.2 or higher
- Implement certificate pinning
- Never transmit sensitive data over insecure channels
- Validate SSL certificates
- Use VPN for additional security

**Lab:** See `OWASP-Mobile/M05-Insecure-Communication/`

---

### M6: Inadequate Privacy Controls

Insufficient privacy controls can lead to unauthorized data collection and privacy violations.

**Prevention:**
- Implement privacy by design
- Minimize data collection
- Provide clear privacy policies
- Implement user consent mechanisms
- Allow users to delete their data

**Lab:** See `OWASP-Mobile/M06-Inadequate-Privacy-Controls/`

---

### M7: Insufficient Binary Protections

Lack of protections against reverse engineering and code tampering.

**Prevention:**
- Implement code obfuscation
- Use anti-debugging techniques
- Implement runtime integrity checks
- Use encryption for sensitive code
- Implement root/jailbreak detection

**Lab:** See `OWASP-Mobile/M07-Insufficient-Binary-Protections/`

---

### M8: Security Misconfiguration

Insecure default configurations or improper security settings in mobile applications.

**Prevention:**
- Review all app permissions
- Disable debugging in production
- Implement proper error handling
- Secure backend APIs
- Use security headers

**Lab:** See `OWASP-Mobile/M08-Security-Misconfiguration/`

---

### M9: Insecure Data Storage

Sensitive data stored insecurely on the device, making it accessible to attackers.

**Prevention:**
- Use platform secure storage mechanisms
- Encrypt sensitive data at rest
- Avoid storing sensitive data when possible
- Clear sensitive data from memory after use
- Implement secure data deletion

**Lab:** See `OWASP-Mobile/M09-Insecure-Data-Storage/`

---

### M10: Insufficient Cryptography

Use of weak or broken cryptographic algorithms that can be compromised.

**Prevention:**
- Use industry-standard algorithms (AES-256, RSA-2048+)
- Implement proper key management
- Use platform cryptographic APIs
- Avoid custom cryptography
- Regularly update crypto libraries

**Lab:** See `OWASP-Mobile/M10-Insufficient-Cryptography/`

---

## 🤖 OWASP LLM Top 10 (2023)

### LLM01: Prompt Injection

Manipulating LLM through crafted inputs to override system instructions or access unauthorized data.

**Prevention:**
- Implement strict input validation
- Use prompt templates with clear boundaries
- Separate instructions from user input
- Implement output filtering
- Use privilege levels for different operations

**Lab:** See `OWASP-LLM/LLM01-Prompt-Injection/`

---

### LLM02: Insecure Output Handling

Insufficient validation of LLM outputs before they're used downstream, similar to XSS vulnerabilities.

**Prevention:**
- Validate and sanitize all LLM outputs
- Encode outputs appropriately for context
- Implement content security policies
- Use sandboxing for code execution
- Monitor for malicious patterns

**Lab:** See `OWASP-LLM/LLM02-Insecure-Output-Handling/`

---

### LLM03: Training Data Poisoning

Manipulating training data or fine-tuning process to introduce vulnerabilities or biases.

**Prevention:**
- Verify all training data sources
- Implement data validation pipelines
- Use anomaly detection
- Monitor model behavior for changes
- Maintain data provenance

**Lab:** See `OWASP-LLM/LLM03-Training-Data-Poisoning/`

---

### LLM04: Model Denial of Service

Resource-intensive operations that cause service degradation or excessive costs.

**Prevention:**
- Implement rate limiting
- Set resource quotas per user
- Monitor usage patterns
- Implement request validation
- Use circuit breakers

**Lab:** See `OWASP-LLM/LLM04-Model-Denial-of-Service/`

---

### LLM05: Supply Chain Vulnerabilities

Risks from using third-party models, datasets, plugins, or APIs.

**Prevention:**
- Verify model sources
- Scan for vulnerabilities
- Use model signing and verification
- Maintain component inventory
- Monitor for security updates

**Lab:** See `OWASP-LLM/LLM05-Supply-Chain-Vulnerabilities/`

---

### LLM06: Sensitive Information Disclosure

LLM inadvertently revealing sensitive information through its responses.

**Prevention:**
- Implement data filtering
- Use differential privacy techniques
- Sanitize training data
- Monitor outputs for sensitive data
- Implement access controls

**Lab:** See `OWASP-LLM/LLM06-Sensitive-Information-Disclosure/`

---

### LLM07: Insecure Plugin Design

Vulnerabilities in LLM plugins that can be exploited for unauthorized access or actions.

**Prevention:**
- Validate all plugin inputs
- Implement proper authorization
- Use sandboxing for plugin execution
- Regular security audits
- Limit plugin capabilities

**Lab:** See `OWASP-LLM/LLM07-Insecure-Plugin-Design/`

---

### LLM08: Excessive Agency

LLM given too much autonomy, leading to unintended or harmful actions.

**Prevention:**
- Implement human-in-the-loop for critical operations
- Limit LLM permissions
- Require confirmation for sensitive actions
- Monitor LLM decisions
- Implement rollback mechanisms

**Lab:** See `OWASP-LLM/LLM08-Excessive-Agency/`

---

### LLM09: Overreliance

Users or systems over-trusting LLM outputs without proper verification.

**Prevention:**
- Display confidence levels
- Implement fact-checking mechanisms
- User education about limitations
- Clear disclaimers about accuracy
- Encourage verification of critical information

**Lab:** See `OWASP-LLM/LLM09-Overreliance/`

---

### LLM10: Model Theft

Unauthorized access to or extraction of proprietary models.

**Prevention:**
- Implement strong access controls
- Monitor for unusual query patterns
- Use rate limiting
- Obfuscate model architecture details
- Implement watermarking

**Lab:** See `OWASP-LLM/LLM10-Model-Theft/`

---

## 📊 Quick Comparison Matrix

| Vulnerability | Web | API | Mobile | LLM |
|--------------|-----|-----|--------|-----|
| Access Control | ✓ | ✓ | ✓ | - |
| Authentication | ✓ | ✓ | ✓ | - |
| Injection | ✓ | - | ✓ | ✓ (Prompt) |
| Cryptography | ✓ | - | ✓ | - |
| Data Storage | - | - | ✓ | - |
| Configuration | ✓ | ✓ | ✓ | - |
| Components | ✓ | - | ✓ | ✓ (Supply Chain) |
| SSRF | ✓ | ✓ | - | - |
| Logging | ✓ | - | - | - |
| Rate Limiting | - | ✓ | - | ✓ |

---

## 🎯 How to Use This Guide

### For Developers:
1. Review relevant sections before starting new features
2. Use as a checklist during code reviews
3. Reference prevention techniques during implementation
4. Test applications using provided labs

### For Security Professionals:
1. Use as assessment framework
2. Reference during penetration testing
3. Create test cases based on vulnerabilities
4. Train development teams

### For Students:
1. Study vulnerabilities systematically
2. Practice with hands-on labs
3. Take quizzes to test knowledge
4. Build secure applications from the start

---

## 🔗 Additional Resources

- **Interactive Labs:** Navigate to `owasp-labs.html` for hands-on practice
- **Cheat Sheets:** See `cheat-sheets/` directory for quick references
- **Quiz Platform:** Test your knowledge at `quiz-platform/`
- **Compliance Mappings:** Map to industry standards at `compliance-mappings/`
- **Attack Diagrams:** Visual representations at `diagrams/`

---

## 📚 References

- OWASP Top 10 Web: https://owasp.org/www-project-top-ten/
- OWASP API Security: https://owasp.org/www-project-api-security/
- OWASP Mobile: https://owasp.org/www-project-mobile-top-10/
- OWASP LLM: https://owasp.org/www-project-top-10-for-large-language-model-applications/

---

## ⚖️ License

This educational repository is licensed under the MIT License.

## ⚠️ Disclaimer

This repository is for **educational purposes only**. Never use these techniques on systems you don't own or don't have explicit permission to test.

---

**Last Updated:** January 2026  
**Version:** 2024.1  
**Maintained by:** [OWASP Top 10 Educational Repository](https://github.com/0x6a03448f4d/OWASP-TOP10)
