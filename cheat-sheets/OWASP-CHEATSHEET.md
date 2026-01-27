# OWASP Top 10 - Complete Cheat Sheet Collection

> Quick reference guide for all OWASP Top 10 vulnerabilities across Web, API, Mobile, and LLM categories.
> 
> **For interactive HTML versions, see:** [Cheat Sheets Index](index.html)

---

## 📋 Table of Contents

### OWASP Web Application Security Risks
1. [Broken Access Control](#1-broken-access-control)
2. [Cryptographic Failures](#2-cryptographic-failures)
3. [Injection](#3-injection)
4. [Insecure Design](#4-insecure-design)
5. [Security Misconfiguration](#5-security-misconfiguration)
6. [Vulnerable and Outdated Components](#6-vulnerable-and-outdated-components)
7. [Identification and Authentication Failures](#7-identification-and-authentication-failures)
8. [Software and Data Integrity Failures](#8-software-and-data-integrity-failures)
9. [Security Logging and Monitoring Failures](#9-security-logging-and-monitoring-failures)
10. [Server-Side Request Forgery (SSRF)](#10-server-side-request-forgery-ssrf)

### OWASP API Security Top 10
- [API01: Broken Object Level Authorization](#api01-broken-object-level-authorization)
- [API02: Broken Authentication](#api02-broken-authentication)
- [API03: Broken Object Property Level Authorization](#api03-broken-object-property-level-authorization)
- [API04: Unrestricted Resource Consumption](#api04-unrestricted-resource-consumption)
- [API05: Broken Function Level Authorization](#api05-broken-function-level-authorization)
- [API06: Unrestricted Access to Sensitive Business Flows](#api06-unrestricted-access-to-sensitive-business-flows)
- [API07: Server-Side Request Forgery](#api07-server-side-request-forgery)
- [API08: Security Misconfiguration](#api08-security-misconfiguration)
- [API09: Improper Inventory Management](#api09-improper-inventory-management)
- [API10: Unsafe Consumption of APIs](#api10-unsafe-consumption-of-apis)

### OWASP LLM Top 10
- [LLM01: Prompt Injection](#llm01-prompt-injection)
- [LLM02: Insecure Output Handling](#llm02-insecure-output-handling)
- [LLM03: Training Data Poisoning](#llm03-training-data-poisoning)
- [LLM04: Model Denial of Service](#llm04-model-denial-of-service)
- [LLM05: Supply Chain Vulnerabilities](#llm05-supply-chain-vulnerabilities)
- [LLM06: Sensitive Information Disclosure](#llm06-sensitive-information-disclosure)
- [LLM07: Insecure Plugin Design](#llm07-insecure-plugin-design)
- [LLM08: Excessive Agency](#llm08-excessive-agency)
- [LLM09: Overreliance](#llm09-overreliance)
- [LLM10: Model Theft](#llm10-model-theft)

### OWASP Mobile Top 10
- [M01: Improper Credential Usage](#m01-improper-credential-usage)
- [M02: Inadequate Supply Chain Security](#m02-inadequate-supply-chain-security)
- [M03: Insecure Authentication/Authorization](#m03-insecure-authenticationauthorization)
- [M04: Insufficient Input/Output Validation](#m04-insufficient-inputoutput-validation)
- [M05: Insecure Communication](#m05-insecure-communication)
- [M06: Inadequate Privacy Controls](#m06-inadequate-privacy-controls)
- [M07: Insufficient Binary Protections](#m07-insufficient-binary-protections)
- [M08: Security Misconfiguration](#m08-security-misconfiguration)
- [M09: Insecure Data Storage](#m09-insecure-data-storage)
- [M10: Insufficient Cryptography](#m10-insufficient-cryptography)

---

## OWASP Web Top 10

### 1. Broken Access Control

**Rank:** #1 | **Prevalence:** 94% of apps tested | **Occurrences:** 318K+

#### What is it?
Broken Access Control occurs when users can access data or perform actions beyond their intended permissions.

#### Common Exploits:
- Direct Object Reference: Modify URL parameters to access other users' data
- Forced Browsing: Access admin pages by guessing URLs
- Missing Function Level Access Control: Call admin APIs as regular user
- Parameter Tampering: Change user_id, role, or permissions in requests
- Elevation of Privilege: Modify tokens/cookies to gain higher access

#### Prevention Checklist:
- ✅ Deny access by default (whitelist approach)
- ✅ Implement server-side authorization checks
- ✅ Use role-based access control (RBAC)
- ✅ Validate user ownership of resources
- ✅ Implement rate limiting for sensitive operations
- ✅ Log access control failures
- ✅ Disable directory listing
- ✅ Use indirect object references (UUIDs)

#### Tools:
- Testing: Burp Suite, OWASP ZAP, Postman
- Prevention: Spring Security, Django Auth, Passport.js, Casbin

---

### 2. Cryptographic Failures

**Rank:** #2 | **Impact:** Sensitive data exposure

#### What is it?
Failures related to cryptography (or lack thereof) that lead to exposure of sensitive data.

#### Common Exploits:
- Transmitting data in clear text (HTTP instead of HTTPS)
- Using weak or deprecated cryptographic algorithms
- Insufficient key management
- Not enforcing encryption in transit or at rest
- Using default keys or weak passwords

#### Prevention Checklist:
- ✅ Use HTTPS/TLS for all data in transit
- ✅ Encrypt sensitive data at rest
- ✅ Use strong, modern encryption algorithms (AES-256, RSA-2048+)
- ✅ Implement proper key management
- ✅ Never store passwords in plain text (use bcrypt, Argon2)
- ✅ Disable caching for sensitive data
- ✅ Use secure random number generators

---

### 3. Injection

**Rank:** #3 | **Types:** SQL, NoSQL, OS Command, LDAP

#### What is it?
Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.

#### Common Exploits:
- SQL Injection: `' OR '1'='1`
- Command Injection: `; rm -rf /`
- LDAP Injection: `*)(uid=*))(|(uid=*`
- NoSQL Injection: `{"$ne": null}`

#### Prevention Checklist:
- ✅ Use parameterized queries (prepared statements)
- ✅ Validate and sanitize all user input
- ✅ Use ORM frameworks
- ✅ Implement input whitelisting
- ✅ Escape special characters
- ✅ Limit database permissions
- ✅ Use stored procedures with parameterization

#### Tools:
- Testing: SQLMap, Burp Suite, OWASP ZAP
- Prevention: Django ORM, SQLAlchemy, Hibernate, Entity Framework

---

### 4. Insecure Design

**Rank:** #4 | **Focus:** Design and architecture flaws

#### What is it?
Risks related to design and architectural flaws, not implementation bugs.

#### Common Issues:
- Missing or ineffective control design
- Lack of security requirements
- Insecure design patterns
- Missing threat modeling
- Insufficient architecture review

#### Prevention Checklist:
- ✅ Establish secure development lifecycle
- ✅ Conduct threat modeling
- ✅ Use secure design patterns
- ✅ Implement defense in depth
- ✅ Perform architecture security reviews
- ✅ Use reference architectures
- ✅ Separate tenants robustly

---

### 5. Security Misconfiguration

**Rank:** #5 | **Common in:** 90% of applications

#### What is it?
Security misconfiguration is the most commonly seen issue, resulting from insecure default configurations, incomplete setups, or verbose error messages.

#### Common Exploits:
- Default credentials still active
- Unnecessary features enabled
- Directory listing enabled
- Detailed error messages exposing stack traces
- Missing security headers
- Outdated software versions

#### Prevention Checklist:
- ✅ Remove unnecessary features, components, documentation
- ✅ Review and update configurations
- ✅ Implement security headers (CSP, HSTS, X-Frame-Options)
- ✅ Disable directory listing
- ✅ Use custom error pages (no stack traces)
- ✅ Keep software up to date
- ✅ Segment application tiers
- ✅ Automate security configuration verification

---

### 6. Vulnerable and Outdated Components

**Rank:** #6 | **Risk:** Using components with known vulnerabilities

#### What is it?
Using libraries, frameworks, and other software modules with known vulnerabilities.

#### Common Issues:
- Using outdated versions with CVEs
- Not scanning dependencies for vulnerabilities
- Lack of update policy
- Using unsupported software

#### Prevention Checklist:
- ✅ Remove unused dependencies
- ✅ Continuously inventory component versions
- ✅ Monitor CVE databases for vulnerabilities
- ✅ Use tools like OWASP Dependency-Check, Snyk
- ✅ Only obtain components from official sources
- ✅ Monitor for unmaintained libraries
- ✅ Implement software composition analysis

---

### 7. Identification and Authentication Failures

**Rank:** #7 | **Previously:** Broken Authentication

#### What is it?
Weaknesses in authentication and session management that allow attackers to compromise passwords, keys, or session tokens.

#### Common Exploits:
- Credential stuffing
- Brute force attacks
- Session fixation
- Weak password policies
- Missing multi-factor authentication
- Exposing session IDs in URLs

#### Prevention Checklist:
- ✅ Implement multi-factor authentication
- ✅ Enforce strong password policies
- ✅ Implement account lockout mechanisms
- ✅ Use secure session management
- ✅ Rotate session IDs after login
- ✅ Invalidate sessions on logout
- ✅ Use HTTPS for all authentication
- ✅ Protect against credential stuffing

---

### 8. Software and Data Integrity Failures

**Rank:** #8 | **Focus:** Supply chain and CI/CD

#### What is it?
Code and infrastructure that doesn't protect against integrity violations, including insecure deserialization.

#### Common Issues:
- Unsigned software updates
- Insecure deserialization
- CI/CD pipeline vulnerabilities
- Auto-update without verification
- Untrusted sources

#### Prevention Checklist:
- ✅ Use digital signatures for updates
- ✅ Verify integrity of libraries and dependencies
- ✅ Secure CI/CD pipeline
- ✅ Review code and configuration changes
- ✅ Avoid insecure deserialization
- ✅ Use software bill of materials (SBOM)

---

### 9. Security Logging and Monitoring Failures

**Rank:** #9 | **Impact:** Delayed breach detection

#### What is it?
Insufficient logging, detection, monitoring, and active response allow attackers to achieve their goals without detection.

#### Common Issues:
- Not logging authentication failures
- Not monitoring for suspicious activities
- Logs not protected from tampering
- Missing alerting mechanisms
- Logs stored only locally

#### Prevention Checklist:
- ✅ Log all authentication events
- ✅ Log access control failures
- ✅ Ensure logs are tamper-proof
- ✅ Implement real-time alerting
- ✅ Use centralized logging (SIEM)
- ✅ Establish incident response plan
- ✅ Regular log reviews

---

### 10. Server-Side Request Forgery (SSRF)

**Rank:** #10 | **New in 2021**

#### What is it?
SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.

#### Common Exploits:
- Access internal services
- Scan internal network
- Read local files
- Bypass firewall rules
- Access cloud metadata services

#### Prevention Checklist:
- ✅ Sanitize and validate all user input
- ✅ Use whitelist of allowed URLs/IPs
- ✅ Disable HTTP redirections
- ✅ Implement network segmentation
- ✅ Block access to internal IPs
- ✅ Use cloud security groups

---

## OWASP API Security Top 10

### API01: Broken Object Level Authorization

**Impact:** High | **Exploitability:** Easy

#### What is it?
APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface for access control issues.

#### Example Attack:
```bash
GET /api/users/123/profile
# Attacker changes to:
GET /api/users/456/profile
```

#### Prevention:
- ✅ Implement proper authorization checks for every object access
- ✅ Use random and unpredictable object IDs
- ✅ Test authorization with automated tools

---

### API02: Broken Authentication

**Impact:** High | **Common in:** API authentication

#### What is it?
Poorly implemented authentication mechanisms that allow attackers to compromise tokens or exploit implementation flaws.

#### Prevention:
- ✅ Implement standard authentication (OAuth2, JWT)
- ✅ Use rate limiting
- ✅ Implement MFA
- ✅ Use strong password policies
- ✅ Don't expose credentials in URLs

---

### API03: Broken Object Property Level Authorization

**Impact:** High | **Focus:** Mass assignment

#### What is it?
Lack of or improper authorization validation at the object property level, allowing unauthorized access or modification.

#### Prevention:
- ✅ Whitelist allowed properties
- ✅ Avoid mass assignment
- ✅ Validate schema strictly
- ✅ Return only necessary data

---

### API04: Unrestricted Resource Consumption

**Impact:** Medium-High | **Type:** DoS

#### What is it?
Lack of limits on resources that can be consumed, leading to denial of service or excessive costs.

#### Prevention:
- ✅ Implement rate limiting
- ✅ Set maximum data sizes
- ✅ Limit execution timeouts
- ✅ Monitor resource usage
- ✅ Use CAPTCHA for expensive operations

---

### API05: Broken Function Level Authorization

**Impact:** High | **Common:** Admin function exposure

#### What is it?
Complex access control policies with different hierarchies, roles, and groups lead to authorization flaws.

#### Prevention:
- ✅ Deny all access by default
- ✅ Implement role-based access control
- ✅ Test authorization for all functions
- ✅ Don't rely on client-side controls

---

### API06: Unrestricted Access to Sensitive Business Flows

**Impact:** Medium | **Type:** Business logic abuse

#### What is it?
Unrestricted access to business flows that can be abused if used excessively in an automated manner.

#### Prevention:
- ✅ Identify critical business flows
- ✅ Implement rate limiting per user
- ✅ Add CAPTCHA for sensitive operations
- ✅ Monitor for unusual patterns

---

### API07: Server-Side Request Forgery

**Impact:** High | **Similar to:** Web SSRF

#### What is it?
API endpoints that fetch remote resources without validating URLs provided by users.

#### Prevention:
- ✅ Validate and sanitize URLs
- ✅ Use URL whitelisting
- ✅ Disable redirects
- ✅ Implement network segmentation

---

### API08: Security Misconfiguration

**Impact:** High | **Very Common**

#### What is it?
Missing or poorly configured security settings in the API stack.

#### Prevention:
- ✅ Remove unnecessary features
- ✅ Keep software updated
- ✅ Implement security headers
- ✅ Use HTTPS everywhere
- ✅ Disable verbose errors

---

### API09: Improper Inventory Management

**Impact:** Medium | **Focus:** API documentation

#### What is it?
Lack of documentation about API endpoints, versions, and their intended use.

#### Prevention:
- ✅ Maintain API inventory
- ✅ Document all endpoints
- ✅ Retire old versions
- ✅ Implement API gateway
- ✅ Monitor for shadow APIs

---

### API10: Unsafe Consumption of APIs

**Impact:** Medium-High | **Focus:** Third-party APIs

#### What is it?
Blindly trusting and integrating with third-party APIs without proper validation.

#### Prevention:
- ✅ Validate all API responses
- ✅ Encrypt communication
- ✅ Implement timeouts
- ✅ Don't blindly forward data
- ✅ Monitor third-party reliability

---

## OWASP LLM Top 10

### LLM01: Prompt Injection

**Impact:** Critical | **New Category**

#### What is it?
Manipulating LLM through crafted prompts to override intended behavior or access unauthorized data.

#### Prevention:
- ✅ Implement strict input validation
- ✅ Use prompt templates
- ✅ Implement output filtering
- ✅ Separate instructions from user input
- ✅ Use privilege levels

---

### LLM02: Insecure Output Handling

**Impact:** High | **Similar to:** XSS

#### What is it?
Insufficient validation of LLM outputs before they're used downstream.

#### Prevention:
- ✅ Validate all LLM outputs
- ✅ Encode outputs appropriately
- ✅ Implement content security policies
- ✅ Use sandboxing

---

### LLM03: Training Data Poisoning

**Impact:** High | **Focus:** Model training

#### What is it?
Manipulating training data or fine-tuning process to introduce vulnerabilities.

#### Prevention:
- ✅ Verify training data sources
- ✅ Implement data validation
- ✅ Use anomaly detection
- ✅ Monitor model behavior

---

### LLM04: Model Denial of Service

**Impact:** Medium | **Type:** Resource exhaustion

#### What is it?
Resource-intensive operations that cause service degradation or high costs.

#### Prevention:
- ✅ Implement rate limiting
- ✅ Set resource quotas
- ✅ Monitor usage patterns
- ✅ Implement request validation

---

### LLM05: Supply Chain Vulnerabilities

**Impact:** High | **Focus:** Third-party models

#### What is it?
Risks from using third-party models, datasets, or plugins.

#### Prevention:
- ✅ Verify model sources
- ✅ Scan for vulnerabilities
- ✅ Use model signing
- ✅ Maintain inventory

---

### LLM06: Sensitive Information Disclosure

**Impact:** Critical | **Focus:** Data leakage

#### What is it?
LLM revealing sensitive information through its responses.

#### Prevention:
- ✅ Implement data filtering
- ✅ Use differential privacy
- ✅ Sanitize training data
- ✅ Monitor outputs

---

### LLM07: Insecure Plugin Design

**Impact:** High | **Focus:** LLM extensions

#### What is it?
Vulnerabilities in LLM plugins that can be exploited.

#### Prevention:
- ✅ Validate plugin inputs
- ✅ Implement authorization
- ✅ Use sandboxing
- ✅ Regular security audits

---

### LLM08: Excessive Agency

**Impact:** High | **Focus:** Autonomy limits

#### What is it?
LLM given too much autonomy leading to unintended actions.

#### Prevention:
- ✅ Implement human-in-the-loop
- ✅ Limit permissions
- ✅ Require confirmation for critical actions
- ✅ Monitor LLM actions

---

### LLM09: Overreliance

**Impact:** Medium | **Focus:** User education

#### What is it?
Users over-trusting LLM outputs without verification.

#### Prevention:
- ✅ Display confidence levels
- ✅ Implement fact-checking
- ✅ User education
- ✅ Clear disclaimers

---

### LLM10: Model Theft

**Impact:** High | **Focus:** IP protection

#### What is it?
Unauthorized access to proprietary models.

#### Prevention:
- ✅ Implement access controls
- ✅ Monitor unusual queries
- ✅ Use rate limiting
- ✅ Obfuscate model details

---

## OWASP Mobile Top 10

### M01: Improper Credential Usage

**Impact:** High | **Common:** Hardcoded credentials

#### What is it?
Credential exposure in mobile applications including API keys, passwords stored insecurely.

#### Prevention:
- ✅ Never hardcode credentials
- ✅ Use secure storage (Keychain/KeyStore)
- ✅ Implement certificate pinning
- ✅ Encrypt sensitive data

---

### M02: Inadequate Supply Chain Security

**Impact:** High | **Focus:** Third-party libraries

#### What is it?
Vulnerabilities in third-party libraries and SDKs used in mobile apps.

#### Prevention:
- ✅ Scan dependencies regularly
- ✅ Use trusted sources
- ✅ Keep libraries updated
- ✅ Implement code signing

---

### M03: Insecure Authentication/Authorization

**Impact:** Critical | **Common:** Mobile auth bypass

#### What is it?
Weak authentication mechanisms or bypassable authorization in mobile apps.

#### Prevention:
- ✅ Implement strong authentication
- ✅ Use biometric authentication
- ✅ Implement session timeout
- ✅ Validate server-side

---

### M04: Insufficient Input/Output Validation

**Impact:** High | **Similar to:** Injection

#### What is it?
Lack of proper validation of inputs and outputs in mobile applications.

#### Prevention:
- ✅ Validate all inputs
- ✅ Sanitize outputs
- ✅ Use parameterized queries
- ✅ Implement content security

---

### M05: Insecure Communication

**Impact:** Critical | **Focus:** Network security

#### What is it?
Unencrypted data transmission or weak TLS implementation.

#### Prevention:
- ✅ Use HTTPS/TLS
- ✅ Implement certificate pinning
- ✅ Validate certificates
- ✅ Avoid mixed content

---

### M06: Inadequate Privacy Controls

**Impact:** High | **Focus:** User privacy

#### What is it?
Insufficient privacy controls leading to unauthorized data collection.

#### Prevention:
- ✅ Implement privacy by design
- ✅ Minimize data collection
- ✅ Provide user controls
- ✅ Implement consent mechanisms

---

### M07: Insufficient Binary Protections

**Impact:** Medium | **Focus:** Reverse engineering

#### What is it?
Lack of code obfuscation and anti-tampering mechanisms.

#### Prevention:
- ✅ Implement code obfuscation
- ✅ Use anti-debugging techniques
- ✅ Implement integrity checks
- ✅ Use encryption

---

### M08: Security Misconfiguration

**Impact:** High | **Common:** Mobile app misconfigs

#### What is it?
Insecure default configurations or improper security settings.

#### Prevention:
- ✅ Review app permissions
- ✅ Disable debugging in production
- ✅ Implement security headers
- ✅ Secure backend services

---

### M09: Insecure Data Storage

**Impact:** Critical | **Very Common**

#### What is it?
Sensitive data stored insecurely on the device.

#### Prevention:
- ✅ Use platform secure storage
- ✅ Encrypt sensitive data
- ✅ Avoid storing sensitive data
- ✅ Clear cache appropriately

---

### M10: Insufficient Cryptography

**Impact:** High | **Focus:** Weak crypto

#### What is it?
Use of weak or broken cryptographic algorithms.

#### Prevention:
- ✅ Use strong algorithms (AES-256)
- ✅ Implement proper key management
- ✅ Use platform crypto APIs
- ✅ Avoid custom crypto

---

## 📚 Resources

- **OWASP Official:** https://owasp.org/Top10/
- **Interactive Labs:** See `../owasp-labs.html`
- **Quiz Platform:** See `../quiz-platform/`
- **Compliance Mappings:** See `../compliance-mappings/`

## 🎯 How to Use This Cheatsheet

1. **Quick Reference:** Use as a desktop reference during development
2. **Study Guide:** Review before security assessments
3. **Code Review:** Check against vulnerability patterns
4. **Interview Prep:** Study for security interviews
5. **CLI Access:** View directly in terminal with `cat OWASP-CHEATSHEET.md | less`

## 📄 License

This cheatsheet is part of the OWASP-TOP10 educational repository.
Licensed under MIT License.

---

**Last Updated:** January 2026
**Version:** 1.0.0
