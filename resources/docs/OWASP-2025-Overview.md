# OWASP Top 10 2025 - Web Application Security

## Overview

The OWASP Top 10 2025 represents the most current and critical web application security risks as identified by the Open Web Application Security Project. This version continues from the 2021 release with updated data and threat landscapes for modern applications.

## The 2025 Top 10

### A01:2025 - Broken Access Control
Users can access data or functionality beyond their assigned permissions, leading to unauthorized information disclosure and manipulation.

**Prevalence:** 94% of applications tested  
**Key Focus:** Authorization failures, IDOR, missing function-level access control

### A02:2025 - Cryptographic Failures
Weak or missing encryption exposes sensitive data in transit and at rest, allowing attackers to steal or modify information.

**Formerly:** Sensitive Data Exposure (2017)  
**Key Focus:** TLS failures, weak algorithms, key management

### A03:2025 - Injection
Untrusted data sent to interpreters (SQL, OS, LDAP, NoSQL) allows attackers to inject malicious code and compromise data integrity.

**Prevalence:** 33% of applications tested  
**Key Focus:** SQL injection, NoSQL injection, ORM injection, command injection

### A04:2025 - Insecure Design
Missing or ineffective security controls in the design phase lead to fundamental security vulnerabilities in applications.

**Key Changes:** **NEW** category in 2021, continued in 2025  
**Key Focus:** Threat modeling, secure design patterns, business logic flaws

### A05:2025 - Security Misconfiguration
Insecure default configurations, incomplete deployments, and unnecessary features leave applications vulnerable to exploitation.

**Prevalence:** 90% of applications tested  
**Key Focus:** Default credentials, unnecessary features, verbose errors, security headers

### A06:2025 - Vulnerable and Outdated Components
Using components with known vulnerabilities, lack of patching, and outdated software expose applications to exploitation.

**Formerly:** Using Components with Known Vulnerabilities (2017)  
**Key Focus:** Dependency management, CVE tracking, supply chain security

### A07:2025 - Identification and Authentication Failures
Weaknesses in authentication mechanisms allow attackers to compromise passwords, keys, session tokens, or exploit implementation flaws.

**Formerly:** Broken Authentication (2017)  
**Key Focus:** Credential stuffing, session management, MFA, brute force

### A08:2025 - Software and Data Integrity Failures
Code and infrastructure that do not protect against integrity violations enable malicious code insertion or system compromise.

**Key Changes:** **NEW** category in 2021, continued in 2025  
**Key Focus:** CI/CD security, insecure deserialization, update mechanisms

### A09:2025 - Security Logging and Monitoring Failures
Insufficient logging, detection, monitoring, and active response allow attackers to persist undetected for extended periods.

**Formerly:** Insufficient Logging & Monitoring (2017)  
**Key Focus:** Log integrity, SIEM integration, incident response

### A10:2025 - Server-Side Request Forgery (SSRF)
SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.

**Key Changes:** **NEW** category in 2021, continued in 2025  
**Key Focus:** Cloud metadata exposure, internal network access, URL validation

## Major Changes from 2017

**New Categories (from 2021):**
- A04:2025-Insecure Design (design-level flaws)
- A08:2025-Software and Data Integrity Failures (supply chain, CI/CD)
- A10:2025-Server-Side Request Forgery (SSRF)

**Removed/Merged:**
- XML External Entities (XXE) - merged into A03:Injection
- Insecure Deserialization - merged into A08:Software and Data Integrity Failures

**Renamed:**
- Sensitive Data Exposure → Cryptographic Failures
- Broken Authentication → Identification and Authentication Failures  
- Insufficient Logging & Monitoring → Security Logging and Monitoring Failures
- Using Components with Known Vulnerabilities → Vulnerable and Outdated Components

## 2025 Threat Landscape

The 2025 version addresses modern challenges:

- **Cloud-Native Security:** SSRF, metadata exposure, serverless vulnerabilities
- **Supply Chain Attacks:** Component integrity, CI/CD security
- **Design Flaws:** Secure-by-design principles, threat modeling
- **API Security:** GraphQL injection, API-specific access control
- **DevSecOps:** Shift-left security, automated security testing

## Statistics & Methodology

The 2025 data is based on:
- Contributions from hundreds of organizations
- Data from 500,000+ applications
- Community survey with 500+ participants
- 4 years of vulnerability trends since 2021

## Resources

- [OWASP Top 10 Official Project](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## Available Content

This platform provides:
- ✅ **Cheatsheets** - Quick reference guides for all 10 vulnerabilities
- ✅ **Quiz Questions** - Test your knowledge of 2025 vulnerabilities  
- 📋 **Documentation** - Detailed overview, examples, and prevention guides
- 🎯 **Attack Flows** - Visual attack scenarios
- ⚖️ **Compliance Mappings** - Map to GDPR, ISO 27001, NIST, PCI-DSS, SOC2
- 🔬 **Labs** - Hands-on vulnerable environments (coming soon)

## Alignment with Other OWASP Projects

The 2025 Web Top 10 aligns with:
- **OWASP API Security Top 10 2023**
- **OWASP Mobile Top 10 2024**
- **OWASP LLM Top 10 2023**
- **OWASP SAMM** (Software Assurance Maturity Model)

---

**Note:** This content reflects the OWASP Top 10 2025 framework. As the security landscape evolves, consult the official OWASP resources for the latest guidance.
