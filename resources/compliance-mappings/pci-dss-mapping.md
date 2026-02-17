# OWASP Top 10 → PCI-DSS Compliance Mapping

**Payment Card Industry Data Security Standard (PCI-DSS) Version 4.0**

This document maps the OWASP Top 10 vulnerabilities to PCI-DSS requirements, helping organizations demonstrate compliance through secure application development.

## Executive Summary

Addressing the OWASP Top 10 vulnerabilities directly supports PCI-DSS compliance, particularly Requirement 6 (Develop and Maintain Secure Systems and Applications). This mapping shows how fixing each OWASP vulnerability helps meet specific PCI-DSS controls.

## Detailed Mapping

### 01. Broken Access Control

**PCI-DSS Requirements:**
- **6.5.8**: Improper access control
- **7.1**: Limit access to system components and cardholder data
- **7.2**: Assign access based on need to know
- **8.2**: Ensure proper user authentication

**Implementation:**
- Implement role-based access control (RBAC)
- Enforce least privilege principle
- Validate authorization on every request
- Log all access attempts

**Evidence:**
- Access control policy documents
- RBAC configuration
- Authorization test results
- Access logs

---

### 02. Cryptographic Failures

**PCI-DSS Requirements:**
- **3.4**: Render PAN unreadable anywhere it is stored
- **3.5**: Protect cryptographic keys
- **4.1**: Use strong cryptography for transmission
- **6.5.3**: Insecure cryptographic storage

**Implementation:**
- Use AES-256 for data at rest
- Use TLS 1.2+ for data in transit
- Secure key management with HSM
- Never store sensitive authentication data

**Evidence:**
- Encryption configuration
- TLS certificate scans
- Key management procedures
- Data flow diagrams

---

### 03. Injection

**PCI-DSS Requirements:**
- **6.5.1**: Injection flaws (SQL, OS, LDAP)
- **6.2**: Protect systems from known vulnerabilities

**Implementation:**
- Use parameterized queries
- Input validation with whitelisting
- Implement WAF with injection rules
- Regular vulnerability scanning

**Evidence:**
- Code review reports
- SQL injection test results
- WAF configuration
- Vulnerability scan results

---

### 04. Insecure Design

**PCI-DSS Requirements:**
- **6.3**: Secure development lifecycle
- **6.4**: Change control processes
- **6.5**: Address common coding vulnerabilities

**Implementation:**
- Threat modeling during design
- Security requirements definition
- Peer code reviews
- Security architecture reviews

**Evidence:**
- Threat models
- Security requirements docs
- Design review reports
- Architecture diagrams

---

### 05. Security Misconfiguration

**PCI-DSS Requirements:**
- **2.2**: Develop configuration standards
- **2.2.1**: Implement only one primary function per server
- **2.2.4**: Configure security parameters
- **6.5.10**: Broken authentication and session management

**Implementation:**
- Hardening guidelines
- Disable unnecessary services
- Remove default accounts
- Secure configuration management

**Evidence:**
- Configuration standards
- Hardening checklists
- Configuration scan results
- Change management logs

---

### 06. Vulnerable and Outdated Components

**PCI-DSS Requirements:**
- **6.2**: Ensure all components are protected from known vulnerabilities
- **6.3.2**: Review software changes prior to release

**Implementation:**
- Inventory all components
- Monitor for vulnerabilities
- Patch management process
- Dependency scanning in CI/CD

**Evidence:**
- Software inventory
- Vulnerability scan reports
- Patch management logs
- SCA tool reports

---

### 07. Identification and Authentication Failures

**PCI-DSS Requirements:**
- **6.5.10**: Broken authentication
- **8.2**: Use strong authentication
- **8.3**: Secure all individual access
- **8.6**: Use MFA for remote access

**Implementation:**
- Strong password policies
- Multi-factor authentication
- Secure session management
- Account lockout mechanisms

**Evidence:**
- Authentication configuration
- Password policy docs
- MFA implementation
- Session management tests

---

### 08. Software and Data Integrity Failures

**PCI-DSS Requirements:**
- **6.3**: Develop software securely
- **6.5.3**: Insecure cryptographic storage
- **11.5**: Deploy change detection mechanism

**Implementation:**
- Code signing
- Integrity verification
- Secure CI/CD pipeline
- File integrity monitoring

**Evidence:**
- Signed packages
- Build pipeline config
- FIM alerts
- Supply chain docs

---

### 09. Security Logging and Monitoring Failures

**PCI-DSS Requirements:**
- **10.1-10.9**: Implement logging and monitoring
- **10.2**: Log all access to cardholder data
- **10.4**: Synchronize clocks
- **10.6**: Review logs

**Implementation:**
- Centralized logging
- Log all security events
- Real-time monitoring
- Automated alerting

**Evidence:**
- Log retention policy
- SIEM configuration
- Log review procedures
- Alert documentation

---

### 10. Server-Side Request Forgery (SSRF)

**PCI-DSS Requirements:**
- **6.5.1**: Injection flaws
- **6.5.4**: Insecure communications
- **1.3**: Prohibit direct public access

**Implementation:**
- URL validation and whitelist
- Network segmentation
- Disable unnecessary protocols
- Firewall rules

**Evidence:**
- Input validation tests
- Network diagrams
- Firewall configurations
- Penetration test reports

---

## Coverage Summary

| OWASP Top 10 | Primary PCI-DSS Req | Secondary Requirements |
|--------------|---------------------|------------------------|
| 01. Broken Access Control | 6.5.8 | 7.1, 7.2, 8.2 |
| 02. Cryptographic Failures | 3.4, 4.1 | 3.5, 6.5.3 |
| 03. Injection | 6.5.1 | 6.2 |
| 04. Insecure Design | 6.3 | 6.4, 6.5 |
| 05. Security Misconfiguration | 2.2 | 6.5.10 |
| 06. Vulnerable Components | 6.2 | 6.3.2 |
| 07. Auth Failures | 6.5.10, 8.2 | 8.3, 8.6 |
| 08. Data Integrity Failures | 6.3, 6.5.3 | 11.5 |
| 09. Logging Failures | 10.1-10.9 | 10.2, 10.4, 10.6 |
| 10. SSRF | 6.5.1, 6.5.4 | 1.3 |

## Implementation Priority

**Critical (Do First):**
1. Cryptographic Failures (#02) - Core PCI requirement
2. Injection (#03) - Common attack vector
3. Auth Failures (#07) - Access security

**High:**
4. Broken Access Control (#01)
5. Vulnerable Components (#06)
6. Logging Failures (#09)

**Medium:**
7. Security Misconfiguration (#05)
8. Data Integrity Failures (#08)
9. Insecure Design (#04)
10. SSRF (#10)

## Audit Preparation

### Documentation Checklist
- [ ] Secure coding standards
- [ ] Security requirements documentation
- [ ] Code review procedures
- [ ] Vulnerability scanning reports
- [ ] Penetration testing results
- [ ] Remediation tracking
- [ ] Training records

### Testing Evidence
- [ ] Authentication test results
- [ ] Authorization test results
- [ ] Injection vulnerability scans
- [ ] Encryption verification
- [ ] Configuration reviews
- [ ] Log review samples

## References

- [PCI DSS v4.0 Official](https://www.pcisecuritystandards.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PCI Software Security Framework](https://www.pcisecuritystandards.org/document_library)

---

*Last Updated: January 2026*
*Document Version: 1.0*
