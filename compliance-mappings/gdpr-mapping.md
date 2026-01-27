# OWASP Top 10 → GDPR Compliance Mapping

**General Data Protection Regulation (EU) 2016/679**

This document maps the OWASP Top 10 vulnerabilities to GDPR requirements, demonstrating how secure application development supports data protection compliance.

## Executive Summary

GDPR Article 32 requires appropriate technical and organizational measures to ensure security of processing. Addressing OWASP Top 10 vulnerabilities is essential for demonstrating compliance with GDPR's security requirements and protecting personal data.

## Key GDPR Articles

- **Article 5**: Principles relating to processing (integrity and confidentiality)
- **Article 25**: Data protection by design and by default
- **Article 32**: Security of processing
- **Article 33/34**: Personal data breach notification

## Detailed Mapping

### 01. Broken Access Control

**GDPR Requirements:**
- **Article 32(1)(b)**: Ability to ensure ongoing confidentiality
- **Article 32(4)**: Measures to ensure appropriate security level
- **Article 5(1)(f)**: Integrity and confidentiality

**Data Protection Impact:**
- Prevents unauthorized access to personal data
- Ensures data is accessible only to authorized persons
- Protects against unlawful processing

**Implementation:**
- Role-based access control for personal data
- Principle of least privilege
- Access logging and monitoring
- Regular access reviews

**GDPR Compliance Evidence:**
- Access control policies
- Authorization matrices
- Access logs and reviews
- Data Processing Records (Article 30)

---

### 02. Cryptographic Failures

**GDPR Requirements:**
- **Article 32(1)(a)**: Pseudonymization and encryption
- **Article 34(3)(a)**: Encryption reduces breach impact
- **Recital 83**: Encryption as security measure

**Data Protection Impact:**
- Protects confidentiality of personal data
- Reduces risk in case of breach
- Enables pseudonymization

**Implementation:**
- Encrypt personal data at rest (AES-256)
- Encrypt data in transit (TLS 1.2+)
- Secure key management
- Hash/pseudonymize where appropriate

**GDPR Compliance Evidence:**
- Encryption policies
- Key management procedures
- Data Protection Impact Assessment (DPIA)
- Technical measures documentation

---

### 03. Injection

**GDPR Requirements:**
- **Article 32(1)**: Ensure security of processing
- **Article 32(2)**: Protection against unlawful processing
- **Article 5(1)(f)**: Security principle

**Data Protection Impact:**
- Prevents data breaches through SQL injection
- Protects integrity of personal data
- Prevents unauthorized data disclosure

**Implementation:**
- Parameterized queries
- Input validation
- Web Application Firewall
- Regular security testing

**GDPR Compliance Evidence:**
- Security testing reports
- Vulnerability scan results
- Penetration testing
- Code review documentation

---

### 04. Insecure Design

**GDPR Requirements:**
- **Article 25**: Data protection by design
- **Article 32**: Appropriate technical measures
- **Recital 78**: Privacy by design

**Data Protection Impact:**
- Ensures security from initial design
- Implements privacy from the start
- Reduces likelihood of data breaches

**Implementation:**
- Privacy impact assessments (DPIA)
- Security requirements in design
- Threat modeling
- Privacy by design principles

**GDPR Compliance Evidence:**
- DPIA documentation
- Design documentation
- Security architecture reviews
- Threat models

---

### 05. Security Misconfiguration

**GDPR Requirements:**
- **Article 32(1)**: Appropriate security measures
- **Article 32(2)**: Regular testing and evaluation
- **Recital 83**: State of the art security

**Data Protection Impact:**
- Prevents accidental data exposure
- Ensures proper security configurations
- Maintains security over time

**Implementation:**
- Security hardening standards
- Configuration management
- Regular security assessments
- Automated compliance checking

**GDPR Compliance Evidence:**
- Configuration standards
- Security assessment reports
- Compliance scan results
- Change management records

---

### 06. Vulnerable and Outdated Components

**GDPR Requirements:**
- **Article 32(1)(d)**: Testing, assessment and evaluation
- **Article 32(2)**: Regular testing
- **Recital 83**: State of the art security

**Data Protection Impact:**
- Reduces risk of known vulnerabilities
- Maintains security posture
- Demonstrates due diligence

**Implementation:**
- Component inventory
- Vulnerability monitoring
- Patch management process
- Software composition analysis

**GDPR Compliance Evidence:**
- Patch management policy
- Vulnerability reports
- Component inventory
- Update logs

---

### 07. Identification and Authentication Failures

**GDPR Requirements:**
- **Article 32(1)**: Ensure confidentiality
- **Article 5(1)(f)**: Security of processing
- **Recital 39**: Pseudonymization

**Data Protection Impact:**
- Ensures only authorized access
- Protects against identity theft
- Maintains accountability

**Implementation:**
- Strong authentication mechanisms
- Multi-factor authentication
- Secure session management
- Password policies

**GDPR Compliance Evidence:**
- Authentication policies
- Access control documentation
- Security audit logs
- User training records

---

### 08. Software and Data Integrity Failures

**GDPR Requirements:**
- **Article 32(1)(b)**: Ongoing integrity
- **Article 5(1)(f)**: Integrity principle
- **Article 32(2)**: Ability to restore availability

**Data Protection Impact:**
- Ensures data has not been altered
- Protects against tampering
- Maintains data accuracy

**Implementation:**
- Digital signatures
- Integrity verification
- Secure CI/CD pipeline
- Change detection

**GDPR Compliance Evidence:**
- Integrity verification procedures
- Change logs
- Backup and recovery procedures
- Incident response documentation

---

### 09. Security Logging and Monitoring Failures

**GDPR Requirements:**
- **Article 32(1)(d)**: Regular testing and evaluation
- **Article 33**: Breach notification (72 hours)
- **Article 34**: Data subject notification
- **Recital 87**: Breach awareness

**Data Protection Impact:**
- Enables breach detection
- Supports breach notification
- Demonstrates accountability
- Facilitates incident response

**Implementation:**
- Centralized logging
- Security monitoring
- Breach detection systems
- Alert procedures

**GDPR Compliance Evidence:**
- Logging policies
- Monitoring procedures
- Breach response plan
- Incident logs

---

### 10. Server-Side Request Forgery (SSRF)

**GDPR Requirements:**
- **Article 32(1)**: Security of processing
- **Article 32(2)**: Protection against unlawful processing
- **Article 5(1)(f)**: Confidentiality

**Data Protection Impact:**
- Prevents unauthorized data access
- Protects internal systems
- Prevents data exfiltration

**Implementation:**
- URL validation
- Network segmentation
- Firewall rules
- Access controls

**GDPR Compliance Evidence:**
- Network security documentation
- Penetration test results
- Firewall configurations
- Security architecture

---

## GDPR Compliance Matrix

| OWASP Top 10 | Primary GDPR Article | Security Measure Type |
|--------------|----------------------|----------------------|
| 01. Broken Access Control | Art. 32(1)(b), Art. 5(1)(f) | Access Control |
| 02. Cryptographic Failures | Art. 32(1)(a) | Encryption |
| 03. Injection | Art. 32(1), Art. 5(1)(f) | Input Validation |
| 04. Insecure Design | Art. 25 | Privacy by Design |
| 05. Security Misconfiguration | Art. 32(1), Art. 32(2) | Configuration Mgmt |
| 06. Vulnerable Components | Art. 32(1)(d), Art. 32(2) | Vulnerability Mgmt |
| 07. Auth Failures | Art. 32(1), Art. 5(1)(f) | Authentication |
| 08. Data Integrity Failures | Art. 32(1)(b), Art. 5(1)(f) | Integrity Controls |
| 09. Logging Failures | Art. 32(1)(d), Art. 33 | Monitoring & Logging |
| 10. SSRF | Art. 32(1), Art. 5(1)(f) | Network Security |

## Data Protection Impact Assessment (DPIA)

When implementing OWASP Top 10 controls, consider DPIA requirements:

1. **Necessity and Proportionality**
   - Are the security measures appropriate?
   - Do they align with data sensitivity?

2. **Risks to Data Subjects**
   - What risks does each vulnerability pose?
   - How do controls mitigate risks?

3. **Measures to Address Risks**
   - Document how each OWASP item is addressed
   - Show residual risk levels

4. **Views of Data Subjects**
   - Consult on security measures where appropriate
   - Document privacy-friendly alternatives

## Breach Notification Considerations

OWASP vulnerabilities can lead to breaches requiring notification:

- **72-hour deadline** (Article 33)
- **Document all breaches** including those not notified
- **Categories of data affected**
- **Approximate number of data subjects**
- **Likely consequences**
- **Measures taken or proposed**

## Accountability and Documentation

**Required Documentation:**
- Security policies and procedures
- Data Protection Impact Assessments
- Records of Processing Activities (Article 30)
- Training records
- Incident response plans
- Technical and organizational measures

## Best Practices for GDPR Compliance

1. **Privacy by Design (Article 25)**
   - Integrate OWASP Top 10 into SDLC
   - Security from initial design

2. **Regular Testing (Article 32(1)(d))**
   - Vulnerability scanning
   - Penetration testing
   - Code reviews

3. **Incident Response (Articles 33/34)**
   - Detection capabilities
   - Response procedures
   - Notification processes

4. **Data Minimization (Article 5(1)(c))**
   - Only collect necessary data
   - Reduce attack surface
   - Limit breach impact

## References

- [GDPR Official Text](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [EDPB Guidelines](https://edpb.europa.eu/our-work-tools/general-guidance/guidelines_en)
- [OWASP GDPR Project](https://owasp.org/www-project-security-and-privacy-for-gdpr/)
- [ICO Guidance](https://ico.org.uk/for-organisations/guide-to-data-protection/)

---

*Last Updated: January 2026*
*Document Version: 1.0*
