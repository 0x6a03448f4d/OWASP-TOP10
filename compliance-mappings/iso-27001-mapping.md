# OWASP Top 10 → ISO 27001:2022 Mapping

## Overview

This document maps OWASP Top 10 Web Application Security Risks to ISO/IEC 27001:2022 Annex A controls. ISO 27001 is the international standard for information security management systems (ISMS).

## ISO 27001:2022 Structure

ISO 27001:2022 Annex A contains 93 controls across 4 themes:
- **Organizational controls** (37 controls)
- **People controls** (8 controls)
- **Physical controls** (14 controls)
- **Technological controls** (34 controls)

## Mapping Table

### 01. Broken Access Control

| ISO 27001 Control | Control Name | Implementation |
|-------------------|--------------|----------------|
| A.5.15 | Access control | Implement role-based access control (RBAC) |
| A.5.16 | Identity management | User provisioning and lifecycle management |
| A.5.18 | Access rights | Principle of least privilege |
| A.8.2 | Privileged access rights | Segregation of duties for privileged users |
| A.8.3 | Information access restriction | Enforce access restrictions at all layers |
| A.8.5 | Secure authentication | Multi-factor authentication where appropriate |

**Implementation Guidance:**
- Define access control policy
- Implement RBAC with least privilege
- Regular access reviews (quarterly minimum)
- Automated access provisioning/de-provisioning
- Access logging and monitoring

**Evidence Examples:**
- Access control policy document
- RBAC configuration and matrix
- Access review logs and reports
- User provisioning procedures
- Access violation alerts

### 02. Cryptographic Failures

| ISO 27001 Control | Control Name | Implementation |
|-------------------|--------------|----------------|
| A.8.24 | Use of cryptography | Strong encryption for data at rest and in transit |
| A.5.10 | Acceptable use of information | Data classification policy |
| A.5.12 | Classification of information | Identify sensitive data requiring encryption |
| A.5.14 | Information transfer | Secure protocols (TLS 1.2+) |
| A.8.11 | Data masking | Mask/tokenize sensitive data |

**Implementation Guidance:**
- Use industry-standard encryption (AES-256, RSA-2048+)
- Implement TLS 1.2 or higher for data in transit
- Proper key management and rotation
- Data classification and handling procedures
- Encryption at application and storage layers

**Evidence Examples:**
- Cryptographic standards documentation
- Key management procedures
- TLS configuration and certificates
- Data classification matrix
- Encryption implementation review

### 03. Injection

| ISO 27001 Control | Control Name | Implementation |
|-------------------|--------------|----------------|
| A.8.3 | Information access restriction | Input validation at all entry points |
| A.8.16 | Monitoring activities | Monitor for injection attempts |
| A.8.23 | Web filtering | Web application firewall (WAF) |
| A.8.25 | Secure development lifecycle | Security in SDLC - code reviews |
| A.8.26 | Application security requirements | Define security requirements early |
| A.8.28 | Secure coding | Follow secure coding guidelines |

**Implementation Guidance:**
- Use parameterized queries/prepared statements
- Input validation and sanitization
- Output encoding
- Principle of least privilege for database access
- Regular security testing and code review

**Evidence Examples:**
- Secure coding standards
- Code review reports
- Penetration testing results
- WAF configuration and logs
- Input validation implementation

### 04. Insecure Design

| ISO 27001 Control | Control Name | Implementation |
|-------------------|--------------|----------------|
| A.5.8 | Information security in project management | Security in all project phases |
| A.5.9 | Inventory of information and assets | Asset identification for threat modeling |
| A.5.21 | Managing information security in ICT supply chain | Secure supply chain design |
| A.8.25 | Secure development lifecycle | Security requirements in design phase |
| A.8.26 | Application security requirements | Document security requirements |
| A.8.29 | Security testing in development | Security testing in all phases |

**Implementation Guidance:**
- Threat modeling for all new systems
- Security architecture review
- Secure design principles (fail securely, defense in depth)
- Security requirements documentation
- Design review with security team

**Evidence Examples:**
- Threat model documentation
- Security architecture diagrams
- Design review meeting minutes
- Security requirements documents
- Risk assessment results

### 05. Security Misconfiguration

| ISO 27001 Control | Control Name | Implementation |
|-------------------|--------------|----------------|
| A.5.23 | Information security for use of cloud services | Secure cloud configuration |
| A.8.8 | Management of technical vulnerabilities | Vulnerability management |
| A.8.9 | Configuration management | Secure baseline configurations |
| A.8.12 | Data leakage prevention | Prevent information disclosure |
| A.8.16 | Monitoring activities | Monitor configuration changes |
| A.8.19 | Installation of software | Controlled software installation |

**Implementation Guidance:**
- Security hardening guides
- Configuration management database (CMDB)
- Automated configuration scanning
- Disable unnecessary features/services
- Regular configuration audits

**Evidence Examples:**
- Security baseline documentation
- Configuration management procedures
- Vulnerability scan reports
- Change management logs
- Security hardening checklist

### 06. Vulnerable and Outdated Components

| ISO 27001 Control | Control Name | Implementation |
|-------------------|--------------|----------------|
| A.5.21 | Managing information security in ICT supply chain | Supply chain security |
| A.8.8 | Management of technical vulnerabilities | Patch management |
| A.8.19 | Installation of software | Software inventory and updates |
| A.8.25 | Secure development lifecycle | Dependency management in SDLC |
| A.8.31 | Separation of development, test and production | Environment separation |

**Implementation Guidance:**
- Maintain software bill of materials (SBOM)
- Automated vulnerability scanning
- Timely patching process
- Dependency update procedures
- Vendor security monitoring

**Evidence Examples:**
- Software inventory (SBOM)
- Patch management logs
- Vulnerability scan results
- Dependency update records
- Security advisory tracking

### 07. Identification and Authentication Failures

| ISO 27001 Control | Control Name | Implementation |
|-------------------|--------------|----------------|
| A.5.16 | Identity management | Identity lifecycle management |
| A.5.17 | Authentication information | Secure credential management |
| A.5.18 | Access rights | Access rights management |
| A.8.2 | Privileged access rights | Privileged account management |
| A.8.5 | Secure authentication | MFA, strong passwords, biometrics |

**Implementation Guidance:**
- Multi-factor authentication (MFA)
- Strong password policies
- Secure session management
- Account lockout mechanisms
- Password storage best practices (bcrypt, Argon2)

**Evidence Examples:**
- Authentication policy
- MFA configuration
- Password policy settings
- Session management documentation
- Identity management procedures

### 08. Software and Data Integrity Failures

| ISO 27001 Control | Control Name | Implementation |
|-------------------|--------------|----------------|
| A.5.21 | Managing information security in ICT supply chain | Supply chain integrity |
| A.8.25 | Secure development lifecycle | Secure CI/CD pipeline |
| A.8.26 | Application security requirements | Integrity requirements |
| A.8.31 | Separation of development, test and production | Environment controls |
| A.8.32 | Change management | Authorized changes only |

**Implementation Guidance:**
- Code signing and verification
- Secure CI/CD pipeline
- Integrity monitoring
- Supply chain security controls
- Separation of duties in deployments

**Evidence Examples:**
- Code signing procedures
- CI/CD security configuration
- Software composition analysis
- Change management records
- Integrity verification logs

### 09. Security Logging and Monitoring Failures

| ISO 27001 Control | Control Name | Implementation |
|-------------------|--------------|----------------|
| A.8.15 | Logging | Comprehensive security logging |
| A.8.16 | Monitoring activities | Continuous monitoring |
| A.5.24 | Information security incident management planning | Incident detection and response |
| A.5.25 | Assessment of information security events | Event analysis |
| A.5.26 | Response to information security incidents | Incident response procedures |
| A.5.28 | Collection of evidence | Evidence preservation |

**Implementation Guidance:**
- Centralized logging (SIEM)
- Log retention policy (minimum 12 months)
- Real-time alerting
- Log integrity protection
- Incident response procedures

**Evidence Examples:**
- Logging policy and procedures
- SIEM configuration
- Log retention schedules
- Security incident reports
- Monitoring dashboards

### 10. Server-Side Request Forgery (SSRF)

| ISO 27001 Control | Control Name | Implementation |
|-------------------|--------------|----------------|
| A.8.3 | Information access restriction | Network segmentation |
| A.8.20 | Networks security | Firewall rules and network controls |
| A.8.21 | Security of network services | Service-level security |
| A.8.23 | Web filtering | URL filtering and validation |
| A.8.28 | Secure coding | Input validation for URLs |

**Implementation Guidance:**
- Network segmentation and isolation
- URL allowlisting/denylisting
- Disable unnecessary protocols
- Internal service protection
- Input validation for all URLs

**Evidence Examples:**
- Network architecture diagrams
- Firewall configuration
- URL validation procedures
- Network segmentation documentation
- Penetration testing results

## Control Theme Summary

### Organizational Controls

| Theme | Related Controls | OWASP Items |
|-------|------------------|-------------|
| Information Security Policies | A.5.1 | All |
| Information Security Roles | A.5.2 | All |
| Segregation of Duties | A.5.3 | 01, 07, 08 |
| Asset Management | A.5.9 | 04, 05, 06 |
| Access Control | A.5.15-A.5.18 | 01, 07 |
| Information Security in Projects | A.5.8 | 04 |

### People Controls

| Theme | Related Controls | OWASP Items |
|-------|------------------|-------------|
| Screening | A.6.1 | 07 |
| Terms and Conditions | A.6.2 | All |
| Information Security Awareness | A.6.3 | All |
| Disciplinary Process | A.6.4 | All |

### Physical Controls

Physical controls are less directly related to application vulnerabilities but support overall security posture.

### Technological Controls

| Theme | Related Controls | OWASP Items |
|-------|------------------|-------------|
| User Endpoint Devices | A.8.1 | 05, 07 |
| Privileged Access Rights | A.8.2 | 01 |
| Information Access Restriction | A.8.3 | 01, 03, 10 |
| Secure Authentication | A.8.5 | 07 |
| Technical Vulnerability Management | A.8.8 | 05, 06 |
| Configuration Management | A.8.9 | 05 |
| Secure Development | A.8.25-A.8.28 | 03, 04, 08, 10 |
| Security Testing | A.8.29 | All |
| Logging & Monitoring | A.8.15-A.8.16 | 09 |

## Implementation Priority by Risk

### Critical (Immediate Implementation)
1. **A.8.5** - Secure authentication (affects: 07)
2. **A.8.15** - Logging (affects: 09)
3. **A.5.15** - Access control (affects: 01)
4. **A.8.24** - Cryptography (affects: 02)

### High (Within 3 months)
1. **A.8.28** - Secure coding (affects: 03, 10)
2. **A.8.8** - Vulnerability management (affects: 06)
3. **A.8.25** - Secure development lifecycle (affects: 04, 08)
4. **A.8.9** - Configuration management (affects: 05)

### Medium (Within 6 months)
1. **A.8.16** - Monitoring activities (affects: 09)
2. **A.8.3** - Information access restriction (affects: 01, 03, 10)
3. **A.8.26** - Application security requirements (affects: 04)
4. **A.5.21** - ICT supply chain (affects: 06, 08)

## Statement of Applicability (SoA)

For each control, document:

| Control | Applicable? | Justification | Implementation Status | Owner |
|---------|-------------|---------------|----------------------|-------|
| A.5.15 | Yes | Access control required for all systems | Implemented | Security Team |
| A.8.24 | Yes | Encryption required for sensitive data | Implemented | DevOps Team |
| ... | ... | ... | ... | ... |

## Risk Treatment Plan

### Addressing OWASP Top 10

| OWASP Item | Risk Level | Treatment | Target Date | Responsible |
|------------|------------|-----------|-------------|-------------|
| 01 - Access Control | High | Implement A.5.15, A.8.2, A.8.3 | Q1 2026 | Security |
| 02 - Cryptography | High | Implement A.8.24, A.5.14 | Q1 2026 | DevOps |
| 03 - Injection | Critical | Implement A.8.28, A.8.23 | Q1 2026 | Development |
| ... | ... | ... | ... | ... |

## Audit Preparation

### Evidence Collection

For ISO 27001 certification audits:

1. **Policy Documents**
   - Information security policy
   - Access control policy
   - Cryptography policy
   - Secure development policy

2. **Procedures**
   - Access provisioning
   - Patch management
   - Incident response
   - Change management

3. **Technical Evidence**
   - Configuration files
   - Security scan reports
   - Penetration test results
   - Log samples

4. **Management Evidence**
   - Risk register
   - Management review minutes
   - Training records
   - Audit reports

### Sample Audit Questions

**A.5.15 - Access Control**
- Q: How do you ensure users only access what they need?
- A: RBAC implementation, quarterly access reviews, least privilege principle

**A.8.24 - Cryptography**
- Q: What encryption do you use for sensitive data?
- A: AES-256 at rest, TLS 1.3 in transit, key rotation every 90 days

**A.8.28 - Secure Coding**
- Q: How do you prevent injection vulnerabilities?
- A: Parameterized queries, input validation, code reviews, SAST tools

## Compliance Dashboard

### Control Implementation Status

| Control Category | Total Controls | Implemented | In Progress | Not Started |
|------------------|----------------|-------------|-------------|-------------|
| Organizational | 15 | 12 | 2 | 1 |
| People | 4 | 4 | 0 | 0 |
| Physical | 2 | 2 | 0 | 0 |
| Technological | 20 | 15 | 4 | 1 |

### OWASP Coverage

| OWASP Item | Controls Mapped | Implementation % |
|------------|-----------------|------------------|
| 01 - Access Control | 6 | 100% |
| 02 - Cryptography | 5 | 100% |
| 03 - Injection | 6 | 80% |
| 04 - Insecure Design | 6 | 70% |
| 05 - Misconfiguration | 6 | 90% |
| 06 - Vulnerable Components | 5 | 85% |
| 07 - Auth Failures | 5 | 100% |
| 08 - Data Integrity | 5 | 75% |
| 09 - Logging Failures | 6 | 100% |
| 10 - SSRF | 5 | 80% |

## Best Practices

### For ISMS Managers
1. Integrate OWASP Top 10 into risk assessment
2. Map controls to multiple vulnerabilities
3. Regular control effectiveness reviews
4. Update SoA when addressing new vulnerabilities

### For Security Teams
1. Document control implementation thoroughly
2. Maintain evidence of control operation
3. Regular testing and validation
4. Continuous improvement mindset

### For Development Teams
1. Understand relevant controls (A.8.25-A.8.29)
2. Follow secure coding guidelines
3. Participate in security testing
4. Document security decisions

## Certification Process

### Timeline

1. **Gap Analysis** (Month 1-2)
   - Assess current state
   - Identify missing controls
   - Create remediation plan

2. **Implementation** (Month 3-8)
   - Implement required controls
   - Document policies and procedures
   - Train personnel

3. **Internal Audit** (Month 9-10)
   - Verify control effectiveness
   - Address findings
   - Management review

4. **Certification Audit** (Month 11-12)
   - Stage 1: Documentation review
   - Stage 2: On-site assessment
   - Receive certification

## References

- [ISO/IEC 27001:2022](https://www.iso.org/standard/82875.html)
- [ISO/IEC 27002:2022](https://www.iso.org/standard/75652.html) - Implementation guidance
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [ISO 27001 Toolkit](https://www.iso27001security.com/)

## Change History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | Jan 2026 | Initial mapping to ISO 27001:2022 | Security Team |

---

**Last Updated**: January 2026  
**Standard Version**: ISO/IEC 27001:2022  
**Contact**: See [SECURITY.md](../SECURITY.md) for questions
