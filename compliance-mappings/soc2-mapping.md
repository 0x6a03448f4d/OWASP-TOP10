# OWASP Top 10 → SOC 2 Mapping

## Overview

This document maps OWASP Top 10 Web Application Security Risks to SOC 2 Trust Service Criteria (TSC). SOC 2 is an auditing procedure that ensures service providers securely manage data to protect the interests of the organization and the privacy of its clients.

## SOC 2 Trust Service Criteria

SOC 2 is based on five Trust Service Criteria:
- **Security (CC)**: Common Criteria - foundational to all SOC 2 reports
- **Availability (A)**: System is available for operation and use
- **Processing Integrity (PI)**: System processing is complete, valid, accurate, timely, and authorized
- **Confidentiality (C)**: Confidential information is protected
- **Privacy (P)**: Personal information is collected, used, retained, disclosed, and disposed appropriately

## Mapping Table

### 01. Broken Access Control

| SOC 2 Criteria | Control Description | Implementation |
|----------------|---------------------|----------------|
| CC6.1 | Logical and physical access controls restrict access to authorized users | Implement role-based access control (RBAC) |
| CC6.2 | New internal and external users are registered and authorized before access | User provisioning and de-provisioning procedures |
| CC6.3 | Removed or changed access is timely | Access reviews and removal processes |
| CC6.6 | Logical access security measures prevent unauthorized access | Authentication and authorization mechanisms |
| CC7.2 | System monitoring detects and identifies anomalies | Access control monitoring and alerting |

**Evidence Examples:**
- Access control matrix documentation
- User access review logs
- RBAC configuration
- Authorization test results
- Access attempt monitoring logs

### 02. Cryptographic Failures

| SOC 2 Criteria | Control Description | Implementation |
|----------------|---------------------|----------------|
| CC6.1 | Data at rest and in transit is encrypted | TLS 1.2+, AES-256 encryption |
| CC6.7 | Encryption keys are managed appropriately | Key management system (KMS) |
| C1.1 | Confidential information is protected | Data classification and encryption |
| C1.2 | Confidential information disposal is appropriate | Secure deletion procedures |

**Evidence Examples:**
- Encryption configuration documentation
- Key management procedures
- TLS certificate validation
- Data classification policy
- Cryptographic standards compliance

### 03. Injection

| SOC 2 Criteria | Control Description | Implementation |
|----------------|---------------------|----------------|
| CC7.2 | System monitoring detects security events | Input validation monitoring |
| CC8.1 | System changes are authorized and tested | Code review for injection vulnerabilities |
| PI1.3 | Processing is complete and accurate | Input validation and sanitization |
| PI1.4 | Processing is valid | Parameterized queries and prepared statements |

**Evidence Examples:**
- Input validation test results
- Code review documentation
- SQL injection testing reports
- Parameterized query implementation
- WAF configuration and logs

### 04. Insecure Design

| SOC 2 Criteria | Control Description | Implementation |
|----------------|---------------------|----------------|
| CC3.1 | Management establishes security policies | Secure design principles documentation |
| CC3.2 | Management establishes a system of controls | Security requirements in SDLC |
| CC3.4 | Management establishes risk management | Threat modeling processes |
| CC8.1 | System changes are authorized, designed, and tested | Security architecture review |

**Evidence Examples:**
- Secure design guidelines
- Threat model documentation
- Security architecture diagrams
- Design review meeting notes
- Security requirements documents

### 05. Security Misconfiguration

| SOC 2 Criteria | Control Description | Implementation |
|----------------|---------------------|----------------|
| CC6.6 | Security configurations are defined and implemented | Configuration management procedures |
| CC7.1 | System components are identified and managed | Asset inventory and configuration baseline |
| CC7.2 | System monitoring detects configuration changes | Configuration drift detection |
| CC8.1 | Changes are tested before implementation | Configuration testing procedures |

**Evidence Examples:**
- Configuration baseline documentation
- Security hardening guides
- Configuration change logs
- Vulnerability scan results
- Patch management records

### 06. Vulnerable and Outdated Components

| SOC 2 Criteria | Control Description | Implementation |
|----------------|---------------------|----------------|
| CC7.1 | System components are identified and managed | Software inventory management |
| CC7.2 | Security events are monitored | Vulnerability monitoring |
| CC8.1 | System changes are tested | Patch testing procedures |
| A1.2 | System availability is monitored | Dependency health monitoring |

**Evidence Examples:**
- Software bill of materials (SBOM)
- Vulnerability scanning reports
- Patch management logs
- Dependency update procedures
- Security advisory reviews

### 07. Identification and Authentication Failures

| SOC 2 Criteria | Control Description | Implementation |
|----------------|---------------------|----------------|
| CC6.1 | Users are authenticated before access | Multi-factor authentication (MFA) |
| CC6.2 | User registration and authorization procedures | Identity verification processes |
| CC6.6 | Security measures prevent unauthorized access | Strong password policies |
| CC6.7 | Credentials are encrypted and protected | Credential storage security |

**Evidence Examples:**
- Authentication configuration
- MFA implementation documentation
- Password policy settings
- Session management procedures
- Authentication logs

### 08. Software and Data Integrity Failures

| SOC 2 Criteria | Control Description | Implementation |
|----------------|---------------------|----------------|
| CC8.1 | Changes are authorized, tested, and approved | CI/CD pipeline security |
| PI1.1 | Processing integrity policies exist | Code signing procedures |
| PI1.3 | Processing is complete and accurate | Integrity verification |
| PI1.5 | Stored information is complete and accurate | Data integrity checks |

**Evidence Examples:**
- Code signing certificates
- CI/CD security configuration
- Integrity verification procedures
- Supply chain security documentation
- Software composition analysis

### 09. Security Logging and Monitoring Failures

| SOC 2 Criteria | Control Description | Implementation |
|----------------|---------------------|----------------|
| CC7.2 | Security events are detected and monitored | SIEM implementation |
| CC7.3 | Security events are analyzed and responded to | Incident response procedures |
| CC7.4 | System is monitored for capacity | Log storage and retention |
| CC7.5 | System incidents are identified and managed | Alerting and escalation procedures |

**Evidence Examples:**
- Logging policy and procedures
- SIEM configuration
- Log retention schedules
- Security incident reports
- Monitoring dashboard screenshots

### 10. Server-Side Request Forgery (SSRF)

| SOC 2 Criteria | Control Description | Implementation |
|----------------|---------------------|----------------|
| CC6.6 | Security measures prevent unauthorized access | Network segmentation |
| CC6.7 | Infrastructure is protected | Firewall and network controls |
| CC7.2 | Security events are monitored | Network traffic monitoring |
| PI1.4 | Processing is valid | URL validation and allowlisting |

**Evidence Examples:**
- Network architecture diagrams
- Firewall rules documentation
- URL validation procedures
- Network segmentation documentation
- Security testing results

## Control Category Summary

### Common Criteria (CC) - Security

All OWASP Top 10 vulnerabilities primarily map to SOC 2 Security Common Criteria:

| CC Category | Related OWASP Items |
|-------------|---------------------|
| CC3 - Risk Assessment | 04 - Insecure Design |
| CC6 - Logical Access | 01, 02, 07, 10 |
| CC7 - System Monitoring | 03, 05, 06, 09 |
| CC8 - Change Management | 04, 05, 06, 08 |

### Processing Integrity (PI)

| PI Criteria | Related OWASP Items |
|-------------|---------------------|
| PI1.1 - Processing Policies | 08 - Data Integrity Failures |
| PI1.3 - Complete Processing | 03 - Injection |
| PI1.4 - Valid Processing | 03, 10 |
| PI1.5 - Data Accuracy | 08 - Data Integrity Failures |

### Confidentiality (C)

| C Criteria | Related OWASP Items |
|------------|---------------------|
| C1.1 - Information Protection | 02 - Cryptographic Failures |
| C1.2 - Disposal | 02 - Cryptographic Failures |

### Availability (A)

| A Criteria | Related OWASP Items |
|------------|---------------------|
| A1.2 - System Monitoring | 06 - Vulnerable Components |

## Implementation Priority

### High Priority (Audit-Critical)
1. **CC6.1** - Logical access controls (affects: 01, 02)
2. **CC7.2** - Security monitoring (affects: 03, 05, 06, 09, 10)
3. **CC8.1** - Change management (affects: 04, 05, 06, 08)

### Medium Priority
1. **CC6.6** - Access security measures (affects: 05, 07, 10)
2. **CC7.3** - Event response (affects: 09)
3. **PI1.3/PI1.4** - Processing integrity (affects: 03, 08, 10)

### Continuous Improvement
1. **CC3.1-CC3.4** - Risk management (affects: 04)
2. **CC7.1** - Asset management (affects: 05, 06)
3. **C1.1-C1.2** - Confidentiality (affects: 02)

## Audit Preparation

### Documentation Required

For each OWASP vulnerability addressed:

1. **Control Description**: How the control prevents/detects the vulnerability
2. **Implementation Evidence**: Configuration, code, policies
3. **Operating Effectiveness**: Logs, reports showing controls work
4. **Testing Results**: Security testing demonstrating effectiveness
5. **Exception Handling**: How deviations are managed

### Sample Control Testing

**Example: Testing CC6.1 for Broken Access Control**

```
Control: Role-based access control prevents unauthorized access

Test Steps:
1. Review RBAC configuration
2. Test access with various user roles
3. Attempt unauthorized access
4. Review access logs
5. Verify least privilege implementation

Expected Results:
- Users can only access authorized resources
- Unauthorized attempts are blocked and logged
- Principle of least privilege is enforced
- Access reviews occur quarterly

Evidence:
- RBAC configuration export
- Access test results
- Access review logs
- Unauthorized access attempt logs
```

## Compliance Dashboard

### Coverage Matrix

| OWASP Top 10 | Security (CC) | Processing Integrity (PI) | Confidentiality (C) | Availability (A) |
|--------------|---------------|---------------------------|---------------------|------------------|
| 01. Broken Access Control | ✅ High | - | - | - |
| 02. Cryptographic Failures | ✅ High | - | ✅ High | - |
| 03. Injection | ✅ Medium | ✅ High | - | - |
| 04. Insecure Design | ✅ High | - | - | - |
| 05. Security Misconfiguration | ✅ High | - | - | - |
| 06. Vulnerable Components | ✅ Medium | - | - | ✅ Medium |
| 07. Auth Failures | ✅ High | - | - | - |
| 08. Data Integrity Failures | ✅ Medium | ✅ High | - | - |
| 09. Logging Failures | ✅ High | - | - | - |
| 10. SSRF | ✅ Medium | ✅ Medium | - | - |

## Remediation Roadmap

### Phase 1: Foundation (Months 1-3)
- Implement CC6.1 - Access controls
- Implement CC6.6 - Authentication
- Implement CC7.2 - Monitoring
- Document policies and procedures

### Phase 2: Enhancement (Months 4-6)
- Implement CC8.1 - Change management
- Implement PI1.3/PI1.4 - Input validation
- Implement C1.1 - Encryption
- Conduct security testing

### Phase 3: Optimization (Months 7-12)
- Implement CC3.x - Risk management
- Implement CC7.3 - Incident response
- Continuous monitoring
- Regular audits and improvements

## Best Practices

### For Security Teams
1. Document all controls with clear mappings to TSC
2. Maintain evidence of control operation
3. Conduct regular control testing
4. Update controls as vulnerabilities evolve

### For Compliance Teams
1. Align vulnerability remediation with SOC 2 requirements
2. Track control effectiveness metrics
3. Prepare comprehensive audit documentation
4. Coordinate with security for testing

### For Development Teams
1. Follow secure coding practices aligned with controls
2. Participate in security testing
3. Document security-relevant changes
4. Maintain security awareness

## References

- [SOC 2 Trust Service Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustdataintegritytaskforce.html)
- [AICPA SOC 2 Reporting](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome.html)
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)

## Updates

This mapping is reviewed and updated:
- Annually, or when TSC updates occur
- When OWASP Top 10 is revised
- Based on audit feedback
- As security landscape evolves

---

**Last Updated**: January 2026  
**Version**: 1.0  
**Contact**: See [SECURITY.md](../SECURITY.md) for questions
