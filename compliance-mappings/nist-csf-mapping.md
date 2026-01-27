# OWASP Top 10 → NIST Cybersecurity Framework Mapping

## Overview

This document maps OWASP Top 10 Web Application Security Risks to the NIST Cybersecurity Framework (CSF) 2.0. The NIST CSF provides a policy framework of computer security guidance for how organizations can assess and improve their ability to prevent, detect, and respond to cyber attacks.

## NIST CSF 2.0 Structure

The framework consists of 6 core functions:
- **Govern (GV)**: Establish and monitor the organization's cybersecurity risk management strategy
- **Identify (ID)**: Understand cybersecurity risks to systems, people, assets, data, and capabilities
- **Protect (PR)**: Implement safeguards to manage cybersecurity risks
- **Detect (DE)**: Find and analyze possible cybersecurity attacks and compromises
- **Respond (RS)**: Take action regarding a detected cybersecurity incident
- **Recover (RC)**: Restore assets and operations affected by a cybersecurity incident

## Mapping Table

### 01. Broken Access Control

| NIST CSF Category | Subcategory ID | Description | Implementation |
|-------------------|----------------|-------------|----------------|
| Protect | PR.AA-01 | Identities and credentials are managed | Identity and access management (IAM) |
| Protect | PR.AA-02 | Identities are proofed and bound to credentials | User verification processes |
| Protect | PR.AA-05 | Access permissions are managed | Role-based access control (RBAC) |
| Protect | PR.AA-06 | Physical and logical access to assets is managed | Access control lists and policies |
| Protect | PR.DS-05 | Protections against data leaks are implemented | Data loss prevention (DLP) |
| Detect | DE.CM-01 | Networks and network services are monitored | Monitor access attempts |

**NIST CSF Implementation Tiers:**
- **Tier 1 (Partial)**: Manual access reviews, basic authentication
- **Tier 2 (Risk-Informed)**: RBAC implementation, periodic reviews
- **Tier 3 (Repeatable)**: Automated access provisioning, continuous monitoring
- **Tier 4 (Adaptive)**: AI-driven anomaly detection, adaptive access control

**Evidence Examples:**
- Access control policies
- RBAC implementation documentation
- Access review logs
- IAM system configuration
- Access monitoring dashboards

### 02. Cryptographic Failures

| NIST CSF Category | Subcategory ID | Description | Implementation |
|-------------------|----------------|-------------|----------------|
| Protect | PR.DS-01 | Data-at-rest is protected | AES-256 encryption for stored data |
| Protect | PR.DS-02 | Data-in-transit is protected | TLS 1.2+ for all communications |
| Protect | PR.DS-05 | Protections against data leaks are implemented | Encryption key management |
| Identify | ID.RA-07 | Threats are identified and documented | Cryptographic risk assessment |
| Protect | PR.DS-08 | Integrity checking mechanisms verify software and data | Digital signatures and hashing |

**NIST CSF Implementation Tiers:**
- **Tier 1**: Basic encryption, manual key management
- **Tier 2**: Standard encryption algorithms, key rotation policy
- **Tier 3**: Automated key management, HSM usage
- **Tier 4**: Quantum-resistant algorithms, zero-trust architecture

**Evidence Examples:**
- Encryption policy and standards
- Key management procedures
- TLS certificate inventory
- Cryptographic implementation audit
- Data classification matrix

### 03. Injection

| NIST CSF Category | Subcategory ID | Description | Implementation |
|-------------------|----------------|-------------|----------------|
| Protect | PR.DS-05 | Protections against data leaks are implemented | Input validation and sanitization |
| Protect | PR.PS-01 | Configuration management practices are established | Secure coding standards |
| Detect | DE.CM-04 | Malicious code is detected | Web application firewall (WAF) |
| Detect | DE.CM-06 | External service provider activity is monitored | API security monitoring |
| Protect | PR.IP-02 | A System Development Life Cycle is implemented | Security in SDLC |

**NIST CSF Implementation Tiers:**
- **Tier 1**: Basic input validation, manual code reviews
- **Tier 2**: Parameterized queries, regular security testing
- **Tier 3**: Automated SAST/DAST, WAF implementation
- **Tier 4**: AI-powered threat detection, runtime protection

**Evidence Examples:**
- Secure coding guidelines
- Code review reports
- WAF configuration and logs
- Security testing results (SAST/DAST)
- Input validation framework documentation

### 04. Insecure Design

| NIST CSF Category | Subcategory ID | Description | Implementation |
|-------------------|----------------|-------------|----------------|
| Govern | GV.RR-02 | Roles, responsibilities, and authorities related to cybersecurity | Security champions program |
| Identify | ID.RA-01 | Asset vulnerabilities are identified | Threat modeling |
| Identify | ID.RA-02 | Cyber threat intelligence is received | Threat intelligence integration |
| Identify | ID.RA-03 | Internal and external threats are identified | Security design review |
| Protect | PR.IP-02 | A System Development Life Cycle is implemented | Security requirements in design |

**NIST CSF Implementation Tiers:**
- **Tier 1**: Ad-hoc security considerations
- **Tier 2**: Security reviews for major projects
- **Tier 3**: Mandatory threat modeling, security architecture
- **Tier 4**: Continuous security design evolution

**Evidence Examples:**
- Threat model documentation
- Security architecture diagrams
- Design review meeting notes
- Security requirements documents
- Risk assessment reports

### 05. Security Misconfiguration

| NIST CSF Category | Subcategory ID | Description | Implementation |
|-------------------|----------------|-------------|----------------|
| Identify | ID.AM-02 | Software platforms and applications are inventoried | Asset inventory management |
| Protect | PR.IP-01 | A baseline configuration is created and maintained | Security baselines |
| Protect | PR.IP-04 | Backups are performed | Configuration backups |
| Protect | PR.PS-01 | Configuration management practices are established | Configuration management |
| Detect | DE.CM-08 | Vulnerability scans are performed | Regular security scanning |

**NIST CSF Implementation Tiers:**
- **Tier 1**: Manual configuration, inconsistent baselines
- **Tier 2**: Documented baselines, periodic audits
- **Tier 3**: Automated configuration management, continuous scanning
- **Tier 4**: Self-healing infrastructure, infrastructure as code

**Evidence Examples:**
- Configuration baseline documentation
- Security hardening guides
- Vulnerability scan reports
- Configuration management database (CMDB)
- Change management records

### 06. Vulnerable and Outdated Components

| NIST CSF Category | Subcategory ID | Description | Implementation |
|-------------------|----------------|-------------|----------------|
| Identify | ID.AM-02 | Software platforms and applications are inventoried | Software Bill of Materials (SBOM) |
| Govern | GV.SC-03 | Cybersecurity supply chain risk management is established | Supply chain risk assessment |
| Protect | PR.IP-12 | A vulnerability management plan is developed | Patch management process |
| Detect | DE.CM-08 | Vulnerability scans are performed | Automated vulnerability scanning |
| Respond | RS.MI-03 | Newly identified vulnerabilities are mitigated | Vulnerability remediation |

**NIST CSF Implementation Tiers:**
- **Tier 1**: Reactive patching, manual inventory
- **Tier 2**: Regular scanning, patch schedule
- **Tier 3**: Automated vulnerability management, SBOM generation
- **Tier 4**: Predictive vulnerability analysis, auto-remediation

**Evidence Examples:**
- Software inventory (SBOM)
- Vulnerability scan reports
- Patch management logs
- Dependency update procedures
- Vendor security advisories tracking

### 07. Identification and Authentication Failures

| NIST CSF Category | Subcategory ID | Description | Implementation |
|-------------------|----------------|-------------|----------------|
| Protect | PR.AA-01 | Identities and credentials are managed | Identity lifecycle management |
| Protect | PR.AA-02 | Identities are proofed and bound to credentials | Strong authentication |
| Protect | PR.AA-03 | Users, devices, and assets are authenticated | Multi-factor authentication (MFA) |
| Protect | PR.AA-04 | Identity assertions are protected | Secure session management |
| Detect | DE.CM-03 | Personnel activity is monitored | Authentication monitoring |

**NIST CSF Implementation Tiers:**
- **Tier 1**: Basic passwords, manual account management
- **Tier 2**: Password policies, MFA for privileged accounts
- **Tier 3**: Enterprise MFA, SSO, automated lifecycle
- **Tier 4**: Passwordless authentication, risk-based auth

**Evidence Examples:**
- Authentication policy
- MFA implementation documentation
- Password policy settings
- Session management configuration
- Authentication logs and monitoring

### 08. Software and Data Integrity Failures

| NIST CSF Category | Subcategory ID | Description | Implementation |
|-------------------|----------------|-------------|----------------|
| Govern | GV.SC-02 | Suppliers are known and prioritized | Supply chain management |
| Govern | GV.SC-06 | Planning and due diligence to reduce supply chain risk | Vendor security assessment |
| Protect | PR.DS-06 | Integrity checking mechanisms verify software | Code signing and verification |
| Protect | PR.DS-08 | Integrity checking mechanisms verify data | Data integrity monitoring |
| Protect | PR.IP-02 | A System Development Life Cycle is implemented | Secure CI/CD pipeline |

**NIST CSF Implementation Tiers:**
- **Tier 1**: Manual verification, basic checksums
- **Tier 2**: Code signing, integrity checks
- **Tier 3**: Automated verification, secure pipeline
- **Tier 4**: Zero-trust supply chain, continuous verification

**Evidence Examples:**
- Code signing procedures
- CI/CD security configuration
- Software composition analysis reports
- Integrity verification logs
- Supply chain security documentation

### 09. Security Logging and Monitoring Failures

| NIST CSF Category | Subcategory ID | Description | Implementation |
|-------------------|----------------|-------------|----------------|
| Detect | DE.CM-01 | Networks and network services are monitored | Network monitoring |
| Detect | DE.CM-06 | External service provider activity is monitored | Third-party monitoring |
| Detect | DE.CM-09 | Computing hardware and software are monitored | Endpoint monitoring |
| Detect | DE.AE-02 | Potentially adverse events are analyzed | Security event analysis |
| Respond | RS.AN-01 | Notifications are investigated | Incident investigation |

**NIST CSF Implementation Tiers:**
- **Tier 1**: Basic logging, manual review
- **Tier 2**: Centralized logging, periodic analysis
- **Tier 3**: SIEM implementation, real-time alerting
- **Tier 4**: AI-powered threat detection, automated response

**Evidence Examples:**
- Logging policy
- SIEM configuration
- Log retention procedures
- Security incident reports
- Monitoring dashboards

### 10. Server-Side Request Forgery (SSRF)

| NIST CSF Category | Subcategory ID | Description | Implementation |
|-------------------|----------------|-------------|----------------|
| Protect | PR.AC-05 | Network integrity is protected | Network segmentation |
| Protect | PR.DS-05 | Protections against data leaks are implemented | Input validation for URLs |
| Protect | PR.PT-04 | Communications and control networks are protected | Firewall rules |
| Detect | DE.CM-01 | Networks and network services are monitored | Network traffic monitoring |
| Detect | DE.CM-07 | Monitoring for unauthorized activity is performed | Anomaly detection |

**NIST CSF Implementation Tiers:**
- **Tier 1**: Basic firewall, manual URL validation
- **Tier 2**: Network segmentation, URL filtering
- **Tier 3**: Automated allowlisting, traffic analysis
- **Tier 4**: Zero-trust network, ML-based detection

**Evidence Examples:**
- Network architecture diagrams
- Firewall configuration
- URL validation procedures
- Network segmentation documentation
- Traffic analysis reports

## Function Summary

### Govern (GV)

| OWASP Item | Related Subcategories | Priority |
|------------|----------------------|----------|
| 04 - Insecure Design | GV.RR-02 | High |
| 06 - Vulnerable Components | GV.SC-03 | High |
| 08 - Data Integrity | GV.SC-02, GV.SC-06 | High |

### Identify (ID)

| OWASP Item | Related Subcategories | Priority |
|------------|----------------------|----------|
| 04 - Insecure Design | ID.RA-01, ID.RA-02, ID.RA-03 | High |
| 05 - Misconfiguration | ID.AM-02 | Medium |
| 06 - Vulnerable Components | ID.AM-02 | High |

### Protect (PR)

| OWASP Item | Related Subcategories | Priority |
|------------|----------------------|----------|
| 01 - Access Control | PR.AA-01, PR.AA-02, PR.AA-05, PR.AA-06 | Critical |
| 02 - Cryptography | PR.DS-01, PR.DS-02, PR.DS-05 | Critical |
| 03 - Injection | PR.DS-05, PR.PS-01, PR.IP-02 | Critical |
| 05 - Misconfiguration | PR.IP-01, PR.PS-01 | High |
| 06 - Vulnerable Components | PR.IP-12 | High |
| 07 - Auth Failures | PR.AA-01, PR.AA-02, PR.AA-03, PR.AA-04 | Critical |
| 08 - Data Integrity | PR.DS-06, PR.DS-08, PR.IP-02 | High |
| 10 - SSRF | PR.AC-05, PR.PT-04 | High |

### Detect (DE)

| OWASP Item | Related Subcategories | Priority |
|------------|----------------------|----------|
| 01 - Access Control | DE.CM-01 | High |
| 03 - Injection | DE.CM-04, DE.CM-06 | High |
| 05 - Misconfiguration | DE.CM-08 | Medium |
| 06 - Vulnerable Components | DE.CM-08 | High |
| 07 - Auth Failures | DE.CM-03 | High |
| 09 - Logging Failures | DE.CM-01, DE.CM-06, DE.CM-09, DE.AE-02 | Critical |
| 10 - SSRF | DE.CM-01, DE.CM-07 | Medium |

### Respond (RS)

| OWASP Item | Related Subcategories | Priority |
|------------|----------------------|----------|
| 06 - Vulnerable Components | RS.MI-03 | High |
| 09 - Logging Failures | RS.AN-01 | High |

### Recover (RC)

Recovery functions apply broadly to incident response but are less specific to individual vulnerabilities.

## Implementation Roadmap

### Phase 1: Foundation (Months 1-3)
**Focus: Protect Function**
- PR.AA (Access Control) - Addresses OWASP 01, 07
- PR.DS (Data Security) - Addresses OWASP 02
- PR.IP-02 (SDLC) - Addresses OWASP 03, 04, 08

### Phase 2: Detection (Months 4-6)
**Focus: Detect Function**
- DE.CM (Monitoring) - Addresses OWASP 09
- DE.CM-08 (Vulnerability Scanning) - Addresses OWASP 05, 06
- DE.AE (Anomaly Detection) - Addresses OWASP 09

### Phase 3: Governance (Months 7-9)
**Focus: Govern Function**
- GV.SC (Supply Chain) - Addresses OWASP 06, 08
- GV.RR (Roles & Responsibilities) - Addresses OWASP 04

### Phase 4: Response & Recovery (Months 10-12)
**Focus: Respond & Recover Functions**
- RS.MI (Mitigation) - Addresses OWASP 06
- RS.AN (Analysis) - Addresses OWASP 09
- RC functions for business continuity

## Maturity Assessment

### Current State Assessment

| Function | Current Tier | Target Tier | Gap |
|----------|--------------|-------------|-----|
| Govern | 2 | 3 | Improve supply chain management |
| Identify | 2 | 3 | Enhance threat modeling |
| Protect | 2 | 3 | Automate access control |
| Detect | 1 | 3 | Implement SIEM |
| Respond | 2 | 3 | Improve incident response |
| Recover | 2 | 3 | Enhance backup/recovery |

### Target State by OWASP Category

| OWASP Item | Current Tier | Target Tier | Key Improvements Needed |
|------------|--------------|-------------|-------------------------|
| 01 - Access Control | 2 | 3 | Automated provisioning, continuous monitoring |
| 02 - Cryptography | 3 | 3 | Maintain current state |
| 03 - Injection | 2 | 3 | SAST/DAST automation, WAF |
| 04 - Insecure Design | 1 | 3 | Mandatory threat modeling |
| 05 - Misconfiguration | 2 | 3 | IaC, automated scanning |
| 06 - Vulnerable Components | 2 | 3 | Automated SBOM, vulnerability management |
| 07 - Auth Failures | 2 | 3 | Enterprise MFA, SSO |
| 08 - Data Integrity | 2 | 3 | Secure CI/CD, code signing |
| 09 - Logging Failures | 1 | 3 | SIEM implementation |
| 10 - SSRF | 2 | 3 | Network segmentation, automated controls |

## Risk Profile

### Risk-Based Prioritization

**Critical Priority:**
1. Authentication Failures (07) - Direct account compromise risk
2. Cryptographic Failures (02) - Data breach exposure
3. Injection (03) - System compromise
4. Logging Failures (09) - Breach detection failure

**High Priority:**
1. Access Control (01) - Unauthorized access
2. Vulnerable Components (06) - Known exploits
3. Data Integrity (08) - Supply chain attacks
4. Insecure Design (04) - Fundamental flaws

**Medium Priority:**
1. Misconfiguration (05) - Information disclosure
2. SSRF (10) - Internal access

## Metrics and Measurement

### Key Performance Indicators (KPIs)

**Govern:**
- % of projects with security requirements (Target: 100%)
- % of vendors assessed for security (Target: 100%)

**Identify:**
- % of assets with current inventory (Target: 100%)
- Threat models completed (Target: All new projects)

**Protect:**
- % of users with MFA enabled (Target: 100%)
- % of data encrypted at rest (Target: 100%)
- % of traffic encrypted in transit (Target: 100%)

**Detect:**
- Mean time to detect (MTTD) (Target: < 1 hour)
- % of logs centralized (Target: 100%)
- Vulnerability scan coverage (Target: 100%)

**Respond:**
- Mean time to respond (MTTR) (Target: < 4 hours)
- % of incidents with root cause analysis (Target: 100%)

**Recover:**
- Recovery time objective (RTO) (Target: < 24 hours)
- Recovery point objective (RPO) (Target: < 1 hour)

## Best Practices

### For Security Leaders
1. Align OWASP remediation with CSF implementation
2. Use CSF tiers to set maturity goals
3. Report progress using CSF framework
4. Integrate with existing risk management

### For Security Teams
1. Map controls to both OWASP and CSF
2. Use CSF for communication with leadership
3. Track metrics for continuous improvement
4. Conduct regular self-assessments

### For Development Teams
1. Understand Protect and Detect functions
2. Implement security in SDLC (PR.IP-02)
3. Support logging and monitoring (DE.CM)
4. Participate in threat modeling (ID.RA-01)

## References

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [NIST CSF Implementation Guidance](https://www.nist.gov/cyberframework/getting-started)
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [NIST CSF Tools](https://www.nist.gov/cyberframework/tools)

## Change History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | Jan 2026 | Initial mapping to NIST CSF 2.0 | Security Team |

---

**Last Updated**: January 2026  
**Framework Version**: NIST CSF 2.0  
**Contact**: See [SECURITY.md](../SECURITY.md) for questions
