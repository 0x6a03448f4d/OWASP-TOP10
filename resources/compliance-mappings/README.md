# Compliance Mapping Matrix 📋

Map OWASP Top 10 vulnerabilities to major compliance frameworks and security standards.

## 🎯 Available Mappings

### Regulatory Frameworks
1. [OWASP → GDPR](gdpr-mapping.md) - General Data Protection Regulation
2. [OWASP → PCI-DSS](pci-dss-mapping.md) - Payment Card Industry Data Security Standard
3. [OWASP → HIPAA](hipaa-mapping.md) - Health Insurance Portability and Accountability Act
4. [OWASP → SOX](sox-mapping.md) - Sarbanes-Oxley Act

### Security Standards
5. [OWASP → ISO 27001](iso-27001-mapping.md) - Information Security Management
6. [OWASP → NIST CSF](nist-csf-mapping.md) - NIST Cybersecurity Framework
7. [OWASP → NIST 800-53](nist-800-53-mapping.md) - Security and Privacy Controls
8. [OWASP → CIS Controls](cis-controls-mapping.md) - Center for Internet Security Controls
9. [OWASP → SOC 2](soc2-mapping.md) - Service Organization Control 2

### Industry Standards
10. [OWASP → ASVS](asvs-mapping.md) - Application Security Verification Standard
11. [OWASP → CWE](cwe-mapping.md) - Common Weakness Enumeration
12. [OWASP → MITRE ATT&CK](mitre-mapping.md) - ATT&CK Framework

## 📊 Mapping Format

Each mapping document includes:
- **OWASP Vulnerability**: Top 10 category
- **Framework Requirements**: Specific controls/requirements
- **Compliance Level**: How it satisfies requirements
- **Implementation Guidance**: Practical steps
- **Evidence Collection**: What to document

## 🎯 Use Cases

### For Compliance Officers
- Demonstrate OWASP Top 10 coverage
- Map security efforts to frameworks
- Generate compliance reports
- Identify gaps in coverage

### For Security Teams
- Prioritize vulnerabilities by compliance impact
- Understand regulatory requirements
- Plan remediation efforts
- Document security controls

### For Auditors
- Verify security control implementation
- Assess compliance posture
- Review evidence of controls
- Identify audit findings

### For Developers
- Understand why security matters
- See business impact of vulnerabilities
- Implement compliant solutions
- Document security decisions

## 📋 Quick Reference Tables

Each mapping includes:
- ✅ **Requirement ID**: Standard's control number
- ✅ **OWASP Category**: Which Top 10 item it relates to
- ✅ **Control Description**: What must be implemented
- ✅ **Implementation Status**: Coverage level
- ✅ **Evidence Examples**: How to prove compliance

## 🔍 Coverage Analysis

Understand how addressing OWASP Top 10 helps with:
- **GDPR**: Article 32 (Security of processing)
- **PCI-DSS**: Requirement 6 (Secure systems/applications)
- **ISO 27001**: Annex A controls
- **NIST**: Core functions and categories
- **SOC 2**: Trust Service Criteria

## 📈 Compliance Dashboard

Visual representation of:
- Coverage by framework
- Implementation status
- Gap analysis
- Priority recommendations

## 🎨 Matrix Views

Available formats:
- **PDF**: Printable reference sheets
- **Excel**: Customizable spreadsheets
- **JSON**: Machine-readable data
- **HTML**: Interactive web views

## 🔄 Regular Updates

Mappings updated to reflect:
- New framework versions
- Emerging requirements
- OWASP updates
- Industry best practices

## 💼 Enterprise Features

For organizations:
- Custom framework mappings
- Organization-specific controls
- Evidence repository integration
- Automated compliance tracking

## 📚 Documentation

Each mapping includes:
- Executive summary
- Detailed control mapping
- Implementation examples
- Testing procedures
- Documentation templates

## 🤝 Contributing

Help improve mappings:
- Suggest additional frameworks
- Update existing mappings
- Share implementation examples
- Report inaccuracies

See [CONTRIBUTING.md](../CONTRIBUTING.md)

## 📖 Related Resources

- [OWASP Compliance Project](https://owasp.org/www-project-compliance/)
- [Framework Official Documentation](#)
- [Implementation Guides](../docs/)

---

**Explore mappings: [View All Compliance Matrices](index.html)** 🚀

## 📝 Example: OWASP → PCI-DSS Quick Map

| OWASP Top 10 | PCI-DSS Requirement |
|--------------|---------------------|
| 01. Broken Access Control | 6.5.8, 7.1, 7.2 |
| 02. Cryptographic Failures | 3.4, 4.1, 6.5.3 |
| 03. Injection | 6.5.1 |
| 04. Insecure Design | 6.3, 6.4, 6.5 |
| 05. Security Misconfiguration | 2.2, 6.5.10 |
| 06. Vulnerable Components | 6.2 |
| 07. Auth Failures | 6.5.10, 8.2 |
| 08. Data Integrity Failures | 6.3, 6.5.3 |
| 09. Logging Failures | 10.1-10.9 |
| 10. SSRF | 6.5.1, 6.5.4 |

See [PCI-DSS Full Mapping](pci-dss-mapping.md) for details.
