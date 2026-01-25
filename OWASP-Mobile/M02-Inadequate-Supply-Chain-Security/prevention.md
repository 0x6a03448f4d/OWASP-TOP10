# M02: Inadequate Supply Chain Security - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Dependency Management Best Practices](#dependency-management-best-practices)
- [Verification and Validation](#verification-and-validation)
- [Build Security](#build-security)
- [Monitoring and Response](#monitoring-and-response)
- [Organizational Policies](#organizational-policies)

## Prevention Strategy Overview

Securing your mobile app's supply chain requires a multi-layered approach across the entire development lifecycle:

```
Defense Layers:
1. Dependency Selection → Choose trusted, well-maintained packages
2. Integrity Verification → Validate checksums and signatures
3. Vulnerability Scanning → Continuous monitoring for known issues
4. SBOM Management → Track all components
5. Isolated Builds → Restrict build environment access
6. Incident Response → Plan for supply chain compromises
```

## Dependency Management Best Practices

### 1. Dependency Selection Criteria

**Before Adding Any Dependency:**

✅ **Evaluate Package Health**
- Active maintenance (recent commits, releases)
- Responsive maintainers to security issues
- Clear versioning and changelog
- Good test coverage
- Security disclosure policy

✅ **Check Package Reputation**
- Number of downloads/stars
- Community engagement
- Known security history
- Corporate or foundation backing
- Code quality and documentation

✅ **Minimize Dependencies**
- Only add when truly necessary
- Prefer standard library alternatives
- Consider implementing simple functionality yourself
- Avoid "dependency hell"

**Evaluation Checklist:**
```
□ Package last updated within 6 months
□ Active issue resolution (< 30 days median)
□ Documented security policy
□ More than 1 maintainer
□ Used by reputable projects
□ No unresolved critical security issues
□ Compatible with your security requirements
□ License compatible with your app
```

### 2. Version Pinning and Lock Files

**Always Use Lock Files:**

```json
// package.json - Specify exact versions
{
  "dependencies": {
    "react-native": "0.72.6",  // Exact version, not "^0.72.6"
    "axios": "1.6.0"            // No wildcards or ranges
  }
}
```

**Lock File Importance:**
- Ensures consistent builds across environments
- Prevents unexpected transitive dependency updates
- Provides audit trail of dependency changes
- Required for reproducible builds

**Best Practices:**
- ✅ Commit lock files to version control
- ✅ Use exact versions for production dependencies
- ✅ Review lock file changes in code review
- ✅ Regenerate lock files intentionally, not accidentally

### 3. Private Package Registry

**Use Private Registry for Internal Packages:**

```yaml
# .npmrc configuration
registry=https://your-private-registry.company.com/
@your-company:registry=https://your-private-registry.company.com/

# Only fallback to public for approved packages
```

**Benefits:**
- Prevents dependency confusion attacks
- Control over package availability
- Internal package privacy
- Caching and performance
- Security scanning before use

**Configuration:**
- Namespace internal packages (@company/package-name)
- Proxy public packages through private registry
- Require authentication for package downloads
- Implement package approval workflow

## Verification and Validation

### 1. Integrity Checking

**Verify Package Checksums:**

```bash
# NPM automatically verifies package integrity with lock files
npm ci  # Clean install using lock file

# Verify specific package
npm view package-name@version dist.integrity

# Gradle (Android)
// build.gradle - Enable dependency verification
dependencyVerification {
    enabled = true
}
```

**Subresource Integrity (SRI):**
```html
<!-- For CDN-loaded resources -->
<script 
  src="https://cdn.example.com/library.js"
  integrity="sha384-hash-value-here"
  crossorigin="anonymous">
</script>
```

### 2. Signature Verification

**Verify Package Signatures:**

```bash
# CocoaPods (iOS) - Use trusted sources
pod install --repo-update

# Verify pod source
pod repo list

# Android - Verify AAR/JAR signatures
jarsigner -verify -verbose app.aar
```

**Best Practices:**
- Use package registries with signature support
- Verify GPG signatures for critical dependencies
- Check certificate chains for SDK downloads
- Implement custom verification scripts if needed

### 3. Dependency Scanning

**Automated Vulnerability Scanning:**

```bash
# NPM Audit
npm audit
npm audit fix  # Auto-fix compatible updates

# Snyk - Comprehensive scanning
snyk test
snyk monitor  # Continuous monitoring

# OWASP Dependency-Check
dependency-check --project "MyApp" --scan ./

# GitHub Dependabot - Automated PR for updates
# Configure in .github/dependabot.yml
```

**Scanning Best Practices:**
- Run scans in CI/CD pipeline
- Set severity thresholds (fail build on high/critical)
- Scan both direct and transitive dependencies
- Regular scheduled scans (at least weekly)
- Review and triage all findings

### 4. Software Bill of Materials (SBOM)

**Generate and Maintain SBOM:**

```bash
# CycloneDX for Android
gradlew cyclonedxBom

# Generate SBOM for Node.js projects
npx @cyclonedx/bom

# SPDX format
npm sbom --sbom-format spdx
```

**SBOM Benefits:**
- Complete inventory of all components
- License compliance tracking
- Vulnerability impact assessment
- Incident response support
- Regulatory compliance (FDA, NTIA)

**SBOM Best Practices:**
- Generate SBOM for every release
- Include in artifact repository
- Update on dependency changes
- Use standard formats (SPDX, CycloneDX)
- Automate SBOM generation in build pipeline

## Build Security

### 1. Isolated Build Environments

**Containerized Builds:**

```dockerfile
# Dockerfile for build environment
FROM node:18-alpine

# Non-root user
RUN addgroup -S builduser && adduser -S builduser -G builduser
USER builduser

# Read-only file system where possible
VOLUME /app
WORKDIR /app

# No network access during build (except registry)
# Implement network policies
```

**Build Isolation:**
- Use clean, ephemeral build environments
- Restrict network access during build
- No credentials in build environment
- Separate build and deployment environments
- Immutable build images

### 2. Build Pipeline Security

**Secure CI/CD Configuration:**

```yaml
# Example GitHub Actions workflow
name: Secure Build

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      # Verify dependencies
      - name: Dependency Check
        run: npm audit
        
      # Use locked dependencies
      - name: Install Dependencies
        run: npm ci  # Not npm install
        
      # Scan for secrets
      - name: Secret Scanning
        uses: trufflesecurity/trufflehog@main
        
      # Build with security checks
      - name: Build
        run: npm run build
        
      # Sign artifacts
      - name: Sign Build
        run: codesign --sign "$CERT" app.ipa
```

**Pipeline Best Practices:**
- Use official, trusted actions/plugins
- Pin action versions by commit SHA
- Minimize secrets in pipeline
- Implement approval gates for production
- Audit pipeline changes
- Use separate credentials per environment

### 3. Dependency Approval Workflow

**Implement Review Process:**

```
New Dependency Request Flow:
1. Developer proposes dependency
   ↓
2. Automated security scan (vulnerabilities, license)
   ↓
3. Manual review by security team
   ↓
4. Approve/Reject with documentation
   ↓
5. Add to approved dependencies list
   ↓
6. Monitor for security updates
```

**Approval Criteria:**
- No known high/critical vulnerabilities
- Compatible license
- Active maintenance
- Minimal transitive dependencies
- Business justification documented
- Alternative evaluation completed

## Monitoring and Response

### 1. Continuous Monitoring

**Automated Monitoring Setup:**

```yaml
# GitHub Dependabot configuration
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
```

**Monitoring Tools:**
- Snyk: Real-time vulnerability alerts
- WhiteSource/Mend: Comprehensive scanning
- Dependabot: Automated update PRs
- Socket.dev: Supply chain attack detection
- npm audit/pip-audit: Registry-level checks

**Alert Configuration:**
- Critical/High vulnerabilities: Immediate notification
- Medium vulnerabilities: Daily digest
- Low vulnerabilities: Weekly summary
- License compliance: As detected
- Abandoned packages: Monthly review

### 2. Incident Response

**Supply Chain Compromise Response Plan:**

```
Incident Response Steps:
1. Detection & Verification
   - Confirm compromise
   - Identify affected dependencies
   - Determine scope of impact
   
2. Containment
   - Block compromised package versions
   - Prevent auto-updates
   - Isolate affected environments
   
3. Assessment
   - Check if malicious code executed
   - Review logs for suspicious activity
   - Identify data exposure
   
4. Remediation
   - Remove compromised dependency
   - Update to safe version
   - Re-scan all dependencies
   - Rebuild and redeploy
   
5. Recovery
   - Deploy fixed version
   - Monitor for anomalies
   - Rotate compromised credentials
   
6. Post-Incident
   - Document incident
   - Update detection rules
   - Improve preventive controls
   - Communicate to stakeholders
```

**Response Checklist:**
```
□ Incident response team identified
□ Communication plan defined
□ Escalation procedures documented
□ Rollback procedures tested
□ Credential rotation process ready
□ User notification templates prepared
□ Legal/PR contacts established
```

## Organizational Policies

### 1. Dependency Policy

**Sample Policy Framework:**

```markdown
## Dependency Management Policy

### Approval Requirements
- All new dependencies must be approved by security team
- Dependencies must have active maintenance (updated within 6 months)
- No critical or high vulnerabilities allowed
- License must be compatible with commercial use

### Update Requirements
- Security updates applied within 48 hours of release
- Dependency scans run on every build
- SBOM generated for every release
- Quarterly dependency health review

### Prohibited Practices
- No wildcard version ranges in production
- No unverified package sources
- No private keys in package configurations
- No auto-update of major versions
```

### 2. Vendor Assessment

**Third-Party SDK Evaluation:**

```
Security Questionnaire for SDK Vendors:
□ How do you handle security vulnerabilities?
□ What is your security disclosure policy?
□ Do you sign your packages?
□ What data does your SDK collect?
□ How is data transmitted and stored?
□ Do you undergo security audits?
□ What is your incident response process?
□ How do you notify customers of security issues?
□ What dependencies does your SDK include?
□ Do you provide SBOM?
```

### 3. Developer Training

**Security Awareness Topics:**
- Supply chain attack vectors
- Dependency evaluation criteria
- Secure dependency installation
- Recognizing suspicious packages
- Incident reporting procedures
- Using security tools

**Training Frequency:**
- Onboarding: Supply chain security module
- Quarterly: Security updates and new threats
- Annual: Comprehensive security review
- Ad-hoc: After significant incidents

## Quick Reference Checklist

### Daily/Build-Time
- [ ] Use `npm ci` or equivalent for installations
- [ ] Run dependency scans in CI/CD
- [ ] Review dependency updates before merging
- [ ] Check lock file changes in code review

### Weekly
- [ ] Review security alerts
- [ ] Update dependencies with security fixes
- [ ] Check for abandoned dependencies

### Monthly
- [ ] Comprehensive dependency audit
- [ ] Review SBOM for accuracy
- [ ] Update security policies as needed

### Quarterly
- [ ] Dependency health assessment
- [ ] Vendor security reviews
- [ ] Policy compliance audit

## Key Takeaways

1. **Never blindly trust dependencies - verify everything**
2. **Use lock files and pin exact versions**
3. **Automate scanning but don't ignore results**
4. **Maintain SBOM for complete visibility**
5. **Have an incident response plan ready**
6. **Make security part of the development culture**

## Tools and Resources

**Dependency Scanning:**
- [Snyk](https://snyk.io/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit)
- [Safety (Python)](https://pyup.io/safety/)

**SBOM Generation:**
- [CycloneDX](https://cyclonedx.org/)
- [SPDX](https://spdx.dev/)

**Monitoring:**
- [Socket.dev](https://socket.dev/)
- [GitHub Dependabot](https://github.com/dependabot)
- [WhiteSource/Mend](https://www.mend.io/)

## Next Steps

- **[Examples](./examples.md)**: See secure vs vulnerable dependency management
- **[Interactive Lab](./lab/)**: Practice supply chain security

---

**Remember**: Your app's security depends on every link in your supply chain.
