# M02: Supply Chain Security Lab - Instructions

## Learning Path: Explore → Discover → Analyze → Understand → Mitigate

---

## Phase 1: Explore the Application (5 minutes)

### Objective
Familiarize yourself with the dependency management dashboard and understand the two configurations being compared.

### Steps

1. **Access the Application**
   - Open http://localhost:5000 in your browser
   - You should see two panels: "Vulnerable Configuration" and "Secure Configuration"

2. **Review the Vulnerable Configuration**
   - Look at the `package.json` displayed on the left
   - Notice the version specifications:
     - `^1.2.0` - Caret allows minor and patch updates
     - `*` - Wildcard allows ANY version
     - `4.17.1` - Exact version but outdated

3. **Review the Secure Configuration**
   - Look at the `package.json` displayed on the right
   - Notice all versions are exact (no `^` or `*`)
   - Versions are current and patched

### Questions to Consider
- What's the difference between `^1.2.0` and `1.2.0`?
- Why might `*` be extremely dangerous?
- How can exact versions help with security?

---

## Phase 2: Discover Vulnerabilities (10 minutes)

### Objective
Learn to identify security vulnerabilities in dependencies using automated scanning.

### Steps

1. **Scan the Vulnerable Configuration**
   - Click the "🔍 Scan for Vulnerabilities" button under "Vulnerable Configuration"
   - Wait for the scan to complete

2. **Review the Scan Results**
   - Note the total number of vulnerabilities found
   - How many packages are affected?
   - What are the severity levels?

3. **Examine Individual Vulnerabilities**
   For each vulnerability, note:
   - **CVE ID**: Unique identifier for the vulnerability
   - **Severity**: Critical, High, Medium, or Low
   - **Description**: What the vulnerability allows an attacker to do
   - **Fixed Version**: Which version patches the issue

4. **Scan the Secure Configuration**
   - Click "🔍 Scan for Vulnerabilities" under "Secure Configuration"
   - Compare the results

### Expected Findings

**Vulnerable Configuration should show:**
- Multiple HIGH and CRITICAL vulnerabilities
- Issues in `axios`, `lodash`, and `express`
- Clear remediation paths

**Secure Configuration should show:**
- Zero vulnerabilities
- All packages using patched versions

### Document Your Findings
```
Package: _______________
Version: _______________
Vulnerability: __________
Severity: ______________
Impact: ________________
Fix: ___________________
```

---

## Phase 3: Understand Version Specifications (10 minutes)

### Objective
Learn the security implications of different version specification methods.

### Version Specification Types

#### 1. Wildcard (`*`)
```json
"lodash": "*"
```
**What it means:** Install ANY version of lodash
**Security risk:** CRITICAL
- Could install ancient, vulnerable versions
- Could install brand new, untested versions
- Zero predictability
- Zero control

#### 2. Caret (`^`)
```json
"axios": "^1.2.0"
```
**What it means:** Install 1.2.0 or any newer version that doesn't change the major version
**Compatible versions:** 1.2.0, 1.2.1, 1.3.0, 1.999.999 (but not 2.0.0)
**Security risk:** MEDIUM
- Auto-updates can introduce vulnerabilities
- Different versions in different environments
- "It works on my machine" problems

#### 3. Tilde (`~`)
```json
"package": "~4.17.0"
```
**What it means:** Install 4.17.0 or any newer patch version
**Compatible versions:** 4.17.0, 4.17.1, 4.17.999 (but not 4.18.0)
**Security risk:** MEDIUM
- Slightly safer than caret
- Still allows auto-updates

#### 4. Exact Version
```json
"axios": "1.6.0"
```
**What it means:** Install EXACTLY version 1.6.0
**Security risk:** LOW (when combined with lock files)
- Predictable, reproducible builds
- You control when to update
- Can verify security of specific version

### Exercise

What would happen with these version specs if a new vulnerability was discovered?

1. `"library": "*"` → ?
2. `"library": "^2.1.0"` when 2.1.1 has a fix → ?
3. `"library": "2.1.0"` exact version → ?

**Answer:**
1. Unpredictable - might auto-install vulnerable or fixed version
2. Might auto-update to fixed version OR install vulnerable 2.1.0
3. Stays at 2.1.0 (vulnerable) until you explicitly update

---

## Phase 4: Generate and Analyze SBOM (10 minutes)

### Objective
Understand the importance of Software Bill of Materials for security tracking.

### Steps

1. **Generate SBOM for Vulnerable Configuration**
   - Click "📋 Generate SBOM" button under Vulnerable Configuration
   - Review the generated SBOM structure

2. **Understand SBOM Structure**
   ```json
   {
     "bomFormat": "CycloneDX",
     "metadata": {
       "component": { /* Your app */ }
     },
     "components": [ /* All dependencies */ ]
   }
   ```

3. **Why SBOM Matters**
   - **Complete Inventory**: Know exactly what's in your application
   - **Vulnerability Tracking**: When new CVEs are published, quickly check if you're affected
   - **License Compliance**: Track open-source licenses
   - **Supply Chain Transparency**: Full visibility into your dependencies
   - **Incident Response**: Faster response to security issues

4. **Generate SBOM for Secure Configuration**
   - Compare the two SBOMs
   - Notice they contain the same number of components but different versions

### Real-World Scenario

Imagine a new critical vulnerability is announced in `axios` version 1.2.0:

**Without SBOM:**
- Manually check every project
- Search through code and package files
- Might miss transitive dependencies
- Slow response time

**With SBOM:**
- Automated scan of all SBOMs
- Instant identification of affected projects
- Quick remediation
- Complete audit trail

---

## Phase 5: Understand Attack Scenarios (15 minutes)

### Objective
Learn how supply chain vulnerabilities are exploited in real-world attacks.

### Scenario 1: Typosquatting Attack

**Attack Flow:**
```
1. Popular package: "react-native"
2. Attacker creates: "react-natve" (typo)
3. Developer makes typo during install
4. Malicious package installed
5. Exfiltrates environment variables
6. API keys stolen
```

**How to Prevent:**
- Use lock files (prevents unexpected packages)
- Review package names carefully before install
- Use private registry with approval workflow
- Enable typosquatting detection tools

### Scenario 2: Dependency Confusion

**Attack Flow:**
```
1. Attacker discovers internal package name: "@yourcompany/auth"
2. Publishes malicious package to public npm with same name
3. Build system checks public registry first
4. Downloads malicious public version
5. Credentials exfiltrated during build
```

**How to Prevent:**
- Configure registry precedence (private first)
- Use scoped packages (@yourcompany/*)
- Implement package approval process
- Network restrictions in build environment

### Scenario 3: Vulnerable Transitive Dependency

**Dependency Tree:**
```
Your App
  ├── package-A (secure)
  │   └── package-B (secure)
  │       └── package-C (VULNERABLE!)
  └── package-D (secure)
```

**Problem:**
- You directly added package-A
- You never knew about package-C
- package-C has critical vulnerability
- Your app is compromised

**How to Prevent:**
- Scan ALL dependencies (direct + transitive)
- Review dependency tree regularly
- Use `npm audit` or similar tools
- Consider security of entire chain

---

## Phase 6: Mitigation Strategies (10 minutes)

### Best Practices Checklist

#### 1. Dependency Selection
- [ ] Only add necessary dependencies
- [ ] Research package before adding (downloads, stars, maintenance)
- [ ] Check for recent updates and active maintenance
- [ ] Review security history
- [ ] Evaluate alternatives

#### 2. Version Management
- [ ] Use exact versions (no `^`, `~`, or `*`)
- [ ] Commit lock files to version control
- [ ] Use `npm ci` instead of `npm install` in CI/CD
- [ ] Review lock file changes in code review
- [ ] Update dependencies intentionally, not automatically

#### 3. Security Scanning
- [ ] Run `npm audit` or equivalent regularly
- [ ] Integrate scanning into CI/CD pipeline
- [ ] Set up automated vulnerability alerts (Dependabot, Snyk)
- [ ] Scan both direct and transitive dependencies
- [ ] Fix vulnerabilities promptly

#### 4. SBOM Management
- [ ] Generate SBOM for every release
- [ ] Store SBOMs in artifact repository
- [ ] Use SBOM for vulnerability impact analysis
- [ ] Provide SBOM to customers/stakeholders
- [ ] Automate SBOM generation in build pipeline

#### 5. Build Security
- [ ] Use isolated build environments
- [ ] Restrict network access during build
- [ ] Don't expose secrets to dependencies
- [ ] Sign and verify build artifacts
- [ ] Use minimal base images

#### 6. Monitoring and Response
- [ ] Set up real-time vulnerability alerts
- [ ] Have incident response plan for supply chain issues
- [ ] Monitor for suspicious package activity
- [ ] Track package updates and changes
- [ ] Regular security audits

---

## Phase 7: Hands-On Exercise (15 minutes)

### Fix the Vulnerable Configuration

Your task: Create a remediation plan for the vulnerable configuration

1. **Identify All Issues**
   ```
   Issue 1:
   - Package: _____________
   - Current Version: _____________
   - Problem: _____________
   - Fix: _____________
   
   Issue 2:
   - Package: _____________
   - Current Version: _____________
   - Problem: _____________
   - Fix: _____________
   ```

2. **Create Secure package.json**
   Based on your findings, write a secure `package.json`:
   ```json
   {
     "name": "mobile-app-secure",
     "version": "1.0.0",
     "dependencies": {
       // Fill in with secure versions
     }
   }
   ```

3. **Document Your Changes**
   For each change, document:
   - What you changed
   - Why you changed it
   - What vulnerability it addresses

---

## Phase 8: Additional Challenges (Optional)

### Challenge 1: Research Real CVEs
Pick one of the vulnerabilities from the lab and research the actual CVE:
- What was the attack vector?
- What was the impact?
- How was it discovered?
- What was the timeline to fix?

### Challenge 2: Dependency Tree Analysis
Research how to view the full dependency tree:
```bash
npm list
npm list --all
npm explain <package-name>
```

### Challenge 3: Lock File Integrity
Research:
- How does npm verify package integrity?
- What information is in `package-lock.json`?
- What happens if checksums don't match?

---

## Summary and Key Takeaways

### Critical Lessons

1. **Every Dependency is a Security Decision**
   - Evaluate thoroughly before adding
   - Understand the full dependency tree
   - Monitor continuously after adding

2. **Version Specification Matters**
   - Exact versions provide control and predictability
   - Wildcards are extremely dangerous
   - Lock files are essential

3. **Automation is Essential**
   - Automated scanning catches vulnerabilities early
   - SBOM provides visibility and audit trail
   - Continuous monitoring detects new issues

4. **Defense in Depth**
   - Multiple layers of protection
   - Verification at multiple stages
   - Assume dependencies can be compromised

5. **Incident Response Planning**
   - Have a plan before incidents occur
   - Know how to quickly identify affected systems
   - Practice response procedures

### Next Steps

1. **Apply to Your Projects**
   - Audit your current dependencies
   - Implement scanning in CI/CD
   - Generate SBOMs
   - Fix identified vulnerabilities

2. **Learn More**
   - Read the prevention guide
   - Study real-world supply chain attacks
   - Follow security advisories
   - Join security communities

3. **Share Knowledge**
   - Educate your team
   - Implement organizational policies
   - Create security champions
   - Build security culture

---

## Cleanup

When you're done with the lab:

```bash
# Stop the lab
docker-compose down

# Remove all data
docker-compose down -v
```

---

**Remember**: In supply chain security, trust but verify. Every dependency is a potential risk that must be managed.
