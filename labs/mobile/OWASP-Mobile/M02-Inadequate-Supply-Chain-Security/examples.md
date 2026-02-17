# M02: Inadequate Supply Chain Security - Examples

## Table of Contents
- [Dependency Management Examples](#dependency-management-examples)
- [Package Verification Examples](#package-verification-examples)
- [Build Security Examples](#build-security-examples)
- [Monitoring Examples](#monitoring-examples)
- [Real-World Case Studies](#real-world-case-studies)

## Dependency Management Examples

### Example 1: Unsafe vs Safe Package Installation

**❌ Vulnerable: Wildcard Versions**

```json
// package.json - UNSAFE
{
  "dependencies": {
    "react-native": "^0.72.0",     // Any minor/patch update
    "axios": "*",                    // Any version!
    "lodash": "~4.17.0",            // Any patch update
    "moment": "latest"               // Unpredictable
  }
}
```

**Problems:**
- Unexpected breaking changes
- Security vulnerabilities in auto-updates
- Non-reproducible builds
- Supply chain injection via updates

**✅ Secure: Exact Version Pinning**

```json
// package.json - SECURE
{
  "dependencies": {
    "react-native": "0.72.6",      // Exact version
    "axios": "1.6.0",               // Exact version
    "lodash": "4.17.21",            // Exact version
    "moment": "2.29.4"              // Exact version
  },
  "devDependencies": {
    "jest": "29.7.0"                // Even dev deps pinned
  }
}
```

**With Lock File:**

```json
// package-lock.json (generated automatically)
{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/axios": {
      "version": "1.6.0",
      "resolved": "https://registry.npmjs.org/axios/-/axios-1.6.0.tgz",
      "integrity": "sha512-...actual-hash...",
      "dependencies": {
        "follow-redirects": "1.15.3"  // Transitive deps locked too
      }
    }
  }
}
```

**Installation Best Practice:**

```bash
# ❌ Don't use - can modify lock file unexpectedly
npm install

# ✅ Use this - respects lock file exactly
npm ci

# Clean install in CI/CD
rm -rf node_modules
npm ci
```

### Example 2: Dependency Confusion Prevention

**❌ Vulnerable: Public Registry Only**

```bash
# .npmrc - UNSAFE
registry=https://registry.npmjs.com/

# Attacker publishes @yourcompany/internal-tool on npm
# Build system downloads malicious public version
```

**✅ Secure: Private Registry with Scoping**

```bash
# .npmrc - SECURE
@yourcompany:registry=https://npm.yourcompany.com/
registry=https://registry.npmjs.com/

# Internal packages MUST use @yourcompany scope
# Public packages default to npm
```

**Package Naming Convention:**

```json
// ✅ Correct internal package naming
{
  "name": "@yourcompany/auth-utils",  // Scoped to private registry
  "version": "1.0.0"
}

// ❌ Wrong - generic name
{
  "name": "auth-utils",  // Could be confused with public package
  "version": "1.0.0"
}
```

### Example 3: Dependency Approval Workflow

**❌ Vulnerable: No Review Process**

```bash
# Developer adds dependency without review
npm install suspicious-package --save

# Commits to repository
git add package.json package-lock.json
git commit -m "Added new library"
git push
```

**✅ Secure: Automated + Manual Review**

```yaml
# .github/workflows/dependency-check.yml
name: Dependency Review

on:
  pull_request:
    paths:
      - 'package.json'
      - 'package-lock.json'

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # Automated checks
      - name: Security Scan
        run: |
          npm audit --audit-level=high
          npx snyk test
          
      # License compliance
      - name: License Check
        run: npx license-checker --summary
        
      # Require human approval
      - name: Require Review
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.pulls.createReview({
              owner: context.repo.owner,
              repo: context.repo.repo,
              pull_number: context.issue.number,
              event: 'REQUEST_CHANGES',
              body: 'Security team approval required for dependency changes'
            })
```

## Package Verification Examples

### Example 4: Integrity Verification

**❌ Vulnerable: No Verification**

```bash
# Download and use package without checking
curl -O https://example.com/library.tgz
tar -xzf library.tgz
cp -r library/* ./node_modules/
```

**Problems:**
- No guarantee of authenticity
- Could be man-in-the-middle attacked
- No detection of tampering

**✅ Secure: Checksum and Signature Verification**

```bash
# Download with checksum
EXPECTED_SHA256="a1b2c3d4e5f6..."

# Download package
curl -O https://example.com/library.tgz

# Verify checksum
echo "$EXPECTED_SHA256  library.tgz" | sha256sum -c -

# Only proceed if verification passes
if [ $? -eq 0 ]; then
    echo "Verification successful"
    tar -xzf library.tgz
else
    echo "Verification failed! Potential tampering detected."
    exit 1
fi
```

**NPM Automatic Verification:**

```bash
# NPM automatically verifies integrity using package-lock.json
npm ci  # Fails if checksums don't match

# Verify specific package
npm view axios@1.6.0 dist.integrity
# Returns: sha512-actual-integrity-hash...
```

### Example 5: Subresource Integrity (SRI)

**❌ Vulnerable: CDN Without Integrity**

```html
<!-- Vulnerable script loading -->
<script src="https://cdn.example.com/analytics.js"></script>
```

**If CDN is compromised, malicious code executes**

**✅ Secure: SRI Protection**

```html
<!-- Protected with SRI -->
<script 
  src="https://cdn.example.com/analytics.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
  crossorigin="anonymous">
</script>
```

**Browser behavior:**
- Downloads script
- Computes SHA-384 hash
- Compares to integrity attribute
- Only executes if hash matches
- Blocks execution if mismatch

**Generating SRI Hashes:**

```bash
# Generate SRI hash for a file
cat analytics.js | openssl dgst -sha384 -binary | openssl base64 -A

# Or use online tools
curl https://www.srihash.org/
```

## Build Security Examples

### Example 6: Isolated Build Environment

**❌ Vulnerable: Shared Build Environment**

```dockerfile
# Dockerfile - UNSAFE
FROM ubuntu:latest

# Installing everything as root
RUN apt-get update && apt-get install -y nodejs npm

# Source code accessible to all processes
WORKDIR /app
COPY . .

# Running as root
RUN npm install
RUN npm run build
```

**Problems:**
- Runs as root
- No network isolation
- Persistent state between builds
- Secrets could leak

**✅ Secure: Isolated Build**

```dockerfile
# Dockerfile - SECURE
FROM node:18-alpine AS builder

# Create non-root user
RUN addgroup -S builduser && adduser -S builduser -G builduser

# Set working directory
WORKDIR /app

# Copy dependency files first (layer caching)
COPY --chown=builduser:builduser package*.json ./

# Switch to non-root user
USER builduser

# Install dependencies from lock file only
RUN npm ci --only=production

# Copy source code
COPY --chown=builduser:builduser . .

# Build application
RUN npm run build

# Multi-stage build - final image only has artifacts
FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
USER node
CMD ["node", "dist/index.js"]
```

**Network Isolation:**

```yaml
# docker-compose.yml
version: '3.8'
services:
  build:
    build: .
    networks:
      - isolated
    # No external network access during build
    network_mode: none  # Or use custom isolated network
```

### Example 7: Secure CI/CD Pipeline

**❌ Vulnerable: Insecure Pipeline**

```yaml
# .github/workflows/build.yml - UNSAFE
name: Build

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install
        run: npm install  # Not using lock file
      - name: Build
        run: npm run build
        env:
          API_KEY: ${{ secrets.API_KEY }}  # Exposed to all dependencies
```

**Problems:**
- `npm install` can modify dependencies
- Secrets accessible to all npm packages during build
- No security scanning
- No verification steps

**✅ Secure: Hardened Pipeline**

```yaml
# .github/workflows/build.yml - SECURE
name: Secure Build

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read  # Minimal permissions

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Dependency Audit
        run: npm audit --audit-level=moderate
        
      - name: License Check
        run: npx license-checker --onlyAllow="MIT;Apache-2.0;BSD-3-Clause"
        
      - name: Secret Scanning
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          
  build:
    needs: security  # Only build if security passes
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
          
      # Use exact lock file
      - name: Install Dependencies
        run: npm ci
        
      # Build without secrets in environment
      - name: Build
        run: npm run build
        
      # Generate SBOM
      - name: Generate SBOM
        run: npx @cyclonedx/cyclonedx-npm --output-file sbom.json
        
      - name: Upload SBOM
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.json
```

## Monitoring Examples

### Example 8: Vulnerability Monitoring

**❌ Vulnerable: No Monitoring**

```bash
# Install dependencies once
npm install

# Never check for vulnerabilities again
# ❌ Security issues accumulate over time
```

**✅ Secure: Continuous Monitoring**

```yaml
# .github/dependabot.yml - Automated monitoring
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"  # Check daily
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
    # Only update patch versions automatically
    versioning-strategy: increase-if-necessary
    
  # Separate configuration for security-only updates
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 5
    labels:
      - "security"
      - "critical"
    # Allow security updates across major versions
    allow:
      - dependency-type: "all"
        update-type: "security"
```

**Manual Monitoring:**

```bash
# Weekly security check
npm audit

# Get detailed report
npm audit --json > audit-report.json

# Fix automatically when possible
npm audit fix

# Fix including breaking changes (review carefully)
npm audit fix --force
```

**Snyk Monitoring:**

```bash
# Install Snyk
npm install -g snyk

# Authenticate
snyk auth

# Test for vulnerabilities
snyk test

# Monitor project (continuous scanning)
snyk monitor

# Get detailed report
snyk test --json > snyk-report.json
```

### Example 9: SBOM Management

**❌ Vulnerable: No SBOM**

```bash
# No tracking of what's actually in the application
# Can't assess impact of new vulnerabilities
# No compliance documentation
```

**✅ Secure: Automated SBOM Generation**

```bash
# Install CycloneDX
npm install -g @cyclonedx/cyclonedx-npm

# Generate SBOM in CycloneDX format
cyclonedx-npm --output-file sbom.json

# Generate in SPDX format
npm sbom --sbom-format spdx > sbom-spdx.json
```

**SBOM in Build Pipeline:**

```yaml
# .github/workflows/sbom.yml
name: Generate SBOM

on:
  push:
    branches: [main]
  release:
    types: [published]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          
      - name: Install Dependencies
        run: npm ci
        
      - name: Generate SBOM
        run: npx @cyclonedx/cyclonedx-npm --output-file sbom.json
        
      - name: Upload to Dependency Track
        run: |
          curl -X POST "https://dependency-track.company.com/api/v1/bom" \
            -H "X-Api-Key: ${{ secrets.DEPENDENCY_TRACK_API_KEY }}" \
            -H "Content-Type: multipart/form-data" \
            -F "project=mobile-app" \
            -F "bom=@sbom.json"
            
      - name: Attach to Release
        uses: actions/upload-release-asset@v1
        if: github.event_name == 'release'
        with:
          upload_url: ${{ github.event.release.upload_url }}
          asset_path: ./sbom.json
          asset_name: sbom.json
          asset_content_type: application/json
```

## Real-World Case Studies

### Case Study 1: Event-Stream Compromise (2018)

**What Happened:**
```
Timeline:
1. Popular npm package "event-stream" (2M weekly downloads)
2. Original maintainer transferred ownership
3. New maintainer published version with malicious code
4. Targeted cryptocurrency wallets
5. Stole credentials and private keys
```

**How It Could Have Been Prevented:**

```yaml
# 1. Dependency scanning would detect suspicious code
snyk test  # Would flag obfuscated code patterns

# 2. Lock file would prevent auto-update
# package-lock.json prevents silent updates

# 3. Code review of dependency changes
# Manual review of transitive dependency changes

# 4. Network monitoring during build
# Detect unexpected outbound connections
```

**Lessons Learned:**
- Monitor transitive dependencies
- Review maintainer changes
- Scan for obfuscated code
- Don't auto-update without review

### Case Study 2: Dependency Confusion (2021)

**Attack Scenario:**
```
1. Attacker finds internal package names from job postings
   Internal package: @company/auth-lib
   
2. Publishes malicious package to public npm
   Published: @company/auth-lib (on npm)
   
3. Build system installs from public registry
   npm install @company/auth-lib
   → Downloads malicious public version
   
4. Malicious code exfiltrates environment variables
   API keys, AWS credentials stolen
```

**Prevention Implementation:**

```bash
# .npmrc - Force private registry for scoped packages
@company:registry=https://npm.company.com/
always-auth=true

# Package managers check private first
registry=https://npm.company.com/
```

```yaml
# package.json - Specify registry explicitly
{
  "name": "@company/auth-lib",
  "publishConfig": {
    "registry": "https://npm.company.com/"
  }
}
```

**Additional Protections:**

```javascript
// pre-install hook to verify registry
// .husky/pre-commit
#!/bin/sh

# Check for suspicious public packages with private naming
npm ls --json | grep "@company" | grep "registry.npmjs.org" && {
  echo "ERROR: Private package found from public registry!"
  exit 1
}
```

### Case Study 3: UA-Parser-JS Compromise (2021)

**Timeline:**
```
1. Maintainer account compromised
2. Malicious versions published (0.7.29, 0.8.0, 1.0.0)
3. Cryptocurrency mining malware injected
4. Millions of applications affected
5. Detected within hours, but damage done
```

**Prevention Strategy:**

```yaml
# Dependabot alerts enabled
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    # Alert on any changes to critical packages
    
security-advisories:
  - package-name: "ua-parser-js"
    severity: "critical"
    action: "notify"
```

**Response Plan:**

```markdown
## Incident Response Checklist

When security alert received:
1. □ Immediately pin to last known good version
2. □ Audit recent builds for compromise
3. □ Check runtime logs for suspicious activity
4. □ Scan for presence of malicious code patterns
5. □ Rotate credentials if potentially exposed
6. □ Communicate to users if necessary
7. □ Update to patched version when available
8. □ Post-incident review and prevention improvement
```

## Quick Reference: Secure vs Vulnerable

| Aspect | ❌ Vulnerable | ✅ Secure |
|--------|--------------|----------|
| Versions | Wildcards (`^`, `*`) | Exact versions |
| Installation | `npm install` | `npm ci` |
| Lock files | Ignored or missing | Committed and enforced |
| Scanning | Manual, infrequent | Automated, continuous |
| SBOM | Not generated | Auto-generated per build |
| Registry | Public only | Private + scoped |
| Approval | None | Automated + manual review |
| Monitoring | None | 24/7 alerts |
| Build | Shared, persistent | Isolated, ephemeral |

## Key Takeaways

1. **Pin exact versions and use lock files religiously**
2. **Automate security scanning in CI/CD**
3. **Maintain SBOM for complete visibility**
4. **Use private registries for internal packages**
5. **Implement dependency approval workflows**
6. **Monitor continuously for new vulnerabilities**
7. **Have incident response plan ready**
8. **Isolate build environments**

## Next Steps

- **[Interactive Lab](./lab/)**: Practice identifying and fixing supply chain vulnerabilities
- **[Back to Overview](./overview.md)**: Review core concepts
- **[Attack Vectors](./attack-vectors.md)**: Understand attack methods
- **[Prevention](./prevention.md)**: Comprehensive security guide

---

**Remember**: Every dependency is a trust decision. Choose wisely, verify thoroughly, monitor constantly.
