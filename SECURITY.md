# Security Policy

## Responsible Disclosure Policy

Thank you for taking the time to responsibly disclose any issues you find.

### Security in Educational Content

**Important Note**: This repository contains educational content about security vulnerabilities. The labs and examples are intentionally vulnerable for learning purposes. Please do not report these intentional vulnerabilities as security issues.

### What Should Be Reported

Please report actual security issues with:

- ✅ The repository infrastructure itself
- ✅ The documentation or code that could enable real-world attacks
- ✅ Vulnerabilities in our deployment scripts or configurations
- ✅ Issues with our Docker setup that could escape isolation
- ✅ Unintentional exposure of sensitive data
- ✅ Supply chain vulnerabilities in our dependencies

### What Should NOT Be Reported

Please do NOT report:

- ❌ Intentional vulnerabilities in lab environments (they're meant to be vulnerable)
- ❌ Security issues in the example "bad code" snippets (they're educational)
- ❌ Theoretical attacks on the vulnerable applications we demonstrate
- ❌ General questions about OWASP Top 10 vulnerabilities

## Supported Versions

We actively maintain the following:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

We recommend always using the latest version from the main branch.

## Reporting a Vulnerability

If you discover a security vulnerability in this repository's infrastructure or code, please follow these steps:

### 1. **DO NOT** Open a Public Issue

Security vulnerabilities should be reported privately to prevent exploitation.

### 2. Report Via GitHub Security Advisory

1. Go to the [Security tab](https://github.com/0x6a03448f4d/OWASP-TOP10/security) of this repository
2. Click "Report a vulnerability"
3. Fill out the security advisory form with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if you have one)

### 3. Alternative Reporting Method

If you cannot use GitHub Security Advisories, you may:

1. Create a private fork
2. Document the issue in detail
3. Contact the maintainers via GitHub with "SECURITY" in the subject
4. Wait for a response before sharing details

### What to Include in Your Report

A good security report includes:

- **Description**: Clear description of the vulnerability
- **Location**: Where the vulnerability exists (file, line number, etc.)
- **Impact**: Potential impact if exploited
- **Reproduction Steps**: Detailed steps to reproduce the issue
- **Proof of Concept**: If possible, a minimal PoC (without being destructive)
- **Suggested Fix**: If you have ideas on how to fix it
- **Disclosure Timeline**: Your expectations for disclosure

### Example Report Template

```markdown
## Vulnerability Description
[Clear description of the issue]

## Affected Components
- File: [path/to/file]
- Version: [version or commit hash]
- Component: [specific feature or module]

## Steps to Reproduce
1. [First step]
2. [Second step]
3. [Third step]

## Impact Assessment
**Severity**: [Critical/High/Medium/Low]
**Attack Vector**: [Network/Local/Physical]
**Privileges Required**: [None/Low/High]

[Detailed explanation of potential impact]

## Proof of Concept
[Minimal code or commands to demonstrate - without being destructive]

## Suggested Mitigation
[Your suggestions for fixing the issue]

## Disclosure Timeline
[Your preferred timeline for disclosure]
```

## Our Commitment

When you report a vulnerability, we commit to:

- **Acknowledge** your report within 48 hours
- **Provide** an initial assessment within 1 week
- **Keep you updated** on our progress
- **Notify you** when the issue is fixed
- **Credit you** in our security advisories (if you wish)

### Timeline

| Step | Timeframe |
|------|-----------|
| Initial Response | 48 hours |
| Severity Assessment | 1 week |
| Fix Development | Depends on severity |
| Public Disclosure | 90 days or when fixed, whichever comes first |

### Severity Assessment

We use the following severity levels:

- **Critical**: Immediate threat, fix ASAP (within days)
- **High**: Serious vulnerability, fix within 1-2 weeks
- **Medium**: Notable security issue, fix within 1 month
- **Low**: Minor security concern, fix in next release

## Safe Harbor

We support safe harbor for security researchers who:

- Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our services
- Only interact with accounts you own or with explicit permission of the account holder
- Do not exploit a security issue for purposes beyond demonstrating it
- Report the vulnerability promptly
- Give us reasonable time to address the issue before disclosure
- Comply with all applicable laws and regulations

We will not pursue legal action against researchers who follow these guidelines.

## Public Disclosure

We believe in transparent security practices. After a vulnerability is fixed:

1. We will publish a security advisory
2. Credit the researcher (with their permission)
3. Detail the vulnerability and the fix
4. Update our CHANGELOG.md

## Security Best Practices for Users

When using this repository:

### For Running Labs

- ✅ Always run labs in isolated Docker containers
- ✅ Use the provided docker-compose configurations
- ✅ Don't expose lab ports to public networks
- ✅ Clean up containers after use (`docker-compose down -v`)
- ✅ Keep Docker and dependencies updated
- ❌ Never run labs in production environments
- ❌ Never use vulnerable code patterns in real applications

### For Contributing

- ✅ Review code for unintentional security issues
- ✅ Ensure Docker configurations are secure
- ✅ Don't commit sensitive data (keys, passwords, tokens)
- ✅ Use dependency scanning tools
- ❌ Don't include weaponizable exploit code
- ❌ Don't share real attack payloads

## Security Scanning

We recommend contributors use:

- **Git Secrets**: Prevent committing secrets
  ```bash
  git secrets --install
  git secrets --register-aws
  ```

- **Trivy**: Scan Docker images
  ```bash
  trivy image your-image-name
  ```

- **Snyk**: Dependency vulnerability scanning
  ```bash
  snyk test
  ```

- **Bandit**: Python security linting
  ```bash
  bandit -r .
  ```

## Dependency Security

We regularly update dependencies to patch known vulnerabilities. Dependencies are tracked in:

- `requirements.txt` for Python projects
- `package.json` for Node.js projects
- Docker base images

## Contact

For security-related questions that aren't vulnerabilities:

- Open a [GitHub Discussion](https://github.com/0x6a03448f4d/OWASP-TOP10/discussions)
- Tag with "security" label
- We'll respond within a few days

---

## Hall of Fame

We thank the following researchers for responsibly disclosing security issues:

*No security issues have been reported yet*

---

**Remember**: Security is a shared responsibility. Thank you for helping keep this educational resource safe! 🛡️

*Last Updated: January 2026*
