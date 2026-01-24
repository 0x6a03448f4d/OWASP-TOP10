# OWASP Top 10 - Educational Repository 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://www.docker.com/)
[![Education](https://img.shields.io/badge/Purpose-Education-green.svg)](https://owasp.org/Top10/)

> **A comprehensive, hands-on educational resource for learning about the OWASP Top 10 vulnerabilities through safe, isolated, Docker-based labs and in-depth documentation.**

## 🎯 Mission Statement

This repository exists to make **cybersecurity education accessible, practical, and ethical**. We teach developers, security professionals, and students about common web application vulnerabilities through:

- 📚 **Comprehensive documentation** explaining each vulnerability
- 🔬 **Safe, isolated labs** for hands-on learning without risk
- 🛠️ **Practical prevention techniques** and secure coding patterns
- ✅ **Ethical approach** - education, never exploitation

## ⚠️ Ethical Use Statement

**This repository is strictly for educational purposes.**

- ✅ Use this to **learn** about vulnerabilities
- ✅ Use this to **improve** your security practices
- ✅ Use this to **teach** others about secure development
- ❌ **Never** use this knowledge to attack real systems
- ❌ **Never** use these techniques without explicit authorization

By using this repository, you commit to **responsible, ethical cybersecurity practices**.

## 📋 Table of Contents

- [What is OWASP Top 10?](#what-is-owasp-top-10)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [The OWASP Top 10 Categories](#the-owasp-top-10-categories)
- [How to Use This Repository](#how-to-use-this-repository)
- [Running the Labs](#running-the-labs)
- [Learning Paths](#learning-paths)
- [Contributing](#contributing)
- [License](#license)
- [Resources](#resources)

## 🔐 What is OWASP Top 10?

The [OWASP Top 10](https://owasp.org/www-project-top-ten/) is a standard awareness document for developers and web application security. It represents a broad consensus about the **most critical security risks** to web applications.

Updated regularly by the Open Web Application Security Project (OWASP), this list helps organizations understand and mitigate the most common and impactful vulnerabilities.

**2021 OWASP Top 10:**

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)

## 📁 Repository Structure

```
OWASP-TOP10/
│
├── README.md                          # You are here
├── LICENSE                            # MIT License
├── CONTRIBUTING.md                    # Contribution guidelines
├── .gitignore                         # Git ignore rules
│
├── OWASP-Web/                         # OWASP Top 10 Web Application Security Risks
│   ├── 01-Broken-Access-Control/
│   │   ├── overview.md               # What it is and why it matters
│   │   ├── attack-vectors.md         # How attacks happen (conceptual)
│   │   ├── prevention.md             # How to prevent it
│   │   ├── examples.md               # Code examples (bad vs good)
│   │   └── lab/                      # Hands-on lab
│   │       └── broken-access-control-adminbutton/
│   │
│   ├── 02-Cryptographic-Failures/
│   ├── 03-Injection/
│   ├── 04-Insecure-Design/
│   ├── 05-Security-Misconfiguration/
│   ├── 06-Vulnerable-Outdated-Components/
│   ├── 07-Identification-Authentication-Failures/
│   ├── 08-Software-Data-Integrity-Failures/
│   ├── 09-Security-Logging-Monitoring-Failures/
│   └── 10-Server-Side-Request-Forgery/
│
├── OWASP-API/                         # OWASP API Security Top 10
│   ├── API01-Broken-Object-Level-Authorization/
│   ├── API02-Broken-Authentication/
│   ├── API03-Broken-Object-Property-Level-Authorization/
│   ├── API04-Unrestricted-Resource-Consumption/
│   ├── API05-Broken-Function-Level-Authorization/
│   ├── API06-Unrestricted-Access-to-Sensitive-Business-Flows/
│   ├── API07-Server-Side-Request-Forgery/
│   ├── API08-Security-Misconfiguration/
│   ├── API09-Improper-Inventory-Management/
│   └── API10-Unsafe-Consumption-of-APIs/
│
├── OWASP-LLM/                         # OWASP LLM Top 10
│   ├── LLM01-Prompt-Injection/
│   ├── LLM02-Insecure-Output-Handling/
│   ├── LLM03-Training-Data-Poisoning/
│   ├── LLM04-Model-Denial-of-Service/
│   ├── LLM05-Supply-Chain-Vulnerabilities/
│   ├── LLM06-Sensitive-Information-Disclosure/
│   ├── LLM07-Insecure-Plugin-Design/
│   └── LLM08-Excessive-Agency/
│
├── OWASP-Mobile/                      # OWASP Mobile Top 10
│   ├── M01-Improper-Credential-Usage/
│   ├── M02-Inadequate-Supply-Chain-Security/
│   ├── M03-Insecure-Authentication-Authorization/
│   ├── M04-Insufficient-Input-Output-Validation/
│   ├── M05-Insecure-Communication/
│   ├── M06-Inadequate-Privacy-Controls/
│   ├── M07-Insufficient-Binary-Protections/
│   ├── M08-Security-Misconfiguration/
│   ├── M09-Insecure-Data-Storage/
│   └── M10-Insufficient-Cryptography/
│
├── images/                            # Diagrams and screenshots
│   ├── diagrams/
│   └── examples/
│
└── labs/                              # Shared lab resources
    └── base/
        ├── Dockerfile                 # Base Docker image for Python labs
        └── common-assets/
```

## 🚀 Getting Started

### Prerequisites

To run the hands-on labs, you'll need:

- **Docker**: [Install Docker](https://docs.docker.com/get-docker/)
- **Docker Compose**: [Install Docker Compose](https://docs.docker.com/compose/install/)
- **Git**: [Install Git](https://git-scm.com/downloads)
- Basic understanding of web applications
- A code editor (VS Code, Sublime, etc.)

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/0x6a03448f4d/OWASP-TOP10.git
   cd OWASP-TOP10
   ```

2. **Choose a topic:**
   Navigate to any category in `OWASP-Web/`, `OWASP-API/`, `OWASP-LLM/`, or `OWASP-Mobile/`

3. **Read the documentation:**
   Start with `overview.md`, then explore `attack-vectors.md`, `prevention.md`, and `examples.md`

4. **Run a lab:**
   ```bash
   cd OWASP-Web/01-Broken-Access-Control/lab/broken-access-control-adminbutton
   docker-compose up
   ```

5. **Follow the instructions:**
   Open `instructions.md` in the lab folder for guided learning tasks

6. **Stop the lab:**
   ```bash
   docker-compose down
   ```

## 🎓 The OWASP Top 10 Categories

### [01 - Broken Access Control](./OWASP-Web/01-Broken-Access-Control/)
**Impact:** Unauthorized access to data and functionality  
**Lab:** Admin button accessible to regular users  
**Key Lesson:** Never rely on client-side access control

### [02 - Cryptographic Failures](./OWASP-Web/02-Cryptographic-Failures/)
**Impact:** Exposure of sensitive data  
**Lab:** Weak MD5 hashing vs secure bcrypt  
**Key Lesson:** Use strong, modern cryptographic algorithms

### [03 - Injection](./OWASP-Web/03-Injection/)
**Impact:** Data breach, data loss, system compromise  
**Lab:** Unsafe SQL query construction  
**Key Lesson:** Always use parameterized queries and input validation

### [04 - Insecure Design](./OWASP-Web/04-Insecure-Design/)
**Impact:** Business logic exploitation  
**Lab:** Login form without rate limiting  
**Key Lesson:** Security must be designed in from the start

### [05 - Security Misconfiguration](./OWASP-Web/05-Security-Misconfiguration/)
**Impact:** Information disclosure, system compromise  
**Lab:** Debug mode enabled in production  
**Key Lesson:** Secure defaults and configuration management

### [06 - Vulnerable and Outdated Components](./OWASP-Web/06-Vulnerable-Outdated-Components/)
**Impact:** System compromise through known vulnerabilities  
**Lab:** Application using outdated dependencies  
**Key Lesson:** Keep dependencies updated and monitored

### [07 - Identification and Authentication Failures](./OWASP-Web/07-Identification-Authentication-Failures/)
**Impact:** Account takeover, identity theft  
**Lab:** Predictable session tokens  
**Key Lesson:** Use strong session management and authentication

### [08 - Software and Data Integrity Failures](./OWASP-Web/08-Software-Data-Integrity-Failures/)
**Impact:** Malicious code execution, supply chain attacks  
**Lab:** Unsigned software updates  
**Key Lesson:** Verify integrity of software and data

### [09 - Security Logging and Monitoring Failures](./OWASP-Web/09-Security-Logging-Monitoring-Failures/)
**Impact:** Undetected breaches, slow incident response  
**Lab:** Application with no logging  
**Key Lesson:** Comprehensive logging and monitoring is essential

### [10 - Server-Side Request Forgery (SSRF)](./OWASP-Web/10-Server-Side-Request-Forgery/)
**Impact:** Internal system access, data exfiltration  
**Lab:** URL fetcher with simulated internal services  
**Key Lesson:** Validate and sanitize all URLs and network requests

## 📖 How to Use This Repository

### For Beginners

1. **Start with Category 01** (Broken Access Control)
2. Read all documentation in order: overview → attack-vectors → prevention → examples
3. Run the lab and follow the instructions step-by-step
4. Take notes on key concepts
5. Move to the next category

### For Developers

1. **Focus on prevention.md** for each category
2. Review the **examples.md** for secure coding patterns
3. Use the labs to **test your understanding**
4. Apply these patterns to your own projects
5. Share knowledge with your team

### For Security Professionals

1. Use as a **training resource** for teams
2. Adapt labs for **internal workshops**
3. Reference documentation in **security reviews**
4. Contribute improvements and additional examples
5. Create custom learning paths for specific needs

### For Educators

1. **Assign categories** as course modules
2. Use labs as **hands-on assignments**
3. Create **quizzes** based on documentation
4. Encourage students to **contribute** improvements
5. Build **capture-the-flag** style challenges around concepts

## 🔬 Running the Labs

Each lab is completely self-contained and runs in Docker for safety and isolation.

### Basic Lab Workflow

```bash
# 1. Navigate to a lab
cd OWASP-Web/XX-Category/lab/lab-name/

# 2. Start the lab
docker-compose up

# 3. Access the application
# Usually at http://localhost:5000 (check lab README)

# 4. Follow instructions.md for guided tasks

# 5. Stop the lab
docker-compose down

# 6. Clean up (optional)
docker-compose down -v  # Removes volumes too
```

### Lab Safety Features

All labs are designed with safety in mind:

- ✅ **Isolated containers** - No access to your system
- ✅ **Local-only networking** - No external connections
- ✅ **No real exploits** - Conceptual demonstrations only
- ✅ **Educational markers** - Clear comments in code
- ✅ **Easy cleanup** - Simple teardown with docker-compose

### Troubleshooting Labs

**Port already in use:**
```bash
# Find what's using the port
lsof -i :5000  # On Mac/Linux
netstat -ano | findstr :5000  # On Windows

# Either stop the conflicting service or modify docker-compose.yml
# to use a different port: "5001:5000"
```

**Docker daemon not running:**
```bash
# Start Docker Desktop or run:
sudo systemctl start docker  # Linux
```

**Permission denied:**
```bash
# Run with sudo (Linux) or ensure Docker Desktop is running
sudo docker-compose up
```

## 🗺️ Learning Paths

### 30-Day Security Challenge

**Week 1: Fundamentals**
- Day 1-2: Broken Access Control
- Day 3-4: Injection
- Day 5-6: Cryptographic Failures
- Day 7: Review and practice

**Week 2: Design & Configuration**
- Day 8-9: Insecure Design
- Day 10-11: Security Misconfiguration
- Day 12-13: Vulnerable Components
- Day 14: Review and practice

**Week 3: Authentication & Integrity**
- Day 15-17: Authentication Failures
- Day 18-20: Data Integrity Failures
- Day 21: Review and practice

**Week 4: Monitoring & Advanced**
- Day 22-24: Logging and Monitoring
- Day 25-27: SSRF
- Day 28-29: Review all categories
- Day 30: Final project - Secure a vulnerable app

### Role-Based Paths

**For Web Developers:**
1. Injection (03)
2. Broken Access Control (01)
3. Cryptographic Failures (02)
4. Authentication Failures (07)
5. Security Misconfiguration (05)

**For DevOps Engineers:**
1. Security Misconfiguration (05)
2. Vulnerable Components (06)
3. Logging and Monitoring (09)
4. Data Integrity Failures (08)
5. SSRF (10)

**For Security Analysts:**
1. Logging and Monitoring (09)
2. Broken Access Control (01)
3. Injection (03)
4. Authentication Failures (07)
5. SSRF (10)

## 🤝 Contributing

We welcome contributions from the community! Whether it's:

- 🐛 Bug fixes
- 📝 Documentation improvements
- 🔬 New labs or lab enhancements
- 💡 Feature suggestions
- 🌍 Translations

**Please read [CONTRIBUTING.md](./CONTRIBUTING.md)** for detailed guidelines on:
- Code of conduct
- Security-safe content rules
- Pull request process
- Writing standards
- Lab development guidelines

### Quick Contribution Checklist

- [ ] Read CONTRIBUTING.md
- [ ] Follow the ethical guidelines
- [ ] No weaponizable exploit code
- [ ] Test your changes
- [ ] Update documentation
- [ ] Submit a clear PR

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](./LICENSE) file for details.

You are free to:
- ✅ Use this for learning
- ✅ Share with others
- ✅ Modify and adapt
- ✅ Use in teaching

With the requirement to:
- ✅ Include copyright notice
- ✅ Include license text
- ✅ Use ethically and responsibly

## 📚 Resources

### Official OWASP Resources
- [OWASP Top 10 Official Page](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Learning Resources
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [Secure Code Warrior](https://www.securecodewarrior.com/)
- [HackerOne CTF](https://www.hackerone.com/for-hackers/hacker101)

### Secure Coding References
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SANS Secure Coding](https://www.sans.org/secure-coding/)

### Tools
- [OWASP ZAP](https://www.zaproxy.org/) - Security testing tool
- [SonarQube](https://www.sonarqube.org/) - Code quality and security
- [Snyk](https://snyk.io/) - Dependency vulnerability scanning
- [Bandit](https://bandit.readthedocs.io/) - Python security linting

## 🙏 Acknowledgments

- **OWASP** for maintaining the Top 10 standard
- All contributors who help improve this repository
- The cybersecurity education community
- Everyone committed to building more secure applications

## 📞 Contact & Support

- **Issues:** Use [GitHub Issues](https://github.com/0x6a03448f4d/OWASP-TOP10/issues) for bugs or questions
- **Discussions:** Use [GitHub Discussions](https://github.com/0x6a03448f4d/OWASP-TOP10/discussions) for general questions
- **Security:** For security concerns, please see CONTRIBUTING.md

---

**Remember:** Knowledge is power. Use it responsibly. 🛡️

*Last Updated: 2025 | Based on OWASP Top 10 2021*
