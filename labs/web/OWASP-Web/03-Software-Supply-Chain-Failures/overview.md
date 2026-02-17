# Software Supply Chain Failures - Overview

## What Are Supply Chain Attacks?

**Software Supply Chain Failures** occur when attackers compromise dependencies, build processes, or distribution channels to inject malicious code. In 2025, with complex dependency trees and automated CI/CD pipelines, this represents a critical threat.

### Modern Attack Vectors

- **Dependency Confusion**: Publishing malicious packages with same names as internal packages
- **Typosquatting**: Packages with names similar to popular libraries
- **Compromised Packages**: Legitimate packages hijacked by attackers
- **Malicious Dependencies**: Intentionally malicious packages
- **Build Pipeline Compromise**: Injecting malware during CI/CD

## Why This Matters in 2025

Modern applications depend on hundreds or thousands of packages:

```
Your App
├── Framework (100+ dependencies)
├── Database Driver (50+ dependencies)
├── HTTP Client (30+ dependencies)
└── Utility Libraries (200+ dependencies)

Total: 1000+ packages in dependency tree
```

**One compromised package = entire application compromised**

## Real-World 2025-Era Attacks

**SolarWinds (2020, still impactful)**
- Build system compromised
- Malicious code injected into updates
- 18,000+ organizations affected

**Log4Shell (2021, ongoing concerns)**
- Critical vulnerability in logging library
- Widespread dependency
- Billions of devices affected

**UA-Parser-JS (2021, modern example)**
- Popular npm package compromised
- Malware injected into legitimate package
- Downloaded millions of times weekly

**PyPI/npm Typosquatting (ongoing 2025)**
- Malicious packages mimicking popular ones
- Steal credentials, crypto wallets
- Continuous threat
