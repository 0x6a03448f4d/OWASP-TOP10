# Supply Chain Attack Vectors

## 1. Dependency Confusion

```python
# Attacker discovers internal package name
# Internal: company-utils (private repo)

# Attacker publishes to PyPI:
# malicious-company-utils (public)

# Developer runs:
pip install company-utils

# If public repo checked first, gets malicious version
```

## 2. Typosquatting

```python
# Popular package: requests
# Attacker publishes: reqeusts, requsets, request

# Developer makes typo:
pip install requsets  # Malicious package!
```

## 3. Compromised Maintainer

```
1. Attacker gains access to maintainer account
2. Publishes malicious version
3. Auto-update systems install malicious code
4. Widespread compromise
```

## 4. Transitive Dependencies

```python
# Your direct dependencies look safe
# But nested dependency is compromised:

Your App
└── trusted-package (safe)
    └── popular-lib (safe)
        └── obscure-dependency (COMPROMISED!)
```

## 5. Build System Compromise

```yaml
# CI/CD pipeline hijacked
# Malicious code injected during build
# Signed with legitimate keys
# Distributed to all users
```
