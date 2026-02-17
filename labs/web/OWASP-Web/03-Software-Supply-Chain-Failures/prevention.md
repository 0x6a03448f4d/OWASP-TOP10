# Supply Chain Security - Prevention

## Dependency Management

### 1. Software Bill of Materials (SBOM)

```python
# Generate SBOM for your project
# Using cyclonedx-bom
pip install cyclonedx-bom
cyclonedx-bom -o sbom.json
```

### 2. Dependency Pinning

```python
# requirements.txt - PRECISE VERSIONS
Flask==3.0.0  # Not Flask>=2.0
requests==2.31.0  # Not requests~=2.0
cryptography==41.0.7  # Exact version

# Generate from current environment
pip freeze > requirements.txt
```

### 3. Dependency Scanning

```bash
# Scan for vulnerabilities
pip-audit

# Check for known malicious packages
python -m pip install safety
safety check

# Use Snyk, Dependabot, or similar
snyk test
```

### 4. Package Verification

```python
# Verify package integrity
pip install package-name --require-hashes

# requirements.txt with hashes
Flask==3.0.0     --hash=sha256:abc123...
```

### 5. Private Package Repository

```python
# Use private PyPI mirror
pip install --index-url https://private-pypi.company.com package-name

# Block public packages
pip install --no-index --find-links=/local/packages package-name
```

## CI/CD Security

```yaml
# .github/workflows/security.yml
name: Supply Chain Security

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Dependency Scan
        run: |
          pip install pip-audit
          pip-audit
      
      - name: SBOM Generation
        run: |
          pip install cyclonedx-bom
          cyclonedx-bom -o sbom.json
      
      - name: License Compliance
        run: |
          pip install pip-licenses
          pip-licenses --fail-on "GPL"
      
      - name: Code Signing
        run: |
          gpg --sign --detach-sig dist/package.whl
```

## Best Practices

- Pin all dependencies to exact versions
- Generate and verify SBOMs
- Scan dependencies regularly
- Use private package repositories
- Verify package signatures
- Monitor for typosquatting
- Implement least privilege in CI/CD
- Use reproducible builds
- Enable 2FA for package publishing
- Review dependency changes carefully
