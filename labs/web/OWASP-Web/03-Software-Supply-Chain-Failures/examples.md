# Supply Chain Security - Examples

**❌ VULNERABLE:**

```python
# requirements.txt
Flask  # No version pinning!
requests>=2.0  # Too broad!
some-random-package  # Unknown package!

# Install command
pip install -r requirements.txt  # No verification!
```

**✅ SECURE:**

```python
# requirements.txt with exact versions and hashes
Flask==3.0.0     --hash=sha256:21...
requests==2.31.0     --hash=sha256:ab...

# Install with verification
pip install --require-hashes -r requirements.txt

# Automated scanning
pip-audit
safety check
```

**✅ MONITORING:**

```python
# Monitor for new dependencies
import subprocess
import json

def check_dependencies():
    # Get current packages
    result = subprocess.run(['pip', 'list', '--format=json'],
                          capture_output=True, text=True)
    current = json.loads(result.stdout)
    
    # Compare with approved list
    with open('approved-packages.json') as f:
        approved = json.load(f)
    
    for package in current:
        if package['name'] not in approved:
            alert(f"Unapproved package detected: {package['name']}")
```
