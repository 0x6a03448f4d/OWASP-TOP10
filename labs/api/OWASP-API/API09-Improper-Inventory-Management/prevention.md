# API09: Improper Inventory Management - Prevention

## Maintain API Inventory

```markdown
# API Inventory
- /api/v3/users (OAuth, rate-limited) - ACTIVE
- /api/v2/users (Basic auth) - DEPRECATED, sunset 2024-Q1
- /api/v1/users (no auth) - REMOVED
```

## Version Lifecycle Management

```python
# Enforce version sunset
@app.before_request
def check_version():
    if request.path.startswith('/api/v1'):
        return jsonify({'error': 'API v1 is deprecated. Use v3'}), 410
```

## Automated Endpoint Discovery

```bash
# Regular scans
nmap -p 443 --script http-enum api.company.com
nuclei -u https://api.company.com
```

## API Gateway

```
All traffic through gateway:
- Centralized inventory
- Unified logging
- Consistent security
```

## Key Takeaways

1. **Inventory**: Maintain complete API catalog
2. **Lifecycle**: Plan version sunsets
3. **Discovery**: Regular automated scans
4. **Gateway**: Central control point
5. **Documentation**: Keep up to date
