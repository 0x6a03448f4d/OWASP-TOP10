# API08: Security Misconfiguration - Prevention

## Secure CORS Configuration

```python
from flask_cors import CORS

# SECURE: Specific origins only
CORS(app, origins=['https://app.example.com'], supports_credentials=True)

# NOT: CORS(app, origins='*')  # VULNERABLE
```

```javascript
// Node.js
const cors = require('cors');
app.use(cors({
    origin: ['https://app.example.com'],
    credentials: true
}));
```

## Generic Error Messages

```python
@app.errorhandler(Exception)
def handle_error(e):
    # Log full error internally
    logger.error(f"Error: {str(e)}", exc_info=True)
    
    # Return generic message to user
    return jsonify({'error': 'An error occurred'}), 500
```

## Security Headers

```python
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

## Disable Debug in Production

```python
# config.py
import os

DEBUG = os.environ.get('FLASK_ENV') == 'development'  # False in prod

# Never expose debug endpoints
if not DEBUG:
    # Remove debug routes
    pass
```

## Configuration Management

```python
# Use environment variables
import os

DATABASE_URL = os.environ['DATABASE_URL']
SECRET_KEY = os.environ['SECRET_KEY']

# NOT: Hardcoded secrets
# DATABASE_URL = 'postgresql://admin:pass@localhost/db'  # VULNERABLE
```

## Key Takeaways

1. **CORS**: Whitelist specific origins
2. **Errors**: Generic messages only
3. **Headers**: All security headers
4. **Debug**: OFF in production
5. **Secrets**: Environment variables
6. **Defaults**: Change all passwords
7. **Audit**: Regular security scans
