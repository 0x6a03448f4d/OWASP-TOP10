# API08: Security Misconfiguration Lab

## Setup
```bash
docker-compose up -d
```
Access: http://localhost:5008

## Exercises

### Exercise 1: CORS Exploitation
Test overly permissive CORS allows any origin to access API with credentials.

### Exercise 2: Information Disclosure
Trigger error endpoint to see full stack traces revealing:
- File paths
- Database credentials
- Internal structure

### Exercise 3: Debug Endpoint Access
Access /_debug to see:
- Full configuration
- Secret keys
- Environment variables

### Exercise 4: Fix Misconfigurations
1. Restrict CORS to specific origins
2. Implement generic error messages
3. Remove debug endpoint
4. Add security headers

## Success Criteria
- ✅ Identify all misconfigurations
- ✅ Understand impact
- ✅ Fix each issue
- ✅ Verify with security scan
