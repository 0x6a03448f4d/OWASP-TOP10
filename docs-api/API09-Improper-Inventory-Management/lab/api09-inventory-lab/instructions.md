# API09: Improper Inventory Management Lab

## Setup
```bash
docker-compose up -d
```
Access: http://localhost:5009

## Exercises

### Exercise 1: Discover Old API Versions
- Find v1, v2, v3 endpoints
- Test which lack authentication

### Exercise 2: Find Undocumented Endpoints
- Fuzzing common paths: /admin, /_internal, /debug
- Find hidden admin endpoint

### Exercise 3: Exploit Old Version
- Use v1 API to bypass v3 security

### Exercise 4: Fix Inventory Issues
1. Sunset v1 (return 410 Gone)
2. Remove undocumented endpoints
3. Document all public APIs
4. Implement consistent security across versions

## Success Criteria
- ✅ Find all undocumented endpoints
- ✅ Exploit old API version
- ✅ Create comprehensive API inventory
- ✅ Implement version lifecycle management
