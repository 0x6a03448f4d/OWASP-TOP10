# API05: Broken Function Level Authorization - Attack Vectors

## Table of Contents
- [Understanding BFLA Attack Vectors](#understanding-bfla-attack-vectors)
- [Common Attack Patterns](#common-attack-patterns)
- [Application Flaws That Enable Attacks](#application-flaws-that-enable-attacks)
- [Signs and Symptoms of Vulnerability](#signs-and-symptoms-of-vulnerability)
- [What Attackers Look For](#what-attackers-look-for)
- [Detection Techniques](#detection-techniques)

## Understanding BFLA Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY**  
> This document describes attack concepts at a high level for educational purposes. No exploit code or weaponizable techniques are provided. Understanding these patterns helps developers build better defenses.

An **attack vector** for BFLA is the method attackers use to execute privileged functions they shouldn't have permission to access. The fundamental pattern is: identify privileged endpoints or operations and attempt to execute them with insufficient privileges.

### The Core Attack Flow

```
1. Reconnaissance
   ↓
   Discover API endpoints and structure
   ↓
   Identify privileged/admin functions
   ↓
   Map authorization requirements

2. Attack Attempt
   ↓
   Authenticate as regular user
   ↓
   Invoke admin function with regular user credentials
   ↓
   If authorization missing → Privilege escalation successful
   ↓
   Execute unauthorized operations
```

## Common Attack Patterns

### 1. Admin Endpoint Discovery and Access

**What it is**: Finding and accessing undocumented administrative endpoints.

**Conceptual Flow**:
```
Regular user logs in → Receives JWT token
↓
Analyzes public API documentation
  GET /api/users       (documented)
  POST /api/users      (documented - registration)
↓
Discovers through JavaScript or network analysis:
  GET /api/admin/users           (undocumented)
  DELETE /api/admin/users/:id    (undocumented)
  PUT /api/admin/system/config   (undocumented)
↓
Attempts access with regular user token:
  curl -H "Authorization: Bearer <user_token>" \
       https://api.example.com/api/admin/users
↓
Result: If no role check → Full admin access
```

**Why It Works**:
- Admin endpoints share same authentication
- Authorization checks not implemented
- Endpoints deployed but not secured
- Developers assume obscurity = security

**Indicators in Your API**:
- URL patterns with `/admin/`, `/internal/`, `/v2/admin/`
- Endpoints returning more data when accessed differently
- Different response structures between similar endpoints
- Error messages revealing privileged operations

### 2. HTTP Method Tampering

**What it is**: Using different HTTP methods on the same endpoint to access privileged operations.

**Conceptual Flow**:
```
User can access: GET /api/products/123
↓
Tests other methods on same endpoint:
  POST   /api/products/123 → 405 Method Not Allowed
  PUT    /api/products/123 → 200 OK (update succeeds!)
  DELETE /api/products/123 → 200 OK (deletion succeeds!)
  PATCH  /api/products/123 → 200 OK (partial update succeeds!)
↓
Exploits lack of method-specific authorization
```

**Why It Works**:
- Authorization logic only checks read operations
- Write/Delete methods added later without auth updates
- Framework defaults allow all methods
- Different methods handled by different code paths

**Indicators in Your API**:
- Same route handles multiple methods
- GET requires auth but PUT/DELETE don't
- Inconsistent authorization between methods
- Method-specific errors reveal functionality

### 3. Parameter Manipulation for Privilege Escalation

**What it is**: Modifying request parameters to claim elevated privileges.

**Conceptual Flow**:
```
Normal registration:
  POST /api/register
  {"username": "alice", "email": "alice@example.com"}
↓
Attacker adds role parameter:
  POST /api/register
  {"username": "eve", "email": "eve@evil.com", "role": "admin"}
↓
Backend trusts client input:
  user = User.create(request.json)  # Includes role!
↓
Result: Eve registered as admin
```

**Parameter Variations**:
```json
// Role-based
{"role": "admin"}
{"user_type": "administrator"}
{"is_admin": true}

// Permission-based
{"permissions": ["read", "write", "delete", "admin"]}
{"access_level": 99}

// Group-based
{"groups": ["users", "administrators"]}
{"department": "IT_ADMIN"}
```

**Why It Works**:
- Backend doesn't validate privileged parameters
- Mass assignment vulnerabilities
- No whitelist of allowed fields
- Trust in client-provided data

### 4. Hidden Parameter Discovery

**What it is**: Finding undocumented parameters that enable privileged operations.

**Conceptual Flow**:
```
Normal request:
  GET /api/users?limit=10
↓
Fuzzing parameters reveals:
  GET /api/users?limit=10&debug=true
    → Returns additional internal fields
  
  GET /api/users?limit=10&include_deleted=true
    → Returns soft-deleted users (admin function)
  
  GET /api/users?limit=10&export=csv
    → Exports all users (data exfiltration)
↓
Unauthorized access to admin features via parameters
```

**Common Hidden Parameters**:
- `debug`, `verbose`, `detailed`
- `admin`, `internal`, `privileged`
- `export`, `download`, `dump`
- `include_deleted`, `show_all`, `bypass_filter`
- `override`, `force`, `skip_validation`

### 5. API Version Exploitation

**What it is**: Accessing older or newer API versions with weaker security.

**Conceptual Flow**:
```
Current API (v3): /api/v3/users
  ✓ Proper authorization checks
↓
Attacker tests other versions:
  /api/v1/users     → Legacy, minimal security
  /api/v2/users     → Deprecated, auth bugs
  /api/beta/users   → New features, incomplete security
  /api/internal/users → Internal version, no public auth
↓
Exploits version with weakest controls
```

**Why It Works**:
- Old versions not retired or patched
- New versions deployed before security review
- Inconsistent security across versions
- Version-specific code paths

### 6. GraphQL Mutation Abuse

**What it is**: Executing privileged mutations without proper authorization.

**Conceptual Flow**:
```
Regular user can query:
  query {
    user(id: "123") { name, email }
  }
↓
Discovers mutations through introspection:
  mutation {
    deleteUser(id: "456")
    updateUserRole(id: "789", role: "admin")
    resetAllPasswords
  }
↓
Executes admin mutations with user credentials
```

**Why It Works**:
- Authorization on queries but not mutations
- GraphQL introspection reveals all operations
- Fine-grained auth not implemented
- Mutations treated like queries

### 7. Bulk Operation Exploitation

**What it is**: Using batch/bulk endpoints intended for admins.

**Conceptual Flow**:
```
Regular endpoint: DELETE /api/users/123 (with ownership check)
↓
Discover bulk endpoint:
  POST /api/users/bulk-delete
  {"user_ids": [123, 456, 789, ...]}
↓
Bulk endpoint missing authorization:
  - No ownership verification
  - No role check for bulk operations
  - Intended for admin use only
↓
Result: Mass deletion by regular user
```

**Bulk Operations at Risk**:
- `bulk-delete`, `batch-delete`
- `bulk-update`, `batch-update`
- `import`, `export`
- `migrate`, `transfer`
- `archive`, `restore`

### 8. Middleware Bypass

**What it is**: Circumventing authorization middleware through alternate routes.

**Conceptual Flow**:
```
Protected route:
  /api/admin/* → Admin middleware → Controller
                  ✓ Role check
↓
Alternate access points:
  /api/v2/admin/* → No middleware
  /admin-api/*    → No middleware  
  /internal/*     → No middleware
↓
Same controllers, different routes, missing auth
```

**Why It Works**:
- Middleware applied to specific routes only
- Alternate routes added later
- Inconsistent middleware configuration
- Framework routing complexity

### 9. Service-to-Service Impersonation

**What it is**: Exploiting inter-service communication that lacks authorization.

**Conceptual Flow**:
```
Microservice Architecture:
  Frontend → API Gateway → Service A → Service B
                            ✓ Auth     ✗ No auth
↓
Attacker accesses Service B directly:
  - Service B trusts requests from Service A
  - No authorization on Service B endpoints
  - Assumes only Service A can call it
↓
Direct access to privileged Service B functions
```

**Why It Works**:
- Internal services trust network perimeter
- Authorization only at API gateway
- Service-to-service auth not implemented
- Assumption of trusted internal network

### 10. Header Manipulation

**What it is**: Modifying headers to claim elevated privileges.

**Conceptual Flow**:
```
Normal request:
  GET /api/data
  Authorization: Bearer <token>
↓
Add internal headers:
  GET /api/data
  Authorization: Bearer <token>
  X-User-Role: admin
  X-Internal-Request: true
  X-Service-Name: admin-service
↓
Backend trusts headers without validation
```

**Commonly Abused Headers**:
- `X-User-Role`, `X-Role`, `X-Admin`
- `X-Internal-Request`, `X-Internal-User`
- `X-Forwarded-For` (IP-based auth bypass)
- `X-Service-Name`, `X-Client-Type`
- Custom application headers

### 11. Token Manipulation

**What it is**: Modifying JWT or other tokens to claim higher privileges.

**Conceptual Flow**:
```
User receives JWT:
  {
    "user_id": 123,
    "role": "user",
    "exp": 1234567890
  }
↓
JWT not properly signed or algorithm is "none":
  - Change "role": "admin"
  - Re-encode JWT
  - Submit modified token
↓
If signature not validated → Admin access granted
```

**Token Vulnerabilities**:
- Algorithm: none attack
- Weak signing keys
- No signature verification
- Client-controlled claims
- Expired tokens accepted

### 12. Endpoint Path Traversal

**What it is**: Manipulating endpoint paths to access privileged functions.

**Conceptual Flow**:
```
User endpoint: /api/user/profile
↓
Path manipulation attempts:
  /api/user/../admin/profile
  /api/user/%2e%2e/admin/users
  /api/user/./admin/settings
↓
Improperly normalized paths lead to admin endpoints
```

**Why It Works**:
- Path normalization after routing
- Framework routing vulnerabilities
- Inconsistent path handling
- URL encoding bypasses filters

### 13. File Operation Privilege Escalation

**What it is**: Using file upload/download endpoints for unauthorized system access.

**Conceptual Flow**:
```
Normal upload: POST /api/files/upload
  → Saves to /uploads/users/
↓
Parameter manipulation:
  POST /api/files/upload
  {"path": "../../config/"}
↓
Upload configuration files to:
  /uploads/users/../../config/ → /config/
↓
Overwrite system configuration with admin privileges
```

**File Operation Risks**:
- Path traversal in file operations
- Unrestricted file types
- No upload location validation
- Download of sensitive files
- Configuration file manipulation

### 14. Race Condition Exploitation

**What it is**: Exploiting timing windows in authorization checks.

**Conceptual Flow**:
```
User initiates privilege request:
  POST /api/request-admin-access
↓
Admin approves in separate system
↓
Brief window where user has elevated token but check incomplete
↓
Rapid execution of admin operations before final validation
```

**Timing Attack Scenarios**:
- Role change propagation delays
- Token validation lag
- Session synchronization issues
- Multi-step verification processes

### 15. Default Credentials and Endpoints

**What it is**: Accessing admin functions using default or common credentials.

**Conceptual Flow**:
```
Common default accounts:
  admin/admin
  administrator/password
  root/root
  api_admin/api_admin
↓
Default admin endpoints:
  /api/admin
  /api/management
  /api/console
  /api/debug
↓
Test default credentials on discovered endpoints
```

**Why It Works**:
- Default accounts not changed
- Test/debug accounts left active
- Common naming conventions
- Documentation examples used in production

### 16. WebSocket Authorization Bypass

**What it is**: Accessing privileged WebSocket channels without proper authorization.

**Conceptual Flow**:
```
Regular REST API: ✓ Proper authorization
WebSocket endpoint: ✗ No authorization
↓
Connect to WebSocket:
  ws://api.example.com/admin-events
↓
Receive admin notifications and data streams:
  - User creation events
  - System alerts
  - Internal metrics
↓
Subscribe to privileged channels without role check
```

**Why It Works**:
- WebSocket auth treated differently than REST
- Channel subscriptions not validated
- Real-time features prioritized over security
- Different authentication mechanisms

### 17. API Documentation Exploitation

**What it is**: Using overly detailed API documentation to find privileged endpoints.

**Information Sources**:
```
Swagger/OpenAPI:
  - All endpoints listed, including admin
  - Parameter details and schemas
  - Authentication requirements
  - Response examples

GraphQL Introspection:
  - Complete schema including mutations
  - Hidden fields and operations
  - Deprecated but still functional endpoints

Source Code:
  - Public repositories
  - JavaScript bundles
  - Mobile app decompilation
  - Error stack traces
```

### 18. Response Analysis for Hidden Functionality

**What it is**: Analyzing API responses to discover privileged operations.

**Conceptual Flow**:
```
GET /api/users/123 response:
{
  "id": 123,
  "name": "Alice",
  "email": "alice@example.com",
  "_links": {
    "self": "/api/users/123",
    "update": "/api/users/123",
    "delete": "/api/admin/users/123"  ← Admin link exposed
  }
}
↓
Regular user follows admin link
↓
If no authorization check → Access granted
```

**Response Indicators**:
- HATEOAS links to admin operations
- Conditional fields based on role
- Error messages revealing operations
- Debug information in responses

### 19. Chained Request Exploitation

**What it is**: Combining multiple requests to achieve privileged operations.

**Conceptual Flow**:
```
Step 1: Create resource (allowed)
  POST /api/projects
  → Returns project_id: 789
↓
Step 2: Assign admin role to self (not validated)
  POST /api/projects/789/members
  {"user_id": 123, "role": "admin"}
↓
Step 3: Perform admin operation
  DELETE /api/projects/456
↓
Multi-step attack achieves privilege escalation
```

### 20. Caching and CDN Bypass

**What it is**: Accessing cached admin responses or bypassing CDN security.

**Conceptual Flow**:
```
Admin makes request:
  GET /api/admin/dashboard
  → Response cached by CDN
↓
Regular user requests same URL:
  → Receives cached admin response
↓
Or bypass CDN authorization:
  Regular: https://api.example.com/admin
  Direct:  https://origin.example.com/admin
           (CDN auth bypassed)
```

## Application Flaws That Enable Attacks

### 1. Authorization Logic Flaws

```python
# Inverted logic
if user.role != 'admin':
    return admin_function()  # Wrong!

# Incomplete checks
if 'admin' in user.roles:  # But doesn't check if user.roles is empty
    
# OR instead of AND
if user.is_authenticated() or user.is_admin():  # Should be AND
```

### 2. Trust Boundary Violations

- Trusting client-provided role information
- Accepting frontend authorization decisions
- Relying on HTTP headers for permissions
- Assuming network location indicates privilege

### 3. Inconsistent Enforcement

- Authorization on some endpoints but not others
- Different security between API versions
- Route-specific middleware gaps
- Framework default permissions

## Signs and Symptoms of Vulnerability

### In Code Review

- [ ] Endpoints without explicit role/permission checks
- [ ] Authorization logic only in frontend code
- [ ] Comments like "TODO: Add admin check"
- [ ] Privileged operations in public controllers
- [ ] Missing authorization middleware on routes
- [ ] Client-controlled role/permission parameters

### In Testing

- [ ] Regular users can access admin URLs
- [ ] Different HTTP methods have different authorization
- [ ] Adding parameters enables new functionality
- [ ] API documentation shows admin endpoints
- [ ] GraphQL introspection reveals privileged mutations
- [ ] Error messages differ by privilege level

### In Production

- [ ] Unauthorized operations in logs
- [ ] Users with unexpected permissions
- [ ] Admin functions in user activity logs
- [ ] Anomalous access patterns
- [ ] Privilege escalation attempts

## What Attackers Look For

### Discovery Phase

1. **Endpoint Enumeration**
   - API documentation (Swagger, OpenAPI)
   - JavaScript source code analysis
   - Network traffic interception
   - Directory and file brute forcing
   - Version control history

2. **Privilege Mapping**
   - Identify user vs admin endpoints
   - Map role-based access patterns
   - Find privilege escalation paths
   - Discover hidden parameters

3. **Authorization Testing**
   - Test each endpoint with different roles
   - Try privileged operations as regular user
   - Manipulate authorization parameters
   - Bypass authorization middleware

### Exploitation Phase

1. **Verify Access**: Confirm unauthorized operation succeeds
2. **Expand Scope**: Test other privileged functions
3. **Automate**: Script mass exploitation
4. **Exfiltrate**: Extract sensitive data or configurations
5. **Persist**: Create backdoor accounts or persistent access

## Detection Techniques

### For Security Teams

1. **Role-Based Testing**
   ```
   For each endpoint:
     - Test as unauthenticated user
     - Test as regular user
     - Test as different role users
     - Verify expected access control
   ```

2. **Automated Scanning**
   - Custom authorization test scripts
   - API security scanners configured for roles
   - GraphQL introspection analysis
   - Endpoint discovery tools

3. **Code Analysis**
   - Search for admin routes without auth decorators
   - Find endpoints handling multiple methods
   - Identify client-controlled permission fields
   - Review authorization middleware coverage

4. **Runtime Monitoring**
   - Alert on privilege violations
   - Track role-based access patterns
   - Monitor for endpoint discovery attempts
   - Log authorization failures

### Red Flags

- Users accessing URLs with `/admin/` patterns
- Successful DELETE/PUT from low-privilege accounts
- Parameter tampering in requests (role, is_admin)
- Unusual access to bulk operations
- GraphQL mutations from unexpected users

## Prevention Summary

All attack vectors share common prevention strategies:

1. **Explicit Authorization**: Every privileged endpoint must verify user permissions
2. **Server-Side Enforcement**: Never trust client-side authorization
3. **Default Deny**: Require explicit permission grants
4. **Centralized Logic**: Use middleware/decorators for consistent enforcement
5. **Regular Audits**: Test all endpoints with all user roles
6. **Minimal Disclosure**: Don't reveal privileged endpoints in responses

See [Prevention](prevention.md) for detailed implementation guidance.

## Next Steps

- **[Prevention](prevention.md)** - Learn how to properly implement function-level authorization
- **[Examples](examples.md)** - See vulnerable and secure code patterns
- **[Lab](lab/api05-function-auth-lab/)** - Practice exploiting and fixing BFLA vulnerabilities
