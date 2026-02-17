# API05: Broken Function Level Authorization - Overview

## Table of Contents
- [What is Broken Function Level Authorization?](#what-is-broken-function-level-authorization)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Broken Function Level Authorization?

**Broken Function Level Authorization (BFLA)** occurs when an API endpoint does not properly verify whether the authenticated user has the necessary privileges to execute a specific function. Unlike object-level authorization (which controls access to specific data), function-level authorization controls access to specific operations or capabilities.

APIs often expose administrative, privileged, or sensitive functions that should only be accessible to specific user roles. When authorization checks are missing, improperly implemented, or easily bypassed, regular users can access functions intended only for administrators or elevated privilege levels.

### Core Concept

```
Regular User attempts: DELETE /api/users/456
Admin Function that should require admin role
                    ↓
BROKEN BFLA = Regular user can execute admin function
              because the endpoint doesn't verify role/privileges
```

### Function-Level vs Object-Level Authorization

| Aspect | Object-Level (BOLA) | Function-Level (BFLA) |
|--------|-------------------|---------------------|
| **Controls** | Access to specific resources | Access to specific operations |
| **Question** | "Can user A access resource B?" | "Can user A perform action X?" |
| **Example Vulnerable** | User views another user's order | User deletes any user account |
| **Typical Issue** | Missing ownership check | Missing role/privilege check |

### Why It's Critical for APIs

APIs are particularly vulnerable to BFLA because:
- **Hidden Endpoints**: Admin functions exist but aren't linked in UI
- **Method-Based Access**: Same URL with different HTTP methods (GET vs DELETE)
- **Parameter Manipulation**: Role or privilege data sent in request
- **Microservices**: Authorization logic distributed across services
- **API Evolution**: Features added without proper access control review

## Why Does This Matter?

### The Business Impact

- **Complete System Compromise**: Attackers gain administrative control
- **Data Destruction**: Unauthorized deletion of critical business data
- **Service Disruption**: Ability to disable features or entire systems
- **Financial Fraud**: Access to financial operations (refunds, transfers, withdrawals)
- **Regulatory Violations**: Unauthorized access to protected functions (GDPR, HIPAA, SOX)
- **Competitive Damage**: Manipulation of pricing, inventory, or business logic
- **Supply Chain Risk**: Compromise of partner/vendor management functions

### The Technical Impact

- **Vertical Privilege Escalation**: Regular users execute admin functions
- **Lateral Movement**: Users access functions of different departments/roles
- **Configuration Changes**: Modification of system settings or security controls
- **User Management**: Creating/deleting users, modifying permissions
- **Data Manipulation**: Bulk operations, imports/exports, database access

## Technical Context

### Common Vulnerable Patterns

#### 1. Missing Authorization Checks

```python
# VULNERABLE: No role check
@app.route('/api/admin/users', methods=['DELETE'])
def delete_user():
    user_id = request.json.get('user_id')
    User.query.filter_by(id=user_id).delete()
    return {'status': 'deleted'}

# Anyone authenticated can call this endpoint
```

#### 2. Client-Side Role Enforcement Only

```javascript
// VULNERABLE: Role check only in frontend
if (user.role === 'admin') {
    // Show delete button in UI
    fetch('/api/users/123', { method: 'DELETE' });
}

// Backend doesn't verify role - endpoint accessible via direct API call
```

#### 3. Hidden Admin Endpoints

```
# Documented public API
GET  /api/users        # List users
POST /api/users        # Create user (registration)

# Undocumented admin endpoints (accessible if discovered)
GET    /api/admin/users          # List all users with PII
DELETE /api/admin/users/:id      # Delete any user
PUT    /api/admin/users/:id/role # Change user roles
```

#### 4. HTTP Method Manipulation

```python
# VULNERABLE: GET has auth check, but DELETE doesn't
@app.route('/api/users/<id>', methods=['GET', 'DELETE'])
def user_endpoint(id):
    if request.method == 'GET':
        if not current_user.can_view(id):
            return {'error': 'Forbidden'}, 403
        return get_user(id)
    
    elif request.method == 'DELETE':
        # Missing authorization check!
        delete_user(id)
        return {'status': 'deleted'}
```

#### 5. Parameter-Based Role Assignment

```python
# VULNERABLE: User controls their role via request parameter
@app.route('/api/action')
def perform_action():
    user_role = request.json.get('role', 'user')  # Attacker sets 'admin'
    
    if user_role == 'admin':
        return perform_admin_action()
    return perform_user_action()
```

### Authorization Hierarchy

```
┌─────────────────────────────────────┐
│         Authentication              │  Who are you?
│  (Session, JWT, API Key)            │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   Function-Level Authorization      │  What can you do?
│   (Role, Privilege, Permission)     │  ← API05 Focus
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│    Object-Level Authorization       │  Which specific data?
│    (Ownership, Scope)               │  ← API01 Focus
└─────────────────────────────────────┘
```

## Real-World Impact

### Case Study 1: Social Media Platform Breach

**Incident**: A popular social media platform had admin endpoints that didn't verify roles.

**Attack Vector**:
- Attacker discovered undocumented endpoint: `/api/v2/admin/delete_account`
- Endpoint required authentication but not admin role
- Any logged-in user could delete any account

**Impact**:
- 15,000+ accounts deleted before detection
- Celebrity and influencer accounts targeted
- $8M in damages and reputation loss
- 3-day service disruption for recovery

**Root Cause**: Admin functions separated from public API but shared authentication middleware without role checks.

### Case Study 2: E-commerce Platform Manipulation

**Incident**: Online retailer exposed admin pricing functions.

**Attack Vector**:
- Standard API: `GET /api/products/123`
- Discovered: `PUT /api/products/123/price` (no admin check)
- Attacker changed prices to $0.01

**Impact**:
- 2,400 orders processed at fraudulent prices
- $450,000 in direct losses
- Additional costs for order cancellations and customer service

**Root Cause**: Price update function added for admin dashboard but deployed to public API without authorization checks.

### Case Study 3: Healthcare System Privilege Escalation

**Incident**: Telemedicine platform allowed role elevation.

**Attack Vector**:
- Registration endpoint: `POST /api/register`
- Parameter: `{"role": "patient"}` in request
- Attacker modified to: `{"role": "doctor"}`

**Impact**:
- Unauthorized access to 12,000+ patient records
- HIPAA violation with $2.3M fine
- Access to prescription system
- 18-month monitoring requirement

**Root Cause**: Role assignment trusted client-side input without server-side validation.

### Case Study 4: Financial Services API

**Incident**: Banking API exposed admin refund function.

**Attack Vector**:
- Mobile app used: `POST /api/transactions/dispute`
- Reverse engineering revealed: `POST /api/admin/transactions/refund`
- No role verification on admin endpoint

**Impact**:
- $1.2M in fraudulent refunds processed
- 340 unauthorized transactions
- Federal investigation and compliance review
- Platform suspended for 2 weeks

**Root Cause**: Internal admin API accidentally deployed to public-facing gateway without access controls.

### Case Study 5: SaaS Platform Account Takeover

**Incident**: Project management SaaS had flawed user management API.

**Attack Vector**:
- Regular users could call: `PUT /api/workspace/users/permissions`
- Endpoint didn't verify caller was workspace admin
- Users elevated themselves to admin role

**Impact**:
- 200+ workspaces compromised
- Intellectual property theft
- Customer data exfiltration
- $15M class action settlement

**Root Cause**: Permission changes implemented without distinguishing between workspace admin and workspace member roles.

## Prevalence and Statistics

### Industry Research

**OWASP API Security Top 10 (2023)**:
- Ranked #5 most critical API vulnerability
- Present in approximately 30% of API implementations
- Average time to detect: 89 days
- Frequently combined with API01 (BOLA) in attacks

**Verizon Data Breach Investigations Report**:
- 23% of web application breaches involved privilege escalation
- 81% of privilege misuse incidents involved administrative functions
- Median time to discover: 56 days

**Salt Security API Threat Research**:
- 40% of organizations experienced a function-level authorization incident
- 300% increase in admin function abuse from 2021-2023
- 65% of attacks target undocumented endpoints

### Vulnerability Patterns by Technology

| Technology | BFLA Prevalence | Common Issue |
|------------|-----------------|--------------|
| REST APIs | 35% | Hidden admin endpoints |
| GraphQL | 42% | Unrestricted mutations |
| Microservices | 38% | Inconsistent auth between services |
| Legacy APIs | 51% | Retrofitted admin functions |
| Mobile APIs | 33% | Client-controlled permissions |

### Detection Difficulty

```
Low Detection → High Attack Success
    │
    ├─ Missing from automated scanners (logic-based)
    ├─ Requires understanding of business logic
    ├─ No obvious error messages
    ├─ Often bypasses WAFs and API gateways
    └─ Requires role-based testing
```

### Cost of Exploitation

- **Average breach cost**: $3.8M (IBM Security Report)
- **Regulatory fines**: $500K - $20M (varies by regulation)
- **Remediation time**: 30-120 days
- **Customer churn**: 15-30% in severe cases

## Common Misunderstandings

### Myth 1: "Authentication is Sufficient"

**Misconception**: If users are authenticated, they can access authenticated endpoints.

**Reality**: Authentication proves identity. Authorization determines permissions. These are separate concerns.

```python
# WRONG: Assuming authentication = authorization
@login_required  # Only checks if user is logged in
def delete_users():
    # Missing: Is this user an admin?
    pass
```

### Myth 2: "Hiding Endpoints Provides Security"

**Misconception**: If admin endpoints aren't documented or linked in the UI, they're secure.

**Reality**: Security through obscurity fails. Endpoints are discoverable through:
- API documentation leaks
- JavaScript source code
- Network traffic analysis
- Error messages
- Directory enumeration
- Version control repositories

### Myth 3: "Role Checks in Frontend are Enough"

**Misconception**: Client-side role validation prevents unauthorized access.

**Reality**: Frontend controls are easily bypassed. Attackers use:
- Direct API calls (curl, Postman)
- Modified mobile apps
- Proxy tools (Burp Suite)
- Browser developer tools

### Myth 4: "Internal APIs Don't Need Authorization"

**Misconception**: APIs behind firewalls or on internal networks don't need function-level checks.

**Reality**: Insider threats, compromised accounts, and lateral movement make internal APIs equally vulnerable.

### Myth 5: "Different HTTP Methods Are Automatically Restricted"

**Misconception**: DELETE/PUT methods are inherently more protected than GET.

**Reality**: HTTP methods are just verbs. Without explicit authorization checks, they're all equally accessible.

```python
# WRONG: Assuming DELETE is automatically restricted
@app.route('/api/users/<id>', methods=['GET', 'DELETE'])
def users(id):
    # Both methods accessible unless explicitly checked
    pass
```

### Myth 6: "Role Names Provide Security"

**Misconception**: Complex role names like "super_admin_privileged" make privilege escalation harder.

**Reality**: Role names are labels. Without proper enforcement, they provide no security.

### Myth 7: "APIs Don't Have Admin Functions"

**Misconception**: Only admin dashboards have administrative functions.

**Reality**: APIs often have:
- Bulk operations
- Data export/import
- Configuration changes
- User management
- System monitoring
- Debugging endpoints
- Reporting functions

### Myth 8: "Testing as Regular User is Sufficient"

**Misconception**: If testers can't access admin functions in the UI, the API is secure.

**Reality**: Proper testing requires:
- Multi-role testing (user, moderator, admin)
- Negative testing (unauthorized access attempts)
- API-level testing (not just UI)
- Privilege escalation attempts

## Key Takeaways

1. **Function-level authorization is mandatory** for every endpoint that performs privileged operations
2. **Authentication ≠ Authorization** - they serve different purposes
3. **Server-side enforcement only** - never trust client-side controls
4. **Explicit role/permission checks** must be implemented for sensitive functions
5. **Default-deny approach** - functions should be restricted unless explicitly allowed
6. **Regular security audits** with role-based testing are essential
7. **Assume discovery** - all endpoints will eventually be found by attackers

## Next Steps

- **[Attack Vectors](attack-vectors.md)** - Learn how attackers exploit BFLA vulnerabilities
- **[Prevention](prevention.md)** - Implement proper function-level authorization
- **[Examples](examples.md)** - See vulnerable and secure code patterns
- **[Lab](lab/api05-function-auth-lab/)** - Practice exploiting and fixing BFLA in a safe environment
