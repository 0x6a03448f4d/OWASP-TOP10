# API03: Broken Object Property Level Authorization - Overview

## Table of Contents
- [What is Broken Object Property Level Authorization?](#what-is-broken-object-property-level-authorization)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Broken Object Property Level Authorization?

**Broken Object Property Level Authorization** occurs when an API exposes too many object properties or allows users to modify properties they shouldn't have access to. This vulnerability manifests in two primary forms:

1. **Excessive Data Exposure**: APIs return more data than necessary, exposing sensitive fields that users shouldn't see
2. **Mass Assignment**: APIs accept all properties in user input, allowing modification of restricted fields like roles, prices, or status flags

Unlike API01 (Broken Object Level Authorization) which deals with accessing entire objects, API03 focuses on accessing or modifying individual properties within objects that should be restricted.

### Core Concept

```
EXCESSIVE DATA EXPOSURE:
User requests their profile: GET /api/users/me
API returns: {
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "password_hash": "$2b$12$...",        ← Should NOT be exposed
  "is_admin": false,                     ← Should NOT be exposed
  "salary": 85000,                       ← Should NOT be exposed
  "ssn": "123-45-6789"                   ← Should NOT be exposed
}

MASS ASSIGNMENT:
User updates profile: PUT /api/users/123
{
  "name": "Jane Doe",
  "is_admin": true          ← Should NOT be modifiable by user
}

VULNERABLE API = Accepts and updates is_admin field
SECURE API = Filters out unauthorized property modifications
```

### Why It's #3 for APIs

Modern APIs often:
- Return entire database objects without filtering sensitive fields
- Use generic serialization that exposes all model properties
- Accept all request body properties without validation
- Rely on client-side filtering (which can be bypassed)
- Use the same models for input and output
- Lack property-level access control
- Trust that clients won't send malicious fields

## Why Does This Matter?

### The Business Impact

- **Data Privacy Violations**: Exposure of PII, health data, financial information (GDPR, HIPAA, PCI-DSS violations)
- **Privilege Escalation**: Regular users gain admin access by setting privileged flags
- **Price Manipulation**: Users change product prices, discount percentages, or balances
- **Financial Fraud**: Modification of payment amounts, refund values, or account balances
- **Competitive Intelligence**: Competitors harvest business-critical data through over-exposed APIs
- **Regulatory Fines**: Million-dollar penalties for data protection failures
- **Audit Trail Corruption**: Modification of logs, timestamps, or tracking fields

### The Technical Impact

- **Horizontal Privilege Escalation**: Users see other users' sensitive data
- **Vertical Privilege Escalation**: Users elevate their privileges to admin
- **Business Logic Bypass**: Circumvent approval workflows by setting status flags
- **Data Harvesting**: Systematic collection of sensitive fields across records
- **State Manipulation**: Direct modification of object states (pending → approved)
- **Audit Evasion**: Manipulation of created_at, updated_at, or audit fields

## Technical Context

### How API03 Differs from API01

| API01 (Object Level) | API03 (Property Level) |
|---------------------|------------------------|
| Can I access THIS object? | Can I see/modify THIS field? |
| GET /users/456 | password_hash in response |
| Whole object authorization | Individual property authorization |
| User A accessing User B's data | User seeing admin-only fields |
| Object ownership checks | Property-level filtering |

### Common Vulnerable Patterns

#### Pattern 1: Excessive Data Exposure - Direct Model Serialization

```python
# VULNERABLE: Returns entire User model
@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user)  # Serializes ALL fields

Response:
{
  "id": 123,
  "username": "john",
  "email": "john@example.com",
  "password_hash": "$2b$12$KIX...",     ← EXPOSED
  "api_key": "sk_live_a1b2c3...",        ← EXPOSED
  "is_admin": false,                      ← EXPOSED
  "salary": 85000,                        ← EXPOSED
  "ssn": "123-45-6789",                   ← EXPOSED
  "reset_token": "abc123...",             ← EXPOSED
  "credit_card": "4111111111111111"       ← EXPOSED
}
```

#### Pattern 2: Mass Assignment - Accepting All Fields

```python
# VULNERABLE: Accepts all request body fields
@app.route('/api/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.get(user_id)
    data = request.json
    
    # Mass assignment vulnerability
    for key, value in data.items():
        setattr(user, key, value)
    
    db.session.commit()
    return jsonify(user)

Malicious Request:
PUT /api/users/123
{
  "name": "Updated Name",
  "is_admin": true,          ← Privilege escalation
  "balance": 1000000,        ← Financial fraud
  "role": "superadmin"       ← Role manipulation
}

Result: User gains admin privileges!
```

#### Pattern 3: Client-Side Filtering

```javascript
// VULNERABLE: API returns everything, filtering done client-side
fetch('/api/users/123')
  .then(res => res.json())
  .then(data => {
    // Client filters sensitive fields
    const {password_hash, ssn, salary, ...safeData} = data;
    displayUser(safeData);
  });

Problem: 
✗ Data already sent over network
✗ Attacker can intercept full response
✗ Browser dev tools reveal all fields
✗ API clients can bypass filtering
```

#### Pattern 4: GraphQL Over-Fetching

```graphql
# VULNERABLE: GraphQL resolver returns all fields
query GetUser {
  user(id: "123") {
    id
    name
    email
    passwordHash      ← Should not be queryable
    isAdmin           ← Should not be queryable
    salary            ← Should not be queryable
    apiKey            ← Should not be queryable
  }
}

Problem: GraphQL introspection reveals all available fields
```

#### Pattern 5: No Read vs Write Separation

```python
# VULNERABLE: Same model for read and write
class UserSchema(Schema):
    id = fields.Int()
    name = fields.Str()
    email = fields.Str()
    is_admin = fields.Bool()  # Readable AND writable
    salary = fields.Int()     # Readable AND writable

# Both endpoints use same schema
@app.route('/api/users/<id>', methods=['GET'])
def get_user(id):
    return UserSchema().dump(user)

@app.route('/api/users/<id>', methods=['PUT'])
def update_user(id):
    data = UserSchema().load(request.json)
    # is_admin and salary can be modified!
```

### The Property Authorization Stack

```
┌─────────────────────────────────────┐
│   1. Authentication (Who are you?)  │  ← Valid token/credentials
├─────────────────────────────────────┤
│   2. Object Authorization           │  ← Can you access this object?
│      (Can you access THIS user?)    │
├─────────────────────────────────────┤
│   3. Property Authorization (API03) │  ← Can you see/modify THIS field?
│      (Can you see salary field?)    │  ← COMMONLY FORGOTTEN
│      (Can you modify is_admin?)     │
└─────────────────────────────────────┘
```

**API03 vulnerabilities occur at Layer 3** - even with perfect authentication and object-level authorization, property-level controls may be missing.

## Real-World Impact

### Case Study 1: Uber (2016)

**Vulnerability**: API returned user data including driver locations and personal information  
**Impact**: Privacy breach affecting millions of users  
**Attack Method**: Excessive data exposure in API responses  
**Root Cause**: No filtering of sensitive fields before returning data

### Case Study 2: GitHub (2020)

**Vulnerability**: API allowed mass assignment of repository permissions  
**Impact**: Unauthorized access to private repositories  
**Attack Method**: Sending additional fields in API requests  
**Root Cause**: Insufficient input validation on property modifications

### Case Study 3: E-Commerce Platform

**Scenario**: Product price modification via mass assignment  
**Vulnerability**: PUT /api/orders endpoint accepted price field  
**Impact**: Users purchased items by setting price to $0.01  
**Attack Method**: Adding "price": 0.01 to order update requests  
**Root Cause**: No allowlist for updatable fields

### Case Study 4: Healthcare API

**Vulnerability**: Patient records API exposed full medical history including sensitive diagnoses  
**Impact**: HIPAA violation, $4.3M fine  
**Attack Method**: API returned all patient fields without role-based filtering  
**Root Cause**: Generic serialization exposing protected health information (PHI)

### Case Study 5: Social Media Platform

**Vulnerability**: User profile API exposed email addresses and phone numbers  
**Impact**: Mass data harvesting for spam/phishing campaigns  
**Attack Method**: Iterating through user IDs and collecting exposed contact info  
**Root Cause**: Profile endpoint returned private fields without permission checks

## Prevalence and Statistics

### OWASP API Security Top 10 2023 Data

- **#3** most critical API vulnerability
- Found in approximately **75%** of APIs tested
- **Highly exploitable** for both data theft and privilege escalation
- Average time to exploit: **Minutes** to discover excessive data exposure
- Detection difficulty: **Easy** (inspect API responses)

### Attack Characteristics

| Metric | Value |
|--------|-------|
| **Exploitability** | Very Easy - just inspect responses or send extra fields |
| **Prevalence** | Very Common - default serialization often vulnerable |
| **Detectability** | Very Easy - visible in API responses |
| **Technical Impact** | Severe - data exposure and privilege escalation |
| **Business Impact** | Severe - compliance violations, fraud |

### Vulnerability Types Distribution

| Vulnerability Type | Prevalence | Severity |
|-------------------|-----------|----------|
| **Excessive Data Exposure** | 60% | High |
| **Mass Assignment** | 40% | Critical |
| **Combined (Both)** | 25% | Critical |

### Industry Vulnerabilities

Different API types face varying property-level authorization risks:

| API Type | Risk Level | Common Issues |
|----------|------------|---------------|
| **Healthcare APIs** | Critical | PHI exposure, diagnostic data |
| **Financial APIs** | Critical | Balance, transaction, account data |
| **E-commerce APIs** | Critical | Price manipulation, order fraud |
| **HR/Payroll APIs** | Critical | Salary, SSN, performance data |
| **Social Media APIs** | High | Email, phone, private content |
| **SaaS APIs** | High | Multi-tenant data bleed |
| **IoT APIs** | Medium-High | Device credentials, sensor data |

## Common Misunderstandings

### Myth 1: "Object Authorization = Property Authorization"

**Reality**: Accessing an object doesn't mean accessing ALL its properties.

```python
# User can access their own profile (object level ✓)
# But should NOT see all fields (property level ✗)

@app.route('/api/users/me')
@require_auth
def get_my_profile():
    # Object level: ✓ User accessing their own data
    # Property level: ✗ Exposing password_hash, api_key, etc.
    return jsonify(current_user)  # WRONG!
```

### Myth 2: "Serializers Handle Security Automatically"

**Reality**: Generic serializers expose everything unless explicitly configured.

```python
# WRONG: Default serializer exposes all fields
user_schema = UserSchema()
return user_schema.dump(user)

# RIGHT: Explicitly define exposed fields
class PublicUserSchema(Schema):
    id = fields.Int()
    name = fields.Str()
    email = fields.Str()
    # password_hash NOT included
    # is_admin NOT included
    # salary NOT included
```

### Myth 3: "Frontend Doesn't Show It = Secure"

**Reality**: Security must be enforced server-side, not in UI.

```
Frontend hides sensitive fields:
✗ Attacker uses curl/Postman
✗ Attacker intercepts API response
✗ Browser dev tools reveal data
✗ Mobile app decompilation exposes data

Security ≠ Obscurity
Backend must filter!
```

### Myth 4: "Input Validation = Mass Assignment Protection"

**Reality**: Validation checks format, not authorization.

```python
# INSUFFICIENT:
class UserUpdateSchema(Schema):
    name = fields.Str(validate=Length(min=1, max=100))
    email = fields.Email()
    is_admin = fields.Bool()  # Validates boolean, but allows modification!

# Validation ensures is_admin is a boolean
# Does NOT prevent users from setting it!

# CORRECT:
class UserUpdateSchema(Schema):
    name = fields.Str(validate=Length(min=1, max=100))
    email = fields.Email()
    # is_admin NOT in schema = cannot be modified
```

### Myth 5: "Private Fields Named with Underscore Are Hidden"

**Reality**: Naming conventions don't enforce access control.

```python
class User(db.Model):
    id = db.Column(db.Integer)
    name = db.Column(db.String)
    _password_hash = db.Column(db.String)  # Underscore = "private"
    _is_admin = db.Column(db.Boolean)

# Still serialized and exposed!
jsonify(user)  # Includes _password_hash and _is_admin

# Python naming conventions ≠ Security
```

### Myth 6: "Read-Only Database Fields Are Protected"

**Reality**: ORM mass assignment can bypass database constraints.

```python
# Database schema:
# is_admin BOOLEAN DEFAULT FALSE  -- Read-only in DB

# BUT... ORM can still set it:
user = User.query.get(user_id)
data = request.json  # {"is_admin": true}

for key, value in data.items():
    setattr(user, key, value)  # Sets is_admin!

db.session.commit()  # Database accepts it!
```

### Myth 7: "DTOs Are Only for Large Applications"

**Reality**: Even small APIs need Data Transfer Objects.

```
DTOs provide:
✓ Security: Control exposed/accepted fields
✓ Versioning: API v1 vs v2 responses
✓ Documentation: Clear API contracts
✓ Validation: Type safety and constraints
✓ Maintenance: Decouple API from database

Use DTOs in ALL API projects!
```

## Key Takeaways

1. ✅ **Use DTOs (Data Transfer Objects)** - Separate input/output models from database models
2. ✅ **Allowlist properties** - Only expose/accept explicitly defined fields
3. ✅ **Separate read/write schemas** - Different properties for GET vs PUT/POST
4. ✅ **Role-based field filtering** - Admins see more fields than regular users
5. ✅ **Never trust client input** - Validate and filter all incoming properties
6. ✅ **Use property-level decorators** - Mark fields as read-only, write-only, admin-only
7. ✅ **Implement field-level authorization** - Check permissions per property
8. ✅ **Test with different roles** - Verify field visibility for each user type
9. ✅ **Log sensitive field access** - Monitor who accesses salary, SSN, etc.
10. ✅ **Review serializers regularly** - Audit exposed fields as models evolve

## What's Next?

- **[Attack Vectors](./attack-vectors.md)**: Learn how attackers exploit property-level authorization flaws
- **[Prevention](./prevention.md)**: Best practices and secure coding patterns for property-level security
- **[Examples](./examples.md)**: Code examples showing vulnerable vs secure implementations
- **[Lab](./lab/api03-mass-assignment-lab/)**: Hands-on practice with mass assignment and excessive data exposure

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
