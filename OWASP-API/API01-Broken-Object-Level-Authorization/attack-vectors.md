# API01: Broken Object Level Authorization - Attack Vectors

## Table of Contents
- [Understanding BOLA Attack Vectors](#understanding-bola-attack-vectors)
- [Common Attack Patterns](#common-attack-patterns)
- [Application Flaws That Enable Attacks](#application-flaws-that-enable-attacks)
- [Signs and Symptoms of Vulnerability](#signs-and-symptoms-of-vulnerability)
- [What Attackers Look For](#what-attackers-look-for)
- [Detection Techniques](#detection-techniques)

## Understanding BOLA Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY**  
> This document describes attack concepts at a high level for educational purposes. No exploit code or weaponizable techniques are provided. Understanding these patterns helps developers build better defenses.

An **attack vector** for BOLA is the method attackers use to access objects they shouldn't have permission to view or modify. The fundamental pattern is simple: identify object identifiers and attempt to access objects belonging to other users.

### The Core Attack Flow

```
1. Legitimate Access
   ↓
   User logs in → Receives token
   ↓
   Accesses own resource: GET /api/orders/5827
   ↓
   Observes response contains order_id

2. Attack Attempt
   ↓
   Modifies request: GET /api/orders/5828
   ↓
   If authorization missing → Access to other user's order
   ↓
   Iterates through IDs → Data enumeration
```

## Common Attack Patterns

### 1. Sequential ID Enumeration

**What it is**: Systematically iterating through sequential object identifiers.

**Conceptual Flow**:
```
User discovers their profile: /api/users/1523
↓
Tests sequential IDs:
  /api/users/1524 → Success (another user's profile)
  /api/users/1525 → Success
  /api/users/1526 → Success
↓
Automated iteration: 1 to 50000
↓
Result: Entire user database scraped
```

**Why It Works**:
- Many systems use auto-incrementing primary keys
- No gap between authentication (✓) and object authorization (✗)
- Easy to automate with simple scripts

**Indicators in Your API**:
- Sequential numeric IDs in responses
- Predictable patterns (1, 2, 3 or 1000, 1001, 1002)
- Consistent increments between created objects

### 2. UUID/GUID Manipulation

**What it is**: Exploiting leaked or predictable UUIDs.

**Conceptual Flow**:
```
User receives: /api/documents/a3f2b1c4-5d6e-7f8g-9h0i-j1k2l3m4n5o6
↓
UUID seems random, BUT:
  - Appears in email notifications
  - Leaked in referrer headers
  - Visible in shared links
  - Found in public API responses
↓
Attacker collects UUIDs from various sources
↓
Tests collected UUIDs → Unauthorized access
```

**Why It Works**:
- UUIDs prevent enumeration but NOT authorization
- Developers assume "hard to guess = secure"
- UUIDs often leak through legitimate channels
- No ownership validation implemented

**Common UUID Leak Sources**:
- Email notifications with document links
- Share functionality
- Public API endpoints
- Error messages and logs
- Analytics and tracking URLs

### 3. Nested Resource Access

**What it is**: Exploiting hierarchical API endpoints without proper authorization at each level.

**Conceptual Flow**:
```
Legitimate: GET /api/users/123/orders/456
             ↓           ↓
          User ID    Order ID
↓
Attack attempts:
  GET /api/users/999/orders/456 → Different user's orders?
  GET /api/users/123/orders/999 → Different order number?
↓
If only outer resource checked: Access granted
```

**Why It Works**:
- Developers check authorization for parent (user)
- Child resources (orders) assumed to be validated by parent check
- Each resource level needs independent validation

**Vulnerable Pattern**:
```python
# Checks user_id but not order ownership
@app.route('/api/users/<user_id>/orders/<order_id>')
def get_order(user_id, order_id):
    if int(user_id) != current_user.id:
        abort(403)
    # Assumes order belongs to user - WRONG!
    return Order.query.get(order_id)
```

### 4. Batch Operation Exploitation

**What it is**: Including unauthorized object IDs in bulk operations.

**Conceptual Flow**:
```
Legitimate batch request:
POST /api/messages/mark-read
{
  "message_ids": [101, 102, 103]  ← User's messages
}
↓
Attack includes mixed IDs:
{
  "message_ids": [101, 102, 999, 1000]  ← Includes others' messages
}
↓
If no per-object validation: All messages marked as read
```

**Why It Works**:
- Authorization checked once for the endpoint
- Individual array items not validated
- Efficiency over security in batch processing

**High-Risk Endpoints**:
- Bulk delete operations
- Batch updates
- Multi-object sharing
- Export/download multiple items

### 5. Parameter Pollution

**What it is**: Using multiple object identifiers to bypass validation.

**Conceptual Flow**:
```
Normal request: GET /api/profile?user_id=123
↓
Validated correctly
↓
Polluted request: GET /api/profile?user_id=123&user_id=456
↓
Application uses second parameter → Unauthorized access
```

**Why It Works**:
- Inconsistent parameter parsing
- First parameter validated, second used
- Framework quirks in handling duplicate parameters

### 6. Body Parameter Injection

**What it is**: Adding unauthorized object references in request bodies.

**Conceptual Flow**:
```
Legitimate update:
PUT /api/profile
{
  "name": "John Doe",
  "email": "john@example.com"
}
↓
Attack adds user_id:
{
  "name": "Hacker",
  "email": "hack@example.com",
  "user_id": 999  ← Attempting to modify different user
}
↓
If not properly validated: Updates wrong user's profile
```

**Why It Works**:
- Mass assignment vulnerabilities
- Insufficient input filtering
- Trusting client-provided context

## Application Flaws That Enable Attacks

### Flaw 1: Missing Authorization Checks

**The Problem**: No validation that user owns the requested object.

```python
# VULNERABLE
@app.route('/api/orders/<order_id>')
@require_authentication
def get_order(order_id):
    # Has valid token but can access ANY order
    return Order.query.get_or_404(order_id)
```

### Flaw 2: Incomplete Authorization Logic

**The Problem**: Authorization only for some operations.

```python
# VULNERABLE
@app.route('/api/documents/<doc_id>', methods=['GET', 'DELETE'])
@require_authentication
def handle_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    if request.method == 'DELETE':
        # DELETE is protected
        if doc.owner_id != current_user.id:
            abort(403)
        doc.delete()
    
    # GET has no authorization check!
    return doc.to_json()
```

### Flaw 3: Client-Side Filtering

**The Problem**: Relying on client to request only authorized objects.

```python
# VULNERABLE
@app.route('/api/orders')
def get_orders():
    # Returns ALL orders, expects client to filter
    # Mobile app only shows user's orders
    return Order.query.all()
```

### Flaw 4: Indirect Object References Not Validated

**The Problem**: Using intermediate objects without full validation chain.

```python
# VULNERABLE
@app.route('/api/invoices/<invoice_id>/download')
def download_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    order = Order.query.get(invoice.order_id)
    
    # Only checks order ownership, not invoice ownership
    if order.user_id != current_user.id:
        abort(403)
    
    # Attacker could create invoice for victim's order
    return generate_pdf(invoice)
```

## Signs and Symptoms of Vulnerability

### Red Flags in API Design

✗ **URL patterns with IDs**: `/api/resource/{id}`  
✗ **No ownership filtering in queries**: `SELECT * FROM orders WHERE id = ?`  
✗ **Different behavior per user not implemented**: Same query for all users  
✗ **Generic error messages**: "Not found" instead of "Forbidden"  
✗ **No audit logs for access**: Can't detect unauthorized attempts  

### Code Smells

```python
# SMELL 1: Direct ID usage without ownership check
user = User.query.get(user_id)

# SMELL 2: No user context in query
orders = Order.query.filter_by(status='pending').all()

# SMELL 3: Authorization only in UI layer
if current_user.role == 'admin':
    # Show admin button
    # But /admin endpoint not protected!

# SMELL 4: Trusting client context
requested_user = request.json.get('user_id')
```

## What Attackers Look For

### Discovery Phase

1. **API Documentation**: Swagger/OpenAPI specs revealing endpoints
2. **Mobile App Decompilation**: Extracting API endpoints and structure
3. **Proxy Traffic Analysis**: Intercepting legitimate requests
4. **Error Messages**: Verbose errors revealing system information
5. **Pattern Recognition**: Identifying ID formats and structures

### Testing Phase

Attackers systematically test:

```
✓ Change numeric IDs up/down
✓ Test UUID variations from collected samples
✓ Modify nested resource IDs independently
✓ Include extra IDs in batch operations
✓ Test both URL and body parameters
✓ Try different HTTP methods (GET, POST, PUT, DELETE, PATCH)
```

### Exploitation Indicators

**HTTP Response Codes**:
- `200 OK` with different data → Likely vulnerable
- `403 Forbidden` → Properly protected
- `404 Not Found` → Could be vulnerable (masking authorization as not found)
- `500 Internal Server Error` → Possible vulnerability, poor error handling

**Response Content**:
- Different user data returned → Confirmed BOLA
- Same data structure, different values → Confirmed vulnerability
- Error revealing authorization logic → Information leak

## Detection Techniques

### For Security Teams

**Automated Testing**:
- API fuzzing with ID mutations
- Multi-user session testing
- Automated ID enumeration (in test environment)
- Integration with CI/CD pipeline

**Manual Testing**:
- Create two test accounts (User A, User B)
- Perform action as User A, note object ID
- Attempt to access same object as User B
- Verify 403 Forbidden (not 200 OK)

**Code Review Checklist**:
- [ ] Every endpoint with object ID has authorization check
- [ ] Database queries filter by owner AND object ID
- [ ] Batch operations validate each item
- [ ] Nested resources validated at each level
- [ ] No client-provided context trusted

### For Developers

**During Development**:
```python
# Template for all object access
def access_object(object_id):
    # 1. Authenticate (already done by framework)
    # 2. Get object
    obj = Model.query.get_or_404(object_id)
    # 3. Authorize (DON'T SKIP THIS!)
    if obj.owner_id != current_user.id and not current_user.is_admin:
        abort(403)
    # 4. Return
    return obj
```

**Testing Pattern**:
```
For each API endpoint:
1. Create resource as User A
2. Note the resource ID
3. Attempt to access as User B (different account)
4. Expected: 403 Forbidden
5. If 200 OK → BOLA vulnerability found
```

## Prevention Mindset

### Secure by Default

```
Every object access must answer:
1. Is user authenticated? (Who are you?)
2. Does this object exist? (Is this real?)
3. Does user own this object? (Is it yours?)
4. Is user allowed this action? (Can you do this?)

Failing any check = Access Denied
```

### Defense in Depth

```
Layer 1: Use unpredictable IDs (UUIDs)
Layer 2: Implement rate limiting
Layer 3: Monitor access patterns
Layer 4: LOG ALL AUTHORIZATION FAILURES
Layer 5: ALWAYS VALIDATE OBJECT OWNERSHIP ← Most Critical
```

## Key Takeaways

1. **BOLA is easy to exploit** - Requires minimal technical skill
2. **Authentication ≠ Authorization** - Valid token doesn't mean valid access to all objects
3. **Every object needs validation** - No exceptions for "internal" or "trusted" APIs
4. **UUIDs are not security** - They make guessing harder but don't replace authorization
5. **Test with multiple users** - Single-user testing misses BOLA entirely
6. **Centralize authorization logic** - Scattered checks lead to gaps

## What's Next?

- **[Prevention](./prevention.md)**: Implement robust object-level authorization
- **[Examples](./examples.md)**: See vulnerable and secure code patterns
- **[Lab](./lab/api01-idor-lab/)**: Practice identifying and fixing BOLA vulnerabilities

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
