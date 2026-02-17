# Lab Instructions: API01 BOLA - IDOR Order Access

## Introduction

Welcome to the BOLA (Broken Object Level Authorization) lab! In this hands-on exercise, you'll discover how APIs can expose sensitive data when they fail to verify that users can only access their own resources.

**Time Required**: 30-45 minutes  
**Difficulty**: Beginner to Intermediate

## Learning Path

This lab follows a structured approach:
1. **Setup** - Get the lab running
2. **Explore** - Understand the API as a normal user
3. **Discover** - Find the BOLA vulnerability
4. **Exploit** - Safely demonstrate the security flaw
5. **Understand** - Learn why this is dangerous
6. **Fix** - Implement proper authorization
7. **Verify** - Test that the fix works

---

## Part 1: Setup and Initial Exploration (10 minutes)

### Task 1.1: Start the Lab

```bash
# Navigate to the lab directory
cd OWASP-API/API01-Broken-Object-Level-Authorization/lab/api01-idor-lab/

# Start the application
docker-compose up
```

**Expected Output**:
```
✓ API running on http://localhost:5000
✓ Educational BOLA/IDOR demonstration
✓ Safe isolated environment
```

### Task 1.2: Access the Web Interface

1. Open your browser to **http://localhost:5000**
2. You should see a simple API testing interface
3. Observe the available functionality:
   - Login form
   - Order lookup
   - API response display

### Task 1.3: Login as Alice

1. In the login form, enter:
   - **Username**: `alice`
   - **Password**: `password123`
2. Click **Login**
3. Observe:
   - A JWT token is displayed
   - Your user information is shown
   - Your orders are listed (orders #101 and #102)

**Questions to Consider**:
- What information is included in your user profile?
- How many orders does Alice have?
- What details are shown for each order?

---

## Part 2: Discovering the BOLA Vulnerability (10 minutes)

### Task 2.1: View Your Own Orders

While logged in as Alice:

1. Click on **Order #101** 
2. Observe the order details displayed
3. Note the URL or API endpoint being called
4. Look at the API response in the interface

**Expected Response**:
```json
{
  "order_id": 101,
  "user_id": 1,
  "username": "alice",
  "items": ["Laptop", "Mouse"],
  "total": 1299.99,
  "status": "Delivered"
}
```

### Task 2.2: Test with Different Order IDs

Now try accessing orders that don't belong to Alice:

1. In the "Get Order by ID" field, enter: `201`
2. Click **Get Order**
3. Observe what happens

**Expected Result**: You should see Bob's order details!

```json
{
  "order_id": 201,
  "user_id": 2,
  "username": "bob",
  "items": ["Phone", "Charger"],
  "total": 899.99,
  "status": "Shipped"
}
```

**❗ VULNERABILITY CONFIRMED**: Alice can access Bob's order!

### Task 2.3: Enumerate More Orders

Try accessing other order IDs:
- Order #202 (Bob's second order)
- Order #301 (Charlie's order)
- Order #302 (Charlie's second order)

**Questions**:
- Can you access all orders?
- What sensitive information is exposed?
- Are the order IDs predictable?

### Task 2.4: Test with Another User

1. Click **Logout**
2. Login as **Bob** (username: `bob`, password: `password123`)
3. Try accessing order #101 (Alice's order)
4. Confirm Bob can also access Alice's orders

**Impact Assessment**:
- Any authenticated user can access any order
- Users can see other users' purchase history
- Private information (addresses, totals) is exposed

---

## Part 3: Understanding the Vulnerability (10 minutes)

### Task 3.1: Review the Vulnerable Code

Open `app/server.py` and locate the `/api/orders/<order_id>` endpoint:

```python
@app.route('/api/orders/<int:order_id>')
@jwt_required()
def get_order(order_id):
    """
    VULNERABILITY: Returns any order without checking ownership!
    
    The user IS authenticated (we check the JWT token)
    But we DON'T verify the order belongs to this user
    """
    if order_id not in orders:
        return jsonify({'error': 'Order not found'}), 404
    
    # VULNERABLE: No authorization check here!
    return jsonify(orders[order_id])
```

**Identify the Problems**:
1. ✅ Authentication is present (`@jwt_required()` decorator)
2. ❌ Authorization is MISSING (no ownership check)
3. ❌ Trusts the client-provided order_id parameter
4. ❌ Returns any order that exists

### Task 3.2: Compare with Secure Endpoint

Find the `/api/orders` endpoint (without ID parameter):

```python
@app.route('/api/orders')
@jwt_required()
def get_user_orders():
    """
    SECURE: Only returns orders belonging to the authenticated user
    """
    current_user_id = get_jwt_identity()
    
    # Filter orders by user ownership
    user_orders = [
        order for order in orders.values() 
        if order['user_id'] == current_user_id
    ]
    
    return jsonify(user_orders)
```

**Key Difference**:
- Gets user ID from JWT token (`get_jwt_identity()`)
- Filters results to only show user's orders
- Never trusts client-provided user/order relationship

### Task 3.3: Understand the Attack Vector

The attack flow:

```
1. Attacker logs in (valid authentication) ✓
   → Receives JWT token

2. Attacker accesses their own order
   GET /api/orders/101
   → Works as expected ✓

3. Attacker modifies order ID
   GET /api/orders/201
   → Server returns Bob's order ✗ VULNERABILITY

4. Attacker enumerates all orders
   GET /api/orders/101, 102, 201, 202, 301, 302...
   → Collects all customer data ✗ DATA BREACH
```

### Task 3.4: Real-World Impact

In a production scenario, this could lead to:

- 🔴 **Privacy Breach**: Access to personal information
- 🔴 **Data Theft**: Competitor analysis, customer lists
- 🔴 **Financial Loss**: Exposed payment amounts, pricing
- 🔴 **Compliance Violations**: GDPR, CCPA, PCI-DSS fines
- 🔴 **Reputation Damage**: Loss of customer trust
- 🔴 **Legal Liability**: Lawsuits from affected customers

**Real Examples**:
- 2019: First American Financial leaked 885 million records via IDOR
- 2020: Various apps exposed user data through similar vulnerabilities
- Common in bug bounty programs (often rated as High/Critical)

---

## Part 4: Fixing the Vulnerability (10 minutes)

### Task 4.1: Implement Authorization Check

Edit `app/server.py` and modify the vulnerable endpoint:

**BEFORE (Vulnerable)**:
```python
@app.route('/api/orders/<int:order_id>')
@jwt_required()
def get_order(order_id):
    if order_id not in orders:
        return jsonify({'error': 'Order not found'}), 404
    
    return jsonify(orders[order_id])
```

**AFTER (Secure)**:
```python
@app.route('/api/orders/<int:order_id>')
@jwt_required()
def get_order(order_id):
    # Get the authenticated user's ID from JWT
    current_user_id = get_jwt_identity()
    
    # Check if order exists
    if order_id not in orders:
        return jsonify({'error': 'Order not found'}), 404
    
    order = orders[order_id]
    
    # CRITICAL: Verify the order belongs to the authenticated user
    if order['user_id'] != current_user_id:
        # Return 404 to not reveal order existence
        return jsonify({'error': 'Order not found'}), 404
    
    return jsonify(order)
```

**Key Changes**:
1. Get current user ID from JWT: `get_jwt_identity()`
2. Verify ownership: `order['user_id'] != current_user_id`
3. Return 404 (not 403) to avoid information leakage

### Task 4.2: Alternative Implementation with Database Query

For production code with a real database:

```python
@app.route('/api/orders/<int:order_id>')
@jwt_required()
def get_order(order_id):
    current_user_id = get_jwt_identity()
    
    # Query with ownership filter built-in
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user_id
    ).first()
    
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    return jsonify(order.to_dict())
```

**Benefits**:
- Single database query
- Ownership check is implicit in the query
- Prevents timing attacks
- More efficient

### Task 4.3: Restart and Test

```bash
# Stop the current container (Ctrl+C)

# Rebuild and restart
docker-compose up --build
```

---

## Part 5: Verification Testing (10 minutes)

### Task 5.1: Test as Alice (Legitimate Access)

1. Login as **alice**
2. Try accessing order #101 (your own order)
3. Try accessing order #102 (your own order)

**Expected Result**: Both should work ✓

### Task 5.2: Test Unauthorized Access

Still logged in as Alice:

1. Try accessing order #201 (Bob's order)
2. Try accessing order #301 (Charlie's order)

**Expected Result**: Both should return "Order not found" ✗

### Task 5.3: Test as Bob

1. Logout
2. Login as **bob**
3. Try accessing order #201 (Bob's own order)
4. Try accessing order #101 (Alice's order)

**Expected Results**:
- Order #201: ✓ Success (Bob's order)
- Order #101: ✗ Error "Order not found" (Alice's order)

### Task 5.4: Verify API Responses

Check the HTTP status codes:

```bash
# Login as Alice
TOKEN="<alice-token>"

# Alice's order (should succeed - 200 OK)
curl -i http://localhost:5000/api/orders/101 \
  -H "Authorization: Bearer $TOKEN"

# Bob's order (should fail - 404 Not Found)
curl -i http://localhost:5000/api/orders/201 \
  -H "Authorization: Bearer $TOKEN"
```

**Correct Behavior**:
- Own orders: `200 OK`
- Other users' orders: `404 Not Found` (not 403 Forbidden!)

### Task 5.5: Why 404 Instead of 403?

**Using 404**:
```
GET /api/orders/999
→ 404 Not Found
(Attacker doesn't know if order 999 exists)
```

**Using 403**:
```
GET /api/orders/999
→ 403 Forbidden
(Reveals order exists but access denied - information leak!)
```

**Best Practice**: Return 404 to avoid confirming resource existence.

---

## Part 6: Additional Challenges (Optional)

### Challenge 1: Create a Reusable Authorization Decorator

Create a decorator for resource ownership checks:

```python
from functools import wraps

def require_order_ownership(f):
    """Decorator to verify user owns the requested order"""
    @wraps(f)
    def decorated_function(order_id, *args, **kwargs):
        current_user_id = get_jwt_identity()
        
        if order_id not in orders:
            return jsonify({'error': 'Order not found'}), 404
        
        if orders[order_id]['user_id'] != current_user_id:
            return jsonify({'error': 'Order not found'}), 404
        
        return f(order_id, *args, **kwargs)
    
    return decorated_function

# Usage
@app.route('/api/orders/<int:order_id>')
@jwt_required()
@require_order_ownership
def get_order(order_id):
    return jsonify(orders[order_id])
```

### Challenge 2: Add Audit Logging

Log all access attempts (successful and failed):

```python
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/api/orders/<int:order_id>')
@jwt_required()
def get_order(order_id):
    current_user_id = get_jwt_identity()
    
    if order_id not in orders:
        return jsonify({'error': 'Order not found'}), 404
    
    order = orders[order_id]
    
    if order['user_id'] != current_user_id:
        # Log unauthorized access attempt
        logger.warning(
            f"Unauthorized access attempt: "
            f"User {current_user_id} tried to access order {order_id} "
            f"belonging to user {order['user_id']}"
        )
        return jsonify({'error': 'Order not found'}), 404
    
    # Log successful access
    logger.info(f"User {current_user_id} accessed order {order_id}")
    
    return jsonify(order)
```

### Challenge 3: Use UUIDs Instead of Sequential IDs

Replace predictable IDs with UUIDs:

```python
import uuid

# Instead of:
orders = {
    101: {'order_id': 101, 'user_id': 1, ...},
    102: {'order_id': 102, 'user_id': 1, ...},
}

# Use:
orders = {
    'a7f3b2c1-9d4e-4f6a-8b2c-1e3d4f5a6b7c': {
        'order_id': 'a7f3b2c1-9d4e-4f6a-8b2c-1e3d4f5a6b7c',
        'user_id': 1,
        ...
    },
}
```

**Benefits**:
- Non-sequential IDs
- Harder to enumerate
- Industry standard practice

**Note**: UUIDs alone are NOT security - still need authorization!

### Challenge 4: Rate Limiting for Enumeration Prevention

Add rate limiting to prevent automated enumeration:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/orders/<int:order_id>')
@jwt_required()
@limiter.limit("10 per minute")
def get_order(order_id):
    # Implementation here
    pass
```

---

## Key Takeaways

### What You Learned

✅ **Authentication ≠ Authorization** - Being logged in doesn't mean you can access everything  
✅ **Always verify ownership** - Check that the resource belongs to the authenticated user  
✅ **Never trust client input** - Including IDs in URLs or request bodies  
✅ **Defense in depth** - Use UUIDs, rate limiting, logging, AND authorization  
✅ **Information disclosure** - Use 404 instead of 403 to avoid revealing resource existence  

### BOLA Prevention Checklist

- [ ] Verify user ownership for every object access
- [ ] Use user ID from authentication token (not from request)
- [ ] Implement authorization checks server-side
- [ ] Use object-level access control for all CRUD operations
- [ ] Consider using UUIDs instead of sequential IDs
- [ ] Log authorization failures
- [ ] Return 404 for unauthorized access (not 403)
- [ ] Test with multiple user accounts
- [ ] Review all API endpoints for BOLA

### Common Mistakes to Avoid

❌ Assuming authentication is sufficient  
❌ Trusting client-provided user/object relationships  
❌ Only protecting the UI (not the API)  
❌ Using predictable sequential IDs  
❌ Forgetting to check authorization on updates/deletes  
❌ Not testing with different user accounts  
❌ Returning 403 (reveals object existence)  

---

## Clean Up

When you're done with the lab:

```bash
# Stop the containers
docker-compose down

# Remove volumes (optional)
docker-compose down -v
```

---

## Questions for Reflection

1. **Why is authentication not enough?** What's the difference between authentication and authorization?

2. **What makes BOLA the #1 API vulnerability?** Why is it so common?

3. **How would you test for BOLA in a production API?** What testing strategy would you use?

4. **What other resources might have BOLA vulnerabilities?** (Think: comments, documents, messages, accounts...)

5. **How can you make authorization checks consistent?** What patterns help prevent BOLA?

---

## Additional Resources

- [OWASP API Security Top 10 - API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PortSwigger: Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
- [HackerOne IDOR Reports](https://hackerone.com/reports?query=type%3Aidor)
- [REST API Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)

---

## Next Steps

1. ✅ Review the **[Prevention Guide](../../prevention.md)** for more best practices
2. ✅ Study the **[Examples](../../examples.md)** for additional API patterns
3. ✅ Apply BOLA prevention to your own APIs
4. ✅ Explore other OWASP API Security Top 10 vulnerabilities

---

**Congratulations!** You've completed the BOLA/IDOR lab. You now understand one of the most critical API security vulnerabilities and how to prevent it.

*Part of the [OWASP API Security Top 10 Educational Repository](../../../../README.md)*
