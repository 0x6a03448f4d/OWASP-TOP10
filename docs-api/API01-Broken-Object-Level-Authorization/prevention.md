# API01: Broken Object Level Authorization - Prevention

## Table of Contents
- [Core Prevention Principles](#core-prevention-principles)
- [Secure Coding Patterns for APIs](#secure-coding-patterns-for-apis)
- [Authorization Implementation Strategies](#authorization-implementation-strategies)
- [Framework-Specific Mitigations](#framework-specific-mitigations)
- [Testing and Validation](#testing-and-validation)
- [Security Checklist](#security-checklist)

## Core Prevention Principles

### 1. Implement Object-Level Authorization for Every Access

**Principle**: Always verify that the authenticated user has permission to access the specific object.

```python
# ✅ GOOD: Complete authorization check
@app.route('/api/orders/<int:order_id>')
@require_authentication
def get_order(order_id):
    # Step 1: Authentication (handled by decorator)
    # Step 2: Retrieve object
    order = Order.query.get_or_404(order_id)
    # Step 3: Object-level authorization (CRITICAL)
    if order.user_id != current_user.id and not current_user.is_admin:
        abort(403, "You don't have permission to access this order")
    # Step 4: Return data
    return jsonify(order.to_dict())

# ❌ BAD: Missing object-level check
@app.route('/api/orders/<int:order_id>')
@require_authentication
def get_order(order_id):
    # Authentication present but no authorization!
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())
```

### 2. Use Database-Level Filtering

**Principle**: Enforce ownership in database queries, not after fetching.

```python
# ✅ GOOD: Filter by ownership in query
@app.route('/api/orders/<int:order_id>')
@require_authentication
def get_order(order_id):
    # Query ensures user can only get their own orders
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id
    ).first_or_404()
    return jsonify(order.to_dict())

# ✅ ALSO GOOD: Using SQLAlchemy relationship
@app.route('/api/orders/<int:order_id>')
@require_authentication
def get_order(order_id):
    # Automatically filters by relationship
    order = current_user.orders.filter_by(id=order_id).first_or_404()
    return jsonify(order.to_dict())

# ❌ BAD: Fetch first, check later
@app.route('/api/orders/<int:order_id>')
@require_authentication
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    # Information already leaked in timing
    if order.user_id != current_user.id:
        abort(403)
    return jsonify(order.to_dict())
```

### 3. Centralize Authorization Logic

**Principle**: Use a consistent, centralized mechanism for all authorization checks.

```python
# ✅ GOOD: Centralized authorization service
class AuthorizationService:
    @staticmethod
    def can_access_order(user, order_id):
        """Centralized authorization logic"""
        order = Order.query.get(order_id)
        if not order:
            return False, None
        if order.user_id == user.id or user.is_admin:
            return True, order
        return False, None
    
    @staticmethod
    def can_modify_order(user, order_id):
        """Different permission levels"""
        can_access, order = AuthorizationService.can_access_order(user, order_id)
        if not can_access:
            return False, None
        # Additional checks for modification
        if order.status == 'shipped':
            return False, order
        return True, order

# Usage
@app.route('/api/orders/<int:order_id>')
@require_authentication
def get_order(order_id):
    can_access, order = AuthorizationService.can_access_order(
        current_user, 
        order_id
    )
    if not can_access:
        abort(403)
    return jsonify(order.to_dict())

@app.route('/api/orders/<int:order_id>', methods=['PUT'])
@require_authentication
def update_order(order_id):
    can_modify, order = AuthorizationService.can_modify_order(
        current_user,
        order_id
    )
    if not can_modify:
        abort(403)
    # Perform update
    order.update(request.json)
    return jsonify(order.to_dict())
```

### 4. Deny by Default

**Principle**: Start with no access; explicitly grant permissions.

```python
# ✅ GOOD: Deny by default approach
@app.route('/api/documents/<doc_id>')
@require_authentication
def get_document(doc_id):
    # Assume no access
    access_granted = False
    
    document = Document.query.get_or_404(doc_id)
    
    # Explicitly check each permission scenario
    if document.owner_id == current_user.id:
        access_granted = True
    elif document.is_public:
        access_granted = True
    elif current_user.id in document.shared_with:
        access_granted = True
    elif current_user.is_admin:
        access_granted = True
    
    if not access_granted:
        abort(403, "Access denied")
    
    return jsonify(document.to_dict())

# ❌ BAD: Allow by default
@app.route('/api/documents/<doc_id>')
@require_authentication
def get_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    
    # Only deny in specific cases (easy to miss cases)
    if document.is_private and document.owner_id != current_user.id:
        abort(403)
    
    # Accessible otherwise - dangerous!
    return jsonify(document.to_dict())
```

## Secure Coding Patterns for APIs

### Pattern 1: Decorator-Based Authorization

```python
from functools import wraps

def require_object_ownership(model_class, param_name='id', owner_field='user_id'):
    """Reusable decorator for object ownership validation"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            object_id = kwargs.get(param_name)
            obj = model_class.query.get_or_404(object_id)
            
            # Check ownership
            if getattr(obj, owner_field) != current_user.id:
                if not current_user.is_admin:
                    abort(403, "You don't own this resource")
            
            # Inject object into function
            kwargs['authorized_object'] = obj
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage
@app.route('/api/orders/<int:id>')
@require_object_ownership(Order, param_name='id', owner_field='user_id')
def get_order(id, authorized_object):
    # authorized_object is already validated
    return jsonify(authorized_object.to_dict())
```

### Pattern 2: Policy-Based Access Control

```python
class OrderPolicy:
    """Policy class for Order authorization"""
    
    @staticmethod
    def can_view(user, order):
        """Can user view this order?"""
        return (
            order.user_id == user.id or
            user.is_admin or
            user.id in order.shared_with_users
        )
    
    @staticmethod
    def can_modify(user, order):
        """Can user modify this order?"""
        if not OrderPolicy.can_view(user, order):
            return False
        # Only owner or admin can modify
        return order.user_id == user.id or user.is_admin
    
    @staticmethod
    def can_delete(user, order):
        """Can user delete this order?"""
        if order.status == 'completed':
            return False  # Completed orders can't be deleted
        return order.user_id == user.id or user.is_admin

# Usage
@app.route('/api/orders/<int:order_id>', methods=['GET', 'PUT', 'DELETE'])
@require_authentication
def handle_order(order_id):
    order = Order.query.get_or_404(order_id)
    
    if request.method == 'GET':
        if not OrderPolicy.can_view(current_user, order):
            abort(403)
        return jsonify(order.to_dict())
    
    elif request.method == 'PUT':
        if not OrderPolicy.can_modify(current_user, order):
            abort(403)
        order.update(request.json)
        return jsonify(order.to_dict())
    
    elif request.method == 'DELETE':
        if not OrderPolicy.can_delete(current_user, order):
            abort(403)
        order.delete()
        return '', 204
```

### Pattern 3: Scoped Queries for List Endpoints

```python
# ✅ GOOD: Always scope to current user
@app.route('/api/orders')
@require_authentication
def list_orders():
    # Only return user's own orders
    if current_user.is_admin:
        # Admins can see all orders (if business logic allows)
        orders = Order.query.all()
    else:
        # Regular users only see their own
        orders = Order.query.filter_by(user_id=current_user.id).all()
    
    return jsonify([order.to_dict() for order in orders])

# ❌ BAD: Return all, expect client to filter
@app.route('/api/orders')
@require_authentication
def list_orders():
    # Returns ALL orders - client must filter
    # Leaks information about other users' orders
    orders = Order.query.all()
    return jsonify([order.to_dict() for order in orders])
```

### Pattern 4: Validate Each Item in Batch Operations

```python
# ✅ GOOD: Validate every item in batch
@app.route('/api/messages/delete', methods=['POST'])
@require_authentication
def delete_messages():
    message_ids = request.json.get('message_ids', [])
    
    # Validate each message ID
    deleted_count = 0
    for msg_id in message_ids:
        message = Message.query.get(msg_id)
        
        # Skip if not found or not owned by user
        if not message or message.user_id != current_user.id:
            continue
        
        message.delete()
        deleted_count += 1
    
    return jsonify({
        'deleted': deleted_count,
        'requested': len(message_ids)
    })

# ❌ BAD: Batch delete without individual validation
@app.route('/api/messages/delete', methods=['POST'])
@require_authentication
def delete_messages():
    message_ids = request.json.get('message_ids', [])
    
    # Deletes all provided IDs without checking ownership!
    Message.query.filter(Message.id.in_(message_ids)).delete()
    
    return jsonify({'deleted': len(message_ids)})
```

### Pattern 5: Validate Nested Resources Independently

```python
# ✅ GOOD: Validate both parent and child
@app.route('/api/users/<int:user_id>/orders/<int:order_id>')
@require_authentication
def get_user_order(user_id, order_id):
    # Validate user access
    if user_id != current_user.id and not current_user.is_admin:
        abort(403, "Cannot access other users' data")
    
    # Validate order belongs to user (double-check)
    order = Order.query.filter_by(
        id=order_id,
        user_id=user_id
    ).first_or_404()
    
    return jsonify(order.to_dict())

# ❌ BAD: Only validate parent
@app.route('/api/users/<int:user_id>/orders/<int:order_id>')
@require_authentication
def get_user_order(user_id, order_id):
    # Only checks user_id
    if user_id != current_user.id:
        abort(403)
    
    # Assumes order belongs to user - WRONG!
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())
```

## Authorization Implementation Strategies

### Strategy 1: Use Unpredictable Resource Identifiers

```python
import uuid

class Order(db.Model):
    # Use UUID instead of sequential integers
    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # ... other fields

# Still need authorization checks!
# UUIDs make enumeration harder but don't replace authorization
```

### Strategy 2: Implement Access Control Lists (ACLs)

```python
class DocumentACL(db.Model):
    """Access Control List for documents"""
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    permission = db.Column(db.String(20))  # 'read', 'write', 'admin'

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def user_has_permission(self, user, required_permission):
        """Check if user has specific permission"""
        # Owner has all permissions
        if self.owner_id == user.id:
            return True
        
        # Check ACL
        acl = DocumentACL.query.filter_by(
            document_id=self.id,
            user_id=user.id
        ).first()
        
        if not acl:
            return False
        
        # Permission hierarchy
        permissions = ['read', 'write', 'admin']
        user_level = permissions.index(acl.permission)
        required_level = permissions.index(required_permission)
        
        return user_level >= required_level

# Usage
@app.route('/api/documents/<int:doc_id>')
@require_authentication
def get_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    if not doc.user_has_permission(current_user, 'read'):
        abort(403)
    
    return jsonify(doc.to_dict())
```

### Strategy 3: Attribute-Based Access Control (ABAC)

```python
class AccessControl:
    """Attribute-based access control"""
    
    @staticmethod
    def evaluate(user, resource, action, context=None):
        """
        Evaluate access based on:
        - User attributes (role, department, clearance)
        - Resource attributes (sensitivity, owner, type)
        - Action (read, write, delete)
        - Context (time, location, IP)
        """
        rules = [
            # Owner can do anything
            lambda: resource.owner_id == user.id,
            
            # Admin can read anything
            lambda: user.is_admin and action == 'read',
            
            # Same department can read non-sensitive
            lambda: (
                user.department == resource.department and
                resource.sensitivity != 'high' and
                action == 'read'
            ),
            
            # Manager can read team resources
            lambda: (
                user.role == 'manager' and
                user.team_id == resource.team_id and
                action in ['read', 'write']
            ),
        ]
        
        # Any matching rule grants access
        return any(rule() for rule in rules)

# Usage
@app.route('/api/files/<int:file_id>', methods=['GET', 'PUT', 'DELETE'])
@require_authentication
def handle_file(file_id):
    file = File.query.get_or_404(file_id)
    
    action_map = {'GET': 'read', 'PUT': 'write', 'DELETE': 'delete'}
    action = action_map[request.method]
    
    if not AccessControl.evaluate(current_user, file, action):
        abort(403)
    
    # Process request based on method
    # ...
```

## Framework-Specific Mitigations

### Flask with Flask-Login

```python
from flask_login import current_user, login_required

@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id
    ).first_or_404()
    return jsonify(order.to_dict())
```

### Django REST Framework

```python
from rest_framework import viewsets, permissions

class IsOwnerOrAdmin(permissions.BasePermission):
    """Custom permission: owner or admin only"""
    
    def has_object_permission(self, request, view, obj):
        return (
            obj.user == request.user or
            request.user.is_staff
        )

class OrderViewSet(viewsets.ModelViewSet):
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    
    def get_queryset(self):
        # Scope to current user
        if self.request.user.is_staff:
            return Order.objects.all()
        return Order.objects.filter(user=self.request.user)
```

### Express.js (Node.js)

```javascript
// Middleware for ownership validation
const requireOwnership = (Model, paramName = 'id') => {
  return async (req, res, next) => {
    try {
      const objectId = req.params[paramName];
      const object = await Model.findById(objectId);
      
      if (!object) {
        return res.status(404).json({ error: 'Not found' });
      }
      
      // Check ownership
      if (object.userId.toString() !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      
      // Attach to request
      req.authorizedObject = object;
      next();
    } catch (error) {
      next(error);
    }
  };
};

// Usage
app.get('/api/orders/:id',
  authenticate,
  requireOwnership(Order, 'id'),
  (req, res) => {
    res.json(req.authorizedObject);
  }
);
```

## Testing and Validation

### Unit Testing Authorization

```python
import unittest

class TestOrderAuthorization(unittest.TestCase):
    def setUp(self):
        self.user1 = create_user('user1')
        self.user2 = create_user('user2')
        self.admin = create_user('admin', is_admin=True)
        self.order1 = create_order(owner=self.user1)
    
    def test_owner_can_access_own_order(self):
        """Owner should access their own order"""
        with app.test_client() as client:
            login(client, self.user1)
            response = client.get(f'/api/orders/{self.order1.id}')
            self.assertEqual(response.status_code, 200)
    
    def test_other_user_cannot_access_order(self):
        """Non-owner should be denied access"""
        with app.test_client() as client:
            login(client, self.user2)
            response = client.get(f'/api/orders/{self.order1.id}')
            self.assertEqual(response.status_code, 403)
    
    def test_admin_can_access_any_order(self):
        """Admin should access any order"""
        with app.test_client() as client:
            login(client, self.admin)
            response = client.get(f'/api/orders/{self.order1.id}')
            self.assertEqual(response.status_code, 200)
```

### Integration Testing

```python
def test_bola_prevention():
    """Test BOLA prevention across API"""
    # Create two users
    alice = create_test_user('alice')
    bob = create_test_user('bob')
    
    # Alice creates a resource
    alice_token = get_auth_token(alice)
    response = requests.post(
        'http://localhost:5000/api/documents',
        headers={'Authorization': f'Bearer {alice_token}'},
        json={'title': 'Alice Document'}
    )
    alice_doc_id = response.json()['id']
    
    # Bob tries to access Alice's document
    bob_token = get_auth_token(bob)
    response = requests.get(
        f'http://localhost:5000/api/documents/{alice_doc_id}',
        headers={'Authorization': f'Bearer {bob_token}'}
    )
    
    # Should be forbidden
    assert response.status_code == 403, "BOLA vulnerability detected!"
```

## Security Checklist

### Development Phase
- [ ] Every endpoint with object ID has authorization check
- [ ] Database queries filter by owner_id AND object_id
- [ ] Centralized authorization logic implemented
- [ ] Batch operations validate each item individually
- [ ] Nested resources validated at each level
- [ ] No client-provided ownership context trusted
- [ ] UUID/non-sequential IDs used (defense in depth)

### Code Review Phase
- [ ] All routes reviewed for object-level authorization
- [ ] No direct trust of request parameters for ownership
- [ ] Authorization decorators/middleware consistently applied
- [ ] List endpoints scoped to current user
- [ ] Proper error codes (403 vs 404) used correctly

### Testing Phase
- [ ] Multi-user testing performed (User A cannot access User B's data)
- [ ] Automated BOLA tests in CI/CD pipeline
- [ ] Attempted ID enumeration blocked
- [ ] Batch operations tested with mixed ownership
- [ ] Admin vs regular user access tested

### Monitoring Phase
- [ ] Authorization failures logged
- [ ] Anomaly detection for access patterns
- [ ] Alerts for repeated 403 errors
- [ ] Regular security audits scheduled

## Key Takeaways

1. ✅ **Always validate object ownership** - Never skip this step
2. ✅ **Filter at database level** - Use queries that include user context
3. ✅ **Centralize authorization** - Consistent, reusable logic
4. ✅ **Validate each item in batch operations** - No shortcuts
5. ✅ **Test with multiple users** - Single-user testing misses BOLA
6. ✅ **Use proper HTTP status codes** - 403 for forbidden, 404 carefully
7. ✅ **Deny by default** - Explicit permission grants only

## What's Next?

- **[Examples](./examples.md)**: See more code examples and patterns
- **[Lab](./lab/api01-idor-lab/)**: Practice fixing BOLA vulnerabilities
- **[Overview](./overview.md)**: Review BOLA fundamentals

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
