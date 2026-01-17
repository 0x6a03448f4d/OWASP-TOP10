# Broken Object Level Authorization (BOLA) - API Examples

## Table of Contents
- [Safe Pseudo-Code Examples](#safe-pseudo-code-examples)
- [Bad vs Good Code Comparisons](#bad-vs-good-code-comparisons)
- [API-Specific Patterns](#api-specific-patterns)
- [GraphQL Examples](#graphql-examples)
- [Real-World API Scenarios](#real-world-api-scenarios)

## Safe Pseudo-Code Examples

These examples demonstrate BOLA vulnerabilities specifically in API contexts without providing exploitable code.

### Example 1: REST API - User Order Access

**❌ VULNERABLE: No Ownership Check**
```python
@app.route('/api/orders/<order_id>')
def get_order(order_id):
    """Anyone can access any order by changing the order_id"""
    order = database.get_order(order_id)
    return jsonify(order.to_dict())
```

**✅ SECURE: Verify Ownership**
```python
@app.route('/api/orders/<order_id>')
@jwt_required()
def get_order(order_id):
    """Only the owner can access their order"""
    current_user_id = get_jwt_identity()
    
    # Get order and verify ownership in one query
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user_id
    ).first()
    
    if not order:
        # Don't reveal if order exists for other users
        return jsonify({'error': 'Order not found'}), 404
    
    return jsonify(order.to_dict())
```

### Example 2: REST API - Document Download

**❌ VULNERABLE: Direct Object Access**
```python
@app.route('/api/documents/<doc_id>/download')
def download_document(doc_id):
    """Any authenticated user can download any document"""
    document = Document.query.get_or_404(doc_id)
    return send_file(document.file_path)
```

**✅ SECURE: Ownership and Permission Check**
```python
@app.route('/api/documents/<doc_id>/download')
@jwt_required()
def download_document(doc_id):
    """Verify user has permission to access this document"""
    current_user_id = get_jwt_identity()
    document = Document.query.get_or_404(doc_id)
    
    # Check if user owns the document or has been granted access
    has_access = (
        document.owner_id == current_user_id or
        current_user_id in document.shared_with_user_ids or
        document.is_public
    )
    
    if not has_access:
        return jsonify({'error': 'Access denied'}), 403
    
    # Log access for audit trail
    log_document_access(current_user_id, doc_id)
    
    return send_file(document.file_path)
```

### Example 3: REST API - Update User Profile

**❌ VULNERABLE: Client Specifies User ID**
```python
@app.route('/api/users/<user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """User can update any profile by changing user_id"""
    data = request.json
    user = User.query.get_or_404(user_id)
    
    # VULNERABLE: No check that user_id matches authenticated user
    user.email = data.get('email')
    user.phone = data.get('phone')
    db.session.commit()
    
    return jsonify({'message': 'User updated'})
```

**✅ SECURE: Use Authenticated User ID**
```python
@app.route('/api/users/me', methods=['PUT'])
@jwt_required()
def update_current_user():
    """Users can only update their own profile"""
    current_user_id = get_jwt_identity()
    user = User.query.get_or_404(current_user_id)
    
    data = request.json
    
    # Whitelist allowed fields
    allowed_fields = ['email', 'phone', 'address']
    for field in allowed_fields:
        if field in data:
            setattr(user, field, data[field])
    
    db.session.commit()
    return jsonify({'message': 'Profile updated'})
```

### Example 4: REST API - Delete Comment

**❌ VULNERABLE: Missing Authorization**
```python
@app.route('/api/comments/<comment_id>', methods=['DELETE'])
@jwt_required()
def delete_comment(comment_id):
    """Any authenticated user can delete any comment"""
    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    
    return jsonify({'message': 'Comment deleted'}), 200
```

**✅ SECURE: Verify Ownership**
```python
@app.route('/api/comments/<comment_id>', methods=['DELETE'])
@jwt_required()
def delete_comment(comment_id):
    """Only comment owner or moderator can delete"""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    comment = Comment.query.get_or_404(comment_id)
    
    # Check ownership or moderator role
    if comment.user_id != current_user_id and not current_user.is_moderator:
        return jsonify({'error': 'You can only delete your own comments'}), 403
    
    db.session.delete(comment)
    db.session.commit()
    
    # Audit log
    log_action('comment_deleted', user_id=current_user_id, comment_id=comment_id)
    
    return jsonify({'message': 'Comment deleted'}), 200
```

## Bad vs Good Code Comparisons

### Comparison 1: API Invoice Access

**❌ BAD**
```python
@app.route('/api/invoices/<invoice_id>')
@jwt_required()
def get_invoice(invoice_id):
    # Problem: No ownership verification
    # Problem: Predictable sequential IDs
    # Problem: Returns full invoice to anyone
    invoice = Invoice.query.get_or_404(invoice_id)
    return jsonify(invoice.to_dict())
```

**✅ GOOD**
```python
from uuid import uuid4

@app.route('/api/invoices/<invoice_uuid>')
@jwt_required()
def get_invoice(invoice_uuid):
    current_user_id = get_jwt_identity()
    
    # Use UUIDs instead of sequential IDs
    invoice = Invoice.query.filter_by(
        uuid=invoice_uuid,
        user_id=current_user_id
    ).first()
    
    if not invoice:
        return jsonify({'error': 'Invoice not found'}), 404
    
    return jsonify(invoice.to_dict())
```

### Comparison 2: API Batch Operations

**❌ BAD**
```python
@app.route('/api/orders/batch-delete', methods=['POST'])
@jwt_required()
def batch_delete_orders():
    # Problem: Accepts any order IDs without verification
    order_ids = request.json.get('order_ids', [])
    
    for order_id in order_ids:
        order = Order.query.get(order_id)
        if order:
            db.session.delete(order)
    
    db.session.commit()
    return jsonify({'message': f'{len(order_ids)} orders deleted'})
```

**✅ GOOD**
```python
@app.route('/api/orders/batch-delete', methods=['POST'])
@jwt_required()
def batch_delete_orders():
    current_user_id = get_jwt_identity()
    order_ids = request.json.get('order_ids', [])
    
    # Only delete orders that belong to current user
    orders = Order.query.filter(
        Order.id.in_(order_ids),
        Order.user_id == current_user_id
    ).all()
    
    deleted_count = len(orders)
    for order in orders:
        db.session.delete(order)
    
    db.session.commit()
    
    return jsonify({
        'message': f'{deleted_count} orders deleted',
        'deleted_count': deleted_count
    })
```

### Comparison 3: API Nested Resources

**❌ BAD**
```python
@app.route('/api/accounts/<account_id>/transactions/<transaction_id>')
@jwt_required()
def get_transaction(account_id, transaction_id):
    # Problem: Only checks transaction_id, ignores account_id
    # Problem: No verification that user owns the account
    transaction = Transaction.query.get_or_404(transaction_id)
    return jsonify(transaction.to_dict())
```

**✅ GOOD**
```python
@app.route('/api/accounts/<account_id>/transactions/<transaction_id>')
@jwt_required()
def get_transaction(account_id, transaction_id):
    current_user_id = get_jwt_identity()
    
    # Verify account ownership
    account = Account.query.filter_by(
        id=account_id,
        user_id=current_user_id
    ).first()
    
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    
    # Verify transaction belongs to this account
    transaction = Transaction.query.filter_by(
        id=transaction_id,
        account_id=account_id
    ).first()
    
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
    
    return jsonify(transaction.to_dict())
```

## API-Specific Patterns

### Pattern 1: Centralized Authorization Decorator

```python
from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity

def require_ownership(model_class, id_param='id'):
    """
    Decorator to verify the authenticated user owns the requested resource
    
    Usage:
        @app.route('/api/posts/<post_id>')
        @jwt_required()
        @require_ownership(Post, 'post_id')
        def get_post(post_id):
            # If we get here, user owns the post
            post = Post.query.get(post_id)
            return jsonify(post.to_dict())
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            resource_id = kwargs.get(id_param)
            
            # Query with ownership filter
            resource = model_class.query.filter_by(
                id=resource_id,
                user_id=current_user_id
            ).first()
            
            if not resource:
                return jsonify({'error': f'{model_class.__name__} not found'}), 404
            
            # Pass resource to the route function
            kwargs['resource'] = resource
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Usage example
@app.route('/api/posts/<post_id>')
@jwt_required()
@require_ownership(Post, 'post_id')
def get_post(post_id, resource):
    # resource is guaranteed to belong to current user
    return jsonify(resource.to_dict())
```

### Pattern 2: API Gateway Authorization

```python
class ResourceAccessControl:
    """Centralized API authorization logic"""
    
    @staticmethod
    def can_read(user_id, resource):
        """Check if user can read a resource"""
        return any([
            resource.user_id == user_id,
            resource.is_public,
            user_id in resource.shared_with_users,
        ])
    
    @staticmethod
    def can_write(user_id, resource):
        """Check if user can modify a resource"""
        return any([
            resource.user_id == user_id,
            user_id in resource.editors,
        ])
    
    @staticmethod
    def can_delete(user_id, resource):
        """Check if user can delete a resource"""
        return resource.user_id == user_id

# Usage in API endpoints
@app.route('/api/documents/<doc_id>', methods=['PUT'])
@jwt_required()
def update_document(doc_id):
    current_user_id = get_jwt_identity()
    document = Document.query.get_or_404(doc_id)
    
    if not ResourceAccessControl.can_write(current_user_id, document):
        return jsonify({'error': 'Access denied'}), 403
    
    # Update document
    data = request.json
    document.update(data)
    db.session.commit()
    
    return jsonify(document.to_dict())
```

### Pattern 3: Multi-Tenant API Isolation

```python
from flask import g
from functools import wraps

def tenant_context_required(f):
    """Ensure all API requests include tenant context"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # Store tenant in request context
        g.tenant_id = user.tenant_id
        
        return f(*args, **kwargs)
    return decorated_function

def apply_tenant_filter(query):
    """Automatically filter queries by tenant"""
    if hasattr(g, 'tenant_id'):
        return query.filter_by(tenant_id=g.tenant_id)
    return query

# Usage
@app.route('/api/users')
@jwt_required()
@tenant_context_required
def get_users():
    # Automatically filtered to current tenant
    query = User.query
    query = apply_tenant_filter(query)
    
    users = query.all()
    return jsonify([u.to_dict() for u in users])
```

## GraphQL Examples

### Example 1: GraphQL Query - Vulnerable

**❌ VULNERABLE: No Authorization in Resolver**
```python
# GraphQL Schema
type Order {
    id: ID!
    userId: ID!
    total: Float!
    items: [OrderItem!]!
}

type Query {
    order(id: ID!): Order
}

# Resolver - VULNERABLE
def resolve_order(root, info, id):
    # Problem: Returns any order regardless of who requests it
    return Order.query.get(id)
```

**✅ SECURE: Authorization in Resolver**
```python
def resolve_order(root, info, id):
    # Get authenticated user from context
    current_user = info.context.get('user')
    
    if not current_user:
        raise GraphQLError('Authentication required')
    
    # Query with ownership filter
    order = Order.query.filter_by(
        id=id,
        user_id=current_user.id
    ).first()
    
    if not order:
        raise GraphQLError('Order not found')
    
    return order
```

### Example 2: GraphQL Mutation - Vulnerable

**❌ VULNERABLE: No Ownership Check**
```python
type Mutation {
    deletePost(id: ID!): Boolean!
}

# Resolver - VULNERABLE
def resolve_delete_post(root, info, id):
    post = Post.query.get(id)
    if post:
        db.session.delete(post)
        db.session.commit()
        return True
    return False
```

**✅ SECURE: Verify Ownership**
```python
def resolve_delete_post(root, info, id):
    current_user = info.context.get('user')
    
    if not current_user:
        raise GraphQLError('Authentication required')
    
    post = Post.query.filter_by(
        id=id,
        user_id=current_user.id
    ).first()
    
    if not post:
        raise GraphQLError('Post not found or access denied')
    
    db.session.delete(post)
    db.session.commit()
    
    # Audit log
    log_action('post_deleted', user_id=current_user.id, post_id=id)
    
    return True
```

### Example 3: GraphQL Field-Level Authorization

```python
from graphql import GraphQLError

class AuthorizationMiddleware:
    """GraphQL middleware for field-level authorization"""
    
    def resolve(self, next, root, info, **args):
        field_name = info.field_name
        
        # Check if field requires authorization
        if hasattr(root, '_check_field_access'):
            current_user = info.context.get('user')
            
            if not root._check_field_access(field_name, current_user):
                raise GraphQLError(f'Access denied to field: {field_name}')
        
        return next(root, info, **args)

# Model with field-level access control
class User:
    def _check_field_access(self, field_name, requesting_user):
        """Control access to sensitive fields"""
        sensitive_fields = ['email', 'phone', 'ssn']
        
        if field_name in sensitive_fields:
            # Only the user themselves can see sensitive fields
            return self.id == requesting_user.id
        
        return True  # Public fields accessible to all
```

## Real-World API Scenarios

### Scenario 1: Banking API

```python
class BankingAPIAccessControl:
    """Access control for banking APIs"""
    
    @staticmethod
    def can_view_account(user_id, account):
        """Who can view an account?"""
        return any([
            account.owner_id == user_id,
            user_id in account.authorized_users,
            account.joint_owner_id == user_id,
        ])
    
    @staticmethod
    def can_transfer_from_account(user_id, account):
        """Who can make transfers?"""
        # Must be owner and account must be active
        return (
            account.owner_id == user_id and
            account.status == 'active' and
            not account.is_frozen
        )

@app.route('/api/accounts/<account_id>/transfer', methods=['POST'])
@jwt_required()
def transfer_money(account_id):
    current_user_id = get_jwt_identity()
    account = Account.query.get_or_404(account_id)
    
    # Verify user can transfer from this account
    if not BankingAPIAccessControl.can_transfer_from_account(current_user_id, account):
        # Log suspicious activity
        log_security_event('unauthorized_transfer_attempt', 
                          user_id=current_user_id, 
                          account_id=account_id)
        return jsonify({'error': 'Access denied'}), 403
    
    # Process transfer with additional security checks
    data = request.json
    result = process_transfer(account, data, current_user_id)
    
    return jsonify(result)
```

### Scenario 2: Healthcare API (HIPAA Compliance)

```python
from datetime import datetime

class HealthcareAPIAccessControl:
    """HIPAA-compliant API access control"""
    
    @staticmethod
    def can_access_patient_record(user_id, patient_record):
        """Strict access control for patient records"""
        user = User.query.get(user_id)
        
        # Log all access attempts
        log_hipaa_access_attempt(user_id, patient_record.id)
        
        # Check access permissions
        has_access = any([
            patient_record.patient_id == user_id,  # Patient themselves
            patient_record.primary_physician_id == user_id,  # Primary doctor
            user_id in patient_record.care_team_ids,  # Care team
            user.has_role('emergency') and user.is_on_duty,  # Emergency access
        ])
        
        if has_access:
            # Log successful access
            log_hipaa_access_success(user_id, patient_record.id)
        else:
            # Log denied access
            log_hipaa_access_denied(user_id, patient_record.id)
        
        return has_access

@app.route('/api/patients/<patient_id>/records/<record_id>')
@jwt_required()
def get_patient_record(patient_id, record_id):
    current_user_id = get_jwt_identity()
    
    # Verify patient exists and user has access
    record = PatientRecord.query.filter_by(
        id=record_id,
        patient_id=patient_id
    ).first_or_404()
    
    if not HealthcareAPIAccessControl.can_access_patient_record(current_user_id, record):
        return jsonify({
            'error': 'Access denied - This incident has been logged'
        }), 403
    
    # Return sanitized record based on user role
    return jsonify(record.to_dict(current_user_id))
```

### Scenario 3: Multi-Tenant SaaS API

```python
class SaaSAPIAccessControl:
    """Multi-tenant SaaS API access control"""
    
    @staticmethod
    def verify_tenant_isolation(user_id, resource):
        """Ensure cross-tenant access is prevented"""
        user = User.query.get(user_id)
        
        if user.tenant_id != resource.tenant_id:
            # Critical security violation
            log_critical_security_event(
                'cross_tenant_access_attempt',
                user_id=user_id,
                user_tenant=user.tenant_id,
                resource_tenant=resource.tenant_id
            )
            raise SecurityViolation('Cross-tenant access denied')
        
        return True
    
    @staticmethod
    def can_manage_tenant_users(user):
        """Who can manage users within a tenant?"""
        return user.has_role('tenant_admin') or user.has_role('owner')

@app.route('/api/projects/<project_id>')
@jwt_required()
def get_project(project_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    # Get project with tenant filter
    project = Project.query.filter_by(
        id=project_id,
        tenant_id=current_user.tenant_id
    ).first()
    
    if not project:
        return jsonify({'error': 'Project not found'}), 404
    
    # Verify tenant isolation (defense in depth)
    SaaSAPIAccessControl.verify_tenant_isolation(current_user_id, project)
    
    return jsonify(project.to_dict())
```

## Key Takeaways

1. ✅ **Always verify ownership** - Check user owns the requested resource
2. ✅ **Use authenticated user ID from token** - Never trust client-provided IDs
3. ✅ **Implement authorization at API layer** - Don't rely on frontend
4. ✅ **Use UUIDs over sequential IDs** - Reduce predictability
5. ✅ **Log authorization failures** - Detect enumeration attacks
6. ✅ **Test with multiple users** - Verify users can't access each other's data
7. ✅ **Apply to all endpoints** - REST, GraphQL, batch operations
8. ✅ **Tenant isolation for multi-tenant** - Prevent cross-tenant access

## What's Next?

- **[Overview](./overview.md)**: Understand BOLA fundamentals
- **[Attack Vectors](./attack-vectors.md)**: Learn attack techniques
- **[Prevention](./prevention.md)**: Best practices for prevention
- **[Lab](./lab/api01-idor-lab/)**: Hands-on practice with BOLA

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
