# Broken Access Control - Prevention

## Table of Contents
- [Core Prevention Principles](#core-prevention-principles)
- [Secure Coding Patterns](#secure-coding-patterns)
- [Input Validation Strategies](#input-validation-strategies)
- [Security Headers and Configuration](#security-headers-and-configuration)
- [Framework-Specific Mitigations](#framework-specific-mitigations)
- [Security Checklist](#security-checklist)
- [Code Review Guidelines](#code-review-guidelines)

## Core Prevention Principles

### 1. Deny by Default

**Principle**: Start with no access. Explicitly grant permissions.

```python
# ✅ GOOD: Deny by default
def get_document(doc_id):
    # Assume no access
    if not current_user.is_authenticated:
        abort(401)  # Unauthorized
    
    doc = Document.query.get(doc_id)
    if not doc:
        abort(404)
    
    # Explicitly check ownership
    if doc.owner_id != current_user.id and not current_user.is_admin:
        abort(403)  # Forbidden
    
    return doc

# ❌ BAD: Allow by default, deny exceptions
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    if some_condition:  # Incomplete checks
        abort(403)
    return doc  # Accessible otherwise
```

### 2. Never Trust Client Input

**Principle**: All authorization decisions must be server-side.

```python
# ❌ BAD: Trust role from client
@app.route('/admin/users')
def admin_users():
    user_role = request.form.get('role')  # From client!
    if user_role == 'admin':
        return render_template('admin_users.html')

# ✅ GOOD: Check role on server
@app.route('/admin/users')
def admin_users():
    if not current_user.is_authenticated:
        abort(401)
    if not current_user.has_role('admin'):  # From server database
        abort(403)
    return render_template('admin_users.html')
```

### 3. Enforce Ownership Checks

**Principle**: Verify resource ownership before granting access.

```python
# ✅ GOOD: Verify ownership
@app.route('/order/<int:order_id>')
def view_order(order_id):
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id  # Enforce ownership
    ).first_or_404()
    
    return render_template('order.html', order=order)

# ❌ BAD: No ownership check
@app.route('/order/<int:order_id>')
def view_order(order_id):
    order = Order.query.get_or_404(order_id)  # Any order!
    return render_template('order.html', order=order)
```

### 4. Centralize Access Control

**Principle**: Use a single, well-tested mechanism for all authorization.

```python
# ✅ GOOD: Centralized access control
from functools import wraps

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.has_permission(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin/users')
@require_permission('admin.users.view')
def admin_users():
    return render_template('admin_users.html')

# ❌ BAD: Scattered checks
@app.route('/admin/users')
def admin_users():
    # Custom check in each function
    if current_user.email not in ['admin@example.com']:
        abort(403)
    return render_template('admin_users.html')
```

### 5. Use Indirect References

**Principle**: Don't expose internal object IDs directly to users.

```python
# ✅ GOOD: Use UUIDs or mapping
import uuid

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Internal
    public_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))

@app.route('/document/<public_id>')
def get_document(public_id):
    doc = Document.query.filter_by(
        public_id=public_id,
        user_id=current_user.id
    ).first_or_404()
    return doc

# ❌ BAD: Sequential IDs
@app.route('/document/<int:doc_id>')
def get_document(doc_id):
    doc = Document.query.get_or_404(doc_id)  # Predictable!
    return doc
```

## Secure Coding Patterns

### Pattern 1: Role-Based Access Control (RBAC)

```python
# Define roles and permissions
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    permissions = db.relationship('Permission', secondary='role_permissions')

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    resource = db.Column(db.String(80))
    action = db.Column(db.String(80))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    roles = db.relationship('Role', secondary='user_roles')
    
    def has_permission(self, permission_name):
        """Check if user has a specific permission"""
        return any(
            permission.name == permission_name
            for role in self.roles
            for permission in role.permissions
        )

# Use in routes
@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if not current_user.has_permission('users.delete'):
        abort(403)
    
    # Additional logic...
    return {'status': 'deleted'}
```

### Pattern 2: Attribute-Based Access Control (ABAC)

```python
# More flexible, policy-based access control
class AccessPolicy:
    @staticmethod
    def can_view_document(user, document):
        """Determine if user can view document based on attributes"""
        # Owner can always view
        if document.owner_id == user.id:
            return True
        
        # Shared documents
        if user.id in document.shared_with:
            return True
        
        # Public documents
        if document.is_public:
            return True
        
        # Department members can view department docs
        if document.department_id == user.department_id:
            return True
        
        return False

@app.route('/document/<int:doc_id>')
def view_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    if not AccessPolicy.can_view_document(current_user, doc):
        abort(403)
    
    return render_template('document.html', doc=doc)
```

### Pattern 3: Resource-Level Authorization

```python
# Check permissions at the resource level
class Resource:
    def check_access(self, user, action):
        """Override in subclasses to implement resource-specific access control"""
        raise NotImplementedError

class Document(Resource, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def check_access(self, user, action):
        """Check if user can perform action on this document"""
        if action == 'read':
            return self.owner_id == user.id or self.is_public
        elif action == 'write':
            return self.owner_id == user.id
        elif action == 'delete':
            return self.owner_id == user.id or user.has_role('admin')
        return False

@app.route('/document/<int:doc_id>', methods=['PUT'])
def update_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    if not doc.check_access(current_user, 'write'):
        abort(403)
    
    # Update logic...
    return {'status': 'updated'}
```

### Pattern 4: Decorator-Based Authorization

```python
# Reusable decorators for common patterns
def require_ownership(resource_class, id_param='id'):
    """Decorator to ensure current user owns the resource"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            resource_id = kwargs.get(id_param)
            resource = resource_class.query.get_or_404(resource_id)
            
            if resource.owner_id != current_user.id:
                abort(403)
            
            # Pass resource to the function
            kwargs['resource'] = resource
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/order/<int:order_id>')
@require_ownership(Order, 'order_id')
def view_order(order_id, resource):
    # 'resource' is the verified Order object
    return render_template('order.html', order=resource)
```

## Input Validation Strategies

### 1. Validate Resource Access

```python
# ✅ GOOD: Validate all aspects
def get_user_resource(resource_id):
    # Validate format
    try:
        resource_id = int(resource_id)
    except (ValueError, TypeError):
        abort(400)  # Bad request
    
    # Validate existence
    resource = Resource.query.get(resource_id)
    if not resource:
        abort(404)  # Not found
    
    # Validate ownership
    if resource.owner_id != current_user.id:
        abort(403)  # Forbidden
    
    return resource
```

### 2. Whitelist Allowed Actions

```python
# ✅ GOOD: Whitelist pattern
ALLOWED_ACTIONS = {'view', 'edit', 'delete', 'share'}

@app.route('/document/<int:doc_id>/<action>')
def document_action(doc_id, action):
    # Validate action is allowed
    if action not in ALLOWED_ACTIONS:
        abort(400)
    
    doc = Document.query.get_or_404(doc_id)
    
    # Check permissions for this specific action
    if not doc.check_access(current_user, action):
        abort(403)
    
    # Process action...
    return {'status': f'{action} completed'}
```

### 3. Sanitize and Validate IDs

```python
# ✅ GOOD: Validate UUID format
import re

UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)

def validate_uuid(uuid_string):
    if not UUID_PATTERN.match(uuid_string):
        abort(400, "Invalid ID format")
    return uuid_string

@app.route('/document/<uuid_str>')
def get_document(uuid_str):
    uuid_str = validate_uuid(uuid_str)
    # Continue with validated UUID...
```

## Security Headers and Configuration

### 1. HTTP Security Headers

```python
# Configure security headers
@app.after_request
def set_security_headers(response):
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Strict CORS policy
    response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    
    return response
```

### 2. CORS Configuration

```python
# ✅ GOOD: Strict CORS
from flask_cors import CORS

app = Flask(__name__)
CORS(app, 
     origins=['https://yourdomain.com'],
     allow_credentials=True,
     methods=['GET', 'POST', 'PUT', 'DELETE'])

# ❌ BAD: Permissive CORS
CORS(app, origins='*', allow_credentials=True)  # NEVER DO THIS!
```

### 3. Session Configuration

```python
# ✅ GOOD: Secure session settings
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Auto-logout
```

## Framework-Specific Mitigations

### Flask with Flask-Login

```python
from flask_login import LoginManager, login_required, current_user

login_manager = LoginManager()
login_manager.init_app(app)

# Protect routes
@app.route('/profile')
@login_required  # Ensures authentication
def profile():
    # Still need to check authorization!
    return render_template('profile.html')

# Custom authorization decorator
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html')
```

### Django

```python
# Use Django's built-in decorators
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import PermissionDenied

@login_required
@permission_required('app.delete_document', raise_exception=True)
def delete_document(request, document_id):
    document = get_object_or_404(Document, id=document_id)
    
    # Additional ownership check
    if document.owner != request.user and not request.user.is_staff:
        raise PermissionDenied
    
    document.delete()
    return redirect('documents')
```

### FastAPI

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = verify_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    return user

async def require_admin(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

@app.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    admin: User = Depends(require_admin)
):
    # Delete user logic...
    return {"status": "deleted"}
```

## Security Checklist

Use this checklist during development and code review:

### Authentication & Authorization

- [ ] All sensitive endpoints require authentication
- [ ] Authorization is checked on every request (not just page load)
- [ ] Authorization checks are server-side (never client-only)
- [ ] Default access is deny (require explicit grants)
- [ ] Role checks use centralized mechanism
- [ ] Permissions are granular enough for principle of least privilege

### Resource Access

- [ ] Resource ownership is verified before access
- [ ] User can only access their own resources (unless shared)
- [ ] Resource IDs are non-sequential or use UUIDs
- [ ] Database queries include ownership filters
- [ ] File access validates user permissions
- [ ] API endpoints validate resource ownership

### Input Validation

- [ ] All user input is validated and sanitized
- [ ] Resource IDs are validated for format and ownership
- [ ] Action parameters are whitelisted
- [ ] URL parameters cannot bypass access control
- [ ] POST/PUT/DELETE operations verify permissions

### Session & State Management

- [ ] Sessions have appropriate timeouts
- [ ] Session tokens are cryptographically random
- [ ] Sessions invalidated on logout
- [ ] Sensitive cookies have Secure and HttpOnly flags
- [ ] CSRF protection is enabled

### API Security

- [ ] All API endpoints have authentication
- [ ] API rate limiting is implemented
- [ ] API responses don't leak sensitive info
- [ ] GraphQL has query depth/complexity limits
- [ ] API documentation doesn't expose internal structure

### Testing & Monitoring

- [ ] Authorization tests cover all roles
- [ ] Tests verify horizontal and vertical access control
- [ ] Authorization failures are logged
- [ ] Suspicious access patterns trigger alerts
- [ ] Regular security audits are performed

## Code Review Guidelines

### What to Look For

**🔴 Critical Issues:**
```python
# Missing authorization entirely
@app.route('/admin/delete/<id>')
def delete_user(id):  # No permission check!
    User.query.get(id).delete()

# Client-side only authorization
if (userRole === 'admin') {  // JavaScript check only!
    callDeleteAPI();
}

# Trusting client input
role = request.form['role']  # User controls this!
if role == 'admin':
    grant_admin_access()
```

**🟡 Warning Signs:**
```python
# Hard-coded credentials or roles
if user.email == 'admin@example.com':

# Incomplete ownership checks
if user.id == document.user_id:  # What about admins?

# Scattered authorization logic
# Different patterns used throughout codebase
```

**✅ Good Patterns:**
```python
# Centralized authorization
@require_permission('users.delete')
def delete_user(id):

# Ownership verification
doc = Document.query.filter_by(
    id=doc_id,
    user_id=current_user.id
).first_or_404()

# Explicit role checks
if not current_user.has_role('admin'):
    abort(403)
```

### Review Questions

For each protected resource or function, ask:

1. **Who should have access?** (Define explicitly)
2. **Is authentication required?** (Verify identity)
3. **Is authorization checked?** (Verify permissions)
4. **Where is the check performed?** (Must be server-side)
5. **Can it be bypassed?** (Test with different roles)
6. **Is ownership verified?** (For user-specific resources)
7. **Are errors logged?** (For monitoring)

## Testing Strategies

### Unit Tests

```python
def test_user_cannot_access_others_profile():
    """Test horizontal access control"""
    user_a = create_user('user_a')
    user_b = create_user('user_b')
    
    with app.test_client() as client:
        # Log in as user_a
        client.post('/login', data={'username': 'user_a'})
        
        # Try to access user_b's profile
        response = client.get(f'/profile/{user_b.id}')
        
        # Should be forbidden
        assert response.status_code == 403
```

### Integration Tests

```python
def test_role_based_access():
    """Test that only admins can delete users"""
    admin = create_user('admin', role='admin')
    regular_user = create_user('regular')
    
    with app.test_client() as client:
        # Regular user tries to delete
        client.post('/login', data={'username': 'regular'})
        response = client.delete('/api/users/1')
        assert response.status_code == 403
        
        # Admin can delete
        client.post('/login', data={'username': 'admin'})
        response = client.delete('/api/users/1')
        assert response.status_code == 200
```

## What's Next?

- **[Overview](./overview.md)**: Understand what broken access control is
- **[Attack Vectors](./attack-vectors.md)**: Learn how attacks happen
- **[Examples](./examples.md)**: See vulnerable vs secure code
- **[Lab](./lab/broken-access-control-adminbutton/)**: Practice fixing vulnerabilities

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
