# API05: Broken Function Level Authorization - Prevention

## Table of Contents
- [Core Principles](#core-principles)
- [Authorization Frameworks and Patterns](#authorization-frameworks-and-patterns)
- [Implementation Strategies](#implementation-strategies)
- [Technology-Specific Guidance](#technology-specific-guidance)
- [Testing and Validation](#testing-and-validation)
- [Common Pitfalls to Avoid](#common-pitfalls-to-avoid)

## Core Principles

### 1. Defense in Depth

Function-level authorization should be implemented at multiple layers:

```
┌─────────────────────────────────────┐
│     API Gateway / Load Balancer     │ ← Coarse-grained filtering
├─────────────────────────────────────┤
│     Authentication Middleware       │ ← Identity verification
├─────────────────────────────────────┤
│  Authorization Middleware (Global)  │ ← Function-level checks
├─────────────────────────────────────┤
│   Route-Specific Authorization      │ ← Operation-specific rules
├─────────────────────────────────────┤
│     Business Logic Layer            │ ← Additional validation
├─────────────────────────────────────┤
│     Data Access Layer               │ ← Object-level checks
└─────────────────────────────────────┘
```

### 2. Default Deny

**Principle**: Access should be explicitly granted, never assumed.

```python
# WRONG: Whitelist admins, everyone else allowed
if user.role != 'admin':
    return forbidden()
# Dangerous: New roles automatically get access

# RIGHT: Explicit permission required
if user.role not in ['admin', 'moderator']:
    return forbidden()
# Safe: Only known roles allowed
```

### 3. Separation of Concerns

- **Authentication**: Who are you? (Identity)
- **Authorization**: What can you do? (Permissions)
- **Business Logic**: Should you do this? (Context)

Never conflate these responsibilities.

### 4. Centralized Authorization Logic

```python
# WRONG: Scattered authorization checks
@app.route('/api/users/<id>', methods=['DELETE'])
def delete_user(id):
    if current_user.role != 'admin':
        return {'error': 'Forbidden'}, 403
    # Delete logic

@app.route('/api/posts/<id>', methods=['DELETE'])
def delete_post(id):
    if current_user.role != 'admin':  # Duplicated!
        return {'error': 'Forbidden'}, 403
    # Delete logic

# RIGHT: Centralized authorization
def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                return {'error': 'Forbidden'}, 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/users/<id>', methods=['DELETE'])
@require_role('admin')
def delete_user(id):
    # Delete logic

@app.route('/api/posts/<id>', methods=['DELETE'])
@require_role('admin')
def delete_post(id):
    # Delete logic
```

### 5. Explicit Over Implicit

Make authorization requirements clear and visible:

```python
# WRONG: Implicit authorization
@app.route('/api/admin/users')
def admin_users():
    # Path suggests admin, but no enforcement

# RIGHT: Explicit authorization
@app.route('/api/admin/users')
@require_admin
@audit_log
def admin_users():
    # Clear authorization requirements
```

## Authorization Frameworks and Patterns

### Role-Based Access Control (RBAC)

**When to use**: Permissions are based on user roles in the organization.

**Structure**:
```
User → Role → Permissions
  ↓      ↓         ↓
Alice  Admin   [read, write, delete, manage_users]
Bob    User    [read, write]
```

**Implementation**:

```python
from enum import Enum

class Role(Enum):
    ADMIN = 'admin'
    MODERATOR = 'moderator'
    USER = 'user'

class Permission(Enum):
    READ_USERS = 'read_users'
    WRITE_USERS = 'write_users'
    DELETE_USERS = 'delete_users'
    MANAGE_SETTINGS = 'manage_settings'

# Role-Permission mapping
ROLE_PERMISSIONS = {
    Role.ADMIN: [
        Permission.READ_USERS,
        Permission.WRITE_USERS,
        Permission.DELETE_USERS,
        Permission.MANAGE_SETTINGS,
    ],
    Role.MODERATOR: [
        Permission.READ_USERS,
        Permission.WRITE_USERS,
    ],
    Role.USER: [
        Permission.READ_USERS,
    ],
}

def has_permission(user, required_permission):
    """Check if user's role has the required permission."""
    user_permissions = ROLE_PERMISSIONS.get(user.role, [])
    return required_permission in user_permissions

def require_permission(permission):
    """Decorator to enforce permission requirements."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_permission(current_user, permission):
                return {'error': 'Insufficient permissions'}, 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage
@app.route('/api/users/<id>', methods=['DELETE'])
@require_permission(Permission.DELETE_USERS)
def delete_user(id):
    # Only admins can execute this
    User.query.get(id).delete()
    return {'status': 'deleted'}
```

**Pros**:
- Simple to understand and implement
- Easy to manage in small to medium organizations
- Clear role hierarchy

**Cons**:
- Can become complex with many roles
- Role explosion problem
- Less flexible for fine-grained control

### Attribute-Based Access Control (ABAC)

**When to use**: Permissions depend on multiple attributes (user, resource, environment, action).

**Structure**:
```
Policy: Can user perform action on resource in context?
  ↓
Attributes:
  User: {role: manager, department: sales, level: 3}
  Resource: {type: report, department: sales, sensitivity: high}
  Environment: {time: business_hours, location: office}
  Action: {type: read, scope: full}
```

**Implementation**:

```python
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class AuthorizationContext:
    user_attributes: Dict[str, Any]
    resource_attributes: Dict[str, Any]
    action: str
    environment: Dict[str, Any]

class Policy:
    """ABAC policy evaluation."""
    
    @staticmethod
    def evaluate(context: AuthorizationContext) -> bool:
        """Evaluate if action is authorized based on attributes."""
        # Example: Department managers can delete their department's resources
        if context.action == 'delete':
            if context.user_attributes.get('role') == 'manager':
                user_dept = context.user_attributes.get('department')
                resource_dept = context.resource_attributes.get('department')
                return user_dept == resource_dept
            return False
        
        # Example: Admins can do everything
        if context.user_attributes.get('role') == 'admin':
            return True
        
        return False

def require_authorization(get_resource):
    """Decorator for ABAC enforcement."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            resource = get_resource(*args, **kwargs)
            
            context = AuthorizationContext(
                user_attributes={
                    'role': current_user.role,
                    'department': current_user.department,
                },
                resource_attributes={
                    'department': resource.department,
                    'owner_id': resource.owner_id,
                },
                action=request.method.lower(),
                environment={
                    'time': datetime.now(),
                    'ip': request.remote_addr,
                }
            )
            
            if not Policy.evaluate(context):
                return {'error': 'Not authorized'}, 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage
@app.route('/api/reports/<id>', methods=['DELETE'])
@require_authorization(lambda id: Report.query.get(id))
def delete_report(id):
    # Only managers of the same department can delete
    Report.query.get(id).delete()
    return {'status': 'deleted'}
```

**Pros**:
- Very flexible and fine-grained
- Scales to complex scenarios
- Dynamic policy evaluation

**Cons**:
- More complex to implement
- Performance considerations
- Harder to audit and debug

### Permission-Based Access Control

**When to use**: Direct user-to-permission mapping for simpler systems.

**Implementation**:

```python
class User:
    def __init__(self, id, permissions):
        self.id = id
        self.permissions = set(permissions)
    
    def has_permission(self, permission):
        return permission in self.permissions
    
    def add_permission(self, permission):
        self.permissions.add(permission)
    
    def remove_permission(self, permission):
        self.permissions.discard(permission)

def require_any_permission(*required_permissions):
    """User must have at least one of the specified permissions."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not any(current_user.has_permission(p) for p in required_permissions):
                return {'error': 'Insufficient permissions'}, 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_all_permissions(*required_permissions):
    """User must have all specified permissions."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not all(current_user.has_permission(p) for p in required_permissions):
                return {'error': 'Insufficient permissions'}, 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage
@app.route('/api/users/<id>', methods=['DELETE'])
@require_all_permissions('users:delete', 'admin:access')
def delete_user(id):
    User.query.get(id).delete()
    return {'status': 'deleted'}
```

### Policy Enforcement Points (PEP)

**Centralized authorization using dedicated service:**

```python
class AuthorizationService:
    """Centralized policy enforcement point."""
    
    def __init__(self):
        self.policies = self._load_policies()
    
    def authorize(self, user, action, resource=None):
        """
        Central authorization check.
        
        Args:
            user: The user attempting the action
            action: The action being attempted (e.g., 'delete_user')
            resource: Optional resource being accessed
        
        Returns:
            bool: True if authorized, False otherwise
        """
        # Check global admin override
        if user.role == 'super_admin':
            return True
        
        # Load applicable policies
        policies = self._get_policies_for_action(action)
        
        # Evaluate each policy
        for policy in policies:
            if policy.evaluate(user, action, resource):
                return True
        
        return False
    
    def _get_policies_for_action(self, action):
        """Get all policies applicable to an action."""
        return [p for p in self.policies if p.applies_to(action)]

# Global instance
auth_service = AuthorizationService()

def authorize(action, get_resource=None):
    """Decorator using centralized authorization."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            resource = get_resource(*args, **kwargs) if get_resource else None
            
            if not auth_service.authorize(current_user, action, resource):
                return {'error': 'Not authorized'}, 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage
@app.route('/api/users/<id>', methods=['DELETE'])
@authorize('delete_user', lambda id: User.query.get(id))
def delete_user(id):
    User.query.get(id).delete()
    return {'status': 'deleted'}
```

## Implementation Strategies

### 1. Middleware-Based Authorization

**Flask Example**:

```python
from flask import Flask, g, request
from functools import wraps

app = Flask(__name__)

def check_authorization():
    """Global authorization middleware."""
    # Skip auth for public endpoints
    public_paths = ['/api/login', '/api/register', '/api/health']
    if request.path in public_paths:
        return
    
    # Verify authentication
    token = request.headers.get('Authorization')
    if not token:
        return {'error': 'Authentication required'}, 401
    
    user = verify_token(token)
    if not user:
        return {'error': 'Invalid token'}, 401
    
    g.current_user = user
    
    # Check function-level authorization
    if request.path.startswith('/api/admin/'):
        if user.role not in ['admin', 'super_admin']:
            return {'error': 'Admin access required'}, 403

app.before_request(check_authorization)
```

**Express.js Example**:

```javascript
const express = require('express');
const app = express();

// Authorization middleware
const requireRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        
        next();
    };
};

// Usage
app.delete('/api/users/:id', 
    requireRole('admin', 'super_admin'),
    async (req, res) => {
        await User.destroy({ where: { id: req.params.id } });
        res.json({ status: 'deleted' });
    }
);
```

### 2. Decorator-Based Authorization

**Python/Flask**:

```python
from functools import wraps
from flask import g, request

def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user'):
            return {'error': 'Authentication required'}, 401
        
        if g.current_user.role != 'admin':
            return {'error': 'Admin access required'}, 403
        
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Decorator to require specific roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return {'error': 'Authentication required'}, 401
            
            if g.current_user.role not in roles:
                return {'error': f'Requires one of: {", ".join(roles)}'}, 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage
@app.route('/api/users/<id>', methods=['DELETE'])
@admin_required
def delete_user(id):
    User.query.get(id).delete()
    return {'status': 'deleted'}

@app.route('/api/posts/<id>', methods=['DELETE'])
@role_required('admin', 'moderator')
def delete_post(id):
    Post.query.get(id).delete()
    return {'status': 'deleted'}
```

### 3. Method-Specific Authorization

```python
from flask import request

class UserAPI:
    """RESTful API with method-specific authorization."""
    
    @staticmethod
    @app.route('/api/users/<id>', methods=['GET', 'PUT', 'DELETE'])
    def user_endpoint(id):
        user = User.query.get(id)
        
        if request.method == 'GET':
            # Read: authenticated users can view
            if not g.current_user:
                return {'error': 'Authentication required'}, 401
            return user.to_dict()
        
        elif request.method == 'PUT':
            # Update: owner or admin
            if g.current_user.id != user.id and g.current_user.role != 'admin':
                return {'error': 'Not authorized'}, 403
            user.update(request.json)
            return user.to_dict()
        
        elif request.method == 'DELETE':
            # Delete: admin only
            if g.current_user.role != 'admin':
                return {'error': 'Admin access required'}, 403
            user.delete()
            return {'status': 'deleted'}
```

### 4. Policy-Based Authorization

```python
class AuthorizationPolicy:
    """Define authorization policies as code."""
    
    @staticmethod
    def can_delete_user(actor, target_user):
        """Policy: Who can delete users?"""
        # Super admins can delete anyone
        if actor.role == 'super_admin':
            return True
        
        # Admins can delete non-admins
        if actor.role == 'admin' and target_user.role != 'admin':
            return True
        
        # Users can delete themselves
        if actor.id == target_user.id:
            return True
        
        return False
    
    @staticmethod
    def can_modify_settings(actor, setting_type):
        """Policy: Who can modify settings?"""
        admin_settings = ['security', 'billing', 'users']
        moderator_settings = ['content', 'moderation']
        
        if actor.role == 'admin':
            return True
        
        if actor.role == 'moderator' and setting_type in moderator_settings:
            return True
        
        return False

# Usage
@app.route('/api/users/<id>', methods=['DELETE'])
def delete_user(id):
    target_user = User.query.get(id)
    
    if not AuthorizationPolicy.can_delete_user(g.current_user, target_user):
        return {'error': 'Not authorized to delete this user'}, 403
    
    target_user.delete()
    return {'status': 'deleted'}
```

### 5. Claim-Based Authorization (JWT)

```python
import jwt
from datetime import datetime, timedelta

def create_token(user):
    """Create JWT with embedded permissions."""
    payload = {
        'user_id': user.id,
        'role': user.role,
        'permissions': user.get_permissions(),
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_permission(required_permission):
    """Decorator to check JWT claims."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            try:
                payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return {'error': 'Token expired'}, 401
            except jwt.InvalidTokenError:
                return {'error': 'Invalid token'}, 401
            
            if required_permission not in payload.get('permissions', []):
                return {'error': 'Insufficient permissions'}, 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage
@app.route('/api/users/<id>', methods=['DELETE'])
@verify_permission('users:delete')
def delete_user(id):
    User.query.get(id).delete()
    return {'status': 'deleted'}
```

## Technology-Specific Guidance

### Flask

```python
from flask import Flask, g
from flask_httpauth import HTTPTokenAuth

app = Flask(__name__)
auth = HTTPTokenAuth(scheme='Bearer')

@auth.verify_token
def verify_token(token):
    """Verify authentication token."""
    user = User.verify_auth_token(token)
    g.current_user = user
    return user is not None

@auth.get_user_roles
def get_user_roles(user):
    """Get user roles for authorization."""
    return [user.role]

# Role-based protection
@app.route('/api/admin/users')
@auth.login_required(role='admin')
def admin_users():
    return {'users': [u.to_dict() for u in User.query.all()]}
```

### Express.js

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

// Authorization middleware factory
const authorize = (allowedRoles = []) => {
    return (req, res, next) => {
        const token = req.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }
        
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;
            
            if (allowedRoles.length && !allowedRoles.includes(decoded.role)) {
                return res.status(403).json({ error: 'Insufficient permissions' });
            }
            
            next();
        } catch (error) {
            return res.status(401).json({ error: 'Invalid token' });
        }
    };
};

// Usage
app.delete('/api/users/:id', authorize(['admin']), async (req, res) => {
    await User.destroy({ where: { id: req.params.id } });
    res.json({ status: 'deleted' });
});
```

### FastAPI

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List

app = FastAPI()
security = HTTPBearer()

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles
    
    def __call__(self, credentials: HTTPAuthorizationCredentials = Depends(security)):
        token = credentials.credentials
        user = verify_token(token)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )
        
        if user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        return user

# Usage
@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(RoleChecker(["admin"]))
):
    user = await User.get(user_id)
    await user.delete()
    return {"status": "deleted"}
```

### Django REST Framework

```python
from rest_framework import permissions, viewsets
from rest_framework.decorators import action

class IsAdminUser(permissions.BasePermission):
    """Custom permission: only admins allowed."""
    
    def has_permission(self, request, view):
        return request.user and request.user.role == 'admin'

class IsAdminOrReadOnly(permissions.BasePermission):
    """Custom permission: admins can modify, others read-only."""
    
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user and request.user.role == 'admin'

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    
    def get_permissions(self):
        """Set permissions based on action."""
        if self.action in ['create', 'update', 'partial_update']:
            permission_classes = [IsAdminOrReadOnly]
        elif self.action == 'destroy':
            permission_classes = [IsAdminUser]
        else:
            permission_classes = [permissions.IsAuthenticated]
        return [permission() for permission in permission_classes]
    
    @action(detail=False, methods=['post'], permission_classes=[IsAdminUser])
    def bulk_delete(self, request):
        """Admin-only bulk delete operation."""
        user_ids = request.data.get('user_ids', [])
        User.objects.filter(id__in=user_ids).delete()
        return Response({'status': 'deleted'})
```

### GraphQL

```javascript
const { ApolloServer, gql, AuthenticationError, ForbiddenError } = require('apollo-server');

const typeDefs = gql`
    type User {
        id: ID!
        name: String!
        email: String!
    }
    
    type Mutation {
        deleteUser(id: ID!): Boolean @requireRole(role: "admin")
        updateUserRole(id: ID!, role: String!): User @requireRole(role: "admin")
    }
`;

const resolvers = {
    Mutation: {
        deleteUser: async (parent, { id }, context) => {
            // Authorization checked by directive
            await User.destroy({ where: { id } });
            return true;
        },
        
        updateUserRole: async (parent, { id, role }, context) => {
            // Authorization checked by directive
            const user = await User.findByPk(id);
            user.role = role;
            await user.save();
            return user;
        }
    }
};

// Custom directive for role-based authorization
class RequireRoleDirective extends SchemaDirectiveVisitor {
    visitFieldDefinition(field) {
        const { resolve = defaultFieldResolver } = field;
        const { role } = this.args;
        
        field.resolve = async function (...args) {
            const context = args[2];
            
            if (!context.user) {
                throw new AuthenticationError('Authentication required');
            }
            
            if (context.user.role !== role) {
                throw new ForbiddenError(`Requires ${role} role`);
            }
            
            return resolve.apply(this, args);
        };
    }
}

const server = new ApolloServer({
    typeDefs,
    resolvers,
    schemaDirectives: {
        requireRole: RequireRoleDirective
    },
    context: ({ req }) => {
        // Get user from token
        const token = req.headers.authorization || '';
        const user = verifyToken(token);
        return { user };
    }
});
```

## Testing and Validation

### Unit Testing Authorization

```python
import unittest
from flask import Flask

class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.client = self.app.test_client()
    
    def test_admin_endpoint_requires_admin_role(self):
        """Admin endpoints should reject non-admin users."""
        # Get user token
        user_token = self.get_user_token(role='user')
        
        response = self.client.delete(
            '/api/users/123',
            headers={'Authorization': f'Bearer {user_token}'}
        )
        
        self.assertEqual(response.status_code, 403)
        self.assertIn('Admin access required', response.json['error'])
    
    def test_admin_endpoint_allows_admin(self):
        """Admin endpoints should allow admin users."""
        admin_token = self.get_user_token(role='admin')
        
        response = self.client.delete(
            '/api/users/123',
            headers={'Authorization': f'Bearer {admin_token}'}
        )
        
        self.assertEqual(response.status_code, 200)
    
    def test_http_method_authorization(self):
        """Different HTTP methods should have different authorization."""
        user_token = self.get_user_token(role='user')
        
        # GET should work for regular users
        get_response = self.client.get(
            '/api/users/123',
            headers={'Authorization': f'Bearer {user_token}'}
        )
        self.assertEqual(get_response.status_code, 200)
        
        # DELETE should fail for regular users
        delete_response = self.client.delete(
            '/api/users/123',
            headers={'Authorization': f'Bearer {user_token}'}
        )
        self.assertEqual(delete_response.status_code, 403)
```

### Integration Testing

```python
class IntegrationAuthTests(unittest.TestCase):
    def test_privilege_escalation_prevention(self):
        """Users should not be able to escalate privileges."""
        user_token = self.get_user_token(role='user')
        
        # Attempt to set role to admin
        response = self.client.put(
            '/api/users/me',
            json={'role': 'admin'},
            headers={'Authorization': f'Bearer {user_token}'}
        )
        
        # Should either reject or ignore the role field
        user = User.query.get(self.current_user_id)
        self.assertEqual(user.role, 'user')
    
    def test_hidden_endpoint_discovery(self):
        """Common admin endpoint patterns should be protected."""
        user_token = self.get_user_token(role='user')
        
        admin_patterns = [
            '/api/admin/users',
            '/api/admin/settings',
            '/api/internal/config',
            '/api/debug/info',
        ]
        
        for endpoint in admin_patterns:
            response = self.client.get(
                endpoint,
                headers={'Authorization': f'Bearer {user_token}'}
            )
            self.assertIn(response.status_code, [403, 404])
```

### Security Testing Checklist

- [ ] **Unauthenticated Access**: Try all endpoints without authentication
- [ ] **Role-Based Access**: Test each endpoint with each role
- [ ] **Method Tampering**: Try GET, POST, PUT, DELETE, PATCH on each endpoint
- [ ] **Parameter Manipulation**: Add role/admin parameters to requests
- [ ] **Header Injection**: Try X-User-Role, X-Admin, etc.
- [ ] **Path Traversal**: Try /api/user/../admin/ patterns
- [ ] **Version Testing**: Test all API versions
- [ ] **GraphQL Introspection**: Check for exposed admin mutations
- [ ] **Bulk Operations**: Verify authorization on batch endpoints
- [ ] **Token Manipulation**: Modify JWT claims and test

## Common Pitfalls to Avoid

### 1. Relying on Frontend Authorization

```javascript
// WRONG: Only hiding in UI
if (user.role === 'admin') {
    <button onClick={deleteUser}>Delete</button>
}

// Backend still accessible via API!
```

**Fix**: Always enforce on backend.

### 2. Trusting Client Data

```python
# WRONG: Trusting role from request
@app.route('/api/action')
def perform_action():
    user_role = request.json.get('role')  # Attacker controls this!
    if user_role == 'admin':
        return admin_action()
```

**Fix**: Get role from authenticated session/token.

### 3. Inconsistent Authorization

```python
# WRONG: Some methods protected, others not
@app.route('/api/users/<id>', methods=['GET', 'DELETE'])
def user_endpoint(id):
    if request.method == 'GET':
        if not current_user.can_view(id):
            return forbidden()
        return get_user(id)
    
    # DELETE has no check!
    return delete_user(id)
```

**Fix**: Protect all methods explicitly.

### 4. OR Instead of AND

```python
# WRONG: OR allows unintended access
if user.is_authenticated() or user.is_admin():
    return sensitive_data()

# Unauthenticated admins would pass!
```

**Fix**: Use AND for compound requirements.

### 5. Incomplete Role Checks

```python
# WRONG: Only checking for NOT admin
if user.role != 'admin':
    return forbidden()

# What if role is None, '', or unexpected value?
```

**Fix**: Explicitly whitelist allowed roles.

### 6. Exposing Admin Links

```python
# WRONG: Including admin URLs in responses
{
    "user": {...},
    "links": {
        "self": "/api/users/123",
        "delete": "/api/admin/users/123"  # Reveals admin endpoint!
    }
}
```

**Fix**: Only include links user is authorized to use.

## Defense in Depth Summary

1. **API Gateway**: Route-level filtering
2. **Authentication**: Verify identity
3. **Authorization Middleware**: Global role checks
4. **Route Guards**: Endpoint-specific permissions
5. **Business Logic**: Additional context validation
6. **Audit Logging**: Track all privileged operations
7. **Monitoring**: Alert on unauthorized access attempts

## Next Steps

- **[Examples](examples.md)** - See complete code examples with secure implementations
- **[Lab](lab/api05-function-auth-lab/)** - Practice implementing and testing function-level authorization
- **[Attack Vectors](attack-vectors.md)** - Understand what you're defending against
