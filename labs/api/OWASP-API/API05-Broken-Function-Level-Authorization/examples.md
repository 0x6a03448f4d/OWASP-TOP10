# API05: Broken Function Level Authorization - Code Examples

## Table of Contents
- [Flask Examples](#flask-examples)
- [Express.js Examples](#expressjs-examples)
- [FastAPI Examples](#fastapi-examples)
- [Django REST Framework Examples](#django-rest-framework-examples)
- [Complete Application Examples](#complete-application-examples)

## Flask Examples

### Example 1: Basic Admin Function Protection

#### ❌ Vulnerable Code

```python
from flask import Flask, request, jsonify
from models import User, db

app = Flask(__name__)

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """VULNERABLE: No authorization check!"""
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'deleted', 'user_id': user_id})

# Any authenticated user can delete any user!
```

**Vulnerabilities**:
- No role verification
- No permission checking
- Admin function accessible to all authenticated users

#### ✅ Secure Code

```python
from flask import Flask, request, jsonify, g
from functools import wraps
from models import User, db

app = Flask(__name__)

def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user'):
            return jsonify({'error': 'Authentication required'}), 401
        
        if g.current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """SECURE: Requires admin role."""
    user = User.query.get_or_404(user_id)
    
    # Additional check: prevent deleting yourself
    if user.id == g.current_user.id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'status': 'deleted', 'user_id': user_id})
```

**Security Improvements**:
- ✓ Explicit admin role check
- ✓ Authentication verification
- ✓ Self-deletion prevention
- ✓ Clear error messages

### Example 2: Method-Specific Authorization

#### ❌ Vulnerable Code

```python
@app.route('/api/products/<int:product_id>', methods=['GET', 'PUT', 'DELETE'])
def product_endpoint(product_id):
    """VULNERABLE: GET protected, but PUT/DELETE are not!"""
    product = Product.query.get_or_404(product_id)
    
    if request.method == 'GET':
        # Only check authorization for GET
        if not g.current_user.can_view_product(product):
            return jsonify({'error': 'Forbidden'}), 403
        return jsonify(product.to_dict())
    
    elif request.method == 'PUT':
        # Missing authorization check!
        product.update(request.json)
        db.session.commit()
        return jsonify(product.to_dict())
    
    elif request.method == 'DELETE':
        # Missing authorization check!
        db.session.delete(product)
        db.session.commit()
        return jsonify({'status': 'deleted'})
```

#### ✅ Secure Code

```python
def require_role(*allowed_roles):
    """Decorator to require specific roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            if g.current_user.role not in allowed_roles:
                return jsonify({
                    'error': f'Requires one of: {", ".join(allowed_roles)}'
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/products/<int:product_id>', methods=['GET'])
@require_role('user', 'admin')
def get_product(product_id):
    """GET: All authenticated users."""
    product = Product.query.get_or_404(product_id)
    return jsonify(product.to_dict())

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@require_role('admin', 'product_manager')
def update_product(product_id):
    """PUT: Admin or product manager only."""
    product = Product.query.get_or_404(product_id)
    product.update(request.json)
    db.session.commit()
    return jsonify(product.to_dict())

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@require_role('admin')
def delete_product(product_id):
    """DELETE: Admin only."""
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({'status': 'deleted'})
```

**Security Improvements**:
- ✓ Separate routes for different methods
- ✓ Method-specific authorization
- ✓ Reusable role decorator
- ✓ Clear permission requirements

### Example 3: Parameter Manipulation Prevention

#### ❌ Vulnerable Code

```python
@app.route('/api/register', methods=['POST'])
def register():
    """VULNERABLE: Trusts client-provided role!"""
    data = request.json
    
    user = User(
        username=data['username'],
        email=data['email'],
        password=hash_password(data['password']),
        role=data.get('role', 'user')  # Attacker can set 'admin'!
    )
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify(user.to_dict()), 201
```

**Attack**:
```bash
curl -X POST https://api.example.com/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "attacker",
    "email": "attacker@evil.com",
    "password": "password123",
    "role": "admin"
  }'
```

#### ✅ Secure Code

```python
@app.route('/api/register', methods=['POST'])
def register():
    """SECURE: Only allowed fields, fixed role."""
    data = request.json
    
    # Whitelist allowed fields
    allowed_fields = {'username', 'email', 'password'}
    user_data = {k: v for k, v in data.items() if k in allowed_fields}
    
    # Server assigns role (never trust client)
    user = User(
        username=user_data['username'],
        email=user_data['email'],
        password=hash_password(user_data['password']),
        role='user'  # Always 'user' for registration
    )
    
    db.session.add(user)
    db.session.commit()
    
    # Don't expose role in response if not needed
    response_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email
    }
    
    return jsonify(response_data), 201

@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
@require_role('admin')
def update_user_role(user_id):
    """SECURE: Separate endpoint for role changes, admin-only."""
    user = User.query.get_or_404(user_id)
    new_role = request.json.get('role')
    
    # Validate role
    valid_roles = ['user', 'moderator', 'admin']
    if new_role not in valid_roles:
        return jsonify({'error': 'Invalid role'}), 400
    
    # Additional business logic checks
    if new_role == 'admin' and g.current_user.role != 'super_admin':
        return jsonify({'error': 'Only super_admin can create admins'}), 403
    
    user.role = new_role
    db.session.commit()
    
    return jsonify({'user_id': user.id, 'role': user.role})
```

**Security Improvements**:
- ✓ Field whitelisting
- ✓ Server-controlled role assignment
- ✓ Separate admin endpoint for role changes
- ✓ Role validation
- ✓ Hierarchical permission checks

### Example 4: Hidden Endpoint Protection

#### ❌ Vulnerable Code

```python
# Public documented endpoint
@app.route('/api/users', methods=['GET'])
def list_users():
    """Public endpoint - returns limited data."""
    users = User.query.limit(100).all()
    return jsonify([{'id': u.id, 'username': u.username} for u in users])

# Hidden admin endpoint (not in documentation)
@app.route('/api/admin/users', methods=['GET'])
def admin_list_users():
    """VULNERABLE: No authorization check on 'hidden' endpoint!"""
    users = User.query.all()
    return jsonify([u.to_dict(include_sensitive=True) for u in users])

# Attacker can discover and access this endpoint
```

#### ✅ Secure Code

```python
@app.route('/api/users', methods=['GET'])
@require_role('user', 'admin')
def list_users():
    """Public endpoint - returns limited data."""
    users = User.query.limit(100).all()
    return jsonify([{'id': u.id, 'username': u.username} for u in users])

@app.route('/api/admin/users', methods=['GET'])
@require_role('admin')
def admin_list_users():
    """SECURE: Admin-only endpoint with explicit check."""
    # Additional parameter validation
    include_deleted = request.args.get('include_deleted', 'false') == 'true'
    export_format = request.args.get('export')
    
    query = User.query
    if include_deleted:
        query = query.filter_by(deleted=True)
    
    users = query.all()
    
    if export_format == 'csv':
        # Verify admin permission for export
        return export_users_csv(users)
    
    return jsonify([u.to_dict(include_sensitive=True) for u in users])

@app.before_request
def check_admin_routes():
    """Global check for admin routes."""
    if request.path.startswith('/api/admin/'):
        if not hasattr(g, 'current_user'):
            return jsonify({'error': 'Authentication required'}), 401
        if g.current_user.role not in ['admin', 'super_admin']:
            return jsonify({'error': 'Admin access required'}), 403
```

**Security Improvements**:
- ✓ Explicit authorization on all endpoints
- ✓ Global admin route protection
- ✓ Parameter validation
- ✓ No reliance on obscurity

## Express.js Examples

### Example 1: Middleware-Based Authorization

#### ❌ Vulnerable Code

```javascript
const express = require('express');
const app = express();

// Authentication middleware (only checks if logged in)
const authenticate = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    req.user = verifyToken(token);
    next();
};

// VULNERABLE: Only checks authentication, not authorization
app.delete('/api/users/:id', authenticate, async (req, res) => {
    await User.destroy({ where: { id: req.params.id } });
    res.json({ status: 'deleted' });
});

// Any authenticated user can delete any user!
```

#### ✅ Secure Code

```javascript
const express = require('express');
const app = express();

// Authentication middleware
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    try {
        req.user = verifyToken(token);
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Authorization middleware factory
const requireRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ 
                error: `Requires one of: ${allowedRoles.join(', ')}` 
            });
        }
        
        next();
    };
};

// SECURE: Requires admin role
app.delete('/api/users/:id', 
    authenticate,
    requireRole('admin', 'super_admin'),
    async (req, res) => {
        const userId = req.params.id;
        
        // Prevent self-deletion
        if (userId === req.user.id) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }
        
        await User.destroy({ where: { id: userId } });
        res.json({ status: 'deleted', userId });
    }
);
```

### Example 2: Role-Based CRUD Operations

#### ❌ Vulnerable Code

```javascript
// VULNERABLE: No differentiation between operations
app.route('/api/posts/:id')
    .get(authenticate, async (req, res) => {
        const post = await Post.findByPk(req.params.id);
        res.json(post);
    })
    .put(authenticate, async (req, res) => {
        // Missing authorization - any user can edit any post!
        const post = await Post.findByPk(req.params.id);
        await post.update(req.body);
        res.json(post);
    })
    .delete(authenticate, async (req, res) => {
        // Missing authorization - any user can delete any post!
        await Post.destroy({ where: { id: req.params.id } });
        res.json({ status: 'deleted' });
    });
```

#### ✅ Secure Code

```javascript
// Permission checking middleware
const canModifyPost = async (req, res, next) => {
    const post = await Post.findByPk(req.params.id);
    
    if (!post) {
        return res.status(404).json({ error: 'Post not found' });
    }
    
    // Admin can modify any post
    if (req.user.role === 'admin') {
        req.post = post;
        return next();
    }
    
    // Moderators can modify any post
    if (req.user.role === 'moderator') {
        req.post = post;
        return next();
    }
    
    // Regular users can only modify their own posts
    if (post.authorId === req.user.id) {
        req.post = post;
        return next();
    }
    
    return res.status(403).json({ error: 'Not authorized to modify this post' });
};

const canDeletePost = async (req, res, next) => {
    const post = await Post.findByPk(req.params.id);
    
    if (!post) {
        return res.status(404).json({ error: 'Post not found' });
    }
    
    // Only admin and post author can delete
    if (req.user.role === 'admin' || post.authorId === req.user.id) {
        req.post = post;
        return next();
    }
    
    return res.status(403).json({ error: 'Not authorized to delete this post' });
};

// SECURE: Different authorization for different operations
app.route('/api/posts/:id')
    .get(authenticate, async (req, res) => {
        // Read: all authenticated users
        const post = await Post.findByPk(req.params.id);
        res.json(post);
    })
    .put(authenticate, canModifyPost, async (req, res) => {
        // Update: owner, moderator, or admin
        await req.post.update(req.body);
        res.json(req.post);
    })
    .delete(authenticate, canDeletePost, async (req, res) => {
        // Delete: owner or admin only
        await req.post.destroy();
        res.json({ status: 'deleted' });
    });
```

### Example 3: Bulk Operations Protection

#### ❌ Vulnerable Code

```javascript
// VULNERABLE: Bulk delete accessible to all users
app.post('/api/users/bulk-delete', authenticate, async (req, res) => {
    const { userIds } = req.body;
    
    await User.destroy({
        where: {
            id: { [Op.in]: userIds }
        }
    });
    
    res.json({ status: 'deleted', count: userIds.length });
});

// Regular user could delete hundreds of users!
```

#### ✅ Secure Code

```javascript
// SECURE: Bulk operations require admin role
app.post('/api/users/bulk-delete', 
    authenticate,
    requireRole('admin'),
    async (req, res) => {
        const { userIds } = req.body;
        
        // Validate input
        if (!Array.isArray(userIds) || userIds.length === 0) {
            return res.status(400).json({ error: 'Invalid user IDs' });
        }
        
        // Limit bulk operation size
        if (userIds.length > 100) {
            return res.status(400).json({ 
                error: 'Bulk operations limited to 100 users at a time' 
            });
        }
        
        // Prevent deleting yourself in bulk
        if (userIds.includes(req.user.id)) {
            return res.status(400).json({ 
                error: 'Cannot delete your own account in bulk operation' 
            });
        }
        
        // Perform deletion with transaction
        const transaction = await sequelize.transaction();
        
        try {
            const result = await User.destroy({
                where: {
                    id: { [Op.in]: userIds }
                },
                transaction
            });
            
            await transaction.commit();
            
            // Audit log
            await AuditLog.create({
                userId: req.user.id,
                action: 'bulk_delete_users',
                details: { userIds, count: result }
            });
            
            res.json({ status: 'deleted', count: result });
        } catch (error) {
            await transaction.rollback();
            res.status(500).json({ error: 'Bulk deletion failed' });
        }
    }
);
```

## FastAPI Examples

### Example 1: Dependency-Based Authorization

#### ❌ Vulnerable Code

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer

app = FastAPI()
security = HTTPBearer()

async def get_current_user(credentials = Depends(security)):
    """VULNERABLE: Only checks authentication, not authorization."""
    token = credentials.credentials
    user = verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user = Depends(get_current_user)
):
    """VULNERABLE: Any authenticated user can delete any user!"""
    user = await User.get(user_id)
    await user.delete()
    return {"status": "deleted", "user_id": user_id}
```

#### ✅ Secure Code

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from typing import List

app = FastAPI()
security = HTTPBearer()

async def get_current_user(credentials = Depends(security)):
    """Get authenticated user."""
    token = credentials.credentials
    user = verify_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    return user

class RoleChecker:
    """Dependency for role-based authorization."""
    
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles
    
    def __call__(self, user = Depends(get_current_user)):
        if user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(self.allowed_roles)}"
            )
        return user

# Use as dependency
require_admin = RoleChecker(["admin", "super_admin"])
require_moderator = RoleChecker(["admin", "moderator"])

@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user = Depends(require_admin)
):
    """SECURE: Only admins can delete users."""
    # Prevent self-deletion
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    user = await User.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    await user.delete()
    return {"status": "deleted", "user_id": user_id}
```

### Example 2: Permission-Based Authorization

#### ✅ Secure Implementation

```python
from enum import Enum
from typing import Set

class Permission(str, Enum):
    READ_USERS = "users:read"
    WRITE_USERS = "users:write"
    DELETE_USERS = "users:delete"
    MANAGE_ROLES = "roles:manage"
    VIEW_ANALYTICS = "analytics:view"

ROLE_PERMISSIONS = {
    "admin": {
        Permission.READ_USERS,
        Permission.WRITE_USERS,
        Permission.DELETE_USERS,
        Permission.MANAGE_ROLES,
        Permission.VIEW_ANALYTICS,
    },
    "moderator": {
        Permission.READ_USERS,
        Permission.WRITE_USERS,
        Permission.VIEW_ANALYTICS,
    },
    "user": {
        Permission.READ_USERS,
    }
}

class PermissionChecker:
    """Dependency for permission-based authorization."""
    
    def __init__(self, required_permissions: Set[Permission]):
        self.required_permissions = required_permissions
    
    def __call__(self, user = Depends(get_current_user)):
        user_permissions = ROLE_PERMISSIONS.get(user.role, set())
        
        if not self.required_permissions.issubset(user_permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        return user

@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user = Depends(PermissionChecker({Permission.DELETE_USERS}))
):
    """Requires specific permission to delete users."""
    user = await User.get(user_id)
    await user.delete()
    return {"status": "deleted"}

@app.put("/api/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    new_role: str,
    current_user = Depends(PermissionChecker({
        Permission.MANAGE_ROLES,
        Permission.WRITE_USERS
    }))
):
    """Requires multiple permissions to change roles."""
    user = await User.get(user_id)
    user.role = new_role
    await user.save()
    return user
```

## Django REST Framework Examples

### Example 1: Custom Permission Classes

#### ❌ Vulnerable Code

```python
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

class UserViewSet(viewsets.ModelViewSet):
    """VULNERABLE: Same permission for all actions."""
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]
    
    # Any authenticated user can create, update, delete any user!
```

#### ✅ Secure Code

```python
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response

class IsAdminUser(permissions.BasePermission):
    """Custom permission: only admins allowed."""
    
    def has_permission(self, request, view):
        return request.user and request.user.role == 'admin'

class IsAdminOrReadOnly(permissions.BasePermission):
    """Admins can modify, others read-only."""
    
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        return request.user and request.user.role == 'admin'

class IsOwnerOrAdmin(permissions.BasePermission):
    """Owner can modify their data, admins can modify any."""
    
    def has_object_permission(self, request, view, obj):
        if request.user.role == 'admin':
            return True
        return obj.id == request.user.id

class UserViewSet(viewsets.ModelViewSet):
    """SECURE: Different permissions per action."""
    queryset = User.objects.all()
    
    def get_permissions(self):
        """Set permissions based on action."""
        if self.action in ['create', 'list']:
            permission_classes = [IsAdminUser]
        elif self.action in ['update', 'partial_update', 'destroy']:
            permission_classes = [IsOwnerOrAdmin]
        else:
            permission_classes = [permissions.IsAuthenticated]
        
        return [permission() for permission in permission_classes]
    
    @action(detail=False, methods=['post'], permission_classes=[IsAdminUser])
    def bulk_delete(self, request):
        """Admin-only bulk delete."""
        user_ids = request.data.get('user_ids', [])
        
        # Prevent deleting yourself
        if request.user.id in user_ids:
            return Response(
                {'error': 'Cannot delete your own account'},
                status=400
            )
        
        deleted_count, _ = User.objects.filter(id__in=user_ids).delete()
        return Response({'deleted': deleted_count})
```

## Complete Application Examples

### Complete Flask Application with Authorization

```python
from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')
    
    def generate_token(self):
        payload = {
            'user_id': self.id,
            'role': self.role,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Authorization decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'Token required'}), 401
        
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user = User.query.get(payload['user_id'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            if g.current_user.role not in roles:
                return jsonify({'error': f'Requires: {", ".join(roles)}'}), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator

# Public endpoints
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    
    # Field whitelist
    allowed = {'username', 'password', 'email'}
    user_data = {k: v for k, v in data.items() if k in allowed}
    
    user = User(
        username=user_data['username'],
        password=hash_password(user_data['password']),
        role='user'  # Always user on registration
    )
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'id': user.id, 'username': user.username}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    
    if user and verify_password(user.password, data['password']):
        token = user.generate_token()
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401

# User endpoints
@app.route('/api/users', methods=['GET'])
@token_required
@require_role('user', 'admin')
def list_users():
    users = User.query.limit(100).all()
    return jsonify([{'id': u.id, 'username': u.username} for u in users])

@app.route('/api/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())

# Admin endpoints
@app.route('/api/admin/users', methods=['GET'])
@token_required
@require_role('admin')
def admin_list_users():
    users = User.query.all()
    return jsonify([u.to_dict(include_sensitive=True) for u in users])

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required
@require_role('admin')
def delete_user(user_id):
    if user_id == g.current_user.id:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'status': 'deleted'})

@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
@token_required
@require_role('admin')
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.json.get('role')
    
    valid_roles = ['user', 'moderator', 'admin']
    if new_role not in valid_roles:
        return jsonify({'error': 'Invalid role'}), 400
    
    user.role = new_role
    db.session.commit()
    
    return jsonify({'user_id': user.id, 'role': user.role})

if __name__ == '__main__':
    app.run(debug=True)
```

## Key Takeaways

1. **Never trust client input** for authorization decisions
2. **Explicit authorization** required for every privileged operation
3. **Separate routes** for different HTTP methods when permissions differ
4. **Centralized authorization logic** using decorators/middleware
5. **Default deny** - require explicit permission grants
6. **Validate all inputs** including roles, permissions, and resource IDs
7. **Audit logging** for all privileged operations
8. **Test with multiple roles** to verify authorization

## Next Steps

- **[Lab](lab/api05-function-auth-lab/)** - Practice implementing secure function-level authorization
- **[Prevention](prevention.md)** - Review comprehensive prevention strategies
- **[Attack Vectors](attack-vectors.md)** - Understand common exploitation techniques
