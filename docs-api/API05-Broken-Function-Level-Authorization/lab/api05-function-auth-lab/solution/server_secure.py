from flask import Flask, request, jsonify, g
from flask_cors import CORS
import jwt
import hashlib
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
CORS(app)

# Secret key - in production, use environment variable
app.config['SECRET_KEY'] = 'secure-secret-key-from-env'

# In-memory database (same as vulnerable version for comparison)
users_db = {
    1: {
        'id': 1,
        'username': 'alice',
        'password': hashlib.sha256('password123'.encode()).hexdigest(),
        'email': 'alice@example.com',
        'role': 'user',
        'created_at': '2024-01-01T10:00:00Z'
    },
    2: {
        'id': 2,
        'username': 'bob',
        'password': hashlib.sha256('password123'.encode()).hexdigest(),
        'email': 'bob@example.com',
        'role': 'user',
        'created_at': '2024-01-02T10:00:00Z'
    },
    3: {
        'id': 3,
        'username': 'admin',
        'password': hashlib.sha256('admin123'.encode()).hexdigest(),
        'email': 'admin@example.com',
        'role': 'admin',
        'created_at': '2024-01-01T09:00:00Z'
    },
}

products_db = {
    1: {'id': 1, 'name': 'Laptop', 'price': 999.99, 'stock': 50},
    2: {'id': 2, 'name': 'Mouse', 'price': 29.99, 'stock': 200},
    3: {'id': 3, 'name': 'Keyboard', 'price': 79.99, 'stock': 150},
}

settings_db = {
    'site_name': 'SecureShop',
    'maintenance_mode': False,
    'registration_enabled': True,
    'max_login_attempts': 5,
}

audit_log = []
next_user_id = 4

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token(user):
    payload = {
        'user_id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def log_action(action, details=None):
    """Log privileged actions for audit trail."""
    entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'action': action,
        'actor': g.current_user['username'] if hasattr(g, 'current_user') else 'system',
        'actor_role': g.current_user['role'] if hasattr(g, 'current_user') else 'system'
    }
    if details:
        entry.update(details)
    audit_log.append(entry)

# SECURE: Authentication decorator
def login_required(f):
    """Verify user is authenticated."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        g.current_user = users_db.get(payload['user_id'])
        if not g.current_user:
            return jsonify({'error': 'User not found'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# SECURE: Admin authorization decorator
def admin_required(f):
    """Verify user is authenticated AND has admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check authentication
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        g.current_user = users_db.get(payload['user_id'])
        if not g.current_user:
            return jsonify({'error': 'User not found'}), 401
        
        # CRITICAL: Check admin role
        if g.current_user['role'] != 'admin':
            log_action('unauthorized_access_attempt', {
                'endpoint': request.endpoint,
                'method': request.method,
                'path': request.path
            })
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# Public endpoints
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'version': 'secure'})

@app.route('/api/register', methods=['POST'])
def register():
    """SECURE: Whitelist allowed fields, server assigns role."""
    global next_user_id
    data = request.json
    
    # SECURE: Whitelist only allowed fields
    allowed_fields = {'username', 'email', 'password'}
    safe_data = {k: v for k, v in data.items() if k in allowed_fields}
    
    username = safe_data.get('username')
    password = safe_data.get('password')
    email = safe_data.get('email')
    
    if not username or not password or not email:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if username exists
    for user in users_db.values():
        if user['username'] == username:
            return jsonify({'error': 'Username already exists'}), 400
    
    # SECURE: Server assigns role, NEVER trust client input
    new_user = {
        'id': next_user_id,
        'username': username,
        'password': hash_password(password),
        'email': email,
        'role': 'user',  # Fixed value - server controlled
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    
    users_db[next_user_id] = new_user
    next_user_id += 1
    
    token = generate_token(new_user)
    
    log_action('user_registration', {'user_id': new_user['id'], 'username': username})
    
    return jsonify({
        'user': {
            'id': new_user['id'],
            'username': new_user['username'],
            'email': new_user['email'],
            'role': new_user['role']
        },
        'token': token
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    
    user = None
    for u in users_db.values():
        if u['username'] == username:
            user = u
            break
    
    if not user or user['password'] != hash_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    token = generate_token(user)
    
    log_action('user_login', {'user_id': user['id']})
    
    return jsonify({
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        },
        'token': token
    })

# User endpoints - require authentication only
@app.route('/api/users', methods=['GET'])
@login_required
def list_users():
    """Public user list - limited information."""
    user_list = [
        {'id': u['id'], 'username': u['username']}
        for u in users_db.values()
    ]
    return jsonify(user_list)

@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    """Get user details - limited for non-admins."""
    user = users_db.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Return public info only
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'created_at': user['created_at']
    })

@app.route('/api/users/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current user's own information."""
    return jsonify({
        'id': g.current_user['id'],
        'username': g.current_user['username'],
        'email': g.current_user['email'],
        'role': g.current_user['role'],
        'created_at': g.current_user['created_at']
    })

# Product endpoints - different authorization for different methods
@app.route('/api/products', methods=['GET'])
@login_required
def list_products():
    """Anyone can view products."""
    return jsonify(list(products_db.values()))

@app.route('/api/products/<int:product_id>', methods=['GET'])
@login_required
def get_product(product_id):
    """Anyone can view a product."""
    product = products_db.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    return jsonify(product)

@app.route('/api/products', methods=['POST'])
@admin_required  # SECURE: Only admins can create
def create_product():
    """SECURE: Only admins can create products."""
    data = request.json
    product_id = max(products_db.keys()) + 1 if products_db else 1
    
    new_product = {
        'id': product_id,
        'name': data.get('name'),
        'price': data.get('price'),
        'stock': data.get('stock', 0)
    }
    
    products_db[product_id] = new_product
    
    log_action('product_created', {'product_id': product_id})
    
    return jsonify(new_product), 201

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@admin_required  # SECURE: Only admins can update
def update_product(product_id):
    """SECURE: Only admins can update products."""
    product = products_db.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    data = request.json
    product['name'] = data.get('name', product['name'])
    product['price'] = data.get('price', product['price'])
    product['stock'] = data.get('stock', product['stock'])
    
    log_action('product_updated', {'product_id': product_id})
    
    return jsonify(product)

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@admin_required  # SECURE: Only admins can delete
def delete_product(product_id):
    """SECURE: Only admins can delete products."""
    if product_id not in products_db:
        return jsonify({'error': 'Product not found'}), 404
    
    deleted_product = products_db.pop(product_id)
    
    log_action('product_deleted', {'product_id': product_id, 'name': deleted_product['name']})
    
    return jsonify({'status': 'deleted', 'product_id': product_id})

# Admin endpoints - all require admin role
@app.route('/api/admin/users', methods=['GET'])
@admin_required  # SECURE: Admin only
def admin_list_users():
    """SECURE: Only admins can see full user details."""
    user_list = [
        {
            'id': u['id'],
            'username': u['username'],
            'email': u['email'],
            'role': u['role'],
            'created_at': u['created_at']
        }
        for u in users_db.values()
    ]
    return jsonify(user_list)

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required  # SECURE: Admin only
def admin_delete_user(user_id):
    """SECURE: Only admins can delete users."""
    if user_id not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    # SECURE: Prevent self-deletion
    if user_id == g.current_user['id']:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    deleted_user = users_db.pop(user_id)
    
    log_action('user_deleted', {'user_id': user_id, 'username': deleted_user['username']})
    
    return jsonify({'status': 'deleted', 'user_id': user_id})

@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@admin_required  # SECURE: Admin only
def admin_update_role(user_id):
    """SECURE: Only admins can change user roles."""
    user = users_db.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    new_role = request.json.get('role')
    valid_roles = ['user', 'moderator', 'admin']
    
    if new_role not in valid_roles:
        return jsonify({'error': 'Invalid role'}), 400
    
    # SECURE: Prevent changing own role
    if user_id == g.current_user['id']:
        return jsonify({'error': 'Cannot modify your own role'}), 400
    
    old_role = user['role']
    user['role'] = new_role
    
    log_action('role_updated', {
        'user_id': user_id,
        'username': user['username'],
        'old_role': old_role,
        'new_role': new_role
    })
    
    return jsonify({
        'user_id': user_id,
        'username': user['username'],
        'role': user['role']
    })

@app.route('/api/admin/users/bulk-delete', methods=['POST'])
@admin_required  # SECURE: Admin only
def bulk_delete_users():
    """SECURE: Only admins can perform bulk deletions."""
    user_ids = request.json.get('user_ids', [])
    
    # SECURE: Validate input
    if not isinstance(user_ids, list) or not user_ids:
        return jsonify({'error': 'Invalid user_ids'}), 400
    
    # SECURE: Limit bulk operation size
    if len(user_ids) > 100:
        return jsonify({'error': 'Bulk operations limited to 100 users'}), 400
    
    # SECURE: Prevent self-deletion
    if g.current_user['id'] in user_ids:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    deleted = []
    for user_id in user_ids:
        if user_id in users_db:
            deleted_user = users_db.pop(user_id)
            deleted.append(deleted_user['username'])
    
    log_action('bulk_delete_users', {'count': len(deleted), 'usernames': deleted})
    
    return jsonify({'status': 'deleted', 'count': len(deleted), 'users': deleted})

@app.route('/api/admin/audit-log', methods=['GET'])
@admin_required  # SECURE: Admin only
def get_audit_log():
    """SECURE: Only admins can view audit logs."""
    return jsonify(audit_log)

# Settings - admin only
@app.route('/api/settings', methods=['GET'])
@admin_required  # SECURE: Admin only
def get_settings():
    """SECURE: Only admins can view settings."""
    return jsonify(settings_db)

@app.route('/api/settings', methods=['PUT'])
@admin_required  # SECURE: Admin only
def update_settings():
    """SECURE: Only admins can modify settings."""
    data = request.json
    
    # SECURE: Whitelist allowed settings
    allowed_settings = {'site_name', 'maintenance_mode', 'registration_enabled', 'max_login_attempts'}
    
    changes = {}
    for key, value in data.items():
        if key in allowed_settings:
            settings_db[key] = value
            changes[key] = value
    
    log_action('settings_updated', {'changes': changes})
    
    return jsonify(settings_db)

# SECURE: No debug endpoints in production!
# The /api/debug/* endpoints have been removed

# Info endpoint
@app.route('/api/info', methods=['GET'])
def info():
    return jsonify({
        'lab': 'API05 - Broken Function Level Authorization (SECURE)',
        'description': 'This is the secure implementation with proper authorization',
        'security_features': [
            'Role-based access control (RBAC)',
            'Admin-only endpoints protected with @admin_required',
            'Field whitelisting in registration',
            'Server-side role assignment',
            'Method-specific authorization',
            'No debug endpoints',
            'Audit logging for privileged operations',
            'Self-modification prevention'
        ],
        'test_accounts': [
            {'username': 'alice', 'password': 'password123', 'role': 'user'},
            {'username': 'bob', 'password': 'password123', 'role': 'user'},
            {'username': 'admin', 'password': 'admin123', 'role': 'admin'}
        ]
    })

if __name__ == '__main__':
    print("=" * 60)
    print("API05 - SECURE Implementation")
    print("=" * 60)
    print("\nStarting secure API server on http://localhost:5000")
    print("\nSecurity features enabled:")
    print("  ✓ Role-based access control")
    print("  ✓ Admin endpoint protection")
    print("  ✓ Field whitelisting")
    print("  ✓ Server-side role assignment")
    print("  ✓ No debug endpoints")
    print("  ✓ Audit logging")
    print("\nTry the attacks from the vulnerable version - they should all fail!")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
