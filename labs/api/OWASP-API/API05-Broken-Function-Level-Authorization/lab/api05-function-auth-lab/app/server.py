from flask import Flask, request, jsonify, render_template, g
from flask_cors import CORS
import jwt
import hashlib
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
CORS(app)

# Secret key for JWT
app.config['SECRET_KEY'] = 'vulnerable-secret-key-12345'

# In-memory database
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
    'site_name': 'VulnShop',
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
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Authentication decorator (only checks if logged in)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        g.current_user = users_db.get(payload['user_id'])
        return f(*args, **kwargs)
    return decorated_function

# Web interface
@app.route('/')
def index():
    return render_template('index.html')

# Public endpoints
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

@app.route('/api/register', methods=['POST'])
def register():
    global next_user_id
    data = request.json
    
    # VULNERABILITY 1: Mass assignment - accepts role from user input
    # SECURITY FLAW: Client controls their own privilege level!
    # An attacker can register as admin by adding {"role": "admin"} to the request
    # NEVER trust client-provided data for security-critical fields like roles/permissions
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role', 'user')  # VULNERABLE: User can specify role!
    
    if not username or not password or not email:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if username exists
    for user in users_db.values():
        if user['username'] == username:
            return jsonify({'error': 'Username already exists'}), 400
    
    new_user = {
        'id': next_user_id,
        'username': username,
        'password': hash_password(password),
        'email': email,
        'role': role,  # VULNERABLE: Trusts client input!
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }
    
    users_db[next_user_id] = new_user
    next_user_id += 1
    
    token = generate_token(new_user)
    
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
    
    # Find user
    user = None
    for u in users_db.values():
        if u['username'] == username:
            user = u
            break
    
    if not user or user['password'] != hash_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    token = generate_token(user)
    
    return jsonify({
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        },
        'token': token
    })

# User endpoints (require authentication)
@app.route('/api/users', methods=['GET'])
@login_required
def list_users():
    # Returns basic user info for all authenticated users
    user_list = [
        {'id': u['id'], 'username': u['username']}
        for u in users_db.values()
    ]
    return jsonify(user_list)

@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    user = users_db.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Return public info
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'created_at': user['created_at']
    })

@app.route('/api/users/me', methods=['GET'])
@login_required
def get_current_user():
    return jsonify({
        'id': g.current_user['id'],
        'username': g.current_user['username'],
        'email': g.current_user['email'],
        'role': g.current_user['role'],
        'created_at': g.current_user['created_at']
    })

# VULNERABILITY 2: Admin endpoints without authorization checks
@app.route('/api/admin/users', methods=['GET'])
@login_required  # Only checks authentication, NOT admin role!
def admin_list_users():
    """VULNERABLE: Any authenticated user can access this endpoint."""
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
@login_required  # VULNERABLE: No admin check!
def admin_delete_user(user_id):
    """VULNERABLE: Any authenticated user can delete any user."""
    if user_id not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    deleted_user = users_db.pop(user_id)
    
    audit_log.append({
        'timestamp': datetime.utcnow().isoformat(),
        'action': 'delete_user',
        'actor': g.current_user['username'],
        'target': deleted_user['username']
    })
    
    return jsonify({'status': 'deleted', 'user_id': user_id})

@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@login_required  # VULNERABLE: No admin check!
def admin_update_role(user_id):
    """VULNERABLE: Any authenticated user can change user roles."""
    user = users_db.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    new_role = request.json.get('role')
    valid_roles = ['user', 'moderator', 'admin']
    
    if new_role not in valid_roles:
        return jsonify({'error': 'Invalid role'}), 400
    
    old_role = user['role']
    user['role'] = new_role
    
    audit_log.append({
        'timestamp': datetime.utcnow().isoformat(),
        'action': 'update_role',
        'actor': g.current_user['username'],
        'target': user['username'],
        'old_role': old_role,
        'new_role': new_role
    })
    
    return jsonify({
        'user_id': user_id,
        'username': user['username'],
        'role': user['role']
    })

# VULNERABILITY 3: Method-based authorization gap
@app.route('/api/products/<int:product_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def product_endpoint(product_id):
    """VULNERABLE: GET checks auth, but PUT/DELETE don't check admin role."""
    product = products_db.get(product_id)
    
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    if request.method == 'GET':
        # Anyone can view
        return jsonify(product)
    
    elif request.method == 'PUT':
        # VULNERABLE: Should require admin, but doesn't check!
        data = request.json
        product['name'] = data.get('name', product['name'])
        product['price'] = data.get('price', product['price'])
        product['stock'] = data.get('stock', product['stock'])
        
        audit_log.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'update_product',
            'actor': g.current_user['username'],
            'product_id': product_id
        })
        
        return jsonify(product)
    
    elif request.method == 'DELETE':
        # VULNERABLE: Should require admin, but doesn't check!
        deleted_product = products_db.pop(product_id)
        
        audit_log.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'delete_product',
            'actor': g.current_user['username'],
            'product_id': product_id
        })
        
        return jsonify({'status': 'deleted', 'product_id': product_id})

@app.route('/api/products', methods=['GET', 'POST'])
@login_required
def products_endpoint():
    if request.method == 'GET':
        return jsonify(list(products_db.values()))
    
    elif request.method == 'POST':
        # VULNERABLE: Should require admin!
        data = request.json
        product_id = max(products_db.keys()) + 1
        
        new_product = {
            'id': product_id,
            'name': data.get('name'),
            'price': data.get('price'),
            'stock': data.get('stock', 0)
        }
        
        products_db[product_id] = new_product
        
        return jsonify(new_product), 201

# VULNERABILITY 4: Hidden debug endpoint
@app.route('/api/debug/users', methods=['GET'])
@login_required
def debug_users():
    """VULNERABLE: Debug endpoint that exposes sensitive data."""
    return jsonify({
        'users': users_db,
        'total_count': len(users_db)
    })

# VULNERABILITY 5: Settings endpoint without proper authorization
@app.route('/api/settings', methods=['GET', 'PUT'])
@login_required
def settings():
    """VULNERABLE: Any authenticated user can view/modify system settings."""
    if request.method == 'GET':
        return jsonify(settings_db)
    
    elif request.method == 'PUT':
        # VULNERABLE: Should require admin!
        data = request.json
        
        for key, value in data.items():
            if key in settings_db:
                settings_db[key] = value
        
        audit_log.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'update_settings',
            'actor': g.current_user['username'],
            'changes': data
        })
        
        return jsonify(settings_db)

# VULNERABILITY 6: Audit log access
@app.route('/api/admin/audit-log', methods=['GET'])
@login_required
def get_audit_log():
    """VULNERABLE: Any authenticated user can view audit logs."""
    return jsonify(audit_log)

# VULNERABILITY 7: Bulk operations
@app.route('/api/admin/users/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_users():
    """VULNERABLE: No admin check for bulk deletion."""
    user_ids = request.json.get('user_ids', [])
    
    deleted = []
    for user_id in user_ids:
        if user_id in users_db:
            deleted_user = users_db.pop(user_id)
            deleted.append(deleted_user['username'])
    
    audit_log.append({
        'timestamp': datetime.utcnow().isoformat(),
        'action': 'bulk_delete_users',
        'actor': g.current_user['username'],
        'deleted': deleted
    })
    
    return jsonify({'status': 'deleted', 'count': len(deleted), 'users': deleted})

# Info endpoint to help with lab
@app.route('/api/info', methods=['GET'])
def info():
    return jsonify({
        'lab': 'API05 - Broken Function Level Authorization',
        'description': 'This API has multiple function-level authorization vulnerabilities',
        'test_accounts': [
            {'username': 'alice', 'password': 'password123', 'role': 'user'},
            {'username': 'bob', 'password': 'password123', 'role': 'user'},
            {'username': 'admin', 'password': 'admin123', 'role': 'admin'}
        ],
        'endpoints': {
            'public': ['/api/health', '/api/register', '/api/login', '/api/info'],
            'authenticated': ['/api/users', '/api/users/<id>', '/api/users/me', '/api/products'],
            'admin': [
                '/api/admin/users',
                '/api/admin/users/<id> [DELETE]',
                '/api/admin/users/<id>/role [PUT]',
                '/api/admin/audit-log',
                '/api/admin/users/bulk-delete'
            ],
            'vulnerable_hidden': ['/api/debug/users', '/api/settings']
        }
    })

if __name__ == '__main__':
    print("=" * 60)
    print("API05 - Broken Function Level Authorization Lab")
    print("=" * 60)
    print("\nStarting vulnerable API server on http://localhost:5000")
    print("\nTest accounts:")
    print("  User:  alice / password123")
    print("  User:  bob   / password123")
    print("  Admin: admin / admin123")
    print("\nVulnerabilities to discover:")
    print("  1. Mass assignment - role parameter in registration")
    print("  2. Admin endpoints without authorization checks")
    print("  3. Method-based authorization gaps")
    print("  4. Hidden debug endpoints")
    print("  5. Settings manipulation")
    print("  6. Audit log exposure")
    print("  7. Bulk operations without role check")
    print("\nVisit http://localhost:5000 for the web interface")
    print("=" * 60)
    
    # NOTE: debug=True is intentional for this lab environment only
    # NEVER use debug=True in production - it allows arbitrary code execution!
    app.run(host='0.0.0.0', port=5000, debug=True)
