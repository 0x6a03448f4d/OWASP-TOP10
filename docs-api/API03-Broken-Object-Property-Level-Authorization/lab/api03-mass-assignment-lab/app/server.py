from flask import Flask, request, jsonify
from functools import wraps
import jwt
import bcrypt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

# In-memory database (resets on restart)
users_db = {}
user_id_counter = 1

# Pre-seed users
def init_db():
    global user_id_counter
    
    users = [
        {
            'username': 'alice',
            'email': 'alice@example.com',
            'password': 'password123',
            'is_admin': False,
            'salary': 65000,
            'role': 'user'
        },
        {
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'password456',
            'is_admin': False,
            'salary': 70000,
            'role': 'user'
        },
        {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'admin123',
            'is_admin': True,
            'salary': 150000,
            'role': 'admin'
        }
    ]
    
    for user_data in users:
        password = user_data.pop('password')
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        user = {
            'id': user_id_counter,
            'username': user_data['username'],
            'email': user_data['email'],
            'password_hash': password_hash,
            'is_admin': user_data['is_admin'],
            'salary': user_data['salary'],
            'role': user_data['role'],
            'api_key': f"key_{user_data['role']}_{user_data['username']}",
            'created_at': '2024-01-15'
        }
        
        users_db[user_id_counter] = user
        user_id_counter += 1

init_db()

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_db.get(data['user_id'])
            
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if not current_user.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Routes
@app.route('/')
def index():
    return jsonify({'message': 'API03 Mass Assignment Lab'})

@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy', 'users_count': len(users_db)})

@app.route('/api/register', methods=['POST'])
def register():
    global user_id_counter
    
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if user exists
    for user in users_db.values():
        if user['username'] == username:
            return jsonify({'error': 'Username already exists'}), 400
        if user['email'] == email:
            return jsonify({'error': 'Email already exists'}), 400
    
    # Create new user
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # ❌ VULNERABILITY: Accepts additional fields from request
    # User could set is_admin=true during registration
    new_user = {
        'id': user_id_counter,
        'username': username,
        'email': email,
        'password_hash': password_hash,
        'is_admin': data.get('is_admin', False),  # ❌ Should always be False!
        'salary': data.get('salary', 50000),      # ❌ Should be set by admin/HR
        'role': data.get('role', 'user'),         # ❌ Should be 'user' always
        'api_key': f"key_user_{username}",
        'created_at': datetime.utcnow().isoformat()
    }
    
    users_db[user_id_counter] = new_user
    user_id_counter += 1
    
    return jsonify({
        'message': 'User registered successfully',
        'user_id': new_user['id']
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
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Generate token
    token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'token': token,
        'user_id': user['id'],
        'username': user['username']
    })

@app.route('/api/users/me')
@token_required
def get_me(current_user):
    # ❌ VULNERABILITY: Excessive Data Exposure
    # Returns ALL fields including sensitive data
    return jsonify(current_user)

@app.route('/api/users/<int:user_id>')
@token_required
def get_user(current_user, user_id):
    user = users_db.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # ❌ VULNERABILITY: Excessive Data Exposure
    # Returns ALL fields to any authenticated user
    # Should filter based on relationship (self vs other) and role (admin vs user)
    return jsonify(user)

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    # Basic authorization: users can only update their own profile (unless admin)
    if current_user['id'] != user_id and not current_user.get('is_admin'):
        return jsonify({'error': 'Forbidden'}), 403
    
    user = users_db.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.json
    
    # ❌ VULNERABILITY: Mass Assignment
    # Accepts ALL fields from request without validation
    # User can set is_admin=true, modify salary, change role, etc.
    for key, value in data.items():
        if key in user and key != 'id':  # Prevent ID change
            user[key] = value
    
    return jsonify({
        'message': 'User updated successfully',
        'user': user  # ❌ Also returns all sensitive fields
    })

@app.route('/api/admin/users')
@admin_required
def admin_list_users(current_user):
    # ❌ VULNERABILITY: Returns ALL user data including sensitive fields
    return jsonify({
        'users': list(users_db.values())
    })

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(current_user, user_id):
    if user_id not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    if user_id == current_user['id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    del users_db[user_id]
    return jsonify({'message': 'User deleted successfully'})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=True)
