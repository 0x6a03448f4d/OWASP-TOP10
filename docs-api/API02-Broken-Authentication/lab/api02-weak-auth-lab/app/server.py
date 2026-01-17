"""
OWASP API Security Top 10 Lab: API02 - Broken Authentication

This lab demonstrates critical authentication vulnerabilities in APIs:
1. Weak JWT implementation (HS256 with weak secret)
2. No rate limiting on login endpoint
3. Long-lived tokens (no expiration)
4. Weak password policies

EDUCATIONAL PURPOSE ONLY
This is a safe, isolated demonstration. No real data is at risk.
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import os
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# VULNERABILITY 1: Weak JWT secret (easily crackable)
JWT_SECRET = 'secret123'  # This is a WEAK secret!

CORS(app)

# Simulated user database (in-memory for demo)
users = {
    1: {
        'id': 1,
        'username': 'alice',
        'email': 'alice@example.com',
        'password': generate_password_hash('password123'),  # Weak password accepted!
        'full_name': 'Alice Smith',
        'role': 'user'
    },
    2: {
        'id': 2,
        'username': 'bob',
        'email': 'bob@example.com',
        'password': generate_password_hash('admin'),  # Very weak password!
        'full_name': 'Bob Johnson',
        'role': 'user'
    },
    3: {
        'id': 3,
        'username': 'admin',
        'email': 'admin@example.com',
        'password': generate_password_hash('admin123'),
        'full_name': 'Admin User',
        'role': 'admin'
    }
}

# User data (sensitive information)
user_data = {
    1: {'credit_card': '**** **** **** 1234', 'ssn': '***-**-5678'},
    2: {'credit_card': '**** **** **** 5678', 'ssn': '***-**-9012'},
    3: {'credit_card': '**** **** **** 9999', 'ssn': '***-**-0000'},
}


@app.route('/')
def index():
    """Serve the API testing interface"""
    return render_template('index.html')


@app.route('/api/register', methods=['POST'])
def register():
    """
    VULNERABILITY: Weak password policy
    
    This endpoint accepts ANY password without validation:
    - No minimum length requirement
    - No complexity requirements
    - Accepts common passwords like "123456", "password", "admin"
    
    SECURE VERSION would:
    - Require minimum 12 characters
    - Require uppercase, lowercase, numbers, special chars
    - Check against common password lists
    - Check against breach databases (Have I Been Pwned)
    """
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    if not username or not email or not password:
        return jsonify({'error': 'All fields required'}), 400
    
    # Check if user exists
    for user in users.values():
        if user['username'] == username or user['email'] == email:
            return jsonify({'error': 'User already exists'}), 400
    
    # VULNERABILITY: No password strength validation!
    # Accepts: "123456", "password", "admin", "abc"
    
    # Create new user
    user_id = max(users.keys()) + 1
    users[user_id] = {
        'id': user_id,
        'username': username,
        'email': email,
        'password': generate_password_hash(password),
        'full_name': data.get('full_name', ''),
        'role': 'user'
    }
    
    return jsonify({
        'message': 'User registered successfully',
        'user_id': user_id
    }), 201


@app.route('/api/login', methods=['POST'])
def login():
    """
    VULNERABILITY 1: No rate limiting
    VULNERABILITY 2: Weak JWT secret
    VULNERABILITY 3: No token expiration
    
    This endpoint has multiple critical flaws:
    
    1. NO RATE LIMITING:
       - Allows unlimited login attempts
       - Enables brute force attacks
       - Enables credential stuffing attacks
       - No account lockout mechanism
    
    2. WEAK JWT SECRET:
       - Uses "secret123" as the signing key
       - Can be cracked with tools like hashcat
       - Allows attacker to forge any token
    
    3. NO TOKEN EXPIRATION:
       - Tokens are valid forever
       - Stolen tokens never expire
       - No refresh token mechanism
       - No way to revoke access
    
    SECURE VERSION would:
    - Implement rate limiting (5 attempts per minute)
    - Use RS256 with strong private key
    - Set 15-minute expiration on access tokens
    - Implement refresh token mechanism
    - Lock account after 10 failed attempts
    """
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    
    # Find user by email
    user = None
    for u in users.values():
        if u['email'] == email:
            user = u
            break
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Verify password
    if not check_password_hash(user['password'], password):
        # VULNERABILITY: No failed attempt tracking!
        # VULNERABILITY: No account lockout!
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # VULNERABILITY: Weak JWT implementation
    # Using HS256 with weak secret and no expiration
    token = jwt.encode(
        {
            'user_id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
            # MISSING: 'exp' (expiration)
            # MISSING: 'iat' (issued at)
            # MISSING: 'jti' (unique token ID)
        },
        JWT_SECRET,  # WEAK SECRET!
        algorithm='HS256'  # Symmetric algorithm (less secure than RS256)
    )
    
    return jsonify({
        'access_token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'full_name': user['full_name'],
            'role': user['role']
        }
    }), 200


@app.route('/api/me')
def get_current_user():
    """
    Get current authenticated user info
    
    This endpoint verifies the JWT token
    """
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401
    
    token = auth_header.replace('Bearer ', '')
    
    try:
        # VULNERABILITY: Accepts weak tokens signed with weak secret
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=['HS256']  # Should be RS256 in production
        )
        
        user_id = payload['user_id']
        user = users.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'full_name': user['full_name'],
            'role': user['role']
        })
        
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401


@app.route('/api/sensitive-data')
def get_sensitive_data():
    """
    Get sensitive user data
    Demonstrates why authentication security is critical
    """
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401
    
    token = auth_header.replace('Bearer ', '')
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload['user_id']
        
        # Return sensitive data
        sensitive = user_data.get(user_id, {})
        
        return jsonify({
            'user_id': user_id,
            'sensitive_data': sensitive,
            'warning': 'This data should be protected by strong authentication!'
        })
        
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401


@app.route('/api/admin/users')
def admin_users():
    """
    Admin endpoint - should be protected
    
    VULNERABILITY: Can be accessed by forging JWT with role=admin
    """
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401
    
    token = auth_header.replace('Bearer ', '')
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        
        # Check admin role
        if payload.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        # Return all users
        user_list = [
            {
                'id': u['id'],
                'username': u['username'],
                'email': u['email'],
                'role': u['role']
            }
            for u in users.values()
        ]
        
        return jsonify({
            'users': user_list,
            'warning': 'Attacker can forge token with admin role!'
        })
        
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401


@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    return jsonify({
        'total_users': len(users),
        'jwt_algorithm': 'HS256',
        'jwt_secret_hint': 'Very weak secret!',
        'rate_limiting': 'DISABLED - Vulnerable to brute force!',
        'token_expiration': 'NONE - Tokens valid forever!',
        'password_policy': 'WEAK - Any password accepted!'
    })


# Error handlers
@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        'error': 'Authentication required',
        'message': 'Please provide a valid JWT token'
    }), 401


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔓 Broken Authentication Vulnerability Lab (API02)")
    print("="*70)
    print("✓ API running on http://localhost:5000")
    print("✓ Educational demonstration - SAFE isolated environment")
    print("✓ This lab demonstrates API2:2023 - Broken Authentication")
    print("\nVulnerabilities:")
    print("  1. 🔴 No rate limiting (brute force possible)")
    print("  2. 🔴 Weak JWT secret 'secret123' (crackable)")
    print("  3. 🔴 No token expiration (valid forever)")
    print("  4. 🔴 Weak password policy (any password accepted)")
    print("\nTest Accounts:")
    print("  • alice@example.com / password123")
    print("  • bob@example.com / admin")
    print("  • admin@example.com / admin123")
    print("\nExploit Opportunities:")
    print("  • Brute force passwords (no rate limit)")
    print("  • Crack JWT secret and forge tokens")
    print("  • Create account with weak password")
    print("  • Escalate to admin by forging token")
    print("="*70 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
