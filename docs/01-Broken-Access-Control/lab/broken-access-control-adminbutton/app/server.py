"""
OWASP Top 10 Lab: Broken Access Control - Admin Button Vulnerability

This lab demonstrates a common broken access control vulnerability where
administrative functions are hidden in the UI but not properly protected
on the server side.

EDUCATIONAL PURPOSE ONLY
This is a safe, isolated demonstration. No real data is at risk.
"""

from flask import Flask, render_template, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Simulated user database (in-memory for this demo)
users = {
    'alice': {
        'password': generate_password_hash('password123'),
        'role': 'user',
        'email': 'alice@example.com'
    },
    'bob': {
        'password': generate_password_hash('password123'),
        'role': 'user',
        'email': 'bob@example.com'
    },
    'admin': {
        'password': generate_password_hash('admin123'),
        'role': 'admin',
        'email': 'admin@example.com'
    }
}

# Simulated sensitive data
sensitive_data = [
    {'id': 1, 'secret': 'API Key: sk_test_123456789'},
    {'id': 2, 'secret': 'Database Password: db_pass_xyz'},
    {'id': 3, 'secret': 'Admin Token: admin_token_abc'},
]


@app.route('/')
def home():
    """Home page - shows different content based on login status"""
    username = session.get('username')
    role = session.get('role')
    return render_template('home.html', username=username, role=role)


@app.route('/login', methods=['POST'])
def login():
    """Login endpoint"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username in users and check_password_hash(users[username]['password'], password):
        session['username'] = username
        session['role'] = users[username]['role']
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'role': users[username]['role']
        })
    
    return jsonify({
        'success': False,
        'message': 'Invalid credentials'
    }), 401


@app.route('/logout')
def logout():
    """Logout endpoint"""
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'})


@app.route('/admin')
def admin_panel():
    """
    VULNERABILITY: This endpoint is accessible to anyone!
    
    The UI hides the "Admin" button for non-admin users,
    but the endpoint itself has no authorization check.
    
    Anyone who knows the URL can access this page.
    """
    # VULNERABLE: No authorization check here!
    # Should check: if session.get('role') != 'admin': abort(403)
    
    return render_template('admin.html', username=session.get('username'))


@app.route('/api/admin/secrets')
def get_secrets():
    """
    VULNERABILITY: API endpoint with no authorization!
    
    This endpoint returns sensitive data but doesn't check
    if the user is actually an admin.
    """
    # VULNERABLE: No authorization check!
    # Should check: if session.get('role') != 'admin': abort(403)
    
    return jsonify({
        'secrets': sensitive_data
    })


@app.route('/api/user/info')
def user_info():
    """Get current user information (this one is properly protected)"""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session['username']
    return jsonify({
        'username': username,
        'role': session.get('role'),
        'email': users[username]['email']
    })


if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: Broken Access Control")
    print("=" * 60)
    print("\nTest Accounts:")
    print("  Regular User 1: alice / password123")
    print("  Regular User 2: bob / password123")
    print("  Administrator:  admin / admin123")
    print("\nApplication running on http://localhost:5000")
    print("\nThis is a SAFE EDUCATIONAL ENVIRONMENT")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
