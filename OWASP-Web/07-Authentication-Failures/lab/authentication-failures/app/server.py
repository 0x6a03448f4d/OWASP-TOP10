"""
OWASP Top 10 Lab: Authentication Failures

EDUCATIONAL PURPOSE ONLY
This is a safe, isolated demonstration of Authentication Failures vulnerabilities.
"""

from flask import Flask, render_template, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "weak_secret_key_for_demo"  # VULNERABLE: Weak secret

# Simulated user database
users = {
    'alice': {'password': 'password123', 'role': 'user'},  # VULNERABLE: Weak password
    'bob': {'password': 'admin', 'role': 'user'},
    'admin': {'password': 'admin123', 'role': 'admin'}
}

failed_attempts = {}

@app.route('/')
def home():
    return render_template('home.html', 
                         username=session.get('username'),
                         role=session.get('role'))

@app.route('/login', methods=['POST'])
def login():
    """VULNERABLE: No rate limiting, weak session management"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # VULNERABLE: No brute force protection
    if username in users and users[username]['password'] == password:
        session['username'] = username
        session['role'] = users[username]['role']
        # VULNERABLE: Session ID not regenerated
        return jsonify({'success': True, 'role': users[username]['role']})
    
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/admin')
def admin_panel():
    """VULNERABLE: Weak authorization check"""
    # Should check session['role'] == 'admin'
    if 'username' in session:
        return render_template('admin.html')
    return "Please login", 401

@app.route('/logout')
def logout():
    """VULNERABLE: Incomplete logout"""
    session.pop('username', None)
    # VULNERABLE: Doesn't clear all session data
    return jsonify({'success': True})

if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: Authentication Failures")
    print("=" * 60)
    print("\nTest Accounts:")
    print("  alice / password123 (user)")
    print("  admin / admin123 (admin)")
    print(f"\nRunning on http://localhost:5031")
    print("\nEDUCATIONAL PURPOSE ONLY")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
