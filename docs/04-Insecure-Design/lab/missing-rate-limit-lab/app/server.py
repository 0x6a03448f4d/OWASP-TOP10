"""
OWASP Top 10 Lab: Insecure Design - Missing Rate Limit

This lab demonstrates a design flaw where no rate limiting is implemented
on login attempts, allowing unlimited brute force attempts.

EDUCATIONAL PURPOSE ONLY
"""

from flask import Flask, render_template, request, jsonify, session
import time

app = Flask(__name__)
app.secret_key = 'insecure-design-demo-key'

# Mock user database
USERS = {
    'alice': 'password123',
    'bob': 'secret456',
    'admin': 'admin789'
}

# Global counter for demonstration (NOT how to track in production!)
login_attempts = {}

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    """
    VULNERABILITY: NO RATE LIMITING
    
    This endpoint allows UNLIMITED login attempts.
    An attacker could try thousands of passwords.
    """
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Track attempts for demo purposes
    if username not in login_attempts:
        login_attempts[username] = 0
    login_attempts[username] += 1
    
    # Check credentials
    if username in USERS and USERS[username] == password:
        session['username'] = username
        return jsonify({
            'success': True,
            'message': f'Welcome {username}!',
            'total_attempts': login_attempts[username]
        })
    
    # VULNERABILITY: No limit on failed attempts!
    return jsonify({
        'success': False,
        'message': 'Invalid credentials',
        'total_attempts': login_attempts[username],
        'warning': f'⚠️ {login_attempts[username]} attempts made - NO LIMIT!'
    }), 401

@app.route('/attempts')
def get_attempts():
    return jsonify(login_attempts)

if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: Insecure Design - No Rate Limiting")
    print("=" * 60)
    print("\nVulnerability: UNLIMITED login attempts allowed")
    print("Application running on http://localhost:5001")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
