"""
OWASP Top 10 Lab: Authentication Failures - Weak Session Management

This lab demonstrates weak session token generation using predictable values.

EDUCATIONAL PURPOSE ONLY
"""

from flask import Flask, render_template, request, jsonify, session

app = Flask(__name__)
app.secret_key = 'weak-session-demo'

# Predictable session counter (VULNERABLE!)
session_counter = 1000

USERS = {
    'alice': 'password123',
    'bob': 'secret456'
}

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    """VULNERABILITY: Predictable session tokens"""
    global session_counter
    
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    
    if username in USERS and USERS[username] == password:
        # VULNERABLE: Predictable session ID
        session_id = f"SESSION_{session_counter}"
        session_counter += 1
        
        session['username'] = username
        session['session_id'] = session_id
        
        return jsonify({
            'success': True,
            'username': username,
            'session_id': session_id,
            'warning': f'⚠️ Predictable session ID! Next will be SESSION_{session_counter}'
        })
    
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return jsonify({'error': 'Not logged in'}), 401

if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: Weak Session Management")
    print("=" * 60)
    print("\nVulnerability: Predictable session tokens")
    print("Application running on http://localhost:5001")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
