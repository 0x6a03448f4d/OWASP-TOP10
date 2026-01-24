"""
OWASP Top 10 Lab: Logging Failures - No Logging

This lab demonstrates an application with NO security logging.

EDUCATIONAL PURPOSE ONLY
"""

from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# NO logging configured! (VULNERABLE)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """VULNERABILITY: Failed logins are NOT logged"""
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Simulate login check
    if username == 'admin' and password == 'admin123':
        # NO SUCCESS LOGGING
        return jsonify({'success': True})
    
    # NO FAILURE LOGGING - Attacks go undetected!
    return jsonify({
        'success': False,
        'warning': '⚠️ This failed login was NOT logged!',
        'impact': 'Attackers can try unlimited passwords undetected'
    }), 401

if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: No Logging")
    print("=" * 60)
    print("\nVulnerability: Zero security logging")
    print("Application running on http://localhost:5001")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
