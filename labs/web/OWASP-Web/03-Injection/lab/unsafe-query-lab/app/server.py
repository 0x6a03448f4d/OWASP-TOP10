"""
OWASP Top 10 Lab: Injection - Unsafe Query

This lab demonstrates SQL injection vulnerability concepts through
a SAFE MOCK database. No real database is used.

EDUCATIONAL PURPOSE ONLY
This is a safe, isolated demonstration. No real attacks are possible.
"""

from flask import Flask, render_template, request, jsonify
import re

app = Flask(__name__)

# MOCK DATABASE - Safe dummy data for demonstration
MOCK_USERS = [
    {"id": 1, "username": "alice", "email": "alice@example.com", "role": "user"},
    {"id": 2, "username": "bob", "email": "bob@example.com", "role": "user"},
    {"id": 3, "username": "admin", "email": "admin@example.com", "role": "admin"},
    {"id": 4, "username": "charlie", "email": "charlie@example.com", "role": "user"},
]

MOCK_PRODUCTS = [
    {"id": 1, "name": "Laptop", "price": 999, "category": "Electronics"},
    {"id": 2, "name": "Mouse", "price": 25, "category": "Electronics"},
    {"id": 3, "name": "Keyboard", "price": 75, "category": "Electronics"},
    {"id": 4, "name": "Monitor", "price": 300, "category": "Electronics"},
]


@app.route('/')
def home():
    """Home page with search interface"""
    return render_template('search.html')


@app.route('/search/vulnerable', methods=['POST'])
def search_vulnerable():
    """
    VULNERABILITY DEMONSTRATION: Unsafe query construction
    
    This simulates what happens when user input is concatenated
    into queries without proper sanitization.
    
    EDUCATIONAL ONLY - This is a MOCK, no real SQL is executed!
    """
    data = request.json
    search_term = data.get('search', '')
    
    # VULNERABLE CODE PATTERN (simulated):
    # query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    
    # Demonstrate the CONCEPT of SQL injection
    is_injection_attempt = False
    injection_indicators = ["'", '"', '--', ';', 'UNION', 'DROP', 'SELECT']
    
    for indicator in injection_indicators:
        if indicator in search_term.upper():
            is_injection_attempt = True
            break
    
    if is_injection_attempt:
        # Demonstrate what WOULD happen (conceptually)
        return jsonify({
            'method': 'String Concatenation (VULNERABLE)',
            'input': search_term,
            'warning': '⚠️ SQL Injection Pattern Detected!',
            'explanation': 'In a real application, this could execute arbitrary SQL',
            'simulated_query': f"SELECT * FROM products WHERE name LIKE '%{search_term}%'",
            'impact': 'Attacker could access/modify/delete ALL data',
            'results': [],
            'vulnerability_level': 'CRITICAL'
        })
    
    # Normal search (safe mock)
    results = [p for p in MOCK_PRODUCTS if search_term.lower() in p['name'].lower()]
    
    return jsonify({
        'method': 'String Concatenation (VULNERABLE)',
        'input': search_term,
        'simulated_query': f"SELECT * FROM products WHERE name LIKE '%{search_term}%'",
        'results': results,
        'warning': 'This method is vulnerable to SQL injection!',
        'vulnerability_level': 'HIGH'
    })


@app.route('/search/secure', methods=['POST'])
def search_secure():
    """
    SECURE DEMONSTRATION: Parameterized query
    
    This shows the proper way to handle user input in queries.
    """
    data = request.json
    search_term = data.get('search', '')
    
    # SECURE CODE PATTERN:
    # cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{search_term}%",))
    
    # Safe search (mock)
    results = [p for p in MOCK_PRODUCTS if search_term.lower() in p['name'].lower()]
    
    return jsonify({
        'method': 'Parameterized Query (SECURE)',
        'input': search_term,
        'simulated_query': 'SELECT * FROM products WHERE name LIKE ? -- (? is placeholder)',
        'results': results,
        'explanation': 'User input is treated as DATA, not CODE',
        'security_level': 'SECURE ✓'
    })


@app.route('/demo/injection-examples')
def injection_examples():
    """
    Educational examples of injection patterns (concept only)
    """
    examples = [
        {
            'name': 'Authentication Bypass',
            'input': "admin' --",
            'vulnerable_query': "SELECT * FROM users WHERE username = 'admin' --' AND password = 'xxx'",
            'impact': 'Bypasses password check by commenting it out',
            'severity': 'CRITICAL'
        },
        {
            'name': 'Data Extraction',
            'input': "' UNION SELECT username, password FROM users --",
            'vulnerable_query': "SELECT * FROM products WHERE name = '' UNION SELECT username, password FROM users --'",
            'impact': 'Retrieves sensitive data from other tables',
            'severity': 'CRITICAL'
        },
        {
            'name': 'Data Deletion',
            'input': "'; DROP TABLE products; --",
            'vulnerable_query': "SELECT * FROM products WHERE id = ''; DROP TABLE products; --'",
            'impact': 'Could delete entire database tables',
            'severity': 'CRITICAL'
        }
    ]
    
    return jsonify({
        'concept': 'SQL Injection Attack Patterns',
        'note': 'These are CONCEPTUAL examples for education only',
        'examples': examples,
        'prevention': 'Always use parameterized queries!',
        'never_do': 'Do NOT try these on real systems - it is illegal!'
    })


if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: Injection - Unsafe Query")
    print("=" * 60)
    print("\nThis lab demonstrates:")
    print("  ✗ String concatenation - VULNERABLE")
    print("  ✓ Parameterized queries - SECURE")
    print("\nApplication running on http://localhost:5001")
    print("\nThis is a SAFE EDUCATIONAL ENVIRONMENT")
    print("No real database or SQL injection is possible here")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
