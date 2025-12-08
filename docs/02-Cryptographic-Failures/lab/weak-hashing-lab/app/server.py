"""
OWASP Top 10 Lab: Cryptographic Failures - Weak Hashing

This lab demonstrates the difference between weak hashing algorithms (MD5) 
and strong password hashing algorithms (bcrypt/Argon2) through a safe, 
educational comparison interface.

EDUCATIONAL PURPOSE ONLY
This is a safe, isolated demonstration. No real passwords are at risk.
"""

from flask import Flask, render_template, request, jsonify
import hashlib
import bcrypt
import time

app = Flask(__name__)

# Dummy user data for demonstration
DEMO_PASSWORDS = [
    "password123",
    "admin",
    "welcome",
    "letmein",
    "qwerty123",
    "Summer2023!"
]


@app.route('/')
def home():
    """Home page with hash comparison interface"""
    return render_template('index.html')


@app.route('/hash/md5', methods=['POST'])
def hash_md5():
    """
    VULNERABILITY DEMONSTRATION: MD5 hashing
    
    This endpoint demonstrates why MD5 is unsuitable for password storage:
    - Too fast (can compute millions per second)
    - No salt (same password = same hash)
    - Vulnerable to rainbow tables
    
    EDUCATIONAL ONLY - DO NOT USE IN PRODUCTION
    """
    data = request.json
    password = data.get('password', '')
    
    # Time the hashing operation
    start_time = time.time()
    
    # MD5 hash (INSECURE for passwords!)
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    
    end_time = time.time()
    duration_ms = (end_time - start_time) * 1000
    
    return jsonify({
        'algorithm': 'MD5',
        'hash': md5_hash,
        'time_ms': duration_ms,
        'security_level': 'INSECURE',
        'warning': 'MD5 can be cracked in seconds with modern GPUs',
        'details': {
            'salt': 'None (same password = same hash)',
            'speed': f'{duration_ms:.4f}ms (Too fast for passwords)',
            'rainbow_table_vulnerable': True
        }
    })


@app.route('/hash/sha256', methods=['POST'])
def hash_sha256():
    """
    VULNERABILITY DEMONSTRATION: SHA-256 hashing
    
    While stronger than MD5, SHA-256 is still too fast for password storage.
    It's designed for data integrity, not password protection.
    """
    data = request.json
    password = data.get('password', '')
    
    start_time = time.time()
    
    # SHA-256 hash (STILL INSECURE for passwords!)
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    
    end_time = time.time()
    duration_ms = (end_time - start_time) * 1000
    
    return jsonify({
        'algorithm': 'SHA-256',
        'hash': sha256_hash,
        'time_ms': duration_ms,
        'security_level': 'WEAK FOR PASSWORDS',
        'warning': 'SHA-256 is too fast for password hashing',
        'details': {
            'salt': 'None (vulnerable to rainbow tables)',
            'speed': f'{duration_ms:.4f}ms (Too fast for passwords)',
            'use_case': 'Good for data integrity, NOT for passwords'
        }
    })


@app.route('/hash/bcrypt', methods=['POST'])
def hash_bcrypt():
    """
    SECURE DEMONSTRATION: Bcrypt hashing
    
    Bcrypt is designed specifically for password storage:
    - Intentionally slow (adjustable work factor)
    - Includes salt automatically
    - Resistant to brute force attacks
    
    THIS IS THE RECOMMENDED APPROACH
    """
    data = request.json
    password = data.get('password', '')
    
    start_time = time.time()
    
    # Bcrypt hash (SECURE for passwords!)
    salt = bcrypt.gensalt(rounds=10)  # 10 rounds for demo (use 12+ in production)
    bcrypt_hash = bcrypt.hashpw(password.encode(), salt)
    
    end_time = time.time()
    duration_ms = (end_time - start_time) * 1000
    
    return jsonify({
        'algorithm': 'bcrypt',
        'hash': bcrypt_hash.decode(),
        'time_ms': duration_ms,
        'security_level': 'SECURE',
        'recommendation': 'Use this for password storage!',
        'details': {
            'salt': 'Included automatically (unique per password)',
            'speed': f'{duration_ms:.2f}ms (Intentionally slow)',
            'cost_factor': '10 rounds (use 12-14 in production)',
            'brute_force_resistant': True
        }
    })


@app.route('/compare', methods=['POST'])
def compare_all():
    """Compare all three hashing algorithms side-by-side"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password required'}), 400
    
    results = []
    
    # MD5
    start = time.time()
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    md5_time = (time.time() - start) * 1000
    results.append({
        'algorithm': 'MD5',
        'hash': md5_hash,
        'time_ms': md5_time,
        'security': 'INSECURE',
        'color': 'danger'
    })
    
    # SHA-256
    start = time.time()
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    sha256_time = (time.time() - start) * 1000
    results.append({
        'algorithm': 'SHA-256',
        'hash': sha256_hash,
        'time_ms': sha256_time,
        'security': 'WEAK',
        'color': 'warning'
    })
    
    # Bcrypt
    start = time.time()
    salt = bcrypt.gensalt(rounds=10)
    bcrypt_hash = bcrypt.hashpw(password.encode(), salt).decode()
    bcrypt_time = (time.time() - start) * 1000
    results.append({
        'algorithm': 'bcrypt',
        'hash': bcrypt_hash,
        'time_ms': bcrypt_time,
        'security': 'SECURE',
        'color': 'success'
    })
    
    return jsonify({
        'password': password,
        'results': results,
        'conclusion': {
            'fastest': 'MD5 (BAD for passwords)',
            'slowest': 'bcrypt (GOOD for passwords)',
            'recommendation': 'Always use bcrypt or Argon2 for passwords'
        }
    })


@app.route('/demo/rainbow-table')
def demo_rainbow_table():
    """
    Educational demonstration of rainbow table concept
    Shows why unsalted hashes are vulnerable
    """
    # Pre-computed MD5 hashes of common passwords (educational only)
    rainbow_table = {}
    for pwd in DEMO_PASSWORDS:
        md5_hash = hashlib.md5(pwd.encode()).hexdigest()
        rainbow_table[md5_hash] = pwd
    
    return jsonify({
        'concept': 'Rainbow Table Attack',
        'explanation': 'Precomputed hashes allow instant password lookup',
        'example_lookups': rainbow_table,
        'note': 'This is why salts are critical - they make rainbow tables useless',
        'demo_only': 'Real rainbow tables contain billions of hashes'
    })


if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: Cryptographic Failures - Weak Hashing")
    print("=" * 60)
    print("\nThis lab demonstrates:")
    print("  ✗ MD5 - Insecure for passwords")
    print("  ✗ SHA-256 - Too fast for passwords")
    print("  ✓ bcrypt - Secure password hashing")
    print("\nApplication running on http://localhost:5001")
    print("\nThis is a SAFE EDUCATIONAL ENVIRONMENT")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
