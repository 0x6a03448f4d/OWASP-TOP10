from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import hashlib
import base64
import secrets
import os
from datetime import datetime
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# VULNERABLE: Hard-coded encryption key
HARDCODED_DES_KEY = b'MYKEY123'  # 8 bytes for DES

# Initialize database
def init_db():
    """Initialize SQLite database with vulnerable crypto"""
    conn = sqlite3.connect('crypto.db')
    c = conn.cursor()
    
    # Users table with MD5 password hashing
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  email TEXT,
                  api_key TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Encrypted data table
    c.execute('''CREATE TABLE IF NOT EXISTS encrypted_data
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  data_type TEXT,
                  encrypted_value TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Insert sample users with MD5 hashed passwords
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        sample_users = [
            ('alice', md5_hash('password123'), 'alice@email.com', 'sk_live_ABC123XYZ'),
            ('bob', md5_hash('qwerty'), 'bob@email.com', 'sk_live_DEF456UVW'),
            ('charlie', md5_hash('letmein'), 'charlie@email.com', 'sk_live_GHI789RST'),
            ('admin', md5_hash('admin'), 'admin@company.com', 'sk_live_ADMIN000')
        ]
        
        c.executemany('INSERT INTO users (username, password_hash, email, api_key) VALUES (?, ?, ?, ?)',
                     sample_users)
        
        # Insert sample encrypted data
        sample_data = [
            (1, 'credit_card', des_encrypt('4532-1234-5678-9010')),
            (1, 'ssn', des_encrypt('123-45-6789')),
            (2, 'credit_card', des_encrypt('4916-7890-1234-5678')),
            (2, 'bank_account', des_encrypt('9876543210')),
            (3, 'credit_card', des_encrypt('5412-3456-7890-1234')),
        ]
        
        c.executemany('INSERT INTO encrypted_data (user_id, data_type, encrypted_value) VALUES (?, ?, ?)',
                     sample_data)
    
    conn.commit()
    conn.close()

# VULNERABLE: MD5 hash function (broken, fast, no salt)
def md5_hash(text):
    """Hash using MD5 - INSECURE!"""
    return hashlib.md5(text.encode()).hexdigest()

# VULNERABLE: DES encryption with hard-coded key
def des_encrypt(plaintext):
    """Encrypt using DES - DEPRECATED!"""
    cipher = DES.new(HARDCODED_DES_KEY, DES.MODE_ECB)
    padded_text = pad(plaintext.encode(), DES.block_size)
    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted).decode()

# VULNERABLE: DES decryption
def des_decrypt(ciphertext):
    """Decrypt using DES"""
    cipher = DES.new(HARDCODED_DES_KEY, DES.MODE_ECB)
    encrypted_bytes = base64.b64decode(ciphertext)
    decrypted = cipher.decrypt(encrypted_bytes)
    return unpad(decrypted, DES.block_size).decode()

@app.route('/')
def index():
    """Main lab interface"""
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    """VULNERABLE: Login with MD5 password hashing"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # VULNERABLE: MD5 hash comparison
    password_hash = md5_hash(password)
    
    conn = sqlite3.connect('crypto.db')
    c = conn.cursor()
    c.execute('SELECT id, username, email, api_key FROM users WHERE username = ? AND password_hash = ?',
              (username, password_hash))
    user = c.fetchone()
    conn.close()
    
    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        return jsonify({
            'success': True,
            'user': {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'api_key': user[3]
            }
        })
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/user-data', methods=['GET'])
def get_user_data():
    """Get encrypted user data"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect('crypto.db')
    c = conn.cursor()
    c.execute('SELECT id, data_type, encrypted_value FROM encrypted_data WHERE user_id = ?',
              (session['user_id'],))
    data = c.fetchall()
    conn.close()
    
    result = []
    for row in data:
        result.append({
            'id': row[0],
            'type': row[1],
            'encrypted': row[2]
        })
    
    return jsonify({'data': result})

@app.route('/api/decrypt', methods=['POST'])
def decrypt_data():
    """Decrypt data using DES"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    encrypted_value = data.get('encrypted_value')
    
    if not encrypted_value:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        decrypted = des_decrypt(encrypted_value)
        return jsonify({'decrypted': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    """Encrypt data using DES"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    plaintext = data.get('plaintext')
    data_type = data.get('type', 'custom')
    
    if not plaintext:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        encrypted = des_encrypt(plaintext)
        
        # Store in database
        conn = sqlite3.connect('crypto.db')
        c = conn.cursor()
        c.execute('INSERT INTO encrypted_data (user_id, data_type, encrypted_value) VALUES (?, ?, ?)',
                  (session['user_id'], data_type, encrypted))
        conn.commit()
        data_id = c.lastrowid
        conn.close()
        
        return jsonify({
            'id': data_id,
            'encrypted': encrypted
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/hash-password', methods=['POST'])
def hash_password():
    """Hash password using MD5"""
    data = request.json
    password = data.get('password')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    # VULNERABLE: MD5 hashing
    hashed = md5_hash(password)
    
    return jsonify({
        'password': password,
        'hash': hashed,
        'algorithm': 'MD5',
        'warning': 'MD5 is cryptographically broken! Use bcrypt instead.'
    })

@app.route('/api/info', methods=['GET'])
def crypto_info():
    """Display cryptographic vulnerabilities"""
    return jsonify({
        'vulnerabilities': [
            {
                'type': 'Weak Algorithm - DES',
                'severity': 'CRITICAL',
                'description': 'DES uses 56-bit keys and is deprecated since 1999',
                'impact': 'All encrypted data can be decrypted in ~22 hours'
            },
            {
                'type': 'Weak Algorithm - MD5',
                'severity': 'CRITICAL',
                'description': 'MD5 has collision attacks and is too fast for passwords',
                'impact': 'Passwords can be cracked using rainbow tables instantly'
            },
            {
                'type': 'Hard-Coded Key',
                'severity': 'CRITICAL',
                'description': 'DES encryption key is hard-coded in source code',
                'impact': 'Key can be extracted via reverse engineering'
            },
            {
                'type': 'ECB Mode',
                'severity': 'HIGH',
                'description': 'DES is using ECB mode which preserves patterns',
                'impact': 'Identical plaintexts produce identical ciphertexts'
            },
            {
                'type': 'No Salt',
                'severity': 'HIGH',
                'description': 'MD5 password hashes have no salt',
                'impact': 'Rainbow table attacks are effective'
            }
        ],
        'encryption': {
            'algorithm': 'DES',
            'mode': 'ECB',
            'key': 'HARDCODED (8 bytes)',
            'key_value': base64.b64encode(HARDCODED_DES_KEY).decode()
        },
        'hashing': {
            'algorithm': 'MD5',
            'salt': False,
            'iterations': 1
        }
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout user"""
    session.clear()
    return jsonify({'success': True})

@app.route('/api/users', methods=['GET'])
def list_users():
    """List all users (for demonstration)"""
    conn = sqlite3.connect('crypto.db')
    c = conn.cursor()
    c.execute('SELECT username, password_hash, email FROM users')
    users = c.fetchall()
    conn.close()
    
    result = []
    for user in users:
        result.append({
            'username': user[0],
            'password_hash': user[1],
            'email': user[2],
            'algorithm': 'MD5 (no salt)'
        })
    
    return jsonify({'users': result})

if __name__ == '__main__':
    # Initialize database on startup
    if not os.path.exists('crypto.db'):
        print("[*] Initializing database with vulnerable crypto...")
        init_db()
        print("[+] Database initialized")
        print("[!] WARNING: This app uses INSECURE cryptography for educational purposes")
        print("[!] - DES encryption (deprecated)")
        print("[!] - MD5 password hashing (broken)")
        print("[!] - Hard-coded encryption key")
        print("[!] - No salt in password hashes")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
