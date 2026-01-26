from flask import Flask, render_template, request, jsonify, session
import json
import sqlite3
import os
import base64
import secrets
from datetime import datetime, timedelta
import hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# VULNERABLE: Insecure data storage patterns demonstrated

# Initialize database with insecure storage
def init_db():
    """Initialize SQLite database with UNENCRYPTED storage"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # VULNERABLE: Unencrypted database storing sensitive data
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT,
                  phone TEXT,
                  ssn TEXT,
                  credit_card TEXT,
                  cvv TEXT,
                  api_key TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  token TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  message TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Insert sample vulnerable data
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        sample_users = [
            ('john_doe', 'Password123!', 'john@email.com', '+1234567890', 
             '123-45-6789', '4532-1234-5678-9010', '123', 'sk_live_51H7h8dK2eZvN9vZpQ'),
            ('jane_smith', 'SecurePass456', 'jane@email.com', '+1987654321',
             '987-65-4321', '4916-7890-1234-5678', '456', 'sk_live_71K9j2fL3aXwM4yRpT'),
            ('admin', 'admin123', 'admin@company.com', '+1555000999',
             '555-00-0999', '5412-3456-7890-1234', '789', 'sk_live_91M3n5gP7cZyQ6xStV')
        ]
        
        c.executemany('''INSERT INTO users (username, password, email, phone, ssn, credit_card, cvv, api_key)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', sample_users)
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Main lab interface"""
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    """VULNERABLE: Login endpoint storing session in plain text"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # VULNERABLE: Plain text password comparison
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, email FROM users WHERE username=? AND password=?", 
              (username, password))
    user = c.fetchone()
    
    if user:
        # VULNERABLE: Storing session token in plain text database
        token = secrets.token_hex(32)
        expires = datetime.now() + timedelta(days=30)
        
        c.execute("INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
                 (user[0], token, expires))
        conn.commit()
        
        # VULNERABLE: Sensitive data in response
        response = {
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user[0],
                'username': user[1],
                'email': user[2]
            },
            'token': token,  # VULNERABLE: Token in response should be stored securely by client
            'expires': expires.isoformat()
        }
        
        conn.close()
        return jsonify(response)
    
    conn.close()
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """VULNERABLE: Returns user data including sensitive information"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("""SELECT id, username, email, phone, ssn, credit_card, cvv, api_key 
                 FROM users WHERE id=?""", (user_id,))
    user = c.fetchone()
    conn.close()
    
    if user:
        # VULNERABLE: Exposing all sensitive data without proper checks
        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'phone': user[3],
            'ssn': user[4],  # HIGHLY SENSITIVE!
            'credit_card': user[5],  # PCI-DSS VIOLATION!
            'cvv': user[6],  # NEVER STORE CVV!
            'api_key': user[7]  # SENSITIVE!
        })
    
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/database/export', methods=['GET'])
def export_database():
    """VULNERABLE: Exports entire database content"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Export all tables
    export_data = {}
    
    # Users table
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    export_data['users'] = [{
        'id': u[0],
        'username': u[1],
        'password': u[2],  # VULNERABLE: Plain text password
        'email': u[3],
        'phone': u[4],
        'ssn': u[5],
        'credit_card': u[6],
        'cvv': u[7],
        'api_key': u[8]
    } for u in users]
    
    # Sessions table
    c.execute("SELECT * FROM sessions")
    sessions = c.fetchall()
    export_data['sessions'] = [{
        'id': s[0],
        'user_id': s[1],
        'token': s[2],  # VULNERABLE: Session tokens exposed
        'created_at': s[3],
        'expires_at': s[4]
    } for s in sessions]
    
    conn.close()
    return jsonify(export_data)

@app.route('/api/storage/preferences', methods=['GET', 'POST'])
def preferences():
    """VULNERABLE: Simulates SharedPreferences/UserDefaults storage"""
    prefs_file = 'preferences.json'
    
    if request.method == 'POST':
        # VULNERABLE: Storing sensitive data in plain text JSON file
        data = request.json
        
        # Save preferences
        with open(prefs_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        return jsonify({'success': True, 'message': 'Preferences saved'})
    
    else:
        # Read preferences
        if os.path.exists(prefs_file):
            with open(prefs_file, 'r') as f:
                data = json.load(f)
            return jsonify(data)
        
        return jsonify({})

@app.route('/api/storage/file/write', methods=['POST'])
def write_file():
    """VULNERABLE: Writes sensitive data to plain text file"""
    data = request.json
    filename = data.get('filename', 'data.txt')
    content = data.get('content', '')
    
    # VULNERABLE: Writing to plain text file
    filepath = os.path.join('storage', filename)
    os.makedirs('storage', exist_ok=True)
    
    with open(filepath, 'w') as f:
        f.write(content)
    
    return jsonify({
        'success': True,
        'message': f'File {filename} written',
        'path': filepath
    })

@app.route('/api/storage/file/read/<filename>', methods=['GET'])
def read_file(filename):
    """VULNERABLE: Reads file content"""
    filepath = os.path.join('storage', filename)
    
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            content = f.read()
        return jsonify({
            'success': True,
            'filename': filename,
            'content': content
        })
    
    return jsonify({'success': False, 'error': 'File not found'}), 404

@app.route('/api/storage/cache', methods=['POST'])
def cache_data():
    """VULNERABLE: Caches sensitive API responses in plain text"""
    data = request.json
    cache_key = data.get('key')
    cache_value = data.get('value')
    
    # VULNERABLE: Caching sensitive data unencrypted
    cache_file = f'cache_{cache_key}.json'
    with open(cache_file, 'w') as f:
        json.dump({
            'key': cache_key,
            'value': cache_value,
            'cached_at': datetime.now().isoformat()
        }, f)
    
    return jsonify({'success': True, 'message': 'Data cached'})

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """VULNERABLE: Exposes application logs with sensitive data"""
    # Simulated logs containing sensitive information
    logs = [
        {'level': 'INFO', 'message': 'User login: john_doe', 'timestamp': datetime.now().isoformat()},
        {'level': 'DEBUG', 'message': 'Password: Password123!', 'timestamp': datetime.now().isoformat()},
        {'level': 'DEBUG', 'message': 'Auth token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...', 'timestamp': datetime.now().isoformat()},
        {'level': 'INFO', 'message': 'Processing payment for card: 4532-1234-5678-9010', 'timestamp': datetime.now().isoformat()},
        {'level': 'DEBUG', 'message': 'CVV: 123', 'timestamp': datetime.now().isoformat()},
        {'level': 'ERROR', 'message': 'Database connection failed for user: admin', 'timestamp': datetime.now().isoformat()},
        {'level': 'DEBUG', 'message': 'API Key: sk_live_51H7h8dK2eZvN9vZpQ', 'timestamp': datetime.now().isoformat()}
    ]
    
    return jsonify(logs)

@app.route('/api/backup/create', methods=['POST'])
def create_backup():
    """VULNERABLE: Creates backup with all sensitive data"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Get all data
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    
    backup_data = {
        'backup_date': datetime.now().isoformat(),
        'users': [{
            'username': u[1],
            'password': u[2],  # VULNERABLE: Password in backup
            'email': u[3],
            'phone': u[4],
            'ssn': u[5],
            'credit_card': u[6],
            'cvv': u[7],
            'api_key': u[8]
        } for u in users],
        'preferences': {}
    }
    
    # Include preferences if exist
    if os.path.exists('preferences.json'):
        with open('preferences.json', 'r') as f:
            backup_data['preferences'] = json.load(f)
    
    # VULNERABLE: Saving backup unencrypted
    backup_filename = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(backup_filename, 'w') as f:
        json.dump(backup_data, f, indent=2)
    
    conn.close()
    
    return jsonify({
        'success': True,
        'backup_file': backup_filename,
        'message': 'Backup created (UNENCRYPTED!)'
    })

@app.route('/api/encryption/base64', methods=['POST'])
def base64_encrypt():
    """VULNERABLE: Demonstrates Base64 encoding (NOT encryption)"""
    data = request.json
    text = data.get('text', '')
    
    # VULNERABLE: Using Base64 as if it were encryption
    encoded = base64.b64encode(text.encode()).decode()
    
    return jsonify({
        'original': text,
        'encoded': encoded,
        'warning': 'Base64 is NOT encryption! It\'s trivially reversible.'
    })

@app.route('/api/encryption/simple-xor', methods=['POST'])
def simple_xor():
    """VULNERABLE: Demonstrates weak XOR encryption"""
    data = request.json
    text = data.get('text', '')
    key = data.get('key', 'secret')
    
    # VULNERABLE: Simple XOR (easily broken)
    result = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))
    encoded = base64.b64encode(result.encode('latin-1')).decode()
    
    return jsonify({
        'original': text,
        'encrypted': encoded,
        'warning': 'XOR with a static key is NOT secure encryption!'
    })

@app.route('/api/info', methods=['GET'])
def app_info():
    """Returns information about storage vulnerabilities"""
    return jsonify({
        'vulnerabilities': [
            {
                'name': 'Unencrypted Database',
                'severity': 'CRITICAL',
                'description': 'SQLite database stores all data in plain text',
                'file': 'users.db'
            },
            {
                'name': 'Plain Text Preferences',
                'severity': 'HIGH',
                'description': 'Preferences stored in unencrypted JSON file',
                'file': 'preferences.json'
            },
            {
                'name': 'Sensitive Data in Logs',
                'severity': 'HIGH',
                'description': 'Application logs contain passwords, tokens, and PII'
            },
            {
                'name': 'Unencrypted Backups',
                'severity': 'CRITICAL',
                'description': 'Backups include all sensitive data without encryption'
            },
            {
                'name': 'Insecure File Storage',
                'severity': 'HIGH',
                'description': 'Files written in plain text to storage directory'
            },
            {
                'name': 'Base64 Used as Encryption',
                'severity': 'MEDIUM',
                'description': 'Base64 encoding mistaken for encryption'
            }
        ],
        'recommendations': [
            'Encrypt database with SQLCipher',
            'Use platform secure storage (Keychain/KeyStore)',
            'Never log sensitive information',
            'Exclude sensitive data from backups',
            'Use proper encryption (AES-256)',
            'Implement data expiration policies'
        ]
    })

if __name__ == '__main__':
    print("\n" + "="*60)
    print("M09: Insecure Data Storage - Vulnerable Lab")
    print("="*60)
    print("\n⚠️  WARNING: This application is INTENTIONALLY VULNERABLE!")
    print("    DO NOT use these patterns in production!\n")
    print("Vulnerabilities demonstrated:")
    print("  - Unencrypted SQLite database")
    print("  - Plain text file storage")
    print("  - Sensitive data in logs")
    print("  - Unencrypted backups")
    print("  - Base64 used as encryption")
    print("  - Passwords stored in plain text")
    print("\nAccess the lab at: http://localhost:5109")
    print("="*60 + "\n")
    
    init_db()
    app.run(host='0.0.0.0', port=5109, debug=True)
