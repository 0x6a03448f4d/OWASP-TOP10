"""
Mobile Credential Exposure Lab - Simulated Mobile App Backend

EDUCATIONAL PURPOSE ONLY
This code intentionally contains security vulnerabilities for learning purposes.
DO NOT use these patterns in production applications.
"""

from flask import Flask, render_template, request, jsonify
import logging
import base64

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded API Credentials
# WARNING: Never hardcode credentials in your application code!
# NOTE: These are FAKE credentials for educational demonstration only
API_KEY = "AIzaSyDxVW2E9vZpQN7h8dK2eZvN9vZpQN7h8d"  # FAKE - For demo only
API_SECRET = "sk_test_FAKE51H7h8dK2eZvN9vZpQN7h8dK2eZv"  # FAKE - For demo only
DATABASE_URL = "mysql://admin:MySecretPassword123@db.example.com:3306/userdb"  # FAKE - For demo only

# VULNERABILITY 2: Hardcoded User Credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin@1234"

# Configure logging (VULNERABILITY 3: Excessive logging)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Simulated user storage (plain text passwords - VULNERABILITY 4)
users_storage = {
    "user@example.com": {
        "password": "MyPassword123",  # Plain text!
        "api_token": "tok_1234567890abcdefgh",
        "role": "user"
    }
}

@app.route('/')
def index():
    """Main page showing the vulnerable application"""
    return render_template('index.html')

@app.route('/api/config')
def get_config():
    """
    VULNERABILITY: Exposing configuration including credentials
    Mobile apps often fetch config from backend - but must not include secrets!
    """
    config = {
        "api_endpoint": "https://api.example.com",
        "api_key": API_KEY,  # VULNERABLE: Sending API key to client!
        "api_secret": API_SECRET,  # VULNERABLE: Sending secret to client!
        "features": {
            "payments": True,
            "analytics": True
        }
    }
    
    logger.info(f"Config requested - API Key: {API_KEY}")  # VULNERABLE: Logging credentials
    
    return jsonify(config)

@app.route('/api/login', methods=['POST'])
def login():
    """
    VULNERABILITY: Logging credentials, storing in plain text
    """
    data = request.get_json()
    email = data.get('email', '')
    password = data.get('password', '')
    
    # VULNERABILITY: Logging user credentials
    logger.info(f"Login attempt - Email: {email}, Password: {password}")
    
    # Check credentials
    if email in users_storage and users_storage[email]['password'] == password:
        token = users_storage[email]['api_token']
        
        # VULNERABILITY: Logging token
        logger.info(f"Login successful - Token: {token}")
        
        return jsonify({
            "success": True,
            "token": token,
            "message": "Login successful"
        })
    
    logger.warning(f"Login failed for {email}")
    return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route('/api/user/credentials', methods=['POST'])
def save_credentials():
    """
    Simulates how a mobile app might save user credentials
    VULNERABILITY: Demonstrates various insecure storage methods
    """
    data = request.get_json()
    email = data.get('email', '')
    password = data.get('password', '')
    storage_method = data.get('method', 'plain')
    
    result = {
        "method": storage_method,
        "stored": False,
        "warning": ""
    }
    
    if storage_method == "plain":
        # VULNERABLE: Plain text storage
        users_storage[email] = {
            "password": password,
            "api_token": f"tok_{email[:5]}",
            "role": "user"
        }
        result["stored"] = True
        result["warning"] = "INSECURE: Credentials stored in plain text!"
        logger.debug(f"Stored plain text password for {email}: {password}")
        
    elif storage_method == "base64":
        # VULNERABLE: Base64 is encoding, not encryption!
        encoded = base64.b64encode(password.encode()).decode()
        users_storage[email] = {
            "password": encoded,
            "api_token": f"tok_{email[:5]}",
            "role": "user"
        }
        result["stored"] = True
        result["warning"] = "INSECURE: Base64 is encoding, not encryption!"
        logger.debug(f"Stored base64 encoded password for {email}: {encoded}")
        
    elif storage_method == "secure":
        # This would be the secure method (simulated)
        result["stored"] = True
        result["warning"] = "Secure: Would use KeyStore/Keychain with encryption"
        # In real app: use platform KeyStore/Keychain
        
    return jsonify(result)

@app.route('/api/logs')
def get_logs():
    """
    VULNERABILITY: Exposing application logs which may contain credentials
    """
    # In reality, this would read from log files
    sample_logs = [
        "INFO: Config requested - API Key: AIzaSyDxVW2E9vZpQN7h8dK2eZvN9vZpQN7h8d",
        "INFO: Login attempt - Email: user@example.com, Password: MyPassword123",
        "INFO: Login successful - Token: tok_1234567890abcdefgh",
        "DEBUG: Stored plain text password for user@test.com: TestPass456",
        "WARNING: Login failed for hacker@evil.com"
    ]
    
    return jsonify({"logs": sample_logs})

@app.route('/api/admin/credentials')
def admin_credentials():
    """
    VULNERABILITY: Exposing admin credentials through an API endpoint
    """
    # This endpoint should require authentication, but doesn't!
    return jsonify({
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD,
        "database_url": DATABASE_URL
    })

@app.route('/api/decompile-simulation')
def decompile_simulation():
    """
    Simulates what an attacker would find when decompiling the app
    """
    findings = {
        "hardcoded_strings": [
            {"type": "API_KEY", "value": API_KEY, "risk": "HIGH"},
            {"type": "API_SECRET", "value": API_SECRET, "risk": "CRITICAL"},
            {"type": "DATABASE_URL", "value": DATABASE_URL, "risk": "CRITICAL"},
            {"type": "ADMIN_PASSWORD", "value": ADMIN_PASSWORD, "risk": "CRITICAL"}
        ],
        "endpoints": [
            "/api/config - Returns API credentials",
            "/api/admin/credentials - Returns admin credentials",
            "/api/logs - Exposes application logs"
        ],
        "storage_vulnerabilities": [
            "Plain text password storage",
            "Base64 encoding (not encryption)",
            "No secure storage implementation"
        ]
    }
    
    return jsonify(findings)

if __name__ == '__main__':
    print("=" * 60)
    print("M01: Improper Credential Usage Lab")
    print("=" * 60)
    print("WARNING: This application contains intentional vulnerabilities")
    print("for educational purposes. DO NOT use in production!")
    print("=" * 60)
    print(f"\nHardcoded credentials present:")
    print(f"  API Key: {API_KEY}")
    print(f"  API Secret: {API_SECRET[:20]}...")
    print(f"  Admin Password: {ADMIN_PASSWORD}")
    print("\nAccess the lab at: http://localhost:5100")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
