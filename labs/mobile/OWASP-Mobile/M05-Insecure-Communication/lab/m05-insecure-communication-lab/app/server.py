"""
Mobile Insecure Communication Lab - Vulnerable API Backend

EDUCATIONAL PURPOSE ONLY
This code intentionally contains security vulnerabilities for learning purposes.
DO NOT use these patterns in production applications.
"""

from flask import Flask, render_template, request, jsonify
import logging
import json

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# VULNERABILITY 1: Hardcoded sensitive data transmitted over HTTP
API_KEY = "sk_live_FAKE_INSECURE_KEY_123456789"  # FAKE - For demo only
DATABASE_PASSWORD = "SuperSecret123!"  # FAKE - For demo only

# Simulated user storage
users_database = {
    "alice@example.com": {
        "password": "Alice2024!",
        "credit_card": "4532-1111-2222-3333",
        "ssn": "123-45-6789",
        "session_token": "tok_insecure_alice_12345"
    },
    "bob@example.com": {
        "password": "BobPass456",
        "credit_card": "5105-1051-0510-5100",
        "ssn": "987-65-4321",
        "session_token": "tok_insecure_bob_67890"
    }
}

@app.route('/')
def index():
    """Main page showing the vulnerable application"""
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    """
    VULNERABILITY: Accepting credentials over HTTP (unencrypted)
    WARNING: In production, ALWAYS use HTTPS for authentication!
    """
    data = request.get_json()
    email = data.get('email', '')
    password = data.get('password', '')
    
    # VULNERABILITY: Logging credentials in cleartext
    logger.info(f"[HTTP] Login attempt - Email: {email}, Password: {password}")
    
    # Check credentials
    if email in users_database and users_database[email]['password'] == password:
        user_data = users_database[email]
        
        # VULNERABILITY: Sending sensitive data over HTTP
        response = {
            "success": True,
            "message": "Login successful",
            "session_token": user_data['session_token'],  # Sent over HTTP!
            "user": {
                "email": email,
                "credit_card": user_data['credit_card'],  # NEVER send over HTTP!
                "ssn": user_data['ssn']  # NEVER send over HTTP!
            }
        }
        
        logger.warning(f"[SECURITY ISSUE] Sending sensitive data over HTTP: {json.dumps(response)}")
        
        return jsonify(response)
    else:
        return jsonify({
            "success": False,
            "message": "Invalid credentials"
        }), 401

@app.route('/api/config', methods=['GET'])
def get_config():
    """
    VULNERABILITY: Exposing API keys and secrets over HTTP
    """
    config = {
        "api_endpoint": "http://api.example.com",  # HTTP!
        "api_key": API_KEY,  # VULNERABLE: Exposing API key
        "features": {
            "payment_gateway": "stripe",
            "analytics_enabled": True
        },
        "database": {
            "host": "db.example.com",
            "password": DATABASE_PASSWORD  # VULNERABLE: Exposing DB password
        }
    }
    
    logger.warning(f"[SECURITY ISSUE] Sending config with secrets over HTTP")
    
    return jsonify(config)

@app.route('/api/user/profile', methods=['GET'])
def get_profile():
    """
    VULNERABILITY: Session token sent via URL parameter over HTTP
    """
    # VULNERABILITY: Token in query parameter (visible in logs, history, etc.)
    token = request.args.get('token', '')
    
    logger.info(f"[HTTP] Profile request with token: {token}")
    
    # Find user by token
    for email, user_data in users_database.items():
        if user_data['session_token'] == token:
            # VULNERABILITY: Sending all user data over HTTP
            profile = {
                "email": email,
                "credit_card": user_data['credit_card'],
                "ssn": user_data['ssn'],
                "password": user_data['password']  # NEVER expose password!
            }
            
            logger.warning(f"[SECURITY ISSUE] Sending full profile over HTTP")
            
            return jsonify(profile)
    
    return jsonify({"error": "Invalid token"}), 401

@app.route('/api/payment', methods=['POST'])
def process_payment():
    """
    VULNERABILITY: Payment data transmitted over HTTP
    """
    data = request.get_json()
    
    # VULNERABILITY: Receiving payment data over HTTP
    payment_info = {
        "card_number": data.get('card_number'),
        "cvv": data.get('cvv'),
        "expiry": data.get('expiry'),
        "amount": data.get('amount')
    }
    
    # VULNERABILITY: Logging payment data
    logger.warning(f"[SECURITY ISSUE] Payment data received over HTTP: {json.dumps(payment_info)}")
    
    return jsonify({
        "success": True,
        "message": "Payment processed (simulated)",
        "transaction_id": "txn_insecure_12345"
    })

@app.route('/api/debug/traffic', methods=['GET'])
def debug_traffic():
    """
    VULNERABILITY: Debug endpoint exposing recent traffic
    Shows what an attacker could see by intercepting HTTP traffic
    """
    # Simulated captured traffic
    captured_traffic = [
        {
            "timestamp": "2024-01-25 10:15:23",
            "method": "POST",
            "path": "/api/login",
            "body": {
                "email": "alice@example.com",
                "password": "Alice2024!"
            },
            "response": {
                "session_token": "tok_insecure_alice_12345",
                "credit_card": "4532-1111-2222-3333"
            }
        },
        {
            "timestamp": "2024-01-25 10:16:45",
            "method": "GET",
            "path": "/api/config",
            "response": {
                "api_key": API_KEY,
                "database_password": DATABASE_PASSWORD
            }
        }
    ]
    
    return jsonify({
        "message": "This is what an attacker sees when intercepting HTTP traffic",
        "captured_requests": captured_traffic
    })

@app.route('/api/insecure-redirect', methods=['GET'])
def insecure_redirect():
    """
    VULNERABILITY: Redirecting from HTTPS to HTTP
    """
    # In a real scenario, this would redirect to HTTP
    return jsonify({
        "message": "This endpoint would redirect to HTTP",
        "redirect_url": "http://insecure.example.com/data",
        "warning": "Downgrading from HTTPS to HTTP exposes data"
    })

# HTTP Status endpoint
@app.route('/api/status', methods=['GET'])
def status():
    """Check if the vulnerable HTTP service is running"""
    return jsonify({
        "status": "running",
        "protocol": "HTTP (INSECURE)",
        "warning": "This server accepts unencrypted HTTP traffic!",
        "vulnerabilities": [
            "Cleartext transmission of credentials",
            "API keys exposed over HTTP",
            "Session tokens sent unencrypted",
            "Payment data not encrypted",
            "Sensitive user data exposed"
        ]
    })

if __name__ == '__main__':
    print("=" * 80)
    print("INSECURE COMMUNICATION LAB - EDUCATIONAL PURPOSE ONLY")
    print("=" * 80)
    print("\n⚠️  WARNING: This server intentionally uses HTTP (unencrypted)!")
    print("⚠️  All traffic is visible to anyone on the network!")
    print("⚠️  NEVER use HTTP for sensitive data in production!\n")
    print("Server running on:")
    print("  - HTTP: http://localhost:5000 (INSECURE)")
    print("\nEndpoints:")
    print("  - GET  /                      - Main page")
    print("  - POST /api/login             - Login (credentials over HTTP)")
    print("  - GET  /api/config            - Config (secrets over HTTP)")
    print("  - GET  /api/user/profile      - User profile (data over HTTP)")
    print("  - POST /api/payment           - Payment (card data over HTTP)")
    print("  - GET  /api/debug/traffic     - View captured traffic")
    print("  - GET  /api/status            - Server status")
    print("\n" + "=" * 80 + "\n")
    
    # Run on HTTP only (INSECURE - for educational demonstration)
    app.run(host='0.0.0.0', port=5000, debug=True)
