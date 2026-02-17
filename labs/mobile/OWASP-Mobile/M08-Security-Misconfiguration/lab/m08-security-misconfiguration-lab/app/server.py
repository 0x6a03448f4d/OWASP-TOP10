"""
Mobile Security Misconfiguration Lab - Vulnerable Flask Application

EDUCATIONAL PURPOSE ONLY
This code intentionally contains security misconfigurations for learning purposes.
DO NOT use these patterns in production applications.
"""

from flask import Flask, render_template, request, jsonify
import logging
import traceback
import os
import sys

app = Flask(__name__)

# VULNERABILITY 1: Debug Mode Enabled
# WARNING: Never enable debug mode in production!
app.config['DEBUG'] = True
app.config['TESTING'] = True

# VULNERABILITY 2: Verbose Error Messages
app.config['PROPAGATE_EXCEPTIONS'] = True

# VULNERABILITY 3: Insecure Configuration Settings
app.config['SECRET_KEY'] = 'dev-secret-key-123'  # Hardcoded, weak secret key
app.config['SESSION_COOKIE_SECURE'] = False  # Allows cookies over HTTP
app.config['SESSION_COOKIE_HTTPONLY'] = False  # JavaScript can access cookies
app.config['SESSION_COOKIE_SAMESITE'] = None  # No CSRF protection

# VULNERABILITY 4: Excessive logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Simulated database credentials exposed in config
DATABASE_CONFIG = {
    "host": "production-db.example.com",
    "port": 5432,
    "username": "db_admin",
    "password": "Prod_Pass_2024!",
    "database": "mobile_app_production"
}

# VULNERABILITY 5: Development endpoints left in production
DEV_MODE_ENABLED = True
INTERNAL_API_KEY = "internal-api-key-abc123"

# Simulated user data
users = {
    "admin@example.com": {
        "password": "admin123",
        "role": "admin",
        "api_key": "usr_admin_key_12345"
    },
    "user@example.com": {
        "password": "user123",
        "role": "user",
        "api_key": "usr_user_key_67890"
    }
}

@app.route('/')
def index():
    """Main page showing the vulnerable application"""
    logger.info("Index page accessed")
    return render_template('index.html')

@app.route('/api/test-error')
def test_error():
    """
    VULNERABILITY: Endpoint that triggers an error with full stack trace
    In production, this exposes internal implementation details
    """
    logger.debug("Test error endpoint called")
    
    # Intentionally cause an error
    try:
        result = 1 / 0  # Division by zero
    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")
        # With debug=True, Flask shows full stack trace
        raise

@app.route('/api/config')
def get_config():
    """
    VULNERABILITY: Exposing internal configuration including sensitive data
    """
    logger.debug(f"Configuration requested - Database password: {DATABASE_CONFIG['password']}")
    
    config = {
        "app_version": "2.1.0",
        "environment": "production",  # Claims production but has dev settings
        "debug_enabled": app.config['DEBUG'],
        "features": {
            "analytics": True,
            "crash_reporting": True,
            "dev_tools": DEV_MODE_ENABLED
        },
        "database": DATABASE_CONFIG,  # VULNERABLE: Exposing DB credentials!
        "internal_api_key": INTERNAL_API_KEY  # VULNERABLE: Internal key exposed!
    }
    
    return jsonify(config)

@app.route('/api/login', methods=['POST'])
def login():
    """
    Login endpoint with verbose error messages
    """
    data = request.get_json()
    email = data.get('email', '')
    password = data.get('password', '')
    
    # VULNERABILITY: Logging credentials
    logger.info(f"Login attempt - Email: {email}, Password: {password}")
    
    if email not in users:
        # VULNERABILITY: Verbose error revealing user existence
        logger.warning(f"Login failed - User {email} does not exist in database")
        return jsonify({
            "success": False,
            "error": f"User '{email}' not found in database",
            "hint": "Please check if you have registered",
            "debug_info": {
                "registered_users_count": len(users),
                "timestamp": "2024-01-15 10:30:45"
            }
        }), 401
    
    if users[email]['password'] != password:
        # VULNERABILITY: Verbose error with timing info
        logger.warning(f"Login failed - Invalid password for {email}")
        return jsonify({
            "success": False,
            "error": "Invalid password",
            "hint": f"Password does not match for user {email}",
            "attempts_remaining": 3,
            "last_successful_login": "2024-01-10 14:22:33"
        }), 401
    
    # Successful login
    logger.info(f"Login successful - User: {email}, API Key: {users[email]['api_key']}")
    
    return jsonify({
        "success": True,
        "user": {
            "email": email,
            "role": users[email]['role'],
            "api_key": users[email]['api_key']
        },
        "message": "Login successful"
    })

@app.route('/dev/debug-info')
def debug_info():
    """
    VULNERABILITY: Development endpoint left in production
    Exposes system information and environment variables
    """
    if not DEV_MODE_ENABLED:
        return jsonify({"error": "Not available"}), 404
    
    logger.debug("Debug info endpoint accessed - exposing system details")
    
    debug_data = {
        "python_version": sys.version,
        "platform": sys.platform,
        "environment_variables": dict(os.environ),
        "loaded_modules": list(sys.modules.keys()),
        "app_config": {
            "SECRET_KEY": app.config['SECRET_KEY'],
            "DEBUG": app.config['DEBUG'],
            "TESTING": app.config['TESTING']
        },
        "database_config": DATABASE_CONFIG,
        "current_directory": os.getcwd(),
        "python_path": sys.path
    }
    
    return jsonify(debug_data)

@app.route('/dev/execute', methods=['POST'])
def execute_code():
    """
    VULNERABILITY: Code execution endpoint for development/testing
    Extremely dangerous if left in production!
    """
    if not DEV_MODE_ENABLED:
        return jsonify({"error": "Not available"}), 404
    
    data = request.get_json()
    code = data.get('code', '')
    
    logger.warning(f"Code execution requested: {code}")
    
    try:
        # CRITICAL VULNERABILITY: Executing arbitrary code!
        result = eval(code)
        return jsonify({
            "success": True,
            "result": str(result),
            "warning": "This endpoint should never exist in production!"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        })

@app.route('/api/user/<user_id>')
def get_user(user_id):
    """
    VULNERABILITY: SQL Injection-like vulnerability with verbose errors
    """
    logger.debug(f"User lookup for ID: {user_id}")
    
    # Simulate SQL injection vulnerability
    if "'" in user_id or '"' in user_id:
        error_msg = f"SQL Error: Syntax error near '{user_id}' in query: SELECT * FROM users WHERE id='{user_id}'"
        logger.error(error_msg)
        
        # VULNERABILITY: Exposing database structure in error
        return jsonify({
            "error": error_msg,
            "database": "mobile_app_production",
            "table": "users",
            "columns": ["id", "email", "password_hash", "role", "api_key", "created_at"],
            "suggestion": "Check your input for special characters"
        }), 400
    
    return jsonify({"message": "User not found"}), 404

@app.route('/api/logs')
def get_logs():
    """
    VULNERABILITY: Exposing application logs
    """
    sample_logs = [
        "DEBUG: Configuration requested - Database password: Prod_Pass_2024!",
        "INFO: Login attempt - Email: admin@example.com, Password: admin123",
        "INFO: Login successful - User: admin@example.com, API Key: usr_admin_key_12345",
        "DEBUG: User lookup for ID: 123",
        "WARNING: Code execution requested: __import__('os').system('whoami')",
        "ERROR: SQL Error: Syntax error near '1' OR '1'='1' in query",
        "INFO: Database connection established: db_admin@production-db.example.com",
        "DEBUG: Internal API key used: internal-api-key-abc123"
    ]
    
    return jsonify({"logs": sample_logs})

@app.route('/api/server-status')
def server_status():
    """
    VULNERABILITY: Exposing server information
    """
    status = {
        "status": "running",
        "version": "Flask 2.3.0",
        "python_version": sys.version,
        "debug_mode": app.config['DEBUG'],
        "server_time": "2024-01-15 10:45:30",
        "uptime": "15 days, 7 hours, 23 minutes",
        "memory_usage": "245 MB / 512 MB",
        "cpu_usage": "12%",
        "active_connections": 47,
        "internal_ip": "10.0.1.15",
        "database_status": "connected",
        "cache_status": "redis connected at 10.0.1.20:6379"
    }
    
    return jsonify(status)

@app.route('/health')
def health_check():
    """
    VULNERABILITY: Health check exposing too much information
    """
    health = {
        "status": "healthy",
        "components": {
            "database": {
                "status": "connected",
                "host": DATABASE_CONFIG['host'],
                "port": DATABASE_CONFIG['port'],
                "username": DATABASE_CONFIG['username'],
                "response_time": "5ms"
            },
            "cache": {
                "status": "connected",
                "host": "redis-master.internal",
                "port": 6379
            },
            "storage": {
                "status": "available",
                "type": "AWS S3",
                "bucket": "mobile-app-uploads-prod",
                "region": "us-east-1"
            }
        }
    }
    
    return jsonify(health)

@app.errorhandler(404)
def not_found(error):
    """
    VULNERABILITY: Verbose 404 error with suggestions
    """
    return jsonify({
        "error": "Not Found",
        "message": f"The requested URL {request.url} was not found on the server",
        "available_endpoints": [
            "/api/config",
            "/api/login",
            "/dev/debug-info",
            "/dev/execute",
            "/api/logs",
            "/health"
        ],
        "suggestion": "Check if you're using the correct endpoint"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """
    VULNERABILITY: Verbose 500 error with stack trace
    """
    return jsonify({
        "error": "Internal Server Error",
        "message": str(error),
        "traceback": traceback.format_exc(),
        "debug": {
            "config": dict(app.config),
            "request_headers": dict(request.headers)
        }
    }), 500

if __name__ == '__main__':
    print("=" * 70)
    print("M08: Security Misconfiguration Lab")
    print("=" * 70)
    print("⚠️  WARNING: This application contains intentional security misconfigurations")
    print("for educational purposes. DO NOT use in production!")
    print("=" * 70)
    print("\n🔓 Security Misconfigurations Present:")
    print("  ✗ Debug mode enabled (Flask debug=True)")
    print("  ✗ Verbose error messages exposing internals")
    print("  ✗ Development endpoints in production")
    print("  ✗ Sensitive data in logs")
    print("  ✗ Database credentials exposed")
    print("  ✗ Insecure cookie settings")
    print("\n🌐 Access the lab at: http://localhost:5108")
    print("=" * 70)
    
    # VULNERABILITY: Running with debug=True in production
    app.run(host='0.0.0.0', port=5000, debug=True)
