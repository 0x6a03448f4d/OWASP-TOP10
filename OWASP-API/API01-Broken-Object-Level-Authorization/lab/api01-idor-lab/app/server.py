"""
OWASP API Security Top 10 Lab: API01 - Broken Object Level Authorization (BOLA)

This lab demonstrates a critical BOLA/IDOR vulnerability where authenticated
users can access other users' orders by simply changing the order ID in the URL.

EDUCATIONAL PURPOSE ONLY
This is a safe, isolated demonstration. No real data is at risk.
"""

from flask import Flask, render_template, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['JWT_SECRET_KEY'] = 'super-secret-jwt-key-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

CORS(app)
jwt = JWTManager(app)

# Simulated user database (in-memory for this demo)
users = {
    1: {
        'id': 1,
        'username': 'alice',
        'password': generate_password_hash('password123'),
        'email': 'alice@example.com',
        'full_name': 'Alice Smith'
    },
    2: {
        'id': 2,
        'username': 'bob',
        'password': generate_password_hash('password123'),
        'email': 'bob@example.com',
        'full_name': 'Bob Johnson'
    },
    3: {
        'id': 3,
        'username': 'charlie',
        'password': generate_password_hash('password123'),
        'email': 'charlie@example.com',
        'full_name': 'Charlie Davis'
    }
}

# Simulated orders database
# In production, this would be a real database with proper relationships
orders = {
    101: {
        'order_id': 101,
        'user_id': 1,
        'username': 'alice',
        'items': ['Laptop', 'Mouse'],
        'quantities': [1, 2],
        'total': 1299.99,
        'status': 'Delivered',
        'shipping_address': '123 Main St, Anytown, USA',
        'created_at': '2024-01-15'
    },
    102: {
        'order_id': 102,
        'user_id': 1,
        'username': 'alice',
        'items': ['Keyboard', 'Monitor'],
        'quantities': [1, 1],
        'total': 450.00,
        'status': 'Processing',
        'shipping_address': '123 Main St, Anytown, USA',
        'created_at': '2024-01-20'
    },
    201: {
        'order_id': 201,
        'user_id': 2,
        'username': 'bob',
        'items': ['Phone', 'Charger', 'Case'],
        'quantities': [1, 2, 1],
        'total': 899.99,
        'status': 'Shipped',
        'shipping_address': '456 Oak Ave, Other City, USA',
        'created_at': '2024-01-18'
    },
    202: {
        'order_id': 202,
        'user_id': 2,
        'username': 'bob',
        'items': ['Headphones'],
        'quantities': [1],
        'total': 199.99,
        'status': 'Delivered',
        'shipping_address': '456 Oak Ave, Other City, USA',
        'created_at': '2024-01-10'
    },
    301: {
        'order_id': 301,
        'user_id': 3,
        'username': 'charlie',
        'items': ['Tablet', 'Stylus'],
        'quantities': [1, 1],
        'total': 649.99,
        'status': 'Processing',
        'shipping_address': '789 Pine Rd, Another Town, USA',
        'created_at': '2024-01-22'
    },
    302: {
        'order_id': 302,
        'user_id': 3,
        'username': 'charlie',
        'items': ['Smart Watch'],
        'quantities': [1],
        'total': 299.99,
        'status': 'Shipped',
        'shipping_address': '789 Pine Rd, Another Town, USA',
        'created_at': '2024-01-19'
    }
}


@app.route('/')
def index():
    """Serve the API testing interface"""
    return render_template('index.html')


@app.route('/api/login', methods=['POST'])
def login():
    """
    Login endpoint - Returns JWT token
    
    This endpoint is SECURE - it properly authenticates users
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Find user by username
    user = None
    for u in users.values():
        if u['username'] == username:
            user = u
            break
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Verify password
    if not check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Create JWT token with user ID as identity
    access_token = create_access_token(identity=user['id'])
    
    return jsonify({
        'access_token': access_token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'full_name': user['full_name']
        }
    }), 200


@app.route('/api/me')
@jwt_required()
def get_current_user():
    """
    Get current authenticated user info
    
    This endpoint is SECURE - returns only the authenticated user's data
    """
    current_user_id = get_jwt_identity()
    user = users.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'full_name': user['full_name']
    })


@app.route('/api/orders')
@jwt_required()
def get_user_orders():
    """
    Get all orders for the authenticated user
    
    This endpoint is SECURE - it filters orders by user ownership
    """
    current_user_id = get_jwt_identity()
    
    # Filter orders to only show those belonging to the authenticated user
    user_orders = [
        order for order in orders.values() 
        if order['user_id'] == current_user_id
    ]
    
    return jsonify(user_orders)


@app.route('/api/orders/<int:order_id>')
@jwt_required()
def get_order(order_id):
    """
    VULNERABILITY: Get a specific order by ID
    
    This endpoint demonstrates a BOLA (Broken Object Level Authorization) 
    vulnerability, also known as IDOR (Insecure Direct Object Reference).
    
    PROBLEM:
    - The user IS authenticated (we verify the JWT token)
    - But we DON'T verify that the order belongs to this user
    - Any authenticated user can access any order by changing the order_id
    
    ATTACK SCENARIO:
    1. Alice logs in and gets a valid JWT token
    2. Alice accesses her order: GET /api/orders/101 ✓ (works)
    3. Alice tries Bob's order: GET /api/orders/201 ✓ (works too - VULNERABILITY!)
    4. Alice can now see Bob's personal information and order details
    
    FIX:
    Add ownership verification:
        current_user_id = get_jwt_identity()
        if order['user_id'] != current_user_id:
            return jsonify({'error': 'Order not found'}), 404
    """
    # Check if order exists
    if order_id not in orders:
        return jsonify({'error': 'Order not found'}), 404
    
    # VULNERABLE: No authorization check here!
    # We should verify: order['user_id'] == current_user_id
    # But we don't - this is the BOLA vulnerability!
    
    return jsonify(orders[order_id])


@app.route('/api/stats')
@jwt_required()
def get_stats():
    """
    Get statistics about the system
    
    This endpoint shows what information is available in the system
    """
    current_user_id = get_jwt_identity()
    
    # Count orders per user
    user_order_count = {}
    for order in orders.values():
        user_id = order['user_id']
        user_order_count[user_id] = user_order_count.get(user_id, 0) + 1
    
    return jsonify({
        'total_users': len(users),
        'total_orders': len(orders),
        'your_orders': user_order_count.get(current_user_id, 0),
        # SECURITY ISSUE: Exposing all order IDs enables enumeration attacks!
        # This makes the BOLA vulnerability easier to exploit by revealing valid IDs.
        # In production, never expose a list of all valid object identifiers.
        'order_ids': list(orders.keys())
    })


# Error handlers
@app.errorhandler(401)
def unauthorized(error):
    """Handle unauthorized access"""
    return jsonify({
        'error': 'Authentication required',
        'message': 'Please provide a valid JWT token'
    }), 401


@app.errorhandler(404)
def not_found(error):
    """Handle not found errors"""
    return jsonify({
        'error': 'Resource not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    return jsonify({
        'error': 'Internal server error'
    }), 500


if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔓 BOLA/IDOR Vulnerability Lab")
    print("="*60)
    print("✓ API running on http://localhost:5000")
    print("✓ Educational demonstration - SAFE isolated environment")
    print("✓ This lab demonstrates API1:2023 - Broken Object Level Authorization")
    print("\nTest Accounts:")
    print("  • alice / password123 (Orders: #101, #102)")
    print("  • bob / password123 (Orders: #201, #202)")
    print("  • charlie / password123 (Orders: #301, #302)")
    print("\nVulnerability:")
    print("  Any authenticated user can access ANY order by changing order_id")
    print("  Example: Alice can access Bob's orders at /api/orders/201")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
