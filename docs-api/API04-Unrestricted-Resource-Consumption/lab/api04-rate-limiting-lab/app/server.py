"""
VULNERABLE API - API04: Unrestricted Resource Consumption

This API intentionally lacks:
- Rate limiting
- Pagination
- Request size limits
- Timeouts
- Resource quotas

DO NOT use this code in production!
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import hashlib
import time
import random
import string
import os

app = Flask(__name__)
CORS(app)

DATABASE = 'vulnerable.db'

# VULNERABLE: No request size limit
# app.config['MAX_CONTENT_LENGTH'] = None

def get_db():
    """Get database connection"""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database with schema"""
    db = get_db()
    cursor = db.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Orders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            total REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    ''')
    
    db.commit()
    db.close()

def seed_database():
    """Seed database with sample data"""
    db = get_db()
    cursor = db.cursor()
    
    # Check if already seeded
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] > 0:
        db.close()
        return
    
    print("Seeding database with sample data...")
    
    # Insert users
    for i in range(1, 10001):  # 10,000 users
        email = f"user{i}@example.com"
        password = hashlib.sha256(f"password{i}".encode()).hexdigest()
        name = f"User {i}"
        
        cursor.execute(
            'INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
            (email, password, name)
        )
    
    # Insert products
    categories = ['Electronics', 'Clothing', 'Books', 'Home', 'Sports']
    for i in range(1, 1001):  # 1,000 products
        name = f"Product {i}"
        description = f"Description for product {i} in {random.choice(categories)}"
        price = round(random.uniform(10, 1000), 2)
        stock = random.randint(0, 100)
        
        cursor.execute(
            'INSERT INTO products (name, description, price, stock) VALUES (?, ?, ?, ?)',
            (name, description, price, stock)
        )
    
    # Insert orders
    for i in range(1, 50001):  # 50,000 orders
        user_id = random.randint(1, 10000)
        product_id = random.randint(1, 1000)
        quantity = random.randint(1, 5)
        
        # Get product price
        cursor.execute('SELECT price FROM products WHERE id = ?', (product_id,))
        price = cursor.fetchone()[0]
        total = price * quantity
        
        cursor.execute(
            'INSERT INTO orders (user_id, product_id, quantity, total) VALUES (?, ?, ?, ?)',
            (user_id, product_id, quantity, total)
        )
    
    db.commit()
    db.close()
    print("Database seeded successfully!")

# Initialize database on startup
if not os.path.exists(DATABASE):
    init_db()
    seed_database()

@app.route('/')
def index():
    """Web interface"""
    return render_template('index.html')

@app.route('/health')
def health():
    """Health check endpoint - no rate limiting needed"""
    return jsonify({'status': 'healthy', 'message': 'API is running'})

# VULNERABLE: No rate limiting on list endpoint
# VULNERABLE: No pagination - returns ALL users
@app.route('/api/users')
def get_users():
    """
    Get all users.
    
    VULNERABILITIES:
    - No pagination (returns all 10,000 users)
    - No rate limiting
    - Massive response size
    """
    db = get_db()
    cursor = db.cursor()
    
    # VULNERABLE: Fetches ALL users
    cursor.execute('SELECT id, email, name, created_at FROM users')
    users = cursor.fetchall()
    
    db.close()
    
    # Convert to list of dicts
    users_list = [
        {
            'id': user['id'],
            'email': user['email'],
            'name': user['name'],
            'created_at': user['created_at']
        }
        for user in users
    ]
    
    return jsonify({
        'data': users_list,
        'count': len(users_list)
    })

# VULNERABLE: No rate limiting on authentication
@app.route('/api/login', methods=['POST'])
def login():
    """
    User login.
    
    VULNERABILITIES:
    - No rate limiting (allows brute force)
    - No account lockout
    - Uses bcrypt (CPU intensive) without rate limiting
    """
    data = request.get_json()
    
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password required'}), 400
    
    email = data['email']
    password = data['password']
    
    # Simulate expensive password hashing
    time.sleep(0.1)  # Simulate bcrypt delay
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute(
        'SELECT id, email, name FROM users WHERE email = ? AND password = ?',
        (email, password_hash)
    )
    user = cursor.fetchone()
    
    db.close()
    
    if user:
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'email': user['email'],
                'name': user['name']
            },
            'token': 'fake-jwt-token-' + str(user['id'])
        })
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

# VULNERABLE: Expensive search operation with no rate limiting
@app.route('/api/search')
def search():
    """
    Search products.
    
    VULNERABILITIES:
    - No rate limiting
    - Expensive LIKE query on large table
    - No query length validation
    - No timeout
    """
    query = request.args.get('q', '')
    
    # VULNERABLE: No query length limit
    # VULNERABLE: No timeout on expensive query
    
    db = get_db()
    cursor = db.cursor()
    
    # VULNERABLE: Full table scan with LIKE
    cursor.execute(
        '''
        SELECT p.*, COUNT(o.id) as order_count
        FROM products p
        LEFT JOIN orders o ON p.id = o.product_id
        WHERE p.name LIKE ? OR p.description LIKE ?
        GROUP BY p.id
        ORDER BY order_count DESC
        ''',
        (f'%{query}%', f'%{query}%')
    )
    
    results = cursor.fetchall()
    db.close()
    
    products = [
        {
            'id': row['id'],
            'name': row['name'],
            'description': row['description'],
            'price': row['price'],
            'stock': row['stock'],
            'order_count': row['order_count']
        }
        for row in results
    ]
    
    return jsonify({
        'query': query,
        'results': products,
        'count': len(products)
    })

# VULNERABLE: CPU-intensive operation with no rate limiting
@app.route('/api/generate-report', methods=['POST'])
def generate_report():
    """
    Generate sales report.
    
    VULNERABILITIES:
    - No rate limiting
    - Very CPU intensive
    - No timeout
    - No queue/async processing
    """
    data = request.get_json() or {}
    user_id = data.get('user_id')
    
    # VULNERABLE: Expensive aggregation query
    db = get_db()
    cursor = db.cursor()
    
    # Simulate very expensive operation
    cursor.execute('''
        SELECT 
            u.id,
            u.name,
            u.email,
            COUNT(o.id) as total_orders,
            SUM(o.total) as total_spent,
            AVG(o.total) as avg_order,
            MIN(o.created_at) as first_order,
            MAX(o.created_at) as last_order
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        GROUP BY u.id
        ORDER BY total_spent DESC
    ''')
    
    results = cursor.fetchall()
    db.close()
    
    # Simulate additional CPU work
    time.sleep(2)  # Simulate report generation
    
    report = [
        {
            'user_id': row['id'],
            'name': row['name'],
            'email': row['email'],
            'total_orders': row['total_orders'] or 0,
            'total_spent': row['total_spent'] or 0,
            'avg_order': row['avg_order'] or 0,
            'first_order': row['first_order'],
            'last_order': row['last_order']
        }
        for row in results
    ]
    
    return jsonify({
        'report': report,
        'generated_at': time.time(),
        'record_count': len(report)
    })

# VULNERABLE: Unbounded batch processing
@app.route('/api/batch/process', methods=['POST'])
def batch_process():
    """
    Process batch of items.
    
    VULNERABILITIES:
    - No limit on batch size
    - No rate limiting
    - Processes everything synchronously
    - Can exhaust memory
    """
    data = request.get_json()
    
    if not data or 'items' not in data:
        return jsonify({'error': 'Items array required'}), 400
    
    items = data['items']
    
    # VULNERABLE: No batch size limit
    # An attacker could send millions of items
    
    results = []
    for item in items:
        # Simulate processing each item (CPU intensive)
        processed = {
            'original': item,
            'processed': item.get('data', '').upper(),
            'hash': hashlib.sha256(str(item).encode()).hexdigest()
        }
        results.append(processed)
    
    return jsonify({
        'results': results,
        'count': len(results)
    })

# VULNERABLE: File upload with no size limit
@app.route('/api/upload', methods=['POST'])
def upload_file():
    """
    Upload file.
    
    VULNERABILITIES:
    - No file size limit
    - No rate limiting
    - No file type validation
    - Stores in memory
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # VULNERABLE: Read entire file into memory (no size check)
    content = file.read()
    
    # Simulate processing
    file_hash = hashlib.sha256(content).hexdigest()
    
    return jsonify({
        'message': 'File uploaded successfully',
        'filename': file.filename,
        'size': len(content),
        'hash': file_hash
    })

# VULNERABLE: No pagination on list endpoint
@app.route('/api/orders')
def get_orders():
    """
    Get all orders.
    
    VULNERABILITIES:
    - No pagination (returns all 50,000 orders)
    - No rate limiting
    - Massive response
    """
    db = get_db()
    cursor = db.cursor()
    
    # VULNERABLE: Fetches ALL orders
    cursor.execute('''
        SELECT 
            o.id,
            o.user_id,
            o.product_id,
            o.quantity,
            o.total,
            o.created_at,
            u.email as user_email,
            p.name as product_name
        FROM orders o
        JOIN users u ON o.user_id = u.id
        JOIN products p ON o.product_id = p.id
        ORDER BY o.created_at DESC
    ''')
    
    orders = cursor.fetchall()
    db.close()
    
    orders_list = [
        {
            'id': order['id'],
            'user_id': order['user_id'],
            'user_email': order['user_email'],
            'product_id': order['product_id'],
            'product_name': order['product_name'],
            'quantity': order['quantity'],
            'total': order['total'],
            'created_at': order['created_at']
        }
        for order in orders
    ]
    
    return jsonify({
        'data': orders_list,
        'count': len(orders_list)
    })

# Endpoint to get stats for monitoring
@app.route('/api/stats')
def get_stats():
    """Get database statistics"""
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM users')
    user_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM products')
    product_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM orders')
    order_count = cursor.fetchone()[0]
    
    db.close()
    
    return jsonify({
        'users': user_count,
        'products': product_count,
        'orders': order_count
    })

if __name__ == '__main__':
    print("=" * 60)
    print("VULNERABLE API - API04: Unrestricted Resource Consumption")
    print("=" * 60)
    print("This API intentionally lacks security controls.")
    print("Do NOT use in production!")
    print("")
    print("Vulnerabilities:")
    print("  - No rate limiting")
    print("  - No pagination")
    print("  - No request size limits")
    print("  - No timeouts")
    print("  - Expensive operations without throttling")
    print("")
    print("API running at: http://localhost:5000")
    print("Web interface: http://localhost:5000/")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
