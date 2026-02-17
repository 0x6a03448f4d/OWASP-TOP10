"""
SECURE API - API04: Unrestricted Resource Consumption - FIXED

This is the secure version with proper resource consumption controls:
- Rate limiting using Flask-Limiter
- Pagination on all list endpoints
- Request size limits (10MB)
- Batch size limits (max 100 items)
- Input validation
- Timeout protection for expensive operations
- Proper error handling

Use this as a reference for securing production APIs.
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import hashlib
import time
import random
import string
import os
import signal
from contextlib import contextmanager

app = Flask(__name__)
CORS(app)

# SECURITY CONTROL 1: Request size limit (10MB maximum)
# Prevents memory exhaustion from large payloads
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB

# SECURITY CONTROL 2: Rate limiting configuration
# Protects against DoS attacks and brute force attempts
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",  # PRODUCTION NOTE: Use Redis (redis://host:port) for:
                               # - Persistence across restarts
                               # - Distributed rate limiting across multiple servers
                               # - Better performance at scale
    default_limits=["100 per hour"],  # Global default limit
    headers_enabled=True  # Send rate limit headers to clients
)

DATABASE = 'secure.db'

# SECURITY CONTROL 3: Batch processing limits
# Prevents memory and CPU exhaustion from oversized batches
MAX_BATCH_SIZE = 100

# SECURITY CONTROL 4: Pagination defaults and limits
# Prevents massive data dumps that exhaust memory
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100

# SECURITY CONTROL 5: Query string length limits
# Prevents expensive database queries from excessively long search terms
MAX_QUERY_LENGTH = 200

# SECURITY CONTROL 6: Timeout for expensive operations (seconds)
# Prevents long-running operations from tying up resources
EXPENSIVE_OPERATION_TIMEOUT = 30


@contextmanager
def timeout(seconds):
    """
    Timeout context manager for expensive operations.
    
    SECURITY CONTROL 7: Implements timeout protection to prevent
    long-running operations from exhausting server resources.
    
    NOTE: This signal-based implementation works for single-threaded
    demo purposes but is NOT thread-safe. For production use with
    multi-threaded WSGI servers, use:
    - threading.Timer for synchronous operations
    - asyncio timeouts for async operations
    - Celery task timeouts for background jobs
    """
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds} seconds")
    
    # Set the signal handler and alarm
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        # Restore previous handler and cancel alarm
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


@app.errorhandler(413)
def request_too_large(error):
    """
    Handle requests that exceed MAX_CONTENT_LENGTH.
    
    SECURITY: Returns clear error when request size limit is exceeded.
    """
    return jsonify({
        'error': 'Request too large',
        'max_size': '10 MB'
    }), 413


@app.errorhandler(429)
def ratelimit_handler(error):
    """
    Handle rate limit exceeded errors.
    
    SECURITY: Provides clear feedback when rate limits are hit.
    """
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': str(error.description)
    }), 429


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
@limiter.exempt  # Health checks should not be rate limited
def health():
    """
    Health check endpoint.
    
    SECURITY: Exempt from rate limiting as it's used for monitoring.
    """
    return jsonify({'status': 'healthy', 'message': 'Secure API is running'})


@app.route('/api/users')
@limiter.limit("60 per minute")  # SECURITY: Rate limit to prevent flooding
def get_users():
    """
    Get paginated list of users.
    
    SECURITY CONTROLS IMPLEMENTED:
    - Rate limiting: 60 requests per minute
    - Pagination: Returns max 100 users per request
    - Input validation: Page and per_page parameters validated
    """
    # SECURITY: Get and validate pagination parameters
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', DEFAULT_PAGE_SIZE))
    except ValueError:
        return jsonify({'error': 'Invalid pagination parameters'}), 400
    
    # SECURITY: Validate pagination bounds
    if page < 1:
        return jsonify({'error': 'Page must be >= 1'}), 400
    
    if per_page < 1 or per_page > MAX_PAGE_SIZE:
        return jsonify({
            'error': f'per_page must be between 1 and {MAX_PAGE_SIZE}'
        }), 400
    
    # Calculate offset
    offset = (page - 1) * per_page
    
    db = get_db()
    cursor = db.cursor()
    
    # SECURITY: Use LIMIT and OFFSET to prevent returning all users
    cursor.execute(
        'SELECT id, email, name, created_at FROM users LIMIT ? OFFSET ?',
        (per_page, offset)
    )
    users = cursor.fetchall()
    
    # Get total count for pagination metadata
    cursor.execute('SELECT COUNT(*) FROM users')
    total = cursor.fetchone()[0]
    
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
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page
        }
    })


@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # SECURITY: Strict rate limit prevents brute force
def login():
    """
    User login endpoint.
    
    SECURITY CONTROLS IMPLEMENTED:
    - Rate limiting: 5 requests per minute to prevent brute force attacks
    - Input validation: Required fields checked
    - Timeout protection: Password hashing operation has time limit
    """
    data = request.get_json()
    
    # SECURITY: Validate required fields
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password required'}), 400
    
    email = data['email']
    password = data['password']
    
    # SECURITY: Validate input lengths
    if len(email) > 255 or len(password) > 255:
        return jsonify({'error': 'Invalid email or password length'}), 400
    
    try:
        # SECURITY: Timeout protection for expensive hashing operation
        with timeout(5):
            # NOTE: This uses SHA-256 for demo purposes only to match the vulnerable version's data
            # PRODUCTION: Use bcrypt, scrypt, or argon2 for password hashing:
            # import bcrypt
            # password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            time.sleep(0.1)  # Simulate bcrypt delay
            password_hash = hashlib.sha256(password.encode()).hexdigest()
    except TimeoutError:
        return jsonify({'error': 'Login operation timeout'}), 408
    
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


@app.route('/api/search')
@limiter.limit("30 per minute")  # SECURITY: Rate limit for expensive search operations
def search():
    """
    Search products with rate limiting and query validation.
    
    SECURITY CONTROLS IMPLEMENTED:
    - Rate limiting: 30 requests per minute
    - Query length validation: Prevents excessively long queries
    - Pagination: Limits result set size
    - Timeout protection: Search operation has time limit
    """
    query = request.args.get('q', '')
    
    # SECURITY: Validate query length to prevent expensive operations
    if len(query) > MAX_QUERY_LENGTH:
        return jsonify({
            'error': f'Query too long (max {MAX_QUERY_LENGTH} characters)'
        }), 400
    
    # SECURITY: Get pagination parameters
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', DEFAULT_PAGE_SIZE))
    except ValueError:
        return jsonify({'error': 'Invalid pagination parameters'}), 400
    
    if page < 1 or per_page < 1 or per_page > MAX_PAGE_SIZE:
        return jsonify({'error': 'Invalid pagination values'}), 400
    
    offset = (page - 1) * per_page
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        # SECURITY: Timeout protection for potentially expensive search
        with timeout(10):
            # SECURITY: Use LIMIT to prevent returning massive result sets
            cursor.execute(
                '''
                SELECT p.*, COUNT(o.id) as order_count
                FROM products p
                LEFT JOIN orders o ON p.id = o.product_id
                WHERE p.name LIKE ? OR p.description LIKE ?
                GROUP BY p.id
                ORDER BY order_count DESC
                LIMIT ? OFFSET ?
                ''',
                (f'%{query}%', f'%{query}%', per_page, offset)
            )
            
            results = cursor.fetchall()
            
            # Get total count
            cursor.execute(
                '''
                SELECT COUNT(DISTINCT p.id)
                FROM products p
                WHERE p.name LIKE ? OR p.description LIKE ?
                ''',
                (f'%{query}%', f'%{query}%')
            )
            total = cursor.fetchone()[0]
    except TimeoutError:
        db.close()
        return jsonify({'error': 'Search operation timeout'}), 408
    
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
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page
        }
    })


@app.route('/api/generate-report', methods=['POST'])
@limiter.limit("2 per minute")  # SECURITY: Very strict limit for expensive operations
def generate_report():
    """
    Generate sales report with strict rate limiting and timeout.
    
    SECURITY CONTROLS IMPLEMENTED:
    - Rate limiting: 2 requests per minute (very expensive operation)
    - Timeout protection: 30 second limit on report generation
    - Input validation: Validates request data
    """
    data = request.get_json() or {}
    
    # SECURITY: Validate input
    if 'user_id' in data:
        try:
            user_id = int(data['user_id'])
            if user_id < 1:
                return jsonify({'error': 'Invalid user_id'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'user_id must be an integer'}), 400
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        # SECURITY: Timeout protection for expensive operation
        with timeout(EXPENSIVE_OPERATION_TIMEOUT):
            # Expensive aggregation query
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
                LIMIT 1000
            ''')  # SECURITY: Limit result set to prevent memory exhaustion
            
            results = cursor.fetchall()
            
            # Simulate additional CPU work
            time.sleep(2)  # Simulate report generation
    except TimeoutError:
        db.close()
        return jsonify({
            'error': 'Report generation timeout',
            'message': 'Operation took too long to complete'
        }), 408
    
    db.close()
    
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


@app.route('/api/batch/process', methods=['POST'])
@limiter.limit("10 per minute")  # SECURITY: Rate limit batch operations
def batch_process():
    """
    Process batch of items with size limits.
    
    SECURITY CONTROLS IMPLEMENTED:
    - Rate limiting: 10 requests per minute
    - Batch size limit: Maximum 100 items per batch
    - Input validation: Validates items array and individual items
    - Timeout protection: Prevents excessively long processing
    """
    data = request.get_json()
    
    # SECURITY: Validate request structure
    if not data or 'items' not in data:
        return jsonify({'error': 'Items array required'}), 400
    
    items = data['items']
    
    # SECURITY: Validate items is a list
    if not isinstance(items, list):
        return jsonify({'error': 'Items must be an array'}), 400
    
    # SECURITY: Enforce batch size limit to prevent memory/CPU exhaustion
    if len(items) > MAX_BATCH_SIZE:
        return jsonify({
            'error': f'Batch size exceeds maximum of {MAX_BATCH_SIZE}',
            'received': len(items),
            'max_allowed': MAX_BATCH_SIZE
        }), 400
    
    # SECURITY: Validate each item
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            return jsonify({
                'error': f'Item at index {i} is not an object'
            }), 400
    
    try:
        # SECURITY: Timeout protection for batch processing
        with timeout(30):
            results = []
            for item in items:
                # Simulate processing each item (CPU intensive)
                processed = {
                    'original': item,
                    'processed': item.get('data', '').upper(),
                    'hash': hashlib.sha256(str(item).encode()).hexdigest()
                }
                results.append(processed)
    except TimeoutError:
        return jsonify({
            'error': 'Batch processing timeout',
            'message': 'Operation took too long to complete'
        }), 408
    
    return jsonify({
        'results': results,
        'count': len(results)
    })


@app.route('/api/upload', methods=['POST'])
@limiter.limit("20 per minute")  # SECURITY: Rate limit file uploads
def upload_file():
    """
    Upload file with size and type validation.
    
    SECURITY CONTROLS IMPLEMENTED:
    - Rate limiting: 20 requests per minute
    - File size limit: Enforced by MAX_CONTENT_LENGTH (10MB)
    - Input validation: Checks file presence and filename
    
    Note: File type validation should be added for production use.
    """
    # SECURITY: Validate file in request
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    # SECURITY: Validate filename
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # SECURITY: Read file (size already limited by MAX_CONTENT_LENGTH)
    try:
        content = file.read()
    except Exception as e:
        return jsonify({'error': 'Failed to read file'}), 400
    
    # Simulate processing
    file_hash = hashlib.sha256(content).hexdigest()
    
    return jsonify({
        'message': 'File uploaded successfully',
        'filename': file.filename,
        'size': len(content),
        'hash': file_hash
    })


@app.route('/api/orders')
@limiter.limit("60 per minute")  # SECURITY: Rate limit to prevent flooding
def get_orders():
    """
    Get paginated list of orders.
    
    SECURITY CONTROLS IMPLEMENTED:
    - Rate limiting: 60 requests per minute
    - Pagination: Returns max 100 orders per request
    - Input validation: Page and per_page parameters validated
    """
    # SECURITY: Get and validate pagination parameters
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', DEFAULT_PAGE_SIZE))
    except ValueError:
        return jsonify({'error': 'Invalid pagination parameters'}), 400
    
    # SECURITY: Validate pagination bounds
    if page < 1:
        return jsonify({'error': 'Page must be >= 1'}), 400
    
    if per_page < 1 or per_page > MAX_PAGE_SIZE:
        return jsonify({
            'error': f'per_page must be between 1 and {MAX_PAGE_SIZE}'
        }), 400
    
    offset = (page - 1) * per_page
    
    db = get_db()
    cursor = db.cursor()
    
    # SECURITY: Use LIMIT and OFFSET to prevent returning all orders
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
        LIMIT ? OFFSET ?
    ''', (per_page, offset))
    
    orders = cursor.fetchall()
    
    # Get total count
    cursor.execute('SELECT COUNT(*) FROM orders')
    total = cursor.fetchone()[0]
    
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
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page
        }
    })


@app.route('/api/products')
@limiter.limit("60 per minute")  # SECURITY: Rate limit product listings
def get_products():
    """
    Get paginated list of products.
    
    SECURITY CONTROLS IMPLEMENTED:
    - Rate limiting: 60 requests per minute
    - Pagination: Returns max 100 products per request
    - Input validation: Page and per_page parameters validated
    """
    # SECURITY: Get and validate pagination parameters
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', DEFAULT_PAGE_SIZE))
    except ValueError:
        return jsonify({'error': 'Invalid pagination parameters'}), 400
    
    # SECURITY: Validate pagination bounds
    if page < 1:
        return jsonify({'error': 'Page must be >= 1'}), 400
    
    if per_page < 1 or per_page > MAX_PAGE_SIZE:
        return jsonify({
            'error': f'per_page must be between 1 and {MAX_PAGE_SIZE}'
        }), 400
    
    offset = (page - 1) * per_page
    
    db = get_db()
    cursor = db.cursor()
    
    # SECURITY: Use LIMIT and OFFSET to prevent returning all products
    cursor.execute(
        'SELECT id, name, description, price, stock, created_at FROM products LIMIT ? OFFSET ?',
        (per_page, offset)
    )
    products = cursor.fetchall()
    
    # Get total count
    cursor.execute('SELECT COUNT(*) FROM products')
    total = cursor.fetchone()[0]
    
    db.close()
    
    products_list = [
        {
            'id': product['id'],
            'name': product['name'],
            'description': product['description'],
            'price': product['price'],
            'stock': product['stock'],
            'created_at': product['created_at']
        }
        for product in products
    ]
    
    return jsonify({
        'data': products_list,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page
        }
    })


@app.route('/api/stats')
@limiter.limit("120 per minute")  # SECURITY: Higher limit for lightweight stats endpoint
def get_stats():
    """
    Get database statistics.
    
    SECURITY: Lightweight operation with moderate rate limit.
    """
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
    print("SECURE API - API04: Unrestricted Resource Consumption")
    print("=" * 60)
    print("This API implements proper security controls:")
    print("")
    print("Security Controls:")
    print("  ✓ Rate limiting on all endpoints")
    print("  ✓ Pagination on list endpoints")
    print("  ✓ Request size limits (10MB)")
    print("  ✓ Batch size limits (max 100 items)")
    print("  ✓ Input validation")
    print("  ✓ Timeout protection for expensive operations")
    print("  ✓ Proper error handling")
    print("")
    print("API running at: http://localhost:5000")
    print("Web interface: http://localhost:5000/")
    print("=" * 60)
    print("")
    print("WARNING: Running in DEBUG mode for lab purposes only!")
    print("PRODUCTION: Set debug=False and use a production WSGI server")
    print("=" * 60)
    
    # SECURITY WARNING: debug=True is INTENTIONALLY used for educational lab purposes
    # This enables the interactive debugger which is a security risk in production
    # PRODUCTION DEPLOYMENT: Use debug=False and deploy with:
    # - gunicorn: gunicorn -w 4 -b 0.0.0.0:5000 server_secure:app
    # - uWSGI: uwsgi --http :5000 --wsgi-file server_secure.py --callable app
    app.run(host='0.0.0.0', port=5000, debug=True)  # noqa: S201 - intentional for lab
