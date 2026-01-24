from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
import json

app = Flask(__name__)
CORS(app)

def init_db():
    conn = sqlite3.connect('ecommerce.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY, name TEXT, price REAL, stock INTEGER, limited_edition INTEGER)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS orders
                 (id INTEGER PRIMARY KEY, user_id INTEGER, product_id INTEGER, quantity INTEGER,
                  total_price REAL, created_at TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS coupons
                 (code TEXT PRIMARY KEY, discount_percent INTEGER, active INTEGER, max_uses INTEGER, used_count INTEGER)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS cart_reservations
                 (id INTEGER PRIMARY KEY, user_id INTEGER, product_id INTEGER, quantity INTEGER,
                  reserved_at TEXT, expires_at TEXT)''')
    
    # Insert sample data
    c.execute("DELETE FROM products")
    products = [
        (1, 'Limited Edition Sneakers', 299.99, 50, 1),
        (2, 'Exclusive Watch', 599.99, 20, 1),
        (3, 'Designer Bag', 449.99, 30, 1),
        (4, 'Regular Shirt', 29.99, 1000, 0),
    ]
    c.executemany('INSERT INTO products VALUES (?,?,?,?,?)', products)
    
    c.execute("DELETE FROM coupons")
    coupons = [
        ('SAVE10', 10, 1, 1000, 0),
        ('SAVE20', 20, 1, 500, 0),
        ('VIP30', 30, 1, 100, 0),
        ('FLASH50', 50, 1, 50, 0),
    ]
    c.executemany('INSERT INTO coupons VALUES (?,?,?,?,?)', coupons)
    
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

# VULNERABLE: No rate limiting on product listing (scraping)
@app.route('/api/products', methods=['GET'])
def get_products():
    conn = sqlite3.connect('ecommerce.db')
    c = conn.cursor()
    c.execute('SELECT * FROM products')
    products = [{'id': r[0], 'name': r[1], 'price': r[2], 'stock': r[3], 'limited_edition': bool(r[4])} 
                for r in c.fetchall()]
    conn.close()
    return jsonify(products)

# VULNERABLE: No purchase velocity checks
@app.route('/api/purchase', methods=['POST'])
def purchase():
    data = request.json
    user_id = data.get('user_id', 1)
    product_id = data['product_id']
    quantity = data.get('quantity', 1)
    coupons = data.get('coupons', [])
    
    conn = sqlite3.connect('ecommerce.db')
    c = conn.cursor()
    
    # Check stock
    c.execute('SELECT price, stock FROM products WHERE id = ?', (product_id,))
    result = c.fetchone()
    if not result:
        conn.close()
        return jsonify({'error': 'Product not found'}), 404
    
    price, stock = result
    
    if stock < quantity:
        conn.close()
        return jsonify({'error': 'Insufficient stock'}), 400
    
    # Calculate total
    total = price * quantity
    
    # VULNERABLE: Apply multiple coupons without limits
    for coupon_code in coupons:
        c.execute('SELECT discount_percent, active, max_uses, used_count FROM coupons WHERE code = ?', (coupon_code,))
        coupon = c.fetchone()
        if coupon and coupon[1]:  # active
            discount_percent, active, max_uses, used_count = coupon
            total *= (1 - discount_percent / 100)
            # Increment usage
            c.execute('UPDATE coupons SET used_count = used_count + 1 WHERE code = ?', (coupon_code,))
    
    # Update stock
    c.execute('UPDATE products SET stock = stock - ? WHERE id = ?', (quantity, product_id))
    
    # Create order
    c.execute('INSERT INTO orders (user_id, product_id, quantity, total_price, created_at) VALUES (?, ?, ?, ?, ?)',
              (user_id, product_id, quantity, total, datetime.now().isoformat()))
    
    order_id = c.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'order_id': order_id, 'total': round(total, 2)})

# VULNERABLE: Unlimited cart reservations
@app.route('/api/cart/reserve', methods=['POST'])
def reserve_cart():
    data = request.json
    user_id = data.get('user_id', 1)
    product_id = data['product_id']
    quantity = data.get('quantity', 1)
    
    conn = sqlite3.connect('ecommerce.db')
    c = conn.cursor()
    
    # Create reservation without checking existing reservations
    expires_at = (datetime.now() + timedelta(hours=24)).isoformat()  # 24 hour expiry
    
    c.execute('INSERT INTO cart_reservations (user_id, product_id, quantity, reserved_at, expires_at) VALUES (?, ?, ?, ?, ?)',
              (user_id, product_id, quantity, datetime.now().isoformat(), expires_at))
    
    # Reduce available stock (not properly managed)
    c.execute('UPDATE products SET stock = stock - ? WHERE id = ?', (quantity, product_id))
    
    reservation_id = c.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'reservation_id': reservation_id, 'expires_at': expires_at})

# Get orders (for monitoring)
@app.route('/api/orders', methods=['GET'])
def get_orders():
    conn = sqlite3.connect('ecommerce.db')
    c = conn.cursor()
    c.execute('SELECT o.*, p.name FROM orders o JOIN products p ON o.product_id = p.id ORDER BY o.created_at DESC LIMIT 50')
    orders = [{'id': r[0], 'user_id': r[1], 'product_id': r[2], 'quantity': r[3], 
               'total_price': r[4], 'created_at': r[5], 'product_name': r[6]} for r in c.fetchall()]
    conn.close()
    return jsonify(orders)

# Reset database
@app.route('/api/reset', methods=['POST'])
def reset_db():
    init_db()
    return jsonify({'success': True, 'message': 'Database reset'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
