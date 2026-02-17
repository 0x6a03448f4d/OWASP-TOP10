# API04: Unrestricted Resource Consumption - Prevention

## Table of Contents
- [Defense Strategy Overview](#defense-strategy-overview)
- [Rate Limiting Implementation](#rate-limiting-implementation)
- [Pagination Best Practices](#pagination-best-practices)
- [Query Limits and Optimization](#query-limits-and-optimization)
- [Timeout Configuration](#timeout-configuration)
- [Caching Strategies](#caching-strategies)
- [Resource Quotas](#resource-quotas)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Infrastructure Protections](#infrastructure-protections)

## Defense Strategy Overview

Preventing resource exhaustion requires a **defense-in-depth** approach with multiple protective layers.

### The Protection Pyramid

```
                    ┌─────────────────┐
                    │   Monitoring    │  ← Detect anomalies
                    └─────────────────┘
                  ┌───────────────────┐
                  │  Business Logic   │  ← Smart limits
                  └───────────────────┘
                ┌─────────────────────┐
              │  Application Layer  │  ← Rate limiting
              └─────────────────────┘
            ┌───────────────────────────┐
            │   Infrastructure Layer    │  ← Resource quotas
            └───────────────────────────┘
          ┌─────────────────────────────────┐
          │        Network Layer            │  ← DDoS protection
          └─────────────────────────────────┘
```

### Core Principles

1. **Fail Gracefully**: Degrade service quality instead of crashing
2. **Limit Everything**: Every resource needs bounds
3. **Monitor Continuously**: Detect abnormal patterns early
4. **Cost-Based Limiting**: Expensive operations get tighter limits
5. **User-Aware Controls**: Different limits for different user types
6. **Adaptive Throttling**: Adjust limits based on system load

## Rate Limiting Implementation

Rate limiting is your first line of defense against volume-based attacks.

### Algorithm 1: Token Bucket

**How It Works**: Tokens are added to a bucket at a fixed rate. Each request consumes a token. When the bucket is empty, requests are rejected.

**Benefits**:
- Allows burst traffic
- Smooth rate limiting
- Industry standard

**Implementation**:

```python
import time
import redis

class TokenBucket:
    def __init__(self, redis_client, key, capacity, refill_rate):
        """
        capacity: Maximum tokens in bucket
        refill_rate: Tokens added per second
        """
        self.redis = redis_client
        self.key = key
        self.capacity = capacity
        self.refill_rate = refill_rate
    
    def consume(self, tokens=1):
        """Try to consume tokens. Returns True if allowed."""
        lua_script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local tokens_requested = tonumber(ARGV[3])
        local now = tonumber(ARGV[4])
        
        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1])
        local last_refill = tonumber(bucket[2])
        
        if tokens == nil then
            tokens = capacity
            last_refill = now
        end
        
        -- Refill tokens based on time elapsed
        local elapsed = now - last_refill
        local new_tokens = math.min(capacity, tokens + (elapsed * refill_rate))
        
        -- Try to consume
        if new_tokens >= tokens_requested then
            new_tokens = new_tokens - tokens_requested
            redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
            redis.call('EXPIRE', key, 3600)  -- Cleanup after 1 hour
            return 1
        else
            return 0
        end
        """
        
        result = self.redis.eval(
            lua_script,
            1,
            self.key,
            self.capacity,
            self.refill_rate,
            tokens,
            time.time()
        )
        
        return bool(result)

# Usage with Flask
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

def rate_limit(capacity=100, refill_rate=10):
    """Decorator for rate limiting endpoints"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Identify user (prefer user ID, fallback to IP)
            user_id = request.headers.get('X-User-ID', request.remote_addr)
            key = f"rate_limit:{f.__name__}:{user_id}"
            
            bucket = TokenBucket(redis_client, key, capacity, refill_rate)
            
            if bucket.consume():
                return f(*args, **kwargs)
            else:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': 60
                }), 429
        
        return wrapped
    return decorator

@app.route('/api/search')
@rate_limit(capacity=100, refill_rate=10)  # 100 tokens, refill 10/sec
def search():
    query = request.args.get('q')
    results = perform_search(query)
    return jsonify(results)
```

### Algorithm 2: Sliding Window

**How It Works**: Tracks requests in a time window that slides continuously.

**Benefits**:
- No boundary issues (vs fixed window)
- Precise rate limiting
- Fair distribution

**Implementation**:

```python
import time
import redis

class SlidingWindow:
    def __init__(self, redis_client, key, max_requests, window_seconds):
        self.redis = redis_client
        self.key = key
        self.max_requests = max_requests
        self.window_seconds = window_seconds
    
    def is_allowed(self):
        """Check if request is allowed under sliding window"""
        now = time.time()
        window_start = now - self.window_seconds
        
        # Use Redis sorted set with timestamps as scores
        pipeline = self.redis.pipeline()
        
        # Remove old entries outside window
        pipeline.zremrangebyscore(self.key, 0, window_start)
        
        # Count requests in current window
        pipeline.zcard(self.key)
        
        # Add current request
        pipeline.zadd(self.key, {f"req_{now}": now})
        
        # Set expiration
        pipeline.expire(self.key, self.window_seconds * 2)
        
        results = pipeline.execute()
        request_count = results[1]
        
        return request_count < self.max_requests

# Usage
def sliding_window_limit(max_requests=100, window_seconds=60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user_id = request.headers.get('X-User-ID', request.remote_addr)
            key = f"sliding_window:{f.__name__}:{user_id}"
            
            window = SlidingWindow(redis_client, key, max_requests, window_seconds)
            
            if window.is_allowed():
                return f(*args, **kwargs)
            else:
                return jsonify({'error': 'Rate limit exceeded'}), 429
        
        return wrapped
    return decorator

@app.route('/api/login', methods=['POST'])
@sliding_window_limit(max_requests=5, window_seconds=60)  # 5 login attempts per minute
def login():
    # Login logic
    pass
```

### Algorithm 3: Fixed Window Counter

**How It Works**: Count requests in fixed time windows (e.g., per minute).

**Benefits**:
- Simple implementation
- Low memory usage
- Easy to understand

**Limitations**:
- Boundary issue: Can receive 2x limit at window boundaries

**Implementation**:

```python
class FixedWindow:
    def __init__(self, redis_client, key, max_requests, window_seconds):
        self.redis = redis_client
        self.key = key
        self.max_requests = max_requests
        self.window_seconds = window_seconds
    
    def is_allowed(self):
        now = int(time.time())
        window = now // self.window_seconds
        key = f"{self.key}:{window}"
        
        current = self.redis.incr(key)
        
        if current == 1:
            self.redis.expire(key, self.window_seconds * 2)
        
        return current <= self.max_requests
```

### Multi-Tier Rate Limiting

Different limits for different user types:

```python
RATE_LIMITS = {
    'anonymous': {
        'requests_per_minute': 10,
        'burst': 20
    },
    'authenticated': {
        'requests_per_minute': 100,
        'burst': 200
    },
    'premium': {
        'requests_per_minute': 1000,
        'burst': 2000
    },
    'admin': {
        'requests_per_minute': 10000,
        'burst': 20000
    }
}

def get_user_tier(request):
    """Determine user tier from request"""
    if not request.headers.get('Authorization'):
        return 'anonymous'
    
    # Decode JWT or check session
    user = get_user_from_token(request.headers['Authorization'])
    
    if user.is_admin:
        return 'admin'
    elif user.subscription == 'premium':
        return 'premium'
    else:
        return 'authenticated'

def adaptive_rate_limit(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        tier = get_user_tier(request)
        limits = RATE_LIMITS[tier]
        
        # Apply tier-specific limits
        # ... implementation
        
        return f(*args, **kwargs)
    return wrapped
```

### Cost-Based Rate Limiting

Different limits based on operation cost:

```python
ENDPOINT_COSTS = {
    '/api/health': 1,           # Cheap
    '/api/users/profile': 5,    # Medium
    '/api/search': 10,          # Expensive
    '/api/reports/generate': 50 # Very expensive
}

def cost_based_rate_limit(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        endpoint = request.endpoint
        cost = ENDPOINT_COSTS.get(endpoint, 10)
        
        user_id = get_user_id(request)
        key = f"cost_limit:{user_id}"
        
        # Token bucket with cost-based consumption
        bucket = TokenBucket(redis_client, key, capacity=1000, refill_rate=10)
        
        if bucket.consume(tokens=cost):
            return f(*args, **kwargs)
        else:
            return jsonify({
                'error': 'Rate limit exceeded',
                'cost': cost,
                'retry_after': cost / 10  # Seconds until enough tokens
            }), 429
    
    return wrapped
```

### Using Flask-Limiter Library

For production use, leverage battle-tested libraries:

```python
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Initialize limiter with Redis backend
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379",
    default_limits=["200 per day", "50 per hour"],
    headers_enabled=True  # Return rate limit info in headers
)

# Global default limits apply to all routes
# Override per route as needed

@app.route('/api/expensive')
@limiter.limit("10 per minute")
def expensive_operation():
    return jsonify({'data': 'result'})

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Stricter for authentication
def login():
    return jsonify({'token': 'xyz'})

# Dynamic limits based on user
def get_user_limit():
    """Return different limits for different users"""
    if is_premium_user(request):
        return "1000 per hour"
    return "100 per hour"

@app.route('/api/search')
@limiter.limit(get_user_limit)
def search():
    return jsonify({'results': []})

# Exempt certain routes
@app.route('/api/health')
@limiter.exempt
def health():
    return jsonify({'status': 'ok'})
```

## Pagination Best Practices

Never return unbounded result sets.

### Cursor-Based Pagination

**Best for**: Large datasets, real-time data

```python
from flask import Flask, request, jsonify
import base64
import json

@app.route('/api/users')
def get_users():
    # Get cursor from query parameter
    cursor = request.args.get('cursor')
    limit = min(int(request.args.get('limit', 100)), 100)  # Max 100 per page
    
    if cursor:
        # Decode cursor
        cursor_data = json.loads(base64.b64decode(cursor))
        last_id = cursor_data['last_id']
        
        # Query after cursor
        users = User.query.filter(User.id > last_id)\
            .order_by(User.id)\
            .limit(limit + 1)\
            .all()
    else:
        # First page
        users = User.query.order_by(User.id).limit(limit + 1).all()
    
    # Check if there's a next page
    has_next = len(users) > limit
    users = users[:limit]
    
    # Generate next cursor
    next_cursor = None
    if has_next and users:
        cursor_data = {'last_id': users[-1].id}
        next_cursor = base64.b64encode(
            json.dumps(cursor_data).encode()
        ).decode()
    
    return jsonify({
        'data': [u.to_dict() for u in users],
        'pagination': {
            'cursor': next_cursor,
            'has_next': has_next,
            'limit': limit
        }
    })
```

### Offset-Based Pagination

**Best for**: Simple cases, known total pages

```python
@app.route('/api/products')
def get_products():
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 50)), 100)  # Max 100
    
    # Validate page number
    if page < 1:
        return jsonify({'error': 'Invalid page number'}), 400
    
    # Limit maximum offset to prevent expensive queries
    max_offset = 10000
    offset = (page - 1) * per_page
    
    if offset > max_offset:
        return jsonify({
            'error': f'Maximum offset exceeded. Use cursor-based pagination for deep pages.'
        }), 400
    
    # Query with offset
    products = Product.query.offset(offset).limit(per_page).all()
    total = Product.query.count()
    
    return jsonify({
        'data': [p.to_dict() for p in products],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page
        }
    })
```

### Keyset Pagination

**Best for**: Large datasets with stable ordering

```python
@app.route('/api/posts')
def get_posts():
    last_created_at = request.args.get('last_created_at')
    last_id = request.args.get('last_id')
    limit = min(int(request.args.get('limit', 50)), 100)
    
    query = Post.query.order_by(Post.created_at.desc(), Post.id.desc())
    
    if last_created_at and last_id:
        # Continue from last position
        query = query.filter(
            db.or_(
                Post.created_at < last_created_at,
                db.and_(
                    Post.created_at == last_created_at,
                    Post.id < last_id
                )
            )
        )
    
    posts = query.limit(limit + 1).all()
    has_next = len(posts) > limit
    posts = posts[:limit]
    
    return jsonify({
        'data': [p.to_dict() for p in posts],
        'pagination': {
            'last_created_at': posts[-1].created_at.isoformat() if posts else None,
            'last_id': posts[-1].id if posts else None,
            'has_next': has_next
        }
    })
```

## Query Limits and Optimization

Protect your database from expensive queries.

### Query Timeouts

```python
from sqlalchemy import event
from sqlalchemy.engine import Engine
import time

# Set statement timeout for PostgreSQL
@event.listens_for(Engine, "connect")
def set_timeout(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("SET statement_timeout = 5000")  # 5 second timeout
    cursor.close()

# Or per-query timeout
@app.route('/api/complex-query')
def complex_query():
    try:
        # Execute with timeout
        db.session.execute('SET LOCAL statement_timeout = 3000')  # 3 seconds
        results = db.session.execute(complex_sql_query).fetchall()
        return jsonify([dict(r) for r in results])
    except Exception as e:
        if 'timeout' in str(e).lower():
            return jsonify({'error': 'Query timeout exceeded'}), 408
        raise
```

### Query Complexity Limits

```python
def limit_query_complexity(max_joins=3, max_where_clauses=5):
    """Decorator to limit query complexity"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Analyze query parameters
            filters = request.args.to_dict()
            
            if len(filters) > max_where_clauses:
                return jsonify({
                    'error': f'Too many filter conditions. Maximum: {max_where_clauses}'
                }), 400
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/api/search')
@limit_query_complexity(max_where_clauses=5)
def search():
    # Build query from validated parameters
    pass
```

### GraphQL Query Depth Limiting

```python
from graphql import GraphQLError

def depth_limit_validator(max_depth):
    """Limit GraphQL query depth to prevent N+1 attacks"""
    def validate(context, document, *args):
        depths = []
        
        def measure_depth(node, depth=0):
            if hasattr(node, 'selection_set') and node.selection_set:
                depths.append(depth)
                for field in node.selection_set.selections:
                    measure_depth(field, depth + 1)
        
        for definition in document.definitions:
            measure_depth(definition)
        
        if depths and max(depths) > max_depth:
            raise GraphQLError(
                f'Query depth {max(depths)} exceeds maximum {max_depth}'
            )
    
    return validate

# Usage with graphene
schema = graphene.Schema(
    query=Query,
    validation_rules=[depth_limit_validator(max_depth=5)]
)
```

### Query Cost Analysis

```python
class QueryCostAnalyzer:
    FIELD_COSTS = {
        'User.posts': 10,        # N+1 risk
        'Post.comments': 10,     # N+1 risk
        'User.followers': 50,    # Expensive
        'search': 100,           # Very expensive
    }
    
    MAX_COST = 1000
    
    @staticmethod
    def calculate_cost(query_ast):
        """Calculate cost of GraphQL query"""
        total_cost = 0
        
        def analyze_node(node, multiplier=1):
            nonlocal total_cost
            
            if hasattr(node, 'name'):
                field_name = node.name.value
                cost = QueryCostAnalyzer.FIELD_COSTS.get(field_name, 1)
                total_cost += cost * multiplier
            
            if hasattr(node, 'selection_set') and node.selection_set:
                for field in node.selection_set.selections:
                    # Arguments can increase multiplier (e.g., limit: 100)
                    new_multiplier = multiplier
                    if hasattr(field, 'arguments'):
                        for arg in field.arguments:
                            if arg.name.value == 'limit':
                                new_multiplier *= int(arg.value.value)
                    
                    analyze_node(field, new_multiplier)
        
        for definition in query_ast.definitions:
            analyze_node(definition)
        
        return total_cost
    
    @staticmethod
    def validate(query_ast):
        cost = QueryCostAnalyzer.calculate_cost(query_ast)
        if cost > QueryCostAnalyzer.MAX_COST:
            raise GraphQLError(
                f'Query cost {cost} exceeds maximum {QueryCostAnalyzer.MAX_COST}'
            )
```

## Timeout Configuration

Set timeouts at every layer to prevent hung requests.

### Application-Level Timeouts

```python
from flask import Flask, request
import signal
from contextlib import contextmanager

@contextmanager
def timeout(seconds):
    """Context manager for function timeout"""
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds} seconds")
    
    # Set signal handler
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

@app.route('/api/expensive-operation')
def expensive_operation():
    try:
        with timeout(5):  # 5 second timeout
            result = perform_expensive_calculation()
            return jsonify(result)
    except TimeoutError:
        return jsonify({'error': 'Operation timeout'}), 408

# Or using concurrent.futures for better control
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import time

executor = ThreadPoolExecutor(max_workers=10)

@app.route('/api/process')
def process_with_timeout():
    def do_work():
        return expensive_operation()
    
    future = executor.submit(do_work)
    
    try:
        result = future.result(timeout=10)  # 10 second timeout
        return jsonify(result)
    except TimeoutError:
        return jsonify({'error': 'Processing timeout'}), 408
```

### Request Timeout Middleware

```python
from flask import Flask, request, jsonify
import time
import threading

class TimeoutMiddleware:
    def __init__(self, app, timeout=30):
        self.app = app
        self.timeout = timeout
    
    def __call__(self, environ, start_response):
        request_start = time.time()
        
        # Set timeout for request
        timer = threading.Timer(
            self.timeout,
            lambda: self._timeout_request(environ)
        )
        timer.start()
        
        try:
            return self.app(environ, start_response)
        finally:
            timer.cancel()
            
            # Log slow requests
            duration = time.time() - request_start
            if duration > self.timeout * 0.8:
                app.logger.warning(
                    f"Slow request: {environ['PATH_INFO']} took {duration:.2f}s"
                )
    
    def _timeout_request(self, environ):
        app.logger.error(f"Request timeout: {environ['PATH_INFO']}")

# Apply middleware
app.wsgi_app = TimeoutMiddleware(app.wsgi_app, timeout=30)
```

### Database Connection Timeout

```python
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

engine = create_engine(
    'postgresql://user:pass@localhost/db',
    pool_size=10,
    max_overflow=20,
    pool_timeout=5,  # Wait max 5 seconds for connection
    pool_recycle=3600,  # Recycle connections after 1 hour
    connect_args={
        'connect_timeout': 5,  # Connection timeout
        'options': '-c statement_timeout=5000'  # Query timeout (5 sec)
    }
)
```

## Caching Strategies

Reduce load by caching expensive operations.

### Response Caching

```python
from flask_caching import Cache
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configure caching
cache = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_URL': 'redis://localhost:6379/0',
    'CACHE_DEFAULT_TIMEOUT': 300  # 5 minutes
})

@app.route('/api/popular-products')
@cache.cached(timeout=300, query_string=True)  # Cache based on query params
def get_popular_products():
    # Expensive database query
    products = Product.query.filter_by(featured=True)\
        .order_by(Product.views.desc())\
        .limit(10).all()
    
    return jsonify([p.to_dict() for p in products])

# Cache with custom key
def make_cache_key():
    """Generate cache key based on user and query"""
    user_id = get_user_id(request)
    query = request.args.get('q', '')
    return f"search:{user_id}:{query}"

@app.route('/api/search')
@cache.cached(timeout=60, key_prefix=make_cache_key)
def search():
    query = request.args.get('q')
    results = perform_search(query)
    return jsonify(results)

# Manual cache control
@app.route('/api/user/<int:user_id>')
def get_user(user_id):
    cache_key = f"user:{user_id}"
    
    # Try cache first
    user_data = cache.get(cache_key)
    
    if user_data is None:
        # Cache miss - fetch from database
        user = User.query.get_or_404(user_id)
        user_data = user.to_dict()
        
        # Store in cache
        cache.set(cache_key, user_data, timeout=600)
    
    return jsonify(user_data)
```

### Memoization for Expensive Functions

```python
from functools import lru_cache
import hashlib
import json

# In-memory caching for pure functions
@lru_cache(maxsize=1000)
def calculate_hash(data):
    """Expensive calculation - cache results"""
    return hashlib.sha256(data.encode()).hexdigest()

# Custom memoization with Redis
def redis_memoize(timeout=3600):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Generate cache key from function name and arguments
            key_data = {
                'func': f.__name__,
                'args': args,
                'kwargs': kwargs
            }
            cache_key = f"memo:{hashlib.md5(json.dumps(key_data, sort_keys=True).encode()).hexdigest()}"
            
            # Check cache
            cached = redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
            
            # Compute result
            result = f(*args, **kwargs)
            
            # Store in cache
            redis_client.setex(
                cache_key,
                timeout,
                json.dumps(result)
            )
            
            return result
        return wrapped
    return decorator

@redis_memoize(timeout=600)
def expensive_calculation(param1, param2):
    # Expensive operation
    import time
    time.sleep(2)
    return param1 + param2
```

### ETags for Conditional Requests

```python
from flask import Flask, request, jsonify, make_response
import hashlib
import json

@app.route('/api/data')
def get_data():
    data = fetch_data_from_db()
    
    # Generate ETag from data
    data_json = json.dumps(data, sort_keys=True)
    etag = hashlib.md5(data_json.encode()).hexdigest()
    
    # Check If-None-Match header
    if request.headers.get('If-None-Match') == etag:
        # Data hasn't changed
        return '', 304  # Not Modified
    
    # Return data with ETag
    response = make_response(jsonify(data))
    response.headers['ETag'] = etag
    response.headers['Cache-Control'] = 'private, max-age=300'
    
    return response
```

## Resource Quotas

Enforce hard limits on resource usage.

### User Quotas

```python
class UserQuota:
    def __init__(self, user_id, redis_client):
        self.user_id = user_id
        self.redis = redis_client
    
    def check_quota(self, resource_type, amount=1):
        """Check if user has quota remaining"""
        quota_key = f"quota:{self.user_id}:{resource_type}"
        
        # Get user's tier limits
        tier = get_user_tier(self.user_id)
        limits = QUOTA_LIMITS[tier][resource_type]
        
        # Get current usage
        current_usage = int(self.redis.get(quota_key) or 0)
        
        if current_usage + amount > limits['daily']:
            return False, {
                'error': 'Daily quota exceeded',
                'limit': limits['daily'],
                'current': current_usage,
                'resets_at': get_next_reset_time()
            }
        
        # Increment usage
        pipeline = self.redis.pipeline()
        pipeline.incrby(quota_key, amount)
        pipeline.expireat(quota_key, get_next_reset_time())
        pipeline.execute()
        
        return True, {
            'remaining': limits['daily'] - current_usage - amount
        }

QUOTA_LIMITS = {
    'free': {
        'api_calls': {'daily': 1000},
        'storage_mb': {'total': 100},
        'export_rows': {'daily': 10000}
    },
    'premium': {
        'api_calls': {'daily': 100000},
        'storage_mb': {'total': 10000},
        'export_rows': {'daily': 1000000}
    }
}

@app.route('/api/export')
def export_data():
    user_id = get_user_id(request)
    row_count = request.args.get('rows', 1000)
    
    quota = UserQuota(user_id, redis_client)
    allowed, info = quota.check_quota('export_rows', row_count)
    
    if not allowed:
        return jsonify(info), 429
    
    # Proceed with export
    data = generate_export(row_count)
    
    return jsonify({
        'data': data,
        'quota': info
    })
```

### File Upload Limits

```python
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configure upload limits
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max request size

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB per file

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/upload', methods=['POST'])
@rate_limit(capacity=10, refill_rate=0.1)  # 10 uploads per 100 seconds
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    # Check file size by reading in chunks
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Seek back to start
    
    if size > MAX_FILE_SIZE:
        return jsonify({
            'error': f'File too large. Maximum: {MAX_FILE_SIZE / 1024 / 1024}MB'
        }), 413
    
    # Check user's storage quota
    user_id = get_user_id(request)
    quota = UserQuota(user_id, redis_client)
    allowed, info = quota.check_quota('storage_mb', size / 1024 / 1024)
    
    if not allowed:
        return jsonify(info), 429
    
    # Save file
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    
    return jsonify({
        'status': 'uploaded',
        'filename': filename,
        'size': size,
        'quota_remaining': info['remaining']
    })

# Handle file too large error
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        'error': 'Request too large',
        'max_size_mb': app.config['MAX_CONTENT_LENGTH'] / 1024 / 1024
    }), 413
```

### Memory Limits for Processing

```python
import resource
import sys

def limit_memory(max_mem_mb):
    """Limit memory usage of current process"""
    max_mem_bytes = max_mem_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (max_mem_bytes, max_mem_bytes))

@app.route('/api/process-large-file', methods=['POST'])
def process_large_file():
    # Limit memory to 500MB
    limit_memory(500)
    
    try:
        # Process file
        result = process_file(request.json['file_url'])
        return jsonify(result)
    except MemoryError:
        return jsonify({'error': 'Processing exceeds memory limits'}), 507
```

## Monitoring and Alerting

You can't protect what you can't see.

### Prometheus Metrics

```python
from prometheus_client import Counter, Histogram, Gauge
from flask import Flask, request
import time

# Define metrics
request_count = Counter(
    'api_requests_total',
    'Total API requests',
    ['method', 'endpoint', 'status']
)

request_duration = Histogram(
    'api_request_duration_seconds',
    'API request duration',
    ['method', 'endpoint']
)

active_requests = Gauge(
    'api_active_requests',
    'Currently active requests',
    ['endpoint']
)

rate_limit_hits = Counter(
    'api_rate_limit_hits_total',
    'Rate limit hits',
    ['endpoint', 'user_tier']
)

@app.before_request
def before_request():
    request.start_time = time.time()
    active_requests.labels(endpoint=request.endpoint).inc()

@app.after_request
def after_request(response):
    # Record metrics
    duration = time.time() - request.start_time
    
    request_count.labels(
        method=request.method,
        endpoint=request.endpoint,
        status=response.status_code
    ).inc()
    
    request_duration.labels(
        method=request.method,
        endpoint=request.endpoint
    ).observe(duration)
    
    active_requests.labels(endpoint=request.endpoint).dec()
    
    return response

# Expose metrics endpoint
from prometheus_client import generate_latest

@app.route('/metrics')
def metrics():
    return generate_latest()
```

### Anomaly Detection

```python
class AnomalyDetector:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def check_anomaly(self, user_id, endpoint):
        """Detect abnormal usage patterns"""
        key = f"usage:{user_id}:{endpoint}"
        
        # Record current access
        now = int(time.time())
        self.redis.zadd(key, {now: now})
        self.redis.expire(key, 3600)  # Keep 1 hour of data
        
        # Get access count in last 5 minutes
        five_min_ago = now - 300
        recent_count = self.redis.zcount(key, five_min_ago, now)
        
        # Get historical average
        historical_key = f"avg:{endpoint}"
        historical_avg = float(self.redis.get(historical_key) or 10)
        
        # Check if current rate is anomalous (>3x average)
        if recent_count > historical_avg * 3:
            self.alert_anomaly(user_id, endpoint, recent_count, historical_avg)
            return True
        
        # Update historical average
        self.redis.set(historical_key, (historical_avg * 0.95) + (recent_count * 0.05))
        
        return False
    
    def alert_anomaly(self, user_id, endpoint, current, avg):
        """Send alert about anomalous behavior"""
        app.logger.warning(
            f"Anomaly detected: User {user_id} on {endpoint} - "
            f"{current} requests vs {avg} average"
        )
        # Send to monitoring system (PagerDuty, Slack, etc.)
```

## Infrastructure Protections

Beyond application code, infrastructure needs limits too.

### Docker Resource Limits

```yaml
# docker-compose.yml
version: '3.8'
services:
  api:
    image: myapi:latest
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
      nproc: 512
```

### Kubernetes Resource Quotas

```yaml
# resource-quota.yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: api-quota
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    
---
# pod-definition.yaml
apiVersion: v1
kind: Pod
metadata:
  name: api-pod
spec:
  containers:
  - name: api
    image: myapi:latest
    resources:
      requests:
        memory: "256Mi"
        cpu: "250m"
      limits:
        memory: "512Mi"
        cpu: "500m"
```

### Nginx Rate Limiting

```nginx
# nginx.conf
http {
    # Define rate limit zones
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
    
    # Connection limits
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    server {
        listen 80;
        
        # General rate limit
        limit_req zone=general burst=20 nodelay;
        limit_conn addr 10;
        
        location /api/login {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://backend;
        }
        
        location /api/ {
            limit_req zone=api burst=200 nodelay;
            proxy_pass http://backend;
        }
        
        # Custom error page for rate limiting
        error_page 429 /rate_limit.html;
    }
}
```

## Complete Example: Protected Flask API

```python
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from prometheus_client import Counter, Histogram
import redis

app = Flask(__name__)

# Redis for rate limiting and caching
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

# Rate limiter
limiter = Limiter(
    app=app,
    key_func=lambda: request.headers.get('X-User-ID', get_remote_address()),
    storage_uri="redis://localhost:6379",
    default_limits=["1000 per day", "100 per hour"],
    headers_enabled=True
)

# Cache
cache = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_URL': 'redis://localhost:6379/1'
})

# Metrics
request_count = Counter('requests_total', 'Total requests', ['endpoint', 'status'])

# Configure limits
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB

# Health check (no limits)
@app.route('/health')
@limiter.exempt
def health():
    return jsonify({'status': 'healthy'})

# Expensive search endpoint
@app.route('/api/search')
@limiter.limit("30 per minute")
@cache.cached(timeout=60, query_string=True)
def search():
    query = request.args.get('q', '')
    
    # Validate query length
    if len(query) > 100:
        return jsonify({'error': 'Query too long'}), 400
    
    # Perform search with timeout
    try:
        with timeout(5):
            results = perform_search(query)
            request_count.labels(endpoint='search', status='success').inc()
            return jsonify(results)
    except TimeoutError:
        request_count.labels(endpoint='search', status='timeout').inc()
        return jsonify({'error': 'Search timeout'}), 408

# List endpoint with pagination
@app.route('/api/users')
@limiter.limit("60 per minute")
def list_users():
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 50)), 100)
    
    if page < 1 or per_page < 1:
        return jsonify({'error': 'Invalid pagination parameters'}), 400
    
    users = User.query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'data': [u.to_dict() for u in users.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': users.total,
            'pages': users.pages
        }
    })

# Authentication endpoint (strict limits)
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Login logic with bcrypt (inherently rate-limited by cost)
    pass

# File upload
@app.route('/api/upload', methods=['POST'])
@limiter.limit("10 per hour")
def upload():
    # Upload logic with size limits
    pass

if __name__ == '__main__':
    app.run()
```

## Key Takeaways

1. **Layer multiple defenses** - Rate limiting + pagination + timeouts + caching
2. **Be proactive** - Set limits before you need them
3. **Monitor everything** - Metrics are essential
4. **Fail gracefully** - Return helpful errors, don't crash
5. **Different limits for different contexts** - One size doesn't fit all
6. **Test your limits** - Ensure they actually work under load

## Next Steps

- **Study Real Examples** → [examples.md](./examples.md) - Working code samples
- **Practice** → [lab/](./lab/api04-rate-limiting-lab/) - Hands-on exploitation and hardening
