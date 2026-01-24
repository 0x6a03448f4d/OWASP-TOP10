# API04: Unrestricted Resource Consumption - Examples

## Table of Contents
- [Flask Examples](#flask-examples)
- [Express.js Examples](#expressjs-examples)
- [FastAPI Examples](#fastapi-examples)
- [Django Examples](#django-examples)
- [Redis-Backed Distributed Rate Limiting](#redis-backed-distributed-rate-limiting)
- [Advanced Pagination Patterns](#advanced-pagination-patterns)
- [Real-World Integration Examples](#real-world-integration-examples)

## Flask Examples

### Example 1: Flask-Limiter Basic Setup

```python
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Initialize Flask-Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,  # Use IP address for rate limiting
    default_limits=["200 per day", "50 per hour"],  # Global limits
    storage_uri="memory://",  # Use Redis in production: "redis://localhost:6379"
    headers_enabled=True  # Send rate limit info in response headers
)

# Apply global limits to all routes
@app.route('/api/public')
def public_endpoint():
    """This endpoint has default limits: 200/day, 50/hour"""
    return jsonify({'message': 'Public data'})

# Override with endpoint-specific limits
@app.route('/api/search')
@limiter.limit("10 per minute")
def search():
    """Stricter limit for expensive search operation"""
    query = request.args.get('q')
    results = perform_search(query)
    return jsonify(results)

# Multiple limits (all must be satisfied)
@app.route('/api/export')
@limiter.limit("5 per hour")
@limiter.limit("100 per day")
def export_data():
    """Both hourly AND daily limits apply"""
    data = generate_export()
    return jsonify(data)

# Exempt certain endpoints from rate limiting
@app.route('/api/health')
@limiter.exempt
def health_check():
    """Health checks don't count toward rate limits"""
    return jsonify({'status': 'healthy'})

# Dynamic rate limits based on user
def get_user_limit():
    """Return different limits for different user tiers"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        return "10 per hour"  # Anonymous users
    
    user = decode_token(auth_header)
    
    if user.tier == 'premium':
        return "1000 per hour"
    elif user.tier == 'free':
        return "100 per hour"
    else:
        return "10 per hour"

@app.route('/api/data')
@limiter.limit(get_user_limit)
def get_data():
    """Limit varies by user tier"""
    return jsonify({'data': fetch_data()})

# Custom key function (rate limit by user ID instead of IP)
def get_user_id():
    """Extract user ID from JWT token"""
    auth_header = request.headers.get('Authorization')
    if auth_header:
        token = auth_header.replace('Bearer ', '')
        user = decode_token(token)
        return str(user.id)
    return get_remote_address()  # Fallback to IP

@app.route('/api/user-specific')
@limiter.limit("50 per hour", key_func=get_user_id)
def user_specific():
    """Rate limit per user, not per IP"""
    return jsonify({'message': 'User-specific endpoint'})

# Handle rate limit exceeded
@app.errorhandler(429)
def ratelimit_handler(e):
    """Custom response for rate limit errors"""
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': str(e.description),
        'retry_after': e.retry_after  # Seconds until rate limit resets
    }), 429

if __name__ == '__main__':
    app.run(debug=True)
```

### Example 2: Flask with Redis Token Bucket

```python
from flask import Flask, jsonify, request
import redis
import time
import json

app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

class TokenBucket:
    """Distributed token bucket rate limiter using Redis"""
    
    def __init__(self, redis_client, capacity, refill_rate):
        self.redis = redis_client
        self.capacity = capacity
        self.refill_rate = refill_rate  # Tokens per second
    
    def consume(self, key, tokens=1):
        """
        Try to consume tokens. Returns (allowed, info) tuple.
        Uses Lua script for atomic operation.
        """
        lua_script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local tokens_requested = tonumber(ARGV[3])
        local now = tonumber(ARGV[4])
        
        -- Get current bucket state
        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1])
        local last_refill = tonumber(bucket[2])
        
        -- Initialize bucket if it doesn't exist
        if tokens == nil then
            tokens = capacity
            last_refill = now
        end
        
        -- Calculate tokens to add based on time elapsed
        local elapsed = math.max(0, now - last_refill)
        local tokens_to_add = elapsed * refill_rate
        local new_tokens = math.min(capacity, tokens + tokens_to_add)
        
        -- Try to consume tokens
        if new_tokens >= tokens_requested then
            new_tokens = new_tokens - tokens_requested
            
            -- Update bucket
            redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
            redis.call('EXPIRE', key, 3600)  -- TTL: 1 hour
            
            return {1, new_tokens, capacity}  -- Allowed
        else
            -- Not enough tokens
            return {0, new_tokens, capacity}  -- Denied
        end
        """
        
        result = self.redis.eval(
            lua_script,
            1,  # Number of keys
            key,
            self.capacity,
            self.refill_rate,
            tokens,
            time.time()
        )
        
        allowed = bool(result[0])
        remaining = float(result[1])
        capacity = float(result[2])
        
        return allowed, {
            'remaining': remaining,
            'capacity': capacity,
            'retry_after': (tokens - remaining) / self.refill_rate if not allowed else 0
        }

def rate_limit(capacity=100, refill_rate=10):
    """Decorator for token bucket rate limiting"""
    def decorator(f):
        from functools import wraps
        
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Generate rate limit key
            user_id = request.headers.get('X-User-ID', request.remote_addr)
            key = f"rate_limit:{f.__name__}:{user_id}"
            
            # Create bucket
            bucket = TokenBucket(redis_client, capacity, refill_rate)
            
            # Try to consume token
            allowed, info = bucket.consume(key)
            
            if allowed:
                # Add rate limit headers
                response = f(*args, **kwargs)
                if isinstance(response, tuple):
                    response_obj = response[0]
                else:
                    response_obj = response
                
                if hasattr(response_obj, 'headers'):
                    response_obj.headers['X-RateLimit-Limit'] = str(capacity)
                    response_obj.headers['X-RateLimit-Remaining'] = str(int(info['remaining']))
                
                return response
            else:
                # Rate limit exceeded
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': int(info['retry_after']),
                    'limit': capacity
                }), 429
        
        return wrapped
    return decorator

@app.route('/api/search')
@rate_limit(capacity=50, refill_rate=5)  # 50 tokens, 5 tokens/sec refill
def search():
    query = request.args.get('q')
    results = perform_search(query)
    return jsonify(results)

@app.route('/api/expensive')
@rate_limit(capacity=10, refill_rate=1)  # 10 tokens, 1 token/sec refill
def expensive_operation():
    result = expensive_calculation()
    return jsonify(result)
```

### Example 3: Flask with Pagination

```python
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import base64
import json

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:pass@localhost/db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'created_at': self.created_at.isoformat()
        }

# Method 1: Offset-based pagination (simple, but slow for large offsets)
@app.route('/api/users/offset')
def users_offset_pagination():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)  # Max 100
    
    # Validate
    if page < 1 or per_page < 1:
        return jsonify({'error': 'Invalid pagination parameters'}), 400
    
    # Limit deep pagination to prevent expensive queries
    max_offset = 10000
    offset = (page - 1) * per_page
    
    if offset > max_offset:
        return jsonify({
            'error': f'Offset too large. Maximum: {max_offset}. Use cursor pagination for deep pages.'
        }), 400
    
    # Query
    users = User.query.order_by(User.id).offset(offset).limit(per_page).all()
    total = User.query.count()
    
    return jsonify({
        'data': [u.to_dict() for u in users],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page,
            'has_next': offset + per_page < total,
            'has_prev': page > 1
        }
    })

# Method 2: Cursor-based pagination (efficient for large datasets)
@app.route('/api/users/cursor')
def users_cursor_pagination():
    cursor = request.args.get('cursor')
    limit = min(request.args.get('limit', 50, type=int), 100)
    
    query = User.query.order_by(User.id)
    
    if cursor:
        # Decode cursor
        try:
            cursor_data = json.loads(base64.urlsafe_b64decode(cursor))
            last_id = cursor_data['last_id']
            
            # Continue from cursor
            query = query.filter(User.id > last_id)
        except:
            return jsonify({'error': 'Invalid cursor'}), 400
    
    # Fetch limit + 1 to check if there's a next page
    users = query.limit(limit + 1).all()
    
    has_next = len(users) > limit
    users = users[:limit]
    
    # Generate next cursor
    next_cursor = None
    if has_next and users:
        cursor_data = {'last_id': users[-1].id}
        next_cursor = base64.urlsafe_b64encode(
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

# Method 3: Keyset pagination (best for time-series data)
@app.route('/api/users/keyset')
def users_keyset_pagination():
    last_created_at = request.args.get('last_created_at')
    last_id = request.args.get('last_id', type=int)
    limit = min(request.args.get('limit', 50, type=int), 100)
    
    query = User.query.order_by(User.created_at.desc(), User.id.desc())
    
    if last_created_at and last_id:
        # Continue from last position
        from datetime import datetime
        last_created = datetime.fromisoformat(last_created_at)
        
        query = query.filter(
            db.or_(
                User.created_at < last_created,
                db.and_(
                    User.created_at == last_created,
                    User.id < last_id
                )
            )
        )
    
    users = query.limit(limit + 1).all()
    has_next = len(users) > limit
    users = users[:limit]
    
    return jsonify({
        'data': [u.to_dict() for u in users],
        'pagination': {
            'last_created_at': users[-1].created_at.isoformat() if users else None,
            'last_id': users[-1].id if users else None,
            'has_next': has_next,
            'limit': limit
        }
    })
```

## Express.js Examples

### Example 4: Express Rate Limit

```javascript
const express = require('express');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');

const app = express();
const redisClient = redis.createClient({
    host: 'localhost',
    port: 6379
});

// Global rate limiter
const globalLimiter = rateLimit({
    store: new RedisStore({
        client: redisClient,
        prefix: 'rl:global:'
    }),
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    handler: (req, res) => {
        res.status(429).json({
            error: 'Rate limit exceeded',
            retryAfter: req.rateLimit.resetTime
        });
    }
});

// Apply to all routes
app.use(globalLimiter);

// Strict limiter for authentication endpoints
const authLimiter = rateLimit({
    store: new RedisStore({
        client: redisClient,
        prefix: 'rl:auth:'
    }),
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    skipSuccessfulRequests: true, // Don't count successful logins
    message: {
        error: 'Too many login attempts, please try again later.'
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    // Login logic
    const { email, password } = req.body;
    
    const user = await authenticateUser(email, password);
    
    if (user) {
        res.json({ token: generateToken(user) });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Different limits based on user tier
const createUserLimiter = (tier) => {
    const limits = {
        free: { windowMs: 60 * 60 * 1000, max: 100 },      // 100/hour
        premium: { windowMs: 60 * 60 * 1000, max: 1000 },  // 1000/hour
        enterprise: { windowMs: 60 * 60 * 1000, max: 10000 } // 10000/hour
    };
    
    const config = limits[tier] || limits.free;
    
    return rateLimit({
        store: new RedisStore({
            client: redisClient,
            prefix: `rl:${tier}:`
        }),
        ...config,
        keyGenerator: (req) => {
            // Use user ID from JWT
            return req.user?.id || req.ip;
        }
    });
};

// Middleware to apply user-specific rate limit
app.use('/api/data', async (req, res, next) => {
    const user = await getUserFromToken(req.headers.authorization);
    req.user = user;
    
    const tier = user?.tier || 'free';
    const limiter = createUserLimiter(tier);
    
    limiter(req, res, next);
});

app.get('/api/data', (req, res) => {
    res.json({ data: 'Your data here' });
});

// Sliding window rate limiter (more precise)
const slidingWindowLimiter = (options) => {
    const { windowMs, max } = options;
    
    return async (req, res, next) => {
        const key = `sw:${req.ip}:${req.path}`;
        const now = Date.now();
        const windowStart = now - windowMs;
        
        try {
            // Remove old entries
            await redisClient.zremrangebyscore(key, 0, windowStart);
            
            // Count requests in window
            const count = await redisClient.zcard(key);
            
            if (count >= max) {
                return res.status(429).json({
                    error: 'Rate limit exceeded'
                });
            }
            
            // Add current request
            await redisClient.zadd(key, now, `${now}-${Math.random()}`);
            await redisClient.expire(key, Math.ceil(windowMs / 1000) * 2);
            
            // Add headers
            res.set('X-RateLimit-Limit', max);
            res.set('X-RateLimit-Remaining', max - count - 1);
            
            next();
        } catch (error) {
            console.error('Rate limiting error:', error);
            next(); // Fail open (allow request if rate limiter fails)
        }
    };
};

app.get('/api/search', 
    slidingWindowLimiter({ windowMs: 60000, max: 30 }),
    (req, res) => {
        const results = performSearch(req.query.q);
        res.json(results);
    }
);

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

### Example 5: Express with Pagination

```javascript
const express = require('express');
const { User } = require('./models');

const app = express();

// Offset pagination
app.get('/api/users', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const perPage = Math.min(parseInt(req.query.per_page) || 50, 100); // Max 100
    
    if (page < 1 || perPage < 1) {
        return res.status(400).json({ error: 'Invalid pagination parameters' });
    }
    
    const offset = (page - 1) * perPage;
    const maxOffset = 10000;
    
    if (offset > maxOffset) {
        return res.status(400).json({
            error: `Offset too large. Use cursor pagination for deep pages.`
        });
    }
    
    try {
        const [users, total] = await Promise.all([
            User.findAll({
                limit: perPage,
                offset: offset,
                order: [['id', 'ASC']]
            }),
            User.count()
        ]);
        
        res.json({
            data: users,
            pagination: {
                page,
                per_page: perPage,
                total,
                total_pages: Math.ceil(total / perPage),
                has_next: offset + perPage < total,
                has_prev: page > 1
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

// Cursor pagination
app.get('/api/users/cursor', async (req, res) => {
    const cursor = req.query.cursor;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    
    try {
        let where = {};
        
        if (cursor) {
            // Decode cursor (base64 JSON)
            const cursorData = JSON.parse(
                Buffer.from(cursor, 'base64').toString()
            );
            where = { id: { $gt: cursorData.last_id } };
        }
        
        const users = await User.findAll({
            where,
            limit: limit + 1,
            order: [['id', 'ASC']]
        });
        
        const hasNext = users.length > limit;
        const results = users.slice(0, limit);
        
        let nextCursor = null;
        if (hasNext && results.length > 0) {
            const cursorData = { last_id: results[results.length - 1].id };
            nextCursor = Buffer.from(JSON.stringify(cursorData)).toString('base64');
        }
        
        res.json({
            data: results,
            pagination: {
                cursor: nextCursor,
                has_next: hasNext,
                limit
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});
```

## FastAPI Examples

### Example 6: FastAPI with SlowAPI

```python
from fastapi import FastAPI, Request, HTTPException
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from typing import Optional

app = FastAPI()

# Initialize limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Global default limits
@app.get("/api/public")
@limiter.limit("100/hour")
async def public_endpoint(request: Request):
    """Default rate limit: 100 requests per hour"""
    return {"message": "Public data"}

# Endpoint-specific limits
@app.get("/api/search")
@limiter.limit("10/minute")
async def search(request: Request, q: str):
    """Stricter limit for expensive search"""
    results = perform_search(q)
    return {"results": results}

# Multiple rate limits
@app.get("/api/export")
@limiter.limit("5/hour")
@limiter.limit("20/day")
async def export_data(request: Request):
    """Both hourly and daily limits apply"""
    data = generate_export()
    return {"data": data}

# Dynamic rate limits based on user
def get_user_limit(request: Request) -> str:
    """Return rate limit based on user tier"""
    auth_header = request.headers.get("authorization")
    
    if not auth_header:
        return "10/hour"  # Anonymous
    
    user = decode_token(auth_header)
    
    if user.tier == "premium":
        return "1000/hour"
    elif user.tier == "free":
        return "100/hour"
    
    return "10/hour"

@app.get("/api/data")
@limiter.limit(get_user_limit)
async def get_data(request: Request):
    """Rate limit varies by user tier"""
    return {"data": fetch_data()}

# Custom key function (rate limit by user ID)
def get_user_id(request: Request) -> str:
    """Extract user ID from JWT token"""
    auth_header = request.headers.get("authorization")
    
    if auth_header:
        token = auth_header.replace("Bearer ", "")
        user = decode_token(token)
        return str(user.id)
    
    return get_remote_address(request)

@app.get("/api/user-specific")
@limiter.limit("50/hour", key_func=get_user_id)
async def user_specific(request: Request):
    """Rate limit per user, not per IP"""
    return {"message": "User-specific data"}

# Exempt endpoint from rate limiting
@app.get("/health")
async def health_check():
    """Health check - no rate limit"""
    return {"status": "healthy"}

# Custom error response for rate limits
@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded",
            "detail": str(exc.detail),
            "retry_after": exc.retry_after
        }
    )
```

### Example 7: FastAPI with Pagination

```python
from fastapi import FastAPI, Query, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Generic, TypeVar
from sqlalchemy.orm import Session
from base64 import b64encode, b64decode
import json

app = FastAPI()

T = TypeVar('T')

class PaginationMetadata(BaseModel):
    page: Optional[int] = None
    per_page: Optional[int] = None
    total: Optional[int] = None
    total_pages: Optional[int] = None
    cursor: Optional[str] = None
    has_next: bool
    has_prev: Optional[bool] = None

class PaginatedResponse(BaseModel, Generic[T]):
    data: List[T]
    pagination: PaginationMetadata

class UserSchema(BaseModel):
    id: int
    email: str
    created_at: str
    
    class Config:
        orm_mode = True

# Offset pagination
@app.get("/api/users", response_model=PaginatedResponse[UserSchema])
async def get_users(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page (max 100)"),
    db: Session = Depends(get_db)
):
    """Get users with offset pagination"""
    offset = (page - 1) * per_page
    max_offset = 10000
    
    if offset > max_offset:
        raise HTTPException(
            status_code=400,
            detail=f"Offset too large. Maximum: {max_offset}. Use cursor pagination."
        )
    
    users = db.query(User).order_by(User.id).offset(offset).limit(per_page).all()
    total = db.query(User).count()
    
    return PaginatedResponse(
        data=users,
        pagination=PaginationMetadata(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page,
            has_next=offset + per_page < total,
            has_prev=page > 1
        )
    )

# Cursor pagination
@app.get("/api/users/cursor", response_model=PaginatedResponse[UserSchema])
async def get_users_cursor(
    cursor: Optional[str] = Query(None, description="Pagination cursor"),
    limit: int = Query(50, ge=1, le=100, description="Items to return (max 100)"),
    db: Session = Depends(get_db)
):
    """Get users with cursor pagination"""
    query = db.query(User).order_by(User.id)
    
    if cursor:
        try:
            cursor_data = json.loads(b64decode(cursor))
            last_id = cursor_data['last_id']
            query = query.filter(User.id > last_id)
        except:
            raise HTTPException(status_code=400, detail="Invalid cursor")
    
    users = query.limit(limit + 1).all()
    
    has_next = len(users) > limit
    users = users[:limit]
    
    next_cursor = None
    if has_next and users:
        cursor_data = {'last_id': users[-1].id}
        next_cursor = b64encode(json.dumps(cursor_data).encode()).decode()
    
    return PaginatedResponse(
        data=users,
        pagination=PaginationMetadata(
            cursor=next_cursor,
            has_next=has_next
        )
    )
```

## Django Examples

### Example 8: Django with django-ratelimit

```python
from django.http import JsonResponse
from django_ratelimit.decorators import ratelimit
from django.views.decorators.cache import cache_page
from django.core.paginator import Paginator
from django.views import View
from django.utils.decorators import method_decorator

# Function-based view with rate limiting
@ratelimit(key='ip', rate='100/h', method='GET')
def public_api(request):
    """Rate limit by IP: 100 requests per hour"""
    return JsonResponse({'message': 'Public data'})

# Rate limit by user
@ratelimit(key='user', rate='1000/h', method='GET')
def user_api(request):
    """Rate limit by authenticated user"""
    if request.user.is_authenticated:
        return JsonResponse({'data': 'User-specific data'})
    return JsonResponse({'error': 'Unauthorized'}, status=401)

# Multiple rate limits
@ratelimit(key='ip', rate='10/m', method='POST')
@ratelimit(key='ip', rate='100/h', method='POST')
def expensive_operation(request):
    """10 per minute AND 100 per hour"""
    result = perform_expensive_calculation()
    return JsonResponse(result)

# Custom key function
def get_api_key(group, request):
    """Extract API key from header for rate limiting"""
    return request.META.get('HTTP_X_API_KEY', 'anonymous')

@ratelimit(key=get_api_key, rate='500/h', method='GET')
def api_key_endpoint(request):
    """Rate limit by API key"""
    return JsonResponse({'data': fetch_data()})

# Dynamic rate limit based on user tier
def get_user_rate(group, request):
    """Return rate limit based on user tier"""
    if not request.user.is_authenticated:
        return '10/h'
    
    if request.user.tier == 'premium':
        return '10000/h'
    elif request.user.tier == 'free':
        return '1000/h'
    
    return '100/h'

@ratelimit(key='user', rate=get_user_rate, method='GET')
def tiered_api(request):
    """Different limits for different user tiers"""
    return JsonResponse({'data': get_user_data(request.user)})

# Class-based view with rate limiting
class SearchView(View):
    @method_decorator(ratelimit(key='ip', rate='30/m', method='GET'))
    def get(self, request):
        query = request.GET.get('q', '')
        results = perform_search(query)
        return JsonResponse({'results': results})

# Pagination in Django
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

def paginated_users(request):
    """Offset-based pagination"""
    page = request.GET.get('page', 1)
    per_page = min(int(request.GET.get('per_page', 50)), 100)  # Max 100
    
    users = User.objects.all().order_by('id')
    paginator = Paginator(users, per_page)
    
    try:
        users_page = paginator.page(page)
    except PageNotAnInteger:
        users_page = paginator.page(1)
    except EmptyPage:
        users_page = paginator.page(paginator.num_pages)
    
    return JsonResponse({
        'data': [
            {'id': u.id, 'email': u.email}
            for u in users_page
        ],
        'pagination': {
            'page': users_page.number,
            'per_page': per_page,
            'total': paginator.count,
            'total_pages': paginator.num_pages,
            'has_next': users_page.has_next(),
            'has_prev': users_page.has_previous()
        }
    })

# Cursor pagination in Django
import base64
import json

def cursor_paginated_users(request):
    """Cursor-based pagination"""
    cursor = request.GET.get('cursor')
    limit = min(int(request.GET.get('limit', 50)), 100)
    
    queryset = User.objects.all().order_by('id')
    
    if cursor:
        try:
            cursor_data = json.loads(base64.b64decode(cursor))
            last_id = cursor_data['last_id']
            queryset = queryset.filter(id__gt=last_id)
        except:
            return JsonResponse({'error': 'Invalid cursor'}, status=400)
    
    users = list(queryset[:limit + 1])
    has_next = len(users) > limit
    users = users[:limit]
    
    next_cursor = None
    if has_next and users:
        cursor_data = {'last_id': users[-1].id}
        next_cursor = base64.b64encode(
            json.dumps(cursor_data).encode()
        ).decode()
    
    return JsonResponse({
        'data': [{'id': u.id, 'email': u.email} for u in users],
        'pagination': {
            'cursor': next_cursor,
            'has_next': has_next,
            'limit': limit
        }
    })
```

## Redis-Backed Distributed Rate Limiting

### Example 9: Production-Ready Distributed Rate Limiter

```python
import redis
import time
from typing import Tuple, Dict
from enum import Enum

class RateLimitAlgorithm(Enum):
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"

class DistributedRateLimiter:
    """
    Production-ready distributed rate limiter supporting multiple algorithms.
    Works across multiple application instances using Redis.
    """
    
    def __init__(self, redis_url: str = 'redis://localhost:6379/0'):
        self.redis = redis.from_url(redis_url, decode_responses=True)
    
    def check_rate_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW
    ) -> Tuple[bool, Dict]:
        """
        Check if request is within rate limit.
        
        Returns:
            (allowed, info) where info contains:
                - remaining: requests remaining
                - reset_at: timestamp when limit resets
                - retry_after: seconds to wait if denied
        """
        if algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
            return self._sliding_window(key, limit, window_seconds)
        elif algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            return self._token_bucket(key, limit, limit / window_seconds)
        elif algorithm == RateLimitAlgorithm.FIXED_WINDOW:
            return self._fixed_window(key, limit, window_seconds)
    
    def _sliding_window(
        self,
        key: str,
        limit: int,
        window_seconds: int
    ) -> Tuple[bool, Dict]:
        """Sliding window rate limiter using Redis sorted set"""
        
        lua_script = """
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        local window_start = now - window
        
        -- Remove old entries
        redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
        
        -- Count current requests in window
        local count = redis.call('ZCARD', key)
        
        if count < limit then
            -- Add current request
            redis.call('ZADD', key, now, now .. '-' .. math.random())
            redis.call('EXPIRE', key, window * 2)
            return {1, limit - count - 1, now + window}
        else
            -- Rate limit exceeded
            local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
            local retry_after = tonumber(oldest[2]) + window - now
            return {0, 0, now + window, retry_after}
        end
        """
        
        now = time.time()
        result = self.redis.eval(
            lua_script,
            1,
            key,
            limit,
            window_seconds,
            now
        )
        
        allowed = bool(result[0])
        remaining = int(result[1])
        reset_at = int(result[2])
        retry_after = int(result[3]) if len(result) > 3 else 0
        
        return allowed, {
            'remaining': remaining,
            'reset_at': reset_at,
            'retry_after': retry_after,
            'limit': limit
        }
    
    def _token_bucket(
        self,
        key: str,
        capacity: int,
        refill_rate: float
    ) -> Tuple[bool, Dict]:
        """Token bucket rate limiter"""
        
        lua_script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        
        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1]) or capacity
        local last_refill = tonumber(bucket[2]) or now
        
        -- Refill tokens
        local elapsed = now - last_refill
        local new_tokens = math.min(capacity, tokens + (elapsed * refill_rate))
        
        if new_tokens >= 1 then
            new_tokens = new_tokens - 1
            redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
            redis.call('EXPIRE', key, 3600)
            return {1, math.floor(new_tokens), capacity}
        else
            local retry_after = (1 - new_tokens) / refill_rate
            return {0, 0, capacity, retry_after}
        end
        """
        
        now = time.time()
        result = self.redis.eval(
            lua_script,
            1,
            key,
            capacity,
            refill_rate,
            now
        )
        
        allowed = bool(result[0])
        remaining = int(result[1])
        capacity = int(result[2])
        retry_after = float(result[3]) if len(result) > 3 else 0
        
        return allowed, {
            'remaining': remaining,
            'capacity': capacity,
            'retry_after': int(retry_after),
            'limit': capacity
        }
    
    def _fixed_window(
        self,
        key: str,
        limit: int,
        window_seconds: int
    ) -> Tuple[bool, Dict]:
        """Fixed window counter"""
        
        now = int(time.time())
        window = now // window_seconds
        window_key = f"{key}:{window}"
        
        current = self.redis.incr(window_key)
        
        if current == 1:
            self.redis.expire(window_key, window_seconds * 2)
        
        allowed = current <= limit
        remaining = max(0, limit - current)
        reset_at = (window + 1) * window_seconds
        
        return allowed, {
            'remaining': remaining,
            'reset_at': reset_at,
            'retry_after': reset_at - now if not allowed else 0,
            'limit': limit
        }

# Usage example
limiter = DistributedRateLimiter('redis://localhost:6379/0')

# Check rate limit with sliding window
allowed, info = limiter.check_rate_limit(
    key='user:123:api_calls',
    limit=100,
    window_seconds=60,
    algorithm=RateLimitAlgorithm.SLIDING_WINDOW
)

if allowed:
    # Process request
    print(f"Request allowed. {info['remaining']} remaining.")
else:
    # Reject request
    print(f"Rate limit exceeded. Retry after {info['retry_after']} seconds.")
```

## Advanced Pagination Patterns

### Example 10: Hybrid Pagination with Search

```python
from flask import Flask, request, jsonify
from sqlalchemy import or_, and_
import base64
import json

app = Flask(__name__)

@app.route('/api/search/paginated')
def search_with_pagination():
    """
    Advanced pagination that works with search/filter.
    Combines cursor pagination with search functionality.
    """
    
    # Search/filter parameters
    query = request.args.get('q', '')
    category = request.args.get('category')
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    
    # Pagination parameters
    cursor = request.args.get('cursor')
    limit = min(int(request.args.get('limit', 50)), 100)
    
    # Build base query
    base_query = Product.query
    
    # Apply filters
    if query:
        base_query = base_query.filter(
            or_(
                Product.name.ilike(f'%{query}%'),
                Product.description.ilike(f'%{query}%')
            )
        )
    
    if category:
        base_query = base_query.filter(Product.category == category)
    
    if min_price is not None:
        base_query = base_query.filter(Product.price >= min_price)
    
    if max_price is not None:
        base_query = base_query.filter(Product.price <= max_price)
    
    # Apply cursor
    if cursor:
        try:
            cursor_data = json.loads(base64.urlsafe_b64decode(cursor))
            last_score = cursor_data['score']
            last_id = cursor_data['id']
            
            # Continue from cursor (with composite ordering)
            base_query = base_query.filter(
                or_(
                    Product.score < last_score,
                    and_(
                        Product.score == last_score,
                        Product.id > last_id
                    )
                )
            )
        except:
            return jsonify({'error': 'Invalid cursor'}), 400
    
    # Order by relevance score and ID
    base_query = base_query.order_by(
        Product.score.desc(),
        Product.id.asc()
    )
    
    # Execute query
    products = base_query.limit(limit + 1).all()
    
    has_next = len(products) > limit
    products = products[:limit]
    
    # Generate next cursor
    next_cursor = None
    if has_next and products:
        cursor_data = {
            'score': products[-1].score,
            'id': products[-1].id
        }
        next_cursor = base64.urlsafe_b64encode(
            json.dumps(cursor_data).encode()
        ).decode()
    
    return jsonify({
        'data': [p.to_dict() for p in products],
        'pagination': {
            'cursor': next_cursor,
            'has_next': has_next,
            'limit': limit
        },
        'filters': {
            'query': query,
            'category': category,
            'min_price': min_price,
            'max_price': max_price
        }
    })
```

## Real-World Integration Examples

### Example 11: Complete Flask API with All Protections

```python
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_sqlalchemy import SQLAlchemy
from prometheus_flask_exporter import PrometheusMetrics
import redis

app = Flask(__name__)

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:pass@localhost/db'
db = SQLAlchemy(app)

# Redis
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379",
    default_limits=["1000 per day", "100 per hour"]
)

# Caching
cache = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_URL': 'redis://localhost:6379/1'
})

# Monitoring
metrics = PrometheusMetrics(app)

# Request size limit
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB

# Health check
@app.route('/health')
@limiter.exempt
def health():
    return jsonify({'status': 'healthy'})

# Public endpoint with caching
@app.route('/api/products')
@limiter.limit("60 per minute")
@cache.cached(timeout=300, query_string=True)
def get_products():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    
    products = Product.query.paginate(page=page, per_page=per_page)
    
    return jsonify({
        'data': [p.to_dict() for p in products.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': products.total
        }
    })

# Search with strict rate limiting
@app.route('/api/search')
@limiter.limit("10 per minute")
def search():
    query = request.args.get('q', '')
    
    if len(query) < 3:
        return jsonify({'error': 'Query too short (min 3 characters)'}), 400
    
    if len(query) > 100:
        return jsonify({'error': 'Query too long (max 100 characters)'}), 400
    
    results = perform_search(query)
    return jsonify({'results': results})

# Authentication with very strict rate limiting
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    
    user = authenticate(email, password)
    
    if user:
        token = generate_token(user)
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401

# Error handlers
@app.errorhandler(413)
def request_too_large(error):
    return jsonify({'error': 'Request too large'}), 413

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        'error': 'Rate limit exceeded',
        'retry_after': error.description
    }), 429

if __name__ == '__main__':
    app.run()
```

## Key Takeaways

1. **Use established libraries** - Don't reinvent rate limiting
2. **Choose the right algorithm** - Sliding window for precision, token bucket for bursts
3. **Always paginate** - Never return unbounded result sets
4. **Cache aggressively** - Reduce database load
5. **Monitor everything** - Metrics are essential
6. **Test under load** - Ensure limits actually work

## Next Steps

- **Practice Exploitation** → [lab/](./lab/api04-rate-limiting-lab/) - Exploit vulnerable API
- **Review Prevention** → [prevention.md](./prevention.md) - Comprehensive defense strategies
