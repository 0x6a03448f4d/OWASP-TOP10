# API06: Unrestricted Access to Sensitive Business Flows - Code Examples

## Table of Contents
- [Flask (Python)](#flask-python)
- [Express (Node.js)](#express-nodejs)  
- [Spring Boot (Java)](#spring-boot-java)
- [ASP.NET Core (C#)](#aspnet-core-c)

## Flask (Python)

### Vulnerable Implementation

```python
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# VULNERABLE: No bot protection on purchases
@app.route('/api/purchase', methods=['POST'])
def purchase():
    data = request.json
    user_id = data['user_id']
    product_id = data['product_id']
    quantity = data['quantity']
    
    # Direct purchase without checks
    conn = sqlite3.connect('store.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO orders (user_id, product_id, quantity) VALUES (?, ?, ?)',
                  (user_id, product_id, quantity))
    conn.commit()
    return jsonify({'success': True})
```

### Secure Implementation  

```python
from flask import Flask, request, jsonify
from redis import Redis
import hashlib
from datetime import datetime, timedelta

app = Flask(__name__)
redis_client = Redis()

class BotProtection:
    def check_rate_limits(self, user_id, ip, device_fp, action):
        hour_key = datetime.now().strftime('%Y-%m-%d-%H')
        limits = {
            f'rl:user:{user_id}:{action}:{hour_key}': (5, 3600),
            f'rl:ip:{ip}:{action}:{hour_key}': (10, 3600),
        }
        for key, (limit, ttl) in limits.items():
            count = self.redis.get(key)
            if count and int(count) >= limit:
                return False
            self.redis.incr(key)
            self.redis.expire(key, ttl)
        return True
    
    def analyze_behavior(self, session_id):
        events = self.redis.lrange(f'session:{session_id}:events', 0, -1)
        if not events:
            return {'risk': 'high'}
        # Check timing, mouse activity, etc.
        return {'risk': 'low'}

@app.route('/api/purchase', methods=['POST'])
def purchase_secure():
    bot = BotProtection()
    if not bot.check_rate_limits(user_id, ip, device, 'purchase'):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    behavior = bot.analyze_behavior(session_id)
    if behavior['risk'] == 'high':
        return jsonify({'requires_verification': True}), 202
    
    # Process purchase
    return jsonify({'success': True})
```

## Express (Node.js)

### Vulnerable Implementation

```javascript
app.post('/api/purchase', async (req, res) => {
    const { user_id, product_id, quantity } = req.body;
    await db.orders.create({ user_id, product_id, quantity });
    res.json({ success: true });
});
```

### Secure Implementation

```javascript
const Redis = require('ioredis');
const redis = new Redis();

class BotProtection {
    async checkRateLimits(userId, ip, action) {
        const hourKey = new Date().toISOString().substring(0, 13);
        const userKey = `rl:user:${userId}:${action}:${hourKey}`;
        const count = await redis.get(userKey) || 0;
        if (parseInt(count) >= 5) return false;
        await redis.incr(userKey);
        await redis.expire(userKey, 3600);
        return true;
    }
}

app.post('/api/purchase', async (req, res) => {
    const bot = new BotProtection();
    const allowed = await bot.checkRateLimits(req.body.user_id, req.ip, 'purchase');
    if (!allowed) {
        return res.status(429).json({ error: 'Rate limit exceeded' });
    }
    await db.orders.create(req.body);
    res.json({ success: true });
});
```

## Spring Boot (Java)

### Vulnerable Implementation

```java
@PostMapping("/purchase")
public ResponseEntity<?> purchase(@RequestBody PurchaseRequest request) {
    orderRepository.save(new Order(request));
    return ResponseEntity.ok(Map.of("success", true));
}
```

### Secure Implementation

```java
@PostMapping("/purchase")
public ResponseEntity<?> purchaseSecure(@RequestBody PurchaseRequest request) {
    if (!botProtection.checkRateLimits(request.getUserId(), "purchase")) {
        return ResponseEntity.status(429).body(Map.of("error", "Rate limit exceeded"));
    }
    
    RiskAnalysis risk = botProtection.calculateRisk(request.getUserId());
    if (risk.getScore() >= 50 && request.getCaptchaToken() == null) {
        return ResponseEntity.status(202).body(Map.of("requires_verification", true));
    }
    
    orderRepository.save(new Order(request));
    return ResponseEntity.ok(Map.of("success", true));
}
```

## ASP.NET Core (C#)

### Vulnerable Implementation

```csharp
[HttpPost("purchase")]
public IActionResult Purchase([FromBody] PurchaseRequest request) {
    _context.Orders.Add(new Order(request));
    _context.SaveChanges();
    return Ok(new { success = true });
}
```

### Secure Implementation

```csharp
[HttpPost("purchase")]
public async Task<IActionResult> PurchaseSecure([FromBody] PurchaseRequest request) {
    if (!await _botProtection.CheckRateLimits(request.UserId, "purchase")) {
        return StatusCode(429, new { error = "Rate limit exceeded" });
    }
    
    var risk = await _botProtection.CalculateRisk(request.UserId);
    if (risk.Score >= 50 && string.IsNullOrEmpty(request.CaptchaToken)) {
        return StatusCode(202, new { requires_verification = true });
    }
    
    _context.Orders.Add(new Order(request));
    await _context.SaveChangesAsync();
    return Ok(new { success = true });
}
```

## Key Takeaways

1. Implement multi-dimensional rate limiting
2. Track behavioral patterns
3. Use device fingerprinting
4. Apply risk-based verification
5. Monitor and alert on anomalies
