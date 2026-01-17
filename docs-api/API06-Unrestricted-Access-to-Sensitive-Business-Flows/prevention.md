# API06: Unrestricted Access to Sensitive Business Flows - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Defense in Depth Approach](#defense-in-depth-approach)
- [Behavioral Analysis](#behavioral-analysis)
- [Device Fingerprinting](#device-fingerprinting)
- [Rate Limiting for Business Logic](#rate-limiting-for-business-logic)
- [Risk Scoring and Adaptive Controls](#risk-scoring-and-adaptive-controls)
- [CAPTCHA and Challenge Implementation](#captcha-and-challenge-implementation)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Best Practices by Business Flow Type](#best-practices-by-business-flow-type)

## Prevention Strategy Overview

Protecting sensitive business flows requires a fundamentally different approach than traditional API security. You're not defending against malicious payloads or unauthorized access—you're preventing automated abuse of legitimate functionality.

### Core Principles

1. **Assume Automation**: Treat all requests as potentially automated until proven otherwise
2. **Behavioral Validation**: Verify actions follow human patterns
3. **Multi-Signal Detection**: Combine multiple indicators, not single checks
4. **Adaptive Response**: Graduated challenges based on risk level
5. **Business Context**: Tailor protections to specific flow sensitivity
6. **Continuous Learning**: Evolve defenses as bot techniques advance

### Defense Layers

```
┌─────────────────────────────────────────┐
│   Layer 1: Request Rate Limiting        │  ← Basic protection
├─────────────────────────────────────────┤
│   Layer 2: Device Fingerprinting        │  ← Identity tracking
├─────────────────────────────────────────┤
│   Layer 3: Behavioral Analysis          │  ← Pattern detection
├─────────────────────────────────────────┤
│   Layer 4: Risk Scoring                 │  ← Intelligence
├─────────────────────────────────────────┤
│   Layer 5: Adaptive Challenges          │  ← Active verification
├─────────────────────────────────────────┤
│   Layer 6: Business Rule Enforcement    │  ← Logic validation
├─────────────────────────────────────────┤
│   Layer 7: Real-time Monitoring         │  ← Continuous oversight
└─────────────────────────────────────────┘
```

## Defense in Depth Approach

### Layer 1: Basic Rate Limiting

**Purpose**: First line of defense against simple automation.

**Implementation**:
```python
# Traditional rate limiting (still necessary but insufficient)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Business-critical endpoints need stricter limits
@app.route('/api/purchase', methods=['POST'])
@limiter.limit("10 per hour")  # Much stricter for purchases
def purchase():
    pass
```

**Limitations**:
- Distributed attacks bypass IP-based limits
- Doesn't detect abuse within limits
- Can block legitimate users during high traffic

### Layer 2: Advanced Rate Limiting

**Purpose**: Context-aware throttling based on multiple dimensions.

**Implementation**:
```python
from redis import Redis
from datetime import datetime, timedelta

class MultiDimensionalRateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def check_limits(self, user_id, ip_address, device_id, action):
        """Check rate limits across multiple dimensions"""
        now = datetime.now()
        hour_window = now.replace(minute=0, second=0, microsecond=0)
        
        limits = {
            f'user:{user_id}:{action}:hour': (10, 3600),      # 10 per hour per user
            f'ip:{ip_address}:{action}:hour': (20, 3600),     # 20 per hour per IP
            f'device:{device_id}:{action}:hour': (15, 3600),  # 15 per hour per device
            f'global:{action}:minute': (100, 60),             # Global velocity check
        }
        
        for key, (limit, window) in limits.items():
            current = self.redis.get(key)
            if current and int(current) >= limit:
                return False, f"Rate limit exceeded: {key}"
            
            # Increment counter
            pipe = self.redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, window)
            pipe.execute()
        
        return True, None

# Usage
@app.route('/api/purchase', methods=['POST'])
def purchase():
    allowed, reason = rate_limiter.check_limits(
        user_id=current_user.id,
        ip_address=request.remote_addr,
        device_id=request.headers.get('X-Device-ID'),
        action='purchase'
    )
    
    if not allowed:
        return jsonify({'error': reason}), 429
    
    # Process purchase
```

## Behavioral Analysis

### Pattern Detection

**Purpose**: Identify non-human interaction patterns.

**Key Metrics to Track**:

1. **Timing Patterns**
   - Time between page view and action
   - Time to complete forms
   - Consistency of timing (humans vary, bots don't)

2. **Navigation Patterns**
   - Did user browse before purchasing?
   - Sequence of pages visited
   - Depth of interaction

3. **Input Patterns**
   - Mouse movements
   - Keyboard dynamics
   - Touch/scroll patterns

**Implementation**:
```python
from datetime import datetime, timedelta

class BehaviorAnalyzer:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def track_event(self, session_id, event_type, metadata=None):
        """Track user events for behavioral analysis"""
        event = {
            'type': event_type,
            'timestamp': datetime.now().isoformat(),
            'metadata': metadata or {}
        }
        
        key = f'session:{session_id}:events'
        self.redis.lpush(key, json.dumps(event))
        self.redis.expire(key, 3600)  # Keep for 1 hour
    
    def analyze_purchase_behavior(self, session_id):
        """Analyze if purchase behavior is suspicious"""
        events_json = self.redis.lrange(f'session:{session_id}:events', 0, -1)
        events = [json.loads(e) for e in events_json]
        
        if not events:
            return {'risk': 'high', 'reason': 'No prior activity'}
        
        # Check for product viewing before purchase
        viewed_product = any(e['type'] == 'product_view' for e in events)
        if not viewed_product:
            return {'risk': 'high', 'reason': 'No product viewing'}
        
        # Check time gaps
        purchase_event = next((e for e in events if e['type'] == 'purchase_attempt'), None)
        first_event = events[-1]  # Oldest event
        
        time_on_site = datetime.fromisoformat(purchase_event['timestamp']) - \
                       datetime.fromisoformat(first_event['timestamp'])
        
        if time_on_site < timedelta(seconds=5):
            return {'risk': 'high', 'reason': 'Too fast (< 5 seconds)'}
        
        # Check mouse movements
        has_mouse_activity = any(e['type'] == 'mouse_move' for e in events)
        if not has_mouse_activity:
            return {'risk': 'medium', 'reason': 'No mouse activity detected'}
        
        # Calculate risk score
        risk_score = 0
        if time_on_site < timedelta(seconds=30):
            risk_score += 30
        if not has_mouse_activity:
            risk_score += 25
        if len(events) < 5:
            risk_score += 20
        
        if risk_score > 50:
            return {'risk': 'high', 'score': risk_score}
        elif risk_score > 25:
            return {'risk': 'medium', 'score': risk_score}
        else:
            return {'risk': 'low', 'score': risk_score}

# Usage in purchase endpoint
@app.route('/api/purchase', methods=['POST'])
def purchase():
    session_id = request.headers.get('X-Session-ID')
    
    # Analyze behavior
    behavior_analysis = behavior_analyzer.analyze_purchase_behavior(session_id)
    
    if behavior_analysis['risk'] == 'high':
        # Require additional verification
        return jsonify({
            'requires_verification': True,
            'challenge_type': 'captcha'
        }), 202
    
    # Process purchase
```

### Client-Side Behavioral Tracking

**JavaScript to track user interactions**:
```javascript
// behavioral-tracker.js
class BehavioralTracker {
    constructor(sessionId, apiEndpoint) {
        this.sessionId = sessionId;
        this.apiEndpoint = apiEndpoint;
        this.events = [];
        this.startTime = Date.now();
        
        this.initializeTracking();
    }
    
    initializeTracking() {
        // Track mouse movements (sampled)
        let lastMouseEvent = 0;
        document.addEventListener('mousemove', (e) => {
            const now = Date.now();
            if (now - lastMouseEvent > 500) {  // Sample every 500ms
                this.trackEvent('mouse_move', {
                    x: e.clientX,
                    y: e.clientY,
                    time_delta: now - this.startTime
                });
                lastMouseEvent = now;
            }
        });
        
        // Track scrolling
        let lastScroll = 0;
        window.addEventListener('scroll', () => {
            const now = Date.now();
            if (now - lastScroll > 1000) {
                this.trackEvent('scroll', {
                    y: window.scrollY,
                    time_delta: now - this.startTime
                });
                lastScroll = now;
            }
        });
        
        // Track clicks
        document.addEventListener('click', (e) => {
            this.trackEvent('click', {
                element: e.target.tagName,
                time_delta: Date.now() - this.startTime
            });
        });
        
        // Track form interactions
        document.querySelectorAll('input').forEach(input => {
            input.addEventListener('focus', () => {
                this.trackEvent('input_focus', {
                    field: input.name,
                    time_delta: Date.now() - this.startTime
                });
            });
        });
    }
    
    trackEvent(type, metadata) {
        this.events.push({ type, metadata, timestamp: Date.now() });
        
        // Send to server periodically
        if (this.events.length >= 10) {
            this.flush();
        }
    }
    
    async flush() {
        if (this.events.length === 0) return;
        
        const eventsToSend = [...this.events];
        this.events = [];
        
        try {
            await fetch(`${this.apiEndpoint}/track-behavior`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': this.sessionId
                },
                body: JSON.stringify({ events: eventsToSend })
            });
        } catch (error) {
            console.error('Failed to send behavioral data', error);
        }
    }
}

// Initialize tracker
const tracker = new BehavioralTracker(SESSION_ID, '/api');
```

## Device Fingerprinting

**Purpose**: Track devices across sessions and accounts to detect distributed abuse.

**Implementation**:
```python
import hashlib
import json

class DeviceFingerprinter:
    def generate_fingerprint(self, request):
        """Generate device fingerprint from request characteristics"""
        components = {
            'user_agent': request.headers.get('User-Agent', ''),
            'accept_language': request.headers.get('Accept-Language', ''),
            'accept_encoding': request.headers.get('Accept-Encoding', ''),
            'screen_resolution': request.headers.get('X-Screen-Resolution', ''),
            'timezone': request.headers.get('X-Timezone', ''),
            'platform': request.headers.get('X-Platform', ''),
            'canvas_hash': request.headers.get('X-Canvas-Hash', ''),  # Client-side generated
            'webgl_hash': request.headers.get('X-WebGL-Hash', ''),
        }
        
        # Create stable hash
        fingerprint_string = json.dumps(components, sort_keys=True)
        fingerprint = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        
        return fingerprint
    
    def track_device_activity(self, fingerprint, user_id, action):
        """Track activity for a device fingerprint"""
        key = f'device:{fingerprint}:activity'
        
        activity = {
            'user_id': user_id,
            'action': action,
            'timestamp': datetime.now().isoformat()
        }
        
        self.redis.lpush(key, json.dumps(activity))
        self.redis.ltrim(key, 0, 99)  # Keep last 100 activities
        self.redis.expire(key, 86400 * 7)  # 7 days
    
    def check_device_reputation(self, fingerprint):
        """Check if device has suspicious patterns"""
        activities_json = self.redis.lrange(f'device:{fingerprint}:activity', 0, -1)
        activities = [json.loads(a) for a in activities_json]
        
        if not activities:
            return {'reputation': 'unknown', 'risk': 'medium'}
        
        # Check for multi-account abuse
        unique_users = set(a['user_id'] for a in activities)
        if len(unique_users) > 10:
            return {
                'reputation': 'suspicious',
                'risk': 'high',
                'reason': f'Used by {len(unique_users)} different accounts'
            }
        
        # Check for high-frequency actions
        recent_purchases = [
            a for a in activities 
            if a['action'] == 'purchase' and 
            datetime.fromisoformat(a['timestamp']) > datetime.now() - timedelta(hours=1)
        ]
        
        if len(recent_purchases) > 5:
            return {
                'reputation': 'suspicious',
                'risk': 'high',
                'reason': f'{len(recent_purchases)} purchases in last hour'
            }
        
        return {'reputation': 'good', 'risk': 'low'}

# Client-side fingerprint generation
"""
<script>
async function generateFingerprint() {
    // Canvas fingerprinting
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Browser fingerprint', 2, 2);
    const canvasHash = canvas.toDataURL().substring(0, 50);
    
    // WebGL fingerprinting
    const gl = canvas.getContext('webgl');
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    const webglHash = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
    
    return {
        canvasHash,
        webglHash,
        screenResolution: `${screen.width}x${screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        platform: navigator.platform
    };
}
</script>
"""
```

## Risk Scoring and Adaptive Controls

**Purpose**: Dynamically assess risk and apply appropriate controls.

**Implementation**:
```python
class RiskScorer:
    def calculate_risk_score(self, context):
        """Calculate comprehensive risk score (0-100)"""
        score = 0
        factors = []
        
        # User account age
        account_age = (datetime.now() - context['user_created_at']).days
        if account_age < 1:
            score += 20
            factors.append('New account (< 1 day)')
        elif account_age < 7:
            score += 10
            factors.append('Recent account (< 7 days)')
        
        # Device reputation
        device_rep = context.get('device_reputation', {})
        if device_rep.get('risk') == 'high':
            score += 25
            factors.append(f"High-risk device: {device_rep.get('reason')}")
        elif device_rep.get('risk') == 'medium':
            score += 10
            factors.append('Medium-risk device')
        
        # Behavioral signals
        behavior = context.get('behavior_analysis', {})
        if behavior.get('risk') == 'high':
            score += 30
            factors.append(f"Suspicious behavior: {behavior.get('reason')}")
        elif behavior.get('risk') == 'medium':
            score += 15
            factors.append('Unusual behavior patterns')
        
        # Velocity checks
        recent_purchases = context.get('recent_purchases_count', 0)
        if recent_purchases > 5:
            score += 20
            factors.append(f'{recent_purchases} recent purchases')
        elif recent_purchases > 2:
            score += 10
            factors.append(f'{recent_purchases} recent purchases')
        
        # IP reputation
        if context.get('ip_is_proxy'):
            score += 15
            factors.append('Proxy/VPN detected')
        
        if context.get('ip_is_datacenter'):
            score += 20
            factors.append('Datacenter IP')
        
        # Location consistency
        if context.get('location_mismatch'):
            score += 10
            factors.append('Location inconsistency')
        
        # Time of day (unusual hours can be suspicious)
        hour = datetime.now().hour
        if hour < 6 or hour > 22:
            score += 5
            factors.append('Unusual time (night hours)')
        
        return min(score, 100), factors
    
    def get_required_verification(self, risk_score):
        """Determine verification level based on risk"""
        if risk_score >= 70:
            return 'strong_verification'  # SMS + Email + CAPTCHA
        elif risk_score >= 50:
            return 'medium_verification'  # Email + CAPTCHA
        elif risk_score >= 30:
            return 'light_verification'   # CAPTCHA only
        else:
            return 'none'

# Usage
@app.route('/api/purchase', methods=['POST'])
def purchase():
    # Gather context
    context = {
        'user_created_at': current_user.created_at,
        'device_reputation': device_fingerprinter.check_device_reputation(device_fp),
        'behavior_analysis': behavior_analyzer.analyze_purchase_behavior(session_id),
        'recent_purchases_count': get_recent_purchase_count(current_user.id),
        'ip_is_proxy': check_ip_proxy(request.remote_addr),
        'ip_is_datacenter': check_ip_datacenter(request.remote_addr),
        'location_mismatch': check_location_consistency(current_user.id, request.remote_addr)
    }
    
    # Calculate risk
    risk_score, risk_factors = risk_scorer.calculate_risk_score(context)
    
    # Log for monitoring
    logger.info(f"Purchase attempt - User: {current_user.id}, Risk: {risk_score}, Factors: {risk_factors}")
    
    # Apply adaptive control
    verification_level = risk_scorer.get_required_verification(risk_score)
    
    if verification_level != 'none':
        return jsonify({
            'requires_verification': True,
            'verification_type': verification_level,
            'risk_score': risk_score
        }), 202
    
    # Process purchase
    return process_purchase(request.json)
```

## CAPTCHA and Challenge Implementation

**Purpose**: Verify human interaction when risk is elevated.

**Best Practices**:

1. **Don't use CAPTCHA as primary defense** (bypassable)
2. **Apply selectively** based on risk score
3. **Use invisible CAPTCHA** for better UX (reCAPTCHA v3, hCaptcha)
4. **Combine with other signals**

**Implementation**:
```python
import requests

class CaptchaVerifier:
    def __init__(self, secret_key):
        self.secret_key = secret_key
    
    def verify_recaptcha(self, token, expected_action):
        """Verify reCAPTCHA v3 token"""
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
            'secret': self.secret_key,
            'response': token
        })
        
        result = response.json()
        
        if not result.get('success'):
            return False, 0.0
        
        # Check action matches
        if result.get('action') != expected_action:
            return False, 0.0
        
        # Get score (0.0 to 1.0, higher is more human-like)
        score = result.get('score', 0.0)
        
        return True, score

# Usage
@app.route('/api/purchase', methods=['POST'])
def purchase():
    data = request.json
    
    # If high risk, verify CAPTCHA
    if risk_score >= 50:
        recaptcha_token = data.get('recaptcha_token')
        if not recaptcha_token:
            return jsonify({'error': 'CAPTCHA required'}), 400
        
        valid, score = captcha_verifier.verify_recaptcha(recaptcha_token, 'purchase')
        
        if not valid or score < 0.5:
            return jsonify({'error': 'CAPTCHA verification failed'}), 400
    
    # Process purchase
```

## Monitoring and Alerting

**Purpose**: Detect attacks in real-time and respond quickly.

**Key Metrics to Monitor**:

1. **Purchase Velocity**
   - Purchases per minute (global and per-user)
   - Sudden spikes in transaction volume
   - Geographic distribution of purchases

2. **Account Activity**
   - New account registration rate
   - Account age distribution of purchasers
   - Multi-account usage patterns

3. **Inventory Patterns**
   - Rapid inventory depletion
   - Cart abandonment rate
   - Reservation patterns

4. **Behavioral Anomalies**
   - Average time on site before purchase
   - Session depth distribution
   - Device fingerprint diversity

**Implementation**:
```python
from datetime import datetime, timedelta

class BusinessFlowMonitor:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def record_metric(self, metric_name, value, tags=None):
        """Record a metric with timestamp"""
        timestamp = datetime.now().isoformat()
        metric_data = {
            'value': value,
            'tags': tags or {},
            'timestamp': timestamp
        }
        
        key = f'metric:{metric_name}:recent'
        self.redis.lpush(key, json.dumps(metric_data))
        self.redis.ltrim(key, 0, 999)  # Keep last 1000 entries
        self.redis.expire(key, 3600)   # 1 hour
    
    def check_purchase_velocity_alert(self):
        """Check if purchase velocity exceeds thresholds"""
        now = datetime.now()
        one_min_ago = now - timedelta(minutes=1)
        five_min_ago = now - timedelta(minutes=5)
        
        purchases_json = self.redis.lrange('metric:purchase:recent', 0, -1)
        purchases = [json.loads(p) for p in purchases_json]
        
        # Count purchases in last 1 minute
        recent_purchases = [
            p for p in purchases 
            if datetime.fromisoformat(p['timestamp']) > one_min_ago
        ]
        
        # Alert if > 50 purchases/minute
        if len(recent_purchases) > 50:
            self.send_alert(
                'HIGH_PURCHASE_VELOCITY',
                f'{len(recent_purchases)} purchases in last minute',
                severity='high'
            )
        
        # Check for sudden spike
        last_5min = [
            p for p in purchases
            if datetime.fromisoformat(p['timestamp']) > five_min_ago
        ]
        
        avg_per_min = len(last_5min) / 5
        if len(recent_purchases) > avg_per_min * 3:
            self.send_alert(
                'PURCHASE_SPIKE',
                f'3x increase: {len(recent_purchases)} vs avg {avg_per_min:.1f}',
                severity='medium'
            )
    
    def check_new_account_purchases(self):
        """Alert on excessive purchases from new accounts"""
        purchases_json = self.redis.lrange('metric:purchase:recent', 0, -1)
        purchases = [json.loads(p) for p in purchases_json]
        
        new_account_purchases = [
            p for p in purchases
            if p.get('tags', {}).get('account_age_days', 999) < 1
        ]
        
        if len(new_account_purchases) > 20:
            self.send_alert(
                'NEW_ACCOUNT_ABUSE',
                f'{len(new_account_purchases)} purchases from accounts < 1 day old',
                severity='high'
            )
    
    def send_alert(self, alert_type, message, severity='medium'):
        """Send alert to monitoring system"""
        alert = {
            'type': alert_type,
            'message': message,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        
        # Log alert
        logger.warning(f"ALERT: {alert}")
        
        # Send to monitoring system (e.g., Slack, PagerDuty)
        # In production, integrate with your alerting infrastructure
        self.redis.lpush('alerts:active', json.dumps(alert))
        
        # If high severity, trigger immediate notification
        if severity == 'high':
            self.trigger_emergency_response(alert)

# Run monitoring checks periodically
def run_monitoring_checks():
    monitor.check_purchase_velocity_alert()
    monitor.check_new_account_purchases()
    # Add more checks as needed

# Schedule with Celery, APScheduler, or similar
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()
scheduler.add_job(run_monitoring_checks, 'interval', seconds=30)
scheduler.start()
```

## Best Practices by Business Flow Type

### E-Commerce Purchases

**Protection Strategy**:
```python
def protect_purchase_flow():
    # 1. Track browsing before purchase
    require_product_view_before_purchase(min_time=5)  # At least 5 seconds
    
    # 2. Limit purchases per user/device/IP
    enforce_purchase_limits(
        per_user_per_hour=5,
        per_device_per_hour=10,
        per_ip_per_hour=20
    )
    
    # 3. Validate checkout timing
    minimum_checkout_time = 3  # seconds
    maximum_checkout_time = 1800  # 30 minutes
    
    # 4. Inventory reservation limits
    max_items_in_cart = 10
    cart_expiration = 900  # 15 minutes
    
    # 5. Monitor for unusual patterns
    alert_on_sequential_product_ids()  # Might indicate enumeration
    alert_on_identical_shipping_addresses()  # Might indicate reseller
```

### Ticket/Booking Systems

**Protection Strategy**:
```python
def protect_booking_flow():
    # 1. Queue system for high-demand events
    implement_virtual_queue(
        max_concurrent_users=1000,
        wait_time_randomization=True
    )
    
    # 2. Strict time limits
    reservation_hold_time = 600  # 10 minutes
    auto_release_unreserved()
    
    # 3. Device and account limits
    max_tickets_per_device = 4
    max_tickets_per_account = 6
    
    # 4. Require account history
    minimum_account_age_days = 30
    require_verified_email()
    require_verified_phone()
    
    # 5. CAPTCHA at critical points
    require_captcha_before_reservation()
    require_captcha_before_payment()
```

### Review/Rating Systems

**Protection Strategy**:
```python
def protect_review_flow():
    # 1. Verify purchase/visit
    require_verified_purchase_for_review()
    
    # 2. Rate limit reviews
    max_reviews_per_user_per_day = 3
    max_reviews_per_product_per_user = 1
    
    # 3. Content analysis
    check_for_duplicate_content()
    check_for_ai_generated_content()
    detect_review_bombing_patterns()
    
    # 4. Account requirements
    minimum_account_age_for_reviews = 7  # days
    minimum_activity_level = 'basic'  # Has made at least 1 purchase
```

### Discount/Coupon Systems

**Protection Strategy**:
```python
def protect_coupon_flow():
    # 1. Strict combination rules
    max_coupons_per_transaction = 1
    max_total_discount_percentage = 50
    
    # 2. Usage tracking
    track_coupon_usage_per_user()
    track_coupon_usage_per_device()
    detect_coupon_sharing_patterns()
    
    # 3. Validation
    validate_coupon_eligibility(user, cart, coupon)
    prevent_coupon_stacking()
    
    # 4. Generation security
    use_cryptographically_random_codes()
    avoid_predictable_patterns()
```

### Account Registration

**Protection Strategy**:
```python
def protect_registration_flow():
    # 1. Rate limiting
    limit_registrations_per_ip(max_per_hour=5)
    limit_registrations_per_device(max_per_day=3)
    
    # 2. Email validation
    block_disposable_email_providers()
    require_email_verification()
    check_email_reputation()
    
    # 3. CAPTCHA
    require_captcha_on_registration()
    
    # 4. Phone verification (for high-value services)
    require_sms_verification()
    block_voip_numbers()
    
    # 5. Monitor patterns
    detect_sequential_username_patterns()
    detect_bulk_registration_attempts()
```

## Implementation Checklist

### Essential Protections

- [ ] **Multi-dimensional rate limiting** (user, IP, device, global)
- [ ] **Behavioral tracking** (time gaps, navigation patterns)
- [ ] **Device fingerprinting** (track across sessions)
- [ ] **Risk scoring** (combine multiple signals)
- [ ] **Adaptive challenges** (CAPTCHA when risk is high)
- [ ] **Business rule enforcement** (context-specific limits)
- [ ] **Real-time monitoring** (detect attacks as they happen)
- [ ] **Alert system** (notify on anomalies)

### Advanced Protections

- [ ] **Machine learning models** (train on historical abuse patterns)
- [ ] **Graph analysis** (detect related accounts/devices)
- [ ] **External threat intelligence** (IP reputation, device reputation)
- [ ] **A/B testing framework** (test new protections without impacting all users)
- [ ] **Automated response** (auto-block on clear abuse patterns)

### Monitoring & Metrics

- [ ] **Dashboard** (real-time view of business flow metrics)
- [ ] **Anomaly detection** (automated alerts on unusual patterns)
- [ ] **Investigation tools** (trace suspicious activity)
- [ ] **False positive tracking** (monitor legitimate users blocked)
- [ ] **Effectiveness metrics** (measure reduction in abuse)

## Key Takeaways

1. **Layer multiple defenses** - No single technique is sufficient
2. **Behavior matters more than requests** - Focus on patterns, not just volume
3. **Risk-based approach** - Apply friction proportional to risk
4. **Continuous monitoring** - Detect and respond in real-time
5. **Balance security and UX** - Don't frustrate legitimate users
6. **Adapt and evolve** - Bot techniques advance, defenses must too
7. **Business context is key** - Tailor protections to specific flows

## Next Steps

- **[Code Examples](examples.md)**: See implementations across different frameworks
- **[Hands-On Lab](lab/api06-business-logic-lab/)**: Practice implementing bot protection
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
