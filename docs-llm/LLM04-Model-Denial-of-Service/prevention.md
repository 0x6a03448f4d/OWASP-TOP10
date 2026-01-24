# LLM04: Model Denial of Service - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Rate Limiting](#rate-limiting)
- [Input Validation](#input-validation)
- [Resource Management](#resource-management)
- [Cost Controls](#cost-controls)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Architecture Patterns](#architecture-patterns)
- [Best Practices](#best-practices)

## Prevention Strategy Overview

Preventing Model Denial of Service requires a comprehensive defense-in-depth approach that combines rate limiting, resource management, input validation, and continuous monitoring.

### Defense-in-Depth Layers

```
[Request Validation] → [Rate Limiting] → [Resource Quotas]
        ↓                    ↓                  ↓
   Reject invalid     Throttle requests   Limit resources
        ↓                    ↓                  ↓
[Queue Management] → [Timeout Controls] → [Cost Monitoring]
        ↓                    ↓                  ↓
   Fair scheduling    Kill long requests  Track spending
        ↓                    ↓                  ↓
[Graceful Degradation] → [Auto-scaling] → [Incident Response]
```

## Rate Limiting

### 1. Multi-Tier Rate Limiting

**Implement rate limits at multiple levels**:

```python
from datetime import datetime, timedelta
from collections import defaultdict
import time

class MultiTierRateLimiter:
    """
    SECURE: Implement rate limiting at multiple tiers
    """
    
    def __init__(self):
        # Track requests at different granularities
        self.request_counts = defaultdict(lambda: defaultdict(int))
        self.token_counts = defaultdict(lambda: defaultdict(int))
        self.last_reset = defaultdict(lambda: defaultdict(datetime))
        
        # Define limits
        self.limits = {
            'requests_per_minute': 60,
            'requests_per_hour': 1000,
            'requests_per_day': 10000,
            'tokens_per_minute': 100000,
            'tokens_per_hour': 1000000,
            'tokens_per_day': 10000000,
            'concurrent_requests': 10,
        }
        
        self.concurrent_requests = defaultdict(int)
    
    def check_rate_limit(self, user_id: str, 
                        requested_tokens: int = 0) -> tuple[bool, str]:
        """Check if request is within rate limits"""
        now = datetime.now()
        
        # Check concurrent requests
        if self.concurrent_requests[user_id] >= self.limits['concurrent_requests']:
            return False, f"Too many concurrent requests (max {self.limits['concurrent_requests']})"
        
        # Check request rate limits
        for period, limit_key in [
            (60, 'requests_per_minute'),
            (3600, 'requests_per_hour'),
            (86400, 'requests_per_day')
        ]:
            if not self._check_limit(user_id, period, limit_key, 'requests'):
                return False, f"Rate limit exceeded: {limit_key}"
        
        # Check token rate limits
        if requested_tokens > 0:
            for period, limit_key in [
                (60, 'tokens_per_minute'),
                (3600, 'tokens_per_hour'),
                (86400, 'tokens_per_day')
            ]:
                if not self._check_token_limit(user_id, period, limit_key, 
                                              requested_tokens):
                    return False, f"Token limit exceeded: {limit_key}"
        
        return True, "OK"
    
    def _check_limit(self, user_id: str, period: int, 
                    limit_key: str, counter_type: str) -> bool:
        """Check if within limit for given period"""
        now = datetime.now()
        last = self.last_reset[user_id][limit_key]
        
        # Reset if period has elapsed
        if (now - last).total_seconds() >= period:
            self.request_counts[user_id][limit_key] = 0
            self.last_reset[user_id][limit_key] = now
        
        # Check limit
        current = self.request_counts[user_id][limit_key]
        return current < self.limits[limit_key]
    
    def _check_token_limit(self, user_id: str, period: int,
                          limit_key: str, requested: int) -> bool:
        """Check if token request is within limit"""
        now = datetime.now()
        last = self.last_reset[user_id][limit_key]
        
        # Reset if period has elapsed
        if (now - last).total_seconds() >= period:
            self.token_counts[user_id][limit_key] = 0
            self.last_reset[user_id][limit_key] = now
        
        # Check if adding requested tokens would exceed limit
        current = self.token_counts[user_id][limit_key]
        return (current + requested) <= self.limits[limit_key]
    
    def record_request(self, user_id: str, tokens_used: int):
        """Record a request for rate limiting"""
        # Increment all counters
        for limit_key in ['requests_per_minute', 'requests_per_hour', 
                         'requests_per_day']:
            self.request_counts[user_id][limit_key] += 1
        
        # Increment token counters
        for limit_key in ['tokens_per_minute', 'tokens_per_hour',
                         'tokens_per_day']:
            self.token_counts[user_id][limit_key] += tokens_used
    
    def acquire_concurrent_slot(self, user_id: str) -> bool:
        """Try to acquire a concurrent request slot"""
        if self.concurrent_requests[user_id] < self.limits['concurrent_requests']:
            self.concurrent_requests[user_id] += 1
            return True
        return False
    
    def release_concurrent_slot(self, user_id: str):
        """Release a concurrent request slot"""
        if self.concurrent_requests[user_id] > 0:
            self.concurrent_requests[user_id] -= 1

# Usage
rate_limiter = MultiTierRateLimiter()

def handle_request(user_id: str, prompt: str, max_tokens: int):
    """Handle request with rate limiting"""
    # Estimate tokens
    estimated_tokens = len(prompt) // 4 + max_tokens
    
    # Check rate limits
    allowed, reason = rate_limiter.check_rate_limit(user_id, estimated_tokens)
    
    if not allowed:
        return {"error": f"Rate limit exceeded: {reason}"}, 429
    
    # Acquire concurrent slot
    if not rate_limiter.acquire_concurrent_slot(user_id):
        return {"error": "Too many concurrent requests"}, 429
    
    try:
        # Process request
        response = llm.generate(prompt, max_tokens=max_tokens)
        
        # Record actual usage
        actual_tokens = response.usage.total_tokens
        rate_limiter.record_request(user_id, actual_tokens)
        
        return {"response": response.text}, 200
    
    finally:
        # Always release slot
        rate_limiter.release_concurrent_slot(user_id)
```

### 2. Token Bucket Algorithm

**Implement smooth rate limiting**:

```python
import time
from threading import Lock

class TokenBucket:
    """
    SECURE: Token bucket for smooth rate limiting
    """
    
    def __init__(self, capacity: int, refill_rate: float):
        """
        capacity: Maximum tokens in bucket
        refill_rate: Tokens added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = Lock()
    
    def consume(self, tokens: int) -> bool:
        """Try to consume tokens, return True if successful"""
        with self.lock:
            # Refill bucket based on time elapsed
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(
                self.capacity,
                self.tokens + (elapsed * self.refill_rate)
            )
            self.last_refill = now
            
            # Try to consume
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    def get_available_tokens(self) -> float:
        """Get current available tokens"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            return min(
                self.capacity,
                self.tokens + (elapsed * self.refill_rate)
            )

class TokenBucketRateLimiter:
    """Rate limiter using token bucket per user"""
    
    def __init__(self, requests_per_second: int, burst_size: int):
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.buckets = {}
    
    def allow_request(self, user_id: str, cost: int = 1) -> bool:
        """Check if request is allowed"""
        if user_id not in self.buckets:
            self.buckets[user_id] = TokenBucket(
                capacity=self.burst_size,
                refill_rate=self.requests_per_second
            )
        
        return self.buckets[user_id].consume(cost)

# Usage
rate_limiter = TokenBucketRateLimiter(
    requests_per_second=10,
    burst_size=50
)

def api_endpoint(user_id: str, prompt: str):
    # Calculate request cost based on complexity
    cost = estimate_request_cost(prompt)
    
    if not rate_limiter.allow_request(user_id, cost):
        return {"error": "Rate limit exceeded"}, 429
    
    return process_request(prompt)
```

## Input Validation

### 1. Input Length Validation

**Enforce strict input length limits**:

```python
import tiktoken

class InputValidator:
    """
    SECURE: Validate and sanitize inputs
    """
    
    def __init__(self, model_name: str = "gpt-4"):
        self.encoder = tiktoken.encoding_for_model(model_name)
        
        # Define limits
        self.max_input_tokens = 8000  # Conservative limit
        self.max_output_tokens = 4000
        self.max_total_tokens = 12000
        self.max_prompt_length = 50000  # characters
    
    def validate_input(self, prompt: str, max_tokens: int) -> tuple[bool, str]:
        """Validate input against limits"""
        
        # Check prompt length in characters
        if len(prompt) > self.max_prompt_length:
            return False, f"Prompt too long: {len(prompt)} chars (max {self.max_prompt_length})"
        
        # Count tokens
        try:
            input_tokens = len(self.encoder.encode(prompt))
        except Exception as e:
            return False, f"Failed to tokenize input: {str(e)}"
        
        # Check input token limit
        if input_tokens > self.max_input_tokens:
            return False, f"Input too long: {input_tokens} tokens (max {self.max_input_tokens})"
        
        # Check output token limit
        if max_tokens > self.max_output_tokens:
            return False, f"Requested output too long: {max_tokens} tokens (max {self.max_output_tokens})"
        
        # Check total token limit
        if input_tokens + max_tokens > self.max_total_tokens:
            return False, f"Total tokens too high: {input_tokens + max_tokens} (max {self.max_total_tokens})"
        
        return True, "OK"
    
    def sanitize_input(self, prompt: str) -> str:
        """Sanitize input to remove potentially problematic content"""
        # Remove null bytes
        prompt = prompt.replace('\x00', '')
        
        # Limit consecutive repetitions (potential DoS pattern)
        import re
        # Replace more than 100 consecutive identical chars
        prompt = re.sub(r'(.)\1{100,}', r'\1' * 100, prompt)
        
        # Remove excessive whitespace
        prompt = ' '.join(prompt.split())
        
        # Truncate if too long
        if len(prompt) > self.max_prompt_length:
            prompt = prompt[:self.max_prompt_length]
        
        return prompt
    
    def detect_repetitive_patterns(self, prompt: str) -> bool:
        """Detect potentially malicious repetitive patterns"""
        words = prompt.split()
        
        if len(words) < 10:
            return False
        
        # Check for excessive repetition
        from collections import Counter
        word_counts = Counter(words)
        most_common_word, count = word_counts.most_common(1)[0]
        
        # If one word appears more than 50% of the time
        if count / len(words) > 0.5:
            return True
        
        # Check for repeated sequences
        sequence_length = 10
        sequences = []
        for i in range(len(words) - sequence_length):
            seq = ' '.join(words[i:i+sequence_length])
            sequences.append(seq)
        
        seq_counts = Counter(sequences)
        if seq_counts.most_common(1)[0][1] > 5:
            return True  # Same sequence repeated more than 5 times
        
        return False

# Usage
validator = InputValidator()

def secure_api_endpoint(prompt: str, max_tokens: int):
    """API endpoint with input validation"""
    
    # Validate input
    valid, message = validator.validate_input(prompt, max_tokens)
    if not valid:
        return {"error": message}, 400
    
    # Detect malicious patterns
    if validator.detect_repetitive_patterns(prompt):
        return {"error": "Suspicious input pattern detected"}, 400
    
    # Sanitize
    prompt = validator.sanitize_input(prompt)
    
    # Process request
    return process_llm_request(prompt, max_tokens)
```

### 2. Complexity Detection

**Detect and limit computationally expensive requests**:

```python
class ComplexityAnalyzer:
    """
    SECURE: Analyze and limit request complexity
    """
    
    def __init__(self):
        self.max_complexity_score = 100
    
    def analyze_complexity(self, prompt: str) -> int:
        """Calculate complexity score for prompt"""
        score = 0
        
        # Length factor
        token_count = len(prompt.split())
        score += token_count // 100  # 1 point per 100 tokens
        
        # Nested structures
        nesting_indicators = [
            'for each',
            'for every',
            'then for',
            'and for',
            'analyze each',
            'list all',
            'enumerate all'
        ]
        
        for indicator in nesting_indicators:
            score += prompt.lower().count(indicator) * 10
        
        # Enumeration requests
        enumeration_keywords = [
            'list all',
            'enumerate',
            'every single',
            'each and every',
            'complete list'
        ]
        
        for keyword in enumeration_keywords:
            score += prompt.lower().count(keyword) * 15
        
        # Cross-referencing
        if 'cross-reference' in prompt.lower():
            score += 30
        if 'compare all' in prompt.lower():
            score += 25
        
        # Translation requests (expensive)
        if 'translate to' in prompt.lower():
            # Count how many languages
            import re
            matches = re.findall(r'(\d+)\s+languages?', prompt.lower())
            if matches:
                score += int(matches[0]) * 2
        
        # Detailed analysis requests
        detail_keywords = [
            'detailed analysis',
            'comprehensive analysis',
            'in-depth',
            'thorough examination',
            'complete breakdown'
        ]
        
        for keyword in detail_keywords:
            score += prompt.lower().count(keyword) * 10
        
        return score
    
    def is_acceptable_complexity(self, prompt: str) -> tuple[bool, int]:
        """Check if prompt complexity is acceptable"""
        score = self.analyze_complexity(prompt)
        
        if score > self.max_complexity_score:
            return False, score
        
        return True, score

# Usage
complexity_analyzer = ComplexityAnalyzer()

def validate_request_complexity(prompt: str):
    acceptable, score = complexity_analyzer.is_acceptable_complexity(prompt)
    
    if not acceptable:
        return {
            "error": f"Request too complex (score: {score}, max: {complexity_analyzer.max_complexity_score})",
            "suggestion": "Please simplify your request or break it into smaller parts"
        }, 400
    
    return process_request(prompt)
```

## Resource Management

### 1. Timeout Controls

**Implement comprehensive timeout mechanisms**:

```python
import asyncio
from concurrent.futures import TimeoutError
import signal
from contextlib import contextmanager

class TimeoutManager:
    """
    SECURE: Manage timeouts for LLM requests
    """
    
    def __init__(self):
        self.default_timeout = 60  # seconds
        self.max_timeout = 300     # 5 minutes maximum
    
    @contextmanager
    def timeout(self, seconds: int):
        """Context manager for timeout"""
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Operation timed out after {seconds} seconds")
        
        # Set alarm
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(seconds)
        
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    
    async def execute_with_timeout(self, coro, timeout_seconds: int = None):
        """Execute coroutine with timeout"""
        if timeout_seconds is None:
            timeout_seconds = self.default_timeout
        
        # Cap at maximum
        timeout_seconds = min(timeout_seconds, self.max_timeout)
        
        try:
            return await asyncio.wait_for(coro, timeout=timeout_seconds)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Request timed out after {timeout_seconds} seconds")

# Usage
timeout_manager = TimeoutManager()

async def process_with_timeout(prompt: str, max_tokens: int):
    """Process request with timeout protection"""
    
    # Calculate timeout based on expected generation time
    # Rough estimate: 50 tokens/second
    estimated_time = (max_tokens / 50) + 10  # +10 seconds buffer
    timeout = min(estimated_time, 300)  # Cap at 5 minutes
    
    try:
        async def generate():
            return await llm.generate_async(prompt, max_tokens=max_tokens)
        
        result = await timeout_manager.execute_with_timeout(
            generate(),
            timeout_seconds=int(timeout)
        )
        
        return {"response": result.text}, 200
    
    except TimeoutError as e:
        # Log timeout for monitoring
        log_timeout_event(prompt, max_tokens, timeout)
        
        return {
            "error": "Request timed out",
            "message": "Your request took too long to process. Please try a simpler query."
        }, 504
```

### 2. Resource Quotas

**Implement per-user resource quotas**:

```python
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict

@dataclass
class ResourceQuota:
    """Resource quota for a user"""
    daily_token_limit: int
    daily_request_limit: int
    max_concurrent_requests: int
    max_tokens_per_request: int
    
    # Tracking
    tokens_used_today: int = 0
    requests_made_today: int = 0
    current_concurrent_requests: int = 0
    last_reset: datetime = None

class QuotaManager:
    """
    SECURE: Manage per-user resource quotas
    """
    
    def __init__(self):
        self.quotas: Dict[str, ResourceQuota] = {}
        
        # Default quotas per tier
        self.quota_tiers = {
            'free': ResourceQuota(
                daily_token_limit=100000,
                daily_request_limit=100,
                max_concurrent_requests=2,
                max_tokens_per_request=2000
            ),
            'basic': ResourceQuota(
                daily_token_limit=1000000,
                daily_request_limit=1000,
                max_concurrent_requests=5,
                max_tokens_per_request=4000
            ),
            'premium': ResourceQuota(
                daily_token_limit=10000000,
                daily_request_limit=10000,
                max_concurrent_requests=20,
                max_tokens_per_request=8000
            )
        }
    
    def get_quota(self, user_id: str, tier: str = 'free') -> ResourceQuota:
        """Get quota for user"""
        if user_id not in self.quotas:
            self.quotas[user_id] = self.quota_tiers[tier]
            self.quotas[user_id].last_reset = datetime.now()
        
        # Reset daily quotas if needed
        quota = self.quotas[user_id]
        if datetime.now() - quota.last_reset > timedelta(days=1):
            quota.tokens_used_today = 0
            quota.requests_made_today = 0
            quota.last_reset = datetime.now()
        
        return quota
    
    def check_quota(self, user_id: str, tier: str,
                   requested_tokens: int) -> tuple[bool, str]:
        """Check if request is within quota"""
        quota = self.get_quota(user_id, tier)
        
        # Check request limit
        if quota.requests_made_today >= quota.daily_request_limit:
            return False, f"Daily request limit reached ({quota.daily_request_limit})"
        
        # Check token limit
        if quota.tokens_used_today + requested_tokens > quota.daily_token_limit:
            remaining = quota.daily_token_limit - quota.tokens_used_today
            return False, f"Daily token limit exceeded ({remaining} tokens remaining)"
        
        # Check concurrent requests
        if quota.current_concurrent_requests >= quota.max_concurrent_requests:
            return False, f"Too many concurrent requests (max {quota.max_concurrent_requests})"
        
        # Check tokens per request
        if requested_tokens > quota.max_tokens_per_request:
            return False, f"Request too large ({requested_tokens} tokens, max {quota.max_tokens_per_request})"
        
        return True, "OK"
    
    def record_usage(self, user_id: str, tokens_used: int):
        """Record resource usage"""
        if user_id in self.quotas:
            self.quotas[user_id].tokens_used_today += tokens_used
            self.quotas[user_id].requests_made_today += 1
    
    def acquire_concurrent_slot(self, user_id: str) -> bool:
        """Acquire concurrent request slot"""
        if user_id in self.quotas:
            quota = self.quotas[user_id]
            if quota.current_concurrent_requests < quota.max_concurrent_requests:
                quota.current_concurrent_requests += 1
                return True
        return False
    
    def release_concurrent_slot(self, user_id: str):
        """Release concurrent request slot"""
        if user_id in self.quotas:
            if self.quotas[user_id].current_concurrent_requests > 0:
                self.quotas[user_id].current_concurrent_requests -= 1

# Usage
quota_manager = QuotaManager()

def handle_user_request(user_id: str, tier: str, prompt: str, max_tokens: int):
    """Handle request with quota checking"""
    
    # Estimate total tokens
    estimated_tokens = len(prompt) // 4 + max_tokens
    
    # Check quota
    allowed, reason = quota_manager.check_quota(user_id, tier, estimated_tokens)
    if not allowed:
        return {"error": reason}, 429
    
    # Acquire slot
    if not quota_manager.acquire_concurrent_slot(user_id):
        return {"error": "Too many concurrent requests"}, 429
    
    try:
        # Process request
        result = llm.generate(prompt, max_tokens=max_tokens)
        
        # Record usage
        quota_manager.record_usage(user_id, result.usage.total_tokens)
        
        return {"response": result.text}, 200
    
    finally:
        quota_manager.release_concurrent_slot(user_id)
```

## Cost Controls

### 1. Cost Monitoring and Alerts

**Monitor and alert on cost anomalies**:

```python
from datetime import datetime, timedelta
from typing import List, Dict
import logging

class CostMonitor:
    """
    SECURE: Monitor and alert on LLM costs
    """
    
    def __init__(self):
        self.cost_per_1k_tokens = {
            'gpt-4': {'input': 0.03, 'output': 0.06},
            'gpt-3.5-turbo': {'input': 0.0015, 'output': 0.002},
        }
        
        self.usage_history: List[Dict] = []
        self.daily_budget = 100.00  # dollars
        self.alert_threshold = 0.8  # Alert at 80% of budget
    
    def calculate_cost(self, model: str, input_tokens: int, 
                      output_tokens: int) -> float:
        """Calculate cost for request"""
        if model not in self.cost_per_1k_tokens:
            logging.warning(f"Unknown model: {model}")
            return 0.0
        
        pricing = self.cost_per_1k_tokens[model]
        
        input_cost = (input_tokens / 1000) * pricing['input']
        output_cost = (output_tokens / 1000) * pricing['output']
        
        return input_cost + output_cost
    
    def record_usage(self, user_id: str, model: str,
                    input_tokens: int, output_tokens: int):
        """Record usage and cost"""
        cost = self.calculate_cost(model, input_tokens, output_tokens)
        
        usage_record = {
            'timestamp': datetime.now(),
            'user_id': user_id,
            'model': model,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'cost': cost
        }
        
        self.usage_history.append(usage_record)
        
        # Check for anomalies
        self.check_for_anomalies(user_id, cost)
    
    def get_daily_cost(self) -> float:
        """Get total cost for current day"""
        today = datetime.now().date()
        
        daily_cost = sum(
            record['cost']
            for record in self.usage_history
            if record['timestamp'].date() == today
        )
        
        return daily_cost
    
    def check_budget(self) -> tuple[bool, float]:
        """Check if within daily budget"""
        current_cost = self.get_daily_cost()
        
        if current_cost >= self.daily_budget:
            return False, current_cost
        
        # Check alert threshold
        if current_cost >= (self.daily_budget * self.alert_threshold):
            logging.warning(
                f"Cost alert: ${current_cost:.2f} / ${self.daily_budget:.2f} "
                f"({current_cost/self.daily_budget*100:.1f}%)"
            )
        
        return True, current_cost
    
    def check_for_anomalies(self, user_id: str, current_cost: float):
        """Detect cost anomalies"""
        # Get user's historical average
        user_history = [
            r for r in self.usage_history
            if r['user_id'] == user_id
        ]
        
        if len(user_history) < 10:
            return  # Not enough history
        
        # Calculate average cost per request
        avg_cost = sum(r['cost'] for r in user_history[-100:]) / len(user_history[-100:])
        
        # Alert if current cost is 10x average
        if current_cost > avg_cost * 10:
            logging.error(
                f"COST ANOMALY: User {user_id} request cost ${current_cost:.4f} "
                f"vs avg ${avg_cost:.4f}"
            )
            # Could trigger automatic blocking

# Usage
cost_monitor = CostMonitor()

def process_with_cost_monitoring(user_id: str, model: str, 
                                prompt: str, max_tokens: int):
    """Process request with cost monitoring"""
    
    # Check budget before processing
    within_budget, current_cost = cost_monitor.check_budget()
    if not within_budget:
        return {
            "error": "Daily budget exceeded",
            "current_cost": current_cost,
            "budget": cost_monitor.daily_budget
        }, 429
    
    # Process request
    result = llm.generate(prompt, max_tokens=max_tokens, model=model)
    
    # Record usage
    cost_monitor.record_usage(
        user_id=user_id,
        model=model,
        input_tokens=result.usage.prompt_tokens,
        output_tokens=result.usage.completion_tokens
    )
    
    return {"response": result.text}, 200
```

## Monitoring and Alerting

### 1. Real-Time Monitoring

**Monitor system health and performance**:

```python
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque
import psutil

@dataclass
class SystemMetrics:
    """System resource metrics"""
    cpu_percent: float
    memory_percent: float
    gpu_memory_percent: float
    request_queue_size: int
    active_requests: int
    avg_response_time: float
    requests_per_second: float

class SystemMonitor:
    """
    SECURE: Monitor system resources and performance
    """
    
    def __init__(self, alert_threshold_cpu=80, alert_threshold_memory=85):
        self.alert_threshold_cpu = alert_threshold_cpu
        self.alert_threshold_memory = alert_threshold_memory
        
        # Track metrics over time
        self.request_times: Deque[float] = deque(maxlen=1000)
        self.request_timestamps: Deque[float] = deque(maxlen=1000)
        self.active_requests = 0
        self.request_queue_size = 0
    
    def get_current_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        # CPU and Memory
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory_percent = psutil.virtual_memory().percent
        
        # GPU (simplified - would use actual GPU monitoring)
        gpu_memory_percent = self.get_gpu_memory_usage()
        
        # Request metrics
        avg_response_time = self.get_avg_response_time()
        requests_per_second = self.get_requests_per_second()
        
        return SystemMetrics(
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            gpu_memory_percent=gpu_memory_percent,
            request_queue_size=self.request_queue_size,
            active_requests=self.active_requests,
            avg_response_time=avg_response_time,
            requests_per_second=requests_per_second
        )
    
    def get_gpu_memory_usage(self) -> float:
        """Get GPU memory usage (placeholder)"""
        # In production, would use nvidia-smi or similar
        return 0.0
    
    def get_avg_response_time(self) -> float:
        """Calculate average response time"""
        if not self.request_times:
            return 0.0
        return sum(self.request_times) / len(self.request_times)
    
    def get_requests_per_second(self) -> float:
        """Calculate requests per second"""
        if len(self.request_timestamps) < 2:
            return 0.0
        
        now = time.time()
        one_second_ago = now - 1.0
        
        recent_requests = sum(
            1 for ts in self.request_timestamps
            if ts > one_second_ago
        )
        
        return recent_requests
    
    def record_request(self, response_time: float):
        """Record request metrics"""
        self.request_times.append(response_time)
        self.request_timestamps.append(time.time())
    
    def check_health(self) -> tuple[bool, List[str]]:
        """Check system health"""
        metrics = self.get_current_metrics()
        issues = []
        
        # Check CPU
        if metrics.cpu_percent > self.alert_threshold_cpu:
            issues.append(f"High CPU usage: {metrics.cpu_percent:.1f}%")
        
        # Check memory
        if metrics.memory_percent > self.alert_threshold_memory:
            issues.append(f"High memory usage: {metrics.memory_percent:.1f}%")
        
        # Check queue size
        if metrics.request_queue_size > 100:
            issues.append(f"Large request queue: {metrics.request_queue_size}")
        
        # Check response times
        if metrics.avg_response_time > 10.0:  # 10 seconds
            issues.append(f"Slow response times: {metrics.avg_response_time:.2f}s")
        
        is_healthy = len(issues) == 0
        
        return is_healthy, issues

# Usage
monitor = SystemMonitor()

async def monitored_request_handler(prompt: str, max_tokens: int):
    """Handle request with monitoring"""
    start_time = time.time()
    monitor.active_requests += 1
    
    try:
        # Check health before processing
        healthy, issues = monitor.check_health()
        
        if not healthy:
            logging.warning(f"System health issues: {issues}")
            
            # If critically unhealthy, reject new requests
            if monitor.active_requests > 50:
                return {
                    "error": "Service temporarily overloaded",
                    "retry_after": 60
                }, 503
        
        # Process request
        result = await llm.generate_async(prompt, max_tokens=max_tokens)
        
        # Record metrics
        response_time = time.time() - start_time
        monitor.record_request(response_time)
        
        return {"response": result.text}, 200
    
    finally:
        monitor.active_requests -= 1
```

## Architecture Patterns

### 1. Queue-Based Architecture

**Implement fair request queuing**:

```python
import asyncio
from asyncio import PriorityQueue
from dataclasses import dataclass, field
from typing import Any
import time

@dataclass(order=True)
class PrioritizedRequest:
    """Request with priority"""
    priority: int
    timestamp: float = field(compare=False)
    request_data: Any = field(compare=False)
    user_id: str = field(compare=False)

class RequestQueue:
    """
    SECURE: Fair queuing with priority
    """
    
    def __init__(self, max_queue_size=1000, max_workers=10):
        self.queue: PriorityQueue = PriorityQueue(maxsize=max_queue_size)
        self.max_workers = max_workers
        self.active_workers = 0
        
        # Priority levels
        self.PRIORITY_HIGH = 1
        self.PRIORITY_NORMAL = 5
        self.PRIORITY_LOW = 10
    
    async def enqueue(self, request_data: Any, user_id: str,
                     priority: int = None) -> bool:
        """Add request to queue"""
        if priority is None:
            priority = self.PRIORITY_NORMAL
        
        # Check if queue is full
        if self.queue.full():
            return False
        
        request = PrioritizedRequest(
            priority=priority,
            timestamp=time.time(),
            request_data=request_data,
            user_id=user_id
        )
        
        await self.queue.put(request)
        return True
    
    async def process_queue(self):
        """Process requests from queue"""
        while True:
            if self.active_workers >= self.max_workers:
                await asyncio.sleep(0.1)
                continue
            
            try:
                request = await asyncio.wait_for(
                    self.queue.get(),
                    timeout=1.0
                )
                
                # Process in background
                asyncio.create_task(self.process_request(request))
            
            except asyncio.TimeoutError:
                continue
    
    async def process_request(self, request: PrioritizedRequest):
        """Process a single request"""
        self.active_workers += 1
        
        try:
            # Wait time in queue
            wait_time = time.time() - request.timestamp
            logging.info(f"Processing request after {wait_time:.2f}s in queue")
            
            # Process the actual request
            result = await llm.generate_async(**request.request_data)
            
            # Return result (would use callback or response storage)
            return result
        
        finally:
            self.active_workers -= 1
            self.queue.task_done()

# Usage
request_queue = RequestQueue(max_queue_size=1000, max_workers=10)

# Start queue processor
asyncio.create_task(request_queue.process_queue())

async def queue_based_endpoint(user_id: str, prompt: str, max_tokens: int):
    """API endpoint using request queue"""
    
    # Determine priority (could be based on user tier)
    priority = request_queue.PRIORITY_NORMAL
    
    # Prepare request
    request_data = {
        'prompt': prompt,
        'max_tokens': max_tokens
    }
    
    # Enqueue
    success = await request_queue.enqueue(request_data, user_id, priority)
    
    if not success:
        return {
            "error": "Request queue full",
            "retry_after": 30
        }, 503
    
    return {
        "status": "queued",
        "message": "Request queued for processing",
        "queue_size": request_queue.queue.qsize()
    }, 202
```

## Best Practices

### 1. Defense in Depth
- ✅ Implement rate limiting at multiple levels (per-second, per-minute, per-hour, per-day)
- ✅ Validate inputs for length and complexity
- ✅ Set maximum token limits for input and output
- ✅ Implement timeouts for all requests
- ✅ Monitor resource usage continuously

### 2. Resource Management
- ✅ Enforce per-user quotas
- ✅ Limit concurrent requests per user
- ✅ Implement request queuing with fair scheduling
- ✅ Use circuit breakers to prevent cascading failures
- ✅ Implement graceful degradation under load

### 3. Cost Control
- ✅ Monitor token usage and costs in real-time
- ✅ Set daily/monthly budget limits
- ✅ Alert on cost anomalies
- ✅ Implement cost attribution per user/API key
- ✅ Secure API keys and rotate regularly

### 4. Monitoring
- ✅ Track response times and throughput
- ✅ Monitor CPU, memory, and GPU utilization
- ✅ Alert on anomalous patterns
- ✅ Log all requests for analysis
- ✅ Implement health check endpoints

### 5. Architecture
- ✅ Use load balancing across multiple model instances
- ✅ Implement auto-scaling based on demand
- ✅ Deploy circuit breakers and fallback mechanisms
- ✅ Cache responses where appropriate
- ✅ Use async/await for better concurrency

### 6. Input Validation
- ✅ Sanitize all user inputs
- ✅ Detect and reject repetitive patterns
- ✅ Limit maximum context length
- ✅ Detect computationally expensive prompts
- ✅ Implement complexity scoring

---

**Key Principle**: DoS prevention requires multiple defensive layers. No single technique is sufficient. Combine rate limiting, input validation, resource quotas, timeout controls, and continuous monitoring for comprehensive protection.
