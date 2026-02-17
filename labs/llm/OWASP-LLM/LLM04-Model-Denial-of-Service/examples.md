# LLM04: Model Denial of Service - Examples

## Table of Contents
- [Vulnerable Examples](#vulnerable-examples)
- [Secure Examples](#secure-examples)
- [Attack Scenarios](#attack-scenarios)
- [Defense Implementations](#defense-implementations)

## Vulnerable Examples

### Example 1: No Rate Limiting

**Vulnerable Code**:
```python
from flask import Flask, request, jsonify
import openai

app = Flask(__name__)
openai.api_key = "sk-..."

@app.route('/api/chat', methods=['POST'])
def chat():
    """VULNERABLE: No rate limiting"""
    data = request.json
    prompt = data.get('prompt', '')
    
    # No checks on:
    # - Request frequency
    # - User identity
    # - Input length
    # - Concurrent requests
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=4000  # User can request expensive operations
    )
    
    return jsonify({"response": response.choices[0].message.content})

# PROBLEM: Attacker can flood endpoint
# for i in range(100000):
#     requests.post('/api/chat', json={'prompt': 'x' * 100000})
```

**Why It's Vulnerable**:
- No request frequency limiting
- No user authentication or tracking
- No input validation
- Unbounded resource consumption
- No concurrent request limits

**Attack Impact**:
```python
# Attacker exploitation
import requests
import threading

def attack():
    url = "http://target/api/chat"
    
    # Flood with maximum-size requests
    def send_request():
        large_prompt = "analyze this: " + ("data " * 50000)
        requests.post(url, json={'prompt': large_prompt})
    
    # Launch 1000 concurrent threads
    threads = []
    for i in range(1000):
        t = threading.Thread(target=send_request)
        t.start()
        threads.append(t)
    
    # Impact:
    # - Server overwhelmed with requests
    # - Legitimate users can't access service
    # - API costs spike to thousands of dollars
    # - System potentially crashes
```

### Example 2: Unbounded Input Length

**Vulnerable Code**:
```python
class ChatService:
    """VULNERABLE: Accepts arbitrarily long inputs"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.client = openai.OpenAI(api_key=api_key)
    
    def process_chat(self, user_message):
        # No length validation
        # No token counting
        # No complexity checking
        
        response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "user", "content": user_message}
            ],
            max_tokens=16000  # Maximum possible
        )
        
        return response.choices[0].message.content

# Usage
chat = ChatService("sk-...")

# PROBLEM: Accepts any length input
user_input = input("Enter your message: ")
response = chat.process_chat(user_input)  # No validation!
```

**Why It's Vulnerable**:
- No maximum input length
- No token counting
- Maximum output tokens allowed
- Single request can consume massive resources

**Attack Impact**:
```python
# Attacker sends maximum context
malicious_input = """
Please analyze the following text in extreme detail.
For each word, provide:
1. Etymology
2. Synonyms and antonyms
3. Usage examples
4. Translations to 50 languages

""" + ("word " * 100000)  # Near maximum context

# Result:
# - Input: ~100K tokens ($3.00)
# - Output: ~16K tokens ($0.96)
# - Total cost per request: ~$4
# - 1000 requests = $4,000
# - Processes for minutes, blocking resources
```

### Example 3: No Timeout Protection

**Vulnerable Code**:
```python
import asyncio

class LLMService:
    """VULNERABLE: No timeout on requests"""
    
    async def generate_response(self, prompt, max_length=10000):
        # No timeout set
        # Long-running requests block forever
        
        try:
            response = await self.llm_client.generate(
                prompt=prompt,
                max_tokens=max_length
                # No timeout parameter!
            )
            return response
        except Exception as e:
            # Generic error handling
            return f"Error: {e}"

# Usage
service = LLMService()

# PROBLEM: Request can run indefinitely
async def handle_user_request(prompt):
    # This could hang forever
    result = await service.generate_response(prompt)
    return result
```

**Why It's Vulnerable**:
- No timeout on LLM requests
- Long-running requests consume resources indefinitely
- No way to kill stuck requests
- Thread/worker pool can be exhausted

**Attack Impact**:
```python
# Attack with slow-generating prompts
async def attack():
    prompts = [
        "Count from 1 to 1000000 in words with explanations",
        "Generate complete dictionary with examples",
        "List all prime numbers up to 10000000"
    ]
    
    # Launch many slow requests
    tasks = []
    for i in range(100):
        for prompt in prompts:
            task = asyncio.create_task(
                service.generate_response(prompt, max_length=100000)
            )
            tasks.append(task)
    
    # Each request takes 10+ minutes
    # 300 requests × 10 minutes = 50+ hours of compute
    # All workers blocked on slow requests
    # Service effectively dead
```

### Example 4: No Cost Monitoring

**Vulnerable Code**:
```python
class AIAssistant:
    """VULNERABLE: No cost tracking or limits"""
    
    def __init__(self, api_key):
        self.api_key = api_key
    
    def answer_question(self, question, context=""):
        # No cost tracking
        # No budget limits
        # No usage monitoring
        
        full_prompt = f"Context: {context}\n\nQuestion: {question}"
        
        response = openai.ChatCompletion.create(
            model="gpt-4",  # Most expensive model
            messages=[{"role": "user", "content": full_prompt}],
            max_tokens=4000
        )
        
        return response.choices[0].message.content
    
    # No cost reporting
    # No usage logs
    # No budget alerts

# PROBLEM: No awareness of costs
assistant = AIAssistant("sk-...")

# API key leaked in GitHub
# Attacker finds it and abuses it
# No monitoring or alerts
# Bill arrives weeks later: $50,000+
```

**Why It's Vulnerable**:
- No cost tracking
- No budget limits
- No usage alerts
- No anomaly detection
- API key exposure risk

## Secure Examples

### Example 1: Multi-Layer Rate Limiting

**Secure Code**:
```python
from flask import Flask, request, jsonify
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta
import time

app = Flask(__name__)

class RateLimiter:
    """SECURE: Multi-tier rate limiting"""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.limits = {
            'per_second': 5,
            'per_minute': 60,
            'per_hour': 500,
            'per_day': 5000
        }
    
    def is_allowed(self, user_id: str) -> tuple[bool, str]:
        """Check if request is within limits"""
        now = time.time()
        
        # Clean old timestamps
        self.requests[user_id] = [
            ts for ts in self.requests[user_id]
            if now - ts < 86400  # Keep last 24 hours
        ]
        
        timestamps = self.requests[user_id]
        
        # Check per-second limit
        recent_1s = sum(1 for ts in timestamps if now - ts < 1)
        if recent_1s >= self.limits['per_second']:
            return False, "Rate limit: too many requests per second"
        
        # Check per-minute limit
        recent_1m = sum(1 for ts in timestamps if now - ts < 60)
        if recent_1m >= self.limits['per_minute']:
            return False, "Rate limit: too many requests per minute"
        
        # Check per-hour limit
        recent_1h = sum(1 for ts in timestamps if now - ts < 3600)
        if recent_1h >= self.limits['per_hour']:
            return False, "Rate limit: too many requests per hour"
        
        # Check per-day limit
        if len(timestamps) >= self.limits['per_day']:
            return False, "Rate limit: daily limit reached"
        
        # Record this request
        self.requests[user_id].append(now)
        return True, "OK"

rate_limiter = RateLimiter()

def rate_limit(f):
    """Rate limiting decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get user ID (from auth token, IP, etc.)
        user_id = request.headers.get('X-User-ID', request.remote_addr)
        
        # Check rate limit
        allowed, message = rate_limiter.is_allowed(user_id)
        
        if not allowed:
            return jsonify({"error": message}), 429
        
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/api/chat', methods=['POST'])
@rate_limit
def chat():
    """Rate-limited chat endpoint"""
    data = request.json
    prompt = data.get('prompt', '')
    
    # Additional validation in next example
    response = process_with_validation(prompt)
    
    return jsonify(response)
```

**Security Features**:
- ✅ Multi-tier rate limiting (per-second, minute, hour, day)
- ✅ Per-user tracking
- ✅ Automatic cleanup of old data
- ✅ Clear error messages
- ✅ Easy to adjust limits

### Example 2: Input Validation and Sanitization

**Secure Code**:
```python
import tiktoken
import re

class SecureInputValidator:
    """SECURE: Comprehensive input validation"""
    
    def __init__(self, model="gpt-4"):
        self.encoder = tiktoken.encoding_for_model(model)
        
        # Define strict limits
        self.max_input_tokens = 8000
        self.max_output_tokens = 2000
        self.max_total_tokens = 10000
        self.max_chars = 40000
    
    def validate_and_sanitize(self, prompt: str, 
                             max_tokens: int) -> tuple[bool, str, str]:
        """Validate and sanitize input"""
        
        # Check if prompt is provided
        if not prompt or not isinstance(prompt, str):
            return False, "Invalid prompt", ""
        
        # Check character length
        if len(prompt) > self.max_chars:
            return False, f"Prompt too long: {len(prompt)} chars (max {self.max_chars})", ""
        
        # Sanitize: remove null bytes
        prompt = prompt.replace('\x00', '')
        
        # Detect repetitive patterns (potential DoS)
        if self._is_repetitive(prompt):
            return False, "Suspicious repetitive pattern detected", ""
        
        # Limit excessive repetition
        prompt = self._limit_repetition(prompt)
        
        # Count tokens
        try:
            tokens = self.encoder.encode(prompt)
            input_token_count = len(tokens)
        except Exception as e:
            return False, f"Failed to tokenize: {e}", ""
        
        # Validate input token count
        if input_token_count > self.max_input_tokens:
            return False, f"Input too long: {input_token_count} tokens (max {self.max_input_tokens})", ""
        
        # Validate output token count
        if max_tokens > self.max_output_tokens:
            return False, f"Requested output too long: {max_tokens} tokens (max {self.max_output_tokens})", ""
        
        # Validate total tokens
        if input_token_count + max_tokens > self.max_total_tokens:
            return False, f"Total tokens exceed limit: {input_token_count + max_tokens} (max {self.max_total_tokens})", ""
        
        return True, "OK", prompt
    
    def _is_repetitive(self, text: str) -> bool:
        """Detect malicious repetitive patterns"""
        words = text.split()
        
        if len(words) < 50:
            return False
        
        # Check if same word appears too frequently
        from collections import Counter
        word_freq = Counter(words)
        most_common_word, count = word_freq.most_common(1)[0]
        
        # If one word is >60% of content, it's suspicious
        if count / len(words) > 0.6:
            return True
        
        return False
    
    def _limit_repetition(self, text: str) -> str:
        """Limit consecutive character repetition"""
        # Replace >50 consecutive identical chars with just 50
        text = re.sub(r'(.)\1{50,}', r'\1' * 50, text)
        return text

# Usage
validator = SecureInputValidator()

def secure_chat_endpoint(prompt: str, max_tokens: int):
    """Secure endpoint with validation"""
    
    # Validate and sanitize
    valid, message, sanitized_prompt = validator.validate_and_sanitize(
        prompt, 
        max_tokens
    )
    
    if not valid:
        return {"error": message}, 400
    
    # Process with validated input
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": sanitized_prompt}],
            max_tokens=min(max_tokens, validator.max_output_tokens)
        )
        
        return {"response": response.choices[0].message.content}, 200
    
    except Exception as e:
        return {"error": "Processing failed"}, 500
```

**Security Features**:
- ✅ Token counting before processing
- ✅ Strict length limits
- ✅ Repetition detection
- ✅ Input sanitization
- ✅ Clear validation errors

### Example 3: Timeout and Resource Management

**Secure Code**:
```python
import asyncio
from contextlib import asynccontextmanager
import time

class SecureLLMService:
    """SECURE: Comprehensive timeout and resource management"""
    
    def __init__(self):
        self.default_timeout = 60  # seconds
        self.max_timeout = 300     # 5 minutes max
        self.max_concurrent = 10
        self.active_requests = 0
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
    
    @asynccontextmanager
    async def request_slot(self):
        """Manage concurrent request slots"""
        async with self.semaphore:
            self.active_requests += 1
            try:
                yield
            finally:
                self.active_requests -= 1
    
    async def generate_with_timeout(self, prompt: str, 
                                   max_tokens: int = 1000,
                                   timeout: int = None) -> dict:
        """Generate response with timeout protection"""
        
        if timeout is None:
            # Calculate timeout based on expected generation time
            # Rough estimate: 50 tokens/second
            estimated_time = (max_tokens / 50) + 10
            timeout = min(estimated_time, self.max_timeout)
        else:
            timeout = min(timeout, self.max_timeout)
        
        # Acquire request slot
        if self.active_requests >= self.max_concurrent:
            return {
                "error": "Too many concurrent requests",
                "retry_after": 5
            }
        
        async with self.request_slot():
            try:
                # Execute with timeout
                response = await asyncio.wait_for(
                    self._generate_internal(prompt, max_tokens),
                    timeout=timeout
                )
                
                return {"response": response}
            
            except asyncio.TimeoutError:
                return {
                    "error": f"Request timed out after {timeout} seconds",
                    "suggestion": "Try a simpler query or reduce max_tokens"
                }
            
            except Exception as e:
                return {
                    "error": f"Generation failed: {str(e)}"
                }
    
    async def _generate_internal(self, prompt: str, max_tokens: int) -> str:
        """Internal generation method"""
        # Simulated async LLM call
        response = await openai_async_client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens
        )
        
        return response.choices[0].message.content

# Usage
llm_service = SecureLLMService()

async def handle_request(prompt: str, max_tokens: int):
    """Handle request with timeout"""
    result = await llm_service.generate_with_timeout(
        prompt=prompt,
        max_tokens=max_tokens
    )
    
    return result

# Example usage
async def main():
    result = await handle_request(
        "Explain quantum computing",
        max_tokens=500
    )
    print(result)
```

**Security Features**:
- ✅ Request timeout protection
- ✅ Concurrent request limiting
- ✅ Resource slot management
- ✅ Automatic timeout calculation
- ✅ Graceful error handling

### Example 4: Cost Monitoring and Alerts

**Secure Code**:
```python
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List
import logging

@dataclass
class UsageRecord:
    """Record of API usage"""
    timestamp: datetime
    user_id: str
    model: str
    input_tokens: int
    output_tokens: int
    cost: float

class CostMonitoringService:
    """SECURE: Comprehensive cost monitoring"""
    
    def __init__(self):
        # Pricing (as of 2024)
        self.pricing = {
            'gpt-4': {
                'input': 0.03,   # per 1K tokens
                'output': 0.06
            },
            'gpt-3.5-turbo': {
                'input': 0.0015,
                'output': 0.002
            }
        }
        
        # Budgets
        self.daily_budget = 100.00    # dollars
        self.hourly_budget = 10.00
        self.user_daily_budget = 5.00
        
        # Tracking
        self.usage_history: List[UsageRecord] = []
        self.user_usage: Dict[str, List[UsageRecord]] = {}
    
    def calculate_cost(self, model: str, input_tokens: int, 
                      output_tokens: int) -> float:
        """Calculate cost for request"""
        if model not in self.pricing:
            logging.warning(f"Unknown model: {model}, using gpt-4 pricing")
            model = 'gpt-4'
        
        prices = self.pricing[model]
        
        input_cost = (input_tokens / 1000) * prices['input']
        output_cost = (output_tokens / 1000) * prices['output']
        
        return input_cost + output_cost
    
    def check_budget(self, user_id: str, estimated_cost: float) -> tuple[bool, str]:
        """Check if request is within budget"""
        now = datetime.now()
        
        # Check system-wide daily budget
        daily_cost = self._get_cost_since(now - timedelta(days=1))
        if daily_cost + estimated_cost > self.daily_budget:
            return False, f"Daily budget exceeded: ${daily_cost:.2f}/${self.daily_budget:.2f}"
        
        # Check hourly budget
        hourly_cost = self._get_cost_since(now - timedelta(hours=1))
        if hourly_cost + estimated_cost > self.hourly_budget:
            return False, f"Hourly budget exceeded: ${hourly_cost:.2f}/${self.hourly_budget:.2f}"
        
        # Check user daily budget
        user_daily_cost = self._get_user_cost_since(
            user_id, 
            now - timedelta(days=1)
        )
        if user_daily_cost + estimated_cost > self.user_daily_budget:
            return False, f"User daily budget exceeded: ${user_daily_cost:.2f}/${self.user_daily_budget:.2f}"
        
        # Check for anomalies
        if self._is_anomalous(user_id, estimated_cost):
            logging.warning(f"Anomalous cost detected for user {user_id}: ${estimated_cost:.4f}")
            # Could block or require additional verification
        
        return True, "OK"
    
    def record_usage(self, user_id: str, model: str,
                    input_tokens: int, output_tokens: int):
        """Record usage and cost"""
        cost = self.calculate_cost(model, input_tokens, output_tokens)
        
        record = UsageRecord(
            timestamp=datetime.now(),
            user_id=user_id,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=cost
        )
        
        self.usage_history.append(record)
        
        if user_id not in self.user_usage:
            self.user_usage[user_id] = []
        self.user_usage[user_id].append(record)
        
        # Log high-cost requests
        if cost > 1.00:
            logging.warning(f"High-cost request: ${cost:.2f} for user {user_id}")
    
    def _get_cost_since(self, since: datetime) -> float:
        """Get total cost since timestamp"""
        return sum(
            record.cost
            for record in self.usage_history
            if record.timestamp >= since
        )
    
    def _get_user_cost_since(self, user_id: str, since: datetime) -> float:
        """Get user's cost since timestamp"""
        if user_id not in self.user_usage:
            return 0.0
        
        return sum(
            record.cost
            for record in self.user_usage[user_id]
            if record.timestamp >= since
        )
    
    def _is_anomalous(self, user_id: str, current_cost: float) -> bool:
        """Detect anomalous costs"""
        if user_id not in self.user_usage or len(self.user_usage[user_id]) < 10:
            return False
        
        # Calculate average cost
        recent_records = self.user_usage[user_id][-100:]
        avg_cost = sum(r.cost for r in recent_records) / len(recent_records)
        
        # Flag if current cost is 20x average
        return current_cost > avg_cost * 20
    
    def get_usage_report(self) -> dict:
        """Generate usage report"""
        now = datetime.now()
        
        return {
            "total_requests": len(self.usage_history),
            "hourly_cost": self._get_cost_since(now - timedelta(hours=1)),
            "daily_cost": self._get_cost_since(now - timedelta(days=1)),
            "hourly_budget": self.hourly_budget,
            "daily_budget": self.daily_budget,
            "budget_utilization": {
                "hourly": f"{(self._get_cost_since(now - timedelta(hours=1)) / self.hourly_budget) * 100:.1f}%",
                "daily": f"{(self._get_cost_since(now - timedelta(days=1)) / self.daily_budget) * 100:.1f}%"
            }
        }

# Usage
cost_monitor = CostMonitoringService()

async def monitored_llm_request(user_id: str, prompt: str, 
                               max_tokens: int, model: str = "gpt-4"):
    """LLM request with cost monitoring"""
    
    # Estimate cost before processing
    input_tokens = len(prompt) // 4  # Rough estimate
    estimated_cost = cost_monitor.calculate_cost(
        model, input_tokens, max_tokens
    )
    
    # Check budget
    allowed, message = cost_monitor.check_budget(user_id, estimated_cost)
    if not allowed:
        return {"error": message}, 429
    
    # Process request
    response = await openai_async_client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens
    )
    
    # Record actual usage
    cost_monitor.record_usage(
        user_id=user_id,
        model=model,
        input_tokens=response.usage.prompt_tokens,
        output_tokens=response.usage.completion_tokens
    )
    
    return {
        "response": response.choices[0].message.content,
        "usage": {
            "input_tokens": response.usage.prompt_tokens,
            "output_tokens": response.usage.completion_tokens,
            "cost": cost_monitor.calculate_cost(
                model,
                response.usage.prompt_tokens,
                response.usage.completion_tokens
            )
        }
    }, 200
```

**Security Features**:
- ✅ Real-time cost calculation
- ✅ Budget enforcement (system and per-user)
- ✅ Anomaly detection
- ✅ Usage tracking and reporting
- ✅ Cost alerts and logging

## Attack Scenarios

### Scenario 1: Concurrent Request Flood

**Attack**:
```python
# Attacker floods with concurrent requests
import asyncio
import aiohttp

async def flood_attack(target_url, api_key):
    """Launch concurrent request flood"""
    
    async def send_request(session):
        async with session.post(
            target_url,
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "prompt": "x " * 10000,  # Large input
                "max_tokens": 4000        # Large output
            }
        ) as response:
            return await response.json()
    
    # Create 1000 concurrent requests
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session) for _ in range(1000)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    print(f"Completed {len(results)} requests")

# Run attack
asyncio.run(flood_attack("https://target/api/chat", "stolen-key"))
```

**Defense**:
```python
# Implemented defenses prevent this
# 1. Rate limiting: Rejects after limit (e.g., 60/min)
# 2. Concurrent limits: Max 10 concurrent per user
# 3. Request queue: Fair scheduling
# 4. Budget limits: Stops at daily budget

# Result:
# - First 10 requests processed
# - Remaining 990 rejected with 429 status
# - Rate limits prevent resource exhaustion
# - Service remains available
```

### Scenario 2: Maximum Context Exploitation

**Attack**:
```python
# Attacker sends maximum-length context
def max_context_attack():
    # Create input near maximum token limit
    attack_prompt = "Analyze this data: " + ("word " * 100000)
    
    response = requests.post(
        "https://target/api/chat",
        json={
            "prompt": attack_prompt,  # ~100K tokens
            "max_tokens": 16000        # Maximum output
        }
    )
    
    # Single request costs:
    # - Input: 100K tokens × $0.03/1K = $3.00
    # - Output: 16K tokens × $0.06/1K = $0.96
    # - Total: ~$4 per request
    # - Takes 5-10 minutes to process
```

**Defense**:
```python
# Input validator catches this
validator = SecureInputValidator()

valid, message, sanitized = validator.validate_and_sanitize(
    attack_prompt,
    max_tokens=16000
)

# Result: valid = False
# Message: "Input too long: 100000 tokens (max 8000)"
# Request rejected before processing
# No cost incurred
# Resources protected
```

## Defense Implementations

### Complete Secure Implementation

**Comprehensive Protected Service**:
```python
from flask import Flask, request, jsonify
import asyncio
from functools import wraps

app = Flask(__name__)

# Initialize all security components
rate_limiter = MultiTierRateLimiter()
validator = SecureInputValidator()
llm_service = SecureLLMService()
cost_monitor = CostMonitoringService()

def secure_endpoint(f):
    """Comprehensive security decorator"""
    @wraps(f)
    async def decorated(*args, **kwargs):
        # 1. Authentication
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401
        
        # 2. Rate limiting
        allowed, message = rate_limiter.check_rate_limit(user_id)
        if not allowed:
            return jsonify({"error": message}), 429
        
        # Execute endpoint
        return await f(user_id, *args, **kwargs)
    
    return decorated

@app.route('/api/chat', methods=['POST'])
@secure_endpoint
async def secure_chat(user_id: str):
    """Fully secured chat endpoint"""
    data = request.json
    prompt = data.get('prompt', '')
    max_tokens = data.get('max_tokens', 1000)
    model = data.get('model', 'gpt-4')
    
    # 3. Input validation
    valid, message, sanitized_prompt = validator.validate_and_sanitize(
        prompt, max_tokens
    )
    if not valid:
        return jsonify({"error": message}), 400
    
    # 4. Cost check
    input_tokens = len(sanitized_prompt) // 4
    estimated_cost = cost_monitor.calculate_cost(
        model, input_tokens, max_tokens
    )
    
    budget_ok, budget_msg = cost_monitor.check_budget(user_id, estimated_cost)
    if not budget_ok:
        return jsonify({"error": budget_msg}), 429
    
    # 5. Process with timeout and resource management
    result = await llm_service.generate_with_timeout(
        prompt=sanitized_prompt,
        max_tokens=max_tokens
    )
    
    if "error" in result:
        return jsonify(result), 500
    
    # 6. Record usage
    # (Would get actual token counts from response)
    cost_monitor.record_usage(
        user_id=user_id,
        model=model,
        input_tokens=input_tokens,
        output_tokens=max_tokens
    )
    
    # 7. Return response with usage info
    return jsonify({
        "response": result["response"],
        "usage": {
            "estimated_cost": estimated_cost,
            "budget_remaining": cost_monitor.user_daily_budget - 
                               cost_monitor._get_user_cost_since(
                                   user_id, 
                                   datetime.now() - timedelta(days=1)
                               )
        }
    }), 200

if __name__ == '__main__':
    app.run()
```

**Security Features**:
- ✅ Multi-tier rate limiting
- ✅ Input validation and sanitization
- ✅ Cost monitoring and budgets
- ✅ Timeout protection
- ✅ Resource management
- ✅ Concurrent request limiting
- ✅ Usage tracking
- ✅ Comprehensive error handling

---

**Key Principle**: Defense against Model DoS requires multiple layers of protection working together. Input validation, rate limiting, resource management, timeout controls, and cost monitoring must all be implemented for comprehensive security.
