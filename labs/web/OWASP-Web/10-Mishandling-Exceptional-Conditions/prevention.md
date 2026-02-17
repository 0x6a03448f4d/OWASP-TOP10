# Proper Exception Handling

## Defensive Programming

```python
from flask import Flask, jsonify, request
from functools import wraps
import logging

logger = logging.getLogger(__name__)

def handle_exceptions(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            logger.warning(f"Validation error: {str(e)}")
            return jsonify({'error': 'Invalid input'}), 400
        except PermissionError as e:
            logger.warning(f"Permission denied: {str(e)}")
            return jsonify({'error': 'Permission denied'}), 403
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)
            # Never expose internal errors to users
            return jsonify({'error': 'Internal server error'}), 500
    return wrapper

@app.route('/api/transfer', methods=['POST'])
@handle_exceptions
def transfer_money():
    data = request.get_json()
    
    # Validate input
    if not data or 'amount' not in data:
        raise ValueError("Amount is required")
    
    amount = float(data['amount'])
    
    if amount <= 0:
        raise ValueError("Amount must be positive")
    
    if amount > 10000:
        raise ValueError("Amount exceeds limit")
    
    # Process transfer
    result = process_transfer(amount)
    return jsonify(result)
```

## Circuit Breaker Pattern

```python
from datetime import datetime, timedelta

class CircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failures = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
    
    def call(self, func, *args, **kwargs):
        if self.state == 'OPEN':
            if datetime.now() - self.last_failure_time > timedelta(seconds=self.timeout):
                self.state = 'HALF_OPEN'
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = func(*args, **kwargs)
            self.on_success()
            return result
        except Exception as e:
            self.on_failure()
            raise
    
    def on_success(self):
        self.failures = 0
        self.state = 'CLOSED'
    
    def on_failure(self):
        self.failures += 1
        self.last_failure_time = datetime.now()
        
        if self.failures >= self.failure_threshold:
            self.state = 'OPEN'
            logger.critical(f"Circuit breaker opened after {self.failures} failures")

# Usage
payment_circuit_breaker = CircuitBreaker(failure_threshold=3, timeout=30)

@app.route('/payment')
def process_payment():
    try:
        result = payment_circuit_breaker.call(external_payment_api)
        return jsonify(result)
    except Exception:
        return jsonify({'error': 'Payment service temporarily unavailable'}), 503
```

## Graceful Degradation

```python
class ResilientService:
    def __init__(self):
        self.cache = {}
        self.fallback_enabled = True
    
    def get_data(self, key):
        try:
            # Try primary data source
            data = self.fetch_from_database(key)
            self.cache[key] = data  # Update cache
            return data
        except DatabaseConnectionError:
            logger.warning("Database unavailable, using cache")
            # Fallback to cache
            if key in self.cache:
                return self.cache[key]
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            # Return degraded response
            if self.fallback_enabled:
                return self.get_fallback_data(key)
            raise
```

## Resource Limits

```python
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import signal

class ResourceLimitedOperation:
    def __init__(self, max_workers=10, timeout=30):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.timeout = timeout
    
    def execute(self, func, *args, **kwargs):
        future = self.executor.submit(func, *args, **kwargs)
        
        try:
            result = future.result(timeout=self.timeout)
            return result
        except TimeoutError:
            logger.warning(f"Operation timed out after {self.timeout}s")
            future.cancel()
            raise
        except Exception as e:
            logger.error(f"Operation failed: {e}")
            raise
```

## Best Practices

- Never expose stack traces to users
- Log all exceptions with context
- Implement circuit breakers for external services
- Set timeouts on all operations
- Validate all inputs
- Handle async errors properly
- Implement retry with exponential backoff
- Use graceful degradation
- Monitor error rates
- Test error paths
