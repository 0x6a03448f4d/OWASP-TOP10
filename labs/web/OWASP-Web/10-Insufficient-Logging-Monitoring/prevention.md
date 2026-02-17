# Logging & Monitoring - Prevention

## Comprehensive Logging

```python
import logging
from logging.handlers import RotatingFileHandler
from flask import request, session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

handler = RotatingFileHandler('security.log', 
                              maxBytes=10000000, 
                              backupCount=5)
formatter = logging.Formatter(
    '%(asctime)s %(levelname)s [%(request_id)s] %(message)s'
)
handler.setFormatter(formatter)
logger.addHandler(handler)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    ip_address = request.remote_addr
    
    if authenticate(username, password):
        logger.info(f"Successful login: user={username}, ip={ip_address}")
        return "Login successful"
    else:
        logger.warning(f"Failed login attempt: user={username}, ip={ip_address}")
        return "Login failed", 401

@app.route('/admin/delete', methods=['POST'])
def delete_user():
    if not session.get('is_admin'):
        logger.warning(
            f"Unauthorized admin access attempt: "
            f"user={session.get('username')}, "
            f"ip={request.remote_addr}, "
            f"endpoint=/admin/delete"
        )
        return "Forbidden", 403
    
    user_id = request.form.get('user_id')
    logger.info(f"User deletion: admin={session['username']}, deleted_user_id={user_id}")
    delete_user_from_db(user_id)
    return "User deleted"
```

## Security Monitoring

```python
from collections import defaultdict
from datetime import datetime, timedelta

# Track failed login attempts
failed_attempts = defaultdict(list)

def check_brute_force(username, ip):
    now = datetime.now()
    cutoff = now - timedelta(minutes=5)
    
    # Clean old attempts
    failed_attempts[username] = [
        time for time in failed_attempts[username] 
        if time > cutoff
    ]
    
    if len(failed_attempts[username]) >= 5:
        logger.critical(
            f"BRUTE FORCE DETECTED: user={username}, ip={ip}, "
            f"attempts={len(failed_attempts[username])}"
        )
        # Trigger alert, block IP, etc.
        return True
    
    failed_attempts[username].append(now)
    return False
```

## Best Practices

- Log all authentication events
- Log access control failures
- Include context (user, IP, timestamp)
- Protect log integrity
- Centralize log collection
- Set up real-time alerts for critical events
- Regularly review logs
- Ensure logs are tamper-proof
- Comply with retention policies
