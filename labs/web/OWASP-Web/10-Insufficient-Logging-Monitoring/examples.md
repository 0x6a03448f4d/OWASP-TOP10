# Logging & Monitoring - Examples

**❌ NO LOGGING:**

```python
@app.route('/login', methods=['POST'])
def login():
    if check_password(username, password):
        session['user'] = username
        return "OK"
    return "Failed", 401
# No logging at all - invisible to security team
```

**✅ PROPER LOGGING:**

```python
import logging

logger = logging.getLogger(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    ip = request.remote_addr
    
    if check_password(username, password):
        logger.info(f"Login success: user={username}, ip={ip}")
        session['user'] = username
        return "OK"
    else:
        logger.warning(f"Login failed: user={username}, ip={ip}")
        return "Failed", 401
```
