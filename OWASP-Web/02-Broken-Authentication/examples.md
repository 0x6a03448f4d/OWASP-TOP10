# Broken Authentication - Code Examples

## Vulnerable vs Secure Code

### Example 1: Password Validation

**❌ VULNERABLE:**

```python
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    
    # BAD: No password requirements
    # BAD: Plain text storage
    users[username] = password
    return "Account created"
```

**✅ SECURE:**

```python
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    
    # Validate password strength
    if len(password) < 12:
        return "Password too short", 400
    
    # Hash password with salt
    from werkzeug.security import generate_password_hash
    hashed = generate_password_hash(password, method='pbkdf2:sha256')
    
    users[username] = hashed
    return "Account created"
```

### Example 2: Session Management

**❌ VULNERABLE:**

```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if check_credentials(username, password):
        # BAD: Predictable session ID
        session['user'] = username
        session['sessionid'] = str(hash(username))
        return "Logged in"
```

**✅ SECURE:**

```python
import secrets

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if check_credentials(username, password):
        # Regenerate session to prevent fixation
        old_session = dict(session)
        session.clear()
        
        # Secure random session ID
        session['user'] = username
        session['sessionid'] = secrets.token_urlsafe(32)
        session.permanent = True
        
        return "Logged in"
```

### Example 3: Logout Handling

**❌ VULNERABLE:**

```python
@app.route('/logout')
def logout():
    # BAD: Only client-side logout
    return redirect('/login')
```

**✅ SECURE:**

```python
@app.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    
    # Blacklist the session token
    blacklist_token(session.get('sessionid'))
    
    return redirect('/login')
```
