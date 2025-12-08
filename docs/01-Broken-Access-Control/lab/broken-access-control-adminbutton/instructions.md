# Lab Instructions: Broken Access Control - Admin Button

## Introduction

Welcome to the Broken Access Control lab! In this hands-on exercise, you'll discover how easily access control can be bypassed when it's only enforced on the client side.

**Time Required**: 30-45 minutes  
**Difficulty**: Beginner

## Learning Path

This lab follows a structured approach:
1. **Explore** - Understand the application as a regular user
2. **Discover** - Find the vulnerability
3. **Exploit** - Demonstrate the security flaw (safely)
4. **Understand** - Learn why this is dangerous
5. **Fix** - Implement proper access control
6. **Verify** - Test that the fix works

---

## Part 1: Setup and Exploration (10 minutes)

### Task 1.1: Start the Lab

```bash
# Navigate to the lab directory
cd docs/01-Broken-Access-Control/lab/broken-access-control-adminbutton/

# Start the application
docker-compose up
```

**Expected Output**: You should see:
```
Application running on http://localhost:5000
This is a SAFE EDUCATIONAL ENVIRONMENT
```

### Task 1.2: Explore as Regular User

1. Open your browser to **http://localhost:5000**
2. Log in as **alice** with password **password123**
3. Observe the interface:
   - What do you see?
   - What buttons are available?
   - What is your role?

**Questions to Consider**:
- Are there any admin features visible?
- What information is displayed about your account?

### Task 1.3: Explore as Admin User

1. Log out
2. Log in as **admin** with password **admin123**
3. Observe the difference:
   - What new buttons appear?
   - What is your role now?

**Expected**: You should see an "🔑 Admin Panel" button

---

## Part 2: Discovering the Vulnerability (10 minutes)

### Task 2.1: Inspect the HTML Source

1. Log back in as **alice** (regular user)
2. Right-click on the page and select **"View Page Source"** or press `Ctrl+U` (Windows/Linux) or `Cmd+Option+U` (Mac)
3. Search for "Admin" in the source code (Ctrl+F or Cmd+F)

**What to Look For**:
```html
<!-- Look for this pattern -->
{% if role == 'admin' %}
<button onclick="location.href='/admin'" class="btn-danger">🔑 Admin Panel</button>
{% endif %}
```

**Question**: What does this tell you about how access control is implemented?

### Task 2.2: Try Direct URL Access

While still logged in as **alice**:

1. Manually type in the address bar: **http://localhost:5000/admin**
2. Press Enter

**Expected Result**: You should see the Admin Panel!

**❗ VULNERABILITY CONFIRMED**: Regular users can access admin functionality by directly navigating to the URL.

### Task 2.3: Check the API Endpoints

1. Open your browser's Developer Tools (F12 or right-click → Inspect)
2. Go to the **Console** tab
3. You should see messages indicating the vulnerability

Alternatively, try accessing the API directly:
```javascript
// Type this in the browser console:
fetch('/api/admin/secrets')
  .then(response => response.json())
  .then(data => console.log(data));
```

**Expected**: You should see sensitive data returned!

**Questions**:
- Why could you access the admin panel?
- Why could you access the API endpoint?
- What server-side checks are missing?

---

## Part 3: Understanding the Vulnerability (10 minutes)

### Task 3.1: Review the Vulnerable Code

Open `app/server.py` and locate the `/admin` route:

```python
@app.route('/admin')
def admin_panel():
    """
    VULNERABILITY: This endpoint is accessible to anyone!
    """
    # VULNERABLE: No authorization check here!
    return render_template('admin.html', username=session.get('username'))
```

**Identify the Problems**:
1. No authentication check (not verifying if user is logged in)
2. No authorization check (not verifying if user is admin)
3. Anyone who knows the URL can access it

### Task 3.2: Review the Vulnerable API

Find the `/api/admin/secrets` route:

```python
@app.route('/api/admin/secrets')
def get_secrets():
    """
    VULNERABILITY: API endpoint with no authorization!
    """
    # VULNERABLE: No authorization check!
    return jsonify({'secrets': sensitive_data})
```

**Same Problems**:
- No authentication
- No authorization
- Returns sensitive data to anyone

### Task 3.3: Understand the Impact

In a real-world scenario, this could lead to:

- 🔴 **Data Breach**: Unauthorized access to sensitive information
- 🔴 **Privilege Escalation**: Regular users gaining admin powers
- 🔴 **Account Takeover**: Ability to modify or delete users
- 🔴 **System Compromise**: Access to administrative functions
- 🔴 **Compliance Violations**: GDPR, HIPAA, PCI-DSS breaches

---

## Part 4: Fixing the Vulnerability (10 minutes)

### Task 4.1: Add Authorization to Admin Panel

Edit `app/server.py` and modify the `/admin` route:

**Before** (Vulnerable):
```python
@app.route('/admin')
def admin_panel():
    return render_template('admin.html', username=session.get('username'))
```

**After** (Secure):
```python
from flask import abort

@app.route('/admin')
def admin_panel():
    # Check authentication
    if 'username' not in session:
        abort(401)  # Unauthorized - not logged in
    
    # Check authorization
    if session.get('role') != 'admin':
        abort(403)  # Forbidden - not an admin
    
    return render_template('admin.html', username=session.get('username'))
```

### Task 4.2: Add Authorization to API Endpoint

Modify the `/api/admin/secrets` route:

**Before** (Vulnerable):
```python
@app.route('/api/admin/secrets')
def get_secrets():
    return jsonify({'secrets': sensitive_data})
```

**After** (Secure):
```python
@app.route('/api/admin/secrets')
def get_secrets():
    # Check authentication
    if 'username' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Check authorization
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    return jsonify({'secrets': sensitive_data})
```

### Task 4.3: Restart the Application

```bash
# Stop the current instance (Ctrl+C)
# Restart with your changes
docker-compose up --build
```

---

## Part 5: Verification (5-10 minutes)

### Task 5.1: Test as Regular User

1. Log in as **alice**
2. Try accessing **http://localhost:5000/admin** directly

**Expected Result**: You should see an error page (403 Forbidden) or be redirected

### Task 5.2: Test the API as Regular User

Open the browser console and try:
```javascript
fetch('/api/admin/secrets')
  .then(response => response.json())
  .then(data => console.log(data));
```

**Expected Result**: You should get an error (403 Forbidden)

### Task 5.3: Test as Admin User

1. Log out and log in as **admin**
2. Click the "🔑 Admin Panel" button
3. Verify you can access the admin panel
4. Check that secrets load properly

**Expected Result**: Admin can access everything normally

### Task 5.4: Test Without Login

1. Log out completely
2. Try accessing **http://localhost:5000/admin** directly

**Expected Result**: 401 Unauthorized error

---

## Part 6: Additional Challenges (Optional)

### Challenge 1: Create a Decorator

Instead of repeating the authorization code, create a reusable decorator:

```python
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            abort(401)
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Use it like this:
@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html', username=session.get('username'))
```

### Challenge 2: Add Logging

Log all authorization failures for security monitoring:

```python
import logging

@app.route('/admin')
def admin_panel():
    if 'username' not in session:
        logging.warning("Unauthorized access attempt to /admin (not logged in)")
        abort(401)
    
    if session.get('role') != 'admin':
        logging.warning(f"Forbidden access attempt to /admin by {session.get('username')}")
        abort(403)
    
    return render_template('admin.html', username=session.get('username'))
```

### Challenge 3: Better Error Pages

Create custom error handlers:

```python
@app.errorhandler(401)
def unauthorized(error):
    return render_template('401.html'), 401

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403
```

---

## Key Takeaways

### What You Learned

✅ **Client-side security is not security** - Never trust the client  
✅ **Hiding != Protecting** - Hidden UI elements don't prevent access  
✅ **Always validate on the server** - Every request must be authorized  
✅ **Defense in depth** - UI restrictions + Server validation  
✅ **Test with different roles** - Verify isolation between users  

### Best Practices

1. 🔒 **Deny by default** - Start with no access, grant explicitly
2. 🔒 **Centralize authorization** - Use decorators or middleware
3. 🔒 **Check every request** - Not just page loads
4. 🔒 **Log failures** - Monitor for attack attempts
5. 🔒 **Test thoroughly** - Try to break your own security

### Common Mistakes to Avoid

❌ Only checking authorization in the UI  
❌ Assuming users won't find hidden URLs  
❌ Forgetting to protect API endpoints  
❌ Not testing with different user roles  
❌ Inconsistent security across endpoints  

---

## Clean Up

When you're done with the lab:

```bash
# Stop the containers
docker-compose down

# Remove volumes (optional)
docker-compose down -v
```

---

## Next Steps

1. ✅ Review the **[Prevention Guide](../../prevention.md)** for more best practices
2. ✅ Study the **[Examples](../../examples.md)** for additional patterns
3. ✅ Move on to the next OWASP Top 10 category
4. ✅ Apply these lessons to your own projects

---

## Questions for Reflection

1. Why is it dangerous to rely on client-side access control?
2. What are the consequences of broken access control in a real application?
3. How would you test for this vulnerability in production code?
4. What other endpoints might need protection in a real application?
5. How can you make authorization checks consistent across your codebase?

---

## Additional Resources

- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/latest/security/)
- [NIST Access Control Guidelines](https://csrc.nist.gov/publications/detail/sp/800-162/final)

---

**Congratulations!** You've completed the Broken Access Control lab. You now understand how critical server-side authorization is for application security.

*Part of the [OWASP Top 10 Educational Repository](../../../../../README.md)*
