# XSS Prevention

## Output Encoding

```python
from flask import Flask, escape, Markup
from markupsafe import escape

@app.route('/profile/<username>')
def profile(username):
    # Auto-escapes in templates
    return render_template('profile.html', name=username)
```

```html
<!-- Template with auto-escaping -->
<h1>Welcome {{ name }}</h1>  <!-- Escaped by default -->
<div>{{ content|safe }}</div>  <!-- Only if trusted -->
```

## Content Security Policy

```python
from flask import Flask, make_response

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] =         "default-src 'self'; script-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```

## Input Validation

```python
import bleach

allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'a']
allowed_attrs = {'a': ['href', 'title']}

def sanitize_input(user_input):
    return bleach.clean(user_input, 
                       tags=allowed_tags,
                       attributes=allowed_attrs,
                       strip=True)
```

## Best Practices

- Escape all user input before rendering
- Use Content Security Policy headers
- Validate and sanitize input
- Use HttpOnly and Secure flags on cookies
- Avoid inline JavaScript
