# XSS Code Examples

## Vulnerable vs Secure

**❌ VULNERABLE:**

```python
@app.route('/comment', methods=['POST'])
def post_comment():
    comment = request.form['comment']
    # Stored in DB without sanitization
    db.insert({'comment': comment})
    
    # Displayed without escaping
    return f"<div>{comment}</div>"
```

**✅ SECURE:**

```python
from markupsafe import escape
import bleach

@app.route('/comment', methods=['POST'])
def post_comment():
    comment = request.form['comment']
    
    # Sanitize input
    clean_comment = bleach.clean(comment)
    db.insert({'comment': clean_comment})
    
    # Escape output
    return render_template('comment.html', 
                         comment=clean_comment)
```
