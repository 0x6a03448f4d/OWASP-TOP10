# C8: Leverage Browser Security Features - Configuration Examples

Each pair below shows an **insecure** configuration—where the browser is told to enforce nothing—and the **secure** version that declares the right headers, cookie flags, and directives. These are a client-side defense-in-depth layer: apply them *and* keep your server-side output encoding, anti-CSRF tokens, and access control.

## 1. Express (Node.js) — Security Headers & Cookies

### Insecure
```javascript
const express = require('express');
const app = express();

// no security headers; x-powered-by banner on
app.post('/login', (req, res) => {
  // cookie readable by JS, sent over http, sent cross-site
  res.cookie('session', token);
  res.json({ ok: true });
});

app.get('/', (req, res) => res.send(renderPage()));   // no CSP, framable, sniffable
app.listen(3000);
```

### Secure
```javascript
const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const app = express();

app.disable('x-powered-by');
app.use(helmet());                                    // nosniff, frameguard, referrer, etc.
app.use(helmet.strictTransportSecurity({
  maxAge: 63072000, includeSubDomains: true, preload: true
}));

// per-request nonce + strict CSP
app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.nonce = nonce;
  res.setHeader('Content-Security-Policy',
    `default-src 'self'; script-src 'nonce-${nonce}' 'strict-dynamic'; ` +
    `object-src 'none'; base-uri 'none'; frame-ancestors 'none'; connect-src 'self'`);
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

app.post('/login', (req, res) => {
  res.cookie('__Host-session', token, {
    httpOnly: true, secure: true, sameSite: 'lax', path: '/'
  });
  res.json({ ok: true });
});
app.listen(3000);
```

## 2. Flask (Python) — Headers & Session Cookie

### Insecure
```python
from flask import Flask, make_response
app = Flask(__name__)

app.config.update(
    SESSION_COOKIE_HTTPONLY=False,   # readable by JavaScript
    SESSION_COOKIE_SECURE=False,     # sent over plaintext
    SESSION_COOKIE_SAMESITE=None,    # sent on cross-site requests
)

@app.route('/')
def index():
    return make_response(render())   # no security headers at all
```

### Secure
```python
import secrets
from flask import Flask, make_response, g
app = Flask(__name__)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

@app.before_request
def make_nonce():
    g.nonce = secrets.token_urlsafe(16)

@app.after_request
def set_security_headers(resp):
    resp.headers['Content-Security-Policy'] = (
        f"default-src 'self'; script-src 'nonce-{g.nonce}' 'strict-dynamic'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; connect-src 'self'"
    )
    resp.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return resp
```

## 3. nginx — Response Headers

### Insecure
```nginx
server {
    listen 80;                       # plaintext, no HTTPS redirect, no HSTS
    server_tokens on;                # advertises version
    location / {
        root /var/www/html;          # no CSP, no nosniff, framable
    }
}
```

### Secure
```nginx
server { listen 80; return 301 https://$host$request_uri; }   # force HTTPS

server {
    listen 443 ssl;
    server_tokens off;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy
        "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
    add_header X-Frame-Options "DENY" always;          # legacy fallback

    location / { root /var/www/html; }
}
```

## 4. HTML — Third-Party Scripts, Framing & Sandbox

### Insecure
```html
<!-- CDN script with no integrity check: a tampered file runs with full trust -->
<script src="https://cdn.example.com/widget.js"></script>

<!-- untrusted third-party content embedded with no restrictions -->
<iframe src="https://untrusted.example/ad"></iframe>

<!-- inline handler that a strict CSP would (rightly) block -->
<button onclick="doTransfer()">Send</button>
```

### Secure
```html
<!-- Subresource Integrity: a modified script is refused by the browser -->
<script src="https://cdn.example.com/widget.js"
        integrity="sha384-BASE64_HASH_OF_EXACT_FILE"
        crossorigin="anonymous"></script>

<!-- restricted sandbox: only the capabilities the embed needs -->
<iframe src="https://untrusted.example/ad"
        sandbox="allow-scripts"></iframe>

<!-- no inline handlers; behavior attached from a nonce-approved script -->
<button id="send">Send</button>
<script nonce="{RANDOM}">
  document.getElementById('send').addEventListener('click', doTransfer);
</script>
```

## 5. CORS — Reflection vs. Allow-List

### Insecure
```javascript
// reflects any origin AND allows credentials -> any site can read responses
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});
```

### Secure
```javascript
const ALLOW = new Set(['https://app.example.com']);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOW.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);   // echo only known origins
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  next();
});
```

## 6. Trusted Types — DOM-XSS Sink

### Insecure
```javascript
// untrusted input flows straight into a dangerous sink
element.innerHTML = location.hash.slice(1);   // DOM-based XSS
```

### Secure
```javascript
// Response header:
// Content-Security-Policy: require-trusted-types-for 'script'; trusted-types app-policy

const policy = trustedTypes.createPolicy('app-policy', {
  createHTML: (s) => DOMPurify.sanitize(s)     // sanitized before it can become HTML
});
element.innerHTML = policy.createHTML(location.hash.slice(1));
// a raw string assignment now throws instead of executing
```

## What Changed, and Why

| Area | Insecure | Secure (browser enforces) |
|------|----------|---------------------------|
| Scripts | No CSP; inline handlers; injected script runs | Nonce + `strict-dynamic` CSP; only vetted code runs |
| Transport | Plaintext allowed; no HSTS | HTTPS forced; HSTS with preload |
| Cookies | Script-readable, cross-site, plaintext | `HttpOnly`, `Secure`, `SameSite`, `__Host-` |
| Framing | Framable by any site | `frame-ancestors 'none'` + `X-Frame-Options` |
| Third-party | Unverified CDN script | Subresource Integrity hash |
| CORS | Reflected origin + credentials | Explicit allow-list + `Vary: Origin` |
| DOM sinks | Raw `innerHTML` | Trusted Types policy |

> **Defense-in-depth reminder**: every "secure" column above is a backstop enforced in the browser. Keep encoding output, using parameterized queries, validating input, and issuing anti-CSRF tokens on the server. The browser holds the second line; the server must still hold the first.

## Next Steps

- **[How to Implement](prevention.md)**: The full set of headers and configuration, and why
- **[Threats Addressed](attack-vectors.md)**: How the insecure versions are exploited
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Configure browser security features hands-on
