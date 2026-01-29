# Cross-Site Scripting (XSS) - Overview

## What is XSS?

**Cross-Site Scripting (XSS)** enables attackers to inject malicious scripts into web pages viewed by other users. When victims load the page, the malicious script executes in their browser, potentially stealing cookies, session tokens, or performing actions on their behalf.

### Types of XSS

1. **Reflected XSS**: Script reflected off web server (URL parameters)
2. **Stored XSS**: Script stored in database and displayed to users
3. **DOM-based XSS**: Vulnerability in client-side JavaScript

### Example Attack

```html
<!-- Vulnerable search page -->
<h1>Results for: <?php echo $_GET['q']; ?></h1>

<!-- Attack URL -->
http://site.com/search?q=<script>alert(document.cookie)</script>
```

## Why XSS Matters

XSS was #7 in OWASP Top 10 2017 and remains critical:

- Session hijacking
- Credential theft
- Malware distribution
- Website defacement
- Phishing attacks

## Classic 2017 XSS Scenarios

- Unescaped user input in HTML
- Rich text editors without sanitization
- JavaScript template injection
- JSON endpoints without Content-Type
