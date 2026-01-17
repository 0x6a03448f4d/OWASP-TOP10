# API07: Server Side Request Forgery - Prevention

## Prevention Strategy Overview

Preventing SSRF requires a multi-layered approach:
1. Input validation and sanitization
2. Network-level controls
3. Application-level defenses
4. Monitoring and detection

### Core Principles

- **Whitelist over blacklist**: Only allow known-good destinations
- **Network segmentation**: Limit what servers can access
- **Least privilege**: Minimize permissions and access
- **Defense in depth**: Multiple layers of protection

## Input Validation

### URL Validation and Sanitization

```python
import urllib.parse
import ipaddress

def is_safe_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Only allow HTTP/HTTPS
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP(S) allowed"
        
        # Get hostname
        hostname = parsed.hostname
        if not hostname:
            return False, "No hostname"
        
        # Resolve to IP
        import socket
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # Block private/reserved IPs
        if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
            return False, f"Private IP not allowed: {ip}"
        
        # Block link-local (169.254.0.0/16)
        if ip_obj.is_link_local:
            return False, "Link-local IP not allowed"
        
        # Whitelist domains (recommended)
        allowed_domains = ['example.com', 'trusted-partner.com']
        if not any(hostname.endswith(domain) for domain in allowed_domains):
            return False, "Domain not in whitelist"
        
        return True, None
        
    except Exception as e:
        return False, str(e)

# Usage
@app.route('/api/import', methods=['POST'])
def import_data():
    url = request.json['url']
    
    is_safe, reason = is_safe_url(url)
    if not is_safe:
        return jsonify({'error': f'Invalid URL: {reason}'}), 400
    
    # Safe to fetch
    response = requests.get(url, timeout=5)
    return jsonify(response.json())
```

### Prevent DNS Rebinding

```python
def fetch_url_safely(url):
    # Validate once
    is_safe, reason = is_safe_url(url)
    if not is_safe:
        raise ValueError(reason)
    
    # Disable redirects to prevent bypass
    response = requests.get(url, allow_redirects=False, timeout=5)
    
    # If redirect, validate new location
    if response.status_code in [301, 302, 303, 307, 308]:
        new_url = response.headers.get('Location')
        is_safe, reason = is_safe_url(new_url)
        if not is_safe:
            raise ValueError(f"Redirect blocked: {reason}")
    
    return response
```

## Network-Level Controls

### Cloud Metadata Protection

**AWS IMDSv2 (Require Token)**:
```bash
# Enforce IMDSv2
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

**Block at Firewall**:
```bash
# iptables rule to block metadata service
iptables -A OUTPUT -d 169.254.169.254 -j REJECT
```

### Network Segmentation

```
[DMZ - API Servers]
       ↓ (only specific internal IPs allowed)
[Internal Network - Services]
       ↓ (isolated)
[Database Layer]
```

### Egress Filtering

```python
# Use proxy with whitelist
import requests

session = requests.Session()
session.proxies = {
    'http': 'http://egress-proxy:3128',
    'https': 'http://egress-proxy:3128'
}

# Proxy enforces destination whitelist
response = session.get(user_url)
```

## Application-Level Defenses

### Use Safe HTTP Clients

```python
import requests
from requests.exceptions import ConnectTimeout

def safe_fetch(url):
    try:
        response = requests.get(
            url,
            timeout=5,  # Prevent hang
            allow_redirects=False,  # No redirect follow
            verify=True,  # Verify SSL
            stream=False  # Load entire response
        )
        return response
    except ConnectTimeout:
        raise ValueError("Request timeout")
```

### Implement Response Size Limits

```python
def fetch_with_size_limit(url, max_size=1024*1024):  # 1MB
    response = requests.get(url, stream=True, timeout=5)
    
    content = b''
    for chunk in response.iter_content(chunk_size=8192):
        content += chunk
        if len(content) > max_size:
            raise ValueError("Response too large")
    
    return content
```

### Content-Type Validation

```python
def fetch_image(url):
    response = safe_fetch(url)
    
    # Verify Content-Type
    content_type = response.headers.get('Content-Type', '')
    if not content_type.startswith('image/'):
        raise ValueError(f"Invalid content type: {content_type}")
    
    # Verify actual content
    import imghdr
    image_type = imghdr.what(None, h=response.content)
    if not image_type:
        raise ValueError("Not a valid image")
    
    return response.content
```

## Monitoring and Detection

### Log Outbound Requests

```python
import logging

def fetch_url(url):
    logger.info(f"Outbound request: {url}")
    
    # Log destination IP
    import socket
    ip = socket.gethostbyname(urllib.parse.urlparse(url).hostname)
    logger.info(f"Resolved to: {ip}")
    
    response = requests.get(url)
    
    logger.info(f"Response: {response.status_code}, {len(response.content)} bytes")
    
    return response
```

### Alert on Suspicious Patterns

```python
def detect_ssrf_attempt(url):
    alerts = []
    
    # Check for metadata service
    if '169.254.169.254' in url:
        alerts.append('AWS metadata service access attempt')
    
    # Check for localhost
    if any(x in url.lower() for x in ['localhost', '127.0.0.1', '0.0.0.0']):
        alerts.append('Localhost access attempt')
    
    # Check for private IPs
    if any(x in url for x in ['192.168.', '10.', '172.16.']):
        alerts.append('Private IP access attempt')
    
    # Check for file protocol
    if url.startswith('file://'):
        alerts.append('File protocol access attempt')
    
    if alerts:
        logger.warning(f"SSRF attempt detected: {alerts}, URL: {url}")
        send_security_alert(alerts, url)
    
    return len(alerts) > 0
```

## Framework-Specific Protection

### Flask

```python
from flask import Flask, request, jsonify
import requests
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)

ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

def validate_url(url):
    parsed = urlparse(url)
    
    if parsed.scheme not in ['http', 'https']:
        return False
    
    if not any(parsed.netloc.endswith(domain) for domain in ALLOWED_DOMAINS):
        return False
    
    # Check IP
    import socket
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    
    return True

@app.route('/api/fetch', methods=['POST'])
def fetch_data():
    url = request.json.get('url')
    
    if not validate_url(url):
        return jsonify({'error': 'Invalid URL'}), 400
    
    response = requests.get(url, timeout=5, allow_redirects=False)
    return jsonify({'data': response.text})
```

### Express (Node.js)

```javascript
const express = require('express');
const axios = require('axios');
const { URL } = require('url');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

const ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com'];

async function validateUrl(urlString) {
    const url = new URL(urlString);
    
    // Only HTTP(S)
    if (!['http:', 'https:'].includes(url.protocol)) {
        throw new Error('Invalid protocol');
    }
    
    // Whitelist check
    if (!ALLOWED_DOMAINS.some(d => url.hostname.endsWith(d))) {
        throw new Error('Domain not allowed');
    }
    
    // Resolve and check IP
    const addresses = await dns.resolve4(url.hostname);
    const addr = ipaddr.parse(addresses[0]);
    
    if (addr.range() !== 'unicast') {
        throw new Error('Private/reserved IP not allowed');
    }
    
    return true;
}

app.post('/api/fetch', async (req, res) => {
    try {
        await validateUrl(req.body.url);
        
        const response = await axios.get(req.body.url, {
            timeout: 5000,
            maxRedirects: 0
        });
        
        res.json({ data: response.data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});
```

## Key Takeaways

1. **Whitelist destinations** - Only allow known-good URLs/domains
2. **Validate before and after redirects** - Prevent redirect bypass
3. **Block private IPs** - Use ipaddress library to check ranges
4. **Disable unnecessary protocols** - Only HTTP(S) if possible
5. **Implement network controls** - Egress filtering, metadata protection
6. **Monitor and alert** - Log all outbound requests, detect patterns
7. **Use safe defaults** - Disable redirects, set timeouts

## Next Steps

- **[Code Examples](examples.md)**: See implementations across frameworks
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Hands-On Lab](lab/api07-ssrf-lab/)**: Practice SSRF prevention
