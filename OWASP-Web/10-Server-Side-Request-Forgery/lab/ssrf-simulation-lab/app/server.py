"""
OWASP Top 10 Lab: SSRF - URL Fetcher

This lab demonstrates SSRF vulnerability through URL fetching with
no validation (MOCKED - no real network requests made).

EDUCATIONAL PURPOSE ONLY
"""

from flask import Flask, render_template, request, jsonify
import re

app = Flask(__name__)

# Mock internal services
INTERNAL_SERVICES = {
    'http://localhost:8080/admin': 'Admin Panel - Sensitive Data',
    'http://127.0.0.1:3306/mysql': 'MySQL Database',
    'http://169.254.169.254/latest/meta-data/': 'AWS Metadata (Cloud)'
}

@app.route('/')
def home():
    return render_template('fetch.html')

@app.route('/fetch/vulnerable', methods=['POST'])
def fetch_vulnerable():
    """VULNERABILITY: No URL validation"""
    data = request.json
    url = data.get('url', '')
    
    # Check if trying to access internal service (simulated)
    for internal_url, description in INTERNAL_SERVICES.items():
        if url.startswith(internal_url) or url.startswith('http://localhost') or url.startswith('http://127.0.0.1'):
            return jsonify({
                'method': 'No Validation (VULNERABLE)',
                'requested_url': url,
                'warning': '⚠️ SSRF Attack Detected!',
                'impact': f'Accessed internal service: {description}',
                'data': f'[Simulated internal data from {url}]',
                'vulnerability': 'CRITICAL'
            })
    
    # Mock external fetch
    return jsonify({
        'method': 'No Validation (VULNERABLE)',
        'requested_url': url,
        'data': f'[Simulated fetch from {url}]',
        'warning': 'No URL validation - SSRF possible!'
    })

@app.route('/fetch/secure', methods=['POST'])
def fetch_secure():
    """SECURE: URL whitelist validation"""
    data = request.json
    url = data.get('url', '')
    
    # Whitelist of allowed domains
    ALLOWED_DOMAINS = ['example.com', 'api.example.com']
    
    # Validate URL
    is_allowed = any(domain in url for domain in ALLOWED_DOMAINS)
    
    if not is_allowed:
        return jsonify({
            'method': 'Whitelist Validation (SECURE)',
            'requested_url': url,
            'error': 'URL not in whitelist',
            'allowed_domains': ALLOWED_DOMAINS
        }), 403
    
    return jsonify({
        'method': 'Whitelist Validation (SECURE)',
        'requested_url': url,
        'data': f'[Fetched from whitelisted URL: {url}]',
        'security': 'SECURE ✓'
    })

if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: SSRF Simulation")
    print("=" * 60)
    print("\nVulnerability: No URL validation allows SSRF")
    print("Application running on http://localhost:5001")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
