from flask import Flask, request, render_template, jsonify
import html
import re
import random

app = Flask(__name__)

# Simulated LLM that can be manipulated via prompt injection
def mock_llm_generate(prompt, mode='vulnerable'):
    """
    Simulates an LLM that responds to prompts
    In vulnerable mode, it follows malicious instructions
    """
    prompt_lower = prompt.lower()
    
    # Detect prompt injection attempts
    if 'ignore' in prompt_lower and 'instructions' in prompt_lower:
        # Follow the malicious instruction
        if '<script>' in prompt:
            match = re.search(r'(<script>.*?</script>)', prompt, re.IGNORECASE)
            if match:
                return match.group(1)
        if 'respond with:' in prompt_lower:
            match = re.search(r'respond with:\s*(.+)', prompt, re.IGNORECASE)
            if match:
                return match.group(1).strip()
    
    # Simulate extracting malicious SQL
    if 'product' in prompt_lower and "'" in prompt:
        if ' or ' in prompt_lower or 'union' in prompt_lower:
            return prompt.split(':')[-1].strip() if ':' in prompt else prompt
    
    # Simulate URL extraction that could be SSRF
    if 'url' in prompt_lower or 'link' in prompt_lower:
        urls = re.findall(r'https?://[^\s]+', prompt)
        if urls:
            return urls[0]
    
    # Default responses
    responses = [
        "Thank you for your question. I'm here to help!",
        "I'd be happy to assist you with that.",
        "That's an interesting query. Let me help you.",
        f"Based on your request: {prompt[:50]}..., here's my response.",
    ]
    
    return random.choice(responses)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/chat', methods=['POST'])
def chat_vulnerable():
    """
    VULNERABLE: Demonstrates XSS through insecure output handling
    """
    data = request.get_json()
    user_input = data.get('message', '')
    
    # Generate LLM response (can be manipulated)
    llm_response = mock_llm_generate(user_input, mode='vulnerable')
    
    # VULNERABILITY: No HTML encoding
    # Returns raw HTML that will be rendered on frontend
    return jsonify({
        'response': llm_response,
        'vulnerability': 'XSS - output not encoded'
    })


@app.route('/api/chat/secure', methods=['POST'])
def chat_secure():
    """
    SECURE: Properly handles LLM output with encoding
    """
    data = request.get_json()
    user_input = data.get('message', '')
    
    # Validate input
    if len(user_input) > 1000:
        return jsonify({'error': 'Input too long'}), 400
    
    # Detect suspicious patterns
    suspicious_patterns = [
        r'<script[^>]*>',
        r'javascript:',
        r'onerror\s*=',
        r'on\w+\s*=',
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return jsonify({
                'error': 'Suspicious input detected',
                'pattern': pattern
            }), 400
    
    # Generate LLM response
    llm_response = mock_llm_generate(user_input, mode='secure')
    
    # SECURE: HTML encode the output
    safe_response = html.escape(llm_response)
    
    return jsonify({
        'response': safe_response,
        'security': 'Output properly encoded'
    })


@app.route('/api/search', methods=['GET'])
def search_vulnerable():
    """
    VULNERABLE: Demonstrates SQL injection through LLM output
    """
    query = request.args.get('q', '')
    
    # LLM extracts search term (can be manipulated)
    search_term = mock_llm_generate(f"Extract product name: {query}")
    
    # VULNERABILITY: String concatenation in SQL
    # Simulated SQL query
    sql_query = f"SELECT * FROM products WHERE name = '{search_term}'"
    
    # Demonstrate the vulnerability
    if "' or '" in search_term.lower() or 'union' in search_term.lower():
        result = {
            'vulnerability': 'SQL Injection Detected!',
            'sql_query': sql_query,
            'risk': 'All database records could be exposed',
            'products': ['Product 1', 'Product 2', 'Product 3', '...ALL PRODUCTS']
        }
    else:
        result = {
            'sql_query': sql_query,
            'products': ['Sample Product']
        }
    
    return jsonify(result)


@app.route('/api/search/secure', methods=['GET'])
def search_secure():
    """
    SECURE: Uses parameterized queries
    """
    query = request.args.get('q', '')
    
    # Validate input
    if len(query) > 200:
        return jsonify({'error': 'Query too long'}), 400
    
    # LLM extracts search term
    search_term = mock_llm_generate(f"Extract product name: {query}")
    
    # Sanitize the search term
    safe_term = re.sub(r'[^\w\s-]', '', search_term)
    
    # SECURE: Would use parameterized query
    # query = "SELECT * FROM products WHERE name LIKE ?"
    # params = (f"%{safe_term}%",)
    
    return jsonify({
        'security': 'Parameterized query used',
        'sanitized_term': safe_term,
        'products': ['Sample Product 1', 'Sample Product 2']
    })


@app.route('/api/fetch-url', methods=['POST'])
def fetch_url_vulnerable():
    """
    VULNERABLE: Demonstrates SSRF through LLM-generated URLs
    """
    data = request.get_json()
    user_input = data.get('text', '')
    
    # LLM extracts URL (can be manipulated to return internal URLs)
    url = mock_llm_generate(f"Extract URL from: {user_input}")
    
    # VULNERABILITY: No URL validation
    # In real scenario, would fetch the URL
    
    # Demonstrate the vulnerability
    if 'localhost' in url or '127.0.0.1' in url or '169.254.169.254' in url:
        return jsonify({
            'vulnerability': 'SSRF Detected!',
            'url': url,
            'risk': 'Internal services could be accessed',
            'example_data': 'AWS Metadata: {"role": "admin", "secret_key": "..."}'
        })
    else:
        return jsonify({
            'url': url,
            'warning': 'Would fetch this URL without validation'
        })


@app.route('/api/fetch-url/secure', methods=['POST'])
def fetch_url_secure():
    """
    SECURE: Validates URLs before fetching
    """
    data = request.get_json()
    user_input = data.get('text', '')
    
    # LLM extracts URL
    url = mock_llm_generate(f"Extract URL from: {user_input}")
    
    # SECURE: Validate URL
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            return jsonify({'error': 'Only HTTP/HTTPS allowed'}), 400
        
        # Check for internal IPs
        blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', 
                        '10.', '172.16.', '192.168.']
        
        for blocked in blocked_hosts:
            if parsed.hostname and (parsed.hostname == blocked or parsed.hostname.startswith(blocked)):
                return jsonify({'error': 'Internal URLs not allowed'}), 400
        
        # Domain allowlist
        allowed_domains = ['example.com', 'api.example.com', 'docs.example.com']
        if parsed.netloc not in allowed_domains:
            return jsonify({'error': 'Domain not in allowlist'}), 400
        
        return jsonify({
            'security': 'URL validated',
            'url': url,
            'status': 'Safe to fetch'
        })
        
    except Exception as e:
        return jsonify({'error': f'Invalid URL: {str(e)}'}), 400


@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'LLM02 Insecure Output Handling Lab'})


if __name__ == '__main__':
    print("=" * 60)
    print("LLM02: Insecure Output Handling Lab")
    print("=" * 60)
    print("Server running on http://localhost:6002")
    print("\nAvailable endpoints:")
    print("  Vulnerable:")
    print("    POST /api/chat - XSS vulnerability")
    print("    GET  /api/search?q=<query> - SQL injection")
    print("    POST /api/fetch-url - SSRF vulnerability")
    print("\n  Secure:")
    print("    POST /api/chat/secure - Properly encoded output")
    print("    GET  /api/search/secure?q=<query> - Parameterized queries")
    print("    POST /api/fetch-url/secure - URL validation")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
