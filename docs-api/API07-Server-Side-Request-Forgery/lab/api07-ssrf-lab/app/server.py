from flask import Flask, request, jsonify, render_template
import requests
import socket

app = Flask(__name__)

# Simulated internal services
internal_services = {
    'metadata': {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'},
    'database': {'host': 'db.internal', 'password': 'db_secret_123'},
    'admin': {'users': ['admin', 'john', 'jane'], 'permissions': 'full'}
}

@app.route('/')
def index():
    return render_template('index.html')

# VULNERABLE: URL import without validation
@app.route('/api/import-data', methods=['POST'])
def import_data():
    url = request.json.get('url', '')
    
    try:
        # NO VALIDATION - VULNERABLE TO SSRF!
        response = requests.get(url, timeout=5)
        return jsonify({'success': True, 'data': response.text[:500]})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# VULNERABLE: Webhook without URL validation
@app.route('/api/webhook/register', methods=['POST'])
def register_webhook():
    callback_url = request.json.get('callback_url', '')
    
    # Simulate webhook callback - NO VALIDATION!
    try:
        response = requests.post(callback_url, json={'event': 'test'}, timeout=5)
        return jsonify({'success': True, 'registered': callback_url})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# VULNERABLE: Image fetch from URL
@app.route('/api/fetch-image', methods=['POST'])
def fetch_image():
    image_url = request.json.get('image_url', '')
    
    try:
        # NO VALIDATION - can access file://
        response = requests.get(image_url, timeout=5)
        return jsonify({'success': True, 'size': len(response.content)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Simulated internal endpoints (to demonstrate SSRF)
@app.route('/internal/metadata')
def metadata():
    # Simulates AWS metadata service
    return jsonify(internal_services['metadata'])

@app.route('/internal/database')
def database():
    return jsonify(internal_services['database'])

@app.route('/internal/admin')
def admin():
    return jsonify(internal_services['admin'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
