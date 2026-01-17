from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import traceback

app = Flask(__name__)

# VULNERABLE: Overly permissive CORS
CORS(app, origins='*', supports_credentials=True)

# VULNERABLE: Debug mode
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret-key-123'
app.config['DATABASE_PASSWORD'] = 'db_pass_prod_2024'

@app.route('/')
def index():
    return render_template('index.html')

# VULNERABLE: Exposes full stack trace
@app.route('/api/users/<user_id>')
def get_user(user_id):
    try:
        # Force error for demo
        if user_id == 'error':
            raise ValueError(f"Invalid user ID: {user_id}")
        return jsonify({'id': user_id, 'name': 'Test User'})
    except Exception as e:
        # VULNERABLE: Returns full stack trace!
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500

# VULNERABLE: Debug endpoint in production
@app.route('/_debug')
def debug():
    return jsonify({
        'config': dict(app.config),
        'environment': 'production',
        'secrets_exposed': True
    })

# VULNERABLE: Missing security headers
@app.route('/api/data')
def get_data():
    response = jsonify({'data': 'sensitive information'})
    # No security headers set!
    return response

if __name__ == '__main__':
    # VULNERABLE: Debug mode ON
    app.run(host='0.0.0.0', port=5000, debug=True)
