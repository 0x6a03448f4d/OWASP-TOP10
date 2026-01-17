from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

users_db = {'1': {'name': 'Alice', 'role': 'user'}, '2': {'name': 'Bob', 'role': 'admin'}}

@app.route('/')
def index():
    return render_template('index.html')

# VULNERABLE: Old v1 - No authentication
@app.route('/api/v1/users', methods=['GET'])
def get_users_v1():
    return jsonify(users_db)

# v2 - Basic validation
@app.route('/api/v2/users', methods=['GET'])
def get_users_v2():
    auth = request.headers.get('Authorization')
    if not auth:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(users_db)

# v3 - Full security
@app.route('/api/v3/users', methods=['GET'])
def get_users_v3():
    auth = request.headers.get('Authorization')
    if not auth or auth != 'Bearer secret-token':
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(users_db)

# VULNERABLE: Undocumented admin endpoint
@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    return jsonify({'all_users': users_db, 'admin_access': True})

# VULNERABLE: Debug endpoint
@app.route('/_internal/debug', methods=['GET'])
def internal_debug():
    return jsonify({'endpoints': ['/api/v1/users', '/api/v2/users', '/api/v3/users', '/api/admin/users', '/_internal/debug']})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
