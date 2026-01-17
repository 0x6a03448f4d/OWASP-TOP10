# API09: Improper Inventory Management - Code Examples

## Version Management

### Secure
```python
SUPPORTED_VERSIONS = ['v3']

@app.before_request
def enforce_version():
    version = request.path.split('/')[2]  # /api/v3/...
    if version not in SUPPORTED_VERSIONS:
        return jsonify({'error': f'Version {version} not supported. Use v3'}), 410
```

## Remove Debug Endpoints

```python
# development.py
@app.route('/_debug')
def debug():
    return jsonify(app.config)

# production.py
# /_debug route NOT included
```

## API Documentation

```python
# Document all endpoints
@app.route('/api/v3/docs')
def api_docs():
    return jsonify({
        'version': 'v3',
        'endpoints': [
            {'path': '/users', 'methods': ['GET', 'POST']},
            {'path': '/users/<id>', 'methods': ['GET', 'PUT', 'DELETE']}
        ]
    })
```
