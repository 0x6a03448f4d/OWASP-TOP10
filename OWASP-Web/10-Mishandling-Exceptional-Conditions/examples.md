# Exception Handling Examples

**❌ DANGEROUS:**

```python
@app.route('/api/user/<user_id>')
def get_user(user_id):
    try:
        user = database.get_user(user_id)
        return jsonify(user)
    except Exception as e:
        # DANGEROUS: Exposes internals
        return str(e), 500
```

**✅ SECURE:**

```python
@app.route('/api/user/<user_id>')
def get_user(user_id):
    try:
        # Validate input
        if not user_id.isdigit():
            return jsonify({'error': 'Invalid user ID'}), 400
        
        user = database.get_user(int(user_id))
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user)
        
    except DatabaseConnectionError as e:
        logger.error(f"Database error: {e}", exc_info=True)
        return jsonify({'error': 'Service temporarily unavailable'}), 503
        
    except Exception as e:
        logger.error(f"Unexpected error in get_user: {e}", exc_info=True)
        # Generic error, no details exposed
        return jsonify({'error': 'Internal server error'}), 500
```
