# Logging Examples (2025)

**❌ INADEQUATE:**

```python
@app.route('/api/delete-user', methods=['POST'])
def delete_user():
    user_id = request.json['user_id']
    delete_from_db(user_id)
    print(f"Deleted user {user_id}")  # Just print!
    return "OK"
```

**✅ COMPREHENSIVE:**

```python
import structlog

logger = structlog.get_logger()

@app.route('/api/delete-user', methods=['POST'])
def delete_user():
    user_id = request.json['user_id']
    
    logger.info(
        "user_deletion_initiated",
        target_user_id=user_id,
        admin_user_id=current_user.id,
        ip_address=request.remote_addr,
        correlation_id=get_correlation_id(),
        timestamp=datetime.now().isoformat(),
        action="DELETE",
        resource="user",
        result="pending"
    )
    
    try:
        delete_from_db(user_id)
        
        logger.info(
            "user_deletion_completed",
            target_user_id=user_id,
            admin_user_id=current_user.id,
            result="success"
        )
    except Exception as e:
        logger.error(
            "user_deletion_failed",
            target_user_id=user_id,
            error=str(e),
            result="failure"
        )
        raise
    
    return "OK"
```
