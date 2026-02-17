# Logging Failures in Cloud-Native

## Log Injection Attack

```python
# Attacker injects malicious log entries
username = '"; DROP TABLE logs; --'
logger.info(f"Login attempt: {username}")
# If logs parsed as code = code injection
```

## Container Log Tampering

```bash
# Attacker gains container access
# Modifies logs to hide tracks
docker exec -it container bash
> /var/log/app.log  # Clear logs
```

## Correlation ID Spoofing

```python
# Attacker reuses legitimate correlation ID
# Makes malicious requests appear as part of valid transaction
# Evades detection
```
