# Logging & Monitoring - Attack Scenarios

## Undetected Attacks

Without proper logging, attackers can:

1. **Brute Force Undetected**
```python
# No logging = attacker tries unlimited passwords
for password in password_list:
    try_login(username, password)
# No one notices thousands of attempts
```

2. **Privilege Escalation Hidden**
```python
# Attacker gains admin access
# No log entry = no investigation trigger
# Attacker maintains access for months
```

3. **Data Exfiltration Silent**
```python
# Attacker downloads sensitive data
# No monitoring = no alerts
# Breach discovered months later
```

## Log Tampering

Attackers may try to cover tracks:
- Delete log files
- Modify log entries
- Disable logging service
- Fill logs with noise
