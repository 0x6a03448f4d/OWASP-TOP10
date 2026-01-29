# Sensitive Data Exposure - Attack Vectors

## Attack Methods

### 1. Man-in-the-Middle (MITM)

Intercepting unencrypted traffic:

```bash
# Using mitmproxy to intercept HTTP traffic
mitmproxy -p 8080

# In another terminal, route traffic through proxy
export http_proxy=http://localhost:8080
curl http://insecure-site.com/login
```

### 2. SSL Strip Attack

Downgrading HTTPS to HTTP:

```python
# Attacker's proxy strips HTTPS
# Victim thinks they're on HTTPS but actually HTTP
# Attacker sees all traffic in clear text
```

### 3. Weak Crypto Detection

Finding weak encryption:

```bash
# Scan for weak SSL/TLS
nmap --script ssl-enum-ciphers -p 443 target.com

# Test for SSLv3
openssl s_client -connect target.com:443 -ssl3
```

### 4. Database Exposure

Finding exposed databases:

```bash
# Search for backup files
gobuster dir -u http://target.com -w wordlist.txt -x .sql,.bak,.db

# Common exposed files
/backup.sql
/database.bak
/data.db
/users.csv
```
