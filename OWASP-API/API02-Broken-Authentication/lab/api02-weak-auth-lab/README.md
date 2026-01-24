# API02 Broken Authentication Lab: Weak Authentication Implementation

## Overview

This lab demonstrates **Broken Authentication** vulnerabilities in a REST API. The application has multiple critical authentication flaws that allow attackers to bypass security, crack tokens, and gain unauthorized access.

## Vulnerabilities Demonstrated

This lab showcases four critical authentication vulnerabilities:

1. **🔴 No Rate Limiting** - Unlimited login attempts enable brute force attacks
2. **🔴 Weak JWT Secret** - Using "secret123" allows token forgery
3. **🔴 No Token Expiration** - Tokens are valid forever
4. **🔴 Weak Password Policy** - Any password is accepted

This is critical because:
- 🔴 **OWASP API Security #2** - Broken Authentication
- 🔴 **Easy to Exploit** - Automated tools readily available
- 🔴 **Account Takeover** - Complete compromise possible
- 🔴 **Token Forgery** - Weak secret allows impersonation

## Learning Objectives

By completing this lab, you will:

1. ✅ Understand how weak authentication enables attacks
2. ✅ Learn why rate limiting is critical
3. ✅ Discover JWT security vulnerabilities
4. ✅ Practice implementing strong authentication
5. ✅ Understand password policy importance
6. ✅ Learn token management best practices

## Prerequisites

- Docker and Docker Compose installed
- Basic understanding of REST APIs and JWT
- Familiarity with HTTP requests (curl, Postman, or browser DevTools)
- Basic Python/Flask knowledge (helpful but not required)

## Quick Start

### 1. Start the Lab

```bash
docker-compose up
```

The API will be available at: **http://localhost:5000**

### 2. Test Accounts

- **Alice**: alice@example.com / password123
- **Bob**: bob@example.com / admin (very weak!)
- **Admin**: admin@example.com / admin123

### 3. Stop the Lab

```bash
docker-compose down
```

## Lab Structure

```
api02-weak-auth-lab/
├── docker-compose.yml          # Docker configuration
├── Dockerfile                  # Container definition
├── app/
│   ├── server.py              # Flask API application (VULNERABLE)
│   ├── requirements.txt       # Python dependencies
│   └── templates/
│       └── index.html         # API testing interface
├── README.md                  # This file
└── instructions.md           # Step-by-step lab guide
```

## API Endpoints

### Authentication
- `POST /api/register` - Register new user (no password validation!) ⚠️
  - Body: `{"username": "user", "email": "user@example.com", "password": "123"}`
  
- `POST /api/login` - Login and receive JWT token ⚠️ VULNERABLE
  - Body: `{"email": "user@example.com", "password": "password"}`
  - Returns: `{"access_token": "eyJ..."}`

### Protected Endpoints
- `GET /api/me` - Get current user info
  - Headers: `Authorization: Bearer <token>`
  
- `GET /api/sensitive-data` - Get sensitive user data
  - Headers: `Authorization: Bearer <token>`

- `GET /api/admin/users` - Admin endpoint (can be forged!)
  - Headers: `Authorization: Bearer <token>`
  - Requires: `role=admin` in JWT

## Vulnerabilities Explained

### Vulnerability 1: No Rate Limiting

```python
@app.route('/api/login', methods=['POST'])
def login():
    # NO RATE LIMITING!
    # Attacker can try unlimited passwords
    # Enables brute force and credential stuffing
    pass
```

**Impact**: Attacker can try millions of passwords with no delay.

### Vulnerability 2: Weak JWT Secret

```python
JWT_SECRET = 'secret123'  # WEAK SECRET!

token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
```

**Impact**: Secret can be cracked in seconds, allowing complete token forgery.

### Vulnerability 3: No Token Expiration

```python
token = jwt.encode(
    {'user_id': user.id},  # No 'exp' claim!
    JWT_SECRET,
    algorithm='HS256'
)
```

**Impact**: Stolen tokens are valid forever, no forced re-authentication.

### Vulnerability 4: Weak Password Policy

```python
def register():
    password = request.json.get('password')
    # NO VALIDATION!
    # Accepts: "123", "password", "admin"
    user.set_password(password)
```

**Impact**: Users can create accounts with easily guessable passwords.

## Attack Scenarios

### Scenario 1: Brute Force Attack

Due to no rate limiting, attacker can try unlimited passwords:

```bash
# Try common passwords
for pwd in password admin 123456 letmein; do
  curl -X POST http://localhost:5000/api/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"alice@example.com\",\"password\":\"$pwd\"}"
done
```

### Scenario 2: JWT Secret Cracking

With weak secret "secret123", attacker can:

1. Obtain valid JWT token
2. Use hashcat to crack secret (takes seconds)
3. Forge new tokens with any claims
4. Escalate privileges to admin

### Scenario 3: Weak Password Registration

```bash
# Register with 3-character password
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hacker",
    "email": "hacker@example.com",
    "password": "123"
  }'
# SUCCESS - No password validation!
```

## Safety Features

This lab is completely safe for educational use:

- ✅ Runs in isolated Docker container
- ✅ Uses demo data only (no real accounts)
- ✅ Local-only (no external network access)
- ✅ In-memory database (no persistence)
- ✅ Educational comments throughout code
- ✅ Cannot harm your system

## Testing the API

### Using the Web Interface

1. Open http://localhost:5000 in your browser
2. Use the built-in interface to:
   - Login as different users
   - Register new users with weak passwords
   - View JWT tokens
   - Test authentication

### Using curl

```bash
# Login
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"password123"}'

# Save the token
TOKEN="<your-token-here>"

# Get user info
curl http://localhost:5000/api/me \
  -H "Authorization: Bearer $TOKEN"

# Try admin endpoint (will fail unless admin)
curl http://localhost:5000/api/admin/users \
  -H "Authorization: Bearer $TOKEN"
```

## Common Issues

### Port Already in Use

If port 5000 is already in use:

```bash
# Find and kill the process
lsof -i :5000
kill <PID>

# Or edit docker-compose.yml to use different port
# Change "5000:5000" to "5001:5000"
```

### Docker Not Running

```bash
# Start Docker Desktop or:
sudo systemctl start docker  # Linux
```

## Next Steps

1. Read the **[instructions.md](./instructions.md)** for guided exercises
2. Explore the vulnerabilities yourself
3. Try to fix the vulnerable code
4. Test your fixes thoroughly

## Related Documentation

- **[Overview](../../overview.md)**: Understand authentication fundamentals
- **[Attack Vectors](../../attack-vectors.md)**: How authentication attacks happen
- **[Prevention](../../prevention.md)**: Best practices for secure authentication
- **[Examples](../../examples.md)**: More API code examples

## Educational Use Only

⚠️ **IMPORTANT**: This lab demonstrates vulnerabilities for educational purposes only. The techniques learned should NEVER be used against real systems without explicit authorization. Unauthorized access to computer systems is illegal.

## OWASP API Security Top 10 Context

This vulnerability is **API2:2023 - Broken Authentication**:

> "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or to exploit implementation flaws to assume other users' identities temporarily or permanently."

## Support

If you encounter issues:
1. Check the [Common Issues](#common-issues) section
2. Review Docker logs: `docker-compose logs`
3. Verify Docker is running: `docker ps`
4. Check if port 5000 is available: `lsof -i :5000`

## Learning Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [JWT.io - JWT Introduction](https://jwt.io/introduction)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Have I Been Pwned](https://haveibeenpwned.com/) - Password breach checking

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../../../README.md)*
