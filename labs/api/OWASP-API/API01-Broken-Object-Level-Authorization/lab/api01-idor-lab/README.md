# API01 BOLA Lab: IDOR Order Access Vulnerability

## Overview

This lab demonstrates a **Broken Object Level Authorization (BOLA)** vulnerability, also known as **IDOR (Insecure Direct Object Reference)**, in a REST API. The application allows authenticated users to access orders, but fails to verify that the requested order belongs to the authenticated user.

## Vulnerability Demonstrated

**Insecure Direct Object Reference (IDOR)**: The API accepts an order ID parameter and returns the order data without verifying the authenticated user owns that order.

This is a critical API vulnerability because:
- 🔴 **BOLA is the #1 API Security Risk** (OWASP API Security Top 10)
- 🔴 **Direct data exposure** - Users can access other users' private data
- 🔴 **Easy to exploit** - Simply change ID in URL
- 🔴 **Often overlooked** - Developers assume authentication is enough

## Learning Objectives

By completing this lab, you will:

1. ✅ Understand how BOLA/IDOR vulnerabilities work in APIs
2. ✅ Learn why authentication alone is not sufficient
3. ✅ Discover how to test for BOLA vulnerabilities
4. ✅ Practice implementing proper object-level authorization
5. ✅ Understand JWT-based authentication vs authorization
6. ✅ Learn API security best practices

## Prerequisites

- Docker and Docker Compose installed
- Basic understanding of REST APIs
- Familiarity with HTTP requests (curl, browser DevTools, or Postman)
- Basic Python/Flask knowledge (helpful but not required)

## Quick Start

### 1. Start the Lab

```bash
docker-compose up
```

The API will be available at: **http://localhost:5000**

### 2. Test Accounts

- **User 1 (Alice)**: Username: `alice`, Password: `password123`
  - Orders: #101, #102
- **User 2 (Bob)**: Username: `bob`, Password: `password123`
  - Orders: #201, #202
- **User 3 (Charlie)**: Username: `charlie`, Password: `password123`
  - Orders: #301, #302

### 3. Stop the Lab

```bash
docker-compose down
```

## Lab Structure

```
api01-idor-lab/
├── docker-compose.yml          # Docker configuration
├── app/
│   ├── server.py              # Flask API application (VULNERABLE)
│   ├── requirements.txt       # Python dependencies
│   └── templates/
│       └── index.html         # Simple API testing interface
├── README.md                  # This file
└── instructions.md           # Step-by-step lab guide
```

## API Endpoints

### Authentication
- `POST /api/login` - Login and receive JWT token
  - Body: `{"username": "alice", "password": "password123"}`
  - Returns: `{"access_token": "eyJ..."}`

### Orders (Authenticated)
- `GET /api/orders/<order_id>` - Get order details ⚠️ VULNERABLE
  - Headers: `Authorization: Bearer <token>`
  - Returns: Order information

- `GET /api/orders` - Get current user's orders
  - Headers: `Authorization: Bearer <token>`
  - Returns: List of user's orders

### User Info
- `GET /api/me` - Get current user info
  - Headers: `Authorization: Bearer <token>`
  - Returns: User information

## What You'll Discover

### The Vulnerability

The application has a critical BOLA flaw:

1. **Authentication Present**: Users must log in with JWT tokens
2. **Authorization Missing**: No check that order belongs to the authenticated user
3. **Predictable IDs**: Sequential order IDs (101, 102, 201, 202...)
4. **Data Exposure**: Users can access other users' orders by changing the ID

### How It Works (Conceptual)

```python
# VULNERABLE CODE (simplified):
@app.route('/api/orders/<order_id>')
@jwt_required()
def get_order(order_id):
    # User IS authenticated (has valid token)
    # But no check that this order belongs to them!
    order = orders_db.get(order_id)
    return jsonify(order)

# An attacker can:
# 1. Login as Alice (get token)
# 2. Access /api/orders/101 (their own order) ✓
# 3. Access /api/orders/201 (Bob's order!) ✓ VULNERABILITY!
```

### Attack Scenario

1. **Alice** logs in and sees her order #101
2. **Alice** tries accessing order #102 → Works (her order)
3. **Alice** tries accessing order #201 → Works! (Bob's order)
4. **Alice** can now see:
   - Bob's order details
   - Bob's shipping address
   - Bob's purchase history
   - Total amount spent

## Safety Features

This lab is completely safe for educational use:

- ✅ Runs in isolated Docker container
- ✅ Uses demo data only (no real customer information)
- ✅ Local-only (no external network access)
- ✅ In-memory database (no persistence)
- ✅ Educational comments throughout code
- ✅ Cannot harm your system

## Testing the API

### Using the Web Interface

1. Open http://localhost:5000 in your browser
2. Use the built-in interface to:
   - Login as different users
   - View orders
   - Test different order IDs
   - See JWT tokens

### Using curl

```bash
# Login as Alice
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'

# Save the token from response
TOKEN="<your-token-here>"

# Get Alice's order (legitimate)
curl http://localhost:5000/api/orders/101 \
  -H "Authorization: Bearer $TOKEN"

# Try accessing Bob's order (IDOR vulnerability!)
curl http://localhost:5000/api/orders/201 \
  -H "Authorization: Bearer $TOKEN"
```

### Using Browser DevTools

1. Open DevTools (F12)
2. Go to Console tab
3. The interface logs all API requests
4. Inspect request/response data

## Common Issues

### Port Already in Use

If port 5000 is already in use:

```bash
# Option 1: Stop the conflicting service
lsof -i :5000
kill <PID>

# Option 2: Edit docker-compose.yml to use different port
# Change "5000:5000" to "5001:5000"
```

### Docker Not Running

```bash
# Start Docker Desktop or:
sudo systemctl start docker  # Linux
```

### JWT Token Expired

JWT tokens expire after 1 hour. Simply login again to get a fresh token.

## Next Steps

1. Read the **[instructions.md](./instructions.md)** for guided exercises
2. Explore the BOLA vulnerability yourself
3. Try to fix the vulnerable code
4. Test your fix thoroughly with multiple users

## Related Documentation

- **[Overview](../../overview.md)**: Understand BOLA fundamentals
- **[Attack Vectors](../../attack-vectors.md)**: How BOLA attacks happen
- **[Prevention](../../prevention.md)**: Best practices for prevention
- **[Examples](../../examples.md)**: More API code examples

## Educational Use Only

⚠️ **IMPORTANT**: This lab demonstrates vulnerabilities for educational purposes only. The techniques learned should NEVER be used against real systems without explicit authorization. Unauthorized access to computer systems is illegal.

## OWASP API Security Top 10 Context

This vulnerability is **API1:2023 - Broken Object Level Authorization**:

> "APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues. Object level authorization checks should be considered in every function that accesses a data source using an ID from the user."

## Support

If you encounter issues:
1. Check the [Common Issues](#common-issues) section
2. Review Docker logs: `docker-compose logs`
3. Verify Docker is running: `docker ps`
4. Check if port 5000 is available: `lsof -i :5000`

## Learning Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [API Security Best Practices](https://owasp.org/www-project-api-security/)
- [JWT Authentication](https://jwt.io/introduction)
- [REST API Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../../../README.md)*
