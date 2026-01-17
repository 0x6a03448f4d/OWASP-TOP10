# API03: Mass Assignment Lab

## 🎯 Learning Objectives

By completing this lab, you will:
- Understand excessive data exposure vulnerabilities in APIs
- Learn how to exploit mass assignment flaws
- Practice privilege escalation through property manipulation
- Implement proper DTOs and field filtering
- Apply secure serialization patterns
- Test property-level authorization controls

## 📋 Lab Overview

This lab contains a vulnerable Flask API for a user profile management system. The API has two critical vulnerabilities:

1. **Excessive Data Exposure**: GET endpoints return sensitive fields like password hashes, admin flags, and salary information
2. **Mass Assignment**: PUT endpoints accept any field from user input, allowing privilege escalation and data manipulation

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Basic understanding of REST APIs
- Familiarity with HTTP requests (curl, Postman, or similar)

### Starting the Lab

```bash
# Navigate to lab directory
cd docs-api/API03-Broken-Object-Property-Level-Authorization/lab/api03-mass-assignment-lab/

# Start the application
docker-compose up -d

# The API will be available at http://localhost:5003
```

### Stopping the Lab

```bash
docker-compose down
```

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────┐
│         Flask API (Port 5003)           │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │  Vulnerable Endpoints:            │ │
│  │  • GET  /api/users/<id>           │ │
│  │  • GET  /api/users/me             │ │
│  │  • PUT  /api/users/<id>           │ │
│  │  • POST /api/register             │ │
│  │  • POST /api/login                │ │
│  └───────────────────────────────────┘ │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │  In-Memory Database               │ │
│  │  • Pre-seeded users               │ │
│  │  • Regular users + Admin          │ │
│  └───────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

## 👥 Pre-configured Accounts

The lab includes three pre-configured user accounts:

| Username | Password | Role | Salary |
|----------|----------|------|---------|
| `alice` | `password123` | Regular User | $65,000 |
| `bob` | `password456` | Regular User | $70,000 |
| `admin` | `admin123` | Administrator | $150,000 |

## 📚 Lab Instructions

Complete instructions are in [instructions.md](./instructions.md), which includes:

### Part 1: Exploitation
- **Exercise 1**: Discover excessive data exposure
- **Exercise 2**: Enumerate all user data including sensitive fields
- **Exercise 3**: Escalate privileges via mass assignment
- **Exercise 4**: Manipulate salary and other restricted fields

### Part 2: Remediation
- **Exercise 5**: Implement proper DTOs with Marshmallow
- **Exercise 6**: Add field-level authorization
- **Exercise 7**: Separate read and write schemas
- **Exercise 8**: Test fixes and verify security

## 🎓 Learning Path

```
1. Understand the vulnerable code
   ↓
2. Exploit excessive data exposure
   ↓
3. Achieve privilege escalation via mass assignment
   ↓
4. Understand the impact
   ↓
5. Implement secure patterns
   ↓
6. Test your fixes
   ↓
7. Learn best practices
```

## 🔍 What You'll Learn

### Vulnerability Discovery
- How to identify sensitive field exposure
- Techniques for discovering hidden fields
- Methods for testing mass assignment flaws
- Tools for API security testing

### Exploitation Techniques
- Harvesting sensitive data from API responses
- Privilege escalation through property manipulation
- Financial fraud via field modification
- Workflow bypass through status manipulation

### Secure Implementation
- Data Transfer Objects (DTOs) with Marshmallow
- Field-level access control
- Role-based serialization
- Input validation and sanitization
- Read-only field enforcement

## 🛠️ Tools You'll Use

- **curl**: Command-line HTTP client
- **Postman** (optional): GUI for API testing
- **jq**: JSON processor for parsing responses
- **Python**: For implementing fixes

## 📖 Key Concepts

### Excessive Data Exposure
When APIs return more data than necessary, exposing sensitive fields that should be hidden.

**Example**: User profile API returning password hash, admin status, and salary to all authenticated users.

### Mass Assignment
When APIs accept all properties from user input without validation, allowing modification of restricted fields.

**Example**: Profile update endpoint accepting `is_admin` field, allowing users to escalate privileges.

### Data Transfer Objects (DTOs)
Dedicated classes that define exactly which fields can be exposed or accepted.

**Example**: Separate `UserPublicSchema`, `UserPrivateSchema`, and `UserAdminSchema` for different access levels.

## ⚠️ Important Notes

1. **This is a vulnerable application by design** - Do not deploy to production!
2. **Use only in isolated lab environment** - Do not test on real systems
3. **Educational purposes only** - Practice responsible disclosure
4. **All data is in-memory** - Restarting the container resets all data

## 🎯 Success Criteria

You've successfully completed the lab when you can:

✅ Identify sensitive fields exposed in API responses  
✅ Exploit mass assignment to gain admin privileges  
✅ Implement DTOs to prevent excessive data exposure  
✅ Add proper field-level authorization  
✅ Verify that fixes prevent both vulnerabilities  
✅ Explain the security impact to others  

## 📝 Lab Challenges

### Challenge 1: Basic Exploitation (Easy)
Gain admin access by exploiting mass assignment

### Challenge 2: Data Harvesting (Medium)
Extract salary information for all users in the system

### Challenge 3: Financial Fraud (Medium)
Give yourself a $500,000 salary through mass assignment

### Challenge 4: Complete Remediation (Hard)
Fix all vulnerabilities and verify with automated tests

## 🔗 Additional Resources

- [Overview](../../overview.md) - Understanding API03 vulnerabilities
- [Attack Vectors](../../attack-vectors.md) - Common exploitation techniques
- [Prevention](../../prevention.md) - Best practices for secure APIs
- [Examples](../../examples.md) - Code examples of vulnerable vs secure patterns

## 💡 Tips

- Start by reading the vulnerable source code in `app/server.py`
- Use browser DevTools or Burp Suite to inspect API responses
- Try sending unexpected fields in your requests
- Compare responses for different user roles
- Test both GET (excessive exposure) and PUT (mass assignment) endpoints

## 🆘 Getting Help

If you're stuck:
1. Review the hints in [instructions.md](./instructions.md)
2. Check the [examples](../../examples.md) for secure patterns
3. Read the [prevention guide](../../prevention.md) for implementation details
4. Examine the vulnerable code to understand the flaws

## 🎉 Next Steps

After completing this lab:
- Try the other OWASP API Security labs
- Practice on deliberately vulnerable apps like DVWA or WebGoat
- Read the OWASP API Security Top 10 documentation
- Apply these concepts to securing your own APIs

---

**Ready to start?** Open [instructions.md](./instructions.md) and begin Part 1!

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../../README.md)*
