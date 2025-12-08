# Cryptographic Failures Lab: Weak Hashing

## Overview

This lab demonstrates the critical difference between weak hashing algorithms (MD5, SHA-256) and secure password hashing algorithms (bcrypt, Argon2) through an interactive comparison interface.

## Vulnerability Demonstrated

**Weak Password Hashing**: The application demonstrates why fast cryptographic hash functions (MD5, SHA-256) are unsuitable for password storage, while showing the proper use of bcrypt for secure password hashing.

This is a critical vulnerability because:
- 🔴 **Fast hashing enables brute force** - Modern GPUs can compute billions of hashes per second
- 🔴 **No salt makes rainbow tables effective** - Precomputed hash lookups
- 🔴 **Password databases become vulnerable** - Stolen hashes can be cracked quickly

## Learning Objectives

By completing this lab, you will:

1. ✅ Understand why MD5 and SHA-256 are insecure for passwords
2. ✅ Learn the importance of slow, salted password hashing
3. ✅ See the performance difference between fast and slow hashing
4. ✅ Understand rainbow table attacks conceptually
5. ✅ Learn to implement bcrypt correctly

## Prerequisites

- Docker and Docker Compose installed
- Basic understanding of hashing concepts
- Familiarity with password security (helpful but not required)

## Quick Start

### 1. Start the Lab

```bash
docker-compose up
```

The application will be available at: **http://localhost:5001**

### 2. Explore the Interface

- Compare MD5, SHA-256, and bcrypt hashing
- Observe the time differences
- See why bcrypt is secure

### 3. Stop the Lab

```bash
docker-compose down
```

## Lab Structure

```
weak-hashing-lab/
├── docker-compose.yml          # Docker configuration (port 5001)
├── app/
│   ├── server.py              # Flask application with hash comparison
│   ├── requirements.txt       # Python dependencies
│   ├── Dockerfile             # Container configuration
│   └── templates/
│       └── index.html         # Interactive comparison interface
├── README.md                  # This file
└── instructions.md           # Step-by-step lab guide
```

## What You'll Discover

### The Differences

1. **MD5 (INSECURE)**:
   - Extremely fast (< 1ms)
   - No built-in salt
   - Vulnerable to rainbow tables
   - Can be cracked in seconds

2. **SHA-256 (WEAK FOR PASSWORDS)**:
   - Still too fast (< 1ms)
   - No built-in salt
   - Better than MD5 but still vulnerable
   - Not designed for password storage

3. **bcrypt (SECURE)**:
   - Intentionally slow (50-100ms+)
   - Automatic salt generation
   - Adjustable work factor
   - Industry standard for passwords

### How It Works (Conceptual)

```python
# WEAK: MD5 hashing
import hashlib
hash = hashlib.md5(password.encode()).hexdigest()
# Problem: Too fast, no salt

# SECURE: bcrypt hashing
import bcrypt
salt = bcrypt.gensalt(rounds=12)
hash = bcrypt.hashpw(password.encode(), salt)
# Solution: Slow, automatic salt
```

## Safety Features

This lab is completely safe for educational use:

- ✅ Runs in isolated Docker container
- ✅ No real password database
- ✅ Demonstrates concepts without real attacks
- ✅ Local-only (no external network access)
- ✅ Educational comments throughout code
- ✅ Cannot harm your system

## Common Issues

### Port Already in Use

If port 5001 is already in use:

```bash
# Find what's using it
lsof -i :5001

# Stop the conflicting service or change port in docker-compose.yml
```

### Docker Not Running

```bash
# Start Docker Desktop or:
sudo systemctl start docker  # Linux
```

## Key Concepts Demonstrated

### 1. Speed vs Security

- **Fast hashing** (MD5/SHA-256): Good for data integrity, BAD for passwords
- **Slow hashing** (bcrypt/Argon2): BAD for data integrity, GOOD for passwords

### 2. Salting

- **Without salt**: Same password = same hash (vulnerable to rainbow tables)
- **With salt**: Same password = different hash (rainbow tables useless)

### 3. Work Factor

- **bcrypt rounds**: Adjustable computational cost
- **Higher rounds** = More secure but slower
- **Recommended**: 12-14 rounds for production

## Next Steps

1. Read the **[instructions.md](./instructions.md)** for guided tasks
2. Experiment with different passwords
3. Observe the time differences
4. Understand why speed matters for security

## Related Documentation

- **[Overview](../../overview.md)**: Understand cryptographic failures
- **[Attack Vectors](../../attack-vectors.md)**: How attacks happen
- **[Prevention](../../prevention.md)**: Best practices
- **[Examples](../../examples.md)**: More code examples

## Educational Use Only

⚠️ **IMPORTANT**: This lab is for learning defensive security practices. The concepts demonstrated should NEVER be used to attack real systems without explicit authorization.

---

*Part of the [OWASP Top 10 Educational Repository](../../../../../README.md)*
