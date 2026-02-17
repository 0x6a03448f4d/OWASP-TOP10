# M09: Insecure Data Storage - Lab

## Overview

This lab demonstrates insecure data storage vulnerabilities in mobile applications and their backend services, including:
- Unencrypted database storage
- Plain text SharedPreferences/UserDefaults
- Insecure file storage
- Sensitive data in logs
- Unencrypted backups
- Weak encoding mistaken for encryption

**Time Required**: 30-45 minutes  
**Difficulty**: Beginner to Intermediate

## Learning Objectives

By completing this lab, you will:
1. Understand how mobile apps store data insecurely
2. Discover vulnerabilities in local storage mechanisms
3. Learn how attackers extract sensitive data from devices
4. Recognize the difference between encoding and encryption
5. Implement secure data storage practices

## Lab Setup

### Prerequisites
- Docker and Docker Compose installed
- Basic understanding of mobile applications and data storage
- A web browser
- (Optional) Command-line tools for testing

### Starting the Lab

```bash
cd OWASP-Mobile/M09-Insecure-Data-Storage/lab/m09-insecure-data-storage-lab/
docker-compose up
```

The application will be available at: `http://localhost:5109`

## What You'll Find

This lab includes:
- A simulated mobile application backend with Flask
- Multiple insecure data storage demonstrations
- Interactive exercises showing real-world vulnerabilities
- Examples of both vulnerable and secure implementations

### Vulnerabilities Demonstrated

1. **Unencrypted Database**: SQLite database storing passwords, SSNs, and payment data in plain text
2. **Plain Text Preferences**: Simulated SharedPreferences/UserDefaults with sensitive data
3. **Insecure File Storage**: Files written without encryption
4. **Logging Sensitive Data**: Application logs containing credentials and PII
5. **Unencrypted Backups**: Backup files including all sensitive data
6. **Base64 as Encryption**: Common mistake of using encoding instead of encryption
7. **Weak XOR**: Demonstration of inadequate encryption algorithms

## Next Steps

Once the lab is running, follow the step-by-step instructions in [instructions.md](./instructions.md) to:
1. Explore the vulnerable implementations
2. Extract sensitive data like an attacker would
3. Understand the risks and attack scenarios
4. Learn how to fix each vulnerability
5. Implement secure data storage practices

## Stopping the Lab

```bash
docker-compose down
```

## Security Note

⚠️ **IMPORTANT**: This lab intentionally contains severe security vulnerabilities for educational purposes. The patterns demonstrated here should **NEVER** be used in production applications. Always:

- Encrypt sensitive data at rest
- Use platform secure storage (Keychain/KeyStore)
- Never store passwords in plain text
- Encrypt databases with SQLCipher or equivalent
- Exclude sensitive data from backups
- Never log sensitive information
- Use proper encryption (AES-256, not Base64)
- Implement data expiration policies

## Files in This Lab

- `server.py` - Vulnerable Flask backend demonstrating insecure storage
- `templates/index.html` - Interactive web interface
- `Dockerfile` - Container configuration
- `docker-compose.yml` - Service orchestration
- `requirements.txt` - Python dependencies
- `README.md` - This file
- `instructions.md` - Detailed step-by-step instructions

---

*Part of OWASP Mobile Top 10 - Educational Repository*
