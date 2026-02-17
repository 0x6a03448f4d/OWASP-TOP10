# M01: Improper Credential Usage - Lab

## Overview

This lab demonstrates common credential exposure vulnerabilities in mobile applications, including:
- Hardcoded API keys
- Plain text credential storage
- Credential leakage through logs
- Insecure configuration files

**Time Required**: 30-45 minutes  
**Difficulty**: Beginner

## Learning Objectives

By completing this lab, you will:
1. Understand how credentials are exposed in mobile applications
2. Learn to identify hardcoded secrets in code
3. Discover how storage mechanisms can leak credentials
4. Implement secure credential management practices

## Lab Setup

### Prerequisites
- Docker and Docker Compose installed
- Basic understanding of mobile development concepts
- A code editor

### Starting the Lab

```bash
cd OWASP-Mobile/M01-Improper-Credential-Usage/lab/m01-credential-exposure-lab/
docker-compose up
```

The application will be available at: `http://localhost:5100`

## What You'll Find

This lab includes:
- A simulated mobile API backend
- Example mobile app code (Python simulation)
- Configuration files with vulnerabilities
- Logging mechanisms that expose credentials

## Next Steps

Once the lab is running, follow the step-by-step instructions in [instructions.md](./instructions.md) to:
1. Explore the vulnerable implementation
2. Identify credential exposure points
3. Understand the security risks
4. Implement secure alternatives

## Stopping the Lab

```bash
docker-compose down
```

---

*Part of OWASP Mobile Top 10 - Educational Repository*
