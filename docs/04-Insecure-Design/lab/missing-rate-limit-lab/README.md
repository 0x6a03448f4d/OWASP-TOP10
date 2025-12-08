# Insecure Design Lab: Missing Rate Limit Lab

## Overview

This lab demonstrates **Insecure Design** through a safe, educational environment.

## Vulnerability Demonstrated

**Missing rate limiting on login attempts**

## Learning Objectives

1. ✅ Understand insecure design vulnerabilities
2. ✅ Learn to identify security flaws
3. ✅ Practice secure coding patterns
4. ✅ Understand the security impact

## Quick Start

### 1. Start the Lab

```bash
docker-compose up
```

The application will be available at: **http://localhost:5001**

### 2. Stop the Lab

```bash
docker-compose down
```

## Lab Structure

```
missing-rate-limit-lab/
├── docker-compose.yml
├── app/
│   ├── server.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── templates/
├── README.md
└── instructions.md
```

## Safety Features

This lab is completely safe for educational use:

- ✅ Runs in isolated Docker container
- ✅ No real sensitive data
- ✅ Local-only (no external network access)
- ✅ Educational comments throughout code
- ✅ Cannot harm your system

## Related Documentation

- **[Overview](../../overview.md)**: Understand insecure design
- **[Attack Vectors](../../attack-vectors.md)**: How attacks happen
- **[Prevention](../../prevention.md)**: Best practices
- **[Examples](../../examples.md)**: More code examples

## Educational Use Only

⚠️ **IMPORTANT**: This lab is for learning defensive security practices only.

---

*Part of the [OWASP Top 10 Educational Repository](../../../../../README.md)*
