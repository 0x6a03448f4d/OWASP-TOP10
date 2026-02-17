# Software Supply Chain Failures Lab

## Overview

This lab demonstrates Software Supply Chain Failures vulnerabilities in a safe, isolated environment.

## Setup

### Using Docker Compose (Recommended)

```bash
docker-compose up --build
```

The application will be available at `http://localhost:5030`

### Manual Setup

```bash
cd app
pip install -r requirements.txt
python server.py
```

## Lab Objectives

1. Understand how Software Supply Chain Failures vulnerabilities work
2. Identify the vulnerable code patterns
3. Exploit the vulnerability safely
4. Learn how to prevent these issues

## Important Notice

⚠️ **EDUCATIONAL PURPOSE ONLY**

This application is intentionally vulnerable. Never use this code or patterns in production applications.

## Documentation

For detailed information, see:
- [Overview](../overview.md)
- [Attack Vectors](../attack-vectors.md)
- [Prevention](../prevention.md)
- [Code Examples](../examples.md)

## Port

This lab runs on port **5030**
