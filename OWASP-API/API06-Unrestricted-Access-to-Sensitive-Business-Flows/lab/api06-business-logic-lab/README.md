# API06: Business Logic Abuse Lab

## Overview

This lab demonstrates vulnerabilities in sensitive business flows and teaches how to protect against automated abuse, bot attacks, and business logic exploitation.

## Scenario

You're testing an e-commerce API that sells limited-edition products. The application has:
- Flash sales with limited inventory
- Discount coupon system
- Cart reservation mechanism
- No bot protection

## Lab Environment

- **Vulnerable API**: Flask application with exploitable business flows
- **Web Interface**: Product catalog and checkout UI
- **Attack Scripts**: Tools to demonstrate automation abuse

## Quick Start

```bash
docker-compose up -d
```

Access:
- **Web UI**: http://localhost:5006
- **API Docs**: http://localhost:5006/api/docs

## Learning Objectives

1. Understand business logic vulnerabilities
2. Exploit automated purchasing at scale
3. Abuse coupon stacking
4. Implement bot detection and prevention
5. Apply behavioral analysis

## Exercises

See [instructions.md](instructions.md) for detailed exercises.
