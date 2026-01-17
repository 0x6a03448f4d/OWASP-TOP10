# API10: Unsafe Consumption of APIs Lab

## Overview
Demonstrates risks of blindly trusting third-party API data without validation.

## Vulnerabilities Demonstrated
- XSS via unsanitized third-party HTML
- SQL injection risk from external data
- Payment response manipulation
- Lack of data validation

## Quick Start
```bash
docker-compose up -d
```
Access: http://localhost:5010

## Learning Objectives
1. Understand third-party data risks
2. Identify injection vulnerabilities
3. Implement input validation
4. Sanitize external data
5. Verify API responses with signatures
