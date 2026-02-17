# API07: Server Side Request Forgery Lab

## Overview
Demonstrates SSRF vulnerabilities where APIs fetch user-controlled URLs without validation.

## Features
- URL import functionality
- Webhook registration
- Image fetch from URL
- Simulated internal services (metadata, database, admin)

## Quick Start
```bash
docker-compose up -d
```
Access: http://localhost:5007

## Learning Objectives
1. Understand SSRF attack vectors
2. Access internal metadata services
3. Read local file system
4. Implement URL validation
5. Apply whitelisting and network controls
