# API08: Security Misconfiguration Lab

## Overview
Demonstrates common security misconfigurations in production APIs.

## Misconfigurations Demonstrated
- Overly permissive CORS (*)
- Verbose error messages with stack traces
- Debug endpoints in production
- Missing security headers
- Exposed secrets in configuration

## Quick Start
```bash
docker-compose up -d
```
Access: http://localhost:5008

## Learning Objectives
1. Identify security misconfigurations
2. Exploit CORS misconfiguration
3. Extract secrets from debug endpoints
4. Understand impact of missing headers
5. Implement secure configuration
