# API09: Improper Inventory Management Lab

## Overview
Demonstrates risks of undocumented APIs, old versions, and shadow endpoints.

## Issues Demonstrated
- Multiple API versions (v1, v2, v3) with different security
- Undocumented admin endpoints
- Debug endpoints left in production
- No centralized API inventory

## Quick Start
```bash
docker-compose up -d
```
Access: http://localhost:5009

## Learning Objectives
1. Discover undocumented endpoints
2. Exploit old API versions
3. Create API inventory
4. Implement version lifecycle management
5. Apply consistent security across versions
