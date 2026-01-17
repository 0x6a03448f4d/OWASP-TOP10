# API09: Improper Inventory Management - Overview

## What is Improper Inventory Management?

**Improper Inventory Management** occurs when organizations don't maintain accurate documentation of their APIs, leading to undocumented endpoints, old API versions, exposed debug endpoints, and shadow APIs that bypass security controls.

### Core Concept

```
Proper Inventory:
✓ All APIs documented
✓ Old versions decommissioned
✓ Debug endpoints removed
✓ Access controls on all endpoints
✓ Regular audits

Improper Inventory:
✗ Undocumented /admin endpoints
✗ v1, v2, v3 all running (v1 vulnerable)
✗ /debug, /_internal still accessible
✗ Shadow APIs (mobile, partners)
✗ No central registry
```

## Why Does This Matter?

### Business Impact
- **Data Breaches**: Old APIs with vulnerabilities still accessible
- **Unauthorized Access**: Undocumented admin endpoints found by attackers
- **Compliance Violations**: Can't secure what you don't know exists
- **Security Bypasses**: New security on v3, old v1 still vulnerable

### Technical Impact
- **Old API Versions**: Legacy /api/v1 lacks authentication
- **Debug Endpoints**: /_debug, /metrics, /_internal exposed
- **Undocumented APIs**: /admin, /internal, /test accessible
- **Shadow APIs**: Mobile app API bypasses web API security
- **Deprecated Endpoints**: Still functional, missing patches

## Common Scenarios

### 1. Multiple API Versions

```
/api/v1/users  - No authentication (VULNERABLE)
/api/v2/users  - Basic auth
/api/v3/users  - OAuth + rate limiting (SECURE)

Problem: v1 still accessible, attackers use it
```

### 2. Debug Endpoints in Production

```
/_debug
/_internal/metrics
/api/health (exposes versions, configs)
/docs (Swagger UI in production)
```

### 3. Undocumented Admin Endpoints

```
/api/admin/users  - Not in docs, no auth
/internal/backup  - Forgotten during migration
/test/reset-db    - Left from development
```

### 4. Shadow APIs

```
Web API:    /api/v2/... (secure)
Mobile API: /mobile-api/... (less secure, bypasses rate limits)
Partner API: /partner/... (different auth, not monitored)
```

## Real-World Impact

**T-Mobile (2021)**: Exposed API endpoint leaked 40M customer records - endpoint wasn't in official inventory

**Peloton (2021)**: Undocumented API endpoints exposed user data - found via fuzzing

**LinkedIn (2021)**: Old API version scraped 700M profiles - v1 API should have been shut down

## Prevalence

- 72% of organizations can't list all their APIs
- 48% have multiple versions running simultaneously
- 35% have undocumented endpoints in production
- 29% have debug/test endpoints accessible
- 61% discovered APIs they didn't know existed

## Prevention

1. **API Inventory**: Maintain complete catalog of all APIs
2. **Version Management**: Sunset old versions, document lifecycle
3. **Endpoint Discovery**: Regular scanning for undocumented endpoints
4. **Environment Separation**: No debug in production
5. **Access Control**: Same security on all versions/endpoints
6. **Regular Audits**: Quarterly inventory reviews
7. **API Gateway**: Central point for all API traffic

## Next Steps
- [Attack Vectors](attack-vectors.md)
- [Prevention](prevention.md)
- [Examples](examples.md)
- [Lab](lab/api09-inventory-lab/)
