# API01: Broken Object Level Authorization - Overview

## Table of Contents
- [What is Broken Object Level Authorization?](#what-is-broken-object-level-authorization)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Broken Object Level Authorization?

**Broken Object Level Authorization (BOLA)**, also known as **Insecure Direct Object Reference (IDOR)**, is the most critical API security vulnerability. It occurs when an API endpoint receives an object identifier (ID) and performs actions on that object without properly validating whether the requesting user has permission to access it.

APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface for access control issues. Authorization checks should verify that the logged-in user has permissions to perform the requested action on the specific object.

### Core Concept

```
User A requests: GET /api/users/123/profile
User B requests: GET /api/users/456/profile

BROKEN BOLA = User A can access /api/users/456/profile (User B's data)
              by simply changing the ID in the request
```

### Why It's #1 for APIs

Unlike traditional web applications where access control is often session-based, APIs:
- Expose object identifiers directly in URLs, JSON payloads, or query parameters
- Are consumed by mobile apps, SPAs, and third-party clients
- Often use predictable IDs (sequential integers, UUIDs)
- Handle multiple objects per request
- Lack the UI layer that might hide unauthorized options

## Why Does This Matter?

### The Business Impact

- **Massive Data Breaches**: Attackers can iterate through IDs to scrape entire databases
- **Privacy Violations**: Unauthorized access to personal information (GDPR, CCPA violations)
- **Financial Fraud**: Access to other users' transactions, payment methods, or wallets
- **Competitive Damage**: Exposure of business-critical data to competitors
- **Regulatory Fines**: Multi-million dollar penalties for data protection failures
- **Trust Erosion**: Permanent damage to brand reputation

### The Technical Impact

- **Horizontal Privilege Escalation**: Users access other users' resources at the same privilege level
- **Vertical Privilege Escalation**: Regular users access admin-level resources
- **Data Enumeration**: Attackers systematically extract entire datasets
- **Business Logic Bypass**: Circumventing intended workflows and restrictions
- **Combined Attacks**: BOLA often enables other vulnerabilities (data exfiltration, account takeover)

## Technical Context

### How BOLA Differs from Traditional Access Control

| Traditional Web Apps | Modern APIs |
|---------------------|-------------|
| Session-based context | Stateless, token-based |
| Server-rendered HTML | JSON/XML responses |
| Limited endpoints | Many granular endpoints |
| UI masks unauthorized options | All endpoints accessible |
| Page-level authorization | Object-level authorization needed |

### Common Vulnerable Patterns

#### Pattern 1: Direct ID in URL
```
GET /api/v1/orders/5827
Authorization: Bearer <token>

Response: 200 OK
{
  "order_id": 5827,
  "user_id": 42,
  "items": [...],
  "total": 299.99
}
```
**Vulnerability**: Anyone with a valid token can change the order ID

#### Pattern 2: ID in Request Body
```
POST /api/v1/documents/share
Authorization: Bearer <token>
{
  "document_id": 9812,
  "share_with": "attacker@example.com"
}
```
**Vulnerability**: Attacker can share any document by changing document_id

#### Pattern 3: Nested Resource Access
```
GET /api/v1/users/123/wallet/transactions
Authorization: Bearer <token>
```
**Vulnerability**: Can access any user's wallet by changing user ID

#### Pattern 4: Batch Operations
```
POST /api/v1/messages/delete
{
  "message_ids": [101, 102, 103, 999, 1000]
}
```
**Vulnerability**: Can delete other users' messages by including their message IDs

### The Authorization Stack

```
┌─────────────────────────────────────┐
│   1. Authentication (Who are you?)  │  ← Token validates identity
├─────────────────────────────────────┤
│   2. Function Authorization         │  ← Can you call this endpoint?
│      (Can you do this action?)      │
├─────────────────────────────────────┤
│   3. Object Authorization (BOLA)    │  ← Can you access THIS object?
│      (Can you access THIS resource?)│  ← MOST COMMONLY FORGOTTEN
└─────────────────────────────────────┘
```

**BOLA vulnerabilities occur at Layer 3** - even with perfect authentication and function-level authorization, object-level checks may be missing.

## Real-World Impact

### Case Study 1: T-Mobile (2021)
**Vulnerability**: BOLA in API allowed access to customer data  
**Impact**: 40+ million customer records exposed  
**Attack Method**: Simple ID enumeration in API endpoints  
**Root Cause**: Missing object-level authorization checks

### Case Study 2: Peloton (2021)
**Vulnerability**: API allowed access to any user's profile data  
**Impact**: Private profiles, workout history, and location data exposed  
**Attack Method**: Changing user ID in API requests  
**Root Cause**: No validation that requesting user owned the data

### Case Study 3: Parler (2021)
**Vulnerability**: Sequential post IDs with no authorization  
**Impact**: Entire platform data (70TB) scraped in days  
**Attack Method**: Iterating through post IDs 1 to N  
**Root Cause**: Publicly accessible endpoints with predictable IDs

### Case Study 4: USPS (2018)
**Vulnerability**: API endpoint exposed user account details  
**Impact**: 60 million user accounts accessible  
**Attack Method**: Changing account parameter in authenticated requests  
**Root Cause**: Authentication present but no authorization validation

## Prevalence and Statistics

### OWASP API Security Top 10 2023 Data

- **#1** most critical API vulnerability
- Found in approximately **95%** of penetration-tested APIs
- **Most exploited** API vulnerability in the wild
- Average time to exploit: **Less than 30 minutes** for skilled attackers
- Detection difficulty: **Easy** (automated tools readily available)

### Attack Characteristics

| Metric | Value |
|--------|-------|
| **Exploitability** | Easy - requires minimal technical skill |
| **Prevalence** | Widespread - found in most APIs |
| **Detectability** | Easy - simple fuzzing reveals issues |
| **Technical Impact** | Severe - complete data exposure |
| **Business Impact** | Severe - breaches, compliance violations |

### Industry Vulnerabilities

Different API types face varying risks:

| API Type | Risk Level | Common Scenarios |
|----------|------------|------------------|
| **Healthcare APIs** | Critical | Patient record access (HIPAA) |
| **Financial APIs** | Critical | Account/transaction access |
| **E-commerce APIs** | High | Order/payment data access |
| **Social Media APIs** | High | Private profile/message access |
| **IoT/Device APIs** | High | Device control, sensor data |
| **SaaS APIs** | High | Multi-tenant data isolation |
| **Internal APIs** | Medium-High | Assume trusted network (risky) |

## Common Misunderstandings

### Myth 1: "Authentication = Authorization"
**Reality**: Having a valid token proves identity, NOT permissions for specific objects.

```python
# NOT ENOUGH:
@app.route('/api/orders/<order_id>')
@require_auth  # Only checks valid token
def get_order(order_id):
    return Order.query.get(order_id)

# CORRECT:
@app.route('/api/orders/<order_id>')
@require_auth
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)
    return order
```

### Myth 2: "UUIDs Prevent BOLA"
**Reality**: UUIDs make enumeration harder but don't prevent BOLA if IDs leak.

```
Sequential IDs: Easy to enumerate (1, 2, 3, ...)
UUIDs: Harder to guess but still vulnerable if:
  - Exposed in responses
  - Leaked through other endpoints
  - Found in logs or error messages
  - Shared in URLs or emails

Authorization checks are STILL required!
```

### Myth 3: "Private APIs Don't Need BOLA Protection"
**Reality**: Internal/private APIs need authorization too.

```
Threats to "private" APIs:
✗ Compromised credentials
✗ Insider threats
✗ Mobile app decompilation
✗ Network sniffing
✗ Supply chain attacks
✗ Future public exposure

Defense in depth: Protect ALL APIs
```

### Myth 4: "Rate Limiting Prevents BOLA"
**Reality**: Rate limiting slows attacks but doesn't prevent unauthorized access.

```
Rate Limiting: Slows enumeration attacks
BOLA Prevention: Stops unauthorized access entirely

Both are needed, but rate limiting ≠ authorization
```

### Myth 5: "Framework Security Features Handle This"
**Reality**: Most frameworks don't automatically enforce object-level authorization.

Frameworks provide:
- ✅ Authentication mechanisms
- ✅ Session management
- ✅ CSRF protection
- ❌ Object-level authorization (YOU must implement this)

## Key Takeaways

1. ✅ **Always validate object ownership** - Check that current_user owns the requested resource
2. ✅ **Never trust client-provided IDs** - Validate authorization for every object ID
3. ✅ **Use database queries to enforce ownership** - Filter by user_id AND object_id
4. ✅ **Implement centralized authorization logic** - DRY principle for security
5. ✅ **Test with different user contexts** - Verify User A cannot access User B's data
6. ✅ **Log authorization failures** - Monitor for attack attempts
7. ✅ **Use random, non-sequential IDs** - Defense in depth (not a substitute for authorization)

## What's Next?

- **[Attack Vectors](./attack-vectors.md)**: Learn how attackers exploit BOLA vulnerabilities
- **[Prevention](./prevention.md)**: Best practices and secure coding patterns for APIs
- **[Examples](./examples.md)**: Code examples showing vulnerable vs secure API implementations
- **[Lab](./lab/api01-idor-lab/)**: Hands-on practice with BOLA vulnerabilities in a safe environment

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
