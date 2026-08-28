# API09: Improper Inventory Management - Attack Vectors

## Table of Contents
- [Understanding the Attack Surface](#understanding-the-attack-surface)
- [Core Attack Flow](#core-attack-flow)
- [Attack Patterns](#attack-patterns)
- [Chaining Inventory Gaps](#chaining-inventory-gaps)

## Understanding the Attack Surface

> **WARNING: EDUCATIONAL PURPOSE ONLY.** These techniques are described so defenders can find and close gaps before attackers do. Only test systems you are explicitly authorized to test.

Attacking improper inventory management is fundamentally an exercise in **discovery**. The attacker's goal is to find the asset the defender forgot: an old version, a stale host, a debug route, or a partner endpoint that never made it into anyone's threat model. Because these assets are unmonitored by definition, exploitation is often quiet and can persist for a long time.

The attacker rarely needs a novel exploit. They need the *weakest reachable copy* of your functionality — and inventory gaps guarantee that a weaker copy usually exists.

## Core Attack Flow

```
1. Map the surface
   |  Enumerate subdomains, hosts, versions, and routes
   v
2. Find the weak variant
   |  Compare auth/rate-limit behavior across versions & hosts
   v
3. Exploit the gap
   |  Use the version/endpoint with missing or weaker controls
   v
4. Persist quietly
   |  Operate through an unmonitored path to avoid detection
```

## Attack Patterns

### 1. Enumerating Deprecated API Versions

Decrement the version on a known endpoint and look for an older variant that still answers with weaker authorization.

```
GET /api/v3/users/1001   -> 401 Unauthorized  (token + scope required)
GET /api/v2/users/1001   -> 401 Unauthorized
GET /api/v1/users/1001   -> 200 OK            (legacy: returns full record!)
```

### 2. Subdomain Enumeration to Find Shadow Hosts

Certificate-transparency logs and brute-force resolvers reveal forgotten hosts still exposed to the internet.

```
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
#   dev-api.example.com
#   staging.example.com
#   api-old.example.com

GET https://dev-api.example.com/api/users   -> 200 OK  (debug mode, real data)
```

### 3. Non-Production Environments with Production Data

Staging often mirrors production data but ships with verbose errors and default credentials.

```
GET https://staging.example.com/api/v3/orders

HTTP/1.1 500 Internal Server Error
{ "error": "OperationalError",
  "stack": "db.connect(host=staging-db.internal:5432, user=admin, password=changeme)" }
```

### 4. Missing Authentication on Old Versions

```
GET /api/v2/account/balance
Authorization: Bearer eyJ...     -> 200 OK

GET /api/v1/account/balance      -> 200 OK   (no Authorization header needed)
```

### 5. Undocumented Debug & Admin Endpoints

```
GET /api/_debug        -> 200 OK   (dumps environment variables)
GET /api/admin/users   -> 200 OK   (no auth, lists all users)
GET /internal/backup   -> 200 OK   (downloads a database dump)
GET /test/reset-db     -> 200 OK   (destructive dev utility, still live)
```

### 6. Framework Diagnostic Endpoints (Actuator, Docs, Introspection)

```
GET /actuator/env       -> configuration incl. secrets
GET /actuator/heapdump  -> full memory dump (tokens, sessions)
GET /openapi.json       -> full machine-readable API spec
POST /graphql {"query":"{__schema{types{name}}}"}  -> introspection
```

### 7. Interactive API Docs as a Discovery Oracle

A leaked OpenAPI/Swagger document enumerates every path, parameter, and payload.

```
curl -s https://api.example.com/openapi.json | jq -r '.paths | keys[]'
/api/v3/users
/api/v1/legacy/export     <-- undocumented elsewhere, but present in the spec
/api/internal/impersonate <-- an admin route the spec forgot to hide
```

### 8. Differing Security Controls Across Versions

```
POST /api/v1/login             (v1 never got rate limiting -> credential stuffing)
GET  /api/v1/invoices/99999    -> 200 OK  (v1 skips object-ownership checks -> BOLA)
```

### 9. Retired-But-Reachable Services

```
GET https://legacy-payments.example.com/api/charge   -> 200 OK
# Migrated months ago, but the old service still accepts requests and holds live keys.
```

### 10. Mobile / Client-Specific Shadow APIs

```
POST https://mobile-api.example.com/v2/profile/update
# Skips the WAF and gateway rate limits that guard api.example.com.
```

### 11. Parameter- and Header-Based Version Selection

```
GET /api/users/1001
Accept: application/vnd.example.v1+json   -> legacy handler, weaker checks

GET /api/users/1001?api-version=1.0        -> routes to deprecated logic
```

### 12. Third-Party Data-Flow Blind Spots

```
POST https://partner-api.example.com/lookup
{ "name": "Jane Doe", "dob": "1990-01-01", "zip": "10001" }
-> 200 OK  { "credit_score": 742, "ssn_last4": "1234" }
```

### 13. Stale Documentation / Changelogs Leaking Removed Routes

```
# A cached changelog: "Deprecated /api/v1/export-all in favor of /api/v3/export"
GET /api/v1/export-all   -> 200 OK  (still exports everything)
```

### 14. JavaScript Bundle & Source-Map Mining

```
curl -s https://example.com/static/app.min.js | grep -oE '/api/[a-zA-Z0-9/_-]+'
/api/v3/users
/api/beta/experimental-search   <-- feature-flagged, but reachable
/api/internal/feature-flags     <-- internal config endpoint
```

## Chaining Inventory Gaps

```
1. crt.sh reveals dev-api.example.com          (stale host)
        v
2. /openapi.json on that host leaks every route (docs disclosure)
        v
3. /api/v1/login has no rate limit             (control drift) -> credential stuffing
        v
4. /actuator/env exposes a database password   (framework default)
        v
5. Attacker pivots to internal systems using leaked credentials
```

### Why These Attacks Succeed and Persist

- **No monitoring on forgotten assets** — abuse of an uninventoried endpoint generates no alerts.
- **Controls never applied uniformly** — improvements land on the current surface only.
- **Discovery is cheap** — CT logs, wordlists, and app inspection need little skill and no access.
- **Data parity, control disparity** — stale and non-prod hosts often carry real data behind weaker walls.

## Key Takeaways

1. **Version enumeration is the flagship attack** — find the copy that still answers.
2. **Discovery is the hard part for defenders** — attackers automate it trivially.
3. **Docs and framework defaults are discovery oracles.**
4. **Shadow, mobile, and partner APIs bypass central defenses** by design.
5. **Non-production hosts are production targets** when reachable.
6. **Gaps chain** — one stale host can unravel an entire environment.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build inventory, governance, and monitoring defenses
- **[Code Examples](examples.md)**: See secure, inventoried implementations
- **[Hands-On Lab](lab/api09-inventory-lab/)**: Practice discovering and retiring unmanaged endpoints
