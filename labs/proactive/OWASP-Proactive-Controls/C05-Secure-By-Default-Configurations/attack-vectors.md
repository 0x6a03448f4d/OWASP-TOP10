# C5: Secure By Default Configurations - Threats Addressed

## Table of Contents
- [Threats Addressed by This Control](#threats-addressed-by-this-control)
- [How Insecure Defaults Become Incidents](#how-insecure-defaults-become-incidents)
- [The Threats, and the Default That Closes Each](#the-threats-and-the-default-that-closes-each)
- [Chaining Insecure Defaults](#chaining-insecure-defaults)

## Threats Addressed by This Control

> **Framing** — this page lists the concrete failure modes that Secure By Default Configurations exists to prevent. Each item is an insecure default that, left in place, becomes an exploitable weakness. For every one, the fix is the same shape: make the safe setting the default.

Insecure defaults are rarely exploited through a clever payload. They are exploited through **observation and enumeration**: an attacker sends ordinary requests, reads what the system volunteers, and walks through whichever door was left open by a default nobody changed. Because these are settings rather than logic bugs, they are cheap to find at scale—automated scanners fingerprint thousands of hosts an hour looking for exactly these defaults.

## How Insecure Defaults Become Incidents

```
1. Ship with an insecure default
   v   (debug on, bucket public, admin/admin active, port open)
2. Deploy without hardening
   v   (template cloned, nobody changed the default)
3. Attacker fingerprints and enumerates
   v   (banners, default paths, default creds, open ports)
4. Attacker walks through the open door
   v   (read data, reach the console, run code, pivot)
5. A secure default would have blocked step 1 entirely.
```

## The Threats, and the Default That Closes Each

### 1. Verbose Errors and Debug Mode in Production

Frameworks default to a developer-friendly mode that returns stack traces—or an interactive debugger—to the client.

```
# Insecure default
DEBUG = True                     # returns tracebacks; interactive console = RCE
# Secure default
DEBUG = False                    # generic error to client, detail to logs only
```

**Closed by**: debug and detailed errors off by default in any non-development environment.

### 2. Wildcard or Reflected CORS

A permissive CORS default lets any site read authenticated responses from a victim's browser.

```
# Insecure default
Access-Control-Allow-Origin: *            (or the request Origin reflected)
Access-Control-Allow-Credentials: true
# Secure default
Access-Control-Allow-Origin: https://app.example.com   # exact allow-list only
```

**Closed by**: no cross-origin access unless an origin is explicitly allow-listed.

### 3. Missing Security Headers

Absent response headers enable a family of browser-side attacks by default.

```
# Insecure default: none of these are set
# Secure default: preset on every response
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
```

**Closed by**: security headers applied centrally as the default for every response.

### 4. Default and Sample Credentials

Well-known credential pairs ship active and are tried automatically against every reachable service.

```
# Insecure default
admin / admin      root / root      guest / guest      elastic / changeme
# Secure default
no usable credential ships; a unique secret must be set at first setup
```

**Closed by**: shipping with no default credential and forcing a unique one at initialization.

### 5. Exposed Management, Admin, and Debug Endpoints

Operational endpoints ship enabled and unauthenticated.

```
# Insecure default
management.endpoints.web.exposure.include=*   # /env, /heapdump reachable
# Secure default
management.endpoints.web.exposure.include=health,info   # nothing sensitive
```

**Closed by**: management planes off, scoped, or authenticated by default.

### 6. Unnecessary Services, Ports, and HTTP Methods

Servers accept verbs and run services the application never needs.

```
# Insecure default
Allow: GET, POST, PUT, DELETE, TRACE, PATCH, CONNECT   # everything on
# Secure default
Allow: GET, POST                                       # only what's needed
```

**Closed by**: deny-by-default for methods, ports, and services; enable only what a route needs.

### 7. Public Cloud Storage and Overly Broad IAM

Storage buckets and roles default to more access than intended.

```
# Insecure default
bucket ACL: AllUsers / AuthenticatedUsers read
IAM policy: "s3:*" on "*"
# Secure default
block public access = on; encryption = on; scoped, least-privilege policy
```

**Closed by**: private-by-default storage, encryption on, and least-privilege IAM in the template.

### 8. Unauthenticated Datastores Bound to All Interfaces

Databases and brokers default to listening everywhere with auth optional.

```
# Insecure default
bind 0.0.0.0                      # reachable from the internet, no auth
# Secure default
bind 127.0.0.1                    # private interface, authentication required
```

**Closed by**: binding to private interfaces and requiring authentication by default.

### 9. Containers Running as Root with Secrets Baked In

Images default to the root user and a full OS, and secrets get copied into layers.

```
# Insecure default
FROM ubuntu                       # full OS, runs as root
COPY .env /app/.env               # secret baked into the image
# Secure default
FROM python:3.12-slim
USER 10001                        # non-root; secrets injected at runtime
```

**Closed by**: non-root, minimal base image, and runtime-injected secrets as the default.

### 10. Weak TLS and Missing HSTS

Legacy protocols and ciphers stay enabled, and HTTPS is not enforced.

```
# Insecure default
TLS 1.0 / 1.1 enabled; RC4/3DES accepted; no HSTS
# Secure default
TLS 1.2+ only; modern ciphers; HSTS preset; HTTP redirected to HTTPS
```

**Closed by**: modern-TLS-only and HSTS as the shipped default.

### 11. Directory Listing and Exposed Files

Auto-indexing and served dotfiles disclose source and secrets.

```
# Insecure default
autoindex on;                     # browsable directories
GET /.git/config  GET /.env  GET /backup.sql   # served from web root
# Secure default
autoindex off; dotfiles and backups blocked/return 404
```

**Closed by**: directory listing off and sensitive paths denied by default.

### 12. Version Banners and Fingerprinting

Servers advertise exact software and versions, handing scanners a CVE match.

```
# Insecure default
Server: nginx/1.18.0     X-Powered-By: Express
# Secure default
server_tokens off; x-powered-by removed
```

**Closed by**: banners suppressed by default so recon returns nothing useful.

### 13. Configuration Drift

Even a system that started secure erodes as ad-hoc changes accumulate.

```
# Insecure default
no automated check; manual edits accepted silently
# Secure default
IaC is the source of truth; drift fails the pipeline or raises an alert
```

**Closed by**: automated configuration validation and drift detection.

### 14. Unpatched Default Versions

Base images and dependencies default to whatever tag was pinned long ago.

```
# Insecure default
FROM node:16                      # floating, stale
# Secure default
current, patched base pinned by digest; automated update PRs
```

**Closed by**: defaulting to current, patched versions and keeping them current.

## Chaining Insecure Defaults

Individually minor defaults combine into full compromise—which is why the control targets the defaults themselves, not just the worst one:

```
Version banner (nginx/PHP)        -> pick a matching known exploit
        +
Directory listing exposes /.env   -> read DB credentials
        +
Datastore bound to 0.0.0.0        -> connect directly with those creds
        =  full data breach, and every link was just a default left unchanged
```

## Key Takeaways

1. **Every threat here is a default left unchanged**—the fix is to change the default, once, for everyone.
2. **Insecure defaults are found by observation**—scanners harvest banners, default paths, and default creds at scale.
3. **Management planes and storage are the highest-value defaults**—close and privatize them by default.
4. **Defaults chain**—a banner plus an exposed file plus an open datastore is a breach with no code exploit.
5. **Drift reopens closed doors**—automated validation keeps secure defaults secure.

## Next Steps

- **[How to Implement](prevention.md)**: Turn each secure default into a repeatable baseline
- **[Examples](examples.md)**: See insecure vs. secure configuration side by side
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Hunt and fix insecure defaults hands-on
