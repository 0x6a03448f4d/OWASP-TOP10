# SSRF — Prevention

## Table of Contents

- [Defense in Depth: The Layers](#defense-in-depth-the-layers)
- [Layer 1 — Allowlist Destinations](#layer-1--allowlist-destinations)
- [Layer 2 — Resolve and Validate the IP](#layer-2--resolve-and-validate-the-ip)
- [Layer 3 — Defeat DNS Rebinding (Pin the IP)](#layer-3--defeat-dns-rebinding-pin-the-ip)
- [Layer 4 — Control Redirects](#layer-4--control-redirects)
- [Layer 5 — Restrict Schemes and Disable Parsers](#layer-5--restrict-schemes-and-disable-parsers)
- [Layer 6 — Network Segmentation and Egress Filtering](#layer-6--network-segmentation-and-egress-filtering)
- [Layer 7 — Enforce IMDSv2](#layer-7--enforce-imdsv2)
- [Layer 8 — Safe Response Handling](#layer-8--safe-response-handling)
- [A Complete Safe-Fetcher Reference](#a-complete-safe-fetcher-reference)
- [Prevention Checklist](#prevention-checklist)

## Defense in Depth: The Layers

No single control stops SSRF. Filters get bypassed by encodings and rebinding; allowlists can be parser-confused; redirects escape validation. The reliable posture is layered: validate at the application, harden the HTTP client, and constrain the network so that even a successful bypass reaches nothing valuable.

| Layer | Control | Stops |
|-------|---------|-------|
| Application | Allowlist of schemes/hosts/ports | Arbitrary destinations |
| Application | Resolve DNS, validate resolved IP | Obfuscated IPs, internal ranges |
| HTTP client | Pin IP; no unvalidated redirects | DNS rebinding, redirect escapes |
| HTTP client | Scheme restriction, timeouts | file://, gopher://, hangs |
| Network | Egress firewall, segmentation | Reaching metadata / internal hosts |
| Cloud | IMDSv2 + least-privilege roles | Credential theft |
| Output | Do not reflect raw responses | Data exfiltration, oracles |

## Layer 1 — Allowlist Destinations

The single most effective control. Deny by default and permit only what the feature genuinely needs: an explicit set of **schemes** (almost always just `https`), **hosts** (exact names, not substrings), and **ports** (usually 443). Prefer an allowlist over a blocklist — blocklists chase an endless list of encodings; allowlists define the small set of things that are OK.

```
Allowlist (durable)                 Blocklist (fragile)
-------------------                 -------------------
scheme in {https}                   scheme not in {file, gopher, dict}
host   in {api.partner.com}         host not in {127.0.0.1, localhost}
port   in {443}                     ...missing 127.1, 0x7f..., [::1], rebinding
                                    ...missing every new internal range
```

When the destination cannot be an allowlist (open webhooks, "fetch any public page"), you must lean harder on Layers 2, 3, and 6 — validate the resolved IP and enforce egress filtering, because you cannot enumerate legitimate hosts in advance.

## Layer 2 — Resolve and Validate the IP

Never validate the hostname string alone. Resolve it, then reject the request if *any* resolved address falls in a private, loopback, link-local, or otherwise reserved range. Check every address the name resolves to (a hostname can return several).

```
Reject if the resolved IP is in any of these:
  0.0.0.0/8         current network / "this host"
  10.0.0.0/8        private
  100.64.0.0/10     carrier-grade NAT
  127.0.0.0/8       loopback
  169.254.0.0/16    link-local (INCLUDES 169.254.169.254 metadata)
  172.16.0.0/12     private
  192.168.0.0/16    private
  192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24  special-use / test
  240.0.0.0/4       reserved
  ::1/128           IPv6 loopback
  fc00::/7          IPv6 unique-local
  fe80::/10         IPv6 link-local
  ::ffff:0:0/96     IPv4-mapped IPv6 (re-check the embedded IPv4!)
```

Language standard libraries already classify these. Prefer them over hand-rolled regexes:

```
# Python
import ipaddress
ip = ipaddress.ip_address(resolved)
blocked = (ip.is_private or ip.is_loopback or ip.is_link_local
           or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

// Node.js
const net = require('node:net');   // net.isIP() to detect family
// use a library such as 'ipaddr.js' -> ipaddr.parse(ip).range()
// reject ranges: 'private','loopback','linkLocal','uniqueLocal','reserved','unspecified'
```

## Layer 3 — Defeat DNS Rebinding (Pin the IP)

Validation is worthless if the app resolves the name a second time to connect — the attacker changes the answer in between. Resolve **once**, validate that address, then connect to **that exact IP**, carrying the original hostname only for TLS SNI and the `Host` header.

```python
# Python (requests): resolve, validate, then connect to the pinned IP
import socket, ipaddress, requests

def safe_get(url, host):
    infos = socket.getaddrinfo(host, None)
    ips = {i[4][0] for i in infos}
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            raise ValueError(f"blocked internal address: {ip}")
    pinned = next(iter(ips))
    # Connect to the validated IP; keep Host header + SNI = original hostname
    return requests.get(url, headers={"Host": host},
                        allow_redirects=False, timeout=5)
```

In Node.js, pass a custom `lookup` function to the HTTP agent that returns only your pre-validated, pinned address, so the socket layer cannot re-resolve to a different IP.

## Layer 4 — Control Redirects

A validated public URL can redirect to an internal one. Two safe options:

- **Disable redirect following entirely** (simplest) and treat a 3xx as an error the user must resolve.
- **Follow manually**, re-running Layers 2–3 on every hop's resolved IP, capping the hop count.

```
# Python requests: never auto-follow
requests.get(url, allow_redirects=False, timeout=5)

// Node.js fetch/undici: cap and inspect
fetch(url, { redirect: 'manual' });        // do not auto-follow; validate Location yourself

// Java (java.net.http): stop following
HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
```

## Layer 5 — Restrict Schemes and Disable Parsers

Permit only `https` (and `http` if unavoidable). Explicitly reject `file://`, `gopher://`, `dict://`, `ftp://`, `ldap://`, and everything else. For document/XML/SVG handling, disable external-entity and remote-reference resolution so parsers cannot be turned into fetchers.

```
# Python: harden XML parsing against XXE -> SSRF (use defusedxml)
from defusedxml.ElementTree import parse   # forbids external entities by default

// Java: disable DTDs / external entities on the parser
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

## Layer 6 — Network Segmentation and Egress Filtering

Assume the application filter will someday be bypassed, and make sure the fetcher's network cannot reach anything sensitive. Put URL-fetching workloads in an isolated segment whose egress firewall **denies by default** and permits only the specific external destinations the feature requires.

```
# Conceptual egress policy for the fetcher segment
default: DENY all outbound

# Explicitly block internal + metadata even if something slips through:
DENY  -> 169.254.169.254/32     (cloud metadata)
DENY  -> 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16

# Allow only what the feature legitimately needs:
ALLOW -> 443/tcp to {approved public destinations}
```

An outbound proxy that all fetches must traverse is a good enforcement point: it can allowlist destinations centrally, strip dangerous schemes, and log every request for detection.

## Layer 7 — Enforce IMDSv2

On cloud instances, require IMDSv2 and disable IMDSv1 so a GET-only SSRF cannot read metadata, and set a low hop limit so responses cannot be routed off-box. Pair this with **least-privilege instance roles** so that even a stolen credential grants little.

```
# AWS EC2: require IMDSv2 (token), forbid v1, limit hops to 1
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required \
  --http-endpoint enabled \
  --http-put-response-hop-limit 1

# Terraform equivalent on the launch template / instance:
metadata_options {
  http_tokens                 = "required"   # IMDSv2 only
  http_put_response_hop_limit = 1
  http_endpoint               = "enabled"
}
```

> IMDSv2 protects the metadata endpoint only. It does nothing for internal databases, admin panels, or file reads — keep every other layer in place.

## Layer 8 — Safe Response Handling

Do not reflect raw fetched content back to the user — bodies, headers, redirect targets, or verbose error text all become exfiltration channels and blind-SSRF oracles. Return a generic result, cap response size, enforce a strict timeout, and log the resolved destination for monitoring.

- **Do not echo** the upstream body or status verbatim; transform it into the minimal data your feature needs.
- **Cap size and time**: reject responses over a sane byte limit; use short connect/read timeouts to blunt port-scan oracles.
- **Normalize errors**: return the same generic error for "blocked", "refused", and "timeout" so attackers cannot distinguish internal states.
- **Log and alert**: record resolved IPs; alert on attempts to reach reserved ranges or the metadata address.

## A Complete Safe-Fetcher Reference

Putting Layers 1–5 and 8 together into one guarded function. This is the shape every language's version should take.

```python
from urllib.parse import urlparse
import socket, ipaddress, requests

ALLOWED_SCHEMES = {"https"}
ALLOWED_PORTS   = {443}
MAX_BYTES       = 1_000_000

def is_blocked_ip(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

def safe_fetch(raw_url):
    u = urlparse(raw_url)

    # Layer 5: scheme allowlist
    if u.scheme not in ALLOWED_SCHEMES:
        raise ValueError("scheme not allowed")

    # Layer 1: port allowlist
    port = u.port or 443
    if port not in ALLOWED_PORTS:
        raise ValueError("port not allowed")

    host = u.hostname
    if not host:
        raise ValueError("missing host")

    # Layer 2 + 3: resolve once, validate EVERY address, pin the result
    addrs = {info[4][0] for info in socket.getaddrinfo(host, port)}
    for ip in addrs:
        if is_blocked_ip(ip):
            raise ValueError(f"blocked internal address: {ip}")

    # Layer 4: never auto-follow redirects; Layer 8: timeout + size cap
    resp = requests.get(raw_url, allow_redirects=False, timeout=5, stream=True)
    if resp.is_redirect or resp.is_permanent_redirect:
        raise ValueError("redirects are not followed")

    body = resp.raw.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("response too large")
    return body[:MAX_BYTES]
```

Where available, prefer a maintained SSRF-protection library or a vetted safe HTTP client over reinventing this — but understand each layer so you can review whatever you adopt.

## Prevention Checklist

- [ ] Every server-side fetch goes through one central, guarded fetcher — no ad-hoc `requests.get(user_url)`.
- [ ] Destinations are **allowlisted** (scheme + exact host + port) wherever the feature allows it.
- [ ] The **resolved IP** is validated against private/loopback/link-local/reserved ranges — not the hostname string.
- [ ] The connection is **pinned** to the validated IP to defeat DNS rebinding.
- [ ] Redirects are **not auto-followed**, or every hop is re-validated.
- [ ] Only `https` (and, if unavoidable, `http`) schemes are permitted; `file/gopher/dict/ftp` are rejected.
- [ ] XML/SVG/document parsers have external-entity resolution disabled.
- [ ] Fetcher workloads run in a **segmented network** with default-deny egress that blocks internal ranges and metadata.
- [ ] **IMDSv2 is enforced**, IMDSv1 disabled, hop limit set low, and instance roles are least-privilege.
- [ ] Responses are **not reflected raw**; size and time are capped; errors are normalized; resolved IPs are logged and alerted.

## Next Steps

- **[Overview](./overview.md)**: What SSRF is and why it matters.
- **[Attack Vectors](./attack-vectors.md)**: The techniques these layers defend against.
- **[Examples](./examples.md)**: Vulnerable vs. secure code in four languages.
- **[Lab](./lab/ssrf-simulation-lab/)**: Practice building and testing a safe fetcher.

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
