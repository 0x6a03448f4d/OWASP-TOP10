# C10: Stop Server-Side Request Forgery - Overview

## Table of Contents
- [What is this control?](#what-is-this-control)
- [Why This Control Matters](#why-this-matters)
- [Core Practices](#core-practices)
- [Where SSRF-Prone Requests Live](#where-ssrf-lives)
- [Real-World Incident Classes](#incident-classes)
- [Common Misunderstandings](#common-misunderstandings)

## What is this control?

**Stop Server-Side Request Forgery (SSRF)** is the proactive control of making sure that when *your server* fetches a URL, it can only ever reach destinations you intended—never an internal service, a cloud metadata endpoint, or a local file. SSRF happens when an attacker supplies or influences a URL that the application then requests on its behalf, turning your trusted server into a proxy that speaks from *inside* your network. This control is the set of defenses that closes that door.

The vulnerability is **Server-Side Request Forgery**; this page is the **defense that stops it**. The distinction matters: the risk is "my server can be tricked into making a request I did not intend"; the control is "every outbound request my server makes is validated against an allow-list, resolved and re-checked at the IP level, and confined by the network so it physically cannot reach anything sensitive."

> **Note on taxonomy**: In the 2021 OWASP Top 10, SSRF was its own category (A10). In the 2025 web Top 10 it has been *folded into Broken Access Control* rather than standing alone. It nonetheless remains a distinct, first-class item in the OWASP Top 10 Proactive Controls (C10, 2024) because stopping it is a specific engineering discipline—how you handle outbound URLs—that developers need to implement deliberately.

### Core Concept

```
Unsafe outbound request (attacker controls where the server goes):
  Input        -> user-supplied URL used verbatim
  Validation   -> none, or a block-list of "bad" strings
  DNS          -> resolved once, only the hostname is checked
  Schemes      -> http, https, file, gopher, dict all allowed
  Redirects    -> followed blindly to wherever they point
  Network      -> app can reach 127.0.0.1, 169.254.169.254, 10.0.0.0/8
  Response     -> raw body reflected back to the caller

Safe outbound request (this control applied):
  Input        -> parsed, then matched against an allow-list
  Validation   -> allow-list of scheme + host + port (deny by default)
  DNS          -> resolved, and the RESOLVED IP is checked and pinned
  Schemes      -> only http/https; file/gopher/dict disabled
  Redirects    -> not followed, or every hop re-validated
  Network      -> egress filtering blocks private/link-local ranges
  Response     -> size-limited, never reflected raw to the caller
```

### Why validating the hostname is not enough

The single most important idea in this control is that **a URL is not safe just because its hostname looked safe**. An attacker who owns a domain can point it at `127.0.0.1` or `169.254.169.254`, and can change that answer *between* the moment you validate it and the moment your HTTP client connects (DNS rebinding). The defense therefore validates on the **resolved IP address**, re-resolves and pins that address for the actual connection, and rejects any address that falls in a private, loopback, link-local, or reserved range.

## Why This Control Matters

### Business Impact of Getting It Right

- **Cloud credential theft is prevented**: the highest-impact SSRF outcome is reaching a cloud instance metadata service and stealing temporary credentials. This control blocks the metadata IP at both the application and network layers.
- **Internal systems stay internal**: admin panels, databases, message queues, and health endpoints that were never meant to face the internet cannot be reached through your public app.
- **Breach blast radius shrinks**: even if one request is malicious, egress filtering and least privilege mean it cannot pivot to anything valuable.
- **Trust in integrations is preserved**: webhooks, importers, and link-preview features are common product requirements; implementing them safely lets you ship them without opening a hole.

### Technical Impact

- **Metadata and secret exposure blocked**: `169.254.169.254` and equivalent endpoints are unreachable from the app.
- **Internal port scanning denied**: the app cannot be used to map internal hosts and ports by timing/response differences.
- **Local file disclosure closed**: disabling `file://` stops `file:///etc/passwd`-style reads.
- **Protocol smuggling stopped**: disabling `gopher://` and `dict://` removes the ability to craft raw requests to internal services (e.g. Redis, SMTP).
- **Rebinding and redirect bypasses defeated**: checking the resolved IP and refusing to follow redirects removes the two most common allow-list bypasses.

## Core Practices

Stopping SSRF is a layered discipline; no single check is sufficient. The reinforcing practices are:

- **Allow-list, do not block-list**: permit an explicit set of schemes, hosts, and ports; deny everything else by default.
- **Validate the resolved IP, not the hostname**: resolve DNS, inspect the returned address(es), and reject private/loopback/link-local/reserved ranges—IPv4 *and* IPv6.
- **Defeat DNS rebinding**: re-resolve at connection time and connect to the exact IP you validated (pin it), so the answer cannot change underneath you.
- **Disable unused URL schemes**: allow only `http`/`https`; never `file://`, `gopher://`, `dict://`, `ftp://`.
- **Do not follow redirects** (or re-validate every hop): a `302` to `http://169.254.169.254/` must not be honored.
- **Enforce network egress filtering and segmentation**: the fetching service should be physically unable to reach internal ranges and the metadata IP.
- **Enforce cloud metadata protection**: require IMDSv2 (session-token) and set the hop limit so the endpoint cannot be reached via a forged request.
- **Handle responses safely**: never reflect the raw upstream body to the user; cap response size and time.
- **Use SSRF-safe HTTP clients**: prefer libraries/wrappers built to validate targets, rather than raw `requests.get(url)`.
- **Apply least privilege and timeouts**: the fetching service holds minimal IAM/network rights and every request has a strict timeout.

## Where SSRF-Prone Requests Live

SSRF lives anywhere your server takes a URL (or something that becomes a URL) from a user and fetches it. Common features to audit:

| Feature | Why it fetches a URL | SSRF risk |
|---------|----------------------|-----------|
| Webhooks | Posts events to a customer-supplied callback URL | Callback pointed at internal/metadata endpoints |
| Link previews / unfurling | Fetches a pasted link to render a card | Any URL a user pastes is fetched server-side |
| Importers | "Import from URL" for files, feeds, or data | URL resolved and downloaded by the server |
| PDF / image / thumbnail generators | Fetches remote assets to render | Embedded URLs pull internal resources |
| Document / HTML converters | Follows `<img>`, CSS, and asset URLs | Markup smuggles internal requests |
| Proxies / gateways | Forward requests to a target URL | Target is directly attacker-controlled |
| Integrations / OAuth discovery | Fetches config or JWKS from a provided base URL | Discovery URL steers the server inward |

## Real-World Incident Classes

These are recurring *classes* of SSRF incident that this control is designed to prevent, described as patterns rather than specific vulnerabilities.

### Class 1: Cloud metadata credential theft

By far the most damaging SSRF class. A user-influenced fetch is steered to a cloud instance metadata service at the link-local address `169.254.169.254`. On configurations that expose credentials without a session token, the attacker retrieves the instance role's temporary keys and uses them against the cloud account. The industry response—session-token-based metadata services (IMDSv2) and mandatory hop limits—exists precisely because of this incident class. Blocking the metadata IP by network egress policy and requiring IMDSv2 closes it.

### Class 2: Reaching internal-only services

SSRF is used to request internal admin consoles, databases, caches, and orchestration APIs that were never exposed to the internet but are reachable from the application host. Because the request originates from a trusted internal source, network ACLs and "internal is safe" assumptions do not stop it.

### Class 3: Internal reconnaissance and port scanning

Even without reading a response, differences in timing and error behaviour let an attacker enumerate live hosts and open ports inside the network, mapping the environment for a later attack.

### Class 4: Local file and protocol abuse

Where the HTTP client honors extra schemes, `file://` reads local files and `gopher://`/`dict://` smuggle crafted bytes to line-based internal services. Restricting schemes to `http`/`https` removes this class entirely.

## Common Misunderstandings

### Myth 1: "I validated the hostname, so it's safe"

**Reality**: hostnames resolve to IPs that the attacker may control and can change after your check. Validate the *resolved IP* and pin it for the connection; a hostname allow-list alone is bypassed by DNS rebinding.

### Myth 2: "A block-list of 127.0.0.1 and localhost is enough"

**Reality**: block-lists are endlessly bypassable—`127.0.0.1` also appears as `127.1`, `2130706433` (decimal), `0x7f000001` (hex), IPv6 `[::1]` and `[::ffff:127.0.0.1]`, and DNS names that resolve to loopback. Allow-list what is permitted instead.

### Myth 3: "It's an internal request, so there's nothing to steal"

**Reality**: the internal network is exactly where the crown jewels live—metadata endpoints, databases, and admin planes. "Internal" is the target, not a mitigation.

### Myth 4: "Following redirects is fine, the first URL was checked"

**Reality**: a validated URL can redirect (`301`/`302`) to `http://169.254.169.254/` or a private IP. Do not follow redirects for user-supplied fetches, or re-validate every hop as strictly as the first.

### Myth 5: "A WAF or URL-string filter will catch it"

**Reality**: string filtering cannot account for every IP encoding, scheme, and DNS trick. The reliable control is IP-level validation after resolution plus network egress filtering—defense in depth, not a regex.

## How This Control Relates to SSRF (the risk)

| Aspect | Server-Side Request Forgery (the risk) | Stop SSRF (the control) |
|--------|----------------------------------------|-------------------------|
| **Nature** | Server tricked into an unintended request | Every outbound request is validated and confined |
| **Default posture** | Fetches wherever the URL points | Deny by default; allow-listed destinations only |
| **Where enforced** | Absent—URL used verbatim | App validation + resolved-IP check + network egress |
| **Failure mode** | Metadata theft, internal access, file read | Explicit, reviewed exception to the allow-list |

## Key Takeaways

1. **The control is about outbound requests**—wherever your server fetches a user-influenced URL, it must be constrained.
2. **Allow-list, never block-list**—permit specific schemes, hosts, and ports; deny everything else.
3. **Check the resolved IP and pin it**—defeat DNS rebinding by validating and connecting to the same address.
4. **Defense in depth**—app validation, disabled schemes, no redirects, network egress filtering, and IMDSv2 together.
5. **SSRF moved under Broken Access Control in 2025, but the defense is still a distinct discipline** you implement in code and infrastructure.

## Self-Assessment Checklist

- [ ] Do you have an inventory of every feature where the server fetches a user-influenced URL?
- [ ] Is each fetch validated against an allow-list of schemes, hosts, and ports (deny by default)?
- [ ] Do you resolve DNS and validate the *resolved IP*, rejecting private/loopback/link-local/reserved ranges (IPv4 and IPv6)?
- [ ] Do you re-resolve and pin the IP at connection time to defeat DNS rebinding?
- [ ] Are non-HTTP schemes (`file`, `gopher`, `dict`, `ftp`) disabled?
- [ ] Are redirects blocked or every hop re-validated?
- [ ] Is network egress filtering in place so the app cannot reach internal ranges or `169.254.169.254`?
- [ ] Is IMDSv2 (session tokens) enforced with a restrictive hop limit on cloud hosts?
- [ ] Are upstream responses size-limited, time-limited, and never reflected raw?
- [ ] Does the fetching service run with least-privilege IAM and strict timeouts?

## Next Steps

- **[Threats Addressed](attack-vectors.md)**: How SSRF is exploited when this control is missing
- **[How to Implement](prevention.md)**: The layered SSRF defenses, step by step
- **[Examples](examples.md)**: Vulnerable vs. secure URL handling across frameworks
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply SSRF defenses hands-on
