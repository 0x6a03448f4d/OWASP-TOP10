# C10: Stop Server-Side Request Forgery - How to Implement

## How to Implement This Control

Stopping SSRF is a layered defense: no single check is sufficient, and the application-layer validation and the network-layer confinement back each other up. Implement the steps below together so that a bypass of one is caught by another.

1. Validate every user-influenced URL against an **allow-list** (scheme, host, port).
2. Resolve DNS and validate the **resolved IP**, rejecting private/reserved ranges—then **pin** it.
3. Disable unused URL **schemes**; permit only `http`/`https`.
4. Do not follow **redirects** (or re-validate every hop).
5. Confine the fetching service with **network egress filtering** and segmentation.
6. Enforce **cloud metadata protection** (IMDSv2 + hop limit).
7. Handle **responses** safely (no raw reflection, size and time limits).
8. Apply **least privilege** and use an **SSRF-safe HTTP client**.

### Design Principles

- **Deny by default**: a fetch is refused unless its destination is explicitly permitted.
- **Validate on the resolved IP, not the string**: the hostname is a hint; the IP is the truth—and it must be the IP you actually connect to.
- **Defense in depth**: assume the app-layer check can be bypassed, and make the network unable to reach anything sensitive anyway.
- **Fail closed and quiet**: on any doubt, refuse the fetch and return a generic error that leaks no internal detail.

## 1. Allow-list Destinations (Scheme, Host, Port)

Prefer an allow-list over a block-list. Block-lists are endlessly bypassable; an allow-list states exactly what is permitted and denies everything else. Where the set of legitimate destinations is known (an importer that only pulls from your own CDN, an integration with a fixed provider), pin it tightly.

```python
# Conceptual allow-list policy — deny by default
ALLOWED_SCHEMES = {"https"}                       # http only if you truly need it
ALLOWED_HOSTS   = {"api.partner.com", "cdn.example.net"}
ALLOWED_PORTS   = {443}

def destination_allowed(scheme, host, port):
    return (scheme in ALLOWED_SCHEMES
            and host in ALLOWED_HOSTS
            and port in ALLOWED_PORTS)
```

When the destination is genuinely open-ended (e.g. a link-preview feature that may fetch any public site), you cannot allow-list hosts—so the resolved-IP validation in step 2 and the network egress filtering in step 5 become the primary defenses. Compare hosts by **exact** match, never `startsWith`/`endsWith`, and reject credentials-in-URL (`user@host`) and non-default ports you did not intend.

## 2. Resolve DNS, Validate the Resolved IP, and Pin It

This is the core of the control. Parse the URL, resolve the hostname to its IP address(es), reject any address in a private, loopback, link-local, or reserved range, and then connect to *that validated IP* so DNS cannot change between the check and the connection (defeating DNS rebinding).

```python
import ipaddress, socket

# Ranges to reject AFTER resolution (IPv4 and IPv6)
def is_blocked_ip(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified
            # explicitly cover the cloud metadata address:
            or ip in ipaddress.ip_network("169.254.169.254/32"))

def resolve_and_validate(host):
    infos = socket.getaddrinfo(host, None)          # may return several IPs
    ips = {info[4][0] for info in infos}
    if not ips:
        raise ValueError("no address")
    for ip in ips:                                  # ALL answers must be safe
        if is_blocked_ip(ip):
            raise ValueError(f"blocked address: {ip}")
    return ips
```

> **Pin the address**: after validation, connect to the exact validated IP (pass it to the client, or supply the `Host` header while dialing the IP). If you validate a hostname and then hand the raw hostname to a normal HTTP client, the client re-resolves independently and a rebinding attacker can return a different, internal IP the second time. Validate and connect must see the *same* address.

Note the `169.254.0.0/16` link-local range already contains `169.254.169.254`; call it out explicitly so reviewers see the metadata endpoint is covered, and remember IPv6 equivalents such as `[::1]`, `[::ffff:127.0.0.1]`, and `fd00::/8`.

## 3. Disable Unused URL Schemes

Restrict the accepted schemes to `http` and `https`. Anything else—`file://`, `gopher://`, `dict://`, `ftp://`—is either a local-file read or a protocol-smuggling primitive and should be rejected before any network activity.

```python
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}   # drop file, gopher, dict, ftp, ...

def scheme_ok(url):
    return urlparse(url).scheme.lower() in ALLOWED_SCHEMES
```

Also configure the underlying HTTP library so it cannot be coaxed into other protocols (for example, disable non-HTTP protocols in cURL-based clients). Reject `file://` unconditionally in any code path that accepts a user URL.

## 4. Do Not Follow Redirects (or Re-validate Every Hop)

A validated URL can respond with a redirect to an internal target. Disable automatic redirect following for user-supplied fetches. If you must follow redirects, treat every `Location` as a brand-new untrusted URL and run the full scheme + resolved-IP validation on each hop.

```python
# Python requests — do not auto-follow; inspect and re-validate manually
resp = session.get(url, allow_redirects=False, timeout=5)
if resp.is_redirect:
    next_url = resp.headers["Location"]
    # re-run scheme_ok() + resolve_and_validate() on next_url before proceeding
    raise ValueError("redirect not permitted for user-supplied fetch")
```

## 5. Network Egress Filtering and Segmentation

Assume the application-layer check can be bypassed and make the network unable to reach anything sensitive regardless. Place the fetching service where it physically cannot route to internal ranges or the metadata IP.

```
# Egress policy for the fetching service (conceptual)
DENY  to 169.254.0.0/16      # link-local incl. 169.254.169.254 metadata
DENY  to 127.0.0.0/8         # loopback
DENY  to 10.0.0.0/8          # RFC1918 private
DENY  to 172.16.0.0/12       # RFC1918 private
DENY  to 192.168.0.0/16      # RFC1918 private
DENY  to fc00::/7, ::1/128, fe80::/10   # IPv6 private / loopback / link-local
ALLOW to 0.0.0.0/0 : 443     # public HTTPS only, everything else denied
```

Implement this with security groups / NACLs, a Kubernetes `NetworkPolicy`, or a forward proxy that the service must use for all outbound traffic. Route user-driven fetches through a dedicated, isolated egress path rather than the general application network.

## 6. Enforce Cloud Metadata Protection (IMDSv2)

Because metadata theft is the highest-impact SSRF outcome, harden the metadata endpoint itself as a second line of defense. Require the session-oriented metadata service (IMDSv2), which needs a `PUT` to obtain a token before any read—something a simple SSRF `GET` cannot perform—and set the response hop limit low so the endpoint is not reachable from containers.

```
# Require IMDSv2 (token-based) and restrict hops on the instance
#   HttpTokens: required          -> plain GET without a session token is refused
#   HttpPutResponseHopLimit: 1    -> not reachable from a container network hop
#   HttpEndpoint: enabled (or disabled entirely if the instance needs no metadata)
```

Where an instance does not need metadata at all, disable the endpoint. Combine this with the egress deny rule above so `169.254.169.254` is blocked even before IMDSv2 is consulted.

## 7. Safe Response Handling

Do not reflect the raw upstream response back to the caller—that is what turns a blind SSRF into a readable one and leaks internal data. Return only what the feature needs (a status, a parsed field, a rendered preview), cap the response size, and enforce a total time budget.

```python
# Bound what you read back from the upstream
MAX_BYTES = 1_000_000           # 1 MB cap
resp = session.get(validated_ip_url, stream=True, timeout=5, allow_redirects=False)

body = b""
for chunk in resp.iter_content(8192):
    body += chunk
    if len(body) > MAX_BYTES:
        raise ValueError("response too large")

# Return a controlled result, never the raw internal body verbatim
return {"status": resp.status_code, "title": extract_title(body)}
```

## 8. Least Privilege, SSRF-safe Clients, and Timeouts

- **Least privilege**: give the fetching service the narrowest cloud IAM role and network reach that its job requires, so a successful SSRF yields little.
- **SSRF-safe HTTP client**: prefer a vetted wrapper/library that performs target validation and IP pinning for you, rather than a raw `requests.get(user_url)`. Centralize all outbound user-driven fetches through one hardened client so the checks cannot be forgotten.
- **Timeouts**: set aggressive connect and read timeouts on every request to blunt port-scanning-by-timing and to prevent resource exhaustion.

## Defense-in-Depth Summary

| Threat | Primary defense | Backstop |
|--------|-----------------|----------|
| Metadata credential theft | Egress deny `169.254.169.254` | IMDSv2 + hop limit, resolved-IP check |
| Internal service access | Allow-list + resolved-IP check | Network segmentation |
| Port scanning | Egress filtering | Uniform errors + timeouts |
| Local file read | Scheme allow-list (no `file://`) | Least-privilege service account |
| DNS rebinding | Re-resolve + pin validated IP | Egress filtering |
| Redirect bypass | Do not follow redirects | Re-validate each hop |

## Key Takeaways

1. **Allow-list and deny by default** — state what is permitted; refuse everything else.
2. **Validate the resolved IP and pin it** — this is the single check that survives real bypasses.
3. **Disable extra schemes and redirects** — remove the `file://`/`gopher://` and redirect-to-internal paths.
4. **Confine the network** — egress filtering and IMDSv2 stop the request even if the app check fails.
5. **Least privilege, safe responses, timeouts** — shrink the payoff and the reconnaissance value of any request that slips through.

## Next Steps

- **[Examples](examples.md)**: Vulnerable vs. secure URL handling across frameworks
- **[Threats Addressed](attack-vectors.md)**: Understand what you're defending against
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply SSRF defenses hands-on
