# C10: Stop Server-Side Request Forgery - Code Examples

Each pair below shows a **vulnerable** outbound fetch and the **secure** version in the same framework. The vulnerable code takes a user-supplied URL and requests it verbatim; the secure code parses the URL, checks the scheme, resolves DNS, validates and pins the resolved IP against reserved ranges, refuses redirects, and bounds the response.

> These snippets illustrate the control. In production, prefer a single, centralized, vetted SSRF-safe HTTP client and back it with network egress filtering—never rely on application code alone.

## Flask (Python)

### Vulnerable
```python
import requests
from flask import Flask, request, Response

app = Flask(__name__)

@app.route('/fetch')
def fetch():
    url = request.args.get('url')          # attacker-controlled
    r = requests.get(url)                  # fetches ANYTHING: file://, 169.254.169.254, 10.0.0.5
    return Response(r.content, r.status_code)   # raw internal body reflected back
```

Problems: no scheme check (`file://` allowed), no IP validation (loopback/metadata/private reachable), redirects auto-followed, DNS re-resolved by the client (rebinding), and the raw response is reflected to the caller.

### Secure
```python
import ipaddress, socket
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_SCHEMES = {'https'}
MAX_BYTES = 1_000_000
TIMEOUT = 5

def is_blocked_ip(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
    # is_link_local covers 169.254.169.254; is_private covers RFC1918; IPv6 handled too

def resolve_safe_ip(host):
    infos = socket.getaddrinfo(host, None)
    ips = {info[4][0] for info in infos}
    if not ips:
        raise ValueError('no address')
    for ip in ips:                         # every answer must be safe
        if is_blocked_ip(ip):
            raise ValueError(f'blocked address: {ip}')
    return next(iter(ips))                 # pin this exact IP for the connection

@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')
    parts = urlparse(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:     # no file://, gopher://, ...
        return jsonify(error='scheme not allowed'), 400
    if not parts.hostname:
        return jsonify(error='invalid url'), 400
    try:
        ip = resolve_safe_ip(parts.hostname)            # validate resolved IP
    except ValueError:
        return jsonify(error='destination not allowed'), 400

    # Connect to the validated IP, preserve Host + SNI, refuse redirects, bound size
    port = parts.port or 443
    pinned = f'https://{ip}:{port}{parts.path or "/"}'
    headers = {'Host': parts.hostname}
    r = requests.get(pinned, headers=headers, timeout=TIMEOUT,
                     allow_redirects=False, stream=True,
                     verify=True, server_hostname=parts.hostname)  # SNI kept via adapter
    if r.is_redirect:
        return jsonify(error='redirects not permitted'), 400

    body = b''
    for chunk in r.iter_content(8192):
        body += chunk
        if len(body) > MAX_BYTES:
            return jsonify(error='response too large'), 502
    return jsonify(status=r.status_code, length=len(body))  # controlled result, not raw body
```

Note: pinning to the IP while preserving the original `Host` and TLS SNI usually needs a small custom adapter or a purpose-built SSRF-safe client; the intent shown is "validate and connect to the same address, and never re-resolve the hostname."

## Express (Node.js)

### Vulnerable
```javascript
const express = require('express');
const app = express();

app.get('/fetch', async (req, res) => {
    const url = req.query.url;              // attacker-controlled
    const upstream = await fetch(url);      // follows redirects, any scheme/IP
    const body = await upstream.text();
    res.send(body);                         // raw internal response reflected back
});

app.listen(3000);
```

### Secure
```javascript
const express = require('express');
const dns = require('dns').promises;
const net = require('net');
const app = express();

const ALLOWED_SCHEMES = new Set(['https:']);
const MAX_BYTES = 1_000_000;

function isBlockedIp(ip) {
    // Normalize IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) to its IPv4 form
    if (ip.startsWith('::ffff:') && net.isIPv4(ip.slice(7))) ip = ip.slice(7);
    if (net.isIPv4(ip)) {
        const [a, b] = ip.split('.').map(Number);
        return (a === 127 || a === 10 || a === 0 ||
                (a === 169 && b === 254) ||           // link-local incl. 169.254.169.254
                (a === 172 && b >= 16 && b <= 31) ||
                (a === 192 && b === 168));
    }
    // IPv6: block loopback, unique-local (fc00::/7), link-local (fe80::/10)
    const lo = ip.toLowerCase();
    return lo === '::1' || lo.startsWith('fc') || lo.startsWith('fd') || lo.startsWith('fe80');
}

app.get('/fetch', async (req, res) => {
    let parsed;
    try { parsed = new URL(req.query.url); } catch { return res.status(400).json({ error: 'invalid url' }); }
    if (!ALLOWED_SCHEMES.has(parsed.protocol)) {         // no file:, gopher:, ...
        return res.status(400).json({ error: 'scheme not allowed' });
    }

    let addrs;
    try { addrs = await dns.lookup(parsed.hostname, { all: true }); }
    catch { return res.status(400).json({ error: 'resolve failed' }); }
    if (addrs.some(a => isBlockedIp(a.address))) {        // every answer must be safe
        return res.status(400).json({ error: 'destination not allowed' });
    }
    const pinnedIp = addrs[0].address;                   // pin the validated IP

    // Connect to the pinned IP, keep the Host header, refuse redirects, bound size
    const upstream = await fetch(`https://${pinnedIp}${parsed.pathname}`, {
        headers: { Host: parsed.hostname },
        redirect: 'manual',                              // do NOT follow redirects
        signal: AbortSignal.timeout(5000),
    });
    if ([301, 302, 303, 307, 308].includes(upstream.status)) {
        return res.status(400).json({ error: 'redirects not permitted' });
    }

    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length > MAX_BYTES) return res.status(502).json({ error: 'response too large' });
    res.json({ status: upstream.status, length: buf.length });  // controlled result
});

app.listen(3000);
```

## Java (Spring)

### Vulnerable
```java
@RestController
class FetchController {

    @GetMapping("/fetch")
    public ResponseEntity<String> fetch(@RequestParam String url) throws Exception {
        // URL taken verbatim: any scheme, any IP, redirects followed by default
        String body = new RestTemplate().getForObject(url, String.class);
        return ResponseEntity.ok(body);          // raw internal body reflected back
    }
}
```

### Secure
```java
@RestController
class FetchController {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("https");
    private static final int MAX_BYTES = 1_000_000;

    private boolean isBlocked(InetAddress addr) {
        return addr.isLoopbackAddress()          // 127.0.0.0/8, ::1
            || addr.isLinkLocalAddress()         // 169.254.0.0/16 incl. 169.254.169.254, fe80::/10
            || addr.isSiteLocalAddress()         // 10/8, 172.16/12, 192.168/16
            || addr.isAnyLocalAddress()          // 0.0.0.0, ::
            || addr.isMulticastAddress();
    }

    @GetMapping("/fetch")
    public ResponseEntity<?> fetch(@RequestParam String url) throws Exception {
        URI uri = URI.create(url);
        if (uri.getScheme() == null || !ALLOWED_SCHEMES.contains(uri.getScheme().toLowerCase()))
            return ResponseEntity.badRequest().body("scheme not allowed");   // no file:, gopher:
        String host = uri.getHost();
        if (host == null) return ResponseEntity.badRequest().body("invalid url");

        // Resolve and validate EVERY address; pick a validated one to pin
        InetAddress[] addrs = InetAddress.getAllByName(host);
        for (InetAddress a : addrs)
            if (isBlocked(a)) return ResponseEntity.badRequest().body("destination not allowed");
        InetAddress pinned = addrs[0];

        // Client that does NOT follow redirects, with timeouts; connect to the pinned IP
        HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)      // redirect-to-internal blocked
            .connectTimeout(Duration.ofSeconds(5))
            .build();
        URI pinnedUri = new URI("https", null, pinned.getHostAddress(),
                                uri.getPort(), uri.getPath(), uri.getQuery(), null);
        HttpRequest req = HttpRequest.newBuilder(pinnedUri)
            .header("Host", host)                            // preserve original Host
            .timeout(Duration.ofSeconds(5))
            .GET().build();

        HttpResponse<byte[]> resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (resp.body().length > MAX_BYTES)
            return ResponseEntity.status(502).body("response too large");
        return ResponseEntity.ok(Map.of("status", resp.statusCode(),
                                        "length", resp.body().length));  // controlled result
    }
}
```

## What Changed, and Why

| Concern | Vulnerable | Secure |
|---------|-----------|--------|
| Scheme | Any (`file://`, `gopher://` allowed) | Allow-list: `https` only |
| Destination | Hostname used verbatim, no IP check | Resolve, reject private/loopback/link-local/reserved |
| DNS rebinding | Client re-resolves independently | Validated IP is pinned for the connection |
| Redirects | Followed automatically | Refused (or would be re-validated per hop) |
| Response | Raw upstream body reflected | Size-limited, controlled result only |
| Timeouts | None | Connect + read timeouts on every request |

## Next Steps

- **[How to Implement](prevention.md)**: The full layered SSRF defense
- **[Threats Addressed](attack-vectors.md)**: How these fetches are exploited when unprotected
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply SSRF-safe URL handling hands-on
