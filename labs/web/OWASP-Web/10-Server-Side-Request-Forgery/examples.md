# SSRF — Vulnerable vs. Secure Examples

## Table of Contents

- [How to Read These Examples](#how-to-read-these-examples)
- [Python / Flask — Link-Preview Fetcher](#python--flask--link-preview-fetcher)
- [Node.js / Express — Image Proxy](#nodejs--express--image-proxy)
- [PHP — Import-from-URL](#php--import-from-url)
- [Java / Spring — Webhook Delivery](#java--spring--webhook-delivery)
- [Side-by-Side Comparison](#side-by-side-comparison)

## How to Read These Examples

Each example shows a realistic web feature in two forms: a **vulnerable** version that fetches a user-supplied URL naively, and a **secure** version that applies the layered defenses from the Prevention page — scheme/host/port allowlisting, resolved-IP validation, IP pinning, and disabled redirects. The security-relevant lines are commented so you can map them back to the layers.

> The secure snippets are teaching references, not drop-in libraries. In production, centralize this logic in one reviewed fetcher and, where possible, use a maintained SSRF-protection library plus network egress controls.

## Python / Flask — Link-Preview Fetcher

### Vulnerable

```python
from flask import Flask, request, Response
import requests

app = Flask(__name__)

@app.route("/preview")
def preview():
    # VULNERABLE: the user fully controls the destination URL.
    url = request.args.get("url")
    # No scheme check, no host check, follows redirects, reflects the body.
    r = requests.get(url, timeout=5)          # fetches ANYTHING, including
    return Response(r.content, mimetype="text/plain")  # 169.254.169.254, file://-ish, localhost

# GET /preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
#   -> instance credentials returned straight to the attacker.
```

### Secure

```python
from flask import Flask, request, Response, abort
from urllib.parse import urlparse
import socket, ipaddress, requests

app = Flask(__name__)
ALLOWED_SCHEMES = {"https"}
ALLOWED_PORTS = {443}
MAX_BYTES = 1_000_000

def is_blocked_ip(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    u = urlparse(url)

    if u.scheme not in ALLOWED_SCHEMES:              # Layer 5: scheme allowlist
        abort(400, "unsupported scheme")
    port = u.port or 443
    if port not in ALLOWED_PORTS:                    # Layer 1: port allowlist
        abort(400, "unsupported port")
    if not u.hostname:
        abort(400, "missing host")

    # Layer 2 + 3: resolve once, validate EVERY resolved IP
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(u.hostname, port)}
    except socket.gaierror:
        abort(400, "cannot resolve host")
    if any(is_blocked_ip(ip) for ip in addrs):
        abort(400, "destination not allowed")        # blocks metadata + internal ranges

    # Layer 4: do not follow redirects; Layer 8: cap size, generic output
    r = requests.get(url, allow_redirects=False, timeout=5, stream=True)
    if 300 <= r.status_code < 400:
        abort(400, "redirects are not followed")
    body = r.raw.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        abort(413, "response too large")
    return Response(body[:MAX_BYTES], mimetype="text/plain")
```

## Node.js / Express — Image Proxy

### Vulnerable

```javascript
const express = require("express");
const app = express();

app.get("/proxy-image", async (req, res) => {
  // VULNERABLE: fetches and streams back any URL the client provides.
  const url = req.query.url;
  const upstream = await fetch(url);            // default: follows redirects
  const buf = Buffer.from(await upstream.arrayBuffer());
  res.set("Content-Type", upstream.headers.get("content-type") || "application/octet-stream");
  res.send(buf);                                // reflects internal responses verbatim
});

// GET /proxy-image?url=http://127.0.0.1:9200/_cat/indices  -> internal Elasticsearch leaked
```

### Secure

```javascript
const express = require("express");
const dns = require("node:dns").promises;
const ipaddr = require("ipaddr.js");
const app = express();

const ALLOWED_SCHEMES = new Set(["https:"]);
const ALLOWED_PORTS = new Set(["443"]);
const BLOCKED_RANGES = new Set(
  ["private", "loopback", "linkLocal", "uniqueLocal", "reserved", "unspecified"]
);
const MAX_BYTES = 1_000_000;

function ipIsBlocked(ip) {
  let addr = ipaddr.parse(ip);
  if (addr.kind() === "ipv6" && addr.isIPv4MappedAddress()) {
    addr = addr.toIPv4Address();                     // re-check mapped IPv4
  }
  return BLOCKED_RANGES.has(addr.range());
}

app.get("/proxy-image", async (req, res) => {
  let u;
  try { u = new URL(req.query.url); } catch { return res.status(400).send("bad url"); }

  if (!ALLOWED_SCHEMES.has(u.protocol)) return res.status(400).send("scheme");   // Layer 5
  const port = u.port || "443";
  if (!ALLOWED_PORTS.has(port)) return res.status(400).send("port");             // Layer 1

  // Layer 2 + 3: resolve, validate every address, then pin it
  const records = await dns.lookup(u.hostname, { all: true });
  if (records.some(r => ipIsBlocked(r.address))) return res.status(400).send("blocked");
  const pinned = records[0].address;

  // Layer 4: manual redirect handling (do not auto-follow)
  const upstream = await fetch(`https://${pinned}${u.pathname}${u.search}`, {
    redirect: "manual",
    headers: { Host: u.hostname },                   // keep original Host for vhosts/SNI
    signal: AbortSignal.timeout(5000),               // Layer 8: timeout
  });
  if (upstream.status >= 300 && upstream.status < 400) return res.status(400).send("no redirects");

  const buf = Buffer.from(await upstream.arrayBuffer());
  if (buf.length > MAX_BYTES) return res.status(413).send("too large");           // Layer 8
  res.type("application/octet-stream").send(buf);
});
```

## PHP — Import-from-URL

### Vulnerable

```php
<?php
// VULNERABLE: import a document from any user-supplied URL.
$url = $_GET['url'];
$data = file_get_contents($url);   // honors file://, http://, ftp://, php:// wrappers!
echo $data;

// ?url=file:///etc/passwd                         -> local file disclosure
// ?url=http://169.254.169.254/latest/meta-data/   -> cloud metadata
?>
```

### Secure

```php
<?php
$ALLOWED_SCHEMES = ['https'];
$ALLOWED_PORTS   = [443];
$MAX_BYTES       = 1000000;

$url = $_GET['url'] ?? '';
$p = parse_url($url);

// Layer 5 + 1: scheme and port allowlist
if (!$p || !in_array($p['scheme'] ?? '', $ALLOWED_SCHEMES, true)) {
    http_response_code(400); exit('unsupported scheme');
}
$host = $p['host'] ?? '';
$port = $p['port'] ?? 443;
if ($host === '' || !in_array($port, $ALLOWED_PORTS, true)) {
    http_response_code(400); exit('bad host/port');
}

// Layer 2: resolve and validate EVERY address against reserved ranges
$ips = array_merge(
    gethostbynamel($host) ?: [],
    array_map(fn($r) => $r['ipv6'] ?? '', @dns_get_record($host, DNS_AAAA) ?: [])
);
foreach (array_filter($ips) as $ip) {
    // FILTER_FLAG_NO_PRIV_RANGE + NO_RES_RANGE reject private/reserved IPs
    if (!filter_var($ip, FILTER_VALIDATE_IP,
                    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        http_response_code(400); exit('destination not allowed');
    }
}

// Layer 4 + 5 + 8: curl with redirects OFF, only https, size/time caps
$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER  => true,
    CURLOPT_FOLLOWLOCATION   => false,                       // never follow redirects
    CURLOPT_PROTOCOLS        => CURLPROTO_HTTPS,             // https only, no file/gopher
    CURLOPT_TIMEOUT          => 5,
    CURLOPT_MAXFILESIZE      => $MAX_BYTES,
]);
$data = curl_exec($ch);
if ($data === false) { http_response_code(502); exit('fetch failed'); }
echo substr($data, 0, $MAX_BYTES);
?>
```

## Java / Spring — Webhook Delivery

### Vulnerable

```java
@RestController
public class WebhookController {

    // VULNERABLE: delivers to any customer-supplied callback URL.
    @PostMapping("/webhooks/test")
    public ResponseEntity<String> test(@RequestBody Map<String, String> body) throws Exception {
        String callback = body.get("url");
        HttpClient client = HttpClient.newHttpClient();     // follows redirects by default
        HttpRequest req = HttpRequest.newBuilder(URI.create(callback)).GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        return ResponseEntity.ok(resp.body());              // reflects internal response
    }
}
// { "url": "http://169.254.169.254/latest/meta-data/" } -> metadata handed back
```

### Secure

```java
@RestController
public class WebhookController {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("https");
    private static final Set<Integer> ALLOWED_PORTS = Set.of(443);
    private static final int MAX_BYTES = 1_000_000;

    private boolean isBlocked(InetAddress a) {
        return a.isLoopbackAddress() || a.isLinkLocalAddress()
            || a.isSiteLocalAddress() || a.isAnyLocalAddress()
            || a.isMulticastAddress()
            || a.getHostAddress().startsWith("169.254");    // link-local incl. metadata
    }

    @PostMapping("/webhooks/test")
    public ResponseEntity<String> test(@RequestBody Map<String, String> body) throws Exception {
        URI uri = URI.create(body.getOrDefault("url", ""));

        if (!ALLOWED_SCHEMES.contains(uri.getScheme())) {          // Layer 5
            return ResponseEntity.badRequest().body("scheme");
        }
        int port = uri.getPort() == -1 ? 443 : uri.getPort();
        if (!ALLOWED_PORTS.contains(port)) {                       // Layer 1
            return ResponseEntity.badRequest().body("port");
        }

        // Layer 2: resolve and validate EVERY address
        for (InetAddress a : InetAddress.getAllByName(uri.getHost())) {
            if (isBlocked(a)) return ResponseEntity.badRequest().body("blocked");
        }

        // Layer 4: never follow redirects; Layer 8: timeout
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        HttpRequest req = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(5)).GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() >= 300 && resp.statusCode() < 400) {
            return ResponseEntity.badRequest().body("no redirects");
        }
        // Layer 8: return a generic result, not the raw upstream body
        return ResponseEntity.ok("delivered");
    }
}
```

## Side-by-Side Comparison

| Concern | Vulnerable Pattern | Secure Pattern |
|---------|--------------------|----------------|
| Destination | Any user URL fetched as-is | Scheme + host + port allowlist |
| Host check | None, or hostname string only | Resolve DNS, validate every resolved IP |
| Rebinding | Re-resolves at connect time | Resolve once, pin the validated IP |
| Redirects | Auto-followed | Disabled or re-validated per hop |
| Schemes | file/gopher/ftp allowed by library | https only; wrappers disabled |
| Output | Raw upstream body reflected | Generic result, size/time capped |
| Metadata | 169.254.169.254 reachable | Blocked by IP validation + IMDSv2 + egress |

## Key Takeaways

1. The vulnerable versions differ by language but share one flaw: **they trust the destination**.
2. Every secure version applies the **same layers** — allowlist, resolved-IP validation, IP pinning, no redirects, restricted schemes, safe output.
3. Library defaults (follow-redirects on, all schemes/wrappers enabled) are **unsafe for user-supplied URLs**; override them.
4. Centralize this into one reviewed fetcher rather than re-implementing it at each call site.

## Next Steps

- **[Overview](./overview.md)**: What SSRF is and why it matters.
- **[Attack Vectors](./attack-vectors.md)**: The techniques these examples defend against.
- **[Prevention](./prevention.md)**: The full layered defense model.
- **[Lab](./lab/ssrf-simulation-lab/)**: Build and break these patterns safely.

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
