# API07: Server Side Request Forgery - Code Examples

## Flask (Python)

### Vulnerable
```python
@app.route('/api/fetch', methods=['POST'])
def fetch():
    url = request.json['url']
    return jsonify(requests.get(url).json())  # VULNERABLE!
```

### Secure
```python
import ipaddress
import socket

ALLOWED_DOMAINS = ['api.example.com']

def validate_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        return False
    hostname = parsed.hostname
    if not any(hostname.endswith(d) for d in ALLOWED_DOMAINS):
        return False
    ip = ipaddress.ip_address(socket.gethostbyname(hostname))
    if ip.is_private or ip.is_loopback:
        return False
    return True

@app.route('/api/fetch', methods=['POST'])
def fetch_secure():
    url = request.json['url']
    if not validate_url(url):
        return jsonify({'error': 'Invalid URL'}), 400
    return jsonify(requests.get(url, timeout=5, allow_redirects=False).json())
```

## Express (Node.js)

### Vulnerable
```javascript
app.post('/api/fetch', async (req, res) => {
    const data = await axios.get(req.body.url);
    res.json(data.data);
});
```

### Secure
```javascript
const ALLOWED_DOMAINS = ['api.example.com'];

async function validateUrl(url) {
    const parsed = new URL(url);
    if (!ALLOWED_DOMAINS.some(d => parsed.hostname.endsWith(d))) {
        throw new Error('Domain not allowed');
    }
    const addr = ipaddr.parse((await dns.resolve4(parsed.hostname))[0]);
    if (addr.range() !== 'unicast') {
        throw new Error('Private IP');
    }
}

app.post('/api/fetch', async (req, res) => {
    try {
        await validateUrl(req.body.url);
        const data = await axios.get(req.body.url, {timeout: 5000, maxRedirects: 0});
        res.json(data.data);
    } catch(e) {
        res.status(400).json({error: e.message});
    }
});
```

## Spring Boot (Java)

### Vulnerable
```java
@PostMapping("/fetch")
public ResponseEntity<?> fetch(@RequestBody Map<String, String> body) {
    String url = body.get("url");
    RestTemplate rest = new RestTemplate();
    return ResponseEntity.ok(rest.getForObject(url, String.class));
}
```

### Secure
```java
private static final List<String> ALLOWED_DOMAINS = Arrays.asList("api.example.com");

private boolean validateUrl(String urlString) throws Exception {
    URL url = new URL(urlString);
    if (!ALLOWED_DOMAINS.stream().anyMatch(d -> url.getHost().endsWith(d))) {
        return false;
    }
    InetAddress addr = InetAddress.getByName(url.getHost());
    return !addr.isLoopbackAddress() && !addr.isLinkLocalAddress() && !addr.isSiteLocalAddress();
}

@PostMapping("/fetch")
public ResponseEntity<?> fetchSecure(@RequestBody Map<String, String> body) {
    try {
        String url = body.get("url");
        if (!validateUrl(url)) {
            return ResponseEntity.badRequest().body("Invalid URL");
        }
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5000);
        factory.setReadTimeout(5000);
        RestTemplate rest = new RestTemplate(factory);
        return ResponseEntity.ok(rest.getForObject(url, String.class));
    } catch (Exception e) {
        return ResponseEntity.badRequest().body(e.getMessage());
    }
}
```

## ASP.NET Core (C#)

### Vulnerable
```csharp
[HttpPost("fetch")]
public async Task<IActionResult> Fetch([FromBody] FetchRequest req) {
    using var client = new HttpClient();
    var data = await client.GetStringAsync(req.Url);
    return Ok(data);
}
```

### Secure
```csharp
private static readonly List<string> AllowedDomains = new() { "api.example.com" };

private async Task<bool> ValidateUrl(string urlString) {
    var uri = new Uri(urlString);
    if (!AllowedDomains.Any(d => uri.Host.EndsWith(d)))  return false;
    var addresses = await Dns.GetHostAddressesAsync(uri.Host);
    var addr = addresses[0];
    return !IPAddress.IsLoopback(addr) && !addr.IsIPv6LinkLocal;
}

[HttpPost("fetch")]
public async Task<IActionResult> FetchSecure([FromBody] FetchRequest req) {
    if (!await ValidateUrl(req.Url))
        return BadRequest("Invalid URL");
    
    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    var data = await client.GetStringAsync(req.Url);
    return Ok(data);
}
```
