# API10: Unsafe Consumption of APIs - Code Examples

Each example consumes a third-party API response. The **vulnerable** version trusts it; the **secure** version enforces TLS, disables blind redirects, schema-validates the data, and parameterizes/encodes it at the sink.

## Flask (Python)

### Vulnerable
```python
@app.route('/import-users', methods=['POST'])
def import_users():
    # No TLS check, follows redirects, no validation, string-built SQL
    data = requests.get('https://crm-partner.com/users').json()
    for u in data['users']:
        db.execute(f"INSERT INTO users(name,email) "
                   f"VALUES('{u['name']}','{u['email']}')")   # SQLi via upstream
    return jsonify(ok=True)
```

### Secure
```python
from pydantic import BaseModel, EmailStr, constr, ValidationError

ALLOWED = {'crm-partner.com'}

class PUser(BaseModel):
    name: constr(max_length=100)
    email: EmailStr                      # role is NOT accepted from upstream

def fetch_json(url, max_bytes=1_000_000):
    host = urllib.parse.urlparse(url).hostname
    if host not in ALLOWED:
        raise ValueError('host not allowlisted')
    r = requests.get(url, timeout=5, verify=True, allow_redirects=False, stream=True)
    if r.is_redirect:
        raise ValueError('unexpected redirect')
    total, buf = 0, b''
    for c in r.iter_content(8192):
        total += len(c)
        if total > max_bytes:
            raise ValueError('response too large')
        buf += c
    return json.loads(buf)

@app.route('/import-users', methods=['POST'])
def import_users_secure():
    try:
        data = fetch_json('https://crm-partner.com/users')
        users = [PUser(**u) for u in data['users']]     # schema-validate
    except (ValidationError, ValueError, KeyError) as e:
        return jsonify(error=str(e)), 400
    for u in users:
        db.execute("INSERT INTO users(name,email) VALUES(%s,%s)",
                   (u.name, u.email))                    # parameterized
    return jsonify(ok=True)
```

## Express (Node.js)

### Vulnerable
```javascript
app.get('/weather', async (req, res) => {
  const { data } = await axios.get('https://weather-partner.com/now');
  // Renders upstream text straight into HTML -> XSS if partner compromised
  res.send(`<div>Weather: ${data.description}</div>`);
});
```

### Secure
```javascript
const https = require('https');
const { z } = require('zod');
const ALLOWED = new Set(['weather-partner.com']);
const Weather = z.object({ description: z.string().max(200) });

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

app.get('/weather', async (req, res) => {
  try {
    const url = new URL('https://weather-partner.com/now');
    if (!ALLOWED.has(url.hostname)) throw new Error('host not allowlisted');
    const { data } = await axios.get(url.toString(), {
      timeout: 5000, maxRedirects: 0, maxContentLength: 1_000_000,
      httpsAgent: new https.Agent({ rejectUnauthorized: true })   // enforce TLS
    });
    const w = Weather.parse(data);                    // schema-validate
    res.send(`<div>Weather: ${escapeHtml(w.description)}</div>`);  // encode
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
```

## Spring Boot (Java)

### Vulnerable
```java
@PostMapping("/sync")
public ResponseEntity<?> sync() {
    RestTemplate rest = new RestTemplate();            // follows redirects, no timeout
    Partner p = rest.getForObject("https://partner.com/data", Partner.class);
    jdbc.execute("UPDATE acct SET tier='" + p.getTier() + "'");  // injection
    return ResponseEntity.ok().build();
}
```

### Secure
```java
private static final Set<String> ALLOWED = Set.of("partner.com");

@PostMapping("/sync")
public ResponseEntity<?> syncSecure() {
    try {
        URI uri = URI.create("https://partner.com/data");
        if (!ALLOWED.contains(uri.getHost()))
            return ResponseEntity.badRequest().body("host not allowlisted");

        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5000);
        factory.setReadTimeout(5000);
        RestTemplate rest = new RestTemplate(factory);

        Partner p = rest.getForObject(uri, Partner.class);
        String tier = p.getTier();
        if (!Set.of("free", "pro", "enterprise").contains(tier))   // validate
            return ResponseEntity.badRequest().body("invalid tier");

        jdbc.update("UPDATE acct SET tier = ?", tier);             // parameterized
        return ResponseEntity.ok().build();
    } catch (Exception e) {
        return ResponseEntity.badRequest().body(e.getMessage());
    }
}
```

## ASP.NET Core (C#)

### Vulnerable
```csharp
[HttpPost("webhook")]
public async Task<IActionResult> Webhook() {
    using var reader = new StreamReader(Request.Body);
    var body = await reader.ReadToEndAsync();
    var e = JsonSerializer.Deserialize<PayEvent>(body);  // no signature check
    if (e.Status == "success") GrantAccess(e.UserId);    // forgeable
    return Ok();
}
```

### Secure
```csharp
[HttpPost("webhook")]
public async Task<IActionResult> WebhookSecure() {
    using var reader = new StreamReader(Request.Body);
    var body = await reader.ReadToEndAsync();

    // Verify provider HMAC before trusting anything
    var sig = Request.Headers["X-Signature"].ToString();
    var expected = Convert.ToHexString(
        new HMACSHA256(_secret).ComputeHash(Encoding.UTF8.GetBytes(body)))
        .ToLowerInvariant();
    if (!CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(sig)))
        return Unauthorized();

    PayEvent e;
    try { e = JsonSerializer.Deserialize<PayEvent>(body); }
    catch { return BadRequest("malformed"); }
    if (e is null || e.UserId <= 0) return BadRequest("invalid");

    if (e.Status == "success") GrantAccess(e.UserId);   // now trustworthy
    return Ok();
}
```

## Secure Consumption Checklist

- Allowlist the host, enforce `verify=True` / `rejectUnauthorized: true`.
- Set timeouts, cap response size, disable auto-redirects.
- Schema-validate the body; reject unexpected fields (never accept upstream `role`).
- Parameterize SQL, encode HTML, disable XML entities, avoid untrusted deserialization.
- Verify webhooks/success with HMAC signatures, not status flags.

## Next Steps

- **[Overview](overview.md)**: Core concept and real-world impact
- **[Prevention](prevention.md)**: Full layered-defense guide
- **[Hands-On Lab](lab/api10-unsafe-consumption-lab/)**: Practice safe API consumption
