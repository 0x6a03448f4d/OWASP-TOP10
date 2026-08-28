# API10: Unsafe Consumption of APIs - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Validate & Schema-Check Upstream Data](#validate--schema-check-upstream-data)
- [Secure the Transport](#secure-the-transport)
- [Control Requests & Redirects](#control-requests--redirects)
- [Sink-Specific Defenses](#sink-specific-defenses)
- [Monitoring & Detection](#monitoring--detection)

## Prevention Strategy Overview

Safe consumption rests on one rule: **treat every third-party response as untrusted input**, and defend in layers.

1. Validate and schema-check upstream data.
2. Secure the transport (TLS verification, optional pinning, allowlisted hosts).
3. Control the request itself (timeouts, size limits, no blind redirects).
4. Defend the sink (parameterize, encode, safe parsers, no untrusted deserialization).
5. Monitor, verify signatures, and contain blast radius.

### Core Principles
- **Zero implicit trust**: origin is not authenticity; a partner can be compromised.
- **Verify, don't assume**: signatures and schemas over status flags.
- **Least privilege & isolation**: sandbox integration processing; minimize what it can reach.
- **Fail closed**: reject malformed/oversized/unexpected responses.

## Validate & Schema-Check Upstream Data

### Schema Validation First
Reject anything that does not match an explicit, strict schema before your logic touches it. This neutralizes malformed-data DoS, unexpected-key mass assignment, and type-confusion bugs.

```python
from pydantic import BaseModel, EmailStr, constr, ValidationError

class PartnerUser(BaseModel):
    name: constr(max_length=100)      # bounded length
    email: EmailStr
    role: str = "user"                # never accept an upstream-supplied role

def parse_users(payload: dict) -> list[PartnerUser]:
    try:
        return [PartnerUser(**u) for u in payload["users"]]
    except (ValidationError, KeyError, TypeError):
        raise ValueError("Upstream response failed validation")  # fail closed
```

### Sanitize/Encode Like User Input
```python
import bleach
safe_name = bleach.clean(user.name)   # strip HTML/JS; also context-encode at output
```

### Never Trust Success Flags — Verify Them
```python
import hmac, hashlib

def verify_webhook(secret: bytes, body: bytes, signature: str) -> bool:
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)   # constant-time
```

## Secure the Transport

### Always Enforce TLS Verification
```python
requests.get(url, timeout=5, verify=True)   # NEVER verify=False in prod
```
```javascript
const agent = new https.Agent({ rejectUnauthorized: true });   // default; keep it
```

### Consider Certificate / Public-Key Pinning for Critical Partners
Pin a partner's expected certificate fingerprint to defend against MITM and CA compromise. Rotate pins with the partner's cert lifecycle to avoid outages.

### Allowlist Integration Endpoints
```python
ALLOWED_HOSTS = {"api.payments.com", "idp.example.com", "crm-partner.com"}

def assert_allowed(url: str):
    host = urllib.parse.urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Endpoint not allowlisted: {host}")
```

## Control Requests & Redirects

### Timeouts and Response-Size Limits
```python
def fetch_json(url, max_bytes=1_000_000, timeout=5):
    assert_allowed(url)
    r = requests.get(url, timeout=timeout, allow_redirects=False, stream=True)
    total, chunks = 0, []
    for c in r.iter_content(8192):
        total += len(c)
        if total > max_bytes:
            raise ValueError("Upstream response too large")   # DoS guard
        chunks.append(c)
    return json.loads(b"".join(chunks))
```

### Do Not Blindly Follow Redirects
```python
r = requests.get(url, allow_redirects=False, timeout=5)
if r.is_redirect:
    target = r.headers.get("Location", "")
    assert_allowed(target)            # re-validate every hop against the allowlist
```

### Block Internal Ranges on Any Followed Host
```python
import ipaddress, socket
def is_public(host: str) -> bool:
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
```

## Sink-Specific Defenses

### SQL: Always Parameterize
```python
db.execute("INSERT INTO users(name,email) VALUES(%s,%s)", (u.name, u.email))
```

### HTML: Context-Aware Output Encoding
```javascript
res.send(`<div>Today: ${escapeHtml(weather.description)}</div>`);
```

### XML: Disable External Entities
```python
parser = etree.XMLParser(resolve_entities=False, no_network=True,
                         dtd_validation=False, load_dtd=False)
doc = etree.fromstring(partner_xml, parser)   # XXE-safe
```

### Deserialization: Use Safe Formats Only
```python
# NEVER pickle.loads / native Java/.NET deserialization on partner data.
data = json.loads(body)
model = PartnerUser(**data)      # then schema-validate
```

### Sandbox & Least Privilege for Integration Processing
- Run integration workers with minimal IAM/network permissions.
- Process partner content in an isolated service/container so a compromise is contained.
- Egress-filter outbound traffic so a poisoned integration can't exfiltrate freely.

## Monitoring & Detection

### Log and Alert on Anomalous Responses
```python
def consume(url):
    r = fetch_json(url)
    log.info("upstream", host=urlparse(url).hostname, size=len(str(r)), status="ok")
    # Alert on: schema-validation failures, unexpected redirects,
    # response-size spikes, new/unknown fields, latency anomalies.
    return r
```

### Detect Integration Abuse Patterns
```python
def flag(url, resp):
    alerts = []
    if any(x in url for x in ("169.254.169.254", "localhost", "127.0.0.1")):
        alerts.append("integration pointed at internal/metadata host")
    if resp.get("role") == "admin":
        alerts.append("upstream attempted to set privileged field")
    if alerts:
        send_security_alert(alerts, url)
    return alerts
```

### Operational Controls
- **Pin and review dependencies** (SRI for browser scripts, lockfiles + signature verification for packages).
- **Rotate integration credentials** and scope them tightly.
- **Circuit-breakers & rate limits** on outbound calls to blunt DoS and runaway retries.
- **Contract tests** against partner schemas so unexpected changes fail fast.

## Framework Quick-Reference

### Flask (Python)
```python
data = fetch_json(url)                     # allowlist + size cap + no redirect
users = [PartnerUser(**u) for u in data["users"]]   # schema validation
db.execute("INSERT INTO users(name,email) VALUES(%s,%s)", (users[0].name, users[0].email))
```

### Express (Node.js)
```javascript
const { data } = await axios.get(url, {
  timeout: 5000, maxRedirects: 0, maxContentLength: 1_000_000,
  httpsAgent: new https.Agent({ rejectUnauthorized: true })
});
const user = UserSchema.parse(data);       // zod/ajv validation
```

## Key Takeaways

1. **Schema-validate every upstream response** and fail closed.
2. **Enforce TLS verification**; pin certs for critical partners.
3. **Allowlist integration hosts** and disable blind redirects.
4. **Timeouts + size limits** to stop DoS from bad responses.
5. **Parameterize, encode, and use safe parsers** at every sink.
6. **Verify success with signatures**, never bare status flags.
7. **Sandbox and monitor** integration processing to contain compromise.

## Next Steps

- **[Code Examples](examples.md)**: Full vulnerable vs. secure implementations
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Hands-On Lab](lab/api10-unsafe-consumption-lab/)**: Practice safe consumption
