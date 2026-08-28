# API10: Unsafe Consumption of APIs - Overview

## Table of Contents
- [What is Unsafe Consumption of APIs?](#what-is-unsafe-consumption-of-apis)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Unsafe Consumption of APIs?

**Unsafe Consumption of APIs** occurs when an application blindly trusts data received from third-party or upstream APIs and processes it without the same validation, sanitization, and transport controls it applies to direct user input. Developers instinctively trust data returned by a partner API, an identity provider, a payment processor, or an internal microservice far more than data typed by an end user — and that misplaced trust is exactly what makes the integration a soft target.

The threat is a shift in perspective. Instead of attacking your API directly, an attacker attacks (or impersonates, or sits in the middle of) a service that *your* API consumes. If they can compromise that upstream service, tamper with its responses in transit, or trick your API into calling an attacker-controlled endpoint, then their malicious payload arrives pre-trusted — flowing straight into your database, your templates, your deserializers, and your business logic.

### Core Concept

```
Safe Consumption of a Third-Party API
  ✓ Validate and schema-check every field of the response
  ✓ Sanitize/encode upstream data before storage or rendering
  ✓ Treat response codes and flags as untrusted claims
  ✓ Enforce TLS with certificate validation on the integration
  ✓ Set timeouts and response-size limits
  ✓ Do not blindly follow redirects to new hosts

Unsafe Consumption of a Third-Party API
  ✗ Blindly trust the upstream response body
  ✗ No validation because "it came from our partner"
  ✗ Assume a 200 OK or {"status":"success"} is authentic
  ✗ Plain HTTP, or TLS with verification disabled
  ✗ Follow arbitrary redirects to arbitrary hosts
  ✗ Pass the response straight into SQL / HTML / a deserializer
```

```
Normal flow:
  Your API  --HTTPS-->  Partner API      returns {"name": "Alice"}
  Your API  stores/renders "Alice"        Result: works fine

Attack flow (partner compromised or MITM):
  Your API  --HTTP-->   Partner API (evil) returns {"name": "'); DROP TABLE users;--"}
  Your API  concatenates into SQL          Result: injection in YOUR database
```

### Why It's Critical for APIs

Modern APIs are rarely standalone. They are woven into a mesh of upstream dependencies, and each integration expands the trust boundary:

- They fan out to many third-party services by design (payments, IdPs, CRMs, geocoding, notifications).
- Integration code is often written once, quickly, and never revisited or threat-modeled.
- The upstream service sits *outside* your security controls — you cannot patch it, audit it, or guarantee it has not been breached.
- Data from an integration is usually deserialized and consumed automatically, with no human in the loop.
- A single compromised partner can poison every customer of that partner simultaneously (a supply-chain multiplier).

## Why Does This Matter?

### The Business Impact

- **Supply-Chain Compromise**: A breached vendor becomes an injection point into your platform and every one of your users.
- **Data Injection & Poisoning**: Malicious records from an upstream feed silently corrupt your database.
- **Customer Data Theft**: Skimming or exfiltration through a trusted integration (the classic Magecart pattern).
- **Business-Logic Bypass**: Forged "payment succeeded" or "user verified" responses grant unpaid access or elevated privileges.
- **Regulatory & Compliance Exposure**: PCI-DSS, GDPR, and HIPAA penalties when a third-party integration leaks protected data.
- **Reputational Damage**: Customers rarely distinguish "we were hacked" from "our vendor was hacked."

### The Technical Impact

- **SQL / NoSQL Injection**: Upstream data concatenated into queries.
- **Stored / Reflected XSS**: Third-party HTML or text rendered without encoding.
- **Insecure Deserialization & RCE**: Partner payloads deserialized into live objects.
- **XXE**: Third-party XML parsed with external entities enabled.
- **SSRF & Pivoting**: Following upstream-supplied URLs/redirects into your internal network.
- **Denial of Service**: Oversized, slow, or malformed responses exhausting memory, threads, or connections.
- **Command Injection**: Upstream fields passed to shell commands or template engines.

## Technical Context

API10 is fundamentally about a broken assumption: **"the other side of the integration is safe."** Four recurring weaknesses turn that assumption into an exploitable vulnerability.

### 1. Blind Trust in Third-Party Responses

```python
# VULNERABLE - trusts CRM data directly in a query
crm = requests.get('https://crm-partner.com/api/users').json()
for user in crm['users']:
    db.execute(f"INSERT INTO users (name, email) "
               f"VALUES ('{user['name']}', '{user['email']}')")
```

A compromised partner returning `"'); DROP TABLE users;--"` in a name field now runs SQL inside *your* database.

### 2. Insecure Integration Transport

Integrations are frequently configured with plain HTTP, or with TLS certificate verification disabled "to make it work" — and that setting ships to production.

```javascript
// VULNERABLE - TLS verification turned off
const agent = new https.Agent({ rejectUnauthorized: false });
const res = await axios.get('https://partner.example/data', { httpsAgent: agent });
```

### 3. Blindly Following Redirects

```python
# Partner responds 302 -> http://169.254.169.254/latest/meta-data/
# Default client follows it and returns cloud metadata to the attacker
requests.get(partner_url)          # allow_redirects=True by default
```

### 4. No Input Validation on Upstream Data

Even honest partners send malformed, oversized, or unexpected data. Without a schema, a type check, or a size cap, a single bad response can crash a worker (DoS), overwrite fields, or smuggle unexpected keys into your objects. Identity-provider claims (`name`, `email`, `picture`) feel authoritative but are attacker-influenceable and must be treated as untrusted.

### Common Unsafe-Consumption Scenarios

**Payment confirmation trust**
```python
# VULNERABLE - trusts an interceptable "success" flag
resp = requests.post('https://pay-partner.com/charge', json=req.json)
if resp.json().get('status') == 'success':
    grant_access(req.json['user_id'])   # forgeable without a signature check
```

**Webhook ingestion**
```python
# VULNERABLE - anyone who knows the URL can POST a fake event
@app.post('/webhooks/orders')
def ingest():
    event = request.json          # no signature verification
    fulfill_order(event['order_id'])
```

**IdP claims used unsanitized**
```python
# VULNERABLE - IdP-provided display name rendered into HTML
profile = oidc_userinfo(token)
return f"<h1>Welcome {profile['name']}</h1>"   # stored/reflected XSS
```

## Real-World Impact

The most damaging real-world cases of unsafely consuming a third party are the **Magecart** supply-chain attacks of 2018, where victims trusted content and services delivered by a compromised third party. These are well-documented and publicly reported.

### Case Study 1: British Airways (2018)

**What happened**:
- Attackers compromised a third-party script used on BA's website/mobile flow and injected card-skimming code.
- Because the site trusted the third-party integration, the malicious script ran with full access to the payment form.
- Payment details for roughly 380,000+ transactions were exfiltrated to an attacker-controlled domain.

**Impact**:
- Hundreds of thousands of customers' names, card numbers, expiry dates, and CVVs harvested.
- The UK ICO ultimately fined British Airways £20 million (originally proposed far higher, then reduced).
- Root cause: trusting third-party code/content without integrity controls (SRI, strict CSP).

### Case Study 2: Ticketmaster UK (2018)

**What happened**:
- A JavaScript component from a third-party support/chatbot supplier (Inbenta) was compromised.
- The tampered script was loaded on Ticketmaster payment pages, skimming card data as customers typed it.

**Impact**:
- Tens of thousands of UK customers affected; fraudulent transactions followed.
- The ICO fined Ticketmaster £1.25 million, citing failure to manage risk from a third-party integration.

### Case Study 3: Newegg (2018)

**What happened**:
- Magecart operators injected a small skimming script into Newegg's checkout flow.
- The skimmer captured card details and sent them to a look-alike attacker domain.

**Impact**:
- Card data was skimmed while the code was live — publicly reported as roughly a month in 2018 (mid-August to mid-September), *not* the much longer window sometimes miscited.
- Reinforces the pattern: a trusted, embedded third-party resource becomes the breach vector.

> **Note on attribution**: These are client-side supply-chain compromises, but they illustrate the exact API10 failure mode — *a system trusting a third party it does not control*. The same trust failure applies server-to-server when your API consumes a partner API, IdP, or webhook. Where a specific CVE or precise figure could not be verified, this lesson deliberately avoids inventing one.

## Prevalence and Statistics

API10:2023 was introduced in the OWASP API Security Top 10 specifically because integrations were a fast-growing and under-defended attack surface. Unlike older categories, it has comparatively few "named" CVEs of its own — the risk usually manifests *through* another vulnerability class (injection, XSS, SSRF, deserialization) that the upstream data triggers. Rather than cite invented percentages, here is what is well-supported:

- Modern applications commonly depend on **dozens to hundreds** of third-party APIs and packages; each is a trust relationship that can be abused.
- Supply-chain and third-party-integration attacks have grown sharply in industry reporting year over year.
- Integration code is under-tested relative to user-facing endpoints, because "internal" and "partner" traffic is assumed trustworthy.
- TLS-verification-disabled settings and default redirect-following are frequently found in real integration code during audits.

> **Accuracy note**: For API10 no equally authoritative, verifiable dataset of exploitation percentages exists, so this page intentionally describes prevalence qualitatively instead of fabricating precise figures.

## Common Misunderstandings

### Myth 1: "It's our partner's API, so the data is safe"
**Reality**: You do not control the partner's security. A breached partner, a rogue insider, or a MITM all produce a "trusted" response containing hostile data. Validate upstream data like user input.

### Myth 2: "We use HTTPS, so responses can't be tampered with"
**Reality**: HTTPS only helps if certificate verification is enabled. Many integrations disable it or fall back to HTTP. And HTTPS does nothing about a genuinely compromised upstream.

### Myth 3: "A 200 OK / status:success means it really succeeded"
**Reality**: Status codes and JSON flags are unauthenticated claims. Without a signature (webhook HMAC) or a server-to-server verification call, they are trivially forgeable.

### Myth 4: "We only read the data, we don't execute it"
**Reality**: Reading data into a SQL query, an HTML template, an XML parser, or a deserializer *is* execution in disguise.

### Myth 5: "Following redirects is convenient and harmless"
**Reality**: An upstream redirect can point at internal infrastructure (SSRF), cloud metadata, or an attacker host serving a poisoned body.

### Myth 6: "Schema validation is only for user-facing endpoints"
**Reality**: Upstream responses are exactly where a strict schema pays off — it rejects malformed, oversized, and unexpected data before it reaches your logic.

## How API10 Relates to Other Risks

| Aspect | API10 Unsafe Consumption | API07 SSRF | Injection (A03) |
|--------|--------------------------|------------|-----------------|
| **Trigger source** | Data from a trusted third party | User-supplied URL fetched by server | User-supplied data in a sink |
| **Root cause** | Misplaced trust in upstream | Missing URL validation | Missing input sanitization |
| **Typical outcome** | Injection/XSS/RCE via partner | Internal access, metadata theft | Data theft, tampering |
| **Fix** | Validate upstream like user input | Allowlist + block internal ranges | Parameterize + encode |

## Unsafe-Consumption Attack Chain

```
1. Identify an Integration
   ↓
2. Gain Influence Over the Response (compromise / MITM / forge / redirect)
   ↓
3. Inject a Trusted Payload (SQL, HTML, XML, serialized object, internal URL)
   ↓
4. Trigger the Sink (store, render, parse, deserialize, re-request)
   → injection / XSS / XXE / RCE / SSRF / DoS
   ↓
5. Expand Impact (poison every customer of the compromised partner)
```

## Key Takeaways

1. **Trust boundaries include your integrations** — upstream data is untrusted input.
2. **Validate and schema-check every third-party response** before using it.
3. **Enforce TLS with certificate verification** on every integration call.
4. **Do not blindly follow redirects** from upstream services.
5. **Verify success claims cryptographically** (signatures, HMAC, server-side checks).
6. **Set timeouts and response-size limits** to blunt DoS from bad responses.
7. **Assume any partner can be compromised** and design so the blast radius is contained.

## How to Identify if You're Vulnerable

- [ ] Do we call third-party APIs, IdPs, or webhooks?
- [ ] Do we validate and schema-check their responses?
- [ ] Do we sanitize/encode upstream data before storing or rendering it?
- [ ] Is TLS certificate verification enforced on every integration?
- [ ] Do our HTTP clients follow redirects automatically?
- [ ] Do we verify webhook/payment success with signatures, not just flags?
- [ ] Do we set timeouts and cap response sizes?
- [ ] Do we parameterize queries built from upstream data?
- [ ] Do we allowlist the endpoints our integrations may talk to?
- [ ] Do we monitor and alert on anomalous upstream responses?

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: Learn how attackers exploit unsafe consumption of APIs
- **[Prevention](prevention.md)**: Implement layered defenses for safe API consumption
- **[Examples](examples.md)**: See vulnerable and secure code across frameworks
- **[Hands-On Lab](lab/api10-unsafe-consumption-lab/)**: Practice detecting and preventing unsafe API consumption
