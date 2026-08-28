# API3:2019 Excessive Data Exposure - Overview

## Table of Contents
- [What is Excessive Data Exposure?](#what-is-excessive-data-exposure)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)
- [Self-Assessment](#self-assessment)

## What is Excessive Data Exposure?

**Excessive Data Exposure** is what happens when an API returns *more* data than the specific client actually needs, and trusts the client to filter, hide, or discard the surplus. The server serialises a whole internal object—every column of a database row, every attribute of a domain model, every nested relation—and ships it over the wire. The user interface then displays only a handful of those fields, so on screen everything looks fine. But the raw response tells a very different story: it contains the fields the UI hides, and an attacker who reads that raw JSON simply *keeps* the parts the app throws away.

The defining characteristic of API3:2019 is that **the filtering happens in the wrong place**. Presentation-layer code (a mobile app, a single-page web front end, a partner integration) is treated as a trusted security boundary. It is not. Anyone can inspect network traffic with browser dev tools, an intercepting proxy such as Burp or mitmproxy, or by pointing `curl` at the endpoint directly. The moment data leaves the server it is fully visible, regardless of what the client chooses to render.

> **In one sentence:** the endpoint is *authorised*—the user is allowed to call it—but the *response* is over-shared, leaking properties that this consumer was never meant to see.

### Core Concept

```
What the mobile app SHOWS on the profile screen:
  {
    "id": 42,
    "displayName": "Jordan Lee",
    "avatarUrl": "https://cdn.example.com/u/42.png"
  }

What the API actually RETURNS for GET /api/users/42:
  {
    "id": 42,
    "displayName": "Jordan Lee",
    "avatarUrl": "https://cdn.example.com/u/42.png",
    "email": "jordan.lee@example.com",       <- PII, not shown in UI
    "phone": "+1-202-555-0142",               <- PII, not shown in UI
    "dateOfBirth": "1991-03-08",              <- PII, not shown in UI
    "passwordHash": "$2b$12$Q8f...",          <- secret, must NEVER leave server
    "mfaSecret": "JBSWY3DPEHPK3PXP",          <- secret
    "isAdmin": false,                          <- internal authorization flag
    "internalRiskScore": 0.83,                <- internal business logic
    "stripeCustomerId": "cus_Nf1...",          <- internal 3rd-party identifier
    "preciseLat": 47.61032,                    <- exact location, UI shows "2 mi away"
    "preciseLng": -122.33207
  }
```

The client rendered three fields. The server sent thirteen. The extra ten—PII, secrets, internal flags, and precise coordinates—are the vulnerability. No exploit chain is required; the attacker just reads the response body.

### Why It's Specific to APIs

In a classic server-rendered web application, the server builds the HTML and only the finished page reaches the browser. Fields the template does not print are never transmitted. Modern APIs invert this: the server emits structured data and delegates rendering to the client. That architectural shift is exactly what makes Excessive Data Exposure an API-native problem:

- APIs return **machine-readable objects**, so "hidden" fields are trivially readable—there is no rendering step that drops them.
- Teams build **generic, reusable endpoints** ("return the user object") and let many different clients pick what they need—so every client receives the union of all fields.
- Object-Relational Mappers and auto-serializers make it **easier to return the whole model than a curated subset**, so the insecure path is the path of least resistance.
- The same endpoint is consumed by **web, mobile, and third parties** with very different trust levels, yet returns one identical, maximal payload to all of them.

## Why Does This Matter?

### Business Impact

- **Privacy Breach and Regulatory Exposure**: Leaking email, phone, date of birth, government IDs, or precise location is a reportable personal-data breach under GDPR, CCPA/CPRA, HIPAA, and similar regimes—triggering notifications, investigations, and fines even if the UI never displayed the data.
- **Account Takeover Enablement**: Exposed password hashes, MFA seeds, password-reset tokens, or session identifiers let attackers crack or replay credentials offline and seize accounts.
- **Competitive and Commercial Harm**: Internal fields such as risk scores, cost prices, margins, fraud flags, or A/B-test assignments hand competitors and fraudsters your business logic for free.
- **Mass Harvesting at Scale**: When a *list* endpoint over-shares, a single authenticated call can dump sensitive fields for thousands of records—turning one leak into a full-database scrape.
- **Trust and Reputation**: "The app never showed my home address, but the API was sending it" is a headline-grade story precisely because it is so easy for the public to understand.

### Technical Impact

- **Direct Information Disclosure**: Sensitive properties are readable in plaintext from the response body with no further exploitation.
- **Reconnaissance for Deeper Attacks**: Internal IDs, foreign keys, and object structures revealed in responses map the data model and fuel BOLA/IDOR, injection, and business-logic attacks.
- **Cross-User Leakage**: List and search endpoints that return full objects expose *other* users' sensitive fields, not just the caller's own.
- **Secret Compromise**: Tokens, API keys, and hashes in responses are immediately usable or crackable, undermining authentication entirely.
- **Silent and Persistent**: Because the app behaves normally, the leak can run for years, quietly logged in proxies, caches, CDNs, and client-side telemetry.

## Technical Context

### How the Anti-Pattern Arises

#### 1. Returning the Entire Database Object / Serialized Model

```python
# Flask + SQLAlchemy: the whole row, verbatim
@app.route('/api/users/<int:uid>')
def get_user(uid):
    user = User.query.get_or_404(uid)
    return jsonify(user.to_dict())   # to_dict() dumps EVERY column,
                                     # including password_hash, mfa_secret, is_admin
```

The developer wanted "the user," the ORM offered a one-line dump of the row, and every sensitive column rode along.

#### 2. Over-Broad Generic Serializers

```python
# Django REST Framework: fields = '__all__' returns everything
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'   # deny-list mindset: expose all, hope to hide later
```

`__all__` is a *deny-list* in disguise: every current and *future* column is exposed by default, so adding a sensitive field later silently leaks it.

#### 3. `SELECT *` Flowing Straight to the Response

```sql
SELECT * FROM users WHERE id = $1;   -- grabs every column
-- ...and the handler serialises the whole row to JSON unchanged
```

#### 4. Verbose Nested Relations

```json
GET /api/orders/1001
{
  "id": 1001,
  "total": 59.90,
  "customer": {                 // full customer object embedded
    "id": 42, "email": "...", "passwordHash": "...", "internalNotes": "..."
  },
  "payment": {                  // full payment object embedded
    "cardLast4": "4242", "cardToken": "tok_...", "gatewayCustomerId": "cus_..."
  }
}
```

Eager-loading relations for convenience embeds entire adjacent objects—each with its own sensitive fields.

#### 5. Debug / Internal Fields Left In

```json
{ "id": 7, "title": "Hello",
  "_debug": { "sqlQuery": "SELECT ...", "cacheKey": "u:7:v3", "featureFlags": {...} },
  "__v": 12, "deletedAt": null, "tenantId": "acme-internal" }
```

### Where the Filtering Should Happen

| Approach | Who decides which fields ship | Secure? |
|----------|-------------------------------|---------|
| Client hides fields in the UI | The client (untrusted) | No — raw response still contains everything |
| Server returns full model, docs say "ignore extra fields" | Nobody enforces it | No — hope is not a control |
| Server returns an explicit response DTO / schema (allow-list) | The server (trusted) | Yes — only named fields can ever leave |
| Server shapes the response per role/consumer | The server (trusted) | Yes — each caller gets only what it needs |

### Data That Should Almost Never Leave the Server

- **Secrets**: password hashes, MFA/TOTP seeds, password-reset and session tokens, API keys, signing keys.
- **Authorization internals**: `isAdmin`, role flags, permission sets, tenant identifiers, feature flags.
- **Sensitive PII**: full government IDs, full payment data, precise geolocation, health data—unless the specific consumer is explicitly entitled to it.
- **Business internals**: cost/margin, fraud and risk scores, moderation notes, internal comments, soft-delete and audit metadata.
- **Implementation detail**: raw SQL, cache keys, stack fragments, internal database primary keys used nowhere by the client.

## Real-World Impact

The following are well-established *classes* of incident. They describe recurring, publicly discussed patterns rather than any single named CVE, and no precise figures are asserted.

### Case Class 1: Mobile / SPA Backends Returning Full User Objects

**Pattern**: A mobile or single-page app shows a trimmed profile, but its backend endpoint returns the complete user record. Security researchers repeatedly demonstrate this by intercepting the app's own traffic with a proxy and observing fields—email, phone, date of birth, internal flags—that never appear on screen.

**Impact**: Bulk PII harvesting and, where hashes or tokens are included, a path to account takeover.

**Root Cause**: The server serialised the whole model and trusted the app to display a subset.

### Case Class 2: Precise Location Leaked Behind "Approximate Distance"

**Pattern**: Location-based social and dating apps display a coarse "2 miles away," but the underlying API response has historically included exact latitude/longitude (or a precise-enough distance to trilaterate). This class of finding has been reported multiple times across several apps by independent researchers.

**Impact**: An attacker can pinpoint a specific user's real-world location—a serious physical-safety issue—without the app ever displaying a map pin.

**Root Cause**: Coarsening was applied in the UI, while the API returned precise coordinates.

### Case Class 3: Over-Sharing List and Search Endpoints

**Pattern**: A "list users," "search," or "directory" endpoint returns full objects for every result. The caller is authorised to *list*, but each element carries sensitive fields for other people.

**Impact**: A single request enumerates sensitive properties across the whole result set—one call becomes a mass scrape.

**Root Cause**: The same maximal serializer used for a single object was reused for collections.

### Case Class 4: GraphQL / Flexible-Query Over-Fetching

**Pattern**: A schema exposes sensitive fields on a type, relying on the client not to request them. Because clients choose their own field set, an attacker simply asks for the sensitive fields directly.

**Impact**: Direct disclosure of any field present in the schema but not access-controlled at the field level.

**Root Cause**: Field-level authorization was assumed to be a client concern rather than a server control.

## Prevalence and Detectability

In the OWASP API Security Top 10 (2019), Excessive Data Exposure was ranked **API3** and characterised as **common, easy to exploit, and moderate-to-severe in impact**. OWASP notes that detection typically requires inspecting responses rather than source code—because the vulnerability lives in what the server *sends*, not in a crash or an error.

- **Prevalence: high.** It is a natural by-product of ORM-plus-auto-serializer development and generic endpoint design, so it appears across a large share of assessed APIs.
- **Detectability: easy for a human, harder for automated scanners.** A scanner cannot always tell that `internalRiskScore` is sensitive; a reviewer reading the raw response immediately can. This is why manual response review and schema validation matter so much.
- **Exploitability: trivial.** No payload, no timing, no chaining—read the JSON.

> **Edition note (2019 → 2023):** In the 2023 edition of the OWASP API Security Top 10, Excessive Data Exposure was *merged* with Mass Assignment into a single category, **API3:2023 – Broken Object Property Level Authorization (BOPLA)**. The reframing recognises that reading properties you shouldn't (Excessive Data Exposure) and writing properties you shouldn't (Mass Assignment) are two sides of the same missing control: property-level authorization. This lesson uses the 2019 framing and terminology, but the defences below map directly onto the 2023 category.

## Common Misunderstandings

### Myth 1: "The app doesn't display it, so it's not exposed"

**Reality**: The response body is fully visible in dev tools, proxies, logs, and `curl`. What the UI renders is irrelevant to what the API transmits.

### Myth 2: "It's fine because the endpoint requires authentication"

**Reality**: Excessive Data Exposure is about *which fields* an authenticated, authorised caller receives. Being logged in does not entitle you to another user's password hash or precise location.

### Myth 3: "We'll just document that clients should ignore extra fields"

**Reality**: Documentation is not a security control. If the field is in the payload, it is exposed—compliant clients and attackers receive identical bytes.

### Myth 4: "HTTPS protects the data"

**Reality**: TLS protects data *in transit* from third parties. It does nothing about the legitimate recipient—the attacker—reading the response their own client received.

### Myth 5: "A deny-list of sensitive fields is enough"

**Reality**: Deny-lists fail open. The day someone adds `ssn` or `internalToken` to the model, it leaks until somebody remembers to blacklist it. Allow-lists fail closed and are the only robust approach.

### Myth 6: "This is the same as Broken Object Level Authorization (BOLA)"

**Reality**: They are related but distinct. BOLA (API1) is about accessing an *object* you shouldn't (wrong `id`). Excessive Data Exposure is about receiving *properties* you shouldn't within an object you *are* allowed to access. You can have one without the other.

### How Excessive Data Exposure Differs from Related Issues

| Aspect | Excessive Data Exposure (API3:2019) | BOLA (API1:2019) | Mass Assignment (API6:2019) |
|--------|-------------------------------------|------------------|-----------------------------|
| **Direction** | Server → client (reading) | Access to whole object | Client → server (writing) |
| **Question** | Which fields come *out*? | Whose object is it? | Which fields go *in*? |
| **Failure** | Over-shared response | Missing object ownership check | Blindly binding request to model |
| **Fix** | Explicit response allow-list | Per-object authorization | Explicit input allow-list |
| **2023 mapping** | API3:2023 BOPLA | API1:2023 BOLA | API3:2023 BOPLA |

## Self-Assessment

Ask these questions about each API response your service returns:

- [ ] Does any endpoint serialise a full database model or ORM object directly to JSON?
- [ ] Do you use `fields = '__all__'`, `SELECT *`, or an auto-serializer that exposes every column by default?
- [ ] Could a caller read any field—hashes, tokens, MFA seeds, internal IDs, flags—that the UI never displays?
- [ ] Do list/search endpoints return the same full object as single-item endpoints?
- [ ] Do nested/related objects embed their own sensitive fields?
- [ ] Are precise values (exact coordinates, full card numbers, full DOB) returned when only coarse values are shown?
- [ ] Is field selection an allow-list (only named fields ship) rather than a deny-list?
- [ ] Is the response shaped per role/consumer, so privileged fields go only to privileged callers?
- [ ] Do you validate outgoing responses against a schema, so a new sensitive field can't silently leak?
- [ ] Has someone actually read the raw JSON (proxy/`curl`), not just looked at the app?

If you answered "no" or "not sure" to several of these, your API is very likely over-sharing today.

## Key Takeaways

1. **Filtering must happen on the server**—the client is not a security boundary, and the raw response is always readable.
2. **Return only what each consumer needs**—explicit response DTOs/schemas, defined as allow-lists, not the whole model.
3. **Allow-list, never deny-list**—so new fields fail closed instead of leaking by default.
4. **List endpoints multiply the damage**—one over-shared collection call can scrape sensitive data at scale.
5. **Review the bytes, not the screen**—inspect actual responses; the UI hides the problem from you as effectively as it hides it from no one.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers find and read over-shared fields
- **[Prevention](prevention.md)**: Server-side response shaping and schema validation
- **[Examples](examples.md)**: Vulnerable vs. secure responses across frameworks
- **[API Security Learning Path](/learn/api)**: Continue with the rest of the OWASP API Top 10
- **[Practice](/practice)**: Apply these techniques against practice targets
