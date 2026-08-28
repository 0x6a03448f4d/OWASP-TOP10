# API3:2019 Excessive Data Exposure - Attack Vectors

## Table of Contents
- [Understanding the Attack Surface](#understanding-the-attack-surface)
- [Core Attack Flow](#core-attack-flow)
- [Attack Patterns](#attack-patterns)
- [Chaining Over-Exposure with Other Flaws](#chaining-over-exposure-with-other-flaws)

## Understanding the Attack Surface

> **⚠ EDUCATIONAL PURPOSE ONLY** — these techniques are shown so you can find and fix over-exposure in systems you own or are explicitly authorised to test.

Excessive Data Exposure is unusual among vulnerabilities in that **there is no exploit to write**. The attacker does not inject anything, does not bypass a check, and often does not even send an unusual request. They send the *same* request the legitimate app sends—and then read the whole response instead of the slice the app chose to render. The entire technique is: look at the raw bytes.

Because of that, the "attack" is really an act of **observation and enumeration**. The skills involved are intercepting traffic, reading JSON, diffing what the UI shows against what the server sent, and then scaling that reading across many objects and endpoints.

The attacker's objectives in this category are typically:

- Recover sensitive fields (PII, secrets, internal flags) that the UI hides but the API sends.
- Turn a single over-shared object into a bulk harvest via list/search endpoints.
- Use leaked internal identifiers and structure to fuel deeper attacks (BOLA, injection, business logic).

### Core Attack Flow

```
1. Intercept
   ↓
   Proxy the app's own traffic (Burp / mitmproxy / browser dev tools)
2. Compare
   ↓
   Diff what the SCREEN shows vs. what the RESPONSE body contains
3. Identify
   ↓
   Flag sensitive extra fields: hashes, tokens, PII, internal flags, IDs
4. Scale
   ↓
   Replay against list/search endpoints and iterate object IDs
5. Harvest / Pivot
   ↓
   Bulk-collect sensitive fields; feed internal IDs into further attacks
```

## Attack Patterns

### 1. Read the Raw Response the App Already Fetches

The simplest and most common vector. Open dev tools or a proxy, use the app normally, and inspect the JSON behind a screen that looks harmless.

```http
GET /api/users/42 HTTP/1.1
Authorization: Bearer <the app's own token>

HTTP/1.1 200 OK
{
  "id": 42, "displayName": "Jordan Lee",
  "email": "jordan.lee@example.com",     // UI never shows this
  "passwordHash": "$2b$12$Q8f...",        // nor this
  "isAdmin": false, "internalRiskScore": 0.83
}
```

**Payoff**: PII and secrets with zero exploitation—the app fetched them for the attacker.

### 2. Diff the UI Against the Payload

Systematically map each on-screen field to a response field; anything left over in the response is a candidate leak.

```
Screen shows:   name, avatar, "2 miles away"
Response has:   name, avatar, preciseLat, preciseLng, email, phone, dob
Leftover  =>    preciseLat, preciseLng, email, phone, dob   (all sensitive)
```

**Payoff**: A precise inventory of hidden fields, including "coarsened" values (distance, masked IDs) that are actually sent in full.

### 3. Harvest List and Search Endpoints

Single-object leaks are bad; collection leaks are catastrophic, because one authorised call returns full objects for many users.

```http
GET /api/users?limit=500 HTTP/1.1

HTTP/1.1 200 OK
[
  { "id": 1, "name": "...", "email": "...", "phone": "...", "isAdmin": true },
  { "id": 2, "name": "...", "email": "...", "phone": "...", "isAdmin": false },
  ... 498 more full records ...
]
```

**Payoff**: Mass PII scrape in a single request. Pagination just means "loop until done."

### 4. Request Alternate or Verbose Representations

Many APIs expose knobs that widen the payload: `?expand=`, `?include=`, `?fields=*`, `?view=full`, or an `Accept` variant. Attackers try them all.

```http
GET /api/orders/1001?expand=customer,payment HTTP/1.1
GET /api/users/42?include=all HTTP/1.1
GET /api/users/42?fields=* HTTP/1.1
```

**Payoff**: Embedded, fully-serialised related objects (customer, payment) each carrying their own sensitive fields.

### 5. GraphQL / Flexible-Query Field Selection

Where the client picks fields, the attacker simply *asks* for the sensitive ones. If field-level authorization is missing, they are returned.

```graphql
query {
  user(id: 42) {
    displayName
    email
    passwordHash        # if it exists on the type and isn't field-authorized
    mfaSecret
    internalRiskScore
  }
}
```

**Payoff**: Direct pull of any field present in the schema but not access-controlled at field level. Introspection (`__schema`) reveals which fields exist to ask for.

### 6. Inspect Old / Undocumented API Versions

Legacy endpoints often predate the current data-minimisation and leak more. Attackers probe `/v1/` after finding `/v2/`.

```http
GET /api/v2/users/42   -> trimmed, safe-looking
GET /api/v1/users/42   -> full legacy object with hashes and flags still present
```

**Payoff**: An older, chattier version of the same data behind a forgotten route.

### 7. Mine Nested and Related Objects

Even a "clean" top-level object can smuggle a full sub-object.

```http
GET /api/reviews/88
{
  "rating": 5, "text": "Great!",
  "author": {                        // full user object nested inside a review
    "id": 42, "email": "...", "passwordResetToken": "...", "isAdmin": false
  }
}
```

**Payoff**: Sensitive fields for *other* users leak through an endpoint that appears to be about something else entirely.

### 8. Read Coarsened Values That Are Actually Precise

UI "coarsening" (rounded distance, masked card, city-level location) is frequently cosmetic—the precise value is still in the payload.

```
Screen: "Card ending 4242"      Response: "cardNumber": "4242424242424242"
Screen: "~2 miles away"          Response: "lat": 47.61032, "lng": -122.33207
Screen: "Member since 2021"      Response: "dob": "1991-03-08"
```

**Payoff**: Full card data, exact geolocation (a physical-safety risk), and precise PII behind a reassuring label.

### 9. Trigger Error and Edge Responses

Validation errors, conflict responses, and "echo back the object" confirmations sometimes serialise the full record even when the normal success path is trimmed.

```http
POST /api/users        # duplicate email
HTTP/1.1 409 Conflict
{ "message": "exists", "existingUser": { "id": 42, "email": "...", "passwordHash": "..." } }
```

**Payoff**: A leak on a path the team never reviewed because it "only returns an error."

### 10. Harvest From Caches, Logs, and Third Parties

Over-shared responses do not just reach the attacker—they land in CDN caches, browser storage, request logs, analytics, and crash reporters, widening exposure.

```
- CDN caches a response containing another user's PII
- Client-side analytics/crash SDK ships the full payload off-device
- Access logs record verbose JSON bodies
```

**Payoff**: Sensitive fields end up in systems with weaker access control than the API itself.

### 11. Enumerate Objects to Combine With BOLA

When over-exposure meets a missing object-ownership check, iterating the `id` harvests full records for everyone.

```python
for id in range(1, 100000):
    GET /api/users/{id}     # BOLA lets you read any id...
                            # ...Excessive Data Exposure makes each one a full leak
```

**Payoff**: Whole-table exfiltration—the two flaws multiply.

### 12. Read Debug and Internal Fields

Fields intended for developers (`_debug`, `__v`, `tenantId`, `featureFlags`, raw SQL) map internals and business logic.

```json
{ "id": 7, "_debug": { "sqlQuery": "SELECT * FROM ...", "cacheKey": "u:7" },
  "tenantId": "acme-internal", "featureFlags": { "newBilling": true } }
```

**Payoff**: Reconnaissance of schema, multi-tenancy, and roadmap—fuel for the next attack.

## Chaining Over-Exposure with Other Flaws

Excessive Data Exposure is a force multiplier. On its own it leaks data; combined, it escalates.

```
Over-shared list endpoint (emails + password-reset tokens)
        +
No rate limiting on the token-reset flow
        =  scripted account takeover across many users
```

```
BOLA: /api/users/{id} accepts any id
        +
Excessive Data Exposure: each response is the full user object
        =  full-database PII scrape by iterating id
```

```
Leaked internal IDs / foreign keys in a response
        -> feed those IDs into other endpoints (IDOR)
        -> map relationships and pivot to admin-only objects
```

## Key Takeaways

1. **The exploit is reading**—no payload, no bypass; the app hands the attacker the data.
2. **Diff the screen against the bytes**—every leftover field in the response is a candidate leak.
3. **List and search endpoints turn a leak into a scrape**—one call, thousands of records.
4. **Coarsened UI values are often precise on the wire**—distance, masked cards, and dates are frequently sent in full.
5. **Over-exposure multiplies other flaws**—paired with BOLA or weak rate limits it becomes mass compromise.

## Next Steps

- **[Prevention Guide](prevention.md)**: Shape responses on the server and validate them against schemas
- **[Code Examples](examples.md)**: See vulnerable vs. secure responses across frameworks
- **[API Security Learning Path](/learn/api)**: Continue with the rest of the OWASP API Top 10
- **[Practice](/practice)**: Apply these techniques against practice targets
