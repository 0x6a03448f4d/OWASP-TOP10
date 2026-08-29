# C3: Validate all Input & Handle Exceptions - How to Implement

## Implementation Strategy Overview

Implementing C3 means wiring three habits into every request path, and never relying on any one of them alone:

1. **Validate** all input at the boundary—allow-list, server-side, typed, schema-checked.
2. **Neutralise at the sink**—parameterise queries and apply context-aware output encoding.
3. **Handle exceptions safely**—fail closed, generic errors out, detailed logs in.

### Core Principles

- **Allow-list, not deny-list**: define what is acceptable and reject the rest.
- **Server is the trust boundary**: client validation is UX only; enforce on the server.
- **Both boundaries, always**: validation on input *and* encoding/parameterisation on output—never one instead of the other.
- **Fail closed and quiet**: on any error, deny and return a generic message; log the detail privately.

## 1. Validate Input: Syntactic and Semantic

Do the cheap structural check first (syntactic), then the meaning check (semantic). Reject as early as possible.

```python
# Syntactic: right shape?
sku = form["sku"]
if not re.fullmatch(r"[A-Z0-9\-]{4,20}", sku):
    raise BadRequest("invalid sku")

# Semantic: makes sense in context?
if not catalog.exists(sku):
    raise BadRequest("unknown sku")
if quantity > catalog.stock(sku):
    raise BadRequest("insufficient stock")
```

## 2. Prefer Allow-Lists

Enumerate the acceptable values or the acceptable pattern. Where the set is small and known, compare against it directly.

```python
# Allow-list of discrete values
SORT_FIELDS = {"name", "created_at", "price"}
if sort not in SORT_FIELDS:            # reject anything else outright
    raise BadRequest("invalid sort field")

# Allow-list by pattern (anchored, bounded length)
if not re.fullmatch(r"[a-z0-9_]{3,30}", username):
    raise BadRequest("invalid username")
```

> Anchor every regex (`\A...\Z` or `fullmatch`) and bound its length. An unanchored pattern like `[a-z]+` matches a substring of a malicious payload and lets it through.

## 3. Validate on the Server

Duplicate any client-side check on the server, which is the only tamper-proof location. Treat the client check purely as a convenience.

```
Browser / mobile app  -->  helpful, instant feedback   (UX, can be bypassed)
        Server        -->  authoritative validation    (SECURITY, enforced here)
```

## 4. Use Strong Typing and Schema Validation

Let the type system and a declarative schema do the work. Parse into concrete types; validate request bodies against a schema and reject unknown fields.

```python
# Pydantic model: types + constraints reject bad input before your code runs
from pydantic import BaseModel, constr, conint, EmailStr

class Signup(BaseModel):
    email: EmailStr
    username: constr(regex=r"^[a-z0-9_]{3,30}$")
    age: conint(ge=13, le=120)
    class Config:
        extra = "forbid"            # reject unexpected fields
```

```json
// JSON Schema (language-agnostic): validate the body at the edge
{
  "type": "object",
  "additionalProperties": false,
  "required": ["email", "quantity"],
  "properties": {
    "email":    { "type": "string", "format": "email" },
    "quantity": { "type": "integer", "minimum": 1, "maximum": 100 }
  }
}
```

## 5. Canonicalise Before Validating

Decode and normalise to one canonical form, then validate that form—so encoded variants cannot slip past the check.

```python
import os, unicodedata

raw = request.args["file"]
value = unicodedata.normalize("NFC", raw)     # normalise Unicode first
# ... URL-decode as needed, then validate the canonical value ...
if not re.fullmatch(r"[A-Za-z0-9_\-.]{1,64}", value):
    raise BadRequest("invalid filename")
```

## 6. Parameterised Queries (Anti-SQL Injection)

This—not input filtering—is the real defence against SQL injection. Never build SQL by concatenation.

```python
# WRONG: string building lets input change the query
cur.execute("SELECT * FROM users WHERE email = '" + email + "'")

# RIGHT: parameters are sent separately; input can never be code
cur.execute("SELECT * FROM users WHERE email = %s", (email,))

# Safe ORM (SQLAlchemy) parameterises for you
session.query(User).filter(User.email == email).one_or_none()
```

> Identifiers (table/column names, `ORDER BY` fields) cannot be bound as parameters. Validate those against an **allow-list** instead (see section 2).

## 7. Context-Aware Output Encoding (Anti-XSS)

Encode data for the exact context where it is written. The same value needs different escaping in HTML body, an attribute, JavaScript, a URL, or CSS.

```
HTML body       <div>{{ value }}</div>         -> HTML-entity encode  ( < > & )
HTML attribute  <input value="{{ value }}">    -> attribute-encode + always quote
JavaScript      var x = "{{ value }}";         -> JS-string encode (or pass as JSON)
URL parameter   /search?q={{ value }}          -> percent-encode
CSS             color: {{ value }};            -> CSS-encode / allow-list
```

Lean on template engines with **auto-escaping** on by default (Jinja2, Razor, Thymeleaf, React's JSX text). For HTML that must be allowed (a rich-text comment), sanitise with a vetted library rather than trying to escape it yourself.

```javascript
// Sanitise user HTML with DOMPurify before inserting it
import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(userHtml);   // strips scripts/handlers, keeps safe tags
```

## 8. Safe Command Execution (Anti-Command Injection)

Avoid the shell. Pass an argument array so there is no shell to interpret metacharacters, and allow-list the input.

```python
# WRONG: shell=True lets ; && | $() run
subprocess.run("ping -c 1 " + host, shell=True)

# RIGHT: argument list, no shell, validated host
if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):
    raise BadRequest("invalid host")
subprocess.run(["ping", "-c", "1", host], shell=False, timeout=5)
```

## 9. Safe LDAP Queries (Anti-LDAP Injection)

Escape LDAP filter metacharacters with the platform encoder and constrain the input format.

```python
from ldap3.utils.conv import escape_filter_chars

if not re.fullmatch(r"[a-z0-9_.\-]{1,64}", uid):
    raise BadRequest("invalid uid")
search_filter = "(uid={})".format(escape_filter_chars(uid))   # * ( ) \ NUL escaped
```

## 10. Safe XML Parsing (Anti-XXE)

Disable DTDs and external entities before parsing any untrusted XML.

```python
# Python: defusedxml is the drop-in safe choice
from defusedxml.ElementTree import fromstring
tree = fromstring(untrusted_xml)      # external entities/DTDs disabled
```

```java
// Java: turn off DOCTYPE and external entities explicitly
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
f.setFeature("http://xml.org/sax/features/external-general-entities", false);
f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
f.setXIncludeAware(false);
f.setExpandEntityReferences(false);
```

## 11. Avoid Unsafe Deserialization

Do not natively deserialize untrusted data. Prefer data-only formats with an explicit schema and field mapping.

```python
# WRONG: pickle/native deserializers construct arbitrary objects -> RCE
obj = pickle.loads(request.body)

# RIGHT: parse JSON into a validated model, mapping only known fields
payload = json.loads(request.body)      # data only, no code
order = Order(**payload)                # schema/type validation (section 4)
```

If a binary or object format is truly required, use one without code-execution semantics, enforce a type allow-list, and integrity-check the data.

## 12. Safe File Handling (Path Traversal & Uploads)

Canonicalise the resolved path and confirm it stays inside the intended directory; validate uploads by content, not by name.

```python
import os
BASE = "/var/app/files"

# Path traversal: resolve, then confine to BASE
requested = os.path.realpath(os.path.join(BASE, user_filename))
if not requested.startswith(BASE + os.sep):
    raise BadRequest("path outside allowed directory")

# Uploads: server-generated name, verified type, size cap, stored outside web root
if upload.size > 5 * 1024 * 1024:
    raise BadRequest("file too large")
if detect_content_type(upload.stream) not in {"image/png", "image/jpeg"}:
    raise BadRequest("unsupported file type")
safe_name = f"{uuid.uuid4().hex}.bin"   # never trust the client filename
```

## 13. Safe Exception Handling

### Fail closed
```python
# Any error during a security decision must deny
try:
    allowed = authz.check(user, resource)
except Exception:
    log.exception("authz check failed")
    allowed = False            # never default to True
```

### Generic errors out, detailed logs in
```python
import uuid, logging
log = logging.getLogger("app")

def handle_error(e):
    error_id = uuid.uuid4().hex
    log.exception("unhandled error id=%s", error_id)     # full detail, server-side only
    return {"error": "Something went wrong", "error_id": error_id}, 500
```

### Rules for exception handling
- **Fail closed**: deny/deny-by-default on error; never fail open on a security check.
- **No leakage**: never return stack traces, queries, file paths, internal hostnames, tokens, or secrets to the client.
- **Catch, don't swallow**: handle exceptions deliberately; avoid empty `catch {}` blocks that hide attacks.
- **Log safely**: record enough context to investigate, but never log passwords, tokens, or full personal data.
- **Turn debug off** in production so framework error pages and interactive debuggers are never reachable.

## Implementation Checklist

| Area | Do |
|------|----|
| Validation | Allow-list, server-side, syntactic + semantic, typed, schema-checked |
| Canonicalisation | Decode/normalise first, then validate the canonical form |
| SQL / NoSQL | Parameterised queries / safe ORM; allow-list identifiers |
| Output / XSS | Context-aware encoding; auto-escaping templates; sanitise rich HTML |
| Commands | Argument arrays, no shell, validated input |
| LDAP | Encode filter metacharacters, constrain format |
| XML | Disable DTDs and external entities |
| Deserialization | Data-only formats + schema; avoid native deserializers |
| Files | Confine paths to a base dir; validate uploads by content |
| Exceptions | Fail closed, generic errors, private logs, debug off |

## Key Takeaways

1. **Validate at the edge** — allow-list, server-side, typed and schema-driven, canonicalised first.
2. **Neutralise at the sink** — parameterised queries and context-aware encoding are the real fixes for injection and XSS.
3. **Both, never either** — validation and encoding are complementary layers, not alternatives.
4. **Configure parsers and deserializers safely** — disable XXE, avoid native deserialization of untrusted data.
5. **Fail closed and quiet** — deny on error, log privately, and never leak internals.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure code in Python, Node.js, and Java
- **[Threats Addressed](attack-vectors.md)**: Understand exactly what you are defending against
- **[Proactive Controls](/learn/proactive)**: Return to the full control set
- **[Practice](/practice)**: Apply what you have learned
