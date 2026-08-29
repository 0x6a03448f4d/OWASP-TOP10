# C3: Validate all Input & Handle Exceptions - Overview

## Table of Contents
- [What is this control?](#what-is-this-control)
- [Why This Control Matters](#why-it-matters)
- [Input Validation in Depth](#input-validation)
- [Validation Is Not a Substitute for Encoding](#not-a-substitute)
- [Safe Exception Handling](#exception-handling)
- [Real-World Impact](#real-world-impact)
- [Common Misunderstandings](#common-misunderstandings)

## What is this control?

**C3 — Validate all Input & Handle Exceptions** is a *proactive* control from the OWASP Top 10 Proactive Controls (2024). It is not a description of a vulnerability; it is a defensive discipline you build into every application to **mitigate** whole classes of attacks—injection, cross-site scripting, XML external entities, path traversal, and unsafe deserialization—and to make sure the failures that do occur fail *safely*.

The control has three tightly related parts. Treat them as one system: each covers a gap the others cannot.

> **1. Input validation** — decide, before any data is used, whether it is well-formed and acceptable. Reject what is not.
> **2. Safe output handling** — when data crosses into an interpreter (SQL, HTML, a shell, an LDAP filter), encode or parameterise it for *that* context so it is treated as data, never as code.
> **3. Exception handling** — when something goes wrong anyway, fail closed, return a generic error to the user, and log the detail server-side without leaking secrets.

### The core idea

```
Untrusted input  -->  [ 1. VALIDATE ]  -->  application logic  -->  [ 2. ENCODE / PARAMETERISE ]  -->  interpreter
                          |                                                   |
                     reject bad,                                        treat data as data,
                     allow-list good                                    never as code
                          |                                                   |
                          +------------------  [ 3. HANDLE EXCEPTIONS: fail closed, log safely ]  ------------------+
```

### What "input" means here

Input is not just form fields. It is **every byte the application did not itself produce**: query strings, request bodies, headers, cookies, uploaded files and their names, URL path segments, data pulled from other services and APIs, message-queue payloads, database rows written by another system, and even environment values. If your code did not create it, treat it as untrusted.

### Two kinds of validation

| Kind | Question it answers | Example |
|------|---------------------|---------|
| **Syntactic** | Is the data the right *shape*? | A date is `YYYY-MM-DD`; a quantity is a positive integer; a UUID matches the UUID pattern. |
| **Semantic** | Does the data make *sense* in context? | The start date is before the end date; the quantity is within stock; the account belongs to the caller. |

Both are required. Syntactically valid input can still be semantically wrong (a perfectly-formatted date of `1900-01-01` for a delivery), and semantic checks assume the shape is already known-good.

## Why This Control Matters

A large share of the most damaging application vulnerabilities reduce to the same root cause: **untrusted input reaching a place where it is interpreted as code or as a command**. C3 is the control that breaks that chain. Implemented well, it is the difference between a probe that returns "400 Bad Request" and one that returns your customer database.

- **It mitigates Injection** (SQL, NoSQL, OS command, LDAP): parameterised queries and safe APIs keep attacker text out of the command structure.
- **It mitigates Cross-Site Scripting**: context-aware output encoding makes injected markup render as inert text.
- **It mitigates XXE and deserialization attacks**: safe parser configuration and avoiding native deserialization of untrusted data close the door before parsing begins.
- **It contains failure**: safe exception handling means that when an unexpected condition *does* occur, the system denies rather than defaults-open, and it does not hand the attacker a stack trace, a query, or a secret.

## Input Validation in Depth

### 1. Prefer allow-lists, not deny-lists

Define what is *acceptable* and reject everything else. Deny-lists (block `<script>`, block `' OR 1=1`) fail because attackers have endless encodings and variants; you cannot enumerate every bad input, but you can usually enumerate the good.

```python
# Deny-list (fragile): tries to name every bad thing
if "<script>" in name or "SELECT" in name: reject()   # bypassed by <ScRiPt>, /**/SELECT, ...

# Allow-list (robust): names the one good thing
if re.fullmatch(r"[A-Za-z][A-Za-z '\-]{1,49}", name):  # a person's name, nothing else
    accept()
else:
    reject()
```

### 2. Validate on the server — always

Client-side validation (JavaScript in the browser, checks in a mobile app) is a **usability feature**, not a security control. The attacker controls the client: they can disable your script, edit the request in a proxy, or call the API directly with `curl`. Every security-relevant validation **must** run again on the server, which is the only place the user cannot tamper with.

> Client validation improves UX by catching mistakes early. Server validation enforces the rules. You need both, and only the server side is trusted.

### 3. Use strong typing and schema validation

The cheapest, most reliable validation is the type system and a schema. Parse a quantity into an integer, a date into a date object, a request body against a declared schema (JSON Schema, a Pydantic model, a Java bean with constraints). Anything that does not fit is rejected at the boundary, before your logic ever sees it.

```python
# Schema/type validation rejects malformed input at the edge
class Order(BaseModel):          # pydantic
    sku: constr(regex=r"^[A-Z0-9\-]{4,20}$")
    quantity: conint(ge=1, le=100)
    ship_date: date              # a string that is not a real date is rejected here
```

### 4. Canonicalise *before* you validate

The same value can be written many ways: `%2e%2e%2f`, `..\`, over-long UTF-8, mixed case, Unicode look-alikes. If you validate the raw form and then decode it later, an attacker slips past the check. **Decode and normalise to a single canonical form first, then validate that.**

```
Raw:        %2e%2e%2f%2e%2e%2fetc%2fpasswd
Canonical:  ../../etc/passwd        <- validate THIS, not the encoded string
```

### 5. Validate files by content, not just by name

For uploads, never trust the client-supplied filename, extension, or `Content-Type`. Verify the real content type, enforce a size limit, generate a fresh server-side filename, and store outside the web root. (Full patterns are in the Prevention page.)

## Validation Is Not a Substitute for Encoding

This is the single most important point in C3, and the most commonly missed:

> **Input validation reduces risk. It does not eliminate injection or XSS on its own. You still need context-aware output encoding and parameterised queries. You need BOTH.**

Why validation alone is not enough:

- Many valid inputs legitimately contain dangerous characters. A name like `O'Brien` contains a single quote; a comment can legitimately contain `<` and `>`; a search box must accept almost anything. You cannot reject these, so validation cannot be your only defence.
- The same string is safe in one context and dangerous in another. `<b>` is harmless in a database column and dangerous in HTML. Safety is decided at the *output* boundary, by the interpreter that will read the data—so the fix must live there too.
- Data arrives from many sources. Even if you validated a value on the way in, another code path or another service may write to the same store without validating. Encoding at output protects regardless of how the data got there.

So the model is **defence in depth**: validate at the input boundary to reject obvious garbage early, and encode/parameterise at every output boundary to neutralise whatever gets through.

```
Validation catches:     malformed, out-of-range, wrong-type input        (reduces attack surface)
Encoding/parameters:    neutralises dangerous characters at the sink     (stops the injection)
        Both together:  belt and braces — neither alone is sufficient
```

### The two output-side controls

- **Parameterised queries / prepared statements / safe ORMs** keep untrusted data out of the *structure* of a SQL/NoSQL command—the database receives the query and the data separately, so the data can never change the command. This, not input filtering, is the real fix for injection.
- **Context-aware output encoding & sanitisation** escapes data for the exact place it is written—HTML body, HTML attribute, JavaScript, URL, CSS—so it renders as text. For rich HTML that must be allowed, a vetted sanitiser (for example DOMPurify) or a template engine with auto-escaping does this correctly.

## Safe Exception Handling

The second half of this control is what happens when validation or any other operation fails. Poor exception handling is itself a security weakness: it leaks information and, worse, can leave the system in an *insecure* state.

### Fail closed, never fail open

When an error occurs during a security decision, the safe default is to **deny**. Code that treats an exception as "allow" is a classic authorization bypass.

```python
# FAIL OPEN (dangerous): an error is treated as "access granted"
try:
    allowed = check_permission(user, resource)
except Exception:
    allowed = True          # <- attacker just needs to make the check throw

# FAIL CLOSED (safe): any error denies access
try:
    allowed = check_permission(user, resource)
except Exception:
    log.exception("permission check failed")
    allowed = False         # deny on error, always
```

### Generic errors to users, detailed logs to the server

A user (and an attacker) should see a short, generic message and perhaps a correlation id. The stack trace, the failing query, internal hostnames, and any secret belong only in server-side logs.

```
To the user:   { "error": "Something went wrong", "error_id": "a1b2c3d4" }   # generic
To the log:    full stack trace + context, tied to error_id a1b2c3d4          # detailed, private
```

### Catch, don't swallow

Handle exceptions deliberately—log them, translate them into a safe response—but do not silently discard them (an empty `catch {}`), which hides attacks and bugs alike. And never log secrets, tokens, passwords, or full personal data while logging the error.

## Real-World Impact

These are *classes* of incidents that this control directly prevents. They recur across the industry year after year.

### SQL injection breaches
String-concatenated queries have driven some of the largest data breaches on record, exposing millions of records at a time. The durable lesson is always the same: the fix is parameterised queries, not cleverer input filtering.

### Stored and reflected XSS
User content rendered into pages without context-aware encoding lets attackers run script in victims' browsers—stealing sessions, performing actions as the victim, and defacing content. Auto-escaping templates and sanitising rich HTML shut this down.

### XXE in XML processors
XML parsers left with external-entity resolution enabled have been used to read local files (for example `/etc/passwd`) and to reach internal systems via server-side request forgery. Disabling external entities and DTDs is the fix.

### Unsafe deserialization
Deserializing attacker-controlled data with native, type-permissive deserializers (across multiple languages and frameworks) has repeatedly led to remote code execution. Avoiding native deserialization of untrusted input—using data-only formats like JSON with a strict schema—removes the sink.

### Verbose errors as reconnaissance
Stack traces and database errors returned to clients have handed attackers exact versions, file paths, schema names, and even credentials—turning a minor bug into a roadmap. Generic errors plus server-side logging deny that free reconnaissance.

> These are incident *classes*, described without fabricated CVE numbers or invented statistics. The point is not a specific breach; it is that the same missing control—validate input, encode output, handle errors safely—is behind all of them.

## Common Misunderstandings

### Myth 1: "If I validate input, I don't need to encode output."
**Reality**: False, and dangerous. Valid input can contain dangerous characters, and safety depends on the output context. You need validation *and* context-aware encoding/parameterisation. This is the central point of C3.

### Myth 2: "A deny-list of bad characters is good enough."
**Reality**: Deny-lists are bypassed by encodings and variants you did not anticipate. Prefer an allow-list of acceptable input, and rely on parameterisation/encoding at the sink.

### Myth 3: "The front-end already validates, so the API is safe."
**Reality**: Client validation is UX only. Attackers bypass the client entirely. Every rule must be enforced on the server.

### Myth 4: "Escaping input as it arrives is the same as encoding on output."
**Reality**: Encoding on *input* corrupts data and still gets the context wrong. Encode at the moment of output, for the specific interpreter that will read it.

### Myth 5: "Catching the exception and returning the message is helpful."
**Reality**: Returning raw exception detail leaks internals to attackers. Return a generic message plus an id; log the detail privately.

### Myth 6: "On error, let it through so users aren't blocked."
**Reality**: Failing open on a security check is an authorization bypass. Always fail closed.

## How C3 Relates to the Vulnerabilities It Defends

| C3 element | Primary threat mitigated | The actual fix |
|------------|--------------------------|----------------|
| Allow-list input validation | Malformed / out-of-range data, some injection probes | Reject at the boundary; reduces surface |
| Parameterised queries / safe ORM | SQL / NoSQL injection | Data sent separately from command |
| Context-aware output encoding | Cross-site scripting (XSS) | Data rendered as inert text |
| Safe parser config | XXE | External entities / DTDs disabled |
| Avoid native deserialization | Insecure deserialization → RCE | Data-only formats + schema |
| Safe exception handling | Info disclosure, fail-open bypass | Fail closed, generic errors, private logs |

## Key Takeaways

1. **C3 is a defence, not a vulnerability** — it mitigates injection, XSS, XXE, path traversal, deserialization, and error-handling risks.
2. **Validate with allow-lists, on the server** — syntactic and semantic, using strong typing and schemas; canonicalise first.
3. **Validation is not a substitute for output encoding or parameterised queries** — you need both, at both boundaries.
4. **Handle exceptions safely** — fail closed, return generic errors, log detail privately, never leak stack traces or secrets.
5. **Defence in depth wins** — reject the obviously bad early, neutralise the rest at every sink.

## Next Steps

- **[Threats Addressed](attack-vectors.md)**: The attack classes this control shuts down, with examples
- **[How to Implement](prevention.md)**: A practical, layered implementation guide
- **[Code Examples](examples.md)**: Insecure vs. secure code in Python, Node.js, and Java
- **[Proactive Controls](/learn/proactive)**: Return to the full control set
- **[Practice](/practice)**: Apply what you have learned
