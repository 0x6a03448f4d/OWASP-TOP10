# Insecure Deserialization - Prevention

There is exactly one defense that always works: **do not deserialize data from an untrusted source with a native, type-restoring deserializer**. Everything else on this page is a layer you add *because* that ideal is sometimes impractical. Treat native deserialization (Java `readObject`, Python `pickle`, PHP `unserialize`, .NET `BinaryFormatter`) as equivalent to running `eval()` on the input, and build defense in depth around it.

## Table of Contents

- [The Governing Principle](#the-governing-principle)
- [Layer 1 — Prefer Data-Only Formats + Schema Validation](#layer-1--prefer-data-only-formats--schema-validation)
- [Layer 2 — Type Allow-Lists & Safe Resolvers](#layer-2--type-allow-lists--safe-resolvers)
- [Layer 3 — Integrity: Sign Serialized State (HMAC)](#layer-3--integrity-sign-serialized-state-hmac)
- [Layer 4 — Least Privilege & Sandboxing](#layer-4--least-privilege--sandboxing)
- [Layer 5 — Patch Libraries & Shrink the Gadget Surface](#layer-5--patch-libraries--shrink-the-gadget-surface)
- [Layer 6 — Monitoring & Detection](#layer-6--monitoring--detection)
- [Per-Language Quick Reference](#per-language-quick-reference)
- [Prevention Checklist](#prevention-checklist)
- [Next Steps](#next-steps)

## The Governing Principle

Rank your options from safest to most dangerous and always pick the highest one you can live with:

1. **Don't deserialize untrusted input at all.** Redesign so the untrusted side sends plain data (JSON, form fields, protobuf), not serialized objects.
2. **If you must accept structured input, use a data-only format** (JSON, MessagePack, protobuf) parsed into simple values, then validated against a strict schema before use.
3. **If you must use a native serializer** (legacy protocol, library requirement), constrain it hard: type allow-list, size/depth limits, least privilege, and integrity checks on anything that left your trust boundary.

> **Why layering matters:** the exploit fires *during* reconstruction, before your business logic runs. So validation "after deserialization" cannot save you—the defenses below all act *at or before* the deserialization step.

## Layer 1 — Prefer Data-Only Formats + Schema Validation

A data-only format restores *values* (strings, numbers, lists, maps), never *arbitrary typed objects with behavior*. There is no `__reduce__`, no `readObject` hook, no magic method to abuse. This single choice eliminates the entire remote-code-execution class. The remaining job is to validate that the data means what you expect.

### Python — JSON with an explicit schema

```python
import json
from jsonschema import validate, ValidationError

SCHEMA = {
    "type": "object",
    "properties": {
        "user":  {"type": "string", "maxLength": 64},
        "role":  {"type": "string", "enum": ["user", "admin"]},
        "exp":   {"type": "integer"}
    },
    "required": ["user", "role", "exp"],
    "additionalProperties": False        # reject unexpected keys
}

def load_state(raw: str) -> dict:
    data = json.loads(raw)               # restores plain values only, never objects
    validate(instance=data, schema=SCHEMA)   # raises on anything unexpected
    return data
```

### PyYAML — always `safe_load`

```python
# DANGEROUS: honours !!python/object tags -> arbitrary instantiation
# data = yaml.load(untrusted)          # or yaml.unsafe_load / Loader=yaml.Loader

import yaml
data = yaml.safe_load(untrusted)        # SafeLoader: plain scalars/lists/dicts only
```

### Node.js — `JSON.parse`, never a function-restoring library

```javascript
// SECURE: JSON.parse never restores or executes functions.
const obj = JSON.parse(req.body);

// Then validate structure (e.g. with ajv / zod) before trusting it:
const { z } = require('zod');
const Schema = z.object({
  user: z.string().max(64),
  role: z.enum(['user', 'admin']),
  exp:  z.number().int()
}).strict();                            // .strict() rejects extra keys
const state = Schema.parse(obj);        // throws on mismatch
```

> **Guard prototype pollution too.** When merging parsed JSON into objects, reject keys named `__proto__`, `constructor`, and `prototype`, or use `Object.create(null)` / `Map` as the merge target.

## Layer 2 — Type Allow-Lists & Safe Resolvers

When a native serializer is unavoidable, never let it instantiate *any* type named in the stream. Restrict resolution to a small allow-list of classes you actually expect. An allow-list (deny by default) is mandatory; a deny-list of "known bad gadgets" is bypassable and not sufficient on its own.

### Java — ObjectInputFilter (JEP 290)

Since Java 9 (and back-ported to 8u121+), `ObjectInputFilter` lets you allow-list classes and cap graph size/depth *before* objects are constructed.

```java
import java.io.*;

ObjectInputStream ois = new ObjectInputStream(in);

// Allow only your own DTOs + required JDK types; reject everything else.
// Also cap depth, references, array size, and total bytes (anti-DoS).
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.example.dto.*;java.util.*;java.lang.*;" +
    "!*;" +                              // deny anything not listed above
    "maxdepth=20;maxrefs=500;maxbytes=100000;maxarray=10000");
ois.setObjectInputFilter(filter);

Object obj = ois.readObject();           // rejected classes never instantiate
```

Set a conservative JVM-wide default too (`-Djdk.serialFilter=...`), and prefer libraries that avoid native serialization entirely. For JSON, keep Jackson's default typing **off** and never enable `enableDefaultTyping()`.

### Python — do not pickle untrusted data; if forced, restrict the unpickler

The correct fix is to not use `pickle` across a trust boundary. If a legacy format forces it, subclass `Unpickler` and allow only specific classes:

```python
import pickle, io

_ALLOWED = {
    ("myapp.models", "UserDTO"),
    ("builtins", "list"),
    ("builtins", "dict"),
}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) in _ALLOWED:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"blocked: {module}.{name}")

def safe_loads(data: bytes):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

> This shrinks the attack surface but does not make pickle "safe." Treat it as a stopgap while you migrate the format to JSON/protobuf.

### PHP — avoid `unserialize` on user input; use `allowed_classes`

```php
<?php
// BEST: use json_decode for user-supplied structured data.
$data = json_decode($raw, true);         // returns arrays/scalars, no objects

// IF unserialize is unavoidable, forbid object instantiation entirely:
$data = unserialize($raw, ['allowed_classes' => false]);

// Or allow ONLY a specific safe class:
$data = unserialize($raw, ['allowed_classes' => ['App\\Dto\\UserDto']]);
?>
```

Also treat filenames as attack surface: never pass user-influenced paths to filesystem functions in a way that permits a `phar://` stream wrapper.

### .NET — retire `BinaryFormatter`; pin type handling

```csharp
// DO NOT USE: BinaryFormatter / NetDataContractSerializer / LosFormatter
//             / SoapFormatter on untrusted input. BinaryFormatter is
//             deprecated and removed from modern .NET for this reason.

// PREFER System.Text.Json (no polymorphic type resolution by default):
var opts = new JsonSerializerOptions();
var dto  = JsonSerializer.Deserialize<UserDto>(json, opts);

// If you must use Json.NET, keep TypeNameHandling = None (the default),
// and if polymorphism is truly required, supply a strict SerializationBinder
// that allow-lists the exact permitted types.
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None
};
```

## Layer 3 — Integrity: Sign Serialized State (HMAC)

If serialized state must round-trip through the client (cookies, hidden fields, tokens), attach a keyed MAC so the server can reject any tampered blob *before* deserializing it. Verify first; deserialize only if the signature checks out. Use a strong secret, a constant-time comparison, and bind expiry/audience so a valid blob cannot be replayed.

```python
import hmac, hashlib, json, time
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

SECRET = get_secret("STATE_SIGNING_KEY")     # 32+ random bytes, from a vault

def sign(state: dict) -> str:
    state = {**state, "exp": int(time.time()) + 900}   # 15-min expiry binding
    body = b64e(json.dumps(state, separators=(",", ":")).encode())
    sig  = hmac.new(SECRET, body, hashlib.sha256).digest()
    return body.decode() + "." + b64e(sig).decode()

def verify(token: str) -> dict | None:
    try:
        body_b64, sig_b64 = token.split(".")
        expected = hmac.new(SECRET, body_b64.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(b64d(sig_b64), expected):  # constant-time
            return None                       # tampered -> reject, never parse
        state = json.loads(b64d(body_b64))    # only NOW, on verified bytes
        if state.get("exp", 0) < time.time():
            return None                       # expired
        return state
    except Exception:
        return None
```

> **Signing is not a license to use native serialization.** A leaked or default key collapses the protection entirely (see the ASP.NET ViewState `machineKey` lesson in Attack Vectors). Sign *data-only* payloads, rotate keys, and store them in a secret manager—never in source.

## Layer 4 — Least Privilege & Sandboxing

Assume a deserialization bug will eventually be triggered and limit the blast radius:

- **Run the service as an unprivileged user**, in a container with a read-only root filesystem and dropped Linux capabilities.
- **Restrict egress.** Deny outbound connections by default so JNDI/LDAP/HTTP callbacks (remote class loading, OAST) fail. Block the app from reaching arbitrary hosts.
- **Disable dangerous runtime features**: for Java, set `com.sun.jndi.ldap.object.trustURLCodebase=false` and `com.sun.jndi.rmi.object.trustURLCodebase=false` to stop remote codebase loading.
- **Isolate the deserialization work** in a separate process/service with a minimal classpath, so even successful RCE lands in a low-value sandbox.
- **Enforce resource limits** (CPU, memory, max request size, parser depth/reference caps) to blunt DoS via crafted object graphs.

## Layer 5 — Patch Libraries & Shrink the Gadget Surface

Gadget chains are assembled from classes already on your classpath. Fewer risky libraries means fewer chains an attacker can build.

- **Keep dependencies current.** Historically, vulnerable versions of libraries such as Apache Commons Collections, Commons BeanUtils, and various JSON binders have provided the building blocks for real-world deserialization RCE. Patch them.
- **Use SCA (software composition analysis)** in CI to flag known-vulnerable serializers and gadget libraries, and fail the build on them.
- **Remove unused dependencies** so they cannot contribute gadgets.
- **Migrate off deprecated serializers** (e.g. .NET `BinaryFormatter`) on a schedule, not "someday."
- **Pin safe defaults** in shared libraries/wrappers so no team can accidentally re-enable polymorphic typing or unsafe loaders.

## Layer 6 — Monitoring & Detection

Deserialization RCE is often blind, so instrument the code paths and watch for the tell-tale side effects:

- **Log every deserialization failure and blocked class** (from your `ObjectInputFilter` / restricted unpickler / `allowed_classes` rejections) as a security event, with source IP and correlation ID.
- **Alert on unexpected class-resolution attempts** and on JNDI/LDAP/RMI lookups originating from application servers.
- **Watch for the app process spawning shells** (`sh`, `cmd`, `powershell`) or making unexpected outbound connections right after handling serialized input.
- **Baseline payload size and depth**; sudden large or deeply nested blobs can indicate DoS or gadget delivery.
- **Feed these events to a SIEM** with correlation rules, and route real detections to on-call. A blocked deserialization attempt is a high-signal event—treat it as an active probe.

## Per-Language Quick Reference

| Language | Avoid | Prefer | If forced, constrain with |
| --- | --- | --- | --- |
| Python | `pickle.loads`, `yaml.load`, `marshal.load` | `json`, `yaml.safe_load` | Restricted `Unpickler.find_class` allow-list |
| Java | `ObjectInputStream.readObject` on untrusted input, Jackson default typing | JSON/protobuf DTOs, no polymorphic typing | `ObjectInputFilter` (JEP 290) allow-list + size/depth caps |
| PHP | `unserialize($userInput)`, `phar://` exposure | `json_decode` | `unserialize($x, ['allowed_classes' => false])` |
| .NET | `BinaryFormatter`, `LosFormatter`, `TypeNameHandling.All` | `System.Text.Json` | `TypeNameHandling.None` or strict `SerializationBinder` |
| Node.js | `node-serialize`, unsafe deep-merge | `JSON.parse` + schema (zod/ajv) | Reject `__proto__`/`constructor`; null-prototype targets |

## Prevention Checklist

- [ ] No native deserializer (`readObject`, `pickle`, `unserialize`, `BinaryFormatter`) runs on data crossing a trust boundary.
- [ ] Untrusted structured input uses a **data-only format** (JSON/protobuf) parsed to plain values.
- [ ] Every deserialized payload is **validated against a strict schema** (deny extra fields) before use.
- [ ] Where native serialization is unavoidable, a **class allow-list** (deny by default) plus size/depth limits are enforced *before* construction.
- [ ] Polymorphic typing is **off** (Jackson default typing, Json.NET `TypeNameHandling`).
- [ ] Client-round-tripped state is **HMAC-signed** (or authenticated-encrypted) with a secret from a vault, verified in constant time, with expiry/audience binding.
- [ ] The service runs **least-privilege**, with restricted egress and JNDI remote codebase loading disabled.
- [ ] Dependencies are **patched and scanned**; known gadget libraries are removed or updated.
- [ ] Deserialization failures and blocked classes are **logged, alerted, and monitored**.

## Next Steps

- **[Overview](./overview.html)**: What insecure deserialization is and why it matters
- **[Attack Vectors](./attack-vectors.html)**: How attackers craft gadget chains and tamper with serialized state
- **[Examples](./examples.html)**: Vulnerable vs. secure code in Java, Python, PHP, and Node.js
- **[Hands-On Lab](./lab/insecure-deserialization/)**: Practice detecting and fixing insecure deserialization in a safe, isolated environment

---

*Part of the [OWASP Top 10 Educational Repository](/platform/frontend/index.html)*
