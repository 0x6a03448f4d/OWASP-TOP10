# Insecure Deserialization - Examples

Each pair below shows a **vulnerable** implementation and the **secure** version in the same language. The vulnerable versions all share one root cause: a native, type-restoring deserializer runs on data an attacker controls. The secure versions either drop native serialization for a data-only format or constrain it with an allow-list plus integrity checks.

## Table of Contents

- [Java — ObjectInputStream vs. JSON DTO + filter](#java--objectinputstream-vs-json-dto--filter)
- [Python — pickle vs. signed JSON](#python--pickle-vs-signed-json)
- [PHP — unserialize vs. json_decode / allowed_classes](#php--unserialize-vs-json_decode--allowed_classes)
- [Node.js — node-serialize vs. JSON.parse + schema](#nodejs--node-serialize-vs-jsonparse--schema)
- [Side-by-Side Summary](#side-by-side-summary)
- [Next Steps](#next-steps)

## Java — ObjectInputStream vs. JSON DTO + filter

### Vulnerable

```java
// Reads a serialized Java object straight from the request body.
// Any gadget chain on the classpath (e.g. a vulnerable Commons Collections)
// executes DURING readObject() -> remote code execution.
protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws IOException, ClassNotFoundException {
    ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
    UserPrefs prefs = (UserPrefs) ois.readObject();   // RCE sink
    applyPreferences(prefs);
}
```

### Secure

```java
// Accept JSON, bind it to a plain DTO, validate. No arbitrary types instantiate.
private static final ObjectMapper MAPPER = new ObjectMapper()
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES); // or reject extras
// NOTE: default typing stays OFF; never call MAPPER.enableDefaultTyping().

protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    UserPrefs prefs = MAPPER.readValue(req.getInputStream(), UserPrefs.class);
    validate(prefs);                        // schema/business-rule checks
    applyPreferences(prefs);
}

// If a legacy protocol truly requires native serialization, constrain it:
ObjectInputStream ois = new ObjectInputStream(in);
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
    "com.example.dto.*;java.util.*;java.lang.*;!*;" +   // allow-list, deny rest
    "maxdepth=20;maxrefs=500;maxbytes=100000"));        // anti-DoS caps
Object obj = ois.readObject();
```

## Python — pickle vs. signed JSON

### Vulnerable

```python
import pickle
from base64 import b64decode

@app.route('/session', methods=['POST'])
def load_session():
    session_data = request.cookies.get('session')
    # DANGEROUS: a crafted cookie with __reduce__ runs os.system() here.
    user = pickle.loads(b64decode(session_data))
    return f"Welcome {user.name}"
```

### Secure

```python
import hmac, hashlib, json, time
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

SECRET = app.config['SESSION_SIGNING_KEY']      # 32+ random bytes from a vault

def verify(token: str):
    try:
        body_b64, sig_b64 = token.split('.')
        expected = hmac.new(SECRET, body_b64.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(b64d(sig_b64), expected):   # constant-time
            return None                                        # tampered
        state = json.loads(b64d(body_b64))      # data-only: no objects restored
        return state if state.get('exp', 0) > time.time() else None
    except Exception:
        return None

@app.route('/session', methods=['POST'])
def load_session():
    state = verify(request.cookies.get('session', ''))
    if not state:
        return "Invalid session", 401
    return f"Welcome {state['name']}"
```

> The cookie is now a signed, data-only JSON blob. An attacker cannot forge it without the key, and even a valid blob only ever produces plain values—never an executable object graph.

## PHP — unserialize vs. json_decode / allowed_classes

### Vulnerable

```php
<?php
// Attacker sends a serialized object string as the cookie. If any class with
// a useful __wakeup/__destruct exists (a POP-chain gadget), it fires here.
$prefs = unserialize($_COOKIE['prefs']);       // object injection sink
echo "Theme: " . $prefs->theme;
?>
```

### Secure

```php
<?php
// BEST: user-supplied structured data as JSON -> arrays/scalars only.
$prefs = json_decode($_COOKIE['prefs'] ?? '{}', true);
if (!is_array($prefs) || !isset($prefs['theme'])) {
    http_response_code(400);
    exit('Invalid preferences');
}
$theme = in_array($prefs['theme'], ['light', 'dark'], true)
       ? $prefs['theme'] : 'light';            // allow-list the value
echo "Theme: " . htmlspecialchars($theme);

// IF a legacy format forces unserialize(), forbid object instantiation:
$data = unserialize($raw, ['allowed_classes' => false]);
?>
```

## Node.js — node-serialize vs. JSON.parse + schema

### Vulnerable

```javascript
// node-serialize can restore FUNCTIONS and evaluates them on load.
// A cookie ending in ()  self-executes during unserialize -> RCE.
const serialize = require('node-serialize');

app.get('/profile', (req, res) => {
  const profile = serialize.unserialize(req.cookies.profile);  // eval sink
  res.send(`Hi ${profile.name}`);
});
```

### Secure

```javascript
// JSON.parse never restores or executes functions. Validate the shape,
// and reject prototype-pollution keys before merging into any object.
const { z } = require('zod');

const Profile = z.object({
  name:  z.string().max(64),
  theme: z.enum(['light', 'dark'])
}).strict();                                    // reject unexpected keys

app.get('/profile', (req, res) => {
  let profile;
  try {
    profile = Profile.parse(JSON.parse(req.cookies.profile || '{}'));
  } catch {
    return res.status(400).send('Invalid profile');
  }
  res.send(`Hi ${profile.name}`);
});

// If you must deep-merge untrusted JSON, block dangerous keys:
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
for (const key of Object.keys(parsed)) {
  if (FORBIDDEN.has(key)) throw new Error('unsafe key');
}
```

## Side-by-Side Summary

| Language | Vulnerable sink | Secure approach |
| --- | --- | --- |
| Java | `ObjectInputStream.readObject` on request body | JSON DTO (typing off) + validation; else `ObjectInputFilter` allow-list |
| Python | `pickle.loads` on a cookie | HMAC-signed, data-only JSON verified before use |
| PHP | `unserialize` on a cookie | `json_decode` + value allow-list; else `allowed_classes => false` |
| Node.js | `node-serialize.unserialize` | `JSON.parse` + strict schema; block `__proto__` |

> **The common fix:** stop letting untrusted input choose which types get instantiated. Restore *data*, validate it, and sign anything that round-trips through the client.

## Next Steps

- **[Overview](./overview.html)**: What insecure deserialization is and why it matters
- **[Attack Vectors](./attack-vectors.html)**: How attackers craft gadget chains and tamper with serialized state
- **[Prevention](./prevention.html)**: Layered defenses—safe formats, allow-lists, integrity, and least privilege
- **[Hands-On Lab](./lab/insecure-deserialization/)**: Practice detecting and fixing insecure deserialization in a safe, isolated environment

---

*Part of the [OWASP Top 10 Educational Repository](/)*
