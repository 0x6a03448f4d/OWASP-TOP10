# Insecure Deserialization - Overview

## Table of Contents

- [What is Insecure Deserialization?](#what-is-insecure-deserialization)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)
- [How to Identify if You're Vulnerable](#how-to-identify-if-youre-vulnerable)

## What is Insecure Deserialization?

**Serialization** is the process of turning an in-memory object—with its fields, its type, and sometimes its behaviour—into a flat stream of bytes that can be stored on disk, cached, put in a cookie, or sent across a network. **Deserialization** is the reverse: taking that byte stream and rebuilding a live object from it. **Insecure Deserialization** is what happens when an application rebuilds objects from data that an attacker controls, without treating that data as hostile.

The danger is subtle because deserialization feels like "just reading data." But many serialization formats do far more than copy field values—they can decide which classes to instantiate, invoke constructors and callback methods, restore private state, and reconnect object graphs. When the byte stream is attacker-controlled, the attacker is effectively scripting your runtime: choosing which types get created and which methods fire while the object is being reassembled. Depending on what classes are available on the application's classpath, that can escalate all the way to **remote code execution (RCE)**.

> **The core insight:** a native serialization format is not a data format—it is a small program that tells the runtime how to reconstruct an object. Deserializing untrusted input is therefore closer to running untrusted code than to parsing untrusted text.

### Serialization vs. Deserialization

```
Serialization  (safe direction):
  object  -->  bytes        e.g. pickle.dumps, ObjectOutputStream, serialize()

Deserialization (dangerous with untrusted input):
  bytes   -->  object       e.g. pickle.loads, ObjectInputStream, unserialize()
                            ^ attacker-controlled bytes can steer WHICH objects
                              are built and WHICH methods run during rebuild
```

### What Goes Wrong

When the serialized data comes from an untrusted source—an HTTP request body, a cookie, a message on a queue, an uploaded file, a query parameter—an attacker can:

- **Execute arbitrary code** by crafting an object graph that, during reconstruction, chains together existing library methods into a "gadget chain" ending in a command execution or code-loading sink.
- **Tamper with application state** by editing serialized fields—flipping `role: user` to `role: admin`, changing a price, or extending an expiry—when the data is not integrity-protected.
- **Escalate privileges or bypass authentication** by forging the serialized representation of a trusted object such as a session or identity token.
- **Trigger injection** (SQL, command, path) because the reconstructed object later flows into a sink, or because a "magic" callback method runs unexpected code paths.
- **Cause denial of service** with small payloads that expand into enormous object graphs or deeply recursive structures ("billion laughs"–style amplification, hash-collision maps, or self-referential graphs).

### Two Distinct Failure Modes

It is worth separating the two problems this category covers, because they have different fixes:

| Failure mode | What the attacker needs | Typical outcome |
|---|---|---|
| **Object-injection / gadget chains** | An endpoint that deserializes attacker bytes with a rich, dangerous format (Java, pickle, PHP, BinaryFormatter) | Remote code execution |
| **Tampering / replay** | Serialized data that is not signed or is signed with a weak/known key | Privilege escalation, auth bypass, data forgery |

The first is fixed by *not deserializing untrusted data with a dangerous format*. The second is fixed by *integrity protection (signing) and treating decoded state as untrusted input*. A single endpoint can suffer from both.

## Why Does This Matter?

### Business Impact

- **Full server compromise**: The headline outcome of insecure deserialization is remote code execution—an attacker running commands as your application. That is the most severe result any single vulnerability class can produce, and it often needs no valid credentials.
- **Account takeover and fraud**: Tampered serialized cookies and tokens let attackers impersonate other users or elevate their own privileges, leading directly to fraud, data theft, and abuse.
- **Data breach and regulatory exposure**: RCE on an application server usually means access to databases and secrets, triggering GDPR, HIPAA, and PCI-DSS breach obligations, fines, and notification duties.
- **Supply-chain blast radius**: Because the exploit depends on which libraries ("gadgets") are on the classpath, a single vulnerable dependency can make thousands of downstream applications exploitable at once.
- **Hard to detect after the fact**: A deserialization RCE often looks like a normal request carrying an opaque blob. Without specific logging, the intrusion can go unnoticed until damage is done.

### Technical Impact

- **Remote Code Execution**: Gadget chains (Java Commons Collections, PHP POP chains, Python pickle `__reduce__`, .NET `BinaryFormatter`) convert a deserialization call into arbitrary command or code execution.
- **Authentication bypass / privilege escalation**: Forged or tampered serialized identity objects grant access the attacker should not have.
- **Injection and SSRF**: Reconstructed objects can carry attacker-chosen values into downstream sinks, and gadget chains frequently include JNDI/URL lookups that reach out to attacker-controlled hosts.
- **Denial of Service**: Crafted objects that expand exponentially or recurse deeply exhaust CPU and memory before any business logic runs.
- **Persistence and lateral movement**: Once code runs on one node, attackers plant web shells, harvest credentials, and pivot across the environment.

## Technical Context

### Why "Just Reading Data" Can Run Code

Native serialization formats were designed for convenience: developers wanted to save an object and get the exact same object back, including its type and private state. To do that, the deserializer must be able to instantiate arbitrary classes named in the stream and run their reconstruction hooks. Those hooks—`readObject` in Java, `__reduce__`/`__setstate__` in Python pickle, `__wakeup`/`__destruct` in PHP, callbacks in .NET—are exactly the machinery an attacker abuses.

The attacker rarely needs to smuggle in new code. Instead they assemble a **gadget chain**: a sequence of method calls, using classes *already present* in the application or its libraries, that the deserializer will trigger automatically during reconstruction. The chain starts at a callback that always runs, threads through helper classes, and ends at a "sink" such as `Runtime.exec`, a template evaluation, or a JNDI lookup. Tools like **ysoserial** (Java) and **ysoserial.net** (.NET) automate building these payloads for dozens of known library combinations.

### Language-by-Language Mechanics

| Platform | Dangerous API | Attacker mechanism | Safe direction |
|---|---|---|---|
| Java | `ObjectInputStream.readObject()` | Gadget chains (e.g. Commons Collections) triggered via `readObject`; JNDI/RMI to load remote classes | JSON/DTOs; `ObjectInputFilter` allow-lists (JEP 290) |
| Python | `pickle.loads()`, `yaml.load()` (full loader) | `__reduce__` returns a callable + args the unpickler executes; YAML `!!python/object/apply` tags | `json`; `yaml.safe_load()` |
| PHP | `unserialize()`, `phar://` stream access | POP chains through `__wakeup`/`__destruct`/`__toString`; phar metadata deserialized on file ops | `json_decode()`; `unserialize($x, ['allowed_classes'=>false])` |
| .NET | `BinaryFormatter`, `NetDataContractSerializer`, Json.NET `TypeNameHandling` | Type information in the stream lets attackers instantiate dangerous types; ViewState with a known key | `System.Text.Json`; avoid `BinaryFormatter` (deprecated/removed) |
| Node.js | `node-serialize`, `funcster`, unsafe `eval`-based parsers | Serialized function bodies executed via IIFE/`eval`; prototype pollution in object mergers | `JSON.parse()`; guard `__proto__`/`constructor` |
| Ruby | `Marshal.load()`, unsafe `YAML.load`/Psych | Object-injection gadget chains through core and library classes | JSON; `YAML.safe_load` |

### A Minimal Illustration (Python pickle)

```python
import pickle, os

class Payload:
    # __reduce__ tells the unpickler how to "rebuild" this object.
    # The unpickler will CALL the returned callable with the returned args.
    def __reduce__(self):
        return (os.system, ("id",))   # attacker-chosen callable + args

blob = pickle.dumps(Payload())        # attacker builds this once

# ...delivered as a cookie / upload / message body...

pickle.loads(blob)                    # victim: os.system("id") runs here
```

No exotic bug is needed—`pickle` is *documented* as unsafe on untrusted input. The same pattern, with different plumbing, exists in every native serializer above.

### Where Serialized Data Enters Applications

- Session state and "remember me" tokens stored in cookies or server-side caches.
- Hidden form fields and view state (for example ASP.NET `__VIEWSTATE`).
- Message queues, caches, and inter-service RPC (Java RMI/JMS, gRPC side-channels, Redis-cached blobs).
- API request bodies that accept a serialized object instead of plain JSON.
- Uploaded files and file paths (PHP `phar://` triggers deserialization on ordinary file operations).
- Configuration, plugins, and cached templates rebuilt at runtime.

## Real-World Impact

The incidents below are described as **classes of publicly documented events and research** rather than precise, quoted figures. They illustrate how deserialization moves from theory to breach.

### Case Class 1: The Java Deserialization "Apocalypse" (2015 onward)

**What happened**: Security researchers published a practical, reusable gadget chain built from the widely deployed *Apache Commons Collections* library, and released the **ysoserial** tool to generate payloads. Any Java application that called `ObjectInputStream.readObject()` on attacker-controlled bytes, and happened to have a vulnerable library on its classpath, could be driven to remote code execution.

**Why it mattered**: The affected pattern lived in extremely common middleware and application servers (enterprise Java app servers, CI systems, and management consoles). Because the gadget depended on a *library*, one research release turned a large population of unrelated applications into targets simultaneously.

**Root cause**: Deserializing untrusted input with Java's native serializer, combined with dangerous gadgets on the classpath. This event directly motivated the JDK's serialization filtering (JEP 290 / `ObjectInputFilter`).

### Case Class 2: Ruby on Rails YAML/Parameter Deserialization (2013)

**What happened**: A well-known Rails vulnerability (tracked as **CVE-2013-0156**) allowed crafted request parameters to be coerced into YAML/symbol/object deserialization, leading to remote code execution on a huge number of default Rails deployments.

**Why it mattered**: It required no authentication and targeted the framework's default request parsing, so essentially every unpatched app was exploitable. It became a canonical example of "parsing untrusted input into rich objects is dangerous."

**Root cause**: Automatic conversion of untrusted parameters into typed objects, including YAML, without restriction.

### Case Class 3: PHP Object Injection and `phar://` Deserialization

**What happened**: PHP applications—including popular CMS platforms and their plugin ecosystems—have repeatedly been exploited through `unserialize()` on user input, using **POP (Property-Oriented Programming) chains** that abuse magic methods like `__wakeup` and `__destruct`. Research presented at Black Hat (2018) showed that even without a direct `unserialize()` call, the `phar://` stream wrapper deserializes attacker-controlled metadata during ordinary file operations (`file_exists`, `fopen`, image checks).

**Why it mattered**: It expanded the attack surface from "obvious deserialization endpoints" to "anywhere a filename is influenced by the user," catching many developers by surprise.

**Root cause**: Rich native object reconstruction driven by untrusted strings and file paths.

### Case Class 4: .NET "Friday the 13th JSON Attacks" and ViewState

**What happened**: Research presented at Black Hat (2017) demonstrated remote code execution across many .NET serializers—including `BinaryFormatter`, `NetDataContractSerializer`, and Json.NET when `TypeNameHandling` was enabled—because the serialized stream carried *type* information the deserializer would faithfully instantiate. Separately, ASP.NET `__VIEWSTATE` was shown to be exploitable for RCE when the signing/encryption key (`machineKey`) was known, leaked, or left at a default.

**Why it mattered**: It showed that "typed" JSON and binary serialization are just as dangerous as classic Java/PHP when type resolution is attacker-influenced. Microsoft ultimately deprecated and moved to remove `BinaryFormatter`.

**Root cause**: Polymorphic deserialization (attacker chooses the type) and weak/leaked integrity keys.

### Case Class 5: Node.js `node-serialize` Code Execution

**What happened**: The `node-serialize` package (and similar libraries) supported serializing JavaScript *functions*. On deserialization, a specially crafted payload with an immediately-invoked function expression (IIFE) caused the function body to execute, giving RCE to anyone who could supply the serialized string.

**Why it mattered**: It is a clean demonstration that "serialization libraries that restore behaviour, not just data" are inherently unsafe on untrusted input—even in a language without Java-style gadgets.

**Root cause**: A serializer that evaluates embedded code during "parsing."

## Prevalence and Statistics

In the **OWASP Top 10 2017**, Insecure Deserialization debuted at **A8:2017**. OWASP characterised it as relatively *uncommon to find by scanning* but *severe when present*—exploitation can be difficult to develop but, once a working gadget exists, it is highly reliable and reusable. The category was added largely on the strength of industry data and the wave of Java deserialization research described above.

Rather than quote precise counts (which vary by source and year), the defensible picture is:

- Deserialization flaws are **lower-frequency but high-severity**—when present they frequently yield remote code execution, the most damaging outcome.
- Exploitability is **weaponised**: public tools (ysoserial family) and published gadget catalogues mean an attacker often does not need to craft a chain from scratch.
- The problem is **concentrated in native serializers and typed/polymorphic parsers**; applications that exchange plain JSON/DTOs and validate them are largely immune to the RCE variant.

> **Edition note:** In the **OWASP Top 10 2021**, this category was merged into **A08:2021 – Software and Data Integrity Failures**, which broadens the theme to include unsigned updates, insecure CI/CD pipelines, and untrusted plugins alongside deserialization. This lesson keeps the **2017 A8** framing and terminology; the defensive principles carry directly into the 2021 category.

## Common Misunderstandings

### Myth 1: "Deserialization just reads data, so it's as safe as parsing JSON"

**Reality**: Native serializers reconstruct *types and behaviour*, not just values. During reconstruction they call methods you never intended to run. That is why deserializing untrusted input is closer to executing untrusted code than to parsing text.

### Myth 2: "There's no dangerous code in the serialized object, so it's fine"

**Reality**: Gadget chains reuse code that is *already* on your classpath. The payload contains no malware—it contains instructions that stitch your own libraries into a weapon. Auditing the payload for "bad code" misses the point.

### Myth 3: "We encrypt/encode the serialized blob, so nobody can tamper with it"

**Reality**: Base64 and encryption are not integrity. Encoding is trivially reversible, and encryption without authentication (or with a leaked/default key, like some ViewState deployments) does not stop forgery. You need a **keyed integrity check (HMAC) or authenticated encryption**, verified *before* deserialization.

### Myth 4: "We only accept serialized data from our own services, so it's trusted"

**Reality**: Internal traffic is reached through SSRF, compromised dependencies, message-queue access, and cache poisoning. "Internal" is not a trust boundary for a format that can yield RCE.

### Myth 5: "Switching to JSON automatically makes us safe"

**Reality**: JSON is much safer *as a data-only format*, but not if you enable **polymorphic type handling** (Json.NET `TypeNameHandling`, Jackson default typing, YAML type tags). Attacker-controlled type names reintroduce the exact same RCE. Keep JSON strictly data, and validate it against a schema.

### Myth 6: "A firewall/WAF will catch deserialization payloads"

**Reality**: Payloads are opaque binary or base64 blobs that vary endlessly; signature-based filtering is easily evaded. WAFs add friction but are not a fix. The fix is architectural: don't deserialize untrusted input with dangerous formats.

## How to Identify if You're Vulnerable

Ask these questions about your application:

- [ ] Do any endpoints deserialize data from requests, cookies, headers, files, or queues using a **native serializer** (Java `ObjectInputStream`, Python `pickle`, PHP `unserialize`, .NET `BinaryFormatter`, Ruby `Marshal`)?
- [ ] Is any serialized state (session, token, view state) sent to the client **without a verified HMAC or authenticated encryption**?
- [ ] Do you use JSON/XML/YAML libraries with **polymorphic type handling or type tags** enabled (Json.NET `TypeNameHandling`, Jackson default typing, `yaml.load` full loader)?
- [ ] Can a user influence a **filename or path** that reaches PHP file functions (exposing `phar://` deserialization)?
- [ ] Are potentially dangerous **gadget libraries** (e.g. Commons Collections) on your classpath, and are they patched?
- [ ] If deserialization is unavoidable, is there a **strict class allow-list** (Java `ObjectInputFilter`, PHP `allowed_classes`) in place?
- [ ] Do you **validate the reconstructed object** against a schema and business rules before using it?
- [ ] Do you **log and monitor** deserialization failures and type-resolution errors as security events?

If you answered "yes" to the first three or "no" to the rest, you likely have exploitable deserialization exposure today.

## Key Takeaways

1. **Native deserialization is code execution in disguise**—treat it like `eval()` on untrusted input.
2. **Gadget chains reuse your own libraries**—the payload looks like data, not malware.
3. **Prefer data-only formats** (plain JSON) with strict schema validation over native serializers.
4. **Integrity is not encoding or encryption alone**—sign serialized state with HMAC and verify before use.
5. **"Internal" and "encrypted" are not trust boundaries**—design so untrusted input never reaches a dangerous deserializer.

## Next Steps

- **[Attack Vectors](./attack-vectors.html)**: How attackers craft gadget chains and tamper with serialized state
- **[Prevention](./prevention.html)**: Layered defenses—safe formats, allow-lists, integrity, and least privilege
- **[Examples](./examples.html)**: Vulnerable vs. secure code in Java, Python, PHP, and Node.js
- **[Hands-On Lab](./lab/insecure-deserialization/)**: Practice detecting and fixing insecure deserialization in a safe, isolated environment

---

*Part of the [OWASP Top 10 Educational Repository](/platform/frontend/index.html)*
