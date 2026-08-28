# M7:2016 Client Code Quality - Attack Vectors

## Table of Contents
- [Understanding Client-Code Attack Vectors](#understanding-client-code-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Untrusted-Input Entry Points](#untrusted-input-entry-points)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Client-Code Defects](#chaining-client-code-defects)

## Understanding Client-Code Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these defects in apps you own or are authorised to test.

Client-code-quality attacks are exploited by **feeding hostile input to a client that trusts it**. The attacker does not need a server bug or stolen credentials—only a way to deliver a crafted value to a code path the app runs on the device. Because the defect is in how the code handles input (a missing bounds check, a dangerous API, an unchecked length), the "payload" is often just a message, a file, a link, or a nearby radio frame.

The attacker's goal in this category is usually one of:

- **Crash the app on demand** (denial of service), sometimes repeatedly enough to make the app unusable.
- **Corrupt memory** in native code, aiming to overwrite a code pointer and hijack control flow inside the sandbox.
- **Leak memory** via an over-read to recover secrets or defeat a mitigation.
- **Reach app or device APIs** through a poorly scoped WebView JavaScript bridge.

### Core Attack Flow

```
1. Choose an entry point
   |
   Deep link, IPC/Intent, WebView, imported file, Bluetooth/NFC, server response
2. Reach a vulnerable handler
   |
   A native parser / a dangerous-API call site / an unsafe deserializer
3. Craft the input
   |
   Oversized length, overflowing size arithmetic, hostile format string, bad type
4. Trigger the defect
   |
   Buffer/heap overflow, UAF, integer overflow, format-string write, crash
5. Escalate (if possible)
   |
   Turn corruption into control-flow hijack, or leak memory, or abuse the JS bridge
```

## Untrusted-Input Entry Points

Every M7 attack starts where attacker-influenced data enters the client. The most common mobile entry points:

| Entry point | How the attacker delivers input | Typical handler at risk |
|-------------|----------------------------------|--------------------------|
| Deep links / custom URL schemes / app links | A crafted link the victim taps (web, message, QR) | URL/route parser, query-param handling |
| IPC (Intents, Services, Content Providers, Broadcasts) | A malicious app on the same device sends data to an exported component | Extra/selector parsing, native handoff |
| WebView | Attacker-controlled or injected web content, JS bridge calls | `addJavascriptInterface` bridge, message handlers |
| Imported files / shared storage | A document, image, or media file the user opens | Native media/format decoders |
| Bluetooth / NFC / QR | A nearby device or tag sends a binary/TLV frame | Custom binary/TLV parser (often native) |
| Server responses | Tampered/MITM'd response, or a malicious backend | Client-side length/offset trust, deserializers |

## Common Attack Patterns

### 1. Stack Buffer Overflow via a Deep Link into Native Code

A deep-link handler copies an attacker-controlled parameter into a fixed-size native buffer without checking length.

```c
// Native (JNI) handler, reached from a deep link parameter
void handle_token(const char *token) {   // token from myapp://auth?token=...
    char buf[64];
    strcpy(buf, token);                  // no bounds check -> stack overflow
    verify(buf);
}
```

```
# Attacker delivers an oversized value:
myapp://auth?token=AAAAAAAA...(300+ bytes)...AAAA
```

**Payoff**: the copy runs past `buf`, overwriting the saved return address. At minimum a crash (DoS); with a defeated canary/ASLR, a step toward control-flow hijack.

### 2. Heap Overflow via Integer Overflow in a Length Field

A native parser reads a count from untrusted input and multiplies it to size an allocation. The multiplication wraps.

```c
uint32_t n = read_u32(input);              // attacker-controlled
Item *items = malloc(n * sizeof(Item));    // n * 24 wraps -> tiny allocation
for (uint32_t i = 0; i < n; i++)           // loop still runs n times
    items[i] = parse_item(input);          // writes far past the buffer
```

**Payoff**: heap metadata and adjacent objects are overwritten—the classic route from a malformed message or file to heap corruption.

### 3. Use-After-Free Triggered by Malformed Input

An error path frees an object but a later code path still uses it.

```c
Session *s = alloc_session(input);
if (!validate(input)) {
    free(s);                 // freed on the error branch
}
process(s);                  // still dereferenced -> use-after-free
```

**Payoff**: if the attacker can control heap allocation to reclaim the freed slot with their own data, the stale pointer reads/writes attacker-shaped memory—a common primitive for exploitation.

### 4. Format-String Bug in a Native Log/Error Path

Untrusted input is passed as the format string itself.

```c
void log_event(const char *name) {         // name from a server response / IPC
    char line[128];
    snprintf(line, sizeof(line), name);    // WRONG: name is the format string
    write_log(line);
}
```

```
# Attacker supplies specifiers as the "name":
name = "%x %x %x %n"     # read the stack; %n can write memory
```

**Payoff**: information disclosure via `%x`/`%s`, or a memory write via `%n`—from what looked like a harmless log line.

### 5. Unsafe Deserialization of an IPC or File Payload

The client decodes an object graph from bytes another app or a file supplies.

```java
// Android: reading a serialized object from an Intent extra
Object obj = getIntent().getSerializableExtra("data");  // arbitrary classes
```
```swift
// iOS: legacy unarchiving without secure coding
let obj = NSKeyedUnarchiver.unarchiveObject(with: data) // arbitrary classes
```

**Payoff**: type-confusion crashes at least; with the right classes present, a gadget chain can escalate to code execution—the client-side twin of server deserialization attacks.

### 6. WebView JavaScript-Bridge Abuse

A bridged WebView loads content the attacker can influence; JavaScript calls into the exposed object.

```java
// Legacy Android (< API 17): reflection exposed ALL public methods
webView.addJavascriptInterface(new AppBridge(), "bridge");
webView.loadUrl(untrustedUrl);           // attacker content can reach the bridge
```

```javascript
// Attacker JavaScript running in the WebView:
bridge.readFile('/data/data/com.app/secret');   // whatever the bridge exposes
// On very old Android, reflection could reach Runtime.exec(...)
```

**Payoff**: attacker-controlled web content reaches native app methods—or, on unpatched legacy versions, device command execution with the app's permissions.

### 7. Malformed Bluetooth/NFC Frame into a Native TLV Parser

A nearby device sends a binary/TLV frame whose declared length exceeds the buffer.

```c
// Reading a TLV: type, length, value
uint8_t len = frame[1];                  // attacker sets len = 0xFF
memcpy(dst, &frame[2], len);             // dst is smaller than 255 -> overflow
```

**Payoff**: proximity-based memory corruption—no network needed, just physical/radio range and an app that trusts the declared length.

### 8. Trusting a Length/Offset From a Server Response

The client reads a size or offset from a response and uses it to index or copy without validation.

```java
int off = response.getInt("offset");     // from a tampered/MITM'd response
byte[] chunk = buffer.copyOfRange(off, off + response.getInt("len"));
// negative or oversized off/len -> exception or out-of-bounds access
```

**Payoff**: crash (DoS) in the managed case; in native code the same pattern is an out-of-bounds read/write. This is why "it came from our server" is not a validation exemption.

### 9. Force-Unwrap / Null-Dereference Crash From Unexpected Types

Managed code assumes a field is present and of a given type.

```swift
// Swift: force-unwrap on attacker-influenced data
let id = json["id"] as! Int              // wrong type / missing -> crash
```
```kotlin
// Kotlin: non-null assertion on a nullable extra
val url = intent.getStringExtra("url")!! // null -> NullPointerException
```

**Payoff**: a reliable, remotely-triggerable crash—low severity individually, but a dependable DoS and sometimes a foothold if it happens mid-security-check.

## Chaining Client-Code Defects

Individually modest defects combine into serious outcomes:

```
Over-read leaks a pointer (info leak)      -> defeats ASLR for this process
        +
Heap overflow in the same parser           -> now aimed with a known address
        +
Corrupted function pointer is called        -> control-flow hijack inside the sandbox
        =  memory-corruption code execution from a single crafted file
```

Another common chain on Android:

```
Exported component accepts an Intent        -> attacker app delivers a payload
        -> payload deserialized into arbitrary objects
        -> gadget classes present on the device
        =  code execution reached from a neighbouring app, no network required
```

## Key Takeaways

1. **The payload is the input**—M7 is triggered by ordinary-looking links, files, IPC messages, and frames, not exotic exploits.
2. **Native parsers are the prime target**—memory corruption lives where memory-unsafe code trusts a length or index.
3. **Crashes are the doorway**—a reliable crash is DoS now and often the first sign of an exploitable corruption.
4. **Every boundary is hostile**—deep links, IPC, WebView, files, radios, and server responses all deliver untrusted input.
5. **Small defects chain**—an info leak plus an overflow equals code execution; validate at every entry point to break the chain early.

## Next Steps

- **[Prevention Guide](prevention.md)**: Bounds-check input and harden native code
- **[Code Examples](examples.md)**: Vulnerable vs. secure code across Kotlin/Java, Swift, and C/C++
- **[Mobile Top 10](/learn/mobile)**: Return to the full mobile security curriculum
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
