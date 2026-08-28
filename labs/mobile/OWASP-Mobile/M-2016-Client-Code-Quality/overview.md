# M7:2016 Client Code Quality - Overview

## Table of Contents
- [What is Client Code Quality?](#what-is-client-code-quality)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Client Code Quality?

**Client Code Quality** (M7 in the OWASP Mobile Top 10, 2016 edition) is the category for *code-level implementation defects inside the mobile client itself* that turn into security problems. It is the "bad coding practices" bucket: the memory-safety bugs, the unchecked input handling, the misuse of dangerous APIs, and the sloppy error handling that live in the app you ship to the device—not on the server.

The distinction is important. Many mobile risks (insecure storage, weak crypto, insecure communication, broken authentication) are about *what* the app does with data. M7 is about *how the code is written*. Two apps can implement the exact same feature; one parses an incoming deep link with a bounds-checked, type-safe routine, and the other copies attacker-controlled bytes into a fixed native buffer with `strcpy`. Same feature, same data flow—but only the second one crashes, corrupts memory, or executes attacker code when fed a hostile input.

> **Scope note:** M7 is about *client-side* code quality. Defects in server code are a separate concern (they fall under the web/API Top 10). M7 asks: when untrusted data reaches your mobile app—from a deep link, an IPC message, a WebView, a file, a Bluetooth/NFC frame, or a server response—is the code that handles it written safely?

### Core Concept

```
Good client code quality:
  Untrusted input -> validated and bounds-checked at the client boundary
  Native buffers  -> sized from the data, copied with length-limited APIs
  Dangerous APIs  -> avoided (no strcpy/sprintf/addJavascriptInterface abuse)
  Deserialization -> restricted to known types, never arbitrary classes
  Errors          -> handled explicitly; failures fail closed, no crash-to-DoS
  Memory          -> freed once, no reuse after free; secrets zeroed after use

Poor client code quality (M7):
  Untrusted input -> trusted as-is: length, type, and range unchecked
  Native buffers  -> fixed-size stack/heap buffers, copied with strcpy/memcpy(len_from_attacker)
  Dangerous APIs  -> strcpy, sprintf, gets, addJavascriptInterface on legacy WebView
  Deserialization -> arbitrary object graphs decoded from untrusted bytes
  Errors          -> swallowed or unhandled: NULL deref, uncaught exception -> crash
  Memory          -> use-after-free, double-free, leaks of tokens/keys in RAM
```

### Where the Defects Live

Client code quality issues are most dangerous in the parts of a mobile app that (a) are written in a memory-unsafe language, and (b) process input the user or a remote party controls:

- **Native code (C/C++ via the Android NDK or an iOS framework)**: The classic memory-safety bugs—stack and heap buffer overflows, integer overflow feeding an allocation, use-after-free, double-free, and format-string bugs—all live here. Managed Kotlin/Java/Swift code is largely immune to these *until it calls across JNI/FFI into native code*.
- **Parsers and decoders**: Anything that turns bytes into structure—a custom binary protocol, an image/media decoder, a TLV parser for NFC, a protobuf/JSON handler with a native backend—is where malformed input causes trouble.
- **Input entry points**: Deep links and app links, exported IPC surfaces (Intents, Services, Content Providers, custom URL schemes), WebView JavaScript bridges, files opened from shared storage, Bluetooth/NFC frames, and server responses. Each is a boundary where untrusted data enters the client.

## Why Does This Matter?

### Business Impact

- **Remote or local code execution on the device**: A memory-corruption bug in a native parser that processes attacker-controlled input can, in the worst case, be turned into arbitrary code execution inside the app's sandbox—giving an attacker whatever the app can reach (tokens, files, camera, contacts).
- **Crashes and denial of service**: The most common outcome is a reliable crash. A hostile deep link or push payload that reliably kills the app degrades the product, and a crash in a background service can be an availability problem in its own right.
- **Data corruption and integrity loss**: Out-of-bounds writes and integer-overflow-driven allocations can silently corrupt adjacent state, leading to wrong results the user (and business) trusts.
- **Reputation and store standing**: Crash-prone or exploitable apps draw negative reviews, and platform crash-reporting can surface memory bugs to attackers as much as to developers.
- **Sensitive-data exposure via memory leaks**: Keys, tokens, and personal data left in freed-but-not-zeroed memory can be recovered from crash dumps or by another bug.

### Technical Impact

- **Memory corruption**: Stack/heap overflows and use-after-free can overwrite return addresses, function pointers, or heap metadata—the raw material for control-flow hijacking.
- **Control-flow hijack**: When corruption reaches a code pointer, a crash becomes potential code execution (subject to platform mitigations like ASLR, PIE, and stack canaries).
- **Information disclosure**: Over-reads (reading past a buffer) can leak adjacent memory—including secrets—back to an attacker or into logs.
- **Logic bypass via crashes**: An unhandled exception during a security check can leave the app in a partially-initialised or fail-open state.
- **JavaScript-to-native bridge abuse**: A poorly scoped WebView bridge lets attacker-controlled web content reach app or (on legacy Android) device APIs.

## Technical Context

### The M7 Defect Families

#### 1. Memory-Safety Bugs in Native Code

C and C++ do not check array bounds, do not track object lifetimes, and do not detect arithmetic overflow. Any native routine that handles untrusted input can exhibit:

```
Stack buffer overflow  -> copy more bytes than a fixed local array holds
Heap buffer overflow   -> write past a malloc'd region, smash heap metadata
Use-after-free (UAF)   -> dereference a pointer after free(); may be attacker-reclaimed
Double-free            -> free() the same pointer twice, corrupt the allocator
Integer overflow       -> size arithmetic wraps, under-allocates, then overflows
Out-of-bounds read     -> read past the end, leak adjacent memory / crash
```

These are reachable in mobile apps through the **JNI/NDK** path on Android and through C/C++ frameworks and libraries on iOS. The managed layer (Kotlin/Java/Swift) hands bytes to native code, and the native code trusts a length or index it should have validated.

#### 2. Integer Overflow Feeding an Allocation

```c
uint32_t count = read_u32(input);          // attacker-controlled
uint8_t *buf = malloc(count * sizeof(Item)); // count * 24 can wrap on 32-bit
for (uint32_t i = 0; i < count; i++)        // loop uses the pre-overflow count
    buf[i] = parse_item(input);             // heap overflow
```

**Risk**: A multiplication that overflows produces a small allocation, then a large loop writes far past it.

#### 3. Format-String Bugs

```c
// Attacker-controlled string used as the format itself:
snprintf(out, sizeof(out), user_input);     // WRONG
// vs
snprintf(out, sizeof(out), "%s", user_input); // correct
```

**Risk**: `%x`/`%n`-style specifiers in the input read the stack or write memory. Most common in native logging and error paths.

#### 4. Unsafe Use of Dangerous APIs

| Dangerous API | Problem | Safer choice |
|---------------|---------|--------------|
| `strcpy`, `strcat`, `sprintf`, `gets` | No bounds; copy until NUL | `strlcpy`/`snprintf` with sizes, or safe C++ containers |
| `memcpy(dst, src, attacker_len)` | Length trusted from input | Validate `len <= sizeof(dst)` first |
| `WebView.addJavascriptInterface` (Android < 4.2 / API < 17) | Reflection exposed all public methods to JS | `@JavascriptInterface` annotation, modern API, no untrusted content |
| Java/Kotlin native deserialization of untrusted bytes | Arbitrary object graphs / gadget chains | Explicit schema (protobuf, JSON with strict types) |
| `NSKeyedUnarchiver` without secure coding (iOS) | Arbitrary class instantiation | `requiringSecureCoding` / `decodeObject(of:)` with a class allow-list |

#### 5. Improper Handling of Untrusted Input at Client Entry Points

```
Deep link / URL scheme  myapp://item?id=... , myapp://open?url=...
Intent / IPC extras     getIntent().getStringExtra("payload")
Content Provider input   a URI/selector supplied by another app
WebView                  postMessage / JS bridge / loaded HTML
File import             a document opened from shared storage
Bluetooth / NFC         a TLV/binary frame from a nearby device
Server response         a length field / offset the client trusts blindly
```

**Risk**: The code assumes well-formed, in-range input. A crafted value (oversized length, negative index, hostile URL, unexpected type) triggers a crash or a memory bug.

#### 6. Poor Error Handling and Memory Leaks of Sensitive Data

- Swallowed exceptions and ignored return codes leave the app in an undefined state; a failed security check that is not handled can fail open.
- Unchecked `NULL`/nil dereferences turn malformed input into crashes.
- Secrets (keys, tokens, decrypted PII) left in buffers that are freed but not zeroed can be recovered from memory dumps.

### Managed vs. Native: Where the Line Is

| Layer | Memory-safe? | Dominant M7 risks |
|-------|--------------|-------------------|
| Kotlin / Java (Android) | Mostly (bounds-checked, GC) | Unsafe deserialization, JS-bridge misuse, unchecked input, swallowed errors |
| Swift (iOS) | Mostly (bounds-checked, ARC) | Force-unwrap crashes, unsafe pointers, insecure unarchiving, C interop |
| C / C++ (NDK / native) | No | Buffer/heap overflow, UAF, double-free, integer overflow, format string |

## Real-World Impact

The examples below are **classes** of well-documented mobile client-code defects, described generically. They illustrate the pattern without asserting specific CVE numbers or breach statistics.

### Case Study Class 1: Native Media/Parser Overflows Reachable From Messages

**Defect class**:
- A native library that decodes media or a structured message format (image, audio, video, or a custom protocol) contains a memory-safety bug—an integer overflow feeding an allocation, or a length field trusted without bounds-checking.
- The mobile app feeds attacker-controlled bytes into that library when it renders a received message or preview.

**Impact**: Because the input can arrive remotely (a message, a shared file, a web resource) and is processed automatically, a malformed payload can crash the app and, in the worst documented cases of this class, corrupt memory in a way that leads toward code execution inside the app sandbox.

**Root cause**: Untrusted input reaching a memory-unsafe parser that trusts a length/size from the data. This is the canonical M7 pattern and the reason platform vendors invest heavily in sandboxing and rewriting media parsers in memory-safe languages.

### Case Study Class 2: Legacy WebView JavaScript-Bridge Exposure

**Defect class**:
- An app uses `addJavascriptInterface` on an Android version below 4.2 (API 17), where the bridge exposed *all* public methods of the injected object to JavaScript via reflection.
- The WebView loads content that an attacker can influence (a third-party page, content over cleartext, or an ad frame).

**Impact**: Attacker-controlled JavaScript could reach reflection and, on affected versions, invoke methods leading to command execution with the app's permissions—a widely discussed class of Android client-code weakness.

**Root cause**: A dangerous API combined with untrusted web content. The platform fix (the `@JavascriptInterface` annotation from API 17) restricts exposure, but the app must also avoid loading untrusted content into a bridged WebView.

### Case Study Class 3: Unsafe Deserialization of On-Device Data

**Defect class**:
- The client deserializes an object graph from untrusted bytes—an IPC extra, an imported file, or a cached server response—using a general-purpose mechanism (Java serialization, insecure `NSKeyedUnarchiver`) that can instantiate arbitrary classes.

**Impact**: Depending on the classes available on the device, this ranges from crashes and type-confusion to gadget-chain-driven code execution. It is a client-side instance of the same deserialization problem seen on servers.

**Root cause**: Trusting the shape of serialized data. The fix is a strict, explicit schema and secure-coding APIs with a class allow-list.

## Prevalence and Detectability

Client code quality issues are **common but unevenly distributed**: pure managed apps (Kotlin/Java/Swift only) see mostly crash-and-DoS-grade issues, while any app that ships native code or wraps a C/C++ library inherits the full memory-safety risk surface.

Rather than cite specific percentages (which vary by report and year), the durable picture is:

- Memory-safety bugs are **concentrated in native code** and in the parsers/decoders that handle untrusted input—exactly the code that is hardest to review by eye.
- They are **detectable** with the right tooling: sanitizers (ASan/UBSan), fuzzing of native parsers, static analysis and linters in CI, and code review focused on input boundaries.
- Impact ranges from **reliable crashes/DoS** (the common case) up to **memory-corruption-driven code execution** (the severe case), gated by platform mitigations such as ASLR, PIE, stack canaries, and `_FORTIFY_SOURCE`.

> Note: OWASP describes M7 as an implementation-quality category—the risk is driven by how code is written rather than by architecture. Treat any single prevalence figure as illustrative; the durable takeaway is that native code and untrusted-input parsers are where the exploitable defects cluster.

## Common Misunderstandings

### Myth 1: "We use Kotlin/Swift, so we're memory-safe"

**Reality**: Managed languages are largely memory-safe *until you cross into native code*. Every JNI call, every bundled C/C++ library, and every use of unsafe pointer APIs re-introduces the classic bugs. The safety guarantee ends at the FFI boundary.

### Myth 2: "It's just a crash, not a security bug"

**Reality**: A reliably triggerable crash is at minimum a denial-of-service, and memory-corruption crashes are the first observable symptom of an exploitable bug. "Only a crash" often means "not yet weaponised."

### Myth 3: "The input comes from our own server, so it's trusted"

**Reality**: Server responses can be tampered with (compromised backend, MITM on weak transport, malicious proxy) and should be validated at the client boundary like any other untrusted input. The client must not trust a length or offset just because it "came from us."

### Myth 4: "Compiler warnings and lints are noise"

**Reality**: A large share of M7 defects are exactly what compilers, linters, and static analyzers flag—unchecked lengths, dangerous API calls, ignored return values. Turning warnings into build failures removes whole classes of bug for free.

### Myth 5: "Platform mitigations (ASLR/PIE) mean overflows don't matter"

**Reality**: Mitigations raise the cost of exploitation; they do not remove the bug. An overflow under ASLR is still a crash/DoS and is still a candidate for exploitation via an info leak. Fix the defect; don't rely on the mitigation alone.

### Myth 6: "Fuzzing is only for browser and OS vendors"

**Reality**: Any app that parses untrusted bytes in native code benefits from fuzzing its parser. It is the single most effective way to find the integer-overflow and bounds bugs that human review misses.

## How M7 Differs From Related Mobile Risks

| Aspect | M7 Client Code Quality | Insufficient Input/Output Validation | Insecure Data Storage |
|--------|------------------------|--------------------------------------|-----------------------|
| **Root cause** | How the client code is written (implementation defects) | Missing validation of specific fields | Where/how data is persisted |
| **Where it lives** | Native parsers, JNI/FFI, dangerous-API call sites | Input/output handling logic | Files, DBs, keychain/keystore |
| **Typical impact** | Crash/DoS up to memory-corruption code execution | Injection, logic bypass | Data theft at rest |
| **Typical fix** | Memory-safe APIs, bounds checks, hardening, fuzzing | Validate/encode per field | Encrypt, use platform key stores |

## Key Takeaways

1. **M7 is about how the client code is written**—implementation defects, not architecture or data placement.
2. **Native code is the epicentre**—C/C++ via JNI/NDK and bundled libraries carry the memory-safety risk that managed code avoids.
3. **Every input boundary is untrusted**—deep links, IPC, WebView, files, Bluetooth/NFC, and even server responses must be validated and bounds-checked at the client.
4. **Dangerous APIs have safe replacements**—prefer length-limited string APIs, safe containers, scoped JS bridges, and schema-based decoding.
5. **Crashes are the warning, not the whole problem**—reliable crashes are DoS today and possible code execution tomorrow.

## How to Identify if You're Vulnerable

- [ ] Does the app ship native C/C++ code (NDK, or bundled libraries), and are its parsers fuzzed?
- [ ] Are all lengths, sizes, offsets, and indices from untrusted input bounds-checked before use?
- [ ] Are dangerous C APIs (`strcpy`, `strcat`, `sprintf`, `gets`) banned in favour of length-limited equivalents?
- [ ] Is every allocation size checked for integer overflow before `malloc`?
- [ ] Is `addJavascriptInterface` only used with the `@JavascriptInterface` annotation, on a modern API, and never with untrusted content?
- [ ] Is deserialization of untrusted bytes restricted to an explicit schema / secure-coding class allow-list?
- [ ] Are deep links, Intents, Content Provider inputs, and custom URL schemes validated at entry?
- [ ] Are compiler hardening flags on (stack canaries, PIE, ASLR, `_FORTIFY_SOURCE`; ARC on iOS)?
- [ ] Do static analysis, linters, and sanitizers (ASan/UBSan) run in CI and fail the build on findings?
- [ ] Are errors handled explicitly (fail closed), and are secrets zeroed in memory after use?

If you answered "no" or "not sure" to several of these—especially any involving native code—you likely have exploitable client-code-quality defects today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers reach and trigger client-code defects
- **[Prevention](prevention.md)**: Write memory-safe, bounds-checked, hardened client code
- **[Examples](examples.md)**: Vulnerable vs. secure code in Kotlin/Java, Swift, and C/C++
- **[Mobile Top 10](/learn/mobile)**: Return to the full mobile security curriculum
- **[Practice](/practice)**: Apply these ideas in hands-on exercises
