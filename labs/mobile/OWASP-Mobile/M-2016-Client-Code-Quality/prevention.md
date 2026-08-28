# M7:2016 Client Code Quality - Prevention

## Prevention Strategy Overview

Preventing client-code-quality defects is about **making unsafe code hard to write and easy to catch**:

1. Treat every input boundary as untrusted and validate/bounds-check there.
2. Prefer memory-safe languages and APIs; contain the unavoidable native code.
3. Turn on compiler and platform hardening so bugs are harder to exploit.
4. Automate detection—static analysis, sanitizers, and fuzzing—in CI.
5. Handle errors deliberately so failures fail closed, not open or crashing.

### Core Principles

- **Validate at the boundary**: the first code that touches untrusted input checks length, type, range, and structure—before anything else uses it.
- **Memory-safe by default**: choose managed languages and safe APIs; every drop into C/C++ is a deliberate, reviewed exception.
- **Least dangerous API**: ban `strcpy`/`sprintf`/`gets`-class calls; use length-limited equivalents and safe containers.
- **Fail closed and quiet**: on malformed input, reject and return a safe default—never crash, never proceed in an undefined state.

## 1. Validate and Bounds-Check All Untrusted Input

Every deep link, IPC message, WebView call, file, radio frame, and server response is untrusted. Validate at the entry point.

```kotlin
// Kotlin: validate a deep link before use
fun handleDeepLink(uri: Uri) {
    val id = uri.getQueryParameter("id")?.toIntOrNull()   // type + null checked
    require(id != null && id in 0..MAX_ID) { "bad id" }     // range checked
    val target = uri.getQueryParameter("url")
    require(target != null && isAllowedHost(target)) { "bad url" } // allow-list
    open(id, target)
}
```

```c
// C: bounds-check a length from untrusted input BEFORE copying
int handle_token(const char *token, size_t token_len) {
    char buf[64];
    if (token_len >= sizeof(buf)) return -1;   // reject oversized input
    memcpy(buf, token, token_len);
    buf[token_len] = '\0';
    return verify(buf);
}
```

Rules of thumb: check **length**, **type**, **range/sign**, and **structure**; reject rather than truncate silently; and never trust a length, offset, or count just because it came from your own server.

## 2. Prevent Integer Overflow in Size Arithmetic

Check multiplications and additions used to size allocations, before allocating.

```c
// C: overflow-checked allocation
Item *alloc_items(uint32_t n) {
    if (n > SIZE_MAX / sizeof(Item)) return NULL;  // would overflow
    return malloc(n * sizeof(Item));
    // or use calloc(n, sizeof(Item)) which checks internally
}
```

Prefer `calloc` (which checks the product), compiler builtins (`__builtin_mul_overflow`), or C++ container APIs that manage size for you. Treat every size derived from input as potentially adversarial.

## 3. Ban Dangerous APIs; Use Safe Equivalents

| Never use | Use instead |
|-----------|-------------|
| `strcpy`, `strcat` | `strlcpy`/`strlcat` (or bounded `snprintf`), or `std::string` |
| `sprintf` | `snprintf` with an explicit size |
| `gets` | `fgets` with a size, or a length-prefixed read |
| Raw `char[]` parsing | `std::string`, `std::vector<uint8_t>`, `std::span` (bounds-aware) |
| Untrusted format strings | Always a literal format: `printf("%s", input)` |

```bash
# Enforce the ban in CI (example grep gate; a linter/clang-tidy is better)
if grep -RnE '\b(strcpy|strcat|sprintf|gets)\s*\(' src/ ; then
    echo "Banned unsafe API found"; exit 1
fi
```

## 4. Contain and Harden Native Code

If you must ship C/C++, compile it with every available mitigation and keep the unsafe surface small.

```makefile
# Android NDK / clang hardening flags
CFLAGS += -fstack-protector-strong        # stack canaries
CFLAGS += -D_FORTIFY_SOURCE=2 -O2          # fortified libc calls
CFLAGS += -fPIE -fPIC                      # position-independent -> ASLR
LDFLAGS += -pie
LDFLAGS += -Wl,-z,relro,-z,now             # RELRO + immediate binding
CFLAGS += -Wall -Wextra -Werror            # warnings are build failures
CFLAGS += -Wformat -Wformat-security       # catch format-string misuse
```

On iOS, keep **ARC** enabled (automatic reference counting removes most manual use-after-free/double-free), avoid `Unsafe*Pointer` APIs unless necessary, and let the toolchain apply stack protection, PIE, and ASLR by default. Prefer writing new parsing logic in Swift (or another memory-safe language) rather than C.

## 5. Static Analysis, Linters, and Sanitizers in CI

Automated tools catch the majority of M7 defects before they ship.

```bash
# Static analysis / linters
clang-tidy   --checks='clang-analyzer-*,bugprone-*,cert-*' src/*.c
cppcheck     --enable=all --inconclusive src/
# Android: Android Lint + detekt (Kotlin); iOS: SwiftLint + the Xcode analyzer

# Sanitizers in test/debug builds (never rely on them in prod alone)
clang -fsanitize=address,undefined -g -O1 parser.c -o parser_test
./parser_test corpus/*        # ASan catches overflows/UAF; UBSan catches int overflow
```

Run these on every pull request and fail the build on new findings. Sanitizer-instrumented test builds turn latent memory bugs into loud, early failures.

## 6. Fuzz Native Parsers

Any code that turns untrusted bytes into structure should be fuzzed—this is the most effective way to find the overflow and integer bugs human review misses.

```cpp
// libFuzzer entry point for a native parser
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_message(data, size);   // must never overflow, UAF, or over-read
    return 0;
}
// Build with sanitizers + coverage, then run against a seed corpus:
//   clang++ -fsanitize=address,fuzzer parser.cc -o fuzz && ./fuzz corpus/
```

Integrate fuzzing into CI (even short runs per PR, longer runs nightly) and keep the crash corpus as regression tests.

## 7. Safe Deserialization on the Device

Never decode arbitrary object graphs from untrusted bytes. Use an explicit schema or a secure-coding allow-list.

```swift
// Android: prefer a schema (protobuf / JSON with strict types) over Java serialization.
// If you must use Parcelable/Serializable, validate every field after reading.

// iOS: require secure coding and specify the exact expected classes
let unarchiver = try NSKeyedUnarchiver(forReadingFrom: data)
unarchiver.requiresSecureCoding = true
let obj = unarchiver.decodeObject(of: [MyModel.self, NSString.self],
                                  forKey: NSKeyedArchiveRootObjectKey)
```

## 8. Lock Down the WebView JavaScript Bridge

```kotlin
// Android: modern, minimal, annotated bridge — and no untrusted content
class SafeBridge {
    @JavascriptInterface                     // required on API 17+ ; nothing else is exposed
    fun getVersion(): String = BuildConfig.VERSION_NAME
}
webView.settings.javaScriptEnabled = true    // only if truly needed
webView.addJavascriptInterface(SafeBridge(), "app")
webView.loadUrl("https://trusted.example.com/")   // first-party, HTTPS only
```

Rules: annotate every exposed method with `@JavascriptInterface`; expose the smallest possible surface (no file/exec/reflection reachable); load only first-party HTTPS content; disable JavaScript when not required; and never bridge a WebView that renders third-party or ad content.

## 9. Deliberate Error Handling

Handle failures explicitly and fail closed. A malformed input should produce a rejection, not a crash or an undefined state.

```swift
// Swift: no force-unwrap on untrusted data
guard let id = json["id"] as? Int, (0..<maxId).contains(id) else {
    return .rejected            // safe default, no crash
}
```

```kotlin
// Kotlin: handle the nullable/typed case instead of !!
val url = intent.getStringExtra("url")
if (url == null || !isAllowedHost(url)) { finish(); return }
```

Check return codes in C, catch and handle exceptions at boundaries, and make sure a failed security check leaves the app in a denied state—never a partially-initialised one.

## 10. Protect Sensitive Data in Memory

- Zero out buffers holding keys, tokens, or decrypted PII as soon as they are no longer needed (e.g., `memset_s` / explicit wipes; do not rely on plain `memset`, which the compiler may optimise away).
- Minimise how long secrets live in memory and avoid copying them into logs, crash reports, or long-lived caches.
- Prefer platform key stores (Android Keystore, iOS Keychain / Secure Enclave) so raw key material never sits in app memory longer than necessary.

## Language-Specific Hardening

### Android (Kotlin/Java + NDK)

- Keep security-sensitive parsing in Kotlin/Java where bounds are checked; drop into the NDK only when necessary, and fuzz that code.
- Enable Android Lint and detekt in CI; treat memory/format warnings as errors in native builds.
- Use the `@JavascriptInterface` annotation and target a modern `minSdk` so the legacy reflection bridge behaviour is gone.

### iOS (Swift + C interop)

- Keep ARC on; avoid manual memory management and `Unsafe*Pointer` unless there is no alternative.
- Prefer Swift value types and bounds-checked collections; avoid force-unwraps and `as!` on untrusted data.
- Use secure coding for any unarchiving and validate deep-link/URL-scheme inputs at the entry point.

## Key Takeaways

1. **Validate at every boundary** — length, type, range, and structure, before any other code uses the input.
2. **Prefer memory-safe code** — contain native C/C++, and replace dangerous APIs with length-limited, bounds-aware equivalents.
3. **Turn on the mitigations** — stack canaries, PIE/ASLR, RELRO, `_FORTIFY_SOURCE`, and ARC make bugs harder to exploit.
4. **Automate detection** — static analysis, sanitizers, and fuzzing in CI catch what review misses.
5. **Fail closed** — deliberate error handling turns malformed input into a clean rejection, not a crash or a bypass.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure code in Kotlin/Java, Swift, and C/C++
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Mobile Top 10](/learn/mobile)**: Return to the full mobile security curriculum
- **[Practice](/practice)**: Apply this hardening in hands-on exercises
