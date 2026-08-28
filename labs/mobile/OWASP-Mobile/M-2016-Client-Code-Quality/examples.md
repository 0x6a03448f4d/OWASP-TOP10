# M7:2016 Client Code Quality - Code Examples

Each pair below shows a **vulnerable** implementation and the **secure** version in the same language. The examples focus on the defects that dominate real mobile client findings: native memory-safety bugs (C/C++ via the NDK), unsafe input handling, dangerous-API misuse, unsafe deserialization, and crash-prone error handling. Memory-safety pairs are shown in C/C++ because that is where those bugs are reachable.

## 1. Native Buffer Copy (C, Android NDK / iOS C interop)

### Vulnerable

```
#include <string.h>

// Reached via JNI from a deep-link parameter or IPC extra
void handle_token(const char *token) {
    char buf[64];
    strcpy(buf, token);          // no bounds check: >63 bytes -> stack overflow
    verify_token(buf);
}
```

### Secure

```
#include <string.h>

int handle_token(const char *token, size_t token_len) {
    char buf[64];
    if (token_len >= sizeof(buf)) return -1;   // reject oversized input
    memcpy(buf, token, token_len);             // bounded copy
    buf[token_len] = '\0';
    return verify_token(buf);
}
// Prefer strlcpy/snprintf when a NUL-terminated source is guaranteed:
//   if (strlcpy(buf, token, sizeof(buf)) >= sizeof(buf)) return -1; // truncated
```

## 2. Integer Overflow Feeding an Allocation (C++)

### Vulnerable

```
#include <cstdint>
#include <cstdlib>

Item *read_items(const uint8_t *in) {
    uint32_t n = read_u32(in);               // attacker-controlled count
    Item *items = (Item *)malloc(n * sizeof(Item));  // n * 24 can wrap
    for (uint32_t i = 0; i < n; i++)
        items[i] = parse_item(in);           // heap overflow after wrap
    return items;
}
```

### Secure

```
#include <vector>
#include <cstdint>

std::vector<Item> read_items(const uint8_t *in, size_t in_len) {
    uint32_t n = read_u32(in);
    if (n > MAX_ITEMS) throw std::runtime_error("too many items"); // cap first
    std::vector<Item> items;
    items.reserve(n);                        // container manages size safely
    for (uint32_t i = 0; i < n; i++)
        items.push_back(parse_item(in, in_len)); // parser is bounds-aware
    return items;
}
// If you must use malloc, check the product: if (n > SIZE_MAX/sizeof(Item)) fail;
// or use calloc(n, sizeof(Item)), which checks internally.
```

## 3. Use-After-Free on an Error Path (C)

### Vulnerable

```
Session *s = alloc_session(input);
if (!validate(input)) {
    free(s);                     // freed here...
}
process(s);                      // ...but still used -> use-after-free
```

### Secure

```
Session *s = alloc_session(input);
if (!s) return -1;
if (!validate(input)) {
    free(s);
    s = NULL;                    // avoid a dangling pointer
    return -1;                   // and stop: do not fall through to use it
}
process(s);
free(s);
s = NULL;
```

## 4. Format-String Bug in a Native Log Path (C)

### Vulnerable

```
void log_event(const char *name) {          // name from a server response / IPC
    char line[128];
    snprintf(line, sizeof(line), name);     // name IS the format string
    write_log(line);                        // "%x %n" in name reads/writes memory
}
```

### Secure

```
void log_event(const char *name) {
    char line[128];
    snprintf(line, sizeof(line), "%s", name); // literal format; name is data
    write_log(line);
}
// Build with -Wformat -Wformat-security -Werror to catch this at compile time.
```

## 5. Deep-Link / Input Handling (Kotlin, Android)

### Vulnerable

```
// Trusts the incoming URI: wrong type crashes, hostile url is opened as-is
fun onDeepLink(uri: Uri) {
    val id = uri.getQueryParameter("id")!!.toInt()   // null/!Int -> crash
    val url = uri.getQueryParameter("url")!!          // null -> crash
    webView.loadUrl(url)                              // open-redirect / attacker page
    loadItem(id)
}
```

### Secure

```
fun onDeepLink(uri: Uri) {
    val id = uri.getQueryParameter("id")?.toIntOrNull()
    if (id == null || id !in 0..MAX_ID) { finish(); return }   // type + range

    val url = uri.getQueryParameter("url")
    if (url == null || !isAllowedHost(url)) { finish(); return } // host allow-list

    loadItem(id)
    webView.loadUrl(url)
}

private fun isAllowedHost(raw: String): Boolean {
    val host = runCatching { Uri.parse(raw).host }.getOrNull() ?: return false
    return host == "app.example.com"                 // exact match, not endsWith
}
```

## 6. Unsafe Deserialization (Java, Android)

### Vulnerable

```
// Decodes an arbitrary object graph from an Intent another app can send
Object data = getIntent().getSerializableExtra("data");  // arbitrary classes
Profile p = (Profile) data;                              // type confusion / gadgets
render(p);
```

### Secure

```
// Use an explicit schema (e.g. JSON with strict typing) and validate every field
String json = getIntent().getStringExtra("data");
if (json == null || json.length() > MAX_JSON) { finish(); return; }

Profile p;
try {
    p = strictGson.fromJson(json, Profile.class);        // fixed target type
} catch (JsonSyntaxException e) {
    finish(); return;                                    // reject malformed input
}
if (!p.isValid()) { finish(); return; }                  // field-level validation
render(p);
```

## 7. Insecure Unarchiving (Swift, iOS)

### Vulnerable

```
// Legacy API instantiates arbitrary classes from untrusted bytes
let obj = NSKeyedUnarchiver.unarchiveObject(with: data)  // no class restriction
let model = obj as! MyModel                              // force-cast -> crash/abuse
render(model)
```

### Secure

```
// Require secure coding and pin the exact expected classes
func decodeModel(_ data: Data) -> MyModel? {
    guard let unarchiver = try? NSKeyedUnarchiver(forReadingFrom: data) else {
        return nil
    }
    unarchiver.requiresSecureCoding = true
    let model = unarchiver.decodeObject(
        of: [MyModel.self, NSString.self],
        forKey: NSKeyedArchiveRootObjectKey) as? MyModel
    unarchiver.finishDecoding()
    return model                                         // nil on mismatch, no crash
}
```

## 8. WebView JavaScript Bridge (Kotlin, Android)

### Vulnerable

```
// Broad bridge + untrusted content: attacker JS reaches app methods
webView.settings.javaScriptEnabled = true
webView.addJavascriptInterface(LegacyBridge(), "bridge")  // exposes public methods
webView.loadUrl(remoteUrlFromServer)                      // may be attacker-influenced

class LegacyBridge {
    fun readFile(path: String): String = File(path).readText()  // dangerous surface
}
```

### Secure

```
// Minimal annotated bridge, first-party HTTPS content only
class SafeBridge {
    @JavascriptInterface                       // required on API 17+; only this is exposed
    fun appVersion(): String = BuildConfig.VERSION_NAME
}

webView.settings.javaScriptEnabled = true      // only because this screen needs it
webView.addJavascriptInterface(SafeBridge(), "app")
webView.loadUrl("https://app.example.com/")    // trusted, HTTPS, no third-party content
// No file, exec, or reflection reachable through the bridge.
```

## 9. Force-Unwrap / Null Handling (Swift, iOS)

### Vulnerable

```
// Assumes shape of attacker-influenced JSON; any mismatch crashes the app
let id = json["id"] as! Int
let name = json["name"] as! String
show(id: id, name: name)
```

### Secure

```
guard
    let id = json["id"] as? Int, (0..<maxId).contains(id),
    let name = json["name"] as? String, name.count <= maxName
else {
    return          // safe default: reject malformed input, never crash
}
show(id: id, name: name)
```

## What Changed, and Why

| Defect | Vulnerable | Secure |
| --- | --- | --- |
| Native buffer copy | `strcpy` into a fixed buffer | Length check + `memcpy`/`strlcpy` |
| Allocation sizing | Unchecked `n * size` (wraps) | Cap + safe container / overflow-checked `calloc` |
| Object lifetime | Use after `free` | NULL after free, stop on the error path |
| Logging | Untrusted input as format string | Literal `"%s"` format + `-Wformat-security` |
| Deep-link input | Force-unwrap, host trusted | Type/range checks + host allow-list |
| Deserialization | Arbitrary classes decoded | Fixed schema / secure-coding allow-list |
| WebView bridge | Broad bridge + untrusted content | Annotated minimal bridge, first-party HTTPS |
| Error handling | Force-unwrap crashes | `guard`/null checks, fail closed |

## Next Steps

- **Prevention**: The full hardening strategy for client code
- **Attack Vectors**: How these defects are reached and triggered
- **Mobile Top 10**: Return to the full mobile security curriculum
- **Practice**: Apply these fixes in hands-on exercises
