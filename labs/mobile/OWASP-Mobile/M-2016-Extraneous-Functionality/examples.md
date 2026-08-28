# M10:2016 Extraneous Functionality - Code Examples

Each pair below shows **vulnerable** code that ships development-only functionality, and the **secure** version that keeps it out of the release build. The examples span Android (Kotlin and Java), iOS (Swift), and the build configuration that actually enforces the separation.

## Android — Kotlin

### 1. Hidden Debug Menu / God-Mode

#### Vulnerable

```
class SettingsActivity : AppCompatActivity() {
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        // Secret trigger recovered by anyone who decompiles the app
        versionLabel.setOnLongClickListener {
            startActivity(Intent(this, InternalDebugMenu::class.java)) // toggles, raw API console
            true
        }
    }
}
// InternalDebugMenu is in src/main — it ships in the release APK
```

#### Secure

```
// Debug-only screen lives in src/debug/ and is NOT compiled into release.
// A no-op stub in src/release/ (or absence of the call) means there is nothing to find.

// src/debug/java/.../DebugHooks.kt
object DebugHooks {
    fun attach(activity: SettingsActivity) {
        activity.versionLabel.setOnLongClickListener {
            activity.startActivity(Intent(activity, InternalDebugMenu::class.java)); true
        }
    }
}

// src/release/java/.../DebugHooks.kt
object DebugHooks { fun attach(activity: SettingsActivity) { /* no-op in release */ } }

// src/main — calls the flavor-specific implementation
override fun onCreate(b: Bundle?) { super.onCreate(b); DebugHooks.attach(this) }
```

### 2. Test / Staging Endpoint and Credentials

#### Vulnerable

```
object Api {
    const val BASE_URL = "https://staging-api.internal.example.com/" // internal host leaked
    const val QA_USER  = "qa_admin"
    const val QA_PASS  = "Test1234!"                                  // usable creds in the binary
}
```

#### Secure

```
object Api {
    // Selected per build type; release cannot reach staging, and no creds are compiled in.
    val BASE_URL = BuildConfig.BASE_URL   // set via buildConfigField in build.gradle
}
// Test accounts are provisioned in the server's test environment only — never in the app.
```

### 3. Client-Side Feature Flag Hiding Shipped Code

#### Vulnerable

```
// Full feature compiled in; hidden only by a local boolean an attacker can flip
if (prefs.getBoolean("ff_new_payments", false)) {
    showUnreleasedPaymentsFlow()
}
```

#### Secure

```
// Authoritative decision comes from the server, tied to the authenticated user/entitlement.
// The client trusts a signed/server-checked response, not a local toggle.
if (entitlements.isEnabled(Feature.NEW_PAYMENTS)) {   // server-verified per request
    showNewPaymentsFlow()
}
// Truly unreleased code that must not leak stays behind a src/debug source set until launch.
```

## Android — Java

### Developer Backdoor and Verbose Logging

#### Vulnerable

```
public boolean isAuthorized(User u) {
    if (u.getId() == 0xDEADBEEFL) return true;              // backdoor: magic id skips checks
    Log.d("Auth", "check user=" + u.getEmail()
                  + " token=" + session.getJwt());          // leaks PII + token in release
    return acl.check(u);
}
```

#### Secure

```
public boolean isAuthorized(User u) {
    // No magic identifiers. Every user goes through the same access-control path.
    if (BuildConfig.DEBUG) {                                 // stripped from release by R8
        SafeLog.d("Auth", "checking user id=" + u.getId());  // no token, no PII, debug only
    }
    return acl.check(u);
}
// SafeLog.d no-ops when !BuildConfig.DEBUG; Log.* calls also removed via
// -assumenosideeffects in proguard-rules.pro.
```

## iOS — Swift

### 1. Debug Menu and Environment Switcher

#### Vulnerable

```
final class RootViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        // Magic value opens an internal console on any stock device
        searchField.addTarget(self, action: #selector(check), for: .editingChanged)
    }
    @objc func check() {
        if searchField.text == "!!debug!!" {
            present(InternalDebugMenu(), animated: true) // ships in the Release binary
        }
    }
}
```

#### Secure

```
final class RootViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        #if DEBUG
        installDebugConsole()   // compiled ONLY into the Debug configuration
        #endif
    }

    #if DEBUG
    private func installDebugConsole() {
        searchField.addTarget(self, action: #selector(openDebug), for: .editingChanged)
    }
    @objc private func openDebug() {
        if searchField.text == "!!debug!!" { present(InternalDebugMenu(), animated: true) }
    }
    #endif
}
// InternalDebugMenu and its trigger are absent from the Release Mach-O entirely.
```

### 2. Base URL and Test Credentials

#### Vulnerable

```
enum API {
    static let baseURL = URL(string: "https://staging-api.internal.example.com/")!
    static let qaUser  = "qa_admin"
    static let qaPass  = "Test1234!"          // recovered with `strings` on the binary
}
```

#### Secure

```
enum API {
    static let baseURL: URL = {
        #if DEBUG
        return URL(string: "https://staging-api.example.com/")!  // Debug builds only
        #else
        return URL(string: "https://api.example.com/")!          // Release: production only
        #endif
    }()
    // No credentials in code. QA accounts exist only in the test back-end.
}
```

### 3. Logging

#### Vulnerable

```
print("login ok: \(user.email) token=\(session.jwt)")   // written in Release too
```

#### Secure

```
func debugLog(_ message: @autoclosure () -> String) {
    #if DEBUG
    print(message())        // argument is not even evaluated in Release
    #endif
}
debugLog("login ok id=\(user.id)")   // no token, no email; and gone from Release

// For production diagnostics use os.Logger with privacy redaction:
import os
let logger = Logger(subsystem: "com.example.app", category: "auth")
logger.info("login ok id=\(user.id, privacy: .public) token=\(session.jwt, privacy: .private)")
```

## Build Configuration — Enforcing the Separation

### 1. Android: Build Types, Flavors, and debuggable

```
// build.gradle (app)
android {
    buildTypes {
        debug {
            buildConfigField "String", "BASE_URL", "\"https://staging-api.example.com/\""
            // debuggable is true for debug by default — fine, it never ships
        }
        release {
            buildConfigField "String", "BASE_URL", "\"https://api.example.com/\""
            debuggable false          // MUST be false; never set android:debuggable in the manifest
            minifyEnabled true        // R8 strips BuildConfig.DEBUG branches + Log.* no-ops
            shrinkResources true
        }
    }
}

// src layout — development-only code physically excluded from release
// app/src/debug/java/...   -> compiled into debug APK only
// app/src/release/java/... -> release stubs / overrides
// app/src/main/java/...    -> shared production code
```

### 2. iOS: Active Compilation Conditions

```
# Build Settings
# Debug   -> SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG
# Release -> SWIFT_ACTIVE_COMPILATION_CONDITIONS = (empty)
#
# Result: every `#if DEBUG ... #endif` block is absent from the Release binary.
# Use separate .xcconfig files / schemes so Release never inherits DEBUG.
```

### 3. CI Gate: Fail the Build on Debug Artifacts

```
#!/usr/bin/env bash
set -euo pipefail
APK=app/build/outputs/apk/release/app-release.apk

# Refuse a debuggable release build
aapt dump badging "$APK" | grep -qi "application-debuggable" \
  && { echo "FAIL: release APK is debuggable"; exit 1; }

# Refuse staging endpoints / test credentials that leaked into the artifact
unzip -p "$APK" classes.dex | strings \
  | grep -Eiq 'staging-api|qa_admin|Test1234|InternalDebugMenu|!!debug!!' \
  && { echo "FAIL: debug/staging artifact found in release"; exit 1; }

# Secret + debug-code static analysis on the source
gitleaks detect --source . --redact
echo "OK: no extraneous functionality detected in release artifact"
```

## What Changed, and Why

| Leftover | Vulnerable | Secure |
| --- | --- | --- |
| Debug menu / god-mode | In `src/main`, ships in release | In `src/debug` / `#if DEBUG`, compiled out |
| Staging endpoint | Hardcoded constant in binary | Selected by `BuildConfig`/`#if DEBUG` |
| Test credentials | Constants in the app | Only in the server's test environment |
| Feature flag | Client boolean hides shipped code | Server-authoritative entitlement |
| Verbose logs | `Log`/`print` in release | No-op / stripped, privacy-redacted `os.Logger` |
| Backdoor | Magic id skips access control | Removed; single access-control path |
| debuggable | `true` in shipped manifest | `false`, verified in CI on the APK |

## Next Steps

- **Prevention**: The full strategy for keeping development code out of release
- **Attack Vectors**: How these leftovers are discovered and exploited
- **Overview**: Revisit the categories of extraneous functionality
- **Mobile Top 10**: Return to the full mobile learning path
- **Practice**: Apply what you've learned in hands-on challenges
