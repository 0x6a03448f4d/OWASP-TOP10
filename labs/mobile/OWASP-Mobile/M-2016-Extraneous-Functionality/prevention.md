# M10:2016 Extraneous Functionality - Prevention

## Prevention Strategy Overview

Every fix for extraneous functionality reduces to one principle: **development-only code must not exist in the production build**. Not hidden, not flag-gated, not obfuscated—*absent*. Because the attacker owns the binary, the only reliable control is to make sure the sensitive code was never compiled into the shipped artifact in the first place.

1. Separate debug and release builds so development code is compiled out, not just switched off.
2. Strip logging, test endpoints, and test credentials from release.
3. Guarantee `debuggable=false` in every released variant.
4. Enforce it all with code review, a release checklist, and automated CI gates that fail the build.

### Core Principles

- **Remove, don't hide**: a hidden feature is still shipped. Compile it out or delete it.
- **Compile-time beats run-time**: `#if DEBUG` and build-flavor source sets remove code from the artifact; a runtime `if` does not.
- **Server-authoritative gating**: if a feature must be toggleable, the authoritative decision belongs on the server, not in a client boolean.
- **Fail the build, not the review**: humans miss leftovers; make automation the backstop that refuses to ship them.

## 1. Separate Debug and Release Builds

The single most effective control is a build system that physically excludes development code from release. On Android this is **build types and product flavors with source sets**; on iOS it is **`#if DEBUG`** compilation conditions.

#### Android — build types and debug-only source sets

```groovy
// build.gradle (app)
android {
    buildTypes {
        debug {
            buildConfigField "String", "BASE_URL", "\"https://staging-api.example.com/\""
            // debuggable defaults to true for the debug type
        }
        release {
            buildConfigField "String", "BASE_URL", "\"https://api.example.com/\""
            debuggable false            // never debuggable in release
            minifyEnabled true          // R8/ProGuard shrink + obfuscate
            shrinkResources true
        }
    }
}
```

Place development-only classes (a diagnostics screen, mock interceptors, seed loaders) in the `src/debug/` source set. They are compiled into the debug APK and **do not exist** in the release APK—so there is nothing for a decompiler to find.

```
app/src/debug/java/com/example/app/DiagnosticsActivity.kt   // debug build ONLY
app/src/main/java/com/example/app/...                       // shared, production code
app/src/release/...                                         // release-only overrides
```

#### iOS — #if DEBUG compilation conditions

```swift
#if DEBUG
    // Compiled ONLY into Debug configuration; absent from Release binary
    let baseURL = URL(string: "https://staging-api.example.com/")!
    installDebugMenu()
#else
    let baseURL = URL(string: "https://api.example.com/")!
#endif
```

`DEBUG` is defined in *Active Compilation Conditions* (or `GCC_PREPROCESSOR_DEFINITIONS`) for the Debug configuration only. Code inside `#if DEBUG` is not present in the Release Mach-O at all.

## 2. Strip Runtime Guards Correctly (BuildConfig.DEBUG / #if DEBUG)

When you must keep a single source file but gate behaviour, use the flag the toolchain can prove is constant, so the optimizer removes the dead branch from release.

```kotlin
// Android: BuildConfig.DEBUG is false in release; R8 strips the guarded block
if (BuildConfig.DEBUG) {
    enableDebugOverlay()          // removed from the release build by the optimizer
}
```

> **Caution**: a guard only protects you if the flag is a compile-time constant *and* the optimizer runs. A boolean read from `SharedPreferences`, a remote config value, or a plain `var` is not stripped—the guarded code still ships and is reachable. Prefer `BuildConfig.DEBUG` / `#if DEBUG` over app-defined runtime flags.

## 3. Silence Production Logging

No release build should write tokens, request/response bodies, or PII to any log sink.

#### Android

```kotlin
// Route all logging through a wrapper that no-ops in release
object Timberish {
    fun d(tag: String, msg: String) {
        if (BuildConfig.DEBUG) Log.d(tag, msg)   // stripped from release
    }
}
```

```proguard
// Additionally strip Log.* calls at build time via ProGuard/R8:
// proguard-rules.pro
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
    public static int i(...);
}
```

#### iOS

```swift
func log(_ message: @autoclosure () -> String) {
    #if DEBUG
    print(message())          // no-op in Release; message() is never even built
    #endif
}
// Prefer os.Logger with appropriate privacy: sensitive values default to redaction.
```

Also confirm third-party analytics/crash SDKs are not configured to capture full network traffic or breadcrumbs containing secrets in release.

## 4. Remove Test / Staging Endpoints and Credentials

- Select the base URL from `BuildConfig`/`#if DEBUG`—release must have no code path that can reach staging.
- Never hardcode test accounts. If QA needs an account, provision it server-side and keep it out of the binary entirely.
- Do not ship an in-app "environment switcher" in release; put it behind a debug-only source set.
- Keep API keys out of source; where a client key is unavoidable, treat it as public and scope it minimally server-side.

```kotlin
// Do NOT do this — constants like these are trivially recovered from the binary
const val QA_USER = "qa_admin"
const val QA_PASS = "Test1234!"
// A test account belongs in the server's test environment, never in the app.
```

## 5. Guarantee debuggable=false and a Hardened Release Manifest

Do not set `android:debuggable` in the manifest at all—let the build type control it, and force it off for release.

```groovy
// build.gradle
release { debuggable false }
```

```xml
<!-- AndroidManifest.xml — do NOT hardcode android:debuggable="true" -->
<application
    android:allowBackup="false"
    ... >
```

Verify the final APK, not just the source:

```
$ aapt dump badging app-release.apk | grep -i debuggable   # expect NO output
$ aapt dump xmltree app-release.apk AndroidManifest.xml | grep -i debuggable
```

## 6. Code Review and a Release Checklist

Make "is there anything here that shouldn't ship?" an explicit review gate, not an afterthought.

```
Release checklist (extraneous functionality)
[ ] No debug/test activities, view controllers, or menus in the release variant
[ ] No hidden gestures / magic values that unlock features
[ ] No client-only feature flag hiding a fully compiled feature
[ ] No test/staging URLs or credentials in the binary (verified by grep of the artifact)
[ ] Logging is stripped/no-op in release (verified on-device with logcat)
[ ] android:debuggable is false in the built APK (verified with aapt)
[ ] No secrets or internal notes left in comments/constants
[ ] Third-party SDKs not capturing sensitive data in release
```

## 7. Automated CI Gates That Fail the Build

Humans miss leftovers; make CI refuse to publish them. Scan the **built artifact**, because that is what the attacker gets.

```bash
# ci: fail the pipeline on debug artifacts and leaked config
set -euo pipefail
APK=app/build/outputs/apk/release/app-release.apk

# 1) Refuse a debuggable release
if aapt dump badging "$APK" | grep -qi "application-debuggable"; then
  echo "FAIL: release APK is debuggable"; exit 1
fi

# 2) Refuse staging/test endpoints and obvious test creds in the binary
if unzip -p "$APK" classes.dex | strings | grep -Eiq 'staging-api|qa_admin|Test1234|debug\.internal'; then
  echo "FAIL: staging endpoint or test credential found in release artifact"; exit 1
fi

# 3) Static analysis for leftover debug code / secrets
# (e.g. MobSF automated scan, semgrep rules, gitleaks on the source)
gitleaks detect --source . --redact
semgrep --config ./ci/no-debug-code.yml --error
```

```bash
# iOS equivalent: verify DEBUG symbols are absent from the Release binary
strings "$APP/MyApp" | grep -Eiq 'staging-api|qa_admin|InternalDebugMenu' \
  && { echo "FAIL: debug artifact in Release binary"; exit 1; } || true
```

Run these gates on every release build so a leftover backdoor or staging URL blocks the release rather than reaching the store.

## 8. Distinguish From Security Misconfiguration When Remediating

The remediation verb tells you which category you are in—and getting it right avoids a false sense of safety.

| Finding | Category | Correct fix |
|---------|----------|-------------|
| Hidden debug menu in release | Extraneous Functionality | *Remove* it (debug source set) |
| Test credentials in a constant | Extraneous Functionality | *Remove* them from the binary |
| Backup allowed for sensitive data | Misconfiguration | *Reconfigure* (`allowBackup=false`) |
| Weak TLS / no pinning | Misconfiguration | *Reconfigure* the network security policy |

If the fix is "set this option to a safer value," it is misconfiguration. If the fix is "this shouldn't be in the app—take it out," it is extraneous functionality.

## Key Takeaways

1. **Compile it out** — debug/product flavors and `#if DEBUG` remove development code from the release artifact entirely.
2. **Guards must be provably constant** — `BuildConfig.DEBUG`/`#if DEBUG` get stripped; runtime flags do not.
3. **No secrets, endpoints, or logs in release** — test creds and staging URLs belong in test environments, never in the binary.
4. **Lock the manifest** — `debuggable=false`, verified on the built APK, not just the source.
5. **Automate the backstop** — CI scans the artifact and fails the build on any debug leftover.

## Next Steps

- **[Examples](examples.md)**: Vulnerable vs. secure code in Kotlin/Java, Swift, and build config
- **[Attack Vectors](attack-vectors.md)**: Understand exactly what you're defending against
- **[Overview](overview.md)**: Revisit the categories of extraneous functionality
- **[Mobile Top 10](/learn/mobile)**: Return to the full mobile learning path
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
