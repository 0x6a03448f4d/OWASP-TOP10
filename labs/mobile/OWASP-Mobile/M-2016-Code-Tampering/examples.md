# M8:2016 Code Tampering - Code Examples

Each pair below shows a **vulnerable** pattern and the **secure** version. The recurring lesson: a client-side check is a *signal*, never a *verdict*—the authoritative decision belongs on the server. Examples span **Kotlin/Java (Android)** and **Swift (iOS)**, covering integrity checks, hooking/root detection, and the server-side validation pattern that actually holds.

Snippets are illustrative and trimmed for clarity (error handling, imports, and platform boilerplate omitted). Treat the *secure* column as the shape of a correct design, not a drop-in library.

## 1. The Entitlement Decision (Kotlin, Android)

### Vulnerable

```
// Premium is decided ON THE DEVICE. A one-line smali patch or Frida hook
// flips this to true; a memory editor flips the field. Trivially bypassed.
class Features(private val prefs: SharedPreferences) {

    fun isPremium(): Boolean = prefs.getBoolean("premium", false)

    fun exportData() {
        if (isPremium()) {            // client trusts itself
            doExpensiveExport()       // attacker just makes isPremium() return true
        } else {
            showPaywall()
        }
    }
}
```

### Secure

```
// The client ASKS; the server DECIDES from its own records and a validated
// store receipt. Even a fully hooked client cannot grant itself the export.
class Features(private val api: Api) {

    suspend fun exportData() {
        // No client-supplied "isPremium" flag is sent or trusted.
        val result = api.requestExport()      // POST /export, auth via session token
        when (result.status) {
            200  -> saveExport(result.body)    // server already authorised + produced it
            403  -> showPaywall()              // server said: not entitled
            else -> showError()
        }
    }
}

// --- server side (pseudocode) ---
// POST /export
//   user = authenticate(session)                    // who is this, per OUR records
//   entitled = subscriptions.isActive(user.id)      // OUR database
//             && receipts.validateWithStore(user)   // Google Play server API
//   if (!entitled) return 403
//   return produceExport(user)                      // work happens server-side
```

## 2. Repackaging / Signature Verification (Kotlin, Android)

### Vulnerable

```
// No integrity check at all. A repackaged, re-signed build runs happily,
// with injected code (overlays, ad-fraud SDKs) alongside the real app.
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        startEverything()            // never asks "am I the genuine build?"
    }
}
```

### Secure

```
// Detect repackaging by pinning YOUR signing certificate. This is a useful
// SIGNAL (it catches static tampering) but can itself be hooked, so the
// result is REPORTED TO THE SERVER and paired with Play Integrity.
object Integrity {
    private const val EXPECTED_SHA256 = "A1B2C3...your-release-cert-digest..."

    fun signingCertMatches(ctx: Context): Boolean {
        val info = ctx.packageManager.getPackageInfo(
            ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signer = info.signingInfo.apkContentsSigners.first()
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(signer.toByteArray())
            .joinToString("") { "%02X".format(it) }
        return digest == EXPECTED_SHA256
    }
}

// On a sensitive action, send the signal; let the SERVER weigh it.
val signals = RiskSignals(certOk = Integrity.signingCertMatches(ctx))
api.reportRisk(signals)   // server may deny/limit if cert does not match

// Authoritative check: server verifies a Play Integrity token (below),
// which fails for any build not signed by the Play-distributed cert.
```

## 3. Root & Hook Detection as Telemetry (Java, Android)

### Vulnerable

```
// Hard LOCAL gate on a single, obviously named method. One Frida hook
// (RootUtil.isRooted -> false) disables it for the whole app.
public class Gate {
    public static void enforce(Activity a) {
        if (RootUtil.isRooted()) {          // single choke point
            a.finish();                     // silent local block = teaches the bypass
        }
    }
}
```

### Secure

```
// Collect MULTIPLE signals (root, Frida/Xposed, debugger, emulator), some in
// native code, and REPORT them. The server decides how to respond. No single
// local branch is the whole defense.
public final class RiskProbe {

    public static RiskSignals collect(Context ctx) {
        return new RiskSignals(
            RootDetector.check(),                 // su/Magisk artefacts, mounts
            HookDetector.frida() || HookDetector.xposed(),  // maps/, ports, libs
            android.os.Debug.isDebuggerConnected(),
            EmulatorDetector.check(),
            Integrity.signingCertMatches(ctx)
        );
    }
}

// Usage: attach signals to sensitive requests; never rely on a local kill.
RiskSignals s = RiskProbe.collect(ctx);
api.performSensitiveAction(request, s);   // server scores & may step-up/deny

/* server: score(s) HIGH (rooted + hooked + cert mismatch) ->
   require re-auth, soft-limit, shadow, or refuse. Log for abuse analytics. */
```

## 4. Client Attestation Verified Server-Side (Kotlin, Android)

### Vulnerable

```
// Anti-tamper "verdict" computed and TRUSTED in the app. The verdict itself
// is just another value an attacker hooks to "GENUINE".
val verdict = LocalIntegrity.selfCheck()     // returns "GENUINE" / "TAMPERED"
if (verdict == "GENUINE") unlockSensitiveFlows()   // hook -> always GENUINE
```

### Secure

```
// Play Integrity: the app only FETCHES a token; the SERVER decodes and trusts it.
suspend fun sensitiveFlow() {
    val nonce = api.getServerNonce()          // server-generated, single-use
    val token = integrityManager.requestIntegrityToken(
        IntegrityTokenRequest.builder().setNonce(nonce).build()
    ).await().token()

    // Send the OPAQUE token up; the app makes NO trust decision itself.
    val ok = api.verifyIntegrity(token)       // server -> Google -> decoded verdict
    if (ok) proceed() else blockOrStepUp()
}

// --- server side ---
// decoded = playIntegrity.decode(token)
// require decoded.appRecognitionVerdict == PLAY_RECOGNIZED   // not repackaged
//      && decoded.deviceRecognitionVerdict meets policy
//      && decoded.nonce == expectedNonce                    // anti-replay
// Only then does the server authorise the sensitive flow.
```

## 5. Jailbreak & Debugger Detection (Swift, iOS)

### Vulnerable

```
// Single boolean gate, trusted locally. A Substrate/Frida hook on
// isJailbroken() returns false and the check evaporates.
func launch() {
    if JailbreakCheck.isJailbroken() {
        exit(0)                     // brittle local kill; easily hooked away
    }
    startApp()
}
```

### Secure

```
// Multiple weak signals combined, reported to the server as risk inputs.
// The app does not stake access on any one of them.
struct RiskSignals: Codable {
    let jailbroken: Bool
    let debugger: Bool
    let suspiciousDylibs: Bool
}

enum RiskProbe {
    static func collect() -> RiskSignals {
        RiskSignals(
            jailbroken: fileExists("/Applications/Cydia.app")
                     || canWrite("/private/jailbreak_test")
                     || canOpen("cydia://"),
            debugger: isDebuggerAttached(),        // sysctl KERN_PROC + P_TRACED
            suspiciousDylibs: loadedImagesContain(["frida", "substrate", "cynject"])
        )
    }

    // Detect a debugger via sysctl (harder to hook than a naive flag)
    static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        sysctl(&mib, 4, &info, &size, nil, 0)
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
}

// Attach to sensitive calls; the server decides the response.
api.performSensitiveAction(request, RiskProbe.collect())
```

## 6. App Attest for Per-Request Trust (Swift, iOS)

### Vulnerable

```
// "Premium" cached locally and trusted forever. A memory edit or a patched
// UserDefaults value unlocks everything; the server is never consulted.
if UserDefaults.standard.bool(forKey: "isPremium") {
    unlockPremium()                 // client is judge, jury, and executioner
}
```

### Secure

```
// App Attest: a hardware-backed key Apple attests; the SERVER verifies it and
// then trusts per-request assertions signed by that key. Client asserts nothing.
import DeviceCheck

func callPremiumEndpoint() async throws {
    let service = DCAppAttestService.shared
    guard service.isSupported else { return fallbackToServerAuthOnly() }

    let nonce = try await api.serverNonce()                 // anti-replay challenge
    let assertionData = try await service.generateAssertion(
        keyId, clientDataHash: sha256(requestBody + nonce)) // signs THIS request

    // Server verifies the assertion against the attested public key + nonce,
    // then derives entitlement from ITS OWN records. No client "isPremium".
    let result = try await api.premiumAction(body: requestBody,
                                             assertion: assertionData)
    apply(result)   // 200 = server authorised; 403 = server denied
}
```

## 7. Secret Handling (Kotlin, Android)

### Vulnerable

```
// Hardcoded key sitting in the binary. jadx/strings extracts it in seconds;
// a Frida hook on the cipher dumps it even if it were "hidden".
object Crypto {
    private const val API_KEY = "sk_live_9f2b...DO_NOT_DO_THIS..."
    fun sign(payload: String) = hmac(API_KEY, payload)
}
```

### Secure

```
// No long-lived secret on the device. The server holds the signing key and
// issues short-lived, scoped tokens; sensitive crypto happens server-side.
class ApiClient(private val tokenStore: SecureTokenStore) {

    // Token is short-lived, scoped, and refreshed from the server.
    suspend fun signedRequest(payload: String): Response {
        val token = tokenStore.currentAccessToken()   // expiring, revocable
        return http.post("/action") {
            header("Authorization", "Bearer $token")
            body(payload)                              // server signs/enforces
        }
    }
}
// If a per-device key is unavoidable, generate it in the Android Keystore
// (StrongBox where available) so it cannot be EXPORTED — while remembering a
// runtime hook can still observe plaintext IN USE, so keep the real secret
// server-side and attest the client.
```

## What Changed, and Why

| Concern | Vulnerable | Secure |
| --- | --- | --- |
| Entitlement | Decided on-device (`isPremium`) | Server derives it from its records + validated receipt |
| Repackaging | No integrity check | Signing-cert pin as a signal + server-verified Play Integrity |
| Root/hook detection | Single local gate, silently kills app | Many signals reported to server; server decides response |
| Attestation | Verdict trusted in-app | Opaque token verified server-side with a nonce |
| Secrets | Hardcoded / long-lived on device | Server-held; short-lived scoped tokens to the client |

**The through-line:** every "secure" example moves the authoritative decision off the device. Client-side integrity, detection, and attestation are valuable defense-in-depth—they raise cost and generate telemetry—but the control that a determined, rooted-device attacker cannot bypass is the one your server enforces.

## Next Steps

- **Prevention**: The full layered defense strategy and its limits
- **Attack Vectors**: How these protections are attacked in practice
- **Overview**: Why the client is untrusted by definition
- **Mobile Security Track**: Continue the OWASP Mobile Top 10 lessons
- **Practice**: Apply these concepts in hands-on challenges
