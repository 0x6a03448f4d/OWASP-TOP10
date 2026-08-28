# M8:2016 Code Tampering - Prevention

## Prevention Strategy Overview

**The one rule that outranks all others:** never trust the client for a security decision. Everything on this page except server-side enforcement is *defense-in-depth*—it raises the attacker's cost but does not, and cannot, stop a determined attacker on a device they control.

Effective defense is layered, and the layers are not equal:

1. **Move the decision to the server** (the only authoritative control).
2. **Attest the client** so the server can weigh how much to trust it.
3. **Verify app integrity and signing** to detect repackaging.
4. **Detect tampering, hooking, and rooted environments** as signals, not gates.
5. **Obfuscate** to raise the cost of understanding and patching.
6. **Monitor and respond** using telemetry instead of silent local blocks.

### Core Principles

- **Server is the source of truth**: entitlements, balances, and permissions are computed and enforced where the attacker has no privileges.
- **Client checks are signals, not verdicts**: report them to the server; let the server decide.
- **Assume every client protection will be bypassed**: design so that a bypassed client still cannot access what it should not.
- **Raise cost, buy time, gain visibility**: obfuscation, detection, and attestation are worthwhile precisely because they make attacks slower and noisier.

## 1. Server-Side Enforcement (The Real Control)

If a feature, a balance, or a permission matters, the server must own it. The client may *request*; only the server *decides*—and it re-checks on every sensitive action rather than trusting a flag the client sent once.

```
// WRONG: client asserts its own entitlement, server obeys
POST /api/export   { "userId": 42, "isPremium": true }   // attacker sets true

// RIGHT: server derives entitlement from its own records, ignores client claims
POST /api/export   { }                       // no trust in client-supplied flags
  -> server looks up user 42's subscription in ITS database
  -> server validates the store receipt with Apple/Google server-to-server
  -> server authorises (or 403s) based on WHAT IT KNOWS, not what the app said
```

Concretely:

- **Validate purchases server-side** using Google Play's / App Store's server APIs and store the entitlement in your own database. Never unlock features on a locally parsed receipt alone.
- **Keep authoritative state on the server**: game currency, scores, quotas, and limits that the client can only propose changes to.
- **Re-authorise every sensitive request** from the user's server-side identity, not from client-supplied roles or flags.

## 2. Client Attestation (Play Integrity / DeviceCheck / App Attest)

Platform attestation lets your *server* obtain a signed statement from the OS/vendor about the app and device—evidence that is far harder to forge than an in-app check, because the signing happens outside the app's reach.

```
Android  -> Play Integrity API
  App requests an integrity token; your SERVER sends it to Google to decode.
  Verdict covers: app recognised & unmodified (matches Play-signed cert),
  device integrity, and licensing. Attacker's re-signed build fails the check.

iOS      -> App Attest & DeviceCheck (DCAppAttestService)
  App generates a hardware-backed key; Apple attests it. Your SERVER verifies
  the attestation and then validates per-request assertions signed by that key.
```

**Rules for attestation to be worth anything:**

- The token/verdict must be **verified on your server**, never interpreted in the app (an in-app verdict is just another hookable branch).
- Include a **server-generated nonce** in each attestation to prevent replay.
- Treat the verdict as an **input to a risk decision**, not a hard local gate.

## 3. App Integrity and Signature Verification

Detect repackaging by checking, at runtime, that the app is signed by *your* certificate—and (more robustly) by having the server require an attestation that proves it. The in-app check below is a useful signal but can itself be hooked, so pair it with server-side attestation.

```
// Android (Kotlin): compare the running app's signing cert to a known pin
fun signingCertMatches(context: Context, expectedSha256: String): Boolean {
    val sig = context.packageManager
        .getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        .signingInfo.apkContentsSigners.first()
    val digest = MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
    return digest.toHex() == expectedSha256   // reject unknown (attacker) certs
}
```

Also verify the integrity of native libraries and critical assets (e.g. a checksum of a bundled config or pinned certificate) so resource swaps are noticed. Report failures to the server rather than only reacting locally.

## 4. Anti-Tampering and Anti-Hooking Detection (Defense-in-Depth)

**Honesty check:** root/jailbreak, Frida, Xposed, emulator, and debugger detection are all bypassable by the same instrumentation they try to detect. They are worthwhile because they filter casual attackers and generate telemetry—*not* because they stop a skilled one.

Useful signals to collect (and send to the server as risk inputs):

- **Rooted/jailbroken environment**: presence of su/Magisk artefacts, Cydia, unusual mounts and paths.
- **Instrumentation present**: Frida server/ports/threads, Xposed/LSPosed hooks, suspicious loaded libraries in `/proc/self/maps`.
- **Debugger attached**: `Debug.isDebuggerConnected()` on Android, `sysctl`/`ptrace` signals on iOS.
- **Emulator/simulator**: known build fingerprints, missing sensors, telltale hardware values.

```
// Send signals to the server; let the SERVER decide the response.
// Do NOT branch locally on the result as your only defense.
val signals = TamperSignals(
    rooted   = RootDetector.check(),
    hooked   = HookDetector.check(),      // Frida/Xposed indicators
    debugger = Debug.isDebuggerConnected(),
    emulator = EmulatorDetector.check(),
    certOk   = signingCertMatches(ctx, EXPECTED_SHA256)
)
api.reportRisk(signals)   // server may step-up auth, limit, or deny
```

Vary and duplicate checks, run some in native code, and avoid a single choke-point method an attacker can hook once to defeat everything.

## 5. Code Obfuscation (Raise the Cost)

Obfuscation does not prevent tampering—it makes locating and patching the right code slower and more error-prone. That delay has real value against automated and low-skill attackers.

- **Android**: enable R8/ProGuard to rename and shrink; move sensitive logic to native code; consider a commercial obfuscator for control-flow flattening and string encryption on high-value logic.
- **iOS**: strip symbols, avoid revealing method names, and obfuscate sensitive strings and constants.
- **Both**: never leave a security decision in a clearly named method (`isPremium`, `isRooted`) that an attacker can grep for in seconds.

```
# Android: enable shrinking/obfuscation (build.gradle)
buildTypes {
    release {
        minifyEnabled true
        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                      'proguard-rules.pro'
    }
}
```

## 6. Keep Secrets and Enforcement Off the Client

- **No hardcoded secrets**: API keys, signing keys, and encryption keys embedded in the binary or resources are extractable—assume they are already public.
- **Short-lived, scoped tokens**: issue narrowly scoped, expiring credentials from the server so a captured token is low-value.
- **Server-side crypto for anything sensitive**: if a key must never leak, use it on the server; the client sends data in, gets a result back.
- **Hardware-backed storage when a key must live on-device**: Android Keystore / iOS Secure Enclave prevent *extraction at rest*—but remember a hook can still observe the plaintext *in use*, so pair with attestation and server checks.

## 7. Monitoring, Telemetry, and Response

Prefer **detect-and-respond over silent-block**. A hard local block teaches the attacker exactly which check to bypass; server-side telemetry lets you observe, score, and react without tipping your hand.

```
# Server-side risk handling of client-reported signals
def handle_request(user, signals, action):
    risk = score(signals)             # rooted + hooked + cert mismatch -> high
    if risk == HIGH and action.is_sensitive:
        require_step_up_auth()        # or soft-limit / shadow / deny
    log_security_event(user, signals, risk)   # analytics + abuse detection
    # Never rely on the client to have blocked itself.
```

Watch for: spikes of cert-mismatch reports (a mod circulating), clusters of hooked/rooted clients hitting monetised endpoints, and impossible client-side state (values the server never issued).

## Layered Defense at a Glance

| Layer | What it does | Stops a determined attacker? |
| --- | --- | --- |
| Server-side enforcement | Owns entitlements, state, and authorisation | **Yes** — the authoritative control |
| Platform attestation | Server-verified proof of genuine app/device | Strongly raises the bar |
| Signature / integrity checks | Detect repackaging and resource swaps | Detects static tampering; hookable |
| Anti-hook / anti-root detection | Signals a compromised runtime | No — bypassable; use as telemetry |
| Obfuscation | Slows analysis and patching | No — raises cost only |
| Monitoring & response | Observe and react to abuse | Limits damage; does not prevent |

## The Honest Bottom Line

A determined attacker with a rooted or jailbroken device **can** defeat every purely client-side protection you ship. Obfuscation, detection, and integrity checks are still worth doing—they raise cost, deter the many casual attackers, and generate the telemetry you need. But the only control that actually holds is the one enforced on infrastructure the attacker does not control: **your server**. Design as if the client is already compromised, because for some fraction of your users it is.

## Key Takeaways

1. **Enforce on the server** — entitlements, balances, and authorisation must not be trusted to the client.
2. **Attest the client server-side** — Play Integrity, App Attest, and DeviceCheck verified by your backend, with a nonce.
3. **Verify signing and integrity** — catch repackaging by pinning your certificate and checksumming critical assets.
4. **Treat detection as telemetry** — root/hook/emulator checks inform a server-side risk decision; they are not gates.
5. **Obfuscate to buy time, not safety** — and never store secrets or final decisions on the device.

## Next Steps

- **Code Examples**: Vulnerable vs. secure integrity, detection, and server-validation code
- **Attack Vectors**: Understand exactly what you are defending against
- **Overview**: Why the client is untrusted by definition
- **Mobile Security Track**: Continue the OWASP Mobile Top 10 lessons
- **Practice**: Apply these concepts in hands-on challenges
