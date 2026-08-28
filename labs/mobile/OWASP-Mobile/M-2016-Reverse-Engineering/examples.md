# M9:2016 Reverse Engineering - Code Examples

Each pair below shows a **vulnerable** pattern that reverse engineering defeats, and the **secure** version that survives a fully-read client. The theme is constant: anything the binary contains is recoverable, so the fix is almost always to move the secret or the decision server-side and to add friction, honestly labelled as friction.

Keys, hosts, and tokens in these snippets are illustrative placeholders, not real credentials.

## 1. Hardcoded API Secret

### Android (Kotlin) — Vulnerable

```
object ApiClient {
    // Recovered in one `jadx` pass or a plain `strings | grep`.
    private const val API_SECRET = "sk_live_9f8a7b6c5d4e3f2a1b0c"

    fun signedRequest(body: String): Request {
        val sig = HmacUtil.hmacSha256(API_SECRET, body)   // signing key ships in the app
        return Request(body, sig)
    }
}
```

### Android (Kotlin) — Secure

```
object ApiClient {
    // No secret in the client. The app authenticates the USER; the SERVER
    // holds the signing key and performs any privileged/signed action.
    fun request(body: String, accessToken: String): Request {
        return Request(
            body = body,
            headers = mapOf("Authorization" to "Bearer $accessToken")
        )
    }
    // If a third-party API needs a secret key, the app calls YOUR backend,
    // and your backend calls the third party with the secret it never ships.
}
```

### iOS (Swift) — Vulnerable

```
enum ApiClient {
    // class-dump + strings recovers this immediately.
    static let apiSecret = "sk_live_9f8a7b6c5d4e3f2a1b0c"

    static func signedRequest(_ body: String) -> URLRequest {
        let sig = HmacUtil.hmacSHA256(key: apiSecret, message: body)
        return makeRequest(body: body, signature: sig)   // secret used on-device
    }
}
```

### iOS (Swift) — Secure

```
enum ApiClient {
    // Client carries a short-lived user token, never a shared secret.
    static func request(_ body: String, accessToken: String) -> URLRequest {
        var req = makeRequest(body: body)
        req.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return req
    }
    // Privileged signing / third-party secret usage happens server-side.
}
```

## 2. Client-Side License / Entitlement Check

### Android (Java) — Vulnerable

```
public class FeatureGate {
    // A single boolean an attacker can hook (Frida) or patch (smali).
    public boolean isPremium(User user) {
        return user.getTier().equals("PREMIUM");   // decided on-device
    }

    public void openPremiumScreen(User user) {
        if (isPremium(user)) {
            renderPremiumContent();   // the premium bytes are already on the device
        }
    }
}
```

### Android (Java) — Secure

```
public class FeatureGate {
    // The server is the authority. The client never holds the premium content
    // unless the server has verified entitlement and returned it.
    public void openPremiumScreen(String accessToken) {
        api.getPremiumContent(accessToken, new Callback() {
            public void onSuccess(Content c) { render(c); }   // server returned it
            public void onDenied()           { showUpgradePrompt(); }
        });
        // A cracked client that forces "isPremium=true" still gets nothing,
        // because the content only exists server-side for entitled users.
    }
}
```

### iOS (Swift) — Vulnerable

```
func openPremiumScreen(_ user: User) {
    if user.tier == "PREMIUM" {          // client-side decision, easily bypassed
        renderPremiumContent()           // content bundled/reachable regardless
    }
}
```

### iOS (Swift) — Secure

```
func openPremiumScreen(accessToken: String) {
    api.fetchPremiumContent(accessToken) { result in
        switch result {
        case .success(let content): self.render(content)   // server-verified
        case .denied:               self.showUpgradePrompt()
        }
    }
    // Entitlement is enforced where the attacker can't rewrite it: the server.
}
```

## 3. Hardcoded Encryption Key

### Android (Kotlin) — Vulnerable

```
object Crypto {
    // Key + algorithm both ship -> the "encryption" is fully reversible.
    private val KEY = "0123456789abcdef".toByteArray()

    fun decrypt(data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(KEY, "AES"),
                    IvParameterSpec(ByteArray(16)))
        return cipher.doFinal(data)
    }
}
```

### Android (Kotlin) — Secure

```
object Crypto {
    // Keys are generated on-device, stored in hardware-backed Keystore,
    // and never exist as a constant in the binary. Sensitive data that must
    // be protected between parties is handled server-side, not with a shipped key.
    fun getOrCreateKey(alias: String): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        return gen.generateKey()   // key material never leaves the secure hardware
    }
}
```

### iOS (Swift) — Vulnerable vs. Secure

```
// VULNERABLE: constant key recovered from the binary
let key = SymmetricKey(data: Data("0123456789abcdef".utf8))

// SECURE: generate a key and store it in the Keychain / Secure Enclave;
// no key constant ships, and Enclave keys are non-exportable.
let access = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage], nil)!
let attrs: [String: Any] = [
    kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String:       kSecAttrTokenIDSecureEnclave,   // hardware-backed
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: "com.example.app.key".data(using: .utf8)!,
        kSecAttrAccessControl as String: access
    ]
]
var error: Unmanaged<CFError>?
let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error)
```

## 4. Hidden Endpoint as a String Constant

### Vulnerable (Kotlin / Swift)

```
// Kotlin — falls out of `strings` before any decompiler is opened
const val ADMIN_BASE = "https://internal-admin.api.example.com/v3/"

// Swift — same problem
let adminBase = "https://internal-admin.api.example.com/v3/"
```

### Secure — Don&rsquo;t Rely on Secrecy of Endpoints

```
// The fix is NOT to hide the URL (you can't) but to secure the endpoint:
//  - Every endpoint requires proper authN + authZ, server-side.
//  - "Internal" routes are not reachable just because a URL is known.
//  - Assume every host string in your app is public and defend accordingly.
const val API_BASE = "https://api.example.com/v3/"   // public is fine if the
                                                     // server enforces access
```

## 5. Certificate Pinning (Friction, Done Right)

### Android (Kotlin) — OkHttp

```
// Pinning deters casual MITM and protocol analysis. It is bypassable on a
// controlled device, so it accompanies server-side controls — it doesn't replace them.
val pinner = CertificatePinner.Builder()
    .add("api.example.com", "sha256/PRIMARY_SPKI_PIN=")
    .add("api.example.com", "sha256/BACKUP_SPKI_PIN=")   // survive key rotation
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(pinner)
    .build()
```

### iOS (Swift) — URLSession delegate

```
func urlSession(_ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

    guard let trust = challenge.protectionSpace.serverTrust,
          validatePinnedSPKI(trust, expected: expectedPins) else {
        completionHandler(.cancelAuthenticationChallenge, nil)   // reject on mismatch
        return
    }
    completionHandler(.useCredential, URLCredential(trust: trust))
}
// Pin the SPKI, keep a backup pin, and still enforce authZ server-side.
```

## 6. Proving &ldquo;This Is the Real App&rdquo; — Secret vs. Attestation

### Vulnerable — a shipped &ldquo;app secret&rdquo;

```
// Anti-automation via a baked-in key. Reverse engineers recover the key and
// the algorithm, then script valid requests without the app. Defeated entirely.
val appProof = HmacUtil.hmacSha256("shipped-app-key", nonce)
```

### Secure — platform attestation verified server-side

```
// Android: Play Integrity — OS issues a token, your server verifies it.
val token = playIntegrityManager.requestIntegrityToken(request).await().token()
api.callProtected(body, integrityToken = token)   // server verifies with Google

// iOS: App Attest — hardware-backed key attests the genuine app instance.
DCAppAttestService.shared.generateKey { keyId, _ in
    // attest keyId, send assertion to YOUR server, which verifies it with Apple
}
// No secret ships; forging a valid token is not a matter of reading the binary.
```

## 7. Release-Build Hygiene (Android)

### Vulnerable

```
android {
    buildTypes {
        release {
            minifyEnabled false           // no obfuscation or shrinking
            debuggable true               // debuggable in production (!)
        }
    }
}
// Verbose Log.d calls left in, source file names intact, symbols present.
```

### Secure

```
android {
    buildTypes {
        release {
            minifyEnabled true            // R8 shrink + obfuscate
            shrinkResources true
            debuggable false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}
// proguard-rules.pro
-assumenosideeffects class android.util.Log {   // strip debug logging
    public static int d(...);
    public static int v(...);
}
// Keep mapping.txt OFF-device for crash de-obfuscation.
```

## What Changed, and Why

| Pattern | Vulnerable | Secure |
| --- | --- | --- |
| API secret | Hardcoded signing key in the binary | User token in client; secret stays server-side / proxied |
| Entitlement | Client-side `isPremium` boolean | Server verifies; premium bytes never reach unentitled devices |
| Encryption key | Constant key + algorithm ship together | Hardware-backed Keystore / Secure Enclave; no key constant |
| Endpoints | Rely on the URL being &ldquo;hidden&rdquo; | Assume public; enforce authN/authZ per endpoint |
| Pinning | Absent, or treated as a boundary | Present as friction, paired with server enforcement |
| &ldquo;Real app&rdquo; proof | Shipped app secret / HMAC key | Play Integrity / App Attest verified server-side |
| Release build | Debuggable, unobfuscated, symbols intact | R8, non-debuggable, stripped, logs removed |

## The Through-Line

Every secure column does one of two things: it **removes the prize** (no secret, no client-side decision, no shipped key) or it **moves the decision to the server** (entitlement, attestation, endpoint authorization). Obfuscation, stripping, and pinning appear only as honestly-labelled friction on top—never as the reason something is safe. That is the entire discipline of defending against reverse engineering: build as if the attacker has already read every line, because they can.

## Next Steps

- **Prevention**: The full layered strategy behind these snippets
- **Attack Vectors**: How these patterns are found and exploited
- **Mobile Top 10**: Return to the full mobile learning path
- **Practice**: Apply these techniques in guided exercises
