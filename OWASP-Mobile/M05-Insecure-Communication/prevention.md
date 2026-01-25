# M05: Insecure Communication - Prevention

## Table of Contents
- [Prevention Overview](#prevention-overview)
- [Enforce HTTPS Everywhere](#enforce-https-everywhere)
- [Proper TLS Configuration](#proper-tls-configuration)
- [Certificate Validation](#certificate-validation)
- [Certificate Pinning](#certificate-pinning)
- [Network Security Configuration](#network-security-configuration)
- [Secure Communication Patterns](#secure-communication-patterns)
- [Testing and Validation](#testing-and-validation)
- [Implementation Checklist](#implementation-checklist)

## Prevention Overview

Preventing insecure communication requires a multi-layered approach focusing on:
1. **Mandatory HTTPS** for all network communications
2. **Strong TLS configuration** using modern protocols and cipher suites
3. **Proper certificate validation** to prevent MITM attacks
4. **Certificate pinning** for critical connections
5. **Network security policies** enforced at the platform level

### Defense-in-Depth Strategy

```
Layer 1: Enforce HTTPS Only (No HTTP allowed)
    ↓
Layer 2: TLS 1.2/1.3 with Strong Cipher Suites
    ↓
Layer 3: Proper Certificate Validation
    ↓
Layer 4: Certificate Pinning for Critical APIs
    ↓
Layer 5: Network Security Configuration
    ↓
Secure Communication Channel
```

## Enforce HTTPS Everywhere

### Principle: Never Use HTTP for Sensitive Data

**Rule:** All network communications containing sensitive data MUST use HTTPS.

### Android Implementation

**1. Network Security Configuration (API 24+):**

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Block all cleartext (HTTP) traffic -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    
    <!-- Enforce HTTPS for all domains -->
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">example.com</domain>
    </domain-config>
</network-security-config>
```

**AndroidManifest.xml:**
```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false">
    <!-- App configuration -->
</application>
```

### iOS Implementation

**1. App Transport Security (ATS):**

```xml
<!-- Info.plist -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Enforce HTTPS globally -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    
    <!-- Exception for specific domains if absolutely necessary -->
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
        </dict>
    </dict>
</dict>
```

### Code-Level Enforcement

**Android - Retrofit Configuration:**
```java
public class SecureApiClient {
    
    private static OkHttpClient createSecureClient() {
        // Force HTTPS only
        return new OkHttpClient.Builder()
            .addInterceptor(chain -> {
                Request request = chain.request();
                
                // Block HTTP requests
                if (!"https".equals(request.url().scheme())) {
                    throw new IllegalStateException(
                        "SECURITY: HTTP not allowed. Use HTTPS only."
                    );
                }
                
                return chain.proceed(request);
            })
            .build();
    }
    
    public static Retrofit createApiService() {
        return new Retrofit.Builder()
            .baseUrl("https://api.example.com/")  // HTTPS only
            .client(createSecureClient())
            .addConverterFactory(GsonConverterFactory.create())
            .build();
    }
}
```

**iOS - URLSession Configuration:**
```swift
class SecureNetworkManager {
    
    static func createSecureSession() -> URLSession {
        let configuration = URLSessionConfiguration.default
        
        // Additional security headers
        configuration.httpAdditionalHeaders = [
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
        ]
        
        return URLSession(configuration: configuration, 
                         delegate: SecureSessionDelegate(), 
                         delegateQueue: nil)
    }
    
    static func makeRequest(url: String, completion: @escaping (Data?, Error?) -> Void) {
        guard url.hasPrefix("https://") else {
            completion(nil, NSError(domain: "Security", code: 1, 
                                   userInfo: [NSLocalizedDescriptionKey: "HTTPS required"]))
            return
        }
        
        let session = createSecureSession()
        let task = session.dataTask(with: URL(string: url)!) { data, response, error in
            completion(data, error)
        }
        task.resume()
    }
}
```

## Proper TLS Configuration

### Use Modern TLS Versions

**Minimum Requirements:**
- TLS 1.2 as minimum (prefer TLS 1.3)
- Disable TLS 1.0 and TLS 1.1 (deprecated)
- Use strong cipher suites only

### Android TLS Configuration

```java
public class SecureTLSConfiguration {
    
    public static SSLContext createSecureSSLContext() throws Exception {
        // Use TLS 1.2 or 1.3
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        
        // Initialize with default trust manager
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init((KeyStore) null);
        
        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        return sslContext;
    }
    
    public static OkHttpClient createTLSSecureClient() throws Exception {
        SSLContext sslContext = createSecureSSLContext();
        
        // Specify TLS versions
        ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
            .cipherSuites(
                // Strong cipher suites only
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            )
            .build();
        
        return new OkHttpClient.Builder()
            .sslSocketFactory(sslContext.getSocketFactory(), 
                             (X509TrustManager) tmf.getTrustManagers()[0])
            .connectionSpecs(Collections.singletonList(spec))
            .build();
    }
}
```

### iOS TLS Configuration

```swift
class TLSSecurityManager {
    
    static func configureSecureTLS() {
        // iOS handles TLS 1.2/1.3 automatically
        // Enforce through ATS configuration
    }
    
    // Custom SSL validation
    func urlSession(_ session: URLSession, 
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard challenge.protectionSpace.authenticationMethod == 
              NSURLAuthenticationMethodServerTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Validate TLS version
        let policy = SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)
        SecTrustSetPolicies(serverTrust, policy)
        
        var error: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &error) else {
            print("TLS validation failed: \(error?.localizedDescription ?? "Unknown error")")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}
```

## Certificate Validation

### Proper Certificate Validation Implementation

**Android - Secure Certificate Validation:**

```java
public class CertificateValidator {
    
    public static OkHttpClient createValidatingClient(Context context) {
        try {
            // Load system CA certificates
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            );
            tmf.init((KeyStore) null);
            
            // Get default trust manager
            X509TrustManager trustManager = null;
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    trustManager = (X509TrustManager) tm;
                    break;
                }
            }
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, null);
            
            return new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                .hostnameVerifier(new StrictHostnameVerifier())  // Strict validation
                .build();
                
        } catch (Exception e) {
            throw new RuntimeException("Failed to create secure client", e);
        }
    }
    
    // Custom hostname verifier with strict validation
    private static class StrictHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            HostnameVerifier defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
            return defaultVerifier.verify(hostname, session);
        }
    }
}
```

**iOS - Certificate Validation:**

```swift
class CertificateValidationDelegate: NSObject, URLSessionDelegate {
    
    func urlSession(_ session: URLSession, 
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // Only handle server trust challenges
        guard challenge.protectionSpace.authenticationMethod == 
              NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Create policy for SSL
        let policies = [SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)]
        SecTrustSetPolicies(serverTrust, policies as CFTypeRef)
        
        // Evaluate trust
        var error: CFError?
        let isValid = SecTrustEvaluateWithError(serverTrust, &error)
        
        if isValid {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            print("Certificate validation failed: \(error?.localizedDescription ?? "Unknown")")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

## Certificate Pinning

### What is Certificate Pinning?

Certificate pinning ensures your app only trusts specific certificates or public keys, preventing MITM attacks even if a CA is compromised.

### Android - Certificate Pinning with OkHttp

```java
public class CertificatePinningExample {
    
    public static OkHttpClient createPinnedClient() {
        // Pin specific certificates (SHA-256 hash of public key)
        CertificatePinner certificatePinner = new CertificatePinner.Builder()
            .add("api.example.com", 
                 "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")  // Primary cert
            .add("api.example.com", 
                 "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")  // Backup cert
            .build();
        
        return new OkHttpClient.Builder()
            .certificatePinner(certificatePinner)
            .build();
    }
    
    // Alternative: Network Security Configuration (Android 7.0+)
    // See res/xml/network_security_config.xml below
}
```

**Network Security Configuration with Pinning:**
```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <!-- Pin to certificate public key (SHA-256) -->
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <!-- Backup pin -->
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**Get Certificate Pin:**
```bash
# Extract SHA-256 pin from certificate
openssl s_client -connect api.example.com:443 < /dev/null | \
  openssl x509 -pubkey -noout | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | \
  base64
```

### iOS - Certificate Pinning

```swift
class CertificatePinningManager: NSObject, URLSessionDelegate {
    
    // Store pinned certificate hashes
    private let pinnedCertificates: Set<String> = [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  // Primary
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="   // Backup
    ]
    
    func urlSession(_ session: URLSession,
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard challenge.protectionSpace.authenticationMethod == 
              NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Validate certificate chain
        var error: CFError?
        let isValid = SecTrustEvaluateWithError(serverTrust, &error)
        
        guard isValid else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get server certificate
        guard let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get public key and compute hash
        let publicKey = SecCertificateCopyKey(serverCertificate)
        let publicKeyData = SecKeyCopyExternalRepresentation(publicKey!, nil)! as Data
        
        let hash = publicKeyData.sha256().base64EncodedString()
        
        // Check if hash matches pinned certificates
        if pinnedCertificates.contains(hash) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            print("Certificate pinning failed: Hash mismatch")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

// Extension for SHA-256 hashing
extension Data {
    func sha256() -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(self.count), &hash)
        }
        return Data(hash)
    }
}
```

### Certificate Pinning Best Practices

1. **Pin Multiple Certificates**: Always pin backup certificates
2. **Set Expiration**: Update pins before certificates expire
3. **Monitor Expiration**: Automated alerts for expiring pins
4. **Graceful Fallback**: Handle pinning failures appropriately
5. **Update Mechanism**: Plan for emergency pin updates

## Network Security Configuration

### Android Network Security Best Practices

```xml
<!-- res/xml/network_security_config.xml - Complete Example -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Base configuration for all connections -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <!-- Trust system certificates -->
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    
    <!-- Production API configuration -->
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <pin digest="SHA-256">primaryCertHash=</pin>
            <pin digest="SHA-256">backupCertHash=</pin>
        </pin-set>
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </domain-config>
    
    <!-- Debug configuration (development only) -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
            <certificates src="system" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

### iOS Network Security Best Practices

```xml
<!-- Info.plist - Complete ATS Configuration -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Global settings -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    
    <!-- Domain-specific requirements -->
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
            <key>NSRequiresCertificateTransparency</key>
            <true/>
        </dict>
    </dict>
</dict>
```

## Secure Communication Patterns

### Pattern 1: Secure API Client Wrapper

```java
public class SecureApiClient {
    private static final String BASE_URL = "https://api.example.com/";
    private static OkHttpClient httpClient;
    
    public static synchronized OkHttpClient getClient() {
        if (httpClient == null) {
            httpClient = new OkHttpClient.Builder()
                // Enforce HTTPS
                .addInterceptor(new HttpsEnforcementInterceptor())
                // Add security headers
                .addInterceptor(new SecurityHeadersInterceptor())
                // Certificate pinning
                .certificatePinner(createCertificatePinner())
                // TLS configuration
                .connectionSpecs(Arrays.asList(
                    ConnectionSpec.MODERN_TLS,
                    ConnectionSpec.COMPATIBLE_TLS
                ))
                // Timeouts
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build();
        }
        return httpClient;
    }
    
    private static CertificatePinner createCertificatePinner() {
        return new CertificatePinner.Builder()
            .add("api.example.com", "sha256/primaryHash=")
            .add("api.example.com", "sha256/backupHash=")
            .build();
    }
}

class HttpsEnforcementInterceptor implements Interceptor {
    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        if (!"https".equals(request.url().scheme())) {
            throw new SecurityException("HTTPS required for all requests");
        }
        return chain.proceed(request);
    }
}

class SecurityHeadersInterceptor implements Interceptor {
    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request().newBuilder()
            .addHeader("X-Content-Type-Options", "nosniff")
            .addHeader("X-Frame-Options", "DENY")
            .addHeader("Strict-Transport-Security", "max-age=31536000")
            .build();
        return chain.proceed(request);
    }
}
```

### Pattern 2: Secure Data Transmission

```kotlin
class SecureDataTransmitter {
    
    suspend fun sendSecureData(data: SensitiveData): Result<Response> {
        return withContext(Dispatchers.IO) {
            try {
                // Validate network security
                if (!isSecureConnection()) {
                    return@withContext Result.failure(
                        SecurityException("Insecure network detected")
                    )
                }
                
                // Encrypt data before transmission
                val encryptedData = encryptData(data)
                
                // Send over HTTPS
                val response = SecureApiClient.getClient()
                    .newCall(buildRequest(encryptedData))
                    .execute()
                
                Result.success(response)
                
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }
    
    private fun isSecureConnection(): Boolean {
        val connectivityManager = context.getSystemService(
            Context.CONNECTIVITY_SERVICE
        ) as ConnectivityManager
        
        val activeNetwork = connectivityManager.activeNetwork ?: return false
        val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
        
        // Check if on VPN or trusted network
        return capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true ||
               capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true
    }
}
```

## Testing and Validation

### Manual Testing Checklist

```bash
# 1. Test HTTPS enforcement
curl http://api.example.com/endpoint
# Should fail or redirect to HTTPS

# 2. Test TLS version
openssl s_client -connect api.example.com:443 -tls1
# Should fail (TLS 1.0 not supported)

openssl s_client -connect api.example.com:443 -tls1_2
# Should succeed

# 3. Test certificate validation
openssl s_client -connect api.example.com:443 -showcerts

# 4. Test cipher suites
nmap --script ssl-enum-ciphers -p 443 api.example.com

# 5. Test with SSL/TLS scanner
./testssl.sh api.example.com
```

### Automated Testing

```java
@Test
public void testHttpsEnforcement() {
    OkHttpClient client = SecureApiClient.getClient();
    
    // Attempt HTTP request
    Request request = new Request.Builder()
        .url("http://api.example.com/test")
        .build();
    
    assertThrows(SecurityException.class, () -> {
        client.newCall(request).execute();
    });
}

@Test
public void testCertificatePinning() {
    // This should fail with invalid certificate
    assertThrows(SSLPeerUnverifiedException.class, () -> {
        OkHttpClient client = new OkHttpClient.Builder()
            .certificatePinner(new CertificatePinner.Builder()
                .add("api.example.com", "sha256/invalidHash=")
                .build())
            .build();
        
        Request request = new Request.Builder()
            .url("https://api.example.com/test")
            .build();
        
        client.newCall(request).execute();
    });
}
```

## Implementation Checklist

### Essential Security Measures

- [ ] **Enforce HTTPS for all communications**
  - [ ] No HTTP URLs in code
  - [ ] Network security configuration blocks cleartext
  - [ ] ATS properly configured (iOS)

- [ ] **Proper TLS Configuration**
  - [ ] TLS 1.2 minimum (prefer 1.3)
  - [ ] Strong cipher suites only
  - [ ] No deprecated protocols (SSL, TLS 1.0/1.1)

- [ ] **Certificate Validation**
  - [ ] Default system validation enabled
  - [ ] No custom trust managers that skip validation
  - [ ] Proper hostname verification

- [ ] **Certificate Pinning**
  - [ ] Implemented for critical APIs
  - [ ] Multiple pins configured (primary + backup)
  - [ ] Expiration dates set and monitored

- [ ] **Code Review**
  - [ ] No hardcoded HTTP URLs
  - [ ] No disabled certificate validation
  - [ ] No `trustAllCerts` implementations

- [ ] **Testing**
  - [ ] MITM attack testing performed
  - [ ] Certificate validation tested
  - [ ] Automated security tests in CI/CD

- [ ] **Monitoring**
  - [ ] Certificate expiration monitoring
  - [ ] TLS handshake failure alerts
  - [ ] Pinning failure tracking

## Summary

Secure communication requires:
1. **Mandatory HTTPS** with no HTTP fallback
2. **Modern TLS** (1.2/1.3) with strong ciphers
3. **Proper certificate validation** without exceptions
4. **Certificate pinning** for critical connections
5. **Platform security features** (NSC, ATS)
6. **Regular testing** and monitoring

These measures provide defense-in-depth against MITM attacks, packet sniffing, and other network-based threats.

---

**Next:** See [Code Examples](./examples.md) for practical implementation examples and try the [Hands-on Lab](./lab/) to practice secure communication.
