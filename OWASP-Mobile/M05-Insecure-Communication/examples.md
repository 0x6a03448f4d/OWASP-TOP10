# M05: Insecure Communication - Code Examples

## Table of Contents
- [Vulnerable vs Secure Patterns](#vulnerable-vs-secure-patterns)
- [Android Examples](#android-examples)
- [iOS Examples](#ios-examples)
- [React Native Examples](#react-native-examples)
- [Flutter Examples](#flutter-examples)
- [Common Mistakes](#common-mistakes)

## Vulnerable vs Secure Patterns

### Pattern 1: HTTP vs HTTPS

**❌ VULNERABLE: Using HTTP**
```java
// INSECURE: Cleartext HTTP transmission
String apiUrl = "http://api.example.com/user/login";
HttpURLConnection connection = (HttpURLConnection) new URL(apiUrl).openConnection();
connection.setRequestMethod("POST");

// Credentials sent in cleartext!
String credentials = "{\"username\":\"user\",\"password\":\"pass123\"}";
connection.getOutputStream().write(credentials.getBytes());
```

**✅ SECURE: Using HTTPS**
```java
// SECURE: Encrypted HTTPS transmission
String apiUrl = "https://api.example.com/user/login";
HttpsURLConnection connection = (HttpsURLConnection) new URL(apiUrl).openConnection();
connection.setRequestMethod("POST");

String credentials = "{\"username\":\"user\",\"password\":\"pass123\"}";
connection.getOutputStream().write(credentials.getBytes());
```

### Pattern 2: Certificate Validation

**❌ VULNERABLE: Trusting All Certificates**
```java
// INSECURE: Accepts any certificate (NEVER DO THIS!)
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // Empty - trusts everything!
        }
        
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // Empty - trusts everything!
        }
        
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
};

SSLContext sslContext = SSLContext.getInstance("TLS");
sslContext.init(null, trustAllCerts, new SecureRandom());

// All certificate validation bypassed - VULNERABLE TO MITM!
HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
```

**✅ SECURE: Proper Certificate Validation**
```java
// SECURE: Use default system trust store
public OkHttpClient createSecureClient() {
    try {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init((KeyStore) null);  // Uses system trust store
        
        X509TrustManager trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        
        return new OkHttpClient.Builder()
            .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
            .hostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier())
            .build();
            
    } catch (Exception e) {
        throw new RuntimeException("Failed to create secure client", e);
    }
}
```

### Pattern 3: TLS Version Configuration

**❌ VULNERABLE: Using Outdated TLS**
```java
// INSECURE: Using deprecated SSL/TLS versions
SSLContext sslContext = SSLContext.getInstance("SSL");  // Don't use SSL!
// or
SSLContext sslContext = SSLContext.getInstance("TLSv1");  // TLS 1.0 is deprecated!
```

**✅ SECURE: Using Modern TLS**
```java
// SECURE: Use TLS 1.2 or 1.3
public OkHttpClient createTLSSecureClient() {
    ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
        .cipherSuites(
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        )
        .build();
    
    return new OkHttpClient.Builder()
        .connectionSpecs(Collections.singletonList(spec))
        .build();
}
```

## Android Examples

### Example 1: Secure Retrofit Configuration

**❌ VULNERABLE**
```java
public class InsecureApiService {
    private static Retrofit retrofit;
    
    public static Retrofit getInstance() {
        if (retrofit == null) {
            // Using HTTP - VULNERABLE!
            retrofit = new Retrofit.Builder()
                .baseUrl("http://api.example.com/")  // HTTP!
                .addConverterFactory(GsonConverterFactory.create())
                .build();
        }
        return retrofit;
    }
}
```

**✅ SECURE**
```java
public class SecureApiService {
    private static Retrofit retrofit;
    
    public static Retrofit getInstance() {
        if (retrofit == null) {
            OkHttpClient client = createSecureClient();
            
            retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")  // HTTPS!
                .client(client)
                .addConverterFactory(GsonConverterFactory.create())
                .build();
        }
        return retrofit;
    }
    
    private static OkHttpClient createSecureClient() {
        return new OkHttpClient.Builder()
            // Enforce HTTPS
            .addInterceptor(chain -> {
                Request request = chain.request();
                if (!"https".equals(request.url().scheme())) {
                    throw new SecurityException("HTTPS required");
                }
                return chain.proceed(request);
            })
            // Certificate pinning
            .certificatePinner(new CertificatePinner.Builder()
                .add("api.example.com", "sha256/primaryHash=")
                .add("api.example.com", "sha256/backupHash=")
                .build())
            // Modern TLS only
            .connectionSpecs(Arrays.asList(
                ConnectionSpec.MODERN_TLS,
                ConnectionSpec.COMPATIBLE_TLS
            ))
            .build();
    }
}
```

### Example 2: Network Security Configuration

**❌ VULNERABLE**
```xml
<!-- AndroidManifest.xml - INSECURE -->
<application
    android:usesCleartextTraffic="true">  <!-- Allows HTTP! -->
    <!-- ... -->
</application>
```

**✅ SECURE**
```xml
<!-- AndroidManifest.xml - SECURE -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false">  <!-- Blocks HTTP -->
    <!-- ... -->
</application>
```

```xml
<!-- res/xml/network_security_config.xml - SECURE -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <pin digest="SHA-256">primaryCertHash=</pin>
            <pin digest="SHA-256">backupCertHash=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

### Example 3: Volley Configuration

**❌ VULNERABLE**
```java
// INSECURE: No certificate validation
RequestQueue queue = Volley.newRequestQueue(context);

StringRequest request = new StringRequest(
    Request.Method.POST,
    "http://api.example.com/login",  // HTTP!
    response -> {
        // Handle response
    },
    error -> {
        // Handle error
    }
);

queue.add(request);
```

**✅ SECURE**
```java
// SECURE: With proper HTTPS and validation
public class SecureVolleyClient {
    
    public static RequestQueue createSecureQueue(Context context) {
        OkHttpClient client = new OkHttpClient.Builder()
            .certificatePinner(new CertificatePinner.Builder()
                .add("api.example.com", "sha256/certHash=")
                .build())
            .build();
        
        Volley.RequestQueue queue = Volley.newRequestQueue(
            context,
            new OkHttp3Stack(client)
        );
        
        return queue;
    }
    
    public static void makeSecureRequest(Context context) {
        RequestQueue queue = createSecureQueue(context);
        
        StringRequest request = new StringRequest(
            Request.Method.POST,
            "https://api.example.com/login",  // HTTPS!
            response -> { /* Handle response */ },
            error -> { /* Handle error */ }
        );
        
        queue.add(request);
    }
}
```

## iOS Examples

### Example 1: URLSession Configuration

**❌ VULNERABLE**
```swift
// INSECURE: Bypassing certificate validation
class InsecureNetworkManager: NSObject, URLSessionDelegate {
    
    func urlSession(_ session: URLSession,
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // DANGEROUS: Accepts any certificate!
        if let serverTrust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        }
    }
    
    func makeRequest() {
        // Using HTTP - INSECURE!
        let url = URL(string: "http://api.example.com/login")!
        let task = URLSession.shared.dataTask(with: url) { data, response, error in
            // Handle response
        }
        task.resume()
    }
}
```

**✅ SECURE**
```swift
// SECURE: Proper certificate validation and HTTPS
class SecureNetworkManager: NSObject, URLSessionDelegate {
    
    private let pinnedHashes: Set<String> = [
        "primaryCertHash",
        "backupCertHash"
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
        
        // Validate certificate
        var error: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &error) else {
            print("Certificate validation failed: \(error!)")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Certificate pinning
        if let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0),
           let publicKey = SecCertificateCopyKey(serverCert),
           let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? {
            
            let hash = publicKeyData.sha256().base64EncodedString()
            
            if pinnedHashes.contains(hash) {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
            } else {
                print("Certificate pinning failed")
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    func makeRequest() {
        // Using HTTPS - SECURE!
        guard let url = URL(string: "https://api.example.com/login"),
              url.scheme == "https" else {
            print("HTTPS required")
            return
        }
        
        let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        let task = session.dataTask(with: url) { data, response, error in
            // Handle response
        }
        task.resume()
    }
}

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

### Example 2: App Transport Security (ATS)

**❌ VULNERABLE**
```xml
<!-- Info.plist - INSECURE -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- Disables ATS entirely - DANGEROUS! -->
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

**✅ SECURE**
```xml
<!-- Info.plist - SECURE -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- ATS enabled by default -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    
    <!-- Specific domain configuration -->
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

### Example 3: Alamofire Configuration

**❌ VULNERABLE**
```swift
// INSECURE: No certificate validation
let manager = Session(configuration: .default)

manager.request("http://api.example.com/data")  // HTTP!
    .responseJSON { response in
        // Handle response
    }
```

**✅ SECURE**
```swift
// SECURE: With certificate pinning and HTTPS enforcement
import Alamofire

class SecureAPIManager {
    static let shared = SecureAPIManager()
    private let session: Session
    
    init() {
        let evaluators: [String: ServerTrustEvaluating] = [
            "api.example.com": PinnedCertificatesTrustEvaluator(
                certificates: [
                    SecureAPIManager.certificate(named: "api_example_com")
                ],
                acceptSelfSignedCertificates: false,
                performDefaultValidation: true,
                validateHost: true
            )
        ]
        
        let serverTrustManager = ServerTrustManager(evaluators: evaluators)
        
        session = Session(
            serverTrustManager: serverTrustManager
        )
    }
    
    func makeRequest(endpoint: String) {
        guard endpoint.hasPrefix("https://") else {
            print("HTTPS required")
            return
        }
        
        session.request(endpoint)
            .validate()
            .responseJSON { response in
                // Handle response
            }
    }
    
    private static func certificate(named name: String) -> SecCertificate {
        let path = Bundle.main.path(forResource: name, ofType: "cer")!
        let data = try! Data(contentsOf: URL(fileURLWithPath: path))
        return SecCertificateCreateWithData(nil, data as CFData)!
    }
}
```

## React Native Examples

### Example 1: Fetch API

**❌ VULNERABLE**
```javascript
// INSECURE: Using HTTP
async function login(username, password) {
  try {
    const response = await fetch('http://api.example.com/login', {  // HTTP!
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    });
    
    return await response.json();
  } catch (error) {
    console.error('Login failed:', error);
  }
}
```

**✅ SECURE**
```javascript
// SECURE: Using HTTPS with validation
const API_BASE_URL = 'https://api.example.com';  // HTTPS only

// Certificate pinning using react-native-ssl-pinning
import { fetch as sslFetch } from 'react-native-ssl-pinning';

async function secureLogin(username, password) {
  try {
    // Validate URL scheme
    if (!API_BASE_URL.startsWith('https://')) {
      throw new Error('HTTPS required');
    }
    
    const response = await sslFetch(`${API_BASE_URL}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
      sslPinning: {
        certs: ['api_example_com'],  // Certificate in assets
      },
      timeoutInterval: 30000,
    });
    
    return await response.json();
  } catch (error) {
    console.error('Secure login failed:', error);
    throw error;
  }
}
```

### Example 2: Axios Configuration

**❌ VULNERABLE**
```javascript
// INSECURE: No certificate validation
import axios from 'axios';

const client = axios.create({
  baseURL: 'http://api.example.com',  // HTTP!
});

// No certificate validation configured
```

**✅ SECURE**
```javascript
// SECURE: With HTTPS enforcement
import axios from 'axios';
import { Platform } from 'react-native';

const API_BASE_URL = 'https://api.example.com';  // HTTPS

// Enforce HTTPS
const enforceHttps = (config) => {
  if (!config.url.startsWith('https://')) {
    throw new Error('HTTPS required for all requests');
  }
  return config;
};

const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
});

client.interceptors.request.use(enforceHttps);

// For certificate pinning on React Native
if (Platform.OS === 'android' || Platform.OS === 'ios') {
  // Use react-native-ssl-pinning or configure native modules
  // See native configuration files
}

export default client;
```

## Flutter Examples

### Example 1: HTTP Client

**❌ VULNERABLE**
```dart
// INSECURE: Using HTTP
import 'package:http/http.dart' as http;

Future<void> login(String username, String password) async {
  // HTTP - INSECURE!
  final response = await http.post(
    Uri.parse('http://api.example.com/login'),
    body: {'username': username, 'password': password},
  );
  
  if (response.statusCode == 200) {
    // Handle success
  }
}
```

**✅ SECURE**
```dart
// SECURE: Using HTTPS with certificate pinning
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'dart:io';

class SecureHttpClient {
  static http.Client createSecureClient() {
    final securityContext = SecurityContext.defaultContext;
    
    // Load certificate for pinning
    final certBytes = File('assets/certificates/api_example_com.pem')
        .readAsBytesSync();
    securityContext.setTrustedCertificatesBytes(certBytes);
    
    final httpClient = HttpClient(context: securityContext);
    
    // Enforce HTTPS
    httpClient.badCertificateCallback = (cert, host, port) {
      // Only for specific pinned certificates
      // Perform certificate validation here
      return false;  // Reject by default
    };
    
    return IOClient(httpClient);
  }
  
  static Future<void> secureLogin(String username, String password) async {
    final client = createSecureClient();
    
    // HTTPS only
    final url = Uri.parse('https://api.example.com/login');
    
    if (url.scheme != 'https') {
      throw Exception('HTTPS required');
    }
    
    try {
      final response = await client.post(
        url,
        body: {'username': username, 'password': password},
      );
      
      if (response.statusCode == 200) {
        // Handle success
      }
    } finally {
      client.close();
    }
  }
}
```

### Example 2: Dio Configuration

**❌ VULNERABLE**
```dart
// INSECURE: No certificate validation
import 'package:dio/dio.dart';

final dio = Dio(BaseOptions(
  baseUrl: 'http://api.example.com',  // HTTP!
));
```

**✅ SECURE**
```dart
// SECURE: With certificate pinning
import 'package:dio/dio.dart';
import 'package:dio/adapter.dart';
import 'dart:io';

class SecureDioClient {
  static Dio createSecureClient() {
    final dio = Dio(BaseOptions(
      baseUrl: 'https://api.example.com',  // HTTPS
      connectTimeout: 30000,
      receiveTimeout: 30000,
    ));
    
    // Add interceptor to enforce HTTPS
    dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) {
        if (!options.uri.scheme.startsWith('https')) {
          return handler.reject(
            DioError(
              requestOptions: options,
              error: 'HTTPS required',
            ),
          );
        }
        return handler.next(options);
      },
    ));
    
    // Configure certificate pinning
    (dio.httpClientAdapter as DefaultHttpClientAdapter).onHttpClientCreate = 
        (client) {
      client.badCertificateCallback = 
          (X509Certificate cert, String host, int port) {
        // Validate certificate hash
        final certHash = cert.sha256.toString();
        final pinnedHashes = [
          'primaryCertHash',
          'backupCertHash',
        ];
        
        return pinnedHashes.contains(certHash);
      };
      
      return client;
    };
    
    return dio;
  }
}
```

## Common Mistakes

### Mistake 1: Development Code in Production

```java
// DANGEROUS: Debug code left in production
if (BuildConfig.DEBUG) {
    // Disable certificate validation for testing
    trustAllCertificates();  // NEVER ship this!
}
```

**Fix:**
```java
// Use proper build configurations
// Remove all certificate bypasses before release
// Use ProGuard to strip debug code
```

### Mistake 2: Improper Error Handling

```java
// VULNERABLE: Falling back to HTTP on HTTPS failure
try {
    response = httpsClient.execute(request);
} catch (SSLException e) {
    // DANGEROUS: Retry with HTTP
    response = httpClient.execute(request);  // INSECURE!
}
```

**Fix:**
```java
// SECURE: Fail securely, never downgrade
try {
    response = httpsClient.execute(request);
} catch (SSLException e) {
    // Log error and fail
    logger.error("HTTPS connection failed", e);
    throw new SecurityException("Secure connection required", e);
}
```

### Mistake 3: Mixed Content

```java
// VULNERABLE: Mixing HTTP and HTTPS
String apiUrl = "https://api.example.com/data";
String imageUrl = "http://cdn.example.com/image.jpg";  // HTTP!

// HTTPS API call
fetchData(apiUrl);

// HTTP image load - INSECURE!
loadImage(imageUrl);
```

**Fix:**
```java
// SECURE: Use HTTPS for all resources
String apiUrl = "https://api.example.com/data";
String imageUrl = "https://cdn.example.com/image.jpg";  // HTTPS

// Both use HTTPS
fetchData(apiUrl);
loadImage(imageUrl);
```

## Summary

Key takeaways:
1. **Always use HTTPS** - Never HTTP for sensitive data
2. **Proper certificate validation** - Don't trust all certificates
3. **Modern TLS** - Use TLS 1.2 or 1.3
4. **Certificate pinning** - For critical APIs
5. **Platform features** - Use NSC (Android) and ATS (iOS)
6. **No exceptions** - Never disable security for convenience

---

**Next:** Try the [Hands-on Lab](./lab/) to practice identifying and fixing insecure communication vulnerabilities.
