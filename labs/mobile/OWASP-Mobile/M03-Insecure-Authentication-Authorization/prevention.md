# M03: Insecure Authentication/Authorization - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Authentication Best Practices](#authentication-best-practices)
- [Session Management](#session-management)
- [Authorization Implementation](#authorization-implementation)
- [Token Security](#token-security)
- [Biometric Authentication](#biometric-authentication)
- [Multi-Factor Authentication](#multi-factor-authentication)
- [Monitoring and Response](#monitoring-and-response)
- [Implementation Checklist](#implementation-checklist)

## Prevention Strategy Overview

Securing authentication and authorization requires a comprehensive, defense-in-depth approach across multiple layers:

```
Security Layers:
1. Strong Authentication → Complex passwords, MFA, secure methods
2. Session Security → Secure tokens, timeouts, proper lifecycle
3. Server-Side Authorization → Every endpoint verified
4. Token Protection → Secure storage, encryption, validation
5. Continuous Monitoring → Detect anomalies and respond
6. Regular Audits → Test and improve security posture
```

## Authentication Best Practices

### 1. Password Security

**Enforce Strong Password Policies:**

```javascript
// Password validation example
const validatePassword = (password) => {
  const requirements = {
    minLength: 12,
    requireUppercase: /[A-Z]/,
    requireLowercase: /[a-z]/,
    requireNumber: /[0-9]/,
    requireSpecial: /[!@#$%^&*(),.?":{}|<>]/
  };
  
  if (password.length < requirements.minLength) {
    return { valid: false, error: 'Password must be at least 12 characters' };
  }
  if (!requirements.requireUppercase.test(password)) {
    return { valid: false, error: 'Password must contain uppercase letter' };
  }
  if (!requirements.requireLowercase.test(password)) {
    return { valid: false, error: 'Password must contain lowercase letter' };
  }
  if (!requirements.requireNumber.test(password)) {
    return { valid: false, error: 'Password must contain a number' };
  }
  if (!requirements.requireSpecial.test(password)) {
    return { valid: false, error: 'Password must contain special character' };
  }
  
  return { valid: true };
};
```

**Password Storage - Server Side:**

```python
# Use bcrypt for password hashing
import bcrypt

def hash_password(password):
    # Generate salt and hash password
    salt = bcrypt.gensalt(rounds=12)  # Cost factor of 12
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def verify_password(password, hashed):
    # Verify password against hash
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Never store passwords in plain text
# Never use weak hashing (MD5, SHA1)
# Always use adaptive hashing (bcrypt, scrypt, Argon2)
```

**Password Best Practices:**
- ✅ Minimum 12 characters length
- ✅ Complexity requirements (uppercase, lowercase, numbers, special chars)
- ✅ Password strength meter for user feedback
- ✅ Common password blacklist (password123, etc.)
- ✅ Breach detection integration (Have I Been Pwned API)
- ✅ Password expiration for sensitive accounts
- ✅ Password history to prevent reuse

### 2. Rate Limiting and Account Lockout

**Implement Rate Limiting:**

```javascript
// Express middleware for rate limiting
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  // Store in Redis for distributed systems
  store: new RedisStore({
    client: redisClient,
    prefix: 'rl:login:'
  })
});

app.post('/api/login', loginLimiter, async (req, res) => {
  // Login logic here
});
```

**Account Lockout Implementation:**

```python
# Track failed login attempts
def handle_login_attempt(username, password):
    user = get_user(username)
    
    if not user:
        # Don't reveal if user exists
        return {'success': False, 'error': 'Invalid credentials'}
    
    # Check if account is locked
    if user.locked_until and user.locked_until > datetime.now():
        return {
            'success': False, 
            'error': 'Account locked due to too many failed attempts'
        }
    
    # Verify password
    if not verify_password(password, user.password_hash):
        user.failed_attempts += 1
        
        # Lock account after 5 failed attempts
        if user.failed_attempts >= 5:
            user.locked_until = datetime.now() + timedelta(minutes=30)
            send_security_alert(user.email, 'Account locked')
        
        user.save()
        return {'success': False, 'error': 'Invalid credentials'}
    
    # Successful login - reset counter
    user.failed_attempts = 0
    user.locked_until = None
    user.save()
    
    return {'success': True, 'token': generate_token(user)}
```

**Rate Limiting Best Practices:**
- ✅ Limit login attempts (5 per 15 minutes)
- ✅ Implement progressive delays after failures
- ✅ CAPTCHA after multiple failed attempts
- ✅ Account lockout with notification
- ✅ IP-based and account-based limits
- ✅ Distributed rate limiting for scalability

### 3. Secure Credential Transmission

**Always Use HTTPS with Certificate Pinning:**

```kotlin
// Android - Certificate Pinning with OkHttp
val hostname = "api.yourapp.com"
val certificatePinner = CertificatePinner.Builder()
    .add(hostname, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add(hostname, "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()
```

```swift
// iOS - Certificate Pinning
class NetworkManager: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, 
                   didReceive challenge: URLAuthenticationChallenge, 
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let pinnedCertificates = [/* Your certificate data */]
        
        if validateCertificate(serverTrust, against: pinnedCertificates) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

## Session Management

### 1. Secure Token Generation

**Generate Cryptographically Secure Tokens:**

```javascript
// Node.js - Secure token generation
const crypto = require('crypto');

function generateSecureToken() {
  // Generate 32 bytes of random data
  return crypto.randomBytes(32).toString('hex');
}

function generateJWT(userId, role) {
  const jwt = require('jsonwebtoken');
  
  const payload = {
    userId: userId,
    role: role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour expiration
  };
  
  // Use strong secret from environment variable
  const secret = process.env.JWT_SECRET; // Minimum 256 bits
  
  return jwt.sign(payload, secret, { algorithm: 'HS256' });
}
```

**Token Generation Best Practices:**
- ✅ Use cryptographically secure random generation
- ✅ Sufficient token length (minimum 256 bits)
- ✅ Include expiration time
- ✅ Use strong signing keys (256+ bits)
- ✅ Rotate signing keys periodically

### 2. Session Timeout and Invalidation

**Implement Proper Session Lifecycle:**

```python
# Session management with Redis
import redis
from datetime import timedelta

redis_client = redis.Redis()

SESSION_TIMEOUT = 30 * 60  # 30 minutes
ABSOLUTE_TIMEOUT = 8 * 60 * 60  # 8 hours

def create_session(user_id, device_id):
    session_id = generate_secure_token()
    
    session_data = {
        'user_id': user_id,
        'device_id': device_id,
        'created_at': time.time(),
        'last_activity': time.time()
    }
    
    # Store session with expiration
    redis_client.setex(
        f'session:{session_id}',
        SESSION_TIMEOUT,
        json.dumps(session_data)
    )
    
    return session_id

def validate_session(session_id):
    session_json = redis_client.get(f'session:{session_id}')
    
    if not session_json:
        return None
    
    session = json.loads(session_json)
    
    # Check absolute timeout
    if time.time() - session['created_at'] > ABSOLUTE_TIMEOUT:
        invalidate_session(session_id)
        return None
    
    # Update last activity and extend session
    session['last_activity'] = time.time()
    redis_client.setex(
        f'session:{session_id}',
        SESSION_TIMEOUT,
        json.dumps(session)
    )
    
    return session

def invalidate_session(session_id):
    redis_client.delete(f'session:{session_id}')
```

**Session Management Best Practices:**
- ✅ Idle timeout: 15-30 minutes
- ✅ Absolute timeout: 8-12 hours
- ✅ Regenerate session ID on login
- ✅ Invalidate session on logout (client and server)
- ✅ Single concurrent session or manage multiple
- ✅ Session binding to device/IP (with flexibility for mobile)

### 3. Secure Token Storage - Mobile

**Android - Secure Storage:**

```kotlin
// Use Android Keystore for token encryption
class SecureTokenStorage(private val context: Context) {
    private val sharedPreferences = context.getSharedPreferences(
        "secure_prefs", 
        Context.MODE_PRIVATE
    )
    
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    
    fun saveToken(token: String) {
        val encryptedToken = encryptToken(token)
        sharedPreferences.edit()
            .putString("auth_token", encryptedToken)
            .apply()
    }
    
    fun getToken(): String? {
        val encryptedToken = sharedPreferences.getString("auth_token", null)
        return encryptedToken?.let { decryptToken(it) }
    }
    
    fun clearToken() {
        sharedPreferences.edit().remove("auth_token").apply()
    }
    
    private fun encryptToken(token: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val key = getOrCreateKey()
        cipher.init(Cipher.ENCRYPT_MODE, key)
        
        val iv = cipher.iv
        val encrypted = cipher.doFinal(token.toByteArray())
        
        return Base64.encodeToString(iv + encrypted, Base64.DEFAULT)
    }
    
    private fun getOrCreateKey(): SecretKey {
        if (!keyStore.containsAlias("auth_key")) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )
            keyGenerator.init(
                KeyGenParameterSpec.Builder(
                    "auth_key",
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
            )
            keyGenerator.generateKey()
        }
        
        return (keyStore.getEntry("auth_key", null) as KeyStore.SecretKeyEntry).secretKey
    }
}
```

**iOS - Keychain Storage:**

```swift
// iOS - Secure Keychain storage
class SecureTokenStorage {
    func saveToken(_ token: String) {
        let data = token.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "authToken",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete existing item
        SecItemDelete(query as CFDictionary)
        
        // Add new item
        SecItemAdd(query as CFDictionary, nil)
    }
    
    func getToken() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "authToken",
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let token = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return token
    }
    
    func clearToken() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "authToken"
        ]
        
        SecItemDelete(query as CFDictionary)
    }
}
```

## Authorization Implementation

### 1. Server-Side Authorization Checks

**Enforce Authorization on Every Endpoint:**

```python
# Python/Flask - Authorization decorator
from functools import wraps
from flask import request, jsonify

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'No authorization token'}), 401
        
        user = validate_token(token)
        if not user:
            return jsonify({'error': 'Invalid token'}), 401
        
        # Add user to request context
        request.user = user
        return f(*args, **kwargs)
    
    return decorated_function

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'user'):
                return jsonify({'error': 'Not authenticated'}), 401
            
            if request.user.role != role:
                return jsonify({'error': 'Insufficient privileges'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage
@app.route('/api/admin/users', methods=['GET'])
@require_auth
@require_role('admin')
def get_all_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])
```

### 2. Prevent IDOR Vulnerabilities

**Always Verify Resource Ownership:**

```javascript
// Node.js - Resource ownership verification
app.get('/api/orders/:orderId', authenticateUser, async (req, res) => {
  const orderId = req.params.orderId;
  const userId = req.user.id; // From authentication middleware
  
  try {
    const order = await Order.findById(orderId);
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    // CRITICAL: Verify ownership
    if (order.userId !== userId && req.user.role !== 'admin') {
      // Log potential IDOR attempt
      securityLogger.warn(`IDOR attempt: User ${userId} tried to access order ${orderId}`);
      return res.status(403).json({ error: 'Access denied' });
    }
    
    res.json(order);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});
```

**Use Non-Predictable Identifiers:**

```python
# Use UUIDs instead of sequential IDs
import uuid

class Order(db.Model):
    # Instead of auto-incrementing integer ID
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    # ... other fields
```

### 3. Implement Proper Access Control

**Role-Based Access Control (RBAC):**

```python
# Define permissions system
class Permission:
    READ_USERS = 'read:users'
    WRITE_USERS = 'write:users'
    DELETE_USERS = 'delete:users'
    READ_ORDERS = 'read:orders'
    WRITE_ORDERS = 'write:orders'

class Role:
    ADMIN = {
        Permission.READ_USERS,
        Permission.WRITE_USERS,
        Permission.DELETE_USERS,
        Permission.READ_ORDERS,
        Permission.WRITE_ORDERS
    }
    
    USER = {
        Permission.READ_ORDERS  # Only read own orders
    }
    
    GUEST = set()  # No permissions

def check_permission(user, required_permission):
    user_permissions = Role.__dict__.get(user.role, set())
    return required_permission in user_permissions

# Middleware
def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not check_permission(request.user, permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator
```

## Token Security

### JWT Best Practices

```javascript
// Secure JWT implementation
const jwt = require('jsonwebtoken');

const JWT_CONFIG = {
  accessTokenExpiry: '15m',  // Short-lived access tokens
  refreshTokenExpiry: '7d',   // Longer refresh tokens
  algorithm: 'HS256',
  issuer: 'your-app-name',
  audience: 'your-app-api'
};

function generateTokenPair(userId, role) {
  const accessToken = jwt.sign(
    {
      userId: userId,
      role: role,
      type: 'access'
    },
    process.env.JWT_ACCESS_SECRET,
    {
      expiresIn: JWT_CONFIG.accessTokenExpiry,
      algorithm: JWT_CONFIG.algorithm,
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience
    }
  );
  
  const refreshToken = jwt.sign(
    {
      userId: userId,
      type: 'refresh',
      tokenId: generateUniqueId() // For revocation
    },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: JWT_CONFIG.refreshTokenExpiry,
      algorithm: JWT_CONFIG.algorithm,
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience
    }
  );
  
  return { accessToken, refreshToken };
}

function validateAccessToken(token) {
  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
      algorithms: [JWT_CONFIG.algorithm],
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience
    });
    
    if (decoded.type !== 'access') {
      throw new Error('Invalid token type');
    }
    
    return decoded;
  } catch (error) {
    return null;
  }
}
```

## Biometric Authentication

### Secure Biometric Implementation

**Android - BiometricPrompt:**

```kotlin
class BiometricAuthManager(private val activity: FragmentActivity) {
    
    fun authenticate(onSuccess: () -> Unit, onError: (String) -> Unit) {
        val executor = ContextCompat.getMainExecutor(activity)
        
        val biometricPrompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    
                    // IMPORTANT: Verify on server side
                    verifyBiometricOnServer { serverVerified ->
                        if (serverVerified) {
                            onSuccess()
                        } else {
                            onError("Server verification failed")
                        }
                    }
                }
                
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onError(errString.toString())
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Authenticate to access your account")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        
        biometricPrompt.authenticate(promptInfo)
    }
    
    private fun verifyBiometricOnServer(callback: (Boolean) -> Unit) {
        // Send biometric verification to server
        // Server checks if biometric auth is enabled for user
        // Server validates the authentication event
        // Only then grant access
    }
}
```

**Biometric Security Checklist:**
- ✅ Use platform biometric APIs (BiometricPrompt, LocalAuthentication)
- ✅ Require server-side verification
- ✅ Set appropriate authenticator strength requirements
- ✅ Implement fallback authentication (with equal security)
- ✅ Detect and prevent root/jailbreak
- ✅ Implement anti-tampering measures

## Multi-Factor Authentication

### TOTP Implementation

```python
# Time-based One-Time Password (TOTP)
import pyotp
import qrcode

def generate_mfa_secret(user_id):
    # Generate secret key
    secret = pyotp.random_base32()
    
    # Store secret for user (encrypted)
    user = User.query.get(user_id)
    user.mfa_secret = encrypt(secret)
    user.mfa_enabled = False  # Not enabled until verified
    user.save()
    
    # Generate QR code for authenticator app
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='YourApp'
    )
    
    return {
        'secret': secret,
        'qr_code_uri': provisioning_uri
    }

def verify_mfa_code(user_id, code):
    user = User.query.get(user_id)
    
    if not user.mfa_enabled:
        return False
    
    secret = decrypt(user.mfa_secret)
    totp = pyotp.TOTP(secret)
    
    # Verify code (allows 30 second window)
    return totp.verify(code, valid_window=1)

def enable_mfa(user_id, verification_code):
    user = User.query.get(user_id)
    
    secret = decrypt(user.mfa_secret)
    totp = pyotp.TOTP(secret)
    
    if totp.verify(verification_code):
        user.mfa_enabled = True
        user.save()
        
        # Generate backup codes
        backup_codes = generate_backup_codes(user_id)
        
        return {'success': True, 'backup_codes': backup_codes}
    
    return {'success': False, 'error': 'Invalid verification code'}
```

## Monitoring and Response

### Security Event Logging

```javascript
// Log security events
const SecurityEvent = {
  LOGIN_SUCCESS: 'login_success',
  LOGIN_FAILURE: 'login_failure',
  LOGOUT: 'logout',
  PASSWORD_CHANGE: 'password_change',
  MFA_ENABLED: 'mfa_enabled',
  MFA_DISABLED: 'mfa_disabled',
  SUSPICIOUS_ACTIVITY: 'suspicious_activity',
  IDOR_ATTEMPT: 'idor_attempt',
  RATE_LIMIT_HIT: 'rate_limit_hit'
};

function logSecurityEvent(eventType, userId, metadata = {}) {
  const event = {
    timestamp: new Date().toISOString(),
    eventType: eventType,
    userId: userId,
    ip: metadata.ip,
    userAgent: metadata.userAgent,
    location: metadata.location,
    details: metadata.details
  };
  
  // Log to security monitoring system
  securityLogger.info(event);
  
  // Alert on critical events
  if (isCriticalEvent(eventType)) {
    sendSecurityAlert(event);
  }
}
```

## Implementation Checklist

### Authentication Checklist
```
□ Strong password policy (12+ chars, complexity requirements)
□ Passwords hashed with bcrypt/Argon2 (not MD5/SHA1)
□ Rate limiting on authentication endpoints (5 attempts/15 min)
□ Account lockout after failed attempts
□ CAPTCHA after multiple failures
□ Secure credential transmission (HTTPS + cert pinning)
□ MFA implementation and enforcement
□ Password breach detection
□ Common password blacklist
□ Secure password reset flow
```

### Session Management Checklist
```
□ Cryptographically secure token generation
□ Appropriate session timeouts (15-30 min idle)
□ Absolute session timeout (8-12 hours)
□ Session invalidation on logout (client + server)
□ Session regeneration on privilege change
□ Secure token storage (Keychain/Keystore)
□ Session binding to device (with mobile considerations)
□ Concurrent session management
□ Token rotation for refresh tokens
□ Token revocation mechanism
```

### Authorization Checklist
```
□ Server-side authorization on all endpoints
□ Resource ownership verification
□ Non-predictable resource identifiers (UUIDs)
□ Role-based access control (RBAC)
□ Function-level access control
□ Horizontal privilege escalation prevention
□ Vertical privilege escalation prevention
□ API authorization enforcement
□ Admin function protection
□ Regular authorization audits
```

### Biometric Authentication Checklist
```
□ Platform biometric APIs used (not custom)
□ Server-side verification required
□ Strong authenticator requirement
□ Secure fallback mechanism
□ Root/jailbreak detection
□ Anti-tampering measures
□ Biometric enrollment verification
□ User can disable biometric auth
```

### Token Security Checklist
```
□ Short-lived access tokens (15 minutes)
□ Longer refresh tokens (7 days max)
□ Strong signing keys (256+ bits)
□ Algorithm whitelist (no "none", no mixed)
□ Token expiration enforced
□ Token signature verification
□ Secure token storage
□ Token rotation on refresh
□ Token revocation capability
□ Tokens not in URLs or logs
```

## Key Takeaways

1. **Always enforce authentication and authorization server-side**
2. **Use strong, adaptive password hashing (bcrypt, Argon2)**
3. **Implement rate limiting and account lockout**
4. **Require MFA for sensitive applications**
5. **Validate resource ownership on every request**
6. **Use secure session management with appropriate timeouts**
7. **Store tokens securely using platform security features**
8. **Monitor and log security events for detection and response**

## Next Steps

- **[Examples](./examples.md)**: See vulnerable vs secure code implementations
- **[Interactive Lab](./lab/)**: Practice implementing secure authentication
- **[Attack Vectors](./attack-vectors.md)**: Review how attacks exploit weak auth

---

**Remember**: Security is not a feature you add at the end—it must be designed in from the start. Defense in depth is essential for robust authentication and authorization.
