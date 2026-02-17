# M03: Insecure Authentication/Authorization - Examples

## Table of Contents
- [Authentication Examples](#authentication-examples)
- [Session Management Examples](#session-management-examples)
- [Authorization Examples](#authorization-examples)
- [Token Security Examples](#token-security-examples)
- [Biometric Authentication Examples](#biometric-authentication-examples)
- [Real-World Case Studies](#real-world-case-studies)
- [Quick Reference](#quick-reference)

## Authentication Examples

### Example 1: Password Validation

**❌ Vulnerable: Weak Password Policy**

```javascript
// UNSAFE - Weak password requirements
function validatePassword(password) {
  if (password.length >= 6) {
    return true;
  }
  return false;
}

// Allows: "pass12", "abc123", "111111"
// No complexity, too short, easily guessed
```

**Problems:**
- Only 6 characters required
- No complexity requirements
- No checking against common passwords
- Vulnerable to brute force and dictionary attacks

**✅ Secure: Strong Password Policy**

```javascript
// SECURE - Comprehensive password validation
function validatePassword(password) {
  const minLength = 12;
  const commonPasswords = ['password', '12345678', 'qwerty123', /* ... */];
  
  // Length check
  if (password.length < minLength) {
    return { valid: false, error: 'Password must be at least 12 characters' };
  }
  
  // Complexity checks
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  if (!hasUppercase || !hasLowercase || !hasNumber || !hasSpecial) {
    return { 
      valid: false, 
      error: 'Password must contain uppercase, lowercase, number, and special character' 
    };
  }
  
  // Common password check
  if (commonPasswords.includes(password.toLowerCase())) {
    return { valid: false, error: 'Password is too common' };
  }
  
  // Optional: Check against breach database
  // if (await isPasswordBreached(password)) {
  //   return { valid: false, error: 'Password found in data breach' };
  // }
  
  return { valid: true };
}
```

### Example 2: Login Rate Limiting

**❌ Vulnerable: No Rate Limiting**

```python
# UNSAFE - No rate limiting
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password_hash, password):
        token = generate_token(user.id)
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401

# Attacker can try unlimited passwords
# Enables brute force attacks
```

**✅ Secure: Rate Limiting with Account Lockout**

```python
# SECURE - Rate limiting and account lockout
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per 15 minutes")
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if not user:
        # Don't reveal if user exists
        time.sleep(0.5)  # Prevent timing attacks
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if account is locked
    if user.locked_until and user.locked_until > datetime.utcnow():
        return jsonify({'error': 'Account temporarily locked'}), 403
    
    # Verify password
    if check_password_hash(user.password_hash, password):
        # Success - reset failed attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()
        
        token = generate_token(user.id)
        log_security_event('LOGIN_SUCCESS', user.id, request.remote_addr)
        
        return jsonify({'token': token})
    else:
        # Failed attempt
        user.failed_login_attempts += 1
        
        # Lock account after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            send_security_alert(user.email, "Account locked due to failed login attempts")
        
        db.session.commit()
        log_security_event('LOGIN_FAILURE', username, request.remote_addr)
        
        time.sleep(0.5)  # Prevent timing attacks
        return jsonify({'error': 'Invalid credentials'}), 401
```

## Session Management Examples

### Example 3: Token Storage

**❌ Vulnerable: Insecure Token Storage**

```kotlin
// Android - UNSAFE token storage
class TokenManager(private val context: Context) {
    fun saveToken(token: String) {
        // Storing in SharedPreferences without encryption
        val prefs = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
        prefs.edit()
            .putString("auth_token", token)  // Plain text!
            .apply()
    }
    
    fun getToken(): String? {
        val prefs = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
        return prefs.getString("auth_token", null)
    }
}

// Token easily extracted by:
// - Root users
// - ADB backup
// - Malware with storage access
```

**✅ Secure: Encrypted Token Storage**

```kotlin
// Android - SECURE token storage using Android Keystore
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SecureTokenManager(private val context: Context) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    
    private val encryptedPrefs = EncryptedSharedPreferences.create(
        context,
        "secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
    
    fun saveToken(token: String) {
        encryptedPrefs.edit()
            .putString("auth_token", token)
            .apply()
    }
    
    fun getToken(): String? {
        return encryptedPrefs.getString("auth_token", null)
    }
    
    fun clearToken() {
        encryptedPrefs.edit()
            .remove("auth_token")
            .apply()
    }
}
```

**iOS - Secure Keychain Storage:**

```swift
// iOS - SECURE token storage using Keychain
import Security

class SecureTokenManager {
    private let account = "authToken"
    
    func saveToken(_ token: String) -> Bool {
        guard let data = token.data(using: .utf8) else { return false }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete existing
        SecItemDelete(query as CFDictionary)
        
        // Add new
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    func getToken() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
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
    
    func clearToken() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
}
```

### Example 4: Session Timeout

**❌ Vulnerable: No Session Expiration**

```javascript
// UNSAFE - Tokens never expire
const jwt = require('jsonwebtoken');

function generateToken(userId) {
  return jwt.sign(
    { userId: userId },
    SECRET_KEY
    // No expiration set!
  );
}

// Token valid forever
// Stolen token = permanent access
```

**✅ Secure: Proper Session Lifecycle**

```javascript
// SECURE - Short-lived access tokens with refresh tokens
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const TOKEN_CONFIG = {
  accessTokenExpiry: '15m',   // 15 minutes
  refreshTokenExpiry: '7d',    // 7 days
  absoluteSessionExpiry: 8 * 60 * 60 * 1000  // 8 hours in ms
};

function generateTokenPair(userId, sessionId) {
  const now = Date.now();
  
  const accessToken = jwt.sign(
    {
      userId: userId,
      sessionId: sessionId,
      type: 'access',
      iat: Math.floor(now / 1000)
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: TOKEN_CONFIG.accessTokenExpiry }
  );
  
  const refreshToken = jwt.sign(
    {
      userId: userId,
      sessionId: sessionId,
      type: 'refresh',
      tokenId: uuidv4(),  // Unique ID for revocation
      iat: Math.floor(now / 1000)
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: TOKEN_CONFIG.refreshTokenExpiry }
  );
  
  // Store session metadata
  storeSession(sessionId, {
    userId: userId,
    createdAt: now,
    lastActivity: now,
    refreshTokenId: jwt.decode(refreshToken).tokenId
  });
  
  return { accessToken, refreshToken };
}

async function refreshAccessToken(refreshToken) {
  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    
    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }
    
    // Check if refresh token is revoked
    if (await isTokenRevoked(decoded.tokenId)) {
      throw new Error('Token revoked');
    }
    
    // Get session
    const session = await getSession(decoded.sessionId);
    
    // Check absolute session timeout
    if (Date.now() - session.createdAt > TOKEN_CONFIG.absoluteSessionExpiry) {
      await deleteSession(decoded.sessionId);
      throw new Error('Session expired');
    }
    
    // Update last activity
    await updateSessionActivity(decoded.sessionId);
    
    // Generate new access token
    const newAccessToken = jwt.sign(
      {
        userId: decoded.userId,
        sessionId: decoded.sessionId,
        type: 'access',
        iat: Math.floor(Date.now() / 1000)
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: TOKEN_CONFIG.accessTokenExpiry }
    );
    
    // Optional: Rotate refresh token
    const newRefreshToken = generateNewRefreshToken(decoded);
    
    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  } catch (error) {
    throw new Error('Invalid refresh token');
  }
}
```

## Authorization Examples

### Example 5: IDOR Prevention

**❌ Vulnerable: Missing Authorization Check**

```python
# UNSAFE - No ownership verification
@app.route('/api/orders/<order_id>', methods=['GET'])
@require_auth
def get_order(order_id):
    order = Order.query.get(order_id)
    
    if not order:
        return jsonify({'error': 'Not found'}), 404
    
    # BUG: Returns any order without checking ownership!
    return jsonify(order.to_dict())

# User can access ANY order by changing order_id
# /api/orders/123 → /api/orders/124
```

**✅ Secure: Proper Authorization Check**

```python
# SECURE - Verify resource ownership
@app.route('/api/orders/<order_id>', methods=['GET'])
@require_auth
def get_order(order_id):
    order = Order.query.get(order_id)
    
    if not order:
        return jsonify({'error': 'Not found'}), 404
    
    # CRITICAL: Verify ownership
    current_user = get_current_user()
    
    if order.user_id != current_user.id and current_user.role != 'admin':
        # Log potential IDOR attempt
        log_security_event(
            'IDOR_ATTEMPT',
            current_user.id,
            f'Attempted to access order {order_id} owned by user {order.user_id}'
        )
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify(order.to_dict())
```

**Better: Use UUIDs Instead of Sequential IDs**

```python
# BEST PRACTICE - Non-predictable identifiers
import uuid

class Order(db.Model):
    # Use UUID instead of auto-incrementing integer
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    # ... other fields

@app.route('/api/orders/<order_id>', methods=['GET'])
@require_auth
def get_order(order_id):
    # Still verify ownership!
    order = Order.query.get(order_id)
    
    if not order:
        return jsonify({'error': 'Not found'}), 404
    
    current_user = get_current_user()
    
    if order.user_id != current_user.id and current_user.role != 'admin':
        log_security_event('IDOR_ATTEMPT', current_user.id, order_id)
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify(order.to_dict())

# Now attacker can't enumerate: UUIDs are random
# But still must verify ownership - defense in depth!
```

### Example 6: Privilege Escalation Prevention

**❌ Vulnerable: Client-Side Role Check**

```javascript
// Mobile App - UNSAFE client-side authorization
class AdminPanel extends React.Component {
  render() {
    // Client-side check only!
    if (this.props.user.role === 'admin') {
      return (
        <View>
          <Button onPress={() => this.deleteUser(userId)}>
            Delete User
          </Button>
        </View>
      );
    }
    return <Text>Access Denied</Text>;
  }
  
  deleteUser(userId) {
    // Direct API call - no server-side check!
    fetch(`/api/admin/users/${userId}`, { method: 'DELETE' });
  }
}

// Attacker bypasses UI and calls API directly
// fetch('/api/admin/users/123', {method: 'DELETE'})
```

**✅ Secure: Server-Side Authorization**

```javascript
// Server - SECURE server-side authorization
app.delete('/api/admin/users/:userId', authenticateUser, (req, res) => {
  // CRITICAL: Check authorization on server
  if (req.user.role !== 'admin') {
    log_security_event('PRIVILEGE_ESCALATION_ATTEMPT', req.user.id);
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  // Additional safety: Prevent self-deletion
  if (req.params.userId === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete own account' });
  }
  
  User.delete(req.params.userId);
  res.json({ success: true });
});

// Mobile App - UI check is fine for UX, but security is on server
class AdminPanel extends React.Component {
  async deleteUser(userId) {
    try {
      const response = await fetch(`/api/admin/users/${userId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.status === 403) {
        // Server rejected - show error
        Alert.alert('Error', 'Insufficient privileges');
      }
    } catch (error) {
      console.error(error);
    }
  }
}
```

## Token Security Examples

### Example 7: JWT Validation

**❌ Vulnerable: Weak JWT Validation**

```javascript
// UNSAFE - Weak JWT validation
const jwt = require('jsonwebtoken');

function validateToken(token) {
  try {
    // Accepts ANY algorithm including "none"!
    const decoded = jwt.verify(token, SECRET_KEY);
    return decoded;
  } catch (error) {
    return null;
  }
}

// Attacker can:
// 1. Create JWT with "alg": "none"
// 2. Remove signature
// 3. Token accepted without verification
```

**✅ Secure: Proper JWT Validation**

```javascript
// SECURE - Strict JWT validation
const jwt = require('jsonwebtoken');

const JWT_OPTIONS = {
  algorithms: ['HS256'],  // Whitelist allowed algorithms
  issuer: 'your-app',
  audience: 'your-app-api',
  clockTolerance: 30  // 30 seconds clock skew tolerance
};

function validateToken(token) {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, JWT_OPTIONS);
    
    // Additional validation
    if (decoded.type !== 'access') {
      throw new Error('Invalid token type');
    }
    
    // Check if token is revoked (check Redis/DB)
    if (isTokenRevoked(decoded.jti)) {
      throw new Error('Token revoked');
    }
    
    return decoded;
  } catch (error) {
    // Log failed validation attempt
    logSecurityEvent('INVALID_TOKEN', error.message);
    return null;
  }
}
```

## Biometric Authentication Examples

### Example 8: Biometric Implementation

**❌ Vulnerable: Client-Side Only Biometric**

```kotlin
// Android - UNSAFE biometric auth
class LoginActivity : AppCompatActivity() {
    private fun authenticateWithBiometric() {
        val biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    // BUG: Directly log user in without server verification!
                    val token = generateLocalToken(userId)
                    saveToken(token)
                    navigateToHome()
                }
            })
        
        biometricPrompt.authenticate(promptInfo)
    }
}

// Attacker can hook this method and bypass biometric check
// No server knows that biometric was actually used
```

**✅ Secure: Server-Verified Biometric**

```kotlin
// Android - SECURE biometric auth with server verification
class LoginActivity : AppCompatActivity() {
    private fun authenticateWithBiometric() {
        val biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    // Request server to issue token for biometric auth
                    requestBiometricToken()
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        
        biometricPrompt.authenticate(promptInfo)
    }
    
    private fun requestBiometricToken() {
        // Server-side verification
        apiService.authenticateWithBiometric(
            userId = userId,
            deviceId = getDeviceId(),
            challenge = serverChallenge
        ).enqueue(object : Callback<TokenResponse> {
            override fun onResponse(call: Call<TokenResponse>, response: Response<TokenResponse>) {
                if (response.isSuccessful) {
                    val token = response.body()?.token
                    saveToken(token)
                    navigateToHome()
                } else {
                    showError("Authentication failed")
                }
            }
            
            override fun onFailure(call: Call<TokenResponse>, t: Throwable) {
                showError("Network error")
            }
        })
    }
}
```

**Server-Side:**

```python
# Server validates biometric authentication
@app.route('/api/auth/biometric', methods=['POST'])
def authenticate_biometric():
    data = request.json
    user_id = data.get('userId')
    device_id = data.get('deviceId')
    
    user = User.query.get(user_id)
    
    # Verify biometric is enabled for this user
    if not user.biometric_enabled:
        return jsonify({'error': 'Biometric not enabled'}), 403
    
    # Verify device is registered
    if not is_device_registered(user_id, device_id):
        return jsonify({'error': 'Device not recognized'}), 403
    
    # Check for root/jailbreak (if device sends attestation)
    if data.get('device_compromised'):
        log_security_event('COMPROMISED_DEVICE_AUTH_ATTEMPT', user_id)
        return jsonify({'error': 'Device security compromised'}), 403
    
    # Generate token
    token = generate_token(user_id, auth_method='biometric')
    
    log_security_event('BIOMETRIC_LOGIN_SUCCESS', user_id)
    
    return jsonify({'token': token})
```

## Real-World Case Studies

### Case Study 1: Banking App IDOR Vulnerability

**Scenario:**
Major mobile banking app allowed users to view any account details by changing account number parameter.

**Vulnerability:**
```python
# Vulnerable endpoint
@app.route('/api/accounts/<account_number>')
@require_auth
def get_account(account_number):
    account = Account.query.filter_by(number=account_number).first()
    return jsonify(account.to_dict())
    # Missing: ownership verification
```

**Exploitation:**
- User accesses their account: `/api/accounts/123456789`
- Changes number: `/api/accounts/123456790`
- Receives another customer's account details
- Attacker scripted enumeration of all accounts

**Impact:**
- 500,000+ customer records exposed
- PII including account balances, transaction history
- $4.5M regulatory fine
- Class action lawsuit
- Mandatory security audit

**Fix:**
```python
@app.route('/api/accounts/<account_number>')
@require_auth
def get_account(account_number):
    account = Account.query.filter_by(number=account_number).first()
    
    if not account:
        return jsonify({'error': 'Not found'}), 404
    
    # Verify ownership
    current_user = get_current_user()
    if account.user_id != current_user.id:
        log_security_event('IDOR_ATTEMPT', current_user.id, account_number)
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify(account.to_dict())
```

### Case Study 2: Session Hijacking via Token Theft

**Scenario:**
E-commerce mobile app stored authentication tokens in plain text in SharedPreferences.

**Vulnerability:**
```kotlin
// Vulnerable code
val prefs = getSharedPreferences("app_data", MODE_PRIVATE)
prefs.edit().putString("auth_token", token).apply()
```

**Exploitation:**
- Malware on rooted device accessed app's SharedPreferences
- Extracted authentication tokens
- Used tokens to make API requests
- Placed fraudulent orders
- Changed account details

**Impact:**
- $2M in fraudulent transactions
- 10,000+ accounts compromised
- Emergency forced logout of all users
- Mandatory password reset

**Fix:**
```kotlin
// Use EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedPrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

encryptedPrefs.edit().putString("auth_token", token).apply()
```

### Case Study 3: Biometric Bypass

**Scenario:**
Fintech app implemented biometric authentication with client-side only verification.

**Vulnerability:**
```kotlin
// Client decides authentication success
override fun onAuthenticationSucceeded(result: AuthenticationResult) {
    loginUser()  // No server verification
}
```

**Exploitation:**
- Attacker used Frida to hook `onAuthenticationSucceeded`
- Forced method to always execute successfully
- Bypassed biometric check completely
- Accessed accounts without valid biometric

**Impact:**
- Multiple accounts accessed by unauthorized persons
- $500K in fraudulent transactions
- Regulatory investigation
- Temporary app suspension

**Fix:**
- Server-side verification required
- Device attestation implemented
- Root/jailbreak detection
- Re-authentication for sensitive operations

## Quick Reference

### Authentication Checklist
| Requirement | Vulnerable | Secure |
|------------|-----------|--------|
| Password Length | 6 chars | 12+ chars |
| Complexity | None | Upper, lower, number, special |
| Rate Limiting | None | 5 attempts / 15 min |
| Account Lockout | None | Lock after 5 failures |
| Transmission | HTTP | HTTPS + cert pinning |
| MFA | Optional/None | Enforced |

### Session Management Checklist
| Requirement | Vulnerable | Secure |
|------------|-----------|--------|
| Token Expiry | Never | 15 min (access), 7 days (refresh) |
| Token Storage | Plain text | Encrypted (Keychain/Keystore) |
| Logout | Client only | Client + server invalidation |
| Token Type | Simple string | Cryptographically secure JWT |
| Session Binding | None | Device + IP (flexible) |

### Authorization Checklist
| Requirement | Vulnerable | Secure |
|------------|-----------|--------|
| Enforcement | Client-side | Server-side |
| Resource IDs | Sequential (1,2,3) | UUIDs |
| Ownership Check | Missing | Every request |
| Privilege Check | UI only | API endpoint |
| Admin Functions | Direct access | Role verification |

### Common Vulnerabilities Summary

| Vulnerability | Attack | Impact | Prevention |
|--------------|--------|--------|------------|
| Weak Passwords | Brute force | Account takeover | Strong policy + rate limiting |
| No MFA | Credential stuffing | Mass compromise | Enforce MFA |
| Plain Text Tokens | Malware theft | Session hijacking | Encrypted storage |
| Client-Side Auth | API bypass | Unauthorized access | Server-side enforcement |
| IDOR | Parameter manipulation | Data breach | Ownership verification |
| Long Sessions | Token theft | Persistent access | Short expiration + refresh |
| Predictable IDs | Enumeration | Mass data exposure | UUIDs + authorization |

## Key Takeaways

1. **Never trust the client** - All security decisions must be server-side
2. **Defense in depth** - Multiple layers of security (passwords + MFA + rate limiting)
3. **Secure storage** - Use platform security features (Keychain, Keystore)
4. **Verify everything** - Check authentication AND authorization on every request
5. **Monitor and log** - Detect and respond to suspicious activity
6. **Short-lived tokens** - Minimize impact of token theft
7. **Test thoroughly** - Security testing must include authorization boundary testing

## Next Steps

- **[Attack Vectors](./attack-vectors.md)**: Review how these vulnerabilities are exploited
- **[Prevention](./prevention.md)**: Detailed secure implementation guidance
- **[Interactive Lab](./lab/)**: Practice exploiting and fixing these issues

---

**Remember**: The difference between a vulnerable and secure implementation is often just a few lines of code. Security must be intentional and consistent throughout your application.
