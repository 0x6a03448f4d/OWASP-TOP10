# C2: Use Cryptography to Protect Data - Code Examples

Each pair below shows an **insecure** use of cryptography and the **secure** version in the same language. The examples focus on the mistakes that dominate real findings: reversible or fast password hashing, broken algorithms and modes, predictable randomness, and hardcoded keys.

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the insecure snippets exist to be recognised and removed, never shipped.

## Python

### Password Storage

#### Insecure
```python
import hashlib

def store_password(pw: str) -> str:
    # MD5, no salt: cracked in seconds; identical passwords collide
    return hashlib.md5(pw.encode()).hexdigest()

def verify(pw: str, stored: str) -> bool:
    return hashlib.md5(pw.encode()).hexdigest() == stored   # also timing-unsafe
```

#### Secure
```python
from argon2 import PasswordHasher          # pip install argon2-cffi
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=1)

def store_password(pw: str) -> str:
    # Argon2id: slow + memory-hard; salt generated and embedded automatically
    return ph.hash(pw)

def verify(pw: str, stored: str) -> bool:
    try:
        ph.verify(stored, pw)             # constant-time verify inside the library
        return True
    except VerifyMismatchError:
        return False
```

### Encrypting Data at Rest

#### Insecure
```python
from Crypto.Cipher import AES             # ECB + hardcoded key: two mistakes at once

KEY = b"1234567890123456"                 # hardcoded, committed to the repo

def encrypt(data: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_ECB)   # ECB leaks plaintext patterns; no integrity
    pad = 16 - len(data) % 16
    return cipher.encrypt(data + bytes([pad]) * pad)
```

#### Secure
```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(data: bytes, key: bytes, aad: bytes = b"") -> bytes:
    # key comes from the KMS at runtime — never hardcoded
    nonce = os.urandom(12)                        # CSPRNG; unique per message
    return nonce + AESGCM(key).encrypt(nonce, data, aad)   # AES-256-GCM: confidential + authenticated

def decrypt(blob: bytes, key: bytes, aad: bytes = b"") -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)    # raises on tamper — fail closed
```

### Generating Tokens

#### Insecure
```python
import random, time

def reset_token() -> str:
    random.seed(int(time.time()))                 # predictable seed
    return "".join(random.choice("0123456789abcdef") for _ in range(32))  # guessable
```

#### Secure
```python
import secrets

def reset_token() -> str:
    return secrets.token_urlsafe(32)              # CSPRNG, ~256 bits of entropy

# Compare tokens in constant time to avoid timing leaks:
import hmac
def token_matches(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
```

## Node.js

### Password Storage

#### Insecure
```javascript
const crypto = require('crypto');

function storePassword(pw) {
  // SHA-1, unsalted: fast hash, billions of guesses/sec on a GPU
  return crypto.createHash('sha1').update(pw).digest('hex');
}
```

#### Secure
```javascript
const argon2 = require('argon2');            // npm i argon2

async function storePassword(pw) {
  // Argon2id with sensible memory/time cost; salt handled internally
  return argon2.hash(pw, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3 });
}

async function verify(hash, pw) {
  return argon2.verify(hash, pw);            // constant-time, returns boolean
}
```

### Encrypting Data at Rest

#### Insecure
```javascript
const crypto = require('crypto');

const KEY = 'hardcoded-app-secret-key-123';   // hardcoded secret in source

function encrypt(text) {
  // createCipher (deprecated): weak key derivation, no IV control, no auth tag
  const cipher = crypto.createCipher('aes-256-cbc', KEY);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}
```

#### Secure
```javascript
const crypto = require('crypto');

// key: 32 random bytes fetched from the KMS at runtime (Buffer), never hardcoded
function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(12);                       // unique nonce per message
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();                         // integrity tag
  return Buffer.concat([iv, tag, ct]);                     // store all three
}

function decrypt(blob, key) {
  const iv = blob.subarray(0, 12), tag = blob.subarray(12, 28), ct = blob.subarray(28);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');  // throws on tamper
}
```

### Generating Tokens

#### Insecure
```javascript
function apiKey() {
  // Math.random is NOT a CSPRNG — predictable, low entropy
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}
```

#### Secure
```javascript
const crypto = require('crypto');

function apiKey() {
  return crypto.randomBytes(32).toString('base64url');     // 256-bit CSPRNG token
}

// Constant-time comparison for secrets:
function safeEqual(a, b) {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
```

## Java

### Password Storage

#### Insecure
```java
import java.security.MessageDigest;

String storePassword(String pw) throws Exception {
    // MD5, unsalted, hex — trivially cracked
    byte[] d = MessageDigest.getInstance("MD5").digest(pw.getBytes("UTF-8"));
    StringBuilder sb = new StringBuilder();
    for (byte b : d) sb.append(String.format("%02x", b));
    return sb.toString();
}
```

#### Secure
```java
// Spring Security Crypto — Argon2 (or BCryptPasswordEncoder)
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

Argon2PasswordEncoder enc = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

String storePassword(String pw) {
    return enc.encode(pw);              // slow, salted, self-describing hash string
}

boolean verify(String pw, String stored) {
    return enc.matches(pw, stored);     // constant-time verification
}
```

### Encrypting Data at Rest

#### Insecure
```java
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

// Hardcoded key + ECB mode + DES: three broken choices
byte[] KEY = "8bytekey".getBytes();

byte[] encrypt(byte[] data) throws Exception {
    SecretKeySpec k = new SecretKeySpec(KEY, "DES");
    Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");   // DES + ECB: broken
    c.init(Cipher.ENCRYPT_MODE, k);
    return c.doFinal(data);
}
```

#### Secure
```java
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

// key: 32 bytes retrieved from a KMS/keystore at runtime, never hardcoded
byte[] encrypt(byte[] data, byte[] key) throws Exception {
    byte[] iv = new byte[12];
    SecureRandom.getInstanceStrong().nextBytes(iv);         // CSPRNG nonce, unique per message
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");     // AES-256-GCM: AEAD
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
           new GCMParameterSpec(128, iv));                  // 128-bit auth tag
    byte[] ct = c.doFinal(data);
    byte[] out = new byte[iv.length + ct.length];
    System.arraycopy(iv, 0, out, 0, iv.length);
    System.arraycopy(ct, 0, out, iv.length, ct.length);     // store iv || ciphertext+tag
    return out;
}
```

### Generating Tokens

#### Insecure
```java
import java.util.Random;

String sessionId() {
    // java.util.Random is a linear PRNG — predictable, not for security
    return Long.toHexString(new Random().nextLong());
}
```

#### Secure
```java
import java.security.SecureRandom;
import java.util.Base64;

String sessionId() throws Exception {
    byte[] buf = new byte[32];
    SecureRandom.getInstanceStrong().nextBytes(buf);        // CSPRNG, 256-bit token
    return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
}

// Constant-time comparison:
boolean safeEquals(byte[] a, byte[] b) {
    return java.security.MessageDigest.isEqual(a, b);
}
```

## What Changed, and Why

| Concern | Insecure | Secure |
|---------|----------|--------|
| Passwords | MD5/SHA-1, unsalted, fast, timing-unsafe | Argon2id/bcrypt, salted, slow, constant-time verify |
| Encryption mode | ECB / unauthenticated CBC / DES | AES-256-GCM (AEAD): confidential + tamper-evident |
| Nonce / IV | Fixed, absent, or library-derived | Fresh CSPRNG nonce per message, stored with ciphertext |
| Randomness | `Math.random()`, `java.util.Random`, time-seeded | CSPRNG (`secrets`, `randomBytes`, `SecureRandom`) |
| Keys | Hardcoded in source / committed | Fetched from KMS/keystore at runtime, rotated |
| Comparisons | `==` / `equals` (timing leak) | Constant-time compare |

## Key Takeaways

1. **Hash passwords, don't fast-hash or encrypt them** — Argon2id/bcrypt with per-user salt.
2. **Use authenticated encryption** — AES-256-GCM, never ECB or bare CBC, never DES/RC4.
3. **Never reuse a nonce, never hardcode a key** — CSPRNG nonces and KMS-managed keys.
4. **All security randomness comes from a CSPRNG** — not `Math.random()` or `java.util.Random`.
5. **Let vetted libraries make the safe choice** — and compare secrets in constant time.

## Next Steps

- **[How to Implement](prevention.md)**: The full layered implementation strategy
- **[Threats Addressed](attack-vectors.md)**: How these mistakes are exploited
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
