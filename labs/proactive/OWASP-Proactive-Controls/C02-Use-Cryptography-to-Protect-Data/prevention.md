# C2: Use Cryptography to Protect Data - How to Implement

## Implementation Strategy Overview

Implementing this control is not about scattering encryption calls through the codebase. It is about making **correct cryptography the default** for every piece of sensitive data, in every state, with keys that are managed like the crown jewels they are. The strategy has six moves:

1. Classify data so you know exactly what must be protected.
2. Encrypt everything in transit with modern TLS.
3. Encrypt sensitive data at rest with authenticated encryption.
4. Hash passwords with a slow, salted function — never encrypt or fast-hash them.
5. Use a CSPRNG for all keys, salts, nonces, and tokens.
6. Manage keys in a KMS/HSM — generate, store, separate, rotate, and revoke.

### Core Principles

- **Don't roll your own crypto**: use vetted libraries (libsodium/PyNaCl, the platform's crypto, Google Tink). The safe path must be the default path.
- **Authenticated encryption always**: confidentiality without integrity is a half-measure; prefer AEAD (AES-256-GCM, ChaCha20-Poly1305).
- **Least data, least exposure**: don't store or transmit sensitive data you don't need; keep it out of logs, URLs, and caches.
- **Crypto-agility**: design so an algorithm or key can be swapped without re-architecting, because today's strong choice will age.

## 1. Classify Data and Define a Crypto Policy

Protection starts with knowing what to protect. Inventory the data, assign a sensitivity tier, and let the tier drive the cryptographic requirement.

```yaml
# data-classification.yaml — reviewed, versioned, enforced in review
fields:
  password:        { tier: restricted, at_rest: hash-argon2id, in_transit: tls }
  card_number:     { tier: restricted, at_rest: aes-256-gcm,   in_transit: tls, log: never }
  ssn:             { tier: restricted, at_rest: aes-256-gcm,   in_transit: tls, log: never }
  email:           { tier: confidential, at_rest: aes-256-gcm, in_transit: tls, log: masked }
  display_name:    { tier: internal,    at_rest: none,         in_transit: tls }

policy:
  restricted_and_confidential:
    - MUST be encrypted in transit (TLS 1.2+) and at rest
    - MUST NOT appear in logs, URLs, query strings, or analytics
    - MUST use keys from the KMS, never a hardcoded value
```

## 2. Encryption in Transit (TLS)

Every network hop that carries sensitive data — browser to server *and* service to service — must use modern TLS with no downgrade path.

```nginx
# nginx: TLS 1.2/1.3 only, strong ciphers, HSTS, HTTP->HTTPS redirect
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers off;         # let clients pick among strong suites
ssl_session_tickets off;

add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

server { listen 80; return 301 https://$host$request_uri; }   # no plaintext
```

- Enable **HSTS** (and submit to the preload list) so browsers refuse to connect over HTTP.
- Disable TLS 1.0/1.1, RC4, 3DES, and export ciphers; verify with a scanner (e.g. `testssl.sh`).
- Automate certificate issuance and renewal (ACME/Let's Encrypt) so certs never silently expire.
- For internal service-to-service traffic, prefer **mutual TLS (mTLS)**.

## 3. Encryption at Rest (Authenticated Encryption)

Encrypt sensitive data before it is stored, using an AEAD cipher so the ciphertext is both confidential and tamper-evident. Let a library handle nonces and tags.

```python
# Python — cryptography library, AES-256-GCM via a random 96-bit nonce
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)                       # CSPRNG, unique per message
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct                            # store nonce alongside ciphertext

def decrypt(blob: bytes, key: bytes, aad: bytes = b"") -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)   # raises if tampered — fail closed
```

- Use **AES-256-GCM** or **ChaCha20-Poly1305**; never ECB, and never CBC without a separate MAC.
- Generate a **fresh nonce per encryption** and never reuse a (key, nonce) pair.
- Enable **transparent disk/volume and database encryption** as defence in depth, and **encrypt all backups** — backups leak as often as live data.
- Bind context with **associated data (AAD)** (e.g. a record id) so ciphertext can't be moved between records.

## 4. Password Storage (Slow, Salted Hashing)

Passwords must be irreversible. Use a memory-hard, deliberately slow password hashing function with a unique per-user salt (the library generates and stores the salt inside the hash string).

```python
# Python — Argon2id (preferred). The salt is generated and embedded automatically.
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=64*1024, parallelism=1)

hashed = ph.hash(user_password)      # store this string; contains algo, params, salt
# ...at login:
try:
    ph.verify(hashed, submitted_password)
    if ph.check_needs_rehash(hashed):        # transparently upgrade work factor
        hashed = ph.hash(submitted_password)
except Exception:
    reject_login()                            # constant-time verify inside the library
```

| Choose | Guidance |
|--------|----------|
| Argon2id | Preferred; tune memory/time to your hardware (e.g. 64 MiB, t=3) |
| scrypt | Good memory-hard alternative |
| bcrypt | Widely supported; cost factor ≥ 10–12; pre-hash if input > 72 bytes |
| PBKDF2-HMAC-SHA256 | When a FIPS-validated option is required; high iteration count |

> **Never** store passwords with MD5, SHA-1, or a single pass of SHA-256, and never store them reversibly (encrypted or plaintext). Add a peppered secret from the KMS only *in addition to* — never instead of — a proper password hash.

## 5. Secure Randomness (CSPRNG)

Every key, salt, IV/nonce, session id, API key, and reset token must come from a cryptographically secure generator.

```
# Python
import secrets
session_id   = secrets.token_urlsafe(32)     # ~256 bits, URL-safe
reset_token  = secrets.token_hex(32)
api_key      = secrets.token_bytes(32)

# Node.js
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('base64url');

# Java
byte[] buf = new byte[32];
java.security.SecureRandom.getInstanceStrong().nextBytes(buf);
```

**Never** use `Math.random()`, `java.util.Random`, `rand()`/`mt_rand()`, or any time-seeded PRNG for a security value. Compare secret tokens with a **constant-time** comparison (`secrets.compare_digest`, `crypto.timingSafeEqual`, `MessageDigest.isEqual`) to avoid timing leaks.

## 6. Key Management

Encryption only moves the secret from "all the data" to "the key," so the key must be handled with far more care than the data. This is where most cryptography programmes succeed or fail.

```
Key management checklist:
  [ ] Keys generated with a CSPRNG (or inside the KMS/HSM)
  [ ] Keys stored in a KMS / HSM / secrets manager — NEVER in source or config
  [ ] Data-encryption keys wrapped by a key-encryption key (envelope encryption)
  [ ] Keys separated from the data they protect (different trust boundary)
  [ ] Least-privilege access; every key use is audited
  [ ] Scheduled rotation + a tested procedure for emergency rotation/revocation
  [ ] No key ever written to logs, error messages, or backups in plaintext
```

```python
# Envelope encryption with a cloud KMS (pattern, AWS shown)
# 1) Ask the KMS for a new data key: you get plaintext + KMS-wrapped versions
resp = kms.generate_data_key(KeyId=CMK_ID, KeySpec="AES_256")
plaintext_key, wrapped_key = resp["Plaintext"], resp["CiphertextBlob"]

ciphertext = aes_gcm_encrypt(plaintext_key, data)   # encrypt data locally
del plaintext_key                                   # zeroise ASAP — don't persist it
store(record, ciphertext=ciphertext, wrapped_key=wrapped_key)
# To read later: KMS.decrypt(wrapped_key) -> plaintext_key -> decrypt data
```

Store only the *wrapped* data key next to the ciphertext; the key that unwraps it lives in the KMS/HSM and never leaves it. Rotate the key-encryption key on a schedule; rotating it re-wraps data keys without re-encrypting all data.

## 7. Use Vetted Libraries and High-Level APIs

Prefer misuse-resistant, high-level interfaces that make the wrong thing hard to do:

- **libsodium / PyNaCl** — `crypto_secretbox` / `crypto_box` pick the algorithm, mode, and nonce handling for you.
- **Google Tink** — opinionated AEAD/keyset APIs with built-in key rotation.
- **Your platform's crypto** — Python `cryptography`, Java JCA/JCE, .NET `System.Security.Cryptography`, Go `crypto/*`.

Avoid low-level primitives and custom modes. If you find yourself choosing an IV by hand or concatenating a MAC manually, step up to a higher-level API instead.

## 8. Crypto-Agility and Lifecycle

Every algorithm is temporary. Build so you can upgrade without a rewrite:

- **Version your ciphertext and hashes** — prefix a scheme identifier (e.g. `v2:`) so old and new formats coexist during migration.
- **Rehash on login** — transparently upgrade password work factors and algorithms when a user next authenticates.
- **Abstract the crypto** behind an interface so swapping AES-GCM for a successor touches one module.
- Track deprecations and plan for post-quantum migration of long-lived data.

```python
# Versioned scheme lets you migrate without downtime
def decrypt(blob):
    scheme, payload = blob.split(b":", 1)
    if scheme == b"v2": return aes_gcm_decrypt(payload)      # current
    if scheme == b"v1": return legacy_decrypt(payload)       # read-only, being retired
    raise ValueError("unknown crypto scheme")
```

## 9. Keep Sensitive Data Out of Logs, URLs, and Caches

Correct encryption is undone if a plaintext copy escapes. Close the side channels:

- Never put secrets or PII in **URLs / query strings** (they land in logs, history, and `Referer`); use POST bodies or headers.
- **Mask or drop** sensitive fields before logging; scrub tokens and passwords from stack traces.
- Set `Cache-Control: no-store` on responses with sensitive data.
- **Zeroise** key and plaintext buffers after use where the language allows it.

## 10. Verification and Monitoring

Prove the control is working, and keep proving it:

```
# In CI / on a schedule
gitleaks detect --source . --redact          # block hardcoded keys/secrets
testssl.sh https://staging.example.com       # verify TLS versions, ciphers, HSTS
semgrep --config p/crypto                     # flag MD5/DES/ECB/Math.random usage
pip-audit ; npm audit                         # crypto library CVEs
```

Alert on: use of deprecated algorithms reintroduced in a diff, TLS configuration drift, secrets pushed to a repo, and KMS access anomalies. Add a periodic review that re-checks algorithm choices and key-rotation status against current guidance.

## Implementation Checklist

- [ ] Sensitive data is classified, and the policy drives encryption decisions.
- [ ] All traffic uses TLS 1.2+/1.3 with HSTS; weak protocols/ciphers disabled.
- [ ] Sensitive data at rest uses AES-256-GCM (or ChaCha20-Poly1305); backups encrypted.
- [ ] Passwords use Argon2id/bcrypt/scrypt/PBKDF2 with per-user salt — never fast/plain hashes.
- [ ] All keys, salts, nonces, and tokens come from a CSPRNG.
- [ ] Nonces/IVs are unique per encryption; no (key, nonce) reuse.
- [ ] Keys live in a KMS/HSM, separated from data, rotated, never hardcoded.
- [ ] Only vetted libraries are used; no home-grown crypto.
- [ ] Ciphertext/hashes are versioned for crypto-agility.
- [ ] Secrets never appear in logs, URLs, or caches; CI blocks committed secrets.

## Key Takeaways

1. **Classify, then protect** — cryptography follows a data-sensitivity policy, not guesswork.
2. **Cover every state** — TLS in transit, AEAD at rest, and minimise exposure in use.
3. **Passwords are hashed, secrets are random** — slow salted hashing plus a CSPRNG everywhere.
4. **Key management is the control** — KMS/HSM, separation, rotation, and no hardcoded keys.
5. **Use libraries and stay agile** — vetted APIs today, a clean upgrade path for tomorrow.

## Next Steps

- **[Examples](examples.md)**: Insecure vs. secure crypto code in Python, Node, and Java
- **[Threats Addressed](attack-vectors.md)**: Understand what you are defending against
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
