# C2: Use Cryptography to Protect Data - Threats Addressed

## Table of Contents
- [Understanding the Threats This Control Addresses](#understanding)
- [The Threats, One by One](#threats)
- [How These Failures Chain](#chaining)

## Understanding the Threats This Control Addresses

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the failures and techniques below are shown so you can recognise and eliminate them in systems you own or are authorised to test.

This control exists to neutralise a specific family of threats: everything that becomes possible when sensitive data is left readable, forgeable, or tamperable. Unlike an injection bug, these threats usually require no clever payload — the attacker simply obtains the data (through a leak, a network position, or a stolen backup) and reads it, because nothing meaningful stood in the way.

The threats fall into four themes, and every item below is one of them:

- **Data exposure** — sensitive data readable because it was never protected.
- **Weak or obsolete algorithms** — protection that exists on paper but is broken in practice.
- **Plaintext storage and transit** — no cryptography applied where it was needed.
- **Key leakage and mismanagement** — the secret that everything depends on is exposed.

### Core Failure Flow

```
1. Reach the data
   ↓
   Network position, leaked backup, stolen disk, exposed bucket, repo access
2. Find it unprotected
   ↓
   Plaintext, weak hash, broken cipher, or a key sitting right next to it
3. Read or forge
   ↓
   Decrypt / crack / tamper — confidentiality and integrity both fall
4. Exploit at scale
   ↓
   Credential stuffing, fraud, impersonation, silent data modification
```

## The Threats, One by One

### 1. Sensitive Data Exposure Through Plaintext Storage

The most direct failure: sensitive fields are stored with no encryption at all, so any read of the database, a backup, or a log reveals them.

```sql
-- Plaintext at rest: one leaked dump exposes everything
SELECT email, ssn, card_number FROM customers LIMIT 1;

 email             | ssn         | card_number
-------------------+-------------+------------------
 alice@example.com | 123-45-6789 | 4111111111111111   <- fully readable
```

**What goes wrong**: A stolen backup, a misconfigured cloud bucket, a SQL-injection dump, or an over-broad log statement turns into instant, total exposure. There is no work for the attacker to do — the data is already in the clear.

**Addressed by**: Encrypting sensitive columns/fields with AES-256-GCM and keeping the keys in a KMS, plus keeping this data out of logs.

### 2. Cleartext or Downgradable Transmission

Data sent over plain HTTP, or over TLS that silently falls back to obsolete versions, can be read or altered by anyone on the path.

```
POST http://api.example.com/login          # plain HTTP — no encryption at all
Content-Type: application/x-www-form-urlencoded

username=alice&password=Sup3rSecret!       # visible to any on-path attacker

# Or: HTTPS present but downgradable
ClientHello: supports TLS 1.0, RC4, 3DES   # attacker forces a weak, breakable session
```

**What goes wrong**: On hostile Wi-Fi or a compromised router, an attacker running an SSL-strip or downgrade attack captures credentials, session cookies, and personal data mid-flight, or modifies responses.

**Addressed by**: TLS 1.2+/1.3 only, HSTS (ideally preloaded), disabling weak protocols and ciphers, and redirecting all HTTP to HTTPS.

### 3. Weak or Broken Algorithms

Cryptography that *looks* present but relies on primitives known to be broken provides false assurance.

```
Broken / forbidden for security use:
  MD5, SHA-1        -> collisions; forge signatures, crack hashes
  DES, 3DES, RC4    -> small keys / biases; recoverable plaintext
  AES-ECB mode      -> leaks plaintext patterns block-by-block
  RSA-512/1024      -> factorable / too small

# MD5 collisions are practical — two inputs, one digest:
md5(file_A) == md5(file_B)   # attacker swaps A for B undetected
```

**What goes wrong**: MD5/SHA-1 collisions let attackers forge signatures and certificates; RC4/DES weaknesses let them recover plaintext; ECB reveals structure in "encrypted" data. The system passes a checkbox audit ("we encrypt") while offering little real protection.

**Addressed by**: Using current, standard primitives (SHA-256/384, AES-GCM, RSA-3072+/ECC) and maintaining crypto-agility so broken algorithms can be retired quickly.

### 4. Fast or Unsalted Password Hashing

Storing passwords with a fast general-purpose hash — or with no salt — means a stolen database is cracked in bulk.

```
# Unsalted, fast hash: identical passwords collide and rainbow tables apply
sha256("password123") = ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
# ...appears identically for every user who chose "password123"

# GPU throughput against a fast hash:
SHA-256  ~ billions of guesses / second
bcrypt   ~ tens of thousands / second   (deliberately, ~1e5x slower)
```

**What goes wrong**: With a fast unsalted hash, precomputed rainbow tables and GPU cracking recover most passwords within hours. Because users reuse passwords, those credentials are then stuffed into other sites for account takeover.

**Addressed by**: Per-user random salt and a slow, memory-hard function — Argon2id, bcrypt, scrypt, or PBKDF2 with a high work factor.

### 5. Missing Integrity / Unauthenticated Encryption

Encrypting for confidentiality but not authenticating the ciphertext lets an attacker modify it without detection.

```
# AES-CBC without a MAC/auth tag is malleable:
# flipping a byte of ciphertext flips the matching plaintext byte
ciphertext[8] ^= 0x01     # e.g. change "role=user" toward "role=adm~"

# Padding-oracle: the server's different responses to valid vs invalid
# padding let an attacker decrypt or forge ciphertext byte-by-byte.
```

**What goes wrong**: Tokens, cookies, and messages can be tampered with (bit-flipping) or decrypted via padding oracles, breaking integrity even though the data was "encrypted."

**Addressed by**: Authenticated encryption (AES-256-GCM, ChaCha20-Poly1305), which rejects any modified ciphertext before decrypting it.

### 6. Predictable Randomness

Security values generated from a non-cryptographic RNG are guessable, so tokens and keys can be predicted.

```javascript
// Predictable: seeded by time, small state, reproducible
let token = Math.random().toString(36).slice(2);   // NOT secret
// java.util.Random(seed), rand()/mt_rand(), time()-based seeds — all predictable

// An attacker who learns/guesses the seed reproduces every
// "random" session id, reset token, or API key you issue.
```

**What goes wrong**: Predictable session identifiers allow session hijacking; guessable password-reset tokens allow account takeover; weak key generation undermines all downstream encryption.

**Addressed by**: A CSPRNG for every key, salt, IV/nonce, and token (`secrets`, `crypto.randomBytes`, `SecureRandom`, `crypto/rand`).

### 7. Nonce / IV Reuse

Even a strong cipher fails catastrophically when the same nonce is reused under the same key.

```python
# AES-GCM with a repeated (key, nonce) pair:
#  - leaks the XOR of the two plaintexts (confidentiality loss)
#  - allows forgery of the authentication tag (integrity loss)
nonce = b"\x00" * 12       # FIXED nonce reused for every message  <- catastrophic
ct1 = gcm_encrypt(key, nonce, msg1)
ct2 = gcm_encrypt(key, nonce, msg2)   # msg1 XOR msg2 now recoverable
```

**What goes wrong**: A hardcoded or counter-restarting nonce silently destroys the guarantees of GCM/CTR modes, exposing plaintext relationships and enabling tag forgery.

**Addressed by**: A fresh, unique nonce per encryption (random 96-bit for GCM, or a safe deterministic counter that never repeats under a key), handled by a vetted library.

### 8. Key Leakage and Mismanagement

The key is the one secret every other control depends on. Expose it and the encryption is meaningless.

```
# Hardcoded key committed to source control:
SECRET_KEY = "aes256-prod-key-do-not-share-9f3c..."   # now in git history forever

# Or a key stored right next to the data it protects:
/app/config/app.key      # readable by the same process that reads the DB dump

# Public-repo secret scanners find pushed keys within minutes.
```

**What goes wrong**: Anyone with repository access, image access, or the leaked config can decrypt everything, forge tokens, or impersonate the service. Keys that are never rotated mean a single past leak stays exploitable indefinitely.

**Addressed by**: Storing keys in a KMS/HSM, injecting them at runtime, separating them from the ciphertext, enforcing least-privilege access, and rotating them on a schedule.

### 9. Rolling Your Own Crypto

Custom ciphers, custom modes, or "clever" home-grown schemes almost always hide fatal flaws.

```python
# XOR "encryption" with a repeating key — trivially broken by frequency analysis
def encrypt(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
# No authentication, key reuse, and recoverable with known-plaintext.
```

**What goes wrong**: Amateur schemes get IVs, padding, authentication, and key handling wrong in ways that are obvious to cryptanalysts and invisible to the author. Obscurity provides no protection.

**Addressed by**: Using vetted, high-level libraries (libsodium, the platform's crypto, Google Tink) that make the safe choice the default.

### 10. Sensitive Data in Logs, URLs, and Caches

Data can be perfectly encrypted in the database and still leak because a copy escaped in plaintext.

```
GET /reset?token=9f3c...&email=alice@example.com   # secrets in the URL (logs, history, Referer)
LOG  2026-08-29  user login  password=Sup3rSecret!  # secret written to app log
Cache-Control: public                              # sensitive response cached by proxies
```

**What goes wrong**: Secrets in query strings land in server logs, browser history, and `Referer` headers; verbose logging records credentials; permissive caching stores private data on shared infrastructure.

**Addressed by**: Keeping secrets out of URLs and logs, scrubbing sensitive fields, and setting `Cache-Control: no-store` on sensitive responses.

## How These Failures Chain

Individually serious, these failures compound into complete compromise:

```
Plaintext HTTP intercepts a session cookie
        +
Weak/unsalted password hash cracked from a leaked dump
        +
Reused password stuffed into the victim's other accounts
        =  full account takeover across services, no application exploit needed
```

Another common chain:

```
Hardcoded key found in a public repo
        -> decrypts an "encrypted" data backup
        -> backup used unauthenticated CBC, so records are also tamperable
        -> attacker exfiltrates and silently modifies data undetected
```

## Key Takeaways

1. **Most crypto threats need no exploit** — unprotected data is simply read once reached.
2. **"Encrypted" is not "protected"** — broken algorithms, ECB mode, and unauthenticated ciphers give false assurance.
3. **Passwords and randomness are prime targets** — fast hashes and predictable RNGs enable bulk cracking and forgery.
4. **The key is the crown jewel** — a leaked or mismanaged key nullifies every other control.
5. **Data leaks sideways** — logs, URLs, and caches expose data the database encrypted correctly.

## Next Steps

- **[How to Implement](prevention.md)**: Apply cryptography correctly across every state of data
- **[Examples](examples.md)**: Insecure vs. secure crypto code in Python, Node, and Java
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
