# C2: Use Cryptography to Protect Data - Overview

## Table of Contents
- [What is this control?](#what-is-this-control)
- [Why Does This Matter?](#why-does-this-matter)
- [The Three States of Data](#the-three-states-of-data)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Common Misunderstandings](#common-misunderstandings)

## What is this control?

**Use Cryptography to Protect Data** is the proactive control that says: wherever sensitive data lives or travels, apply *correct, current, well-implemented cryptography* so that even if an attacker reaches the bytes, they cannot read, forge, or tamper with them. It is the defensive discipline whose absence OWASP catalogues as **A02:2021 – Cryptographic Failures**. This control is the cure; that Top 10 category is the disease.

Cryptography here is not one feature you switch on. It is a set of decisions made deliberately across the whole system:

- **Encryption in transit** — TLS 1.2+/1.3 so data on the wire cannot be read or altered.
- **Encryption at rest** — authenticated encryption (for example AES-256-GCM) so stored data is unreadable without the key.
- **Password protection** — slow, salted password hashing (Argon2id, bcrypt, scrypt, PBKDF2), never plain SHA/MD5.
- **Strong, current algorithms** — and the retirement of broken ones (MD5, SHA-1 for security, DES, RC4, ECB mode).
- **Secure randomness** — a CSPRNG for every key, token, salt, and nonce, never `Math.random()`.
- **Key management** — keys generated, stored, rotated, and separated properly (KMS/HSM), never hardcoded.
- **Vetted libraries** — use libsodium, your platform's crypto, or Tink; do not roll your own primitives.

The core idea is that cryptography moves the security boundary. Without it, protecting data depends on nobody ever reaching the disk, the backup, the log, the network tap, or the stolen laptop. With it, the data's confidentiality and integrity depend on *the secrecy of a key* — a much smaller, much more defensible thing to protect.

### Core Concept

```
Without this control:
  In transit   -> plaintext HTTP, or TLS with weak/downgradable ciphers
  At rest      -> plaintext columns, unencrypted backups and disks
  Passwords    -> stored as MD5/SHA-1, unsalted, or (worst) plaintext
  Algorithms   -> DES, RC4, ECB mode, MD5 signatures still in use
  Randomness   -> tokens/keys from Math.random() or time-seeded PRNGs
  Keys         -> hardcoded in source, committed to git, shared everywhere

With this control:
  In transit   -> TLS 1.2+/1.3, HSTS, no downgrade, modern cipher suites
  At rest      -> AES-256-GCM authenticated encryption, encrypted backups
  Passwords    -> Argon2id / bcrypt / scrypt / PBKDF2, per-user salt
  Algorithms   -> current, standard primitives; broken ones removed
  Randomness   -> CSPRNG (secrets, crypto.randomBytes, SecureRandom)
  Keys         -> generated in and served by a KMS/HSM, rotated, separated
```

### What This Control Is Not

Cryptography protects *data*; it is not a substitute for the controls around it:

- It does **not** replace access control (C1). Encrypted data returned to the wrong user is still a breach.
- It does **not** replace input validation. A well-encrypted field can still carry an injection payload.
- Encryption is **not** hashing, and hashing is **not** encryption. Encryption is reversible with a key; a password hash is a deliberately slow, one-way function. Using the wrong one is a classic failure.
- Encoding (Base64, hex, URL-encoding) is **not** encryption. It provides zero confidentiality.

## Why Does This Matter?

Cryptographic failures are consistently among the most damaging classes of breach because they compromise the data itself — the thing an organisation is ultimately responsible for — rather than a single function.

### Business Impact

- **Mass data exposure**: When a plaintext database or unencrypted backup leaks, every record is immediately readable. Encryption turns the same leak into unusable ciphertext.
- **Account takeover at scale**: Weakly hashed or plaintext passwords are cracked in bulk and replayed against other sites (credential stuffing).
- **Regulatory penalties**: GDPR, HIPAA, PCI-DSS, and similar regimes treat unencrypted sensitive data as a reportable failure and levy fines; many provide safe-harbour relief when data was strongly encrypted.
- **Loss of trust and contracts**: Disclosing that passwords or personal data were stored insecurely causes lasting reputational and commercial damage.

### Technical Impact

- **Confidentiality loss**: Data on the wire or on disk is read directly by anyone who obtains it.
- **Integrity loss**: Without authenticated encryption or signatures, an attacker can silently modify ciphertext, cookies, or tokens (bit-flipping, padding-oracle tampering).
- **Forgery**: Predictable randomness lets attackers guess session tokens, password-reset links, and API keys.
- **Downgrade and interception**: Missing HSTS and weak TLS allow man-in-the-middle attackers to strip encryption and read traffic.

## The Three States of Data

Cryptography must be considered for data in each of the states it can occupy. Most programmes cover the first two well and forget the third.

| State | What it means | Primary control |
|-------|---------------|-----------------|
| **In transit** | Data moving over a network (client↔server, service↔service) | TLS 1.2+/1.3, HSTS, no downgrade, mTLS internally |
| **At rest** | Data stored on disk: databases, files, backups, object storage | Authenticated encryption (AES-256-GCM), disk/volume encryption, encrypted backups |
| **In use** | Data live in memory while being processed | Minimise exposure, zeroise buffers, and where feasible use confidential-computing / enclaves |

A field can be perfectly encrypted at rest and still be exposed if it is logged in plaintext, sent over plain HTTP, or held in a heap dump. This control is only as strong as its weakest state.

## Technical Context

### 1. Classify Data Before You Encrypt It

You cannot protect what you have not identified. Start by classifying data so cryptographic effort is spent where it matters:

```
Sensitivity tiers (example):
  Restricted   -> passwords, secrets, keys, payment data, health records
  Confidential -> PII, tokens, internal business data
  Internal     -> non-public but low-impact
  Public       -> freely shareable

Rule: Restricted and Confidential data MUST be encrypted in transit
      and at rest, and MUST NOT appear in logs, URLs, or analytics.
```

### 2. Authenticated Encryption, Not Just Encryption

Confidentiality alone is not enough — you also need to know the ciphertext was not tampered with. **Authenticated encryption with associated data (AEAD)** provides both. Prefer AES-256-GCM or ChaCha20-Poly1305 over unauthenticated modes like CBC (and never ECB, which leaks patterns).

```
ECB mode leaks structure — identical plaintext blocks
produce identical ciphertext blocks:

  plaintext blocks:   [AAAA][BBBB][AAAA][CCCC]
  ECB ciphertext:     [ 9f ][ 2c ][ 9f ][ e1 ]   <- repetition visible!
  GCM ciphertext:     [ 4d ][ a0 ][ 71 ][ b8 ] + auth tag  (no pattern, tamper-evident)
```

### 3. Passwords Are Hashed, Not Encrypted

Passwords must never be reversible. Store them with a **slow, salted, memory-hard** password hashing function so that a stolen database cannot be reversed cheaply:

| Function | Use for passwords? | Notes |
|----------|--------------------|-------|
| Argon2id | Yes (preferred) | Memory-hard; current best practice |
| scrypt | Yes | Memory-hard alternative |
| bcrypt | Yes | Widely available; ~72-byte input limit |
| PBKDF2 | Yes (if others unavailable) | High iteration count; FIPS-friendly |
| SHA-256 / SHA-3 | **No** | Too fast; billions of guesses/second on a GPU |
| MD5 / SHA-1 | **Never** | Broken and trivially cracked |

### 4. Randomness Must Be Cryptographically Secure

Keys, salts, IVs/nonces, session identifiers, API keys, and password-reset tokens must come from a **cryptographically secure pseudo-random number generator (CSPRNG)**. General-purpose generators (`Math.random()`, `java.util.Random`, `rand()`) are predictable and must never be used for security values.

```
Secure sources:
  Python   -> secrets.token_bytes(), os.urandom()
  Node.js  -> crypto.randomBytes()
  Java     -> java.security.SecureRandom
  Go       -> crypto/rand
Never:     Math.random(), java.util.Random, rand()/mt_rand(), time()-seeded PRNGs
```

### 5. Keys Are the Real Secret

Encryption relocates the problem from "protect all the data" to "protect the key." That trade only pays off if keys are managed properly: generated with a CSPRNG, stored in a KMS or HSM (never in source or config), separated from the data they protect, rotated on a schedule, and revocable. A hardcoded key committed to a repository nullifies every other cryptographic control.

## Real-World Impact

The incident *classes* below recur across the industry. They are described as patterns rather than attributed to specific named breaches or fabricated statistics.

### Class 1: Plaintext or Weakly Hashed Password Databases

**Failure**: A breached database stores passwords in plaintext, or hashed with a single pass of MD5/SHA-1 and no salt.

**Consequence**: Attackers recover most passwords within hours using rainbow tables and GPU cracking, then replay them against banking, email, and corporate accounts (credential stuffing) because users reuse passwords.

**The control that prevents it**: Per-user salted Argon2id/bcrypt makes bulk cracking economically infeasible; even a full database leak yields few usable passwords.

### Class 2: Unencrypted Data at Rest (Databases, Backups, Buckets)

**Failure**: Sensitive records sit in plaintext columns, and backups or cloud storage snapshots are unencrypted.

**Consequence**: A single leaked backup, stolen disk, or misconfigured bucket exposes every record immediately — no cracking required.

**The control that prevents it**: Field/column encryption with AES-256-GCM plus encrypted volumes and backups turns the same leak into unreadable ciphertext.

### Class 3: Missing or Downgradable Transport Encryption

**Failure**: Endpoints accept plain HTTP, lack HSTS, or negotiate obsolete TLS versions and weak ciphers (RC4, export suites).

**Consequence**: An on-path attacker (hostile Wi-Fi, compromised router) strips or downgrades encryption and reads or modifies traffic, including session cookies and credentials.

**The control that prevents it**: TLS 1.2+/1.3 only, HSTS with preload, and no fallback to weak protocols close the interception window.

### Class 4: Hardcoded and Leaked Keys

**Failure**: API keys, encryption keys, or signing secrets are committed to source control or baked into container images.

**Consequence**: Anyone with read access to the repository or image can decrypt data, forge tokens, or impersonate the service. Public-repo secret scanning finds these within minutes of a push.

**The control that prevents it**: Keys are stored in a KMS/secrets manager, injected at runtime, rotated, and never written to disk in plaintext; commit-time secret scanning blocks accidental leaks.

## Common Misunderstandings

### Myth 1: "We use HTTPS, so our data is encrypted"

**Reality**: HTTPS protects data *in transit* only. The moment it arrives it is plaintext in memory, in the database, and in your logs unless you also encrypt at rest and hash passwords properly.

### Myth 2: "We hash passwords with SHA-256, so we're fine"

**Reality**: Fast hashes are designed to be fast — exactly the wrong property for passwords. A GPU tries billions of SHA-256 guesses per second. Passwords need a deliberately slow, salted function (Argon2id/bcrypt).

### Myth 3: "Encoding the data hides it"

**Reality**: Base64, hex, and URL-encoding are reversible with no key and provide zero confidentiality. Encoding is not a security control.

### Myth 4: "We wrote our own encryption so attackers can't understand it"

**Reality**: Security through obscurity fails. Home-grown crypto and custom modes almost always contain fatal flaws (bad IV handling, no authentication, key reuse). Use vetted libraries — libsodium, your platform's crypto, or Tink.

### Myth 5: "The key can live in the config file / source code"

**Reality**: A key stored next to the data it protects (or in git history) provides no protection. Keys belong in a KMS/HSM, separated from the ciphertext, and must be rotatable.

### Myth 6: "AES means we're secure"

**Reality**: AES in ECB mode leaks patterns; AES-CBC without an authentication tag is malleable and vulnerable to padding oracles; any AES with a reused nonce or a hardcoded key is broken. The *mode*, *nonce handling*, and *key management* matter as much as the cipher.

## How This Control Maps to Cryptographic Failures

| Cryptographic Failure (the risk) | This Control's Answer (the defense) |
|----------------------------------|-------------------------------------|
| Data sent in cleartext | TLS 1.2+/1.3 with HSTS, no downgrade |
| Data stored in cleartext | AES-256-GCM authenticated encryption at rest |
| Weak/deprecated algorithms (MD5, DES, RC4, ECB) | Strong, current primitives; crypto-agility to retire old ones |
| Passwords stored with fast/unsalted hashes | Argon2id / bcrypt / scrypt / PBKDF2 with per-user salt |
| Predictable randomness | CSPRNG for every key, salt, nonce, and token |
| Hardcoded / mismanaged keys | KMS/HSM, rotation, separation, least privilege |

## Key Takeaways

1. **This control is the defense against Cryptographic Failures** — protect data in transit, at rest, and (where feasible) in use.
2. **Classify first** — know which data is sensitive so cryptography is applied where it counts.
3. **Use authenticated encryption** (AES-256-GCM/ChaCha20-Poly1305), current algorithms, and retire the broken ones.
4. **Hash passwords, don't encrypt them** — slow, salted Argon2id/bcrypt/scrypt/PBKDF2, never plain SHA/MD5.
5. **Randomness and keys are the whole game** — CSPRNG everywhere, keys in a KMS/HSM, rotated and never hardcoded.
6. **Don't roll your own** — use vetted libraries and keep the system crypto-agile so algorithms can be upgraded.

## Next Steps

- **[Threats Addressed](attack-vectors.md)**: What goes wrong when this control is missing or misused
- **[How to Implement](prevention.md)**: The step-by-step guide to applying cryptography correctly
- **[Examples](examples.md)**: Insecure vs. secure crypto code in Python, Node, and Java
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
