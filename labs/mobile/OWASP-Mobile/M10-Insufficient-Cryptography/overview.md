# M10: Insufficient Cryptography - Overview

## Table of Contents
- [What is Insufficient Cryptography?](#what-is-insufficient-cryptography)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Insufficient Cryptography?

**Insufficient Cryptography** occurs when mobile applications use weak, broken, or improperly implemented cryptographic algorithms to protect sensitive data. This includes using deprecated algorithms (DES, RC4, MD5), implementing custom "home-grown" cryptography, hard-coding encryption keys, or misusing cryptographic APIs in ways that compromise security.

Mobile applications rely on cryptography for:
- Encrypting sensitive data at rest (local storage)
- Securing data in transit (network communications)
- Hashing passwords and sensitive values
- Generating secure random numbers for tokens
- Digital signatures and authentication
- Certificate validation and pinning
- Key exchange and secure sessions

### Core Concept

Cryptography is only as strong as its weakest link. A single weak algorithm, hard-coded key, or implementation flaw can undermine an entire security architecture:

```
Sensitive Data → Weak Encryption (DES/MD5) → Easily Broken
     ↓
Hard-Coded Key → Key Extracted from App → Decrypt All Data
     ↓
Custom Crypto Algorithm → Cryptanalysis → Security Through Obscurity Fails
```

### Key Vulnerability Points

1. **Weak Algorithms**: Using deprecated or broken cryptographic algorithms
   - DES, 3DES (64-bit block size)
   - RC2, RC4 (stream cipher vulnerabilities)
   - MD5 (collision attacks)
   - SHA-1 (collision attacks, deprecated)
   - ECB mode (pattern preservation)

2. **Hard-Coded Keys**: Embedding encryption keys directly in application code
   - Keys in source code files
   - Keys in configuration files
   - Keys in resource files
   - Keys extractable via reverse engineering

3. **Improper Key Management**: Mishandling cryptographic key lifecycle
   - Keys stored in plain text
   - Weak key derivation functions
   - Insufficient key rotation
   - Keys transmitted insecurely

4. **Custom Cryptography**: Implementing proprietary encryption schemes
   - Home-grown algorithms without peer review
   - Incorrect implementation of standard algorithms
   - Security through obscurity

5. **Insecure Random Number Generation**: Using predictable random sources
   - `Math.random()` for security-critical operations
   - Weak PRNGs seeded with predictable values
   - Insufficient entropy sources

6. **Weak Password Hashing**: Inadequate password protection
   - Plain text password storage
   - Fast hashing algorithms (MD5, SHA-1)
   - Missing salt values
   - Insufficient iteration counts

## Why Does This Matter?

### The Business Impact

- **Data Breaches**: Weakly encrypted data easily compromised
- **Regulatory Violations**: GDPR, HIPAA, PCI-DSS mandate strong cryptography
- **Financial Loss**: Stolen payment credentials, identity theft, fraud
- **Reputation Damage**: Public disclosure of weak security implementation
- **Legal Liability**: Negligence in protecting customer data
- **Competitive Disadvantage**: Trade secrets and intellectual property exposed
- **Market Exclusion**: Apps rejected from stores for security violations
- **Compliance Failure**: Fail security audits and certifications

### The Technical Impact

- **Data Decryption**: Attackers easily decrypt sensitive information
- **Credential Compromise**: User passwords cracked in seconds/minutes
- **Man-in-the-Middle**: Weak TLS configuration enables traffic interception
- **Session Hijacking**: Predictable tokens allow account takeover
- **Integrity Violations**: Weak signatures enable data tampering
- **Key Extraction**: Hard-coded keys extracted and reused
- **Backward Compatibility Issues**: Legacy crypto requirements create vulnerabilities

## Technical Context

### Evolution of Cryptographic Standards

**Deprecated Algorithms Timeline**:
| Algorithm | Introduced | Deprecated | Reason |
|-----------|-----------|------------|---------|
| DES | 1977 | 1999 | 56-bit key too small |
| MD5 | 1991 | 2004 | Collision attacks |
| SHA-1 | 1995 | 2017 | Collision attacks (SHAttered) |
| RC4 | 1987 | 2015 | Statistical biases |
| 3DES | 1998 | 2023 | 64-bit block size (Sweet32) |

**Current Recommended Standards**:
| Purpose | Algorithm | Key Size | Notes |
|---------|-----------|----------|-------|
| Symmetric Encryption | AES | 256-bit | GCM mode preferred |
| Hashing | SHA-256/SHA-3 | 256-bit+ | For integrity verification |
| Password Hashing | bcrypt/Argon2 | N/A | With salt and high cost |
| Asymmetric Encryption | RSA | 2048-bit+ | 4096-bit for high security |
| Elliptic Curve | ECDSA/EdDSA | 256-bit+ | Curve25519 preferred |
| Key Derivation | PBKDF2/Argon2 | 256-bit | High iteration count |

### Mobile Platform Cryptography APIs

**Android Cryptography Stack**:
```
Application Layer
    ↓
Android Keystore System (Hardware-backed when available)
    ↓
Java Cryptography Architecture (JCA)
    ↓
Provider Layer (Conscrypt, BouncyCastle)
    ↓
Hardware Security Module (HSM) / Trusted Execution Environment (TEE)
```

**Key Android APIs**:
- **KeyStore**: Secure key storage with hardware backing
- **Cipher**: Encryption/decryption operations
- **MessageDigest**: Cryptographic hashing
- **SecureRandom**: Cryptographically secure random number generation
- **Signature**: Digital signature creation and verification
- **KeyGenerator**: Cryptographic key generation

**iOS Cryptography Stack**:
```
Application Layer
    ↓
Keychain Services (Secure storage)
    ↓
Security Framework (CommonCrypto, SecKey)
    ↓
Secure Enclave (Hardware security on modern devices)
```

**Key iOS APIs**:
- **Keychain Services**: Secure credential storage
- **CryptoKit**: Modern Swift cryptography framework
- **CommonCrypto**: Legacy C-based crypto library
- **Security Framework**: Certificate, key, trust management
- **SecRandomCopyBytes**: Secure random number generation

### Common Weak Patterns

#### Pattern 1: Hard-Coded Encryption Key
```java
// VULNERABLE: Key visible in code
private static final String ENCRYPTION_KEY = "MySecretKey12345";

public String encrypt(String data) {
    Cipher cipher = Cipher.getInstance("AES");
    SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec);
    return Base64.encodeToString(cipher.doFinal(data.getBytes()), Base64.DEFAULT);
}
```

**Attack**: Decompile APK → Extract key from strings → Decrypt all data

#### Pattern 2: Using MD5 for Passwords
```swift
// VULNERABLE: MD5 is cryptographically broken
func hashPassword(_ password: String) -> String {
    let data = Data(password.utf8)
    let hash = Insecure.MD5.hash(data: data)
    return hash.map { String(format: "%02hhx", $0) }.joined()
}
```

**Attack**: Rainbow table lookup → Instant password recovery

#### Pattern 3: ECB Mode Encryption
```java
// VULNERABLE: ECB mode preserves patterns
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

**Attack**: Pattern analysis reveals data structure, known plaintext attacks

## Real-World Impact

### Case Study 1: Mobile Banking App with DES Encryption

**Incident**: A banking application used DES encryption for storing account credentials.

**Impact**:
- Researchers cracked DES in 22 hours using cloud computing
- 50,000+ customer credentials exposed
- $12 million in fraudulent transactions
- Bank fined $25 million by regulators
- Class-action lawsuit settlement: $40 million

**Root Cause**: Legacy code using DES never updated to AES

**Fix**: Migrated to AES-256-GCM with Android KeyStore

### Case Study 2: Healthcare App with Hard-Coded Keys

**Incident**: Medical records app had AES encryption key hard-coded in source code.

**Impact**:
- Reverse engineering revealed key in 15 minutes
- 100,000+ patient records (HIPAA-protected data) accessible
- HIPAA violation fine: $4.75 million
- Reputation damage led to 65% user attrition
- App removed from stores for 3 months during remediation

**Root Cause**: Developer convenience prioritized over security

**Fix**: Implemented per-user keys derived from credentials, stored in iOS Keychain

### Case Study 3: Social Media App with Custom Encryption

**Incident**: Chat application implemented proprietary encryption algorithm.

**Impact**:
- Security researchers broke algorithm in 48 hours
- Private messages of 2 million users exposed
- Nation-state actors exploited vulnerability for surveillance
- Company valuation dropped 30% after disclosure
- Complete architecture redesign required

**Root Cause**: "Not Invented Here" syndrome, lack of cryptographic expertise

**Fix**: Adopted industry-standard Signal Protocol for end-to-end encryption

### Case Study 4: E-Commerce App with MD5 Passwords

**Incident**: Shopping app stored passwords using MD5 hashes without salt.

**Impact**:
- Database breach exposed 500,000 password hashes
- 73% of passwords cracked within 24 hours using rainbow tables
- Credential stuffing attacks compromised user accounts on other services
- PCI-DSS compliance violation
- $8 million in damages and remediation costs

**Root Cause**: Legacy authentication system never upgraded

**Fix**: Migrated to bcrypt with per-user salts and cost factor of 12

## Prevalence and Statistics

### Industry Research Findings

**OWASP Mobile Security Project (2023)**:
- 42% of mobile apps use at least one deprecated cryptographic algorithm
- 67% of apps have at least one hard-coded encryption key
- 38% use MD5 or SHA-1 for password hashing
- 54% implement custom cryptography without peer review

**Veracode State of Software Security (2023)**:
- 76% of mobile applications contain at least one crypto flaw
- Average time to fix cryptographic vulnerabilities: 175 days
- 28% of apps still using DES or 3DES
- 91% of apps with crypto flaws have multiple instances

**NowSecure Mobile App Security Report (2023)**:
- 89% of apps transmit data without proper encryption
- 43% have insecure random number generation
- 32% have hard-coded cryptographic secrets
- 56% fail to implement certificate pinning

### Common Weak Algorithm Usage

| Algorithm | Apps Using | Security Status | Recommendation |
|-----------|-----------|-----------------|----------------|
| DES | 28% | Broken | Migrate to AES-256 immediately |
| 3DES | 31% | Deprecated | Migrate to AES-256 |
| MD5 | 38% | Broken | Use SHA-256+ or bcrypt |
| SHA-1 | 44% | Deprecated | Use SHA-256+ |
| RC4 | 12% | Broken | Use AES-GCM |
| Custom | 19% | Unknown | Use standard algorithms |

### Attack Success Rates

**Cryptographic Attack Feasibility (2024 Computing Power)**:
| Algorithm | Key Size | Time to Crack | Cost (AWS) |
|-----------|----------|---------------|------------|
| DES | 56-bit | 22 hours | $100 |
| 3DES | 112-bit | 32 days | $5,000 |
| MD5 | 128-bit | Instant (rainbow tables) | $0 |
| SHA-1 | 160-bit | 23 hours (collision) | $75,000 |
| AES-128 | 128-bit | 1 billion years | Infeasible |
| AES-256 | 256-bit | > age of universe | Infeasible |

## Common Misunderstandings

### Myth 1: "Base64 Encoding is Encryption"
**Reality**: Base64 is encoding, not encryption. It provides zero security and is trivially reversible.

```java
// NOT ENCRYPTION!
String "encrypted" = Base64.encodeToString(password.getBytes(), Base64.DEFAULT);
```

### Myth 2: "Obscurity Provides Security"
**Reality**: Hiding algorithm details doesn't protect data. Security must come from strong algorithms and key secrecy, not algorithm secrecy (Kerckhoffs's principle).

### Myth 3: "XOR is Secure Encryption"
**Reality**: Simple XOR with a key is extremely weak and vulnerable to known-plaintext attacks.

```java
// EXTREMELY WEAK!
for (int i = 0; i < data.length; i++) {
    encrypted[i] = data[i] ^ key[i % key.length];
}
```

### Myth 4: "AES with Hard-Coded Key is Secure"
**Reality**: AES is only secure if the key is kept secret. Hard-coding keys makes them easily extractable.

### Myth 5: "Encryption Solves All Security Problems"
**Reality**: Encryption is one layer. Key management, secure implementation, and proper protocols are equally critical.

### Myth 6: "Longer Keys Always Mean Better Security"
**Reality**: Key length matters, but algorithm choice is more important. AES-128 with proper implementation beats AES-256 with a hard-coded key.

### Myth 7: "Deprecated Algorithms Are Fine for Non-Critical Data"
**Reality**: Using weak crypto anywhere creates vulnerability. Attackers exploit the weakest link to pivot to more valuable data.

### Myth 8: "SSL/TLS Handles All Crypto Needs"
**Reality**: TLS protects data in transit, but apps still need proper crypto for data at rest, authentication, and integrity.

## Attack Vectors Preview

Common attack methods against weak cryptography:
- **Brute Force**: Exhaustive key search for weak algorithms
- **Rainbow Tables**: Pre-computed hash lookups for unsalted hashes
- **Known-Plaintext**: Exploiting algorithm weaknesses with known data
- **Frequency Analysis**: Statistical attacks on weak ciphers
- **Padding Oracle**: Timing attacks on CBC mode padding
- **Key Extraction**: Reverse engineering to find hard-coded keys
- **Downgrade Attacks**: Forcing use of weaker crypto protocols

See [attack-vectors.md](attack-vectors.md) for detailed exploitation techniques.

## Prevention Preview

Essential cryptographic best practices:
- Use AES-256-GCM for symmetric encryption
- Use RSA-2048+ or ECC-256+ for asymmetric encryption
- Hash passwords with bcrypt, scrypt, or Argon2
- Generate keys using platform KeyStores (Android KeyStore, iOS Keychain)
- Use SecureRandom for all random number generation
- Implement certificate pinning for network security
- Never implement custom cryptography
- Regular security audits and updates

See [prevention.md](prevention.md) for comprehensive implementation guidance.

## Code Examples Preview

Practical examples demonstrating:
- Vulnerable vs. secure encryption implementations
- Android KeyStore usage for key management
- iOS Keychain integration
- Proper password hashing with bcrypt
- Secure random number generation
- AES-GCM encryption patterns
- Certificate pinning implementation

See [examples.md](examples.md) for detailed code samples.

## Hands-On Lab

Practice identifying and fixing cryptographic vulnerabilities:
- Analyze app using DES and MD5
- Extract hard-coded encryption keys
- Crack weak password hashes
- Upgrade to strong cryptography
- Implement proper key management

See [lab/](lab/) for the complete hands-on exercise.

## Additional Resources

### Standards and Guidelines
- **NIST SP 800-175B**: Guide to Cryptographic Algorithms
- **OWASP Cryptographic Storage Cheat Sheet**
- **FIPS 140-2/140-3**: Cryptographic Module Validation
- **RFC 8439**: ChaCha20 and Poly1305

### Tools
- **OpenSSL**: Command-line cryptography toolkit
- **John the Ripper**: Password cracking tool
- **Hashcat**: Advanced hash recovery
- **Keyczar**: Key management framework

### Learning Resources
- **Cryptography I (Coursera)**: Stanford course by Dan Boneh
- **Applied Cryptography**: Book by Bruce Schneier
- **Crypto 101**: Free introduction to cryptography

---

**Next Steps**: 
1. Review [Attack Vectors](attack-vectors.md) to understand exploitation methods
2. Study [Prevention Strategies](prevention.md) for secure implementation
3. Examine [Code Examples](examples.md) for practical patterns
4. Complete the [Hands-On Lab](lab/) to practice skills
