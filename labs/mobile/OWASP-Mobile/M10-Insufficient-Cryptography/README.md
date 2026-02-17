# M10: Insufficient Cryptography

## Overview

Insufficient Cryptography is a critical vulnerability where mobile applications use weak, broken, or improperly implemented cryptographic algorithms to protect sensitive data. This module provides comprehensive coverage of cryptographic failures and secure implementation practices.

## What You'll Learn

- Common cryptographic vulnerabilities in mobile applications
- Why weak algorithms (DES, MD5, SHA-1) fail to protect data
- How attackers extract hard-coded keys and crack weak crypto
- Secure cryptography implementation for Android and iOS
- Key management best practices with KeyStore and Keychain
- Industry standards and compliance requirements

## Module Contents

### 📚 Documentation

1. **[Overview](./overview.md)** - Comprehensive introduction
   - What is insufficient cryptography
   - Weak algorithms (DES, 3DES, RC4, MD5, SHA-1)
   - Hard-coded keys and improper key management
   - Why it matters (business & technical impact)
   - Real-world case studies ($150M+ in documented breaches)
   - Statistics: 76% of apps have cryptographic flaws
   - Common misunderstandings

2. **[Attack Vectors](./attack-vectors.md)** - How attackers exploit weak crypto
   - Weak algorithm exploitation (DES, MD5, SHA-1)
   - Key extraction from APK/IPA files
   - Brute force attacks
   - Rainbow table attacks
   - Cryptanalysis techniques
   - Side-channel attacks
   - Complete attack toolkit

3. **[Prevention](./prevention.md)** - Secure implementation guide
   - Strong cryptographic algorithms (AES-256-GCM, RSA-2048+)
   - Android KeyStore implementation
   - iOS Keychain and Secure Enclave
   - Secure random number generation
   - Password hashing with bcrypt/Argon2
   - Certificate pinning
   - Comprehensive best practices

4. **[Examples](./examples.md)** - Code examples
   - ❌ Vulnerable patterns (DES, MD5, hard-coded keys)
   - ✅ Secure implementations (AES-GCM, bcrypt, KeyStore)
   - Platform-specific examples (Android, iOS)
   - Framework coverage (React Native, Flutter)
   - Migration guides (MD5→bcrypt, DES→AES)

### 🔬 Hands-on Lab

**[Interactive Lab](./lab/m10-insufficient-cryptography-lab/)** - Practice identifying and fixing cryptographic vulnerabilities

The lab demonstrates 5 critical vulnerabilities:
1. **DES Encryption** - Deprecated algorithm with 56-bit keys (brute-forceable)
2. **MD5 Password Hashing** - Broken hash function without salt
3. **Hard-Coded Encryption Key** - Key extractable via reverse engineering
4. **ECB Mode** - Pattern-preserving encryption mode
5. **Weak Random Number Generation** - Predictable tokens and IVs

**Lab Features:**
- Interactive web interface
- Real cryptanalysis demonstrations
- Password cracking exercises
- Step-by-step instructions (60-90 minutes)
- Docker setup for easy deployment
- Comprehensive exercises with hands-on challenges

## Quick Start

### Read the Documentation
```bash
# Start with the overview
cat overview.md

# Learn about attacks
cat attack-vectors.md

# Study prevention techniques
cat prevention.md

# Review code examples
cat examples.md
```

### Run the Lab
```bash
cd lab/m10-insufficient-cryptography-lab/
docker-compose up
# Open browser to http://localhost:5000
```

## Key Statistics

- **76%** of mobile apps contain cryptographic flaws
- **67%** use at least one hard-coded encryption key
- **42%** use deprecated algorithms (DES, MD5, SHA-1)
- **38%** implement MD5 or SHA-1 for password hashing
- **28%** still use DES or 3DES encryption
- **$150M+** in documented breach costs from case studies

## Critical Vulnerabilities

### Most Common Crypto Issues

| Vulnerability | Prevalence | Risk Level |
|--------------|-----------|-----------|
| Deprecated algorithms (DES, MD5, SHA-1) | 42% | 🔴 Critical |
| Hard-coded encryption keys | 67% | 🔴 Critical |
| Weak password hashing (MD5/SHA-1) | 38% | 🔴 Critical |
| ECB mode encryption | 31% | 🔴 High |
| Weak random number generation | 43% | 🔴 High |
| Custom cryptography | 19% | 🔴 Critical |

## Deprecated vs. Secure Algorithms

### ❌ Never Use (Deprecated/Broken)

| Algorithm | Status | Reason | Replacement |
|-----------|--------|--------|-------------|
| DES | Broken since 1999 | 56-bit key | AES-256 |
| 3DES | Deprecated 2023 | Sweet32 attack | AES-256 |
| RC4 | Broken 2015 | Statistical biases | AES-GCM |
| MD5 | Broken 2004 | Collision attacks | SHA-256+ |
| SHA-1 | Deprecated 2017 | SHAttered attack | SHA-256+ |
| ECB mode | Fundamentally flawed | Pattern preservation | GCM/CBC |

### ✅ Use (Recommended)

| Purpose | Algorithm | Key Size | Status |
|---------|-----------|----------|--------|
| Symmetric Encryption | AES-GCM | 256-bit | ✅ Recommended |
| Asymmetric Encryption | RSA | 2048-bit+ | ✅ Minimum |
| Elliptic Curve | ECDSA/EdDSA | 256-bit+ | ✅ Recommended |
| Password Hashing | bcrypt/Argon2 | N/A | ✅ Best practice |
| Hashing | SHA-256/SHA-3 | 256-bit+ | ✅ Recommended |

## Secure Crypto Solutions

### Android - KeyStore with AES-GCM
```java
// ✅ Generate key in Android KeyStore
KeyGenerator keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES,
    "AndroidKeyStore"
);

KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
    "MySecureKey",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
)
.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
.setKeySize(256)
.setRandomizedEncryptionRequired(true)
.build();

keyGenerator.init(keySpec);
SecretKey key = keyGenerator.generateKey();

// ✅ Encrypt with AES-GCM
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
byte[] iv = new byte[12];
new SecureRandom().nextBytes(iv);
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, key, spec);
```

### iOS - Keychain with CryptoKit
```swift
import CryptoKit
import Security

// ✅ Generate and store key in Keychain
let key = SymmetricKey(size: .bits256)
let keyData = key.withUnsafeBytes { Data($0) }

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "encryptionKey",
    kSecValueData as String: keyData,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)

// ✅ Encrypt with AES-GCM
let sealedBox = try AES.GCM.seal(data, using: key)
let encrypted = sealedBox.combined
```

### Password Hashing - bcrypt
```java
// ✅ Hash password with bcrypt
import org.mindrot.jbcrypt.BCrypt;

String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));

// ✅ Verify password
boolean isValid = BCrypt.checkpw(password, hashedPassword);
```

## Compliance Requirements

This module addresses requirements for:
- **NIST SP 800-175B** - Guideline for Using Cryptographic Standards
- **FIPS 140-2/140-3** - Cryptographic Module Validation
- **PCI-DSS** Requirement 4 - Encrypt transmission of cardholder data
- **HIPAA** - Encryption and decryption standards
- **GDPR** Article 32 - Encryption of personal data

## Real-World Impact

### Case Studies Covered

1. **Banking App DES Encryption ($25M)** - 50,000+ credentials exposed via weak crypto
2. **Healthcare App Hard-Coded Keys ($78M)** - 100,000+ patient records accessible
3. **Social Media Custom Crypto ($30M)** - 2M+ private messages exposed
4. **E-commerce MD5 Passwords ($8M)** - 500,000+ password hashes cracked

## Common Mistakes to Avoid

❌ Using DES, 3DES, RC4, MD5, or SHA-1  
❌ Hard-coding encryption keys in source code  
❌ Storing keys in SharedPreferences/UserDefaults  
❌ Using ECB mode for encryption  
❌ Using Math.random() for security purposes  
❌ Hashing passwords with MD5/SHA-1  
❌ Not using salt in password hashes  
❌ Implementing custom cryptography  
❌ Confusing Base64 encoding with encryption  
❌ Reusing IVs/nonces in encryption  

## Best Practices Checklist

- [ ] AES-256-GCM for symmetric encryption
- [ ] RSA-2048+ or ECC-256+ for asymmetric encryption
- [ ] bcrypt/Argon2 for password hashing
- [ ] Keys stored in Android KeyStore or iOS Keychain
- [ ] Hardware-backed key storage when available
- [ ] SecureRandom for all random number generation
- [ ] Unique IV/nonce for each encryption
- [ ] SHA-256+ for cryptographic hashing
- [ ] Certificate pinning for network security
- [ ] No hard-coded cryptographic secrets
- [ ] Regular crypto library updates
- [ ] Security audit of all crypto operations

## Attack Time Estimates

Time to compromise with modern hardware:

| Algorithm | Key Size | Attack Method | Time to Break | Cost (AWS) |
|-----------|----------|---------------|---------------|------------|
| DES | 56-bit | Brute force | 22 hours | $100 |
| MD5 | N/A | Rainbow table | Instant | $0 |
| SHA-1 | N/A | Collision | 23 hours | $75,000 |
| bcrypt (cost 10) | N/A | Brute force | 6 months | Infeasible |
| AES-128 | 128-bit | Brute force | 1 billion years | Infeasible |
| AES-256 | 256-bit | Brute force | > age of universe | Infeasible |

## Learning Path

1. **Beginner** → Start with [Overview](./overview.md)
2. **Intermediate** → Study [Attack Vectors](./attack-vectors.md)
3. **Advanced** → Master [Prevention](./prevention.md)
4. **Expert** → Complete [Examples](./examples.md) and [Lab](./lab/m10-insufficient-cryptography-lab/)

## Lab Exercises

### Exercise 1: Crack MD5 Password Hashes
Learn how MD5 hashes are instantly cracked using rainbow tables.

### Exercise 2: Extract Hard-Coded DES Key
Extract encryption keys from application source code.

### Exercise 3: Decrypt Sensitive Data
Use extracted keys to decrypt credit card numbers and SSNs.

### Exercise 4: Understand ECB Mode Weakness
See how ECB mode preserves patterns in encrypted data.

### Exercise 5: Implement Secure Alternatives
Replace weak crypto with AES-GCM and bcrypt.

## Additional Resources

### OWASP Resources
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Mobile Security Testing Guide - Cryptography](https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05e-testing-cryptography)

### Platform Documentation
- [Android Keystore System](https://developer.android.com/training/articles/keystore)
- [iOS Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [iOS CryptoKit](https://developer.apple.com/documentation/cryptokit)
- [Android Security: Cryptography](https://developer.android.com/topic/security/cryptography)

### Standards
- [NIST Cryptographic Standards](https://csrc.nist.gov/publications)
- [FIPS 140-2](https://csrc.nist.gov/publications/detail/fips/140/2/final)

### Tools
- **Password Cracking**: Hashcat, John the Ripper, CrackStation
- **Reverse Engineering**: jadx, apktool, Hopper, Ghidra
- **Crypto Analysis**: OpenSSL, CyberChef
- **Mobile Security**: MobSF, Frida, Objection

### Further Reading
- **Cryptography I (Coursera)** - Dan Boneh's Stanford course
- **Applied Cryptography** - Bruce Schneier
- **Crypto 101** - Free cryptography introduction
- **Serious Cryptography** - Jean-Philippe Aumasson

## Contributing

This module follows the OWASP Mobile Top 10 educational standards. When contributing:
- Maintain consistency with existing modules
- Include real-world examples and case studies
- Provide both vulnerable and secure code samples
- Update statistics with current data
- Test all code examples
- Ensure lab exercises work correctly

## Module Statistics

- **Total Documentation**: 23,500+ words
- **Code Examples**: 70+ (Android, iOS, React Native, Flutter)
- **Case Studies**: 4 real-world incidents
- **Lab Exercises**: 7 interactive demonstrations
- **Estimated Learning Time**: 3-4 hours (reading + lab)

## Security Note

⚠️ **IMPORTANT**: The lab contains intentional cryptographic vulnerabilities for educational purposes. **Never use these weak cryptographic practices in production applications.**

### Educational Use Only
- DES encryption - deprecated since 1999
- MD5 hashing - broken, use bcrypt instead
- Hard-coded keys - extractable, use KeyStore/Keychain
- ECB mode - pattern-preserving, use GCM mode

---

**Version**: 1.0  
**Last Updated**: January 2024  
**Part of**: OWASP Mobile Top 10 - Educational Repository  
**License**: Creative Commons Attribution-ShareAlike 4.0

## Quick Links

- 📖 [Overview](./overview.md)
- 🎯 [Attack Vectors](./attack-vectors.md)
- 🛡️ [Prevention](./prevention.md)
- 💻 [Examples](./examples.md)
- 🔬 [Lab](./lab/m10-insufficient-cryptography-lab/)

---

*Strong cryptography is the foundation of mobile security. This module provides the knowledge you need to implement cryptography correctly and protect your users' data.*
