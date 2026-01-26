# M09: Insecure Data Storage

## Overview

Insecure Data Storage is one of the most critical vulnerabilities in mobile applications. This module provides comprehensive coverage of how mobile apps store sensitive data insecurely and how to protect against data theft from compromised devices.

## What You'll Learn

- How mobile applications store data locally
- Common vulnerabilities in SharedPreferences, UserDefaults, SQLite databases, and files
- Attack techniques for extracting data from devices
- Secure storage implementation for Android and iOS
- Industry best practices and compliance requirements

## Module Contents

### 📚 Documentation

1. **[Overview](./overview.md)** - Comprehensive introduction
   - What is insecure data storage
   - Why it matters (business & technical impact)
   - Real-world case studies ($89M+ in documented breaches)
   - Statistics: 76% of apps store data insecurely
   - Common misunderstandings

2. **[Attack Vectors](./attack-vectors.md)** - How attackers exploit storage
   - Physical access attacks
   - Backup extraction (ADB, iTunes, iCloud)
   - Rooted/jailbroken device exploitation
   - Malware and forensic analysis
   - Complete toolset for attackers

3. **[Prevention](./prevention.md)** - Secure implementation guide
   - Android: EncryptedSharedPreferences, KeyStore, SQLCipher
   - iOS: Keychain, Data Protection, Core Data encryption
   - File encryption techniques
   - Backup protection strategies
   - Root/jailbreak detection

4. **[Examples](./examples.md)** - Code examples
   - ❌ Vulnerable patterns (what NOT to do)
   - ✅ Secure implementations (what TO do)
   - Platform-specific examples
   - Framework coverage (React Native, Flutter, Xamarin)
   - Migration guides

### 🔬 Hands-on Lab

**[Interactive Lab](./lab/m09-insecure-data-storage-lab/)** - Practice identifying and fixing vulnerabilities

The lab demonstrates 6 critical vulnerabilities:
1. **Unencrypted Database** - SQLite storing passwords, SSNs, credit cards in plain text
2. **Plain Text Preferences** - SharedPreferences/UserDefaults with sensitive data
3. **Insecure File Storage** - Files written without encryption
4. **Logging Sensitive Data** - Credentials and PII in application logs
5. **Unencrypted Backups** - All data exposed in backup files
6. **Base64 as Encryption** - Common misconception of encoding vs encryption

**Lab Features:**
- Interactive web interface
- Real attack simulations
- Step-by-step instructions (30-45 minutes)
- Docker setup for easy deployment
- Comprehensive exercises with Q&A

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
cd lab/m09-insecure-data-storage-lab/
docker-compose up
# Open browser to http://localhost:5109
```

## Key Statistics

- **76%** of mobile apps store sensitive data insecurely
- **89%** don't properly use platform encryption APIs
- **67%** include sensitive data in backups
- **52%** use unencrypted SQLite databases
- **$89M+** in documented breach costs from case studies

## Critical Vulnerabilities

### Most Common Storage Issues

| Vulnerability | Prevalence | Risk Level |
|--------------|-----------|-----------|
| Unencrypted SharedPreferences/UserDefaults | 68% | 🔴 Critical |
| Plain text SQLite databases | 61% | 🔴 Critical |
| Sensitive data in logs | 54% | 🔴 High |
| Unencrypted external storage | 47% | 🔴 High |
| Sensitive data in backups | 72% | 🔴 Critical |

## Secure Storage Solutions

### Android
```kotlin
// ✅ Use EncryptedSharedPreferences
val encryptedPrefs = EncryptedSharedPreferences.create(
    context, "secure_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// ✅ Encrypt databases with SQLCipher
val factory = SupportFactory(SQLiteDatabase.getBytes(passphrase))
Room.databaseBuilder(context, AppDatabase::class.java, "db")
    .openHelperFactory(factory).build()
```

### iOS
```swift
// ✅ Use Keychain for sensitive data
KeychainManager.save(key: "auth_token", data: tokenData)

// ✅ Apply Data Protection to files
try data.write(to: fileURL, options: [.completeFileProtection])
```

## Compliance Requirements

This module addresses requirements for:
- **GDPR** Article 32 - Appropriate technical measures for data security
- **CCPA** - Reasonable security for personal information
- **HIPAA** - Encryption of electronic protected health information
- **PCI-DSS** Requirement 3 - Protect stored cardholder data

## Real-World Impact

### Case Studies Covered

1. **Banking App ($89M)** - Unencrypted database exposed 3.2M users
2. **Healthcare App ($78M)** - Patient records in plain text files
3. **Messaging App ($12M)** - Cached messages recoverable from storage
4. **E-commerce App ($34M)** - Credit card numbers in SharedPreferences

## Common Mistakes to Avoid

❌ Storing passwords locally  
❌ Using SharedPreferences/UserDefaults for sensitive data  
❌ Unencrypted SQLite databases  
❌ Logging credentials or tokens  
❌ Including sensitive data in backups  
❌ Thinking Base64 is encryption  
❌ Storing CVV codes (NEVER!)  
❌ Assuming rooted/jailbroken devices are rare  

## Best Practices Checklist

- [ ] Database encrypted with SQLCipher
- [ ] Using EncryptedSharedPreferences (Android) or Keychain (iOS)
- [ ] No passwords stored locally (only server-side hashes)
- [ ] PII minimized and encrypted
- [ ] Credit card data follows PCI-DSS
- [ ] Files encrypted with platform APIs
- [ ] Sensitive data excluded from backups
- [ ] No sensitive data in logs
- [ ] Authentication tokens have expiration
- [ ] Root/jailbreak detection implemented
- [ ] Regular security audits
- [ ] Penetration testing completed

## Learning Path

1. **Beginner** → Start with [Overview](./overview.md)
2. **Intermediate** → Study [Attack Vectors](./attack-vectors.md)
3. **Advanced** → Master [Prevention](./prevention.md)
4. **Expert** → Complete [Examples](./examples.md) and [Lab](./lab/m09-insecure-data-storage-lab/)

## Additional Resources

### OWASP Resources
- [OWASP Mobile Security Testing Guide](https://mobile-security.gitbook.io/)
- [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/)

### Platform Documentation
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [iOS Security Guide](https://support.apple.com/guide/security/welcome/web)
- [Android Keystore System](https://developer.android.com/training/articles/keystore)
- [iOS Keychain Services](https://developer.apple.com/documentation/security/keychain_services)

### Tools
- **Android**: ADB, SQLite Browser, jadx, Frida
- **iOS**: iMazing, iBackup Viewer, Hopper, Frida
- **Cross-platform**: MobSF, SQLCipher, Objection

## Contributing

This module follows the OWASP Mobile Top 10 educational standards. When contributing:
- Maintain consistency with existing modules
- Include real-world examples
- Provide both vulnerable and secure code samples
- Update statistics with current data
- Test all code examples

## Module Statistics

- **Total Documentation**: 9,849 words
- **Code Examples**: 50+ (Android, iOS, React Native, Flutter, Xamarin)
- **Case Studies**: 4 real-world incidents
- **Lab Exercises**: 6 interactive demonstrations
- **Estimated Learning Time**: 2-3 hours (reading + lab)

## Security Note

⚠️ **IMPORTANT**: The lab contains intentional vulnerabilities for educational purposes. Never use lab code patterns in production applications.

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
- 🔬 [Lab](./lab/m09-insecure-data-storage-lab/)

---

*Protecting mobile data starts with understanding how it can be compromised. This module provides the knowledge you need to secure your users' sensitive information.*
