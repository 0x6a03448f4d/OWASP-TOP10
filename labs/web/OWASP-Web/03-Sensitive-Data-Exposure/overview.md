# Sensitive Data Exposure - Overview

## What is Sensitive Data Exposure?

**Sensitive Data Exposure** occurs when applications fail to adequately protect sensitive information such as financial data, healthcare records, and personal identifiable information (PII). This can happen both at rest (stored data) and in transit (transmitted data).

### Common Causes

- **Weak Encryption**: Using outdated algorithms (DES, RC4)
- **No Encryption**: Storing or transmitting data in clear text
- **Weak Key Management**: Hardcoded keys, insufficient key rotation
- **Improper Certificate Validation**: Ignoring SSL/TLS errors
- **Insecure Protocols**: Using HTTP instead of HTTPS, FTP instead of SFTP

## Why Does This Matter?

Sensitive data exposure can lead to:

- Identity theft and fraud
- Privacy violations and regulatory fines
- Loss of competitive advantage
- Reputational damage

### Classic 2017 Vulnerabilities

In the 2017 era, common issues included:

1. **HTTP instead of HTTPS**: Credentials sent in clear text
2. **Weak SSL/TLS**: Supporting SSLv3, TLS 1.0
3. **MD5/SHA1 Hashing**: Cryptographically broken algorithms
4. **Database Encryption**: No encryption at rest
5. **Backup Exposure**: Unencrypted backup files accessible

## Real-World Impact

**Heartbleed (2014, still relevant 2017)**
- OpenSSL vulnerability exposed private keys
- Millions of servers affected
- Encrypted communications compromised

**Target Breach (2013, lessons learned by 2017)**
- 40 million credit cards stolen
- Weak network segmentation
- Inadequate encryption
