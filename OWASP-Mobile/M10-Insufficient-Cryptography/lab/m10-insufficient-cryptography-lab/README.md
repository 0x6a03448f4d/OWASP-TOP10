# M10: Insufficient Cryptography Lab

## Overview

This hands-on lab demonstrates critical cryptographic vulnerabilities in mobile applications. You'll learn to identify, exploit, and fix weak cryptography through practical exercises.

## ⚠️ Vulnerabilities Demonstrated

1. **DES Encryption** (Deprecated since 1999)
   - 56-bit key size
   - Brute-forceable in ~22 hours
   - ECB mode preserves patterns

2. **MD5 Password Hashing** (Broken)
   - Fast computation enables billions of guesses/second
   - No salt - vulnerable to rainbow tables
   - Collision attacks possible

3. **Hard-Coded Encryption Key**
   - Extractable via reverse engineering
   - Same key for all users
   - No key rotation

4. **ECB Mode** (Pattern-preserving)
   - Identical plaintexts produce identical ciphertexts
   - Reveals data structure

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.11+ (for local development)
- hashcat or John the Ripper (for password cracking exercises)

### Running the Lab

**Option 1: Docker (Recommended)**
```bash
cd lab/m10-insufficient-cryptography-lab/
docker-compose up
```

**Option 2: Local Python**
```bash
cd lab/m10-insufficient-cryptography-lab/app/
pip install -r requirements.txt
python server.py
```

Access the lab at: **http://localhost:5000**

## 📚 Lab Structure

```
m10-insufficient-cryptography-lab/
├── app/
│   ├── server.py           # Flask app with weak crypto
│   ├── templates/
│   │   └── index.html      # Interactive web interface
│   ├── requirements.txt
│   └── Dockerfile
├── docker-compose.yml
├── README.md
└── instructions.md         # Detailed exercises
```

## 🎯 Learning Objectives

By completing this lab, you will:

1. **Identify** weak cryptographic algorithms (DES, MD5)
2. **Extract** hard-coded encryption keys from code
3. **Crack** MD5 password hashes using rainbow tables
4. **Decrypt** data encrypted with weak algorithms
5. **Understand** why modern cryptography is essential
6. **Implement** secure alternatives (AES-GCM, bcrypt)

## 🔍 What You'll Find

### Pre-Loaded Data

**Users** (username : password):
- alice : password123
- bob : qwerty
- charlie : letmein
- admin : admin

**Encrypted Data**:
- Credit card numbers (DES-encrypted)
- SSNs (DES-encrypted)
- Bank account numbers (DES-encrypted)

### Hard-Coded Secrets

```python
HARDCODED_DES_KEY = b'MYKEY123'  # 8 bytes for DES
```

All encryption uses this hard-coded key - easily extractable!

## 🛠️ Tools You'll Use

### Password Cracking
- **CrackStation**: Online rainbow table lookup
- **hashcat**: GPU-accelerated cracking
- **John the Ripper**: CPU-based cracking

### Cryptanalysis
- **OpenSSL**: Command-line crypto toolkit
- **CyberChef**: Web-based crypto analysis
- **Base64 decoder**: For ciphertext inspection

## 📖 Exercises

See **[instructions.md](instructions.md)** for detailed step-by-step exercises:

1. **Exercise 1**: Crack MD5 password hashes
2. **Exercise 2**: Extract hard-coded DES key
3. **Exercise 3**: Decrypt sensitive data
4. **Exercise 4**: Understand ECB mode weakness
5. **Exercise 5**: Implement secure alternatives

## 🎓 Educational Use Only

This lab contains intentionally vulnerable code for educational purposes. **Never use these cryptographic practices in production applications.**

## 🔗 Next Steps

After completing the lab:
1. Review [prevention.md](../../prevention.md) for secure implementation patterns
2. Study [examples.md](../../examples.md) for real-world code samples
3. Read [attack-vectors.md](../../attack-vectors.md) for advanced techniques

## 📝 Notes

- The database is recreated on each startup
- All data is local and temporary
- Perfect for security training and CTF practice

---

**Ready to start?** Open [instructions.md](instructions.md) for guided exercises!
