# M10: Insufficient Cryptography - Lab Instructions

## Introduction

Welcome to the Insufficient Cryptography lab! This hands-on exercise will teach you to identify, exploit, and fix cryptographic vulnerabilities in mobile applications.

**Time Required**: 60-90 minutes  
**Difficulty**: Intermediate  
**Prerequisites**: Basic understanding of encryption and hashing

## Lab Setup

### Start the Lab Environment

```bash
cd lab/m10-insufficient-cryptography-lab/
docker-compose up
```

Navigate to **http://localhost:5000** in your browser.

### Verify Setup

You should see:
- ✅ Login interface
- ✅ Encryption/decryption tools
- ✅ Password hasher
- ✅ Warning about vulnerabilities

## Exercise 1: Crack MD5 Password Hashes

**Objective**: Understand why MD5 is broken for password hashing.

### Step 1: Extract Password Hashes

1. Scroll down to the **"All User Password Hashes"** section
2. Click **"Show Password Hashes"**
3. Observe the MD5 hashes for all users

**Example output**:
```
alice    5f4dcc3b5aa765d61d8327deb882cf99
bob      d8578edf8458ce06fbc5bb76a58c5ca4
charlie  0d107d09f5bbe40cade3de5c71e9e9b7
admin    21232f297a57a5a743894a0e4a801fc3
```

### Step 2: Crack with Online Rainbow Tables

1. Copy alice's hash: `5f4dcc3b5aa765d61d8327deb882cf99`
2. Visit **https://crackstation.net/**
3. Paste the hash and submit

**Result**: Instant crack! Password: `password123`

### Step 3: Crack All Hashes

Crack the remaining hashes:
- bob's hash: `d8578edf8458ce06fbc5bb76a58c5ca4`
- charlie's hash: `0d107d09f5bbe40cade3de5c71e9e9b7`
- admin's hash: `21232f297a57a5a743894a0e4a801fc3`

**Expected Results**:
```
alice   → password123
bob     → qwerty
charlie → letmein
admin   → admin
```

### Step 4: Crack with Hashcat (Optional)

```bash
# Create hash file
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hashes.txt
echo "d8578edf8458ce06fbc5bb76a58c5ca4" >> hashes.txt
echo "0d107d09f5bbe40cade3de5c71e9e9b7" >> hashes.txt
echo "21232f297a57a5a743894a0e4a801fc3" >> hashes.txt

# Crack with hashcat
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Show results
hashcat -m 0 hashes.txt --show
```

### Step 5: Test MD5 Hasher

1. Go to **"MD5 Password Hasher"** section
2. Enter a password: `test123`
3. Click **"Hash with MD5"**
4. Observe the hash: `cc03e747a6afbbcbf8be7668acfebee5`
5. Crack this hash on CrackStation

**Result**: Instant crack!

### 🎓 Key Learnings

- ✅ MD5 hashes crack **instantly** with rainbow tables
- ✅ No salt means same password = same hash
- ✅ Fast computation enables **billions of guesses per second**
- ❌ **Never use MD5 for password hashing**
- ✅ **Use bcrypt, Argon2, or scrypt instead**

---

## Exercise 2: Extract Hard-Coded Encryption Key

**Objective**: Understand the danger of hard-coded cryptographic keys.

### Step 1: Analyze the Source Code

1. Open `app/server.py` in a text editor
2. Search for encryption-related code

**Find this vulnerable code**:
```python
# VULNERABLE: Hard-coded encryption key
HARDCODED_DES_KEY = b'MYKEY123'  # 8 bytes for DES
```

### Step 2: View Key Information in Browser

1. Go to **"Identified Vulnerabilities"** section
2. Click **"Show Vulnerabilities"**
3. Find the **Encryption Configuration** section

**You'll see**:
```
Algorithm: DES
Mode: ECB
Key: HARDCODED (8 bytes)
Key (Base64): TVlLRVkxMjM=
```

### Step 3: Decode the Key

```bash
# Decode Base64 key
echo "TVlLRVkxMjM=" | base64 -d
# Output: MYKEY123
```

### Step 4: Simulate Reverse Engineering

In a real attack scenario:

```bash
# Decompile hypothetical mobile app
apktool d vulnerable-app.apk

# Search for crypto keys
grep -r "Cipher" decompiled/
grep -r "DES" decompiled/
grep -r "MYKEY" decompiled/

# Result: Hard-coded key found!
```

### 🎓 Key Learnings

- ✅ Hard-coded keys are **easily extractable**
- ✅ Same key used for **all users and all data**
- ✅ Key rotation **impossible** without app update
- ❌ **Never hard-code encryption keys**
- ✅ **Use Android KeyStore or iOS Keychain**

---

## Exercise 3: Decrypt Sensitive Data

**Objective**: Exploit weak encryption to access protected data.

### Step 1: Login to the Application

1. Go to **"User Authentication"** section
2. Username: `alice`
3. Password: `password123` (cracked in Exercise 1)
4. Click **"Login"**

**Success!** You're logged in as alice.

### Step 2: View Encrypted Data

1. In the **"User Dashboard"** section
2. Click **"Load My Data"**

**You'll see**:
```
Type           Encrypted Value
credit_card    qBx7N2Y4h8uL5pK3mR9tVw==
ssn            xP4mN9dF2aQ8zR5vK1jH6w==
```

### Step 3: Decrypt Credit Card

1. Click **"Decrypt"** button next to the credit card entry
2. The ciphertext is automatically filled in the decryption tool

**Result**: `4532-1234-5678-9010`  
**You've extracted alice's credit card number!**

### Step 4: Decrypt SSN

Repeat for the SSN field.

**Result**: `123-45-6789`  
**You've extracted alice's Social Security Number!**

### Step 5: Decrypt Data Manually

Using the extracted key from Exercise 2:

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import base64

# Hard-coded key (extracted)
key = b'MYKEY123'

# Encrypted credit card
ciphertext = base64.b64decode('qBx7N2Y4h8uL5pK3mR9tVw==')

# Decrypt with DES
cipher = DES.new(key, DES.MODE_ECB)
plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)

print(f"Decrypted: {plaintext.decode()}")
# Output: 4532-1234-5678-9010
```

### 🎓 Key Learnings

- ✅ Weak encryption + hard-coded key = **complete compromise**
- ✅ All user data decryptable with **single extracted key**
- ✅ DES is **deprecated and breakable**
- ❌ **Never use DES encryption**
- ✅ **Use AES-256-GCM with proper key management**

---

## Exercise 4: Understand ECB Mode Weakness

**Objective**: See how ECB mode preserves patterns in encrypted data.

### Step 1: Encrypt Identical Data

1. Go to **"Encrypt Data (DES)"** section
2. Encrypt: `SECRET`
3. Note the ciphertext (e.g., `abcd1234efgh5678`)
4. Clear the field and encrypt `SECRET` again

**Observation**: Same plaintext → **Same ciphertext!**

### Step 2: Encrypt Similar Data

1. Encrypt: `1111-1111-1111-1111` (repeated pattern)
2. Encrypt: `1234-5678-9012-3456` (different pattern)
3. Compare the ciphertexts

**Observation**: Pattern visible even in encrypted form!

### Step 3: ECB Penguin Demonstration

ECB mode encrypts each block identically, preserving patterns.

**Famous Example**: Encrypting the Tux penguin image
- Original: Clear penguin shape
- ECB-encrypted: Penguin shape **still visible**
- CBC/GCM-encrypted: Complete noise

### 🎓 Key Learnings

- ✅ ECB mode is **deterministic** (same input → same output)
- ✅ Patterns in plaintext **leak through** ciphertext
- ✅ Enables **chosen-plaintext attacks**
- ❌ **Never use ECB mode**
- ✅ **Use CBC, GCM, or CTR mode with unique IVs**

---

## Exercise 5: Test Different Attack Vectors

**Objective**: Explore various cryptographic attack scenarios.

### Attack 1: Known-Plaintext Attack

1. You know alice encrypted her email: `alice@email.com`
2. Encrypt the same email yourself
3. Compare ciphertexts

**Result**: Identical! You can now identify this encrypted value anywhere.

### Attack 2: Brute Force DES (Conceptual)

**DES Key Space**: 2^56 = 72,057,594,037,927,936 keys

**Modern GPU Attack**:
```bash
# Hypothetical hashcat command for DES
hashcat -m 14000 -a 3 encrypted.txt ?a?a?a?a?a?a?a?a

# Expected time: ~22 hours on modern GPU cluster
# Cost: ~$100 in cloud computing
```

### Attack 3: Rainbow Table Generation

For MD5 without salt:

```bash
# Generate rainbow table (conceptual)
rtgen md5 loweralpha 1 7 0 2400 33554432 0

# Coverage: All lowercase passwords up to 7 characters
# Table size: ~10 GB
# Lookup time: Milliseconds
```

### 🎓 Key Learnings

- ✅ Weak crypto fails against **multiple attack vectors**
- ✅ Modern hardware makes old algorithms **trivial to break**
- ✅ Defense requires **strong algorithms + proper implementation**

---

## Exercise 6: Implement Secure Alternatives

**Objective**: Learn how to fix the vulnerabilities.

### Fix 1: Replace MD5 with bcrypt

**Vulnerable Code**:
```python
import hashlib

def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()
```

**Secure Code**:
```python
import bcrypt

def secure_hash(password):
    # bcrypt automatically generates salt
    salt = bcrypt.gensalt(rounds=12)  # Cost factor: 2^12 = 4096 iterations
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)
```

**Security Improvements**:
- ✅ Unique salt per password
- ✅ Computationally expensive (4096 iterations)
- ✅ Resistant to rainbow tables
- ✅ Resistant to brute force

### Fix 2: Replace DES with AES-GCM

**Vulnerable Code**:
```python
from Crypto.Cipher import DES

HARDCODED_KEY = b'MYKEY123'

def weak_encrypt(plaintext):
    cipher = DES.new(HARDCODED_KEY, DES.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), DES.block_size))
```

**Secure Code (Android)**:
```java
import android.security.keystore.KeyGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class SecureEncryption {
    private static final String KEY_ALIAS = "MyAppKey";
    
    // Generate key in Android KeyStore
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        );
        
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .build();
        
        keyGen.init(spec);
        return keyGen.generateKey();
    }
    
    // Encrypt with AES-GCM
    public static byte[] encrypt(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Generate random IV
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        
        // Return IV + ciphertext
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        
        return combined;
    }
}
```

**Security Improvements**:
- ✅ AES-256 (strong algorithm)
- ✅ GCM mode (authenticated encryption)
- ✅ Key in Android KeyStore (hardware-backed)
- ✅ Unique IV per encryption
- ✅ No hard-coded keys

### Fix 3: Use Secure Random

**Vulnerable Code**:
```python
import random

def weak_token():
    return str(random.randint(0, 999999))
```

**Secure Code**:
```python
import secrets

def secure_token():
    return secrets.token_urlsafe(32)  # 256-bit token
```

### 🎓 Key Learnings

- ✅ Use **bcrypt/Argon2** for password hashing
- ✅ Use **AES-256-GCM** for encryption
- ✅ Store keys in **KeyStore/Keychain**
- ✅ Use **SecureRandom/SecRandomCopyBytes** for random values
- ✅ **Never implement custom cryptography**

---

## Exercise 7: Penetration Testing Challenge

**Objective**: Apply all learned techniques in a realistic scenario.

### Scenario

You've obtained access to a mobile app database backup containing:
- 100 user accounts with MD5 hashes
- Encrypted credit card data (DES-ECB)
- Hard-coded encryption key in app source

### Your Tasks

1. **Crack 10+ passwords** from the MD5 hashes
2. **Extract the DES key** from source code
3. **Decrypt at least 5 credit cards**
4. **Document all findings**
5. **Propose fixes** for each vulnerability

### Success Criteria

- ✅ 10+ passwords cracked (60 seconds max)
- ✅ DES key extracted and verified
- ✅ 5+ credit cards decrypted correctly
- ✅ Complete remediation plan

### Report Template

```markdown
# Penetration Test Report

## Executive Summary
[Brief overview of findings]

## Vulnerabilities Identified
1. Weak Password Hashing (MD5)
   - Severity: CRITICAL
   - Impact: 100% of passwords crackable
   - Recommendation: Migrate to bcrypt

2. Deprecated Encryption (DES)
   - Severity: CRITICAL
   - Impact: All data decryptable
   - Recommendation: Upgrade to AES-256-GCM

3. Hard-Coded Keys
   - Severity: CRITICAL
   - Impact: Key extractable via reverse engineering
   - Recommendation: Use Android KeyStore

## Proof of Concept
[Screenshots and steps to reproduce]

## Remediation Plan
[Detailed fix implementation]

## Timeline
- Immediate: Disable affected features
- Week 1: Implement bcrypt password migration
- Week 2: Implement AES-256 with KeyStore
- Week 3: Security audit and testing
```

---

## Advanced Challenges

### Challenge 1: Timing Attack

Create a timing attack against constant-time password comparison:

```python
import time

def timing_attack(check_function, max_length=8):
    """Exploit timing differences to guess password"""
    password = ""
    charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    
    for position in range(max_length):
        max_time = 0
        best_char = None
        
        for char in charset:
            test_pass = password + char + "x" * (max_length - position - 1)
            
            start = time.perf_counter()
            check_function(test_pass)
            elapsed = time.perf_counter() - start
            
            if elapsed > max_time:
                max_time = elapsed
                best_char = char
        
        password += best_char
        print(f"Found: {password}")
    
    return password
```

### Challenge 2: Padding Oracle Attack

Implement a padding oracle attack against CBC mode encryption.

### Challenge 3: Key Derivation Weakness

Analyze weak key derivation and propose PBKDF2/Argon2 alternatives.

---

## Summary

### What You Learned

1. ✅ **MD5 is broken** - Instant cracks with rainbow tables
2. ✅ **DES is deprecated** - 56-bit keys brute-forceable
3. ✅ **Hard-coded keys are dangerous** - Easily extracted
4. ✅ **ECB mode leaks patterns** - Use GCM or CBC
5. ✅ **Secure alternatives exist** - bcrypt, AES-GCM, KeyStore

### Best Practices

| ❌ Vulnerable | ✅ Secure |
|--------------|-----------|
| MD5 passwords | bcrypt/Argon2 |
| DES encryption | AES-256-GCM |
| Hard-coded keys | KeyStore/Keychain |
| ECB mode | GCM/CBC modes |
| Math.random() | SecureRandom |
| No salt | Unique salt per password |

### Next Steps

1. **Review** [prevention.md](../../prevention.md) for implementation details
2. **Study** [examples.md](../../examples.md) for code patterns
3. **Explore** [attack-vectors.md](../../attack-vectors.md) for advanced techniques
4. **Practice** on real-world apps (with permission!)

---

## Resources

### Tools
- **Hashcat**: https://hashcat.net/hashcat/
- **John the Ripper**: https://www.openwall.com/john/
- **CrackStation**: https://crackstation.net/
- **CyberChef**: https://gchq.github.io/CyberChef/

### Documentation
- **OWASP Cryptographic Storage**: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- **NIST Cryptographic Standards**: https://csrc.nist.gov/publications
- **Android Keystore**: https://developer.android.com/training/articles/keystore
- **iOS Keychain**: https://developer.apple.com/documentation/security/keychain_services

### Further Reading
- **Cryptography I (Coursera)**: Dan Boneh's Stanford course
- **Applied Cryptography**: Bruce Schneier
- **Crypto 101**: Free cryptography book

---

## Troubleshooting

### Lab Won't Start
```bash
# Check if port 5000 is available
lsof -i :5000

# Rebuild containers
docker-compose down
docker-compose up --build
```

### Database Issues
```bash
# Remove old database
rm app/crypto.db

# Restart application
docker-compose restart
```

### Cracking Tools
```bash
# Install hashcat (Ubuntu/Debian)
sudo apt install hashcat

# Install John the Ripper
sudo apt install john

# Download rockyou wordlist
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

---

**Congratulations!** You've completed the M10: Insufficient Cryptography lab. You now understand the critical importance of strong cryptography in mobile security.

**Remember**: These vulnerabilities are common in real-world applications. Always use strong, modern cryptographic practices!
