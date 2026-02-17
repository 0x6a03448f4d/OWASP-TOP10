# Lab Instructions: Cryptographic Failures - Weak Hashing

## Introduction

Welcome to the Cryptographic Failures lab! In this hands-on exercise, you'll learn why certain hashing algorithms are unsuitable for password storage and discover the proper way to protect user passwords.

**Time Required**: 20-30 minutes  
**Difficulty**: Beginner

## Learning Path

This lab follows a structured approach:
1. **Understand** - Learn about different hashing algorithms
2. **Compare** - See the differences in action
3. **Analyze** - Understand the security implications
4. **Apply** - Learn best practices

---

## Part 1: Setup and Initial Exploration (5 minutes)

### Task 1.1: Start the Lab

```bash
# Navigate to the lab directory
cd OWASP-Web/02-Cryptographic-Failures/lab/weak-hashing-lab/

# Start the application
docker-compose up
```

**Expected Output**: You should see:
```
Application running on http://localhost:5001
This is a SAFE EDUCATIONAL ENVIRONMENT
```

### Task 1.2: Access the Interface

1. Open your browser to **http://localhost:5001**
2. Observe the interface:
   - Hash Comparison Tool (left panel)
   - Understanding the Differences (right panel)
   - Key Learning Points (bottom)

**Questions to Consider**:
- What are the three hashing algorithms shown?
- Which one is marked as "Secure"?
- What's the default test password?

---

## Part 2: Exploring Hash Algorithms (10 minutes)

### Task 2.1: Test MD5 Hashing

1. Keep the default password: `SecurePass2023!`
2. Click the **"MD5 (Weak)"** button
3. Observe the results:
   - What's the hash value?
   - How long did it take?
   - What security level is shown?

**Key Observations**:
```
Algorithm: MD5
Time: < 1 millisecond (extremely fast)
Security Level: INSECURE
Rainbow Table Vulnerable: YES
```

**Why This Matters**:
- Modern GPUs can compute **billions** of MD5 hashes per second
- A 8-character password can be cracked in **hours**
- No salt means same password = same hash everywhere

### Task 2.2: Test SHA-256 Hashing

1. Click the **"SHA-256 (Weak)"** button
2. Compare with MD5:
   - Is it faster or slower than MD5?
   - Is the hash longer?
   - Is it secure for passwords?

**Key Observations**:
```
Algorithm: SHA-256
Time: Still < 1 millisecond
Security Level: WEAK FOR PASSWORDS
Use Case: Data integrity, NOT passwords
```

**Important Distinction**:
- SHA-256 is **stronger** than MD5
- But still **too fast** for password hashing
- Designed for checksums, not password protection

### Task 2.3: Test bcrypt Hashing

1. Click the **"bcrypt (Secure)"** button
2. Compare with previous algorithms:
   - How much slower is it?
   - Does the hash include the salt?
   - What's the security level?

**Key Observations**:
```
Algorithm: bcrypt
Time: 50-100+ milliseconds (intentionally slow)
Security Level: SECURE
Built-in Salt: YES (automatic)
Brute Force Resistant: YES
```

**Why This Is Better**:
- **Slow by design**: Makes brute force impractical
- **Automatic salting**: Each hash is unique
- **Adjustable cost**: Can increase difficulty over time

### Task 2.4: Compare All Algorithms

1. Click the **"Compare All Algorithms"** button
2. Examine the side-by-side comparison
3. Notice:
   - Time differences
   - Hash formats
   - Security levels

**Expected Results**:
```
MD5:      ~0.1 ms   (INSECURE)
SHA-256:  ~0.1 ms   (WEAK)
bcrypt:   ~50 ms    (SECURE)
```

---

## Part 3: Understanding the Security Impact (5 minutes)

### Task 3.1: Calculate Brute Force Time

With the comparison results, calculate approximate brute force times:

**For MD5 (assuming 1 million hashes per second)**:
```
8-character password (lowercase+numbers):
36^8 = 2,821,109,907,456 possibilities
At 1 million/sec = ~32 days

With GPU (10 billion/sec) = ~47 minutes!
```

**For bcrypt (10 rounds, ~100ms per hash)**:
```
Same 8-character password:
At 10 hashes/sec = ~8,948 YEARS

Much more secure!
```

### Task 3.2: Understanding Rainbow Tables

1. Review the "Understanding the Differences" panel
2. Read about MD5's vulnerability to rainbow tables

**Concept**:
- Rainbow tables = Precomputed hash lookups
- Without salt: One table cracks all users
- With salt: Need unique table per user (impractical)

### Task 3.3: Review the Comparison Table

Scroll down to "Key Learning Points" table and review:
- Speed comparison
- Salt implementation
- Purpose of each algorithm
- Rainbow table vulnerability
- Brute force resistance

---

## Part 4: Testing with Different Passwords (5 minutes)

### Task 4.1: Test Common Passwords

Try these common passwords and observe the MD5 hashes:

1. `password` - MD5: `5f4dcc3b5aa765d61d8327deb882cf99`
2. `admin` - MD5: `21232f297a57a5a743894a0e4a801fc3`
3. `123456` - MD5: `e10adc3949ba59abbe56e057f20f883e`

**Search these hashes online** (e.g., on crackstation.net)

**What This Proves**:
- MD5 hashes are publicly known for common passwords
- Rainbow tables make cracking instant
- This is why salting is critical

### Task 4.2: Same Password, Different bcrypt Hashes

1. Enter password: `test123`
2. Click "bcrypt (Secure)" - note the hash
3. Click it again - note the NEW hash
4. Click once more - note ANOTHER different hash

**Key Insight**:
- Same password = Different bcrypt hashes every time
- Why? Built-in random salt!
- Rainbow tables are useless against bcrypt

---

## Part 5: Understanding the Code (5 minutes)

### Task 5.1: Review the Vulnerable Code

Open `app/server.py` and locate the MD5 endpoint:

```python
@app.route('/hash/md5', methods=['POST'])
def hash_md5():
    password = data.get('password', '')
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    # PROBLEM: Too fast, no salt!
```

**Identify the Issues**:
1. No salt added
2. Fast algorithm
3. Same password = same hash

### Task 5.2: Review the Secure Code

Find the bcrypt endpoint:

```python
@app.route('/hash/bcrypt', methods=['POST'])
def hash_bcrypt():
    password = data.get('password', '')
    salt = bcrypt.gensalt(rounds=10)  # Auto-generated salt
    bcrypt_hash = bcrypt.hashpw(password.encode(), salt)
```

**Identify the Improvements**:
1. ✅ Automatic salt generation
2. ✅ Slow algorithm (10 rounds)
3. ✅ Same password = different hash each time

---

## Part 6: Key Takeaways and Best Practices

### What You Learned

✅ **MD5 and SHA-256 are INSECURE for passwords**
- Too fast to compute
- Vulnerable to GPU brute force
- Rainbow tables effective without salt

✅ **bcrypt is the CORRECT choice**
- Intentionally slow (adjustable)
- Built-in automatic salting
- Industry standard

✅ **Speed is BAD for password hashing**
- Slower = More secure
- Recommended: 12-14 bcrypt rounds in production

### Best Practices Checklist

- [ ] Use bcrypt, Argon2, or scrypt for passwords
- [ ] NEVER use MD5, SHA-1, or plain SHA-256 for passwords
- [ ] Use at least 12 rounds for bcrypt in production
- [ ] Never store passwords in plaintext
- [ ] Never log passwords (even hashed ones)
- [ ] Use cryptographically secure random for salts

### Production Implementation

```python
# CORRECT password hashing
import bcrypt

def hash_password(password: str) -> bytes:
    """Hash password with bcrypt"""
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds minimum
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password: str, hashed: bytes) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed)
```

---

## Clean Up

When you're done with the lab:

```bash
# Stop the containers
docker-compose down

# Remove volumes (optional)
docker-compose down -v
```

---

## Next Steps

1. ✅ Review the **[Prevention Guide](../../prevention.md)** for more best practices
2. ✅ Study the **[Examples](../../examples.md)** for additional patterns
3. ✅ Apply these lessons to your own projects
4. ✅ Move on to the next OWASP Top 10 category

---

## Questions for Reflection

1. Why is speed a bad characteristic for password hashing?
2. How do salts prevent rainbow table attacks?
3. What's the recommended number of bcrypt rounds for production?
4. Why can't you "decrypt" a password hash?
5. When SHOULD you use SHA-256? (Hint: data integrity, not passwords)

---

## Additional Resources

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [bcrypt Documentation](https://github.com/pyca/bcrypt/)
- [Argon2 - Password Hashing Competition Winner](https://github.com/P-H-C/phc-winner-argon2)

---

**Congratulations!** You've completed the Cryptographic Failures lab. You now understand why proper password hashing is critical for application security.

*Part of the [OWASP Top 10 Educational Repository](../../../../../README.md)*
