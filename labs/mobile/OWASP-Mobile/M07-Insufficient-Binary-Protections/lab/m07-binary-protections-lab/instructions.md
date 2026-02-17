# M07: Insufficient Binary Protections - Lab Instructions

## Introduction

Welcome to the hands-on investigation of binary protection vulnerabilities! This lab will guide you through discovering and understanding how insufficient binary protections expose mobile applications to reverse engineering, tampering, and exploitation.

**Your Role**: You are a security researcher conducting a security assessment of a mobile banking application. Your task is to identify binary protection weaknesses that could be exploited by attackers.

**Learning Approach**: This is a discovery-based lab. Each phase builds on the previous one, revealing progressively more sophisticated vulnerabilities.

---

## Lab Structure

This lab is divided into **5 phases**:

1. **Phase 1**: Code Decompilation Analysis (15 minutes)
2. **Phase 2**: Integrity and Tampering Detection (10 minutes)
3. **Phase 3**: Debug Mode and Information Disclosure (10 minutes)
4. **Phase 4**: Environment Security Assessment (10 minutes)
5. **Phase 5**: Memory Analysis and Comprehensive Review (10 minutes)

**Total Estimated Time**: 45-60 minutes

---

## Getting Started

### Prerequisites Check

Before beginning, ensure:
- ✅ Docker container is running (`docker-compose ps`)
- ✅ Lab accessible at http://localhost:5107
- ✅ You have reviewed the README.md
- ✅ You have basic understanding of mobile app architecture

### Initial Reconnaissance

1. Open your browser and navigate to: **http://localhost:5107**
2. Observe the main interface - note the 6 demonstration sections
3. Read the warning banner at the top
4. Don't click anything yet - we'll explore systematically

---

## Phase 1: Code Decompilation Analysis

### Objective

Understand how lack of code obfuscation exposes application internals, business logic, and hardcoded secrets.

### Background

Mobile applications are distributed as compiled binaries (APK for Android, IPA for iOS). Without proper obfuscation, these binaries can be easily decompiled back to readable source code using free tools like jadx (Android) or Hopper (iOS).

### Exercise 1.1: Analyze Decompiled Code

1. **Locate the "Decompilation Simulator" card** on the main page

2. **Click "Analyze Binary"** button

3. **Observe the output** - you should see:
   - Decompiled class name
   - Method names and their logic
   - Variable names
   - Hardcoded values

### Questions to Consider

❓ **Q1.1**: What class name and method names do you see? Are they meaningful (e.g., `PaymentProcessor`, `validateCard`) or obfuscated (e.g., `a`, `b`, `c`)?

❓ **Q1.2**: Look at the decompiled code. Can you understand what the application does just from reading it?

❓ **Q1.3**: Are there any hardcoded values visible in the code? What are they?

❓ **Q1.4**: If you were an attacker, what information could you extract from this decompiled code?

### Exercise 1.2: Identify Hardcoded Secrets

Look carefully at the decompiled output:

1. **Find API keys** - Look for strings starting with `sk_`, `pk_`, or containing "api_key"
2. **Locate endpoints** - Find any URLs (http://, https://)
3. **Discover algorithms** - Identify validation logic or encryption methods
4. **Note comments** - Any developer comments that reveal intentions

### Expected Findings

You should discover:
- ❌ **CRITICAL**: API keys in plaintext (Stripe, AWS, etc.)
- ❌ **HIGH**: Server endpoints exposed
- ❌ **HIGH**: Business logic completely visible
- ❌ **MEDIUM**: Algorithm implementation details
- ❌ **MEDIUM**: Database schemas or data structures

### Real-World Context

```
Attack Scenario:
1. Attacker downloads your app from Play Store
2. Runs: jadx yourapp.apk (takes 30 seconds)
3. Searches for: "api", "key", "secret", "password"
4. Finds: STRIPE_API_KEY = "sk_live_xyz123..."
5. Uses key: Conducts fraudulent transactions
6. Your bill: $50,000 in unauthorized charges
```

### Reflection

✍️ **Document**: List all sensitive information you found in the decompiled code.

✍️ **Risk Assessment**: For each finding, rate the risk level (Critical/High/Medium/Low).

✍️ **Mitigation**: How would you protect this information? (Hint: Think obfuscation, encryption, server-side logic)

---

## Phase 2: Integrity and Tampering Detection

### Objective

Understand how applications detect (or fail to detect) code tampering and repackaging.

### Background

Without integrity checks, attackers can:
- Modify application code (bypass premium checks)
- Inject malicious code (steal credentials)
- Repackage and redistribute (malware distribution)
- Remove security checks (disable protections)

### Exercise 2.1: Test Tampering Detection

1. **Locate the "Tampering Detector" card**

2. **Click "Check Integrity"** button

3. **Observe the results**:
   - Does the app detect it's been modified?
   - Is signature verification working?
   - What integrity checks are (or aren't) in place?

### Questions to Consider

❓ **Q2.1**: Does the application report that it's tampered or legitimate?

❓ **Q2.2**: What specific integrity checks are mentioned (if any)?

❓ **Q2.3**: If you click "Simulate Tampering", what happens? Does the app detect it?

❓ **Q2.4**: What would happen in a real scenario if tampering goes undetected?

### Exercise 2.2: Understand Signature Verification

Click **"Check Signature"** to see certificate information:

1. **Observe the signature details**
2. **Note whether validation is actually performed**
3. **Check if the signature matches expected values**

### Expected Findings

You should discover:
- ❌ **CRITICAL**: No signature verification implemented
- ❌ **HIGH**: Signature checked but not enforced
- ❌ **HIGH**: No checksum validation of code files
- ❌ **MEDIUM**: Tampering simulation succeeds without detection

### Real-World Attack

```
Repackaging Attack:
1. Decompile legitimate banking app
2. Inject code to steal credentials:
   - Hook login function
   - Send username/password to attacker's server
3. Repackage and sign with debug certificate
4. Distribute via third-party store or phishing
5. Users install, thinking it's legitimate
6. 5,000 users compromised before detection
7. $2M in fraudulent transactions
```

### Reflection

✍️ **Impact Analysis**: What could an attacker achieve if they successfully repackage your app?

✍️ **Detection Strategy**: What mechanisms should be in place to detect tampering?

✍️ **Response Plan**: If tampering is detected, what should the app do?

---

## Phase 3: Debug Mode and Information Disclosure

### Objective

Identify debugging-related vulnerabilities that expose sensitive information and enable real-time manipulation.

### Background

Production applications should NEVER have debugging enabled. Debug mode allows:
- Debugger attachment (breakpoints, variable inspection)
- Verbose logging (credentials in logcat)
- Additional APIs (debug endpoints)
- Reduced security constraints

### Exercise 3.1: Check Debug Status

1. **Locate the "Debug Mode Checker" card**

2. **Click "Check Debug Status"** button

3. **Analyze the output**:
   - Is debugging enabled?
   - What debug flags are set?
   - What information is being logged?

### Questions to Consider

❓ **Q3.1**: Is the application in debug mode? What specific flags indicate this?

❓ **Q3.2**: Look at the "Debug Information Exposed" section. What sensitive data is visible?

❓ **Q3.3**: Can you find any API keys, tokens, or credentials in the debug output?

❓ **Q3.4**: If debugging is enabled, what could an attacker do with a debugger?

### Exercise 3.2: Analyze Verbose Logging

Click **"View Debug Logs"**:

1. **Review all log entries**
2. **Identify sensitive data** (look for passwords, tokens, API keys)
3. **Note security-relevant events** (authentication, permissions, etc.)

### Expected Findings

You should discover:
- ❌ **CRITICAL**: Debuggable flag set to `true`
- ❌ **CRITICAL**: API keys and secrets in logs
- ❌ **HIGH**: User credentials logged
- ❌ **HIGH**: Session tokens visible
- ❌ **MEDIUM**: Detailed stack traces
- ❌ **MEDIUM**: Internal API endpoints exposed

### Real-World Example

```
Debug Mode Exploitation:
1. Attacker verifies app is debuggable:
   $ adb shell dumpsys package com.bank.app | grep debuggable
   debuggable=true
   
2. Attacker attaches debugger:
   $ adb shell am set-debug-app -w com.bank.app
   $ jdb -attach localhost:8700
   
3. Sets breakpoint on login method:
   > stop in LoginActivity.performLogin
   
4. User attempts to login
   
5. Breakpoint hits, attacker inspects:
   > locals
   username = "victim@email.com"
   password = "SecretPass123!"
   
6. Credentials stolen without network interception!
```

### Reflection

✍️ **Log Review**: List all sensitive data you found in debug logs.

✍️ **Attack Surface**: How does debug mode increase the attack surface?

✍️ **Prevention**: What should be done before releasing to production?

---

## Phase 4: Environment Security Assessment

### Objective

Evaluate the application's ability to detect compromised device environments (rooted Android, jailbroken iOS).

### Background

On rooted/jailbroken devices:
- All app-level protections can be bypassed
- Frida/Xposed can hook any function
- Certificate pinning can be disabled
- File system is fully accessible
- Security boundaries don't exist

### Exercise 4.1: Test Root Detection

1. **Locate the "Root Detection Demo" card**

2. **Click "Detect Root"** button

3. **Observe the detection results**:
   - What detection methods are used?
   - Are they effective?
   - Can they be bypassed?

### Questions to Consider

❓ **Q4.1**: Does the application detect root/jailbreak? What methods does it use?

❓ **Q4.2**: How many root detection checks are performed?

❓ **Q4.3**: Click "Simulate Root Bypass" - does the detection get fooled?

❓ **Q4.4**: What should the app do when running on a rooted device?

### Exercise 4.2: Evaluate Detection Methods

The app should check for:
- ✅ `su` binary presence
- ✅ Root management apps (Magisk, SuperSU)
- ✅ Writable system directories
- ✅ Test-keys build tags
- ✅ SafetyNet/Play Integrity

**Task**: Click "Show Detection Methods" and verify which are implemented.

### Expected Findings

You should discover:
- ❌ **HIGH**: No root detection implemented
- ❌ **HIGH**: Single detection method (easily bypassed)
- ❌ **MEDIUM**: Detection present but not enforced
- ❌ **MEDIUM**: No SafetyNet/Play Integrity check
- ⚠️ **INFO**: Detection can be bypassed with Frida

### Real-World Bypass

```
Root Detection Bypass with Frida:
// Frida script to bypass all root checks
Java.perform(function() {
    // Bypass file existence checks
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.includes('su') || path.includes('Superuser')) {
            return false;  // Lie: file doesn't exist
        }
        return this.exists();
    };
    
    // Bypass package manager checks
    var PackageManager = Java.use('android.content.pm.PackageManager');
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
        if (pkg === 'com.topjohnwu.magisk' || pkg === 'eu.chainfire.supersu') {
            throw 'Package not found';  // Lie: not installed
        }
        return this.getPackageInfo(pkg, flags);
    };
    
    console.log('[+] Root detection bypassed!');
});

// Run with: frida -U -f com.bank.app -l bypass.js
// Result: App thinks device is NOT rooted
```

### Reflection

✍️ **Detection Gaps**: What root detection methods are missing?

✍️ **Bypass Resistance**: How could the detection be made harder to bypass?

✍️ **Policy Decision**: Should the app exit, warn, or disable features on rooted devices?

---

## Phase 5: Memory Analysis and Comprehensive Review

### Objective

Understand how sensitive data exposure in memory enables attacks, and conduct a comprehensive security assessment.

### Background

Even with strong network security, sensitive data in application memory can be:
- Dumped using debuggers or memory tools
- Extracted via memory scanning (GameGuardian, Cheat Engine)
- Harvested by malware on rooted devices
- Captured in crash dumps or screenshots

### Exercise 5.1: Memory Dump Analysis

1. **Locate the "Memory Viewer" card**

2. **Click "Dump Memory"** button

3. **Analyze the memory contents**:
   - What sensitive data is visible?
   - Is encryption being used?
   - Are credentials stored in memory?

### Questions to Consider

❓ **Q5.1**: What types of sensitive data are found in memory?

❓ **Q5.2**: Are API keys, tokens, or passwords visible in plaintext?

❓ **Q5.3**: How long does sensitive data remain in memory?

❓ **Q5.4**: What encryption or obfuscation is (or isn't) applied to memory?

### Exercise 5.2: Search for Specific Secrets

Use the "Search Memory" feature:

1. Search for: **"password"**
2. Search for: **"token"**
3. Search for: **"api_key"**
4. Search for: **"secret"**

**Document all findings**.

### Expected Findings

You should discover:
- ❌ **CRITICAL**: API keys in plaintext in memory
- ❌ **CRITICAL**: User passwords stored without protection
- ❌ **HIGH**: Session tokens accessible
- ❌ **HIGH**: Encryption keys stored insecurely
- ❌ **MEDIUM**: PII (names, emails, addresses) in clear text

### Exercise 5.3: Comprehensive Security Analysis

1. **Locate the "Protection Analyzer" card**

2. **Click "Run Full Analysis"** button

3. **Review the comprehensive report**:
   - Overall security score
   - Specific vulnerabilities identified
   - Risk ratings
   - Recommended fixes

### Questions to Consider

❓ **Q5.5**: What is the overall security score? What does it mean?

❓ **Q5.6**: Which vulnerability category has the most issues?

❓ **Q5.7**: What are the top 3 most critical findings?

❓ **Q5.8**: If this were a real application, what should be prioritized first?

### Real-World Memory Attack

```
Memory Dumping Attack:
1. Attacker installs GameGuardian on rooted device
2. Opens banking app, navigates to balance screen
3. GameGuardian scans memory for values:
   - Current balance: $1,234.56
   - Searches for floating point: 1234.56
   - Finds memory address: 0x7b8a3f00
   
4. Also finds nearby in memory:
   - Account number: 1234567890
   - Auth token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   - API endpoint: https://api.bank.com/v1/
   
5. Attacker now has:
   - Valid session token
   - Account details
   - API endpoint
   
6. Can replay requests to:
   - View transaction history
   - Initiate transfers
   - Access sensitive account data
```

### Reflection

✍️ **Comprehensive Assessment**: Summarize all vulnerabilities found across all phases.

✍️ **Risk Prioritization**: Rank findings from most to least critical.

✍️ **Remediation Plan**: For each critical finding, propose a specific fix.

---

## Summary and Conclusions

### What You've Learned

Congratulations! You've completed a comprehensive binary protection security assessment. You should now understand:

1. ✅ **Decompilation Risks**: How easily code can be reverse engineered without obfuscation
2. ✅ **Tampering Threats**: The importance of integrity checks and signature verification
3. ✅ **Debug Dangers**: Why production apps must never have debugging enabled
4. ✅ **Environment Security**: The critical need for root/jailbreak detection
5. ✅ **Memory Exposure**: How sensitive data in memory can be extracted
6. ✅ **Defense in Depth**: Why multiple protection layers are necessary

### Key Takeaways

**Critical Vulnerabilities Found:**
- No code obfuscation → Business logic exposed
- No signature verification → Repackaging possible
- Debug mode enabled → Real-time manipulation possible
- No root detection → All protections can be bypassed
- Secrets in memory → Easy extraction

**Why This Matters:**
- **Financial Impact**: API key exposure can cost $10,000-$100,000+
- **Intellectual Property**: Algorithms and business logic stolen by competitors
- **User Safety**: Repackaged apps can steal credentials
- **Compliance**: PCI-DSS, HIPAA require binary protections
- **Reputation**: Security breaches damage user trust

### Recommended Next Steps

1. **Review Prevention Guide**: Study `../prevention.md` for secure implementation patterns
2. **Examine Code Examples**: Check `../examples.md` for vulnerable vs. secure code
3. **Understand Attack Vectors**: Read `../attack-vectors.md` to think like an attacker
4. **Implement Protections**: Apply these learnings to your own applications

### Security Best Practices Checklist

Based on this lab, ensure your applications:

- [ ] **Enable ProGuard/R8** with comprehensive obfuscation rules
- [ ] **Remove all hardcoded secrets** (API keys, passwords, tokens)
- [ ] **Disable debugging** in production builds (`debuggable=false`)
- [ ] **Implement signature verification** on app startup
- [ ] **Add root/jailbreak detection** with appropriate response
- [ ] **Use KeyStore/Keychain** for sensitive data storage
- [ ] **Implement certificate pinning** for all network communications
- [ ] **Clear sensitive data** from memory when no longer needed
- [ ] **Remove all Log.d/NSLog** debug statements
- [ ] **Conduct penetration testing** before major releases

### Additional Resources

**Tools to Try** (on your own test apps):
- **jadx**: Android APK decompiler
- **Hopper**: iOS IPA disassembler
- **MobSF**: Mobile Security Framework (automated scanning)
- **Frida**: Dynamic instrumentation toolkit
- **APKTool**: APK decompilation and repackaging

**Further Reading:**
- OWASP Mobile Application Security Verification Standard (MASVS)
- OWASP Mobile Security Testing Guide (MSTG)
- Android Security Best Practices
- iOS Security Guide

---

## Lab Completion

### Self-Assessment

Rate your understanding (1-5 scale):

- [ ] Understanding of decompilation and reverse engineering: ___/5
- [ ] Knowledge of tampering detection techniques: ___/5
- [ ] Awareness of debug mode risks: ___/5
- [ ] Understanding of root/jailbreak detection: ___/5
- [ ] Knowledge of memory security: ___/5
- [ ] Ability to implement binary protections: ___/5

### Feedback

Help us improve this lab:

- What was most valuable? ______________________
- What was confusing? ______________________
- What should we add? ______________________
- Overall rating: ___/5

---

## Next Module

Once you've completed this lab:
1. Stop the environment: `docker-compose down`
2. Review the other M0X modules in the OWASP Mobile Top 10
3. Practice implementing protections in a test application
4. Share your learnings with your development team

**Great work completing the Insufficient Binary Protections lab!** 🎉

The knowledge you've gained here is critical for building secure mobile applications. Remember: defense in depth, continuous testing, and staying updated on the latest threats are keys to mobile application security.
