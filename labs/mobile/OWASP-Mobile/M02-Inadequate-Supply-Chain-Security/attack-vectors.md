# M02: Inadequate Supply Chain Security - Attack Vectors

## Table of Contents
- [Understanding Supply Chain Attacks](#understanding-supply-chain-attacks)
- [Attack Vector Categories](#attack-vector-categories)
- [Attack Scenarios](#attack-scenarios)
- [Attack Chain Analysis](#attack-chain-analysis)
- [Exploitation Techniques](#exploitation-techniques)
- [Detection Indicators](#detection-indicators)

## Understanding Supply Chain Attacks

Supply chain attacks exploit the trust relationship between mobile applications and their dependencies. Rather than attacking the application directly, attackers compromise components that the application depends on.

### The Trust Chain

```
Developer → Package Registry → Build System → App Store → User Device
     ↓           ↓                  ↓              ↓            ↓
  Trusts      Trusts            Trusts        Trusts       Trusts
     ↓           ↓                  ↓              ↓            ↓
Any compromise in this chain affects everyone downstream
```

## Attack Vector Categories

### 1. Malicious Package Injection

**Typosquatting Attack**
- Attacker creates package with name similar to popular library
- Developers accidentally install wrong package
- Example: `react-native` vs `react-natve`

**Dependency Confusion**
- Exploits package manager behavior with internal vs public packages
- Attacker publishes package with internal name on public registry
- Build system installs malicious public version instead of internal

**Brandjacking**
- Using trusted brand names to create deceptive packages
- "facebook-sdk-unofficial" appearing legitimate
- Developers trust the name association

### 2. Legitimate Package Compromise

**Account Takeover**
- Attacker compromises maintainer account credentials
- Publishes malicious update to legitimate package
- All apps auto-updating receive infected version

**Repository Injection**
- Compromising source code repositories
- Injecting malicious code through pull requests
- Social engineering maintainers to merge malicious code

**Build System Compromise**
- Attacking CI/CD pipelines
- Injecting malicious code during build process
- Published package differs from source code

### 3. Transitive Dependency Attacks

**Deep Dependency Exploitation**
- Targeting obscure dependencies deep in dependency tree
- Less scrutiny on packages few developers directly interact with
- Example: Popular package depends on 50+ libraries, one is compromised

**Dependency Confusion Chain**
- Compromising low-level dependencies
- Malicious code propagates up dependency chain
- Affects thousands of apps indirectly

### 4. Abandoned Package Exploitation

**Package Takeover**
- Identifying abandoned but widely-used packages
- Social engineering to gain maintainer access
- Publishing "update" with malicious payload

**Namespace Squatting**
- Registering package names before projects claim them
- Waiting for developers to make assumptions about official packages
- Serving malicious code to unsuspecting developers

### 5. SDK and Framework Attacks

**Third-Party SDK Compromise**
- Analytics, advertising, or social media SDKs infected
- Automatic updates push malicious code
- Widespread impact across many applications

**Framework Backdoors**
- Compromising development frameworks
- All apps built with framework are vulnerable
- Long-term persistent access

## Attack Scenarios

### Scenario 1: The Typosquatting Trap

```
Attack Flow:
1. Attacker researches popular packages (e.g., "axios" - HTTP client)
2. Creates similar package "axois" with malicious code
3. Developer makes typo during installation
4. Package installed in project
5. Malicious code exfiltrates environment variables
6. API keys and secrets stolen
7. Attacker accesses backend systems
```

**Impact**: Credential theft, backend compromise, data breach

### Scenario 2: The Dependency Confusion Attack

```
Attack Flow:
1. Attacker discovers internal package name from error messages/job postings
2. Publishes package with same name to public npm/PyPI
3. Build system checks public registry first
4. Downloads malicious public package instead of internal
5. Malicious code executes in build environment
6. Source code and secrets exfiltrated
7. Supply chain fully compromised
```

**Impact**: Source code theft, credential exposure, backdoored releases

### Scenario 3: The Legitimate Package Hijack

```
Attack Flow:
1. Attacker identifies popular but under-maintained package
2. Social engineers way into maintainer team
3. Publishes malicious "security update"
4. Apps auto-update to compromised version
5. Malicious SDK collects user data
6. Data sent to attacker-controlled servers
7. Millions of users affected
```

**Impact**: Mass data collection, privacy violations, app store removal

### Scenario 4: The Build Tool Compromise

```
Attack Flow:
1. Attacker compromises developer's machine via phishing
2. Injects malicious plugin into build tool configuration
3. Plugin modifies compiled application during build
4. Backdoor inserted that's not in source code
5. App published with hidden malicious functionality
6. Source code reviews miss the compromise
7. Users install backdoored application
```

**Impact**: Backdoored applications, persistent access, undetectable compromise

## Attack Chain Analysis

### Phase 1: Reconnaissance

**Attacker Activities:**
- Identifying popular packages and their typo variants
- Discovering internal package names
- Finding vulnerable or abandoned projects
- Researching maintainer accounts and security practices

**Duration**: Days to months of preparation

### Phase 2: Compromise

**Attack Methods:**
- Publishing malicious packages
- Compromising maintainer accounts via credential theft
- Social engineering to gain commit access
- Exploiting build system vulnerabilities

**Duration**: Minutes to hours for execution

### Phase 3: Distribution

**Propagation:**
- Developers install compromised packages
- CI/CD systems auto-download malicious dependencies
- Package updates push malicious code to existing installations
- App updates distribute compromised code to users

**Duration**: Hours to days for widespread distribution

### Phase 4: Exploitation

**Malicious Actions:**
- Exfiltrating credentials and API keys
- Collecting user data (contacts, location, messages)
- Installing additional malware
- Creating backdoors for persistent access
- Cryptocurrency mining

**Duration**: Continuous until detected

### Phase 5: Persistence

**Maintaining Access:**
- Backdoors in multiple dependencies
- Compromised build pipelines
- Account access for future updates
- Distributed across app ecosystem

**Duration**: Months to years if undetected

## Exploitation Techniques

### 1. Data Exfiltration

```
Conceptual Approach:
- Malicious dependency collects sensitive data
- Encodes data to avoid detection
- Sends to attacker-controlled endpoint
- Uses legitimate-looking traffic patterns
```

**What Gets Stolen:**
- Environment variables with API keys
- User authentication tokens
- Personal user data
- Application source code
- Build artifacts and certificates

### 2. Backdoor Installation

```
Conceptual Approach:
- Inject remote code execution capability
- Establish command and control channel
- Hide communication in normal traffic
- Enable future arbitrary code execution
```

**Capabilities Enabled:**
- Remote control of application behavior
- Dynamic payload delivery
- Credential harvesting
- Lateral movement to backend systems

### 3. Supply Chain Poisoning

```
Conceptual Approach:
- Compromise one package in dependency tree
- Malicious code spreads to dependent packages
- Creates cascading compromise
- Difficult to trace origin
```

**Spread Pattern:**
- Direct dependencies affected immediately
- Transitive dependencies over time
- Ecosystem-wide contamination possible

## Detection Indicators

### Technical Indicators

**Package Anomalies:**
- Unexpected network connections during build
- New dependencies appearing in package-lock files
- Changes in package checksums or hashes
- Unusual permissions requested by SDKs

**Code Indicators:**
- Obfuscated code in dependencies
- Base64-encoded strings (potential payload hiding)
- Dynamic code evaluation (eval, Function constructor)
- Suspicious network requests to unknown domains

**Behavioral Indicators:**
- Build times suddenly increase
- Unexpected files in build output
- Environment variables accessed by libraries
- New outbound network connections

### Process Indicators

**Development Environment:**
- Unfamiliar packages in node_modules
- Unexpected package updates
- Lock file modifications without explicit updates
- Build warnings about deprecated or vulnerable packages

**Runtime Indicators:**
- Unexpected API calls from app
- Data sent to unknown endpoints
- Increased battery or data usage
- Crashes or performance degradation

## Defense Strategies Preview

While detailed defenses are covered in the Prevention guide, key detection strategies include:

1. **Dependency Scanning**: Automated vulnerability detection
2. **Integrity Verification**: Checksum and signature validation
3. **SBOM Maintenance**: Complete dependency inventory
4. **Network Monitoring**: Detecting unusual build-time connections
5. **Code Review**: Manual inspection of critical dependencies

## Risk Assessment

### High-Risk Scenarios

- Installing packages from unknown authors
- Auto-updating dependencies without review
- Using deprecated or unmaintained packages
- No dependency integrity verification
- Lack of SBOM or dependency tracking

### Medium-Risk Scenarios

- Using popular packages without version pinning
- Transitive dependencies not regularly audited
- Build processes without network restrictions
- Limited code review of dependency updates

### Lower-Risk Scenarios

- Pinned dependencies with manual update reviews
- Comprehensive dependency scanning
- Network-restricted build environments
- Regular security audits of dependency chain

## Key Takeaways

1. **Supply chain attacks exploit trust relationships in development**
2. **A single compromised dependency can affect millions of users**
3. **Attacks can occur at multiple points: registry, build, runtime**
4. **Detection requires both automated tools and manual vigilance**
5. **Defense must be proactive, not reactive**

## Next Steps

- **[Prevention Guide](./prevention.md)**: Learn how to secure your supply chain
- **[Examples](./examples.md)**: See vulnerable vs secure dependency practices
- **[Interactive Lab](./lab/)**: Practice identifying supply chain vulnerabilities

---

**Remember**: In supply chain security, paranoia is a feature, not a bug.
