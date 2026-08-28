# Software and Data Integrity Failures - Attack Vectors

## Table of Contents

- [Understanding Integrity Attack Vectors](#understanding-integrity-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Integrity Failures](#chaining-integrity-failures)

## Understanding Integrity Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in systems you own or are authorised to test.

Integrity attacks do not break cryptography—they exploit the **absence of a check**. The attacker's move is to get their code or data accepted somewhere along the path from author to execution, at a point where the victim performs no verification. Because that path is long (developer → repo → build → registry → CDN → update → runtime), there are many places to insert a substitution, and one successful insertion can propagate to every downstream consumer.

The attacker's goal in this category is usually one of:

- Get malicious code accepted as if it were genuine (dependency, plugin, build output, or update).
- Get untrusted bytes deserialized into live behavior (code execution via object graphs).
- Get tampered data trusted as authoritative (client-held state, unverified tokens).

### Core Attack Flow

```
1. Locate the trust boundary with no verification
   ↓
   A dependency without a pinned hash? An update without a signature?
   A deserializer fed by user input? A cookie trusted without an HMAC?
2. Position the payload
   ↓
   Publish a package, compromise a build step, sit on the update channel,
   craft a serialized gadget, or edit the client-held value
3. Get it accepted
   ↓
   The victim installs / builds / updates / deserializes / trusts it
   WITHOUT comparing against a trusted signature or hash
4. Execute / escalate / exfiltrate
   ↓
   Run code, install a backdoor, or rewrite an authorization decision
```

## Common Attack Patterns

### 1. Dependency Substitution via Typosquatting

The attacker publishes a package whose name is a near-miss of a popular one and waits for a developer to mistype it or copy a bad tutorial.

```
# Intended
npm install react-router-dom

# Attacker registered a look-alike; a typo installs it
npm install react-router-domm     # malicious package runs its install script
```

Malicious packages commonly abuse lifecycle install hooks to run code the moment they are installed:

```json
// package.json in the malicious package
{
  "name": "react-router-domm",
  "scripts": { "postinstall": "node ./steal-env.js" }  // runs on npm install
}
```

**Payoff**: code execution on developer and CI machines, and exfiltration of environment secrets—before the app is ever run.

### 2. Dependency Confusion (Namespace Substitution)

An internal package name (e.g. `acme-internal-utils`) is not published to the public registry. The attacker publishes a package with that *same name* and a higher version to the public registry; a misconfigured resolver prefers the public, higher version.

```
# Internal registry has acme-internal-utils@1.4.0
# Attacker publishes acme-internal-utils@99.0.0 to the PUBLIC registry
# A build that checks both, un-scoped, pulls 99.0.0 -> attacker code
```

**Payoff**: attacker code runs inside the trusted internal build. Fixed by scoping, explicit registries, and pinned hashes.

### 3. Compromised or Malicious Maintainer Update

An attacker takes over a maintainer account (phishing, leaked token) or inherits an abandoned package, then ships a poisoned minor version. Projects using floating ranges auto-upgrade.

```
# package.json using a floating range
"dependencies": { "left-helper": "^2.0.0" }   # accepts 2.x automatically

# Attacker publishes left-helper@2.3.1 with a hidden payload
# Next `npm install` / CI build silently pulls it in
```

**Payoff**: silent code injection into every project that resolves the new version. Lockfiles with pinned hashes break this.

### 4. Unverified CDN Script (Missing SRI)

A page loads a third-party script by URL with no Subresource Integrity attribute. If the CDN is compromised or the URL is hijacked, the browser executes whatever is served.

```html
<!-- No integrity check: browser trusts whatever the CDN returns -->
<script src="https://cdn.example.com/widget/v3/widget.js"></script>

<!-- If the CDN is compromised, this runs in every visitor's session -->
// injected: document.forms[0].addEventListener('submit', stealCard);
```

**Payoff**: client-side code execution for every visitor (form/card skimming, session theft). Fixed with an `integrity=` hash.

### 5. Insecure Auto-Update (Unsigned Binary)

An application fetches an update descriptor and binary, then installs it without verifying a signature. An on-path attacker (rogue Wi-Fi, DNS spoofing, compromised mirror) serves a malicious replacement.

```
GET /updates/latest.json
→ { "version": "5.2.0", "url": "http://updates.example.com/app-5.2.0.bin" }

# The client downloads app-5.2.0.bin and executes it directly.
# Attacker on the path returns their own binary with the same name.
# No signature is checked -> malware installs, often with elevated rights.
```

**Payoff**: full endpoint compromise, frequently at high privilege. Fixed by verifying a signature over the artifact against a pinned key.

### 6. Build-Pipeline Injection (SolarWinds-class)

The attacker gains write access to the CI/CD system—via a leaked token, an over-privileged runner, or a poisoned pipeline dependency—and inserts code that runs during the build, so the final signed artifact contains the payload.

```
# Attacker edits a build step (or a tool the build invokes):
build:
  script:
    - ./configure
    - inject_backdoor.sh   # <-- added; runs before the artifact is signed
    - make && make package
    - sign --key $RELEASE_KEY   # signs the ALREADY-tampered artifact
```

**Payoff**: the malware ships to every customer under a genuine signature. Fixed by pipeline least-privilege, review, isolation, and provenance.

### 7. Poisoned CI Action / Plugin

Pipelines pull reusable actions/plugins by a mutable tag (e.g. `@v3`). If that tag is repointed to malicious code, every consuming pipeline executes it with the pipeline's secrets.

```
# Mutable reference: whatever @v3 points to today runs in your pipeline
- uses: some-org/deploy-action@v3

# Pin to an immutable commit SHA instead:
- uses: some-org/deploy-action@a1b2c3d4e5f6...   # cannot be silently moved
```

**Payoff**: theft of CI secrets and injection into your artifacts. Fixed by pinning to immutable digests.

### 8. Insecure Deserialization → Remote Code Execution

The application deserializes attacker-controlled bytes with a native deserializer. Crafted input triggers a "gadget chain"—existing classes whose deserialization side effects combine into code execution.

```python
# Python: pickle runs __reduce__ during load -> arbitrary code
import pickle, base64
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('id > /tmp/pwned',))

payload = base64.b64encode(pickle.dumps(Exploit()))
# Server does: pickle.loads(base64.b64decode(request.cookies['state']))
# -> os.system('id > /tmp/pwned') executes on the server
```

**Payoff**: server-side code execution. The same pattern exists for Java (`ObjectInputStream`), PHP (`unserialize`), .NET (`BinaryFormatter`), and Ruby. Fixed by never deserializing untrusted data natively.

### 9. Tampered Client-Side State

The server stores a security-relevant value on the client and trusts it back without an integrity check.

```
Set-Cookie: cart_total=149.99; role=user

# The user edits the cookie before the next request:
Cookie: cart_total=0.01; role=admin

# Server reads and trusts these values -> price manipulation + privilege escalation
```

**Payoff**: price/limit manipulation and privilege escalation. Fixed by keeping authoritative state server-side or binding it with a verified HMAC.

### 10. Unverified / Forged Tokens (alg=none, key confusion)

A JWT-style token is decoded and trusted without proper signature verification, or the server accepts an attacker-chosen algorithm.

```
# Attacker changes the header to "alg":"none" and strips the signature:
{"alg":"none","typ":"JWT"}.{"user":"admin","role":"admin"}.

# A permissive library that "verifies" alg=none accepts it as valid.
# Also dangerous: RS256 -> HS256 confusion, using the public key as an HMAC secret.
```

**Payoff**: identity and privilege forgery. Fixed by pinning the expected algorithm and always verifying with the correct key.

### 11. Update-Metadata / Rollback Tampering

Even with signed artifacts, an attacker who controls the update *metadata* can force a downgrade to an older, signed-but-vulnerable version, or freeze a client on a stale version to keep a known bug exploitable.

```
# Attacker replays an OLD but validly-signed manifest:
{ "version": "1.0.3", "url": "...", "sig": "<valid old signature>" }
# Client happily "updates" backward to a version with a known RCE.
```

**Payoff**: re-exposure of patched vulnerabilities. Fixed by monotonic version checks and signed, freshness-protected metadata (as in update frameworks like TUF).

### 12. Serialized Object as an SSRF / Deserialization Bridge

Some gadget chains do not run commands directly but instantiate objects that make network calls or read files during deserialization, turning an integrity failure into SSRF or file disclosure even where direct RCE gadgets are unavailable.

```
# A gadget that opens a URL or file handle during construction lets the
# attacker reach internal services or read local files simply by being
# deserialized -> integrity failure becomes SSRF / local file read.
```

**Payoff**: internal reconnaissance and data disclosure. Fixed by the same rule: do not deserialize untrusted data.

## Chaining Integrity Failures

Real intrusions combine these patterns. Integrity failures are especially powerful as the *first* link, because they establish trusted-looking code that later steps build on.

```
Poisoned CI action (Pattern 7)
   → steals the release signing token from pipeline secrets
   → attacker signs a malicious build (Pattern 6) with a genuine key
   → malicious signed update ships to all clients (Pattern 5)
   → client auto-updater installs it at high privilege
   → persistent backdoor across the entire customer base
```

```
Missing SRI (Pattern 4)
   → compromised CDN injects a skimmer into the checkout page
   → skimmer reads card data + session token
   → tampered client state (Pattern 9) escalates to admin
   → full account and payment compromise
```

The defensive lesson is that a single verified checkpoint can break the whole chain: had any one step verified a signature or hash against a trusted reference, the substituted artifact would have been rejected.

## Detection Signals

- **Dependencies**: lockfile hash mismatches, unexpected new transitive packages, install-time network calls, packages with install scripts you didn't expect.
- **Build/CI**: pipeline definition changes, new or modified steps, unexplained use of signing secrets, runners reaching unexpected hosts.
- **Updates**: update requests over plain HTTP, missing signature-verification logs, version downgrades.
- **Deserialization**: deserialization of request bodies/cookies, unusual class-loading, spikes in server errors from malformed serialized input.
- **Client state**: requests with edited cookies/tokens, role or price values that don't match server records, tokens with `alg=none`.

## Next Steps

- **[Overview](./overview.md)**: Concepts and why integrity failures matter
- **[Prevention](./prevention.md)**: Layered defenses that break these vectors
- **[Examples](./examples.md)**: Vulnerable vs. secure implementations
- **[Lab](./lab/unsigned-update-lab/)**: Practice identification

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
