# CICD-SEC-3: Dependency Chain Abuse - Code Examples

Each pair below shows an **insecure** package-manager configuration and the **secure** version for the same ecosystem. The examples focus on the settings that decide the attack: which registry answers, how versions and hashes are verified, whether private names can be shadowed, and whether install-time scripts run.

## npm / Node.js

### Insecure

```ini
# .npmrc — public registry is the only source; scopes fall back publicly
registry=https://registry.npmjs.org/
# No @acme scope mapping, so @acme (and unscoped internal names) can be
# resolved from the PUBLIC registry -> dependency-confusion window open.
```

```json
// package.json — floating ranges, unscoped internal name
{
  "dependencies": {
    "acme-auth-utils": "^1.0.0",   // internal name, unscoped, floating
    "lodash": "*"                  // any version the registry serves
  }
}
```

```bash
# Build step — loose install that trusts whatever resolves and runs scripts
npm install            # regenerates lock, honors highest match, runs postinstall
# A public "acme-auth-utils@99.99.99" wins and its postinstall executes.
```

### Secure

```ini
# .npmrc — single internal proxy; @acme bound PRIVATELY with no public fallback
registry=https://registry.internal.acme/npm/
@acme:registry=https://registry.internal.acme/npm/
//registry.internal.acme/npm/:_authToken=${NPM_TOKEN}
always-auth=true
ignore-scripts=true            # no lifecycle scripts during install
```

```json
// package.json — scoped internal name, exact versions
{
  "dependencies": {
    "@acme/auth-utils": "1.4.2",   // scoped -> only the private registry
    "lodash": "4.17.21"            // exact version, matched to the lockfile
  }
}
```

```bash
# Build step — locked, hash-verified, script-free install in CI
npm ci --ignore-scripts
#   * fails if package.json and package-lock.json disagree
#   * installs the EXACT, sha512-integrity-checked artifacts from the lock
#   * runs no postinstall/preinstall scripts
npm audit signatures           # verify registry signatures/provenance
```

## pip / Python

### Insecure

```ini
# pip.conf / CLI — private index MERGED with public PyPI
[global]
index-url = https://pypi.org/simple
extra-index-url = https://pypi.internal.acme/simple
#   pip queries BOTH and picks the highest version across them.
#   A public "acme-auth-utils" at a higher version shadows the private one.
```

```
# requirements.txt — no pins, no hashes
acme-auth-utils        # unpinned internal name
requests               # unpinned
```

```bash
# Install — sdists allowed, so setup.py can run arbitrary code
pip install -r requirements.txt
# No hash verification; malicious setup.py executes on the build agent.
```

### Secure

```ini
# pip.conf — a SINGLE internal index; no extra-index-url merging
[global]
index-url = https://pypi.internal.acme/simple
require-hashes = true
only-binary = :all:            # prefer wheels; do not execute setup.py
```

```
# requirements.txt — pinned versions + integrity hashes
acme-auth-utils==1.4.2 \
  --hash=sha256:9f2b3a1c0d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a
requests==2.32.3 \
  --hash=sha256:55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eaf68af20a760
```

```bash
# Install — hashes enforced; any unpinned/altered package is rejected
pip install --require-hashes --only-binary=:all: -r requirements.txt
#   --require-hashes: every requirement MUST carry a matching hash
#   --only-binary:    no source builds, so no setup.py runs at install
```

## Maven / Java

### Insecure

```xml
<!-- pom.xml / settings.xml — public Maven Central reachable directly,
     version RANGES allowed, no checksum enforcement -->
<repositories>
  <repository>
    <id>central</id>
    <url>https://repo.maven.apache.org/maven2</url>  <!-- public, direct -->
  </repository>
</repositories>

<dependency>
  <groupId>com.acme</groupId>
  <artifactId>auth-utils</artifactId>
  <version>[1.0,)</version>   <!-- open range: highest available wins -->
</dependency>
```

### Secure

```xml
<!-- settings.xml — mirror EVERYTHING through the internal repository -->
<mirrors>
  <mirror>
    <id>internal</id>
    <mirrorOf>*</mirrorOf>   <!-- no direct Central access -->
    <url>https://nexus.internal.acme/repository/maven/</url>
  </mirror>
</mirrors>

<!-- pom.xml — exact version, group you own and have verified -->
<dependency>
  <groupId>com.acme</groupId>
  <artifactId>auth-utils</artifactId>
  <version>1.4.2</version>   <!-- exact, no range -->
</dependency>
```

```bash
# Build — fail hard on any checksum mismatch
mvn -C clean verify        # -C = strict checksum policy (fail, don't warn)
# Combine with the OWASP dependency-check plugin for known-bad versions.
```

## Scoping vs. Confusion at a Glance

```
Unscoped, public fallback ON:
  "acme-auth-utils"  ->  resolver may accept a PUBLIC match  ->  confusion

Scoped, private binding, NO fallback:
  "@acme/auth-utils" ->  ONLY the internal registry answers  ->  safe
  (+ @acme claimed on the public registry so it cannot be squatted)
```

## CI Pipeline: Insecure vs. Secure Install Stage

### Insecure

```yaml
build:
  image: node:20
  script:
    - npm install                 # loose, regenerates lock, runs scripts
    - npm run build
  # Full deploy secrets present in this environment; unrestricted egress.
```

### Secure

```yaml
install:
  image: node:20-slim
  script:
    - npm ci --ignore-scripts     # locked, hash-verified, no scripts
    - npm audit --audit-level=high
    - npm audit signatures        # provenance/signature check
  # No deploy secrets here; egress restricted; ephemeral, non-root user.

deploy:
  needs: [install]                # secrets injected only AFTER a clean install
  script: ./publish.sh            # operates on verified artifacts only
```

## What Changed, and Why

| Control | Insecure | Secure |
|---------|----------|--------|
| Registry source | Public registry direct, or public+private merged | Single internal proxy/registry, allow-listed |
| Internal names | Unscoped, shadowable publicly | Scoped, private-only binding, claimed publicly |
| Versions | Ranges / `*` / open ranges | Exact pins matched to a lockfile |
| Integrity | No hash verification | `npm ci` / `--require-hashes` / strict checksums |
| Install scripts | Run automatically (postinstall, setup.py) | Disabled / wheels-only, allow-list exceptions |
| Provenance | None | Signature/provenance verification |
| Agent | Secrets present, broad egress | Least-privilege, isolated install stage |

## Next Steps

- **[Prevention](prevention.md)**: The full resolution-control strategy
- **[Attack Vectors](attack-vectors.md)**: How these misconfigurations are exploited
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10
- **[Practice](/practice)**: Apply these controls hands-on
