# A06:2021 – Vulnerable and Outdated Components: Examples

## Table of Contents

- [How to Read These Examples](#how-to-read-these-examples)
- [Example 1: Node.js / npm Manifest & Lockfile](#example-1-nodejs--npm-manifest--lockfile)
- [Example 2: Fixing a Transitive npm Dependency](#example-2-fixing-a-transitive-npm-dependency)
- [Example 3: Python / pip Requirements](#example-3-python--pip-requirements)
- [Example 4: Java / Maven Dependencies](#example-4-java--maven-dependencies)
- [Example 5: Container Base Image](#example-5-container-base-image)
- [Example 6: Client-Side Libraries](#example-6-client-side-libraries)
- [Example 7: CI/CD Scanning Gate](#example-7-cicd-scanning-gate)
- [Example 8: End-of-Life Runtime](#example-8-end-of-life-runtime)
- [Summary Table](#summary-table)

## How to Read These Examples

Each example shows a **❌ VULNERABLE** pattern—how outdated or unmanaged components creep in—followed by the **✅ SECURE** version that fixes it. The version numbers are illustrative placeholders; the *patterns* are the point. Always resolve exact fixed versions from your scanner and the official advisory at the time you patch.

## Example 1: Node.js / npm Manifest & Lockfile

### ❌ Vulnerable: floating ranges, no lockfile, stale versions

```json
// package.json -- everything floats, nothing is pinned
{
  "dependencies": {
    "express": "*",           // "give me anything" -- unrepeatable builds
    "lodash": "^4.17.4",      // known-vulnerable range left in place
    "jsonwebtoken": "~8.0.0"  // old major, missing security fixes
  }
}
```

```
# No package-lock.json committed.
$ npm install                 # resolves DIFFERENT versions on each machine
# Nobody knows what actually shipped, so nobody can audit it.
```

**Why it's dangerous:** Without a committed lockfile you have no inventory—production, CI, and each developer may run different, possibly-vulnerable versions. Floating `*` and stale ranges mean known-vulnerable builds ship silently.

### ✅ Secure: pinned, locked, audited, reproducible

```json
// package.json -- explicit, current, maintained versions
{
  "dependencies": {
    "express": "4.19.2",
    "lodash": "4.17.21",      // patched version
    "jsonwebtoken": "9.0.2"   // current major with fixes
  },
  "scripts": {
    "preinstall": "npm audit --audit-level=high"
  }
}
```

```
# Commit package-lock.json. Install exact, verified versions everywhere:
$ npm ci                      # fails if lockfile & manifest disagree
$ npm audit --audit-level=high  # non-zero exit on High/Critical
```

## Example 2: Fixing a Transitive npm Dependency

### ❌ Vulnerable: a deep dependency you never chose is flagged

```
$ npm audit
# High    Prototype Pollution in some-lib < 6.5.3
# node_modules/parent-pkg/node_modules/some-lib
# You depend on parent-pkg, which pins the vulnerable some-lib.

$ npm ls some-lib
myapp@1.0.0
└─┬ parent-pkg@2.0.0
  └── some-lib@6.4.0          <- vulnerable, transitive
```

### ✅ Secure: override the transitive version (or upgrade the parent)

```json
// package.json -- force the patched version across the whole tree
{
  "overrides": {
    "some-lib": "6.5.3"       // npm 8.3+ ; Yarn uses "resolutions"
  }
}
```

```
$ npm install && npm ls some-lib
myapp@1.0.0
└─┬ parent-pkg@2.0.0
  └── some-lib@6.5.3          <- patched
$ npm test                    # verify nothing broke, then commit lockfile

# Prefer upgrading parent-pkg if a newer release already pulls the fix:
$ npm install parent-pkg@latest && npm test
```

## Example 3: Python / pip Requirements

### ❌ Vulnerable: unpinned, unscanned, possibly end-of-life

```
# requirements.txt
Django            # unpinned -- resolves to whatever, or stays frozen old
requests          # no version, no hash
PyYAML==3.13      # old version with a known unsafe-load class of issue

# Installed once long ago, never re-checked against new advisories.
$ pip install -r requirements.txt
```

### ✅ Secure: pinned, hash-verified, and audited

```
# requirements.txt -- pinned to current, supported versions
Django==4.2.11
requests==2.31.0
PyYAML==6.0.1

# Generate hashes for integrity (e.g. with pip-tools / pip-compile):
#   Django==4.2.11 --hash=sha256:...
$ pip install -r requirements.txt --require-hashes

# Audit on every build; fails the pipeline on known vulns:
$ pip install pip-audit
$ pip-audit -r requirements.txt --strict

# Constrain a transitive dependency without editing upstream:
# constraints.txt
urllib3>=1.26.18
$ pip install -r requirements.txt -c constraints.txt
```

## Example 4: Java / Maven Dependencies

### ❌ Vulnerable: old framework, no scanning, unmanaged transitives

```xml
<!-- pom.xml -->
<dependencies>
  <dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.0</version>   <!-- pre-fix, Log4Shell-class exposure -->
  </dependency>
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.9.8</version>    <!-- old; deserialization gadget class -->
  </dependency>
</dependencies>
<!-- No dependency scanning configured. -->
```

### ✅ Secure: current versions + OWASP Dependency-Check gate

```xml
<!-- pom.xml -->
<dependencies>
  <dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.23.1</version>   <!-- patched -->
  </dependency>
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.17.0</version>   <!-- current -->
  </dependency>
</dependencies>

<build><plugins>
  <plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.0.9</version>
    <configuration><failBuildOnCVSS>7</failBuildOnCVSS></configuration>
    <executions><execution><goals><goal>check</goal></goals></execution></executions>
  </plugin>
</plugins></build>

<!-- Inspect the full tree so transitives are visible: -->
<!-- $ mvn dependency:tree -->
```

## Example 5: Container Base Image

### ❌ Vulnerable: old, floating, root, never rebuilt

```dockerfile
# Dockerfile
FROM node:14              # end-of-life runtime; "14" also floats
COPY . /app
WORKDIR /app
RUN npm install          # not "npm ci" -- unpinned resolution
CMD ["node", "server.js"]
# Runs as root. Never re-scanned. OS packages frozen at build time.
```

### ✅ Secure: minimal, pinned, patched, non-root, scanned

```dockerfile
# Dockerfile
FROM node:20.11.1-slim@sha256:....   # supported, minimal, digest-pinned

RUN apt-get update && apt-get upgrade -y \
 && rm -rf /var/lib/apt/lists/*       # patch OS packages at build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev                 # exact, verified, prod-only deps
COPY . .
USER 10001                            # drop root
CMD ["node", "server.js"]
```

```
# Scan the built image in CI; fail on HIGH/CRITICAL, and REBUILD on a
# cadence so base-image patches reach production:
$ trivy image --severity HIGH,CRITICAL --exit-code 1 myorg/app:1.4.2
```

## Example 6: Client-Side Libraries

### ❌ Vulnerable: ancient CDN library, no integrity, no version control

```html
<!-- Loads an outdated library from a third party with no integrity check -->
<script src="https://code.example-cdn.com/jquery/1.12.4/jquery.min.js"></script>
<script src="/static/vendor/angular-1.5.8/angular.min.js"></script>
<!-- Old, known-vulnerable, and if the CDN is compromised you run its code. -->
```

### ✅ Secure: current version, managed as a dependency, with SRI

```html
<!-- If you must use a CDN, pin a current version AND add
     Subresource Integrity so a tampered file is rejected: -->
<script
  src="https://code.example-cdn.com/jquery/3.7.1/jquery.min.js"
  integrity="sha384-...."
  crossorigin="anonymous"></script>
```

```
# Better: manage front-end libs as real dependencies so they are
# inventoried and scanned like everything else:
# package.json -> "jquery": "3.7.1"
$ npm ci
$ npx retire --path ./dist     # scan bundled JS for known-vulnerable libs
```

## Example 7: CI/CD Scanning Gate

### ❌ Vulnerable: scanning is manual, advisory-blind, and optional

```
# No dependency scanning in the pipeline.
# Someone "runs npm audit occasionally" and ignores the output.
# New advisories against already-shipped code are never noticed.
```

### ✅ Secure: automated gate on PRs + daily re-scan of main

```yaml
# .github/workflows/deps.yml
name: dependency-scan
on:
  pull_request:
  schedule:
    - cron: '0 6 * * *'        # catch advisories published after merge
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: google/osv-scanner-action@v1
        with:
          scan-args: "--lockfile=package-lock.json"
      - uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          severity: HIGH,CRITICAL
          exit-code: '1'        # block the merge on High/Critical

# Plus .github/dependabot.yml to open automated update PRs.
```

## Example 8: End-of-Life Runtime

### ❌ Vulnerable: staying on an unsupported runtime "because it works"

```
# runtime.txt / base image / CI matrix all say:
python-2.7
# Python 2.7 is end-of-life: no more security fixes, ever.
# Every future advisory in the runtime or its ecosystem stays open.
# "It still works" is not "it is still safe."
```

### ✅ Secure: migrate to a supported version, ahead of EOL

```
# Track support windows and plan migrations BEFORE the cutoff:
#   endoflife.date/python , endoflife.date/nodejs , ...
python-3.12                  # supported, receiving security fixes

# Upgrade behind a good test suite so the migration is verifiable:
$ tox            # run tests across the target runtime
$ pip-audit -r requirements.txt   # confirm the new stack is clean

# Budget EOL migrations as planned work, not emergencies.
```

## Summary Table

| Area | Vulnerable Pattern | Secure Pattern |
|------|--------------------|----------------|
| Versioning | Floating `*` / `^`, no lockfile | Pinned versions, committed lockfile, `npm ci` |
| Transitives | Ignored; vulnerable deep in the tree | Overrides/constraints; upgrade the parent |
| Python deps | Unpinned, unhashed, unscanned | Pinned + `--require-hashes` + pip-audit |
| Java deps | Old libs, no scanning | Current versions + Dependency-Check gate |
| Containers | EOL image, root, never rebuilt | Minimal, pinned, patched, non-root, scanned |
| Client-side | Old CDN lib, no integrity | Current version, SRI, managed & scanned |
| CI/CD | Manual, optional, advisory-blind | Automated gate + daily re-scan + auto-PRs |
| Runtime | End-of-life, "it still works" | Supported version, migrated ahead of EOL |

## Key Takeaways

1. **Pin and lock everything.** Reproducible builds are the prerequisite for an auditable inventory.
2. **Transitive dependencies need explicit handling**—overrides, constraints, or upgrading the parent.
3. **Scanning must be automated and blocking**, and must re-run against already-released code as new advisories appear.
4. **Containers and runtimes age.** Rebuild on minimal, supported, patched bases; migrate off end-of-life software as planned work.
5. **The secure version is rarely more code**—it is mostly discipline: current versions, verified sources, and a gate that fails the build.

## Next Steps

- **[Overview](./overview.md)**: The category, its impact, and how it is defined
- **[Attack Vectors](./attack-vectors.md)**: How attackers find and exploit known-vulnerable components
- **[Prevention](./prevention.md)**: A layered program of inventory, scanning, and patching
- **[Hands-On Lab](./lab/outdated-library-lab/)**: Detect, patch, and re-scan an outdated library

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
