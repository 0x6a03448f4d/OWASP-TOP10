# C6: Keep Your Components Secure - Code Examples

## Table of Contents
- [How to Read These Examples](#how-to-read-these-examples)
- [Node.js / npm](#nodejs--npm)
- [Python / pip](#python--pip)
- [Java / Maven](#java--maven)
- [CI Scanning Pipeline](#ci-scanning-pipeline)
- [SBOM Generation](#sbom-generation)
- [Summary Table](#summary-table)

## How to Read These Examples

Each block pairs an **insecure** configuration with the **secure** version that implements this control. The focus is on the things a component-security review actually checks: how versions are declared, whether lockfiles and integrity hashes are used, where packages are sourced from, and whether scanning runs automatically. Language differs; the principles do not.

> Version numbers below are illustrative placeholders to show pinning and range syntax—they are not references to specific vulnerabilities.

## Node.js / npm

### Package manifest and lockfile

#### Insecure

```
// package.json - floating ranges, no lockfile committed
{
  "name": "billing-service",
  "dependencies": {
    "express": "^4",        // any 4.x - resolves differently over time
    "lodash": "*",          // literally any version
    "left-pad": "latest"    // whatever is newest at install time
  }
}

// .gitignore
package-lock.json           // lockfile ignored (!) - builds not reproducible

// Install in CI
$ npm install               // may pull newer, unreviewed transitive code
```

**Why it is dangerous**: two builds of the same commit can install different code; there is no integrity hash to detect tampering; a freshly published malicious version is pulled automatically.

#### Secure

```
// package.json - human-readable ranges, but the lockfile decides
{
  "name": "billing-service",
  "dependencies": {
    "express": "4.19.2",    // pinned exact
    "lodash": "4.17.21"
  }
}

// package-lock.json is COMMITTED and records integrity hashes:
//   "lodash": {
//     "version": "4.17.21",
//     "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHqxHRQ2GkQ..."
//   }

// Install in CI - fails if lockfile and manifest disagree, enforces hashes
$ npm ci
```

**Why it is safe**: `npm ci` installs the exact locked versions and verifies each `integrity` hash, so builds are reproducible and tampered artifacts are rejected.

### Registry sourcing and dependency-confusion defense

#### Insecure

```
# .npmrc - internal packages can resolve to the PUBLIC registry
registry=https://registry.npmjs.org/
# Internal package published unscoped as "billing-utils"
# An attacker publishing public "billing-utils@99.0.0" wins by version.
```

#### Secure

```
# .npmrc - scope internal packages to an internal registry only
@myorg:registry=https://npm.internal.myorg.com/
registry=https://registry.npmjs.org/
always-auth=true

# Internal package is published as "@myorg/billing-utils"
# The @myorg scope can ONLY resolve to the internal registry,
# so a public look-alike can never be substituted.
```

### Auditing

```
# Insecure: never run, or run and ignored
# Secure: fail the build on high/critical, review lower severities
$ npm audit --audit-level=high
$ npm audit fix        # applies compatible fixes; review the diff
```

## Python / pip

### Requirements and hashes

#### Insecure

```
# requirements.txt - unpinned, no hashes
flask
requests>=2
pyyaml

# Install - resolves to whatever is newest, no integrity check
$ pip install -r requirements.txt
```

**Why it is dangerous**: unpinned versions drift, transitive dependencies are invisible, and nothing verifies that the downloaded artifact matches a known-good hash.

#### Secure

```
# requirements.txt - fully pinned WITH integrity hashes
# (generate with: pip-compile --generate-hashes  OR  pip hash)
flask==3.0.3 \
    --hash=sha256:34e815dfaa43340d1d15a5c3a02b8476004037eb4840b34910c6e21679d288f3
requests==2.32.3 \
    --hash=sha256:55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eaf68af20a760
pyyaml==6.0.2 \
    --hash=sha256:0a9a2848a5b7feac301353437eb7d5957887edbf81d56e903999a75a3d743086

# Install - reject anything whose hash does not match
$ pip install --require-hashes -r requirements.txt
```

**Why it is safe**: `--require-hashes` refuses to install any artifact—direct or transitive—whose content does not match a pinned hash, defeating tampering and substitution.

### Poetry lockfile

```
# Secure: pyproject.toml + committed poetry.lock
# poetry.lock pins exact versions and content hashes for the whole tree.
$ poetry install --sync     # installs exactly what the lock records
$ poetry lock --no-update   # regenerate lock without bumping versions
```

### Auditing

```
# Insecure: no scanning
# Secure: scan the resolved environment, fail on findings
$ pip-audit --strict
$ pip-audit -r requirements.txt --require-hashes
```

## Java / Maven

### Dependency declaration

#### Insecure

```
<!-- pom.xml - version ranges and SNAPSHOTs, no scanning -->
<dependencies>
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>[2.0,)</version>   <!-- open range: any 2.x+ -->
  </dependency>
  <dependency>
    <groupId>org.example</groupId>
    <artifactId>billing-core</artifactId>
    <version>1.2.0-SNAPSHOT</version>  <!-- mutable, non-reproducible -->
  </dependency>
</dependencies>
```

**Why it is dangerous**: version ranges and `SNAPSHOT` artifacts change under you, builds are not reproducible, and no plugin checks the resolved tree against known advisories.

#### Secure

```
<!-- pom.xml - exact versions, enforcer, and an SCA gate -->
<dependencies>
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.17.2</version>   <!-- pinned exact -->
  </dependency>
</dependencies>

<build>
  <plugins>
    <!-- Ban version ranges and SNAPSHOTs; require reproducible versions -->
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-enforcer-plugin</artifactId>
      <version>3.5.0</version>
      <executions><execution>
        <id>enforce-versions</id>
        <goals><goal>enforce</goal></goals>
        <configuration><rules>
          <requireReleaseDeps/>      <!-- no SNAPSHOTs -->
          <banDuplicatePomDependencyVersions/>
        </rules></configuration>
      </execution></executions>
    </plugin>

    <!-- OWASP Dependency-Check: fail the build on high-severity CVEs -->
    <plugin>
      <groupId>org.owasp</groupId>
      <artifactId>dependency-check-maven</artifactId>
      <version>10.0.3</version>
      <configuration><failBuildOnCVSS>7</failBuildOnCVSS></configuration>
      <executions><execution><goals><goal>check</goal></goals></execution></executions>
    </plugin>
  </plugins>
</build>
```

**Why it is safe**: exact versions make the build reproducible, the Enforcer plugin bans ranges and `SNAPSHOT` dependencies, and Dependency-Check fails the build when a resolved component carries a high-severity advisory.

## CI Scanning Pipeline

#### Insecure

```
# No component scanning in CI - vulnerabilities ship unnoticed.
build:
  script:
    - npm install
    - npm run build
    - deploy
```

#### Secure

```
# SCA runs as a gate; a critical finding stops the release.
build:
  script:
    - npm ci                                   # reproducible, hash-verified install
    - npm audit --audit-level=high             # native auditor gate
    - trivy fs --severity HIGH,CRITICAL \
             --exit-code 1 .                   # multi-ecosystem SCA gate
    - npx @cyclonedx/cyclonedx-npm \
             --output-file sbom.json           # produce SBOM artifact
    - npm run build
  artifacts:
    paths: [ sbom.json ]                        # keep SBOM with the release

# Separate scheduled job re-scans deployed SBOMs against new advisories
nightly-rescan:
  script:
    - grype sbom:sbom.json --fail-on high
```

## SBOM Generation

#### Insecure

```
# No inventory. During an emergency the only answer to
# "are we affected?" is to grep build files by hand, under pressure.
```

#### Secure

```
# A standard-format SBOM is produced for every build and stored.
# Node
$ npx @cyclonedx/cyclonedx-npm --output-file sbom.json
# Python
$ cyclonedx-py environment --output-format json --outfile sbom.json
# Java (Maven)
$ mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
# Language-agnostic, from source tree or image
$ syft dir:. -o cyclonedx-json=sbom.json
$ syft myapp:1.4.2 -o spdx-json=sbom.spdx.json

# Now "which releases ship jackson-databind 2.17.2?" is a query,
# answerable in seconds instead of days.
```

## Summary Table

| Concern | Insecure | Secure |
|---------|----------|--------|
| Version declaration | Floating ranges, `latest`, SNAPSHOTs | Exact pins, ranges banned by policy |
| Lockfile | Ignored or absent | Committed; `npm ci` / `poetry.lock` / pinned pom |
| Integrity | No hashes | Integrity hashes enforced (`--require-hashes`, lockfile) |
| Sourcing | Any registry, unscoped internal names | Controlled proxy, scoped internal packages |
| Scanning | None or ignored | SCA gate in CI + continuous re-scan |
| Inventory | Unknown transitive tree | SBOM (CycloneDX/SPDX) per build |
| Updates | Only when something breaks | Dependabot/Renovate PRs on a cadence |

## Next Steps

- **[Overview](overview.md)**: What this control is and why it matters
- **[Threats Addressed](attack-vectors.md)**: The failure modes these examples prevent
- **[How to Implement](prevention.md)**: The full step-by-step build-out
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply component security hands-on
