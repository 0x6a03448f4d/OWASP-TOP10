# CICD-SEC-3: Dependency Chain Abuse - Prevention

## Prevention Strategy Overview

Preventing Dependency Chain Abuse is about **taking control of resolution**—removing every gap between the name a developer typed and the bytes the build runs:

1. Fetch dependencies only from a controlled internal proxy/registry with an allow-list.
2. Claim and scope internal names so they can never be shadowed publicly.
3. Pin versions *and* verify integrity hashes on every install.
4. Disable install-time scripts by default; allow-list the few that are essential.
5. Verify provenance/signatures, scan continuously, and monitor for look-alikes.

### Core Principles

- **One source of truth**: builds pull from a single controlled registry/proxy, never directly from the public internet.
- **Reproducible by hash**: a build fetches the exact bytes recorded in the lockfile, or it fails—never "whatever the registry serves today."
- **Least functionality**: no public fallback for private scopes, no arbitrary install scripts, no floating versions.
- **Least privilege on the agent**: assume a rogue install script *will* run once—make sure it gains as little as possible.

## 1. Fetch Only Through a Controlled Internal Registry / Proxy

Point every build at a single internal registry (Artifactory, Nexus, Verdaccio, a cloud artifact registry, or a pull-through proxy). It mirrors approved public packages and hosts your private ones, so builds never talk to public registries directly and an allow-list governs what may enter.

```ini
# .npmrc — all installs go through the internal proxy, never public directly
registry=https://registry.internal.acme/npm/
always-auth=true
//registry.internal.acme/npm/:_authToken=${NPM_TOKEN}
```

```ini
# pip.conf — single internal index; NO --extra-index-url merging with PyPI
[global]
index-url = https://pypi.internal.acme/simple/
# Do not add extra-index-url to a public index: it merges namespaces
# and reintroduces the confusion window.
```

Configure the proxy to **not auto-create** public packages that collide with an internal name, and to require review before a new public package is admitted to the mirror.

## 2. Claim and Scope Internal Package Names

Two complementary moves close the confusion window:

- **Use a namespace/scope** for all internal packages and bind that scope to the private registry.
- **Claim the scope and the names** on the public registries so an attacker cannot register them—even as placeholders.

```ini
# .npmrc — bind the @acme scope to the private registry ONLY.
# There is no public fallback for anything under @acme.
@acme:registry=https://registry.internal.acme/npm/
//registry.internal.acme/npm/:_authToken=${NPM_TOKEN}
registry=https://registry.internal.acme/npm/
```

```
# Manifest uses the scoped name everywhere:
#   "@acme/auth-utils": "1.4.2"     (resolves privately, never public)
# And @acme is claimed on the public registry so it cannot be squatted.
```

For ecosystems without npm-style scopes, achieve the same effect with group/coordinate ownership (Maven `groupId` you control and have verified) and reserved names on the public index.

## 3. Pin Versions and Verify Integrity Hashes

Pinning a version stops floating upgrades; verifying a hash guarantees the bytes. You need both, enforced by a locked install command.

```bash
# Node: commit package-lock.json and install in locked, hash-verified mode.
npm ci        # fails if package.json and lock disagree; installs exact,
              # integrity-checked (sha512) artifacts from the lockfile
```

```
# Python: hashed requirements + enforce that every package has a hash.
# requirements.txt
acme-auth-utils==1.4.2 \
  --hash=sha256:9f2b...c41a
requests==2.32.3 \
  --hash=sha256:55365...e7d0

pip install --require-hashes -r requirements.txt
# --require-hashes makes pip REJECT any package without a pinned hash.
```

```xml
<!-- Maven: pin exact versions (no ranges) and verify with a checksum plugin -->
<dependency>
  <groupId>com.acme</groupId>
  <artifactId>auth-utils</artifactId>
  <version>1.4.2</version>   <!-- exact, never [1.0,) -->
</dependency>
<!-- Enforce checksum policy: --> mvn -C  (fail on checksum mismatch)
```

Rules of thumb: commit the lockfile, install with the *locked* command in CI, and treat any lock/manifest drift as a build failure to review—not an auto-fix.

## 4. Disable Install-Time Scripts by Default

Lifecycle scripts are the code-execution step for most of these attacks. Turn them off on the build agent and allow-list only the few packages that genuinely need them.

```bash
# npm: refuse to run any lifecycle scripts during install
npm ci --ignore-scripts

# Or make it the default via .npmrc:
ignore-scripts=true
```

```bash
# Prefer wheels over sdists so pip does not execute setup.py:
pip install --only-binary=:all: --require-hashes -r requirements.txt
# Wheels are pre-built; no arbitrary setup.py runs at install time.
```

Where a package legitimately needs a build step (native modules), allow-list it explicitly and run it in an isolated, least-privilege stage rather than enabling scripts globally.

## 5. Verify Provenance and Signatures

Where the ecosystem supports it, verify that a package was built and published by who you expect.

```bash
# Verify npm-published provenance / signatures against the registry keys:
npm audit signatures        # checks registry signatures for installed packages

# Enforce a provenance/attestation policy in the proxy or a policy engine
# (e.g. require SLSA-style build provenance, Sigstore signatures) before
# a package is admitted to the internal mirror.
```

Provenance shifts trust from "the name looked right" to "this artifact was produced by the expected build from the expected source."

## 6. Software Composition Analysis (SCA) on Every Build

SCA is your continuous catch for *known* malicious and vulnerable versions. Run it in the pipeline and fail on high-severity findings.

```bash
# In CI — fail the build on known-bad dependencies
npm audit --audit-level=high
pip-audit -r requirements.txt
mvn org.owasp:dependency-check-maven:check

# Generate an SBOM so every artifact has a verifiable bill of materials
syft dir:. -o cyclonedx-json > sbom.json
```

Pair SCA with an SBOM per artifact so that when a new advisory or malicious-package report lands, you can instantly answer "are we affected, and where?"

## 7. Monitor for New and Look-Alike Packages

Because typosquats and confusion packages are brand new (no advisory yet), watch the registries directly.

```
# Signals worth alerting on:
- A PUBLIC package appears with the same name as one of your INTERNAL names
- A new package whose name is an edit-distance-1 typo of a dependency you use
- A dependency you rely on suddenly changes maintainer/owner or publishes
  a version far higher than its history
- A first-ever version of a transitive dependency enters your lockfile
```

Feed these signals to your security team and block the offending names at the proxy before a build can resolve them.

## 8. Harden and Isolate the Build Agent

Assume an install script will eventually run once. Limit what it can reach.

- Run installs as a **non-root, least-privilege** user in an **ephemeral** container that is destroyed after the job.
- Restrict **egress** so a malicious script cannot phone home or exfiltrate to arbitrary hosts.
- Keep **secrets out of the install stage**: inject deploy/cloud credentials only in later, isolated stages—never in the environment that runs `install`.
- Block access to **cloud metadata endpoints** from the dependency-install step.

```yaml
# Separate untrusted install from privileged steps (illustrative):
install:
  image: node:20-slim
  script: npm ci --ignore-scripts        # no secrets in this environment
  # network: restricted egress, no cloud-metadata access

deploy:
  needs: [build]                          # secrets only here, after artifacts
  script: ./publish.sh                    # runs on verified artifacts only
```

## 9. Secure the Publishing Side

Stop *your* packages from becoming the hijack vector for someone else.

- Require **MFA** on every maintainer/registry account and on publish.
- Use **short-lived, scoped publish tokens** in CI; never long-lived tokens in code or logs.
- Watch for **expiring domains** tied to maintainer emails; renew or migrate before they lapse.
- Publish with **provenance/signatures** so consumers can verify your artifacts.

## Defence-in-Depth Summary

| Abuse class | Primary control | Backstop control |
|-------------|-----------------|------------------|
| Dependency confusion | Scope + private-only registry, no public fallback | Claim names publicly; proxy allow-list |
| Typosquatting | Install via curated internal proxy | Look-alike monitoring; SCA |
| Brandjacking | Proxy allow-list of approved packages | Provenance/signature verification |
| Dependency hijacking | Pin version + verify integrity hash | Provenance checks; maintainer-change alerts |
| Transitive poisoning | Locked, hash-verified install of the full graph | SBOM + SCA on every build |
| Install-script RCE | `--ignore-scripts` / prefer wheels | Least-privilege, isolated, egress-restricted agent |

## Key Takeaways

1. **Control the source** — one internal proxy/registry with an allow-list beats trusting the public internet on every build.
2. **Own your names** — scope internal packages, bind the scope privately, and claim the names publicly so they cannot be shadowed.
3. **Pin and verify** — exact versions plus integrity hashes plus a locked install command make builds reproducible and tamper-evident.
4. **Scripts off by default** — installing should not execute arbitrary code; allow-list the rare exceptions.
5. **Assume one gets through** — least-privilege, ephemeral, egress-restricted agents and continuous monitoring limit the blast radius.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure package-manager configuration
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10
- **[Practice](/practice)**: Apply these controls hands-on
