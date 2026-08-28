# Software and Data Integrity Failures - Prevention

## Table of Contents

- [Defense Strategy: Verify Before You Trust](#defense-strategy-verify-before-you-trust)
- [Layer 1: Dependency & Package Integrity](#layer-1-dependency--package-integrity)
- [Layer 2: Subresource Integrity for Browser Assets](#layer-2-subresource-integrity-for-browser-assets)
- [Layer 3: Secure CI/CD Pipelines](#layer-3-secure-cicd-pipelines)
- [Layer 4: Signed, Verified Updates](#layer-4-signed-verified-updates)
- [Layer 5: Safe Deserialization & Trusted Data](#layer-5-safe-deserialization--trusted-data)
- [Consolidated Checklist](#consolidated-checklist)

## Defense Strategy: Verify Before You Trust

Every defense in this category is a variation on one rule: **never act on an artifact or piece of data until you have verified, against a trusted reference, that it is genuine and unmodified.** The trusted reference is a hash you already know, or a public key you already trust—delivered through a channel independent of the artifact itself.

The layers below map onto the four faces of integrity failure. They are additive: dependency pinning does not protect your update channel, and signed updates do not protect your deserialization endpoints. Apply all of them.

| Layer | Protects against | Primary control |
|-------|------------------|-----------------|
| Dependency integrity | Typosquat, confusion, poisoned versions | Lockfiles with pinned hashes, verified registries, SCA |
| Subresource integrity | Compromised CDN / third-party script | SRI hashes on browser assets |
| Secure CI/CD | Build-pipeline injection | Least privilege, review, isolation, pinned actions, provenance |
| Signed updates | Malicious / rolled-back updates | Signature verification against a pinned key + version checks |
| Safe data handling | Deserialization RCE, tampered state | Safe formats, schema validation, HMAC on client state |

## Layer 1: Dependency & Package Integrity

### Pin to verified hashes with a committed lockfile

A lockfile records the exact version *and cryptographic hash* of every resolved dependency. Committing it and installing in "frozen" mode means the build fails if any package's content no longer matches the recorded hash.

```
# Node.js: install strictly from the lockfile; fail on any mismatch
npm ci                     # refuses to modify package-lock.json; verifies integrity

# package-lock.json records a Subresource-Integrity-style hash per package:
# "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
# "integrity": "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
```

```
# Python (pip): require hashes for every package
pip install --require-hashes -r requirements.txt

# requirements.txt with pinned hashes:
# requests==2.31.0 \
#   --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1
```

### Prevent dependency confusion

```
# npm: scope internal packages and pin the registry for that scope
# .npmrc
@acme:registry=https://registry.internal.acme.com/
# Public registry can never satisfy @acme/* -> confusion attack blocked
```

- Use a private registry / proxy that you control; do not let builds fall back to the public registry for internal names.
- Disable automatic execution of install scripts where feasible (`npm config set ignore-scripts true`) and vet the ones you need.
- Prefer **exact versions** over floating ranges for anything security-sensitive.

### Run Software Composition Analysis (SCA)

```
# Fail the build on known-vulnerable or policy-violating dependencies
npm audit --audit-level=high
pip-audit -r requirements.txt
osv-scanner --lockfile=package-lock.json
```

> SCA overlaps with **A06:2021 Vulnerable & Outdated Components** (known CVEs). Here we use it additionally to catch *integrity* signals—unexpected new packages, yanked versions, and provenance gaps.

## Layer 2: Subresource Integrity for Browser Assets

Subresource Integrity (SRI) lets the browser verify that a script or stylesheet fetched from a CDN matches a hash you embedded in your HTML. If the CDN is compromised, the hash no longer matches and the browser refuses to execute the file.

```html
<!-- Vulnerable: browser trusts whatever the CDN serves -->
<script src="https://cdn.example.com/lib/3.7.1/lib.min.js"></script>

<!-- Secure: browser executes ONLY if the content hash matches -->
<script src="https://cdn.example.com/lib/3.7.1/lib.min.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"></script>
```

```
# Generate the SRI hash for a file you are pinning:
cat lib.min.js | openssl dgst -sha384 -binary | openssl base64 -A
# Prefix the output with "sha384-" for the integrity attribute.
```

- Combine SRI with a **Content-Security-Policy** that requires it: `require-sri-for script style` (where supported) so an un-hashed asset is blocked.
- Pin to a specific, immutable version URL—SRI cannot protect a "latest" URL whose content is expected to change.
- Self-host critical scripts where you can; SRI is the mitigation when you cannot.

## Layer 3: Secure CI/CD Pipelines

The build system is trusted to produce your release, so it is exactly where a SolarWinds-class attacker wants to be. Treat the pipeline as production infrastructure.

### Least privilege and secret hygiene

- Grant each pipeline the **minimum** scopes it needs; never a single all-powerful token.
- Use **short-lived, workload-identity (OIDC) credentials** instead of long-lived static secrets where possible.
- Restrict who can edit pipeline definitions; require review for changes to build config just like application code.
- Isolate the signing key: sign in a separate, hardened step/environment that untrusted build steps cannot reach.

### Pin actions/plugins to immutable digests

```
# Vulnerable: mutable tag can be silently repointed to malicious code
- uses: actions/checkout@v4

# Secure: pin to an immutable commit SHA
- uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608  # v4.1.0
```

### Harden the pipeline and enforce review

```yaml
# Example GitHub Actions job hardened for integrity
permissions:
  contents: read            # default to read-only; grant more only per-job
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@... # egress control on the runner
        with:
          egress-policy: block
          allowed-endpoints: registry.npmjs.org:443 github.com:443
      - uses: actions/checkout@<sha>
      - run: npm ci                          # frozen, hash-verified install
      - run: npm run build
      # Signing happens in a separate, higher-trust job with restricted access
```

- **Protected branches + mandatory review**: no code reaches the release branch without an approved pull request.
- **Segregation of duties**: the person who writes code should not be able to unilaterally push a signed release.
- **Ephemeral, isolated runners**: a fresh environment per build limits persistence and cross-contamination.
- **No unsigned artifacts**: only artifacts produced by the trusted pipeline and signed by it are allowed to deploy.

### Generate and verify build provenance

```
# Sign an artifact and produce provenance you can later verify (Sigstore cosign):
cosign sign-blob --yes app-5.2.0.bin --output-signature app-5.2.0.bin.sig

# Consumers verify it came from your trusted identity BEFORE trusting it:
cosign verify-blob \
  --signature app-5.2.0.bin.sig \
  --certificate-identity "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v5.2.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  app-5.2.0.bin
```

> Provenance frameworks such as **SLSA** formalize "how was this artifact built, and can I verify it?" The deeper supply-chain governance (SBOMs, org-wide policy) is covered in the **2025 Software Supply Chain Failures** lesson; here the goal is that *your own pipeline* produces tamper-evident, verifiable releases.

## Layer 4: Signed, Verified Updates

An auto-updater is remote code execution by design—it downloads code and runs it. The only thing that makes that safe is verifying a signature over the update against a public key you shipped with the application.

```
# Secure update flow (pseudocode):
1. Fetch update manifest over HTTPS
2. Verify the manifest signature with the PINNED public key
3. Reject if manifest.version <= installed.version   # block rollback
4. Download the artifact
5. Recompute the artifact hash; compare to the signed hash in the manifest
6. Verify the artifact signature with the PINNED public key
7. ONLY THEN install/execute
```

```python
# Python: verify a detached signature before applying an update
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

PINNED_PUBKEY = Ed25519PublicKey.from_public_bytes(SHIPPED_PUBLIC_KEY_BYTES)

def apply_update(artifact: bytes, signature: bytes, new_version, cur_version):
    if new_version <= cur_version:
        raise SecurityError("refusing rollback / replay")
    try:
        PINNED_PUBKEY.verify(signature, artifact)   # raises on tampering
    except InvalidSignature:
        raise SecurityError("update signature invalid - aborting")
    install(artifact)                               # trusted only after verify
```

- **Pin the public key** inside the application; never fetch the verification key from the same server as the update.
- **Deliver signatures/hashes out-of-band** from the artifact, or sign so that controlling the file server is not enough.
- **Prevent rollback** with monotonic version checks and freshness-protected metadata (the approach codified by **The Update Framework, TUF**).
- **Fail closed**: an unverifiable update is not installed, and the failure is logged and alerted.

## Layer 5: Safe Deserialization & Trusted Data

### Do not deserialize untrusted data with native deserializers

The most reliable defense is architectural: never feed attacker-controllable bytes to `pickle.loads`, Java `ObjectInputStream`, PHP `unserialize`, or .NET `BinaryFormatter`. Use a **data-only format** and reconstruct your own objects explicitly.

```python
# Vulnerable: native object deserialization of user input
import pickle
state = pickle.loads(base64.b64decode(request.cookies['state']))  # RCE risk

# Secure: parse data-only JSON, then validate into a known schema
import json
from pydantic import BaseModel, ValidationError

class CartState(BaseModel):
    item_ids: list[int]
    coupon: str | None = None

raw = json.loads(request.cookies['state'])      # data only, no code execution
try:
    state = CartState(**raw)                     # strict schema validation
except ValidationError:
    abort(400)
```

### If you must round-trip state through the client, sign it

```python
# Bind client-held state with an HMAC and verify on every request
import hmac, hashlib, json

def seal(state: dict, key: bytes) -> str:
    body = json.dumps(state, separators=(',', ':')).encode()
    tag = hmac.new(key, body, hashlib.sha256).hexdigest()
    return base64.b64encode(body).decode() + '.' + tag

def unseal(token: str, key: bytes) -> dict:
    b64, tag = token.split('.', 1)
    body = base64.b64decode(b64)
    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, expected):   # constant-time compare
        raise SecurityError("state tampering detected")
    return json.loads(body)
```

### Verify tokens correctly

- **Pin the algorithm**: never let the token's own header choose it; reject `alg=none` and unexpected algorithms.
- **Verify, don't just decode**: use the verifying API with the correct key on every use.
- **Keep authoritative state server-side** where you can; a session ID that maps to server storage cannot be tampered into new privileges.

```python
# JWT: pin algorithms and always verify
import jwt   # PyJWT
claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])  # explicit allow-list
# Never: jwt.decode(token, options={"verify_signature": False})
```

### Harden Java / .NET deserialization if it cannot be removed

- **Java**: apply a strict deserialization allow-list with `ObjectInputFilter` (JEP 290); prefer JSON/DTO mapping over native serialization.
- **.NET**: avoid `BinaryFormatter` entirely (deprecated for security); use `System.Text.Json` with known types.
- **PHP**: avoid `unserialize` on user input; if unavoidable, pass `['allowed_classes' => false]`.

## Consolidated Checklist

- [ ] Lockfiles committed; CI installs in frozen, hash-verified mode.
- [ ] Internal package names scoped to a private registry (no confusion fallback).
- [ ] SCA runs in CI and fails the build on policy violations.
- [ ] All CDN scripts/styles carry SRI hashes; CSP enforces it.
- [ ] CI/CD uses least-privilege, short-lived credentials; signing is isolated.
- [ ] Actions/plugins pinned to immutable SHAs, not mutable tags.
- [ ] Protected branches, mandatory review, segregation of duties.
- [ ] Releases carry verifiable provenance; only signed artifacts deploy.
- [ ] Updates verify a pinned-key signature and block rollback before install.
- [ ] No native deserialization of untrusted data; data-only formats + schema validation.
- [ ] Client-held state is HMAC-sealed or kept server-side.
- [ ] Tokens verified with a pinned algorithm; `alg=none` rejected.

## Next Steps

- **[Overview](./overview.md)**: Concepts and why integrity failures matter
- **[Attack Vectors](./attack-vectors.md)**: The techniques these defenses stop
- **[Examples](./examples.md)**: Vulnerable vs. secure implementations
- **[Lab](./lab/unsigned-update-lab/)**: Practice prevention

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
