# Software and Data Integrity Failures - Examples

Each pair below shows a **vulnerable** implementation and the **secure** version that verifies integrity. The examples cover the areas that dominate real findings: CI/CD pipelines, auto-update mechanisms in Node and Python, Java deserialization, and CDN/Subresource Integrity.

## Table of Contents

- [1. CI/CD Pipeline (GitHub Actions YAML)](#1-cicd-pipeline-github-actions-yaml)
- [2. Auto-Update Mechanism (Node.js)](#2-auto-update-mechanism-nodejs)
- [3. Auto-Update Mechanism (Python)](#3-auto-update-mechanism-python)
- [4. Deserialization (Java)](#4-deserialization-java)
- [5. Deserialization (Python pickle)](#5-deserialization-python-pickle)
- [6. CDN Script Integrity (SRI)](#6-cdn-script-integrity-sri)
- [7. Trusted Client-Side State](#7-trusted-client-side-state)

## 1. CI/CD Pipeline (GitHub Actions YAML)

### Vulnerable

```yaml
name: release
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all            # every job can write everything
    steps:
      - uses: actions/checkout@main   # mutable ref: today's "main" runs in CI
      - uses: some-org/publish@v1     # mutable tag can be repointed to malware
      - run: npm install              # resolves floating ranges, runs any script
      - run: npm publish              # unsigned artifact, broad token in scope
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}   # long-lived, wide-scope secret
```

**Problems**: write-all permissions, mutable action refs, unpinned dependencies with install scripts, a long-lived publish token exposed to every step, and no artifact signing. Any compromised step can exfiltrate the token or inject code before publish.

### Secure

```yaml
name: release
on:
  push:
    tags: ['v*']                      # release only from reviewed, tagged commits

permissions:
  contents: read                      # least privilege by default

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@017...   # pinned SHA; block egress
        with:
          egress-policy: block
          allowed-endpoints: registry.npmjs.org:443 github.com:443
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608  # v4 pinned
      - run: npm ci                    # frozen, hash-verified install
      - run: npm run build && npm test

  publish:
    needs: build
    runs-on: ubuntu-latest
    environment: production            # requires approval / protected env
    permissions:
      id-token: write                  # short-lived OIDC for provenance
      contents: read
    steps:
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
      - run: npm ci
      # npm provenance ties the published package to THIS verified workflow:
      - run: npm publish --provenance --access public
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}   # scoped, isolated to this job
```

**Fixes**: read-only default permissions, pinned action SHAs, frozen dependency install, a separate protected publish job, short-lived OIDC provenance, and egress control so a poisoned step cannot phone home.

## 2. Auto-Update Mechanism (Node.js)

### Vulnerable

```javascript
const https = require('https');
const { execFile } = require('child_process');
const fs = require('fs');

// Downloads a binary and runs it. No signature, no version check.
function autoUpdate(manifestUrl) {
  https.get(manifestUrl, res => {
    let body = '';
    res.on('data', c => body += c);
    res.on('end', () => {
      const { url } = JSON.parse(body);         // trusts manifest blindly
      const file = fs.createWriteStream('/opt/app/update.bin');
      https.get(url, r => r.pipe(file).on('finish', () => {
        execFile('/opt/app/update.bin');        // executes whatever arrived
      }));
    });
  });
}
```

**Problem**: whatever the manifest points to is executed. An on-path attacker or a compromised mirror achieves remote code execution, often at the updater's (elevated) privilege.

### Secure

```javascript
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');

// Public key SHIPPED WITH THE APP (pinned); never fetched at runtime.
const PINNED_PUBKEY = fs.readFileSync(__dirname + '/release-ed25519.pub');
const CURRENT_VERSION = require('./version.json').version;

function verify(buf, sigB64) {
  return crypto.verify(null, buf, PINNED_PUBKEY, Buffer.from(sigB64, 'base64'));
}

async function autoUpdate(manifest) {
  // manifest = { version, url, sha256, artifactSig, manifestSig }
  const manifestBytes = Buffer.from(JSON.stringify({
    version: manifest.version, url: manifest.url, sha256: manifest.sha256,
  }));
  if (!verify(manifestBytes, manifest.manifestSig))
    throw new Error('manifest signature invalid');
  if (semverLte(manifest.version, CURRENT_VERSION))
    throw new Error('refusing rollback / replay');

  const artifact = await download(manifest.url);           // Buffer
  const digest = crypto.createHash('sha256').update(artifact).digest('hex');
  if (digest !== manifest.sha256)
    throw new Error('artifact hash mismatch');
  if (!verify(artifact, manifest.artifactSig))
    throw new Error('artifact signature invalid');

  fs.writeFileSync('/opt/app/update.bin', artifact);        // trusted only now
  install('/opt/app/update.bin');
}
```

**Fixes**: the manifest and artifact are both signature-verified against a pinned key, the hash is checked, and rollbacks are rejected. An unverifiable update is never written or executed.

## 3. Auto-Update Mechanism (Python)

### Vulnerable

```python
import requests, subprocess

def update():
    info = requests.get("http://updates.example.com/latest.json").json()
    blob = requests.get(info["url"]).content     # plain HTTP, no verification
    with open("/opt/app/plugin.py", "wb") as f:
        f.write(blob)
    subprocess.run(["python", "/opt/app/plugin.py"])   # runs untrusted code
```

**Problem**: plaintext channel and zero verification. Anyone on the path substitutes the payload and gains code execution.

### Secure

```python
import requests, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Pinned verification key compiled/shipped with the app:
PINNED_PUBKEY = Ed25519PublicKey.from_public_bytes(_SHIPPED_PUBKEY_BYTES)
CURRENT_VERSION = (5, 1, 0)

def _verify(data: bytes, sig: bytes):
    PINNED_PUBKEY.verify(sig, data)   # raises InvalidSignature on tampering

def update():
    # HTTPS is necessary but NOT sufficient; signatures are the real control.
    manifest = requests.get("https://updates.example.com/latest.json").json()
    manifest_bytes = f"{manifest['version']}|{manifest['url']}|{manifest['sha256']}".encode()
    try:
        _verify(manifest_bytes, bytes.fromhex(manifest["manifest_sig"]))
    except InvalidSignature:
        raise SystemExit("manifest signature invalid - aborting")

    if tuple(manifest["version"]) <= CURRENT_VERSION:
        raise SystemExit("refusing rollback / replay")

    blob = requests.get(manifest["url"]).content
    if hashlib.sha256(blob).hexdigest() != manifest["sha256"]:
        raise SystemExit("artifact hash mismatch")
    try:
        _verify(blob, bytes.fromhex(manifest["artifact_sig"]))
    except InvalidSignature:
        raise SystemExit("artifact signature invalid - aborting")

    # Only reached if EVERYTHING verified:
    with open("/opt/app/plugin.py", "wb") as f:
        f.write(blob)
```

**Fixes**: HTTPS transport plus pinned-key signature verification of both manifest and artifact, a hash check, and rollback protection. Note that HTTPS alone would not have stopped a compromised mirror.

## 4. Deserialization (Java)

### Vulnerable

```java
// Reconstructs arbitrary objects from an attacker-controlled stream.
public Session load(byte[] data) throws Exception {
    ObjectInputStream ois =
        new ObjectInputStream(new ByteArrayInputStream(data));
    return (Session) ois.readObject();   // gadget chains -> RCE
}
```

**Problem**: native Java deserialization instantiates any serializable class on the classpath and runs its lifecycle methods, enabling well-known gadget-chain exploits.

### Secure

```java
// Option A (best): don't use native serialization. Use JSON + a fixed type.
public Session load(byte[] data) throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    return mapper.readValue(data, Session.class);   // data-only, fixed target type
}

// Option B (if native serialization is unavoidable): strict allow-list filter.
public Session loadFiltered(byte[] data) throws Exception {
    ObjectInputStream ois =
        new ObjectInputStream(new ByteArrayInputStream(data));
    ois.setObjectInputFilter(info -> {              // JEP 290
        Class<?> c = info.serialClass();
        if (c == null) return ObjectInputFilter.Status.UNDECIDED;
        return c == Session.class
            ? ObjectInputFilter.Status.ALLOWED
            : ObjectInputFilter.Status.REJECTED;    // everything else denied
    });
    return (Session) ois.readObject();
}
```

**Fixes**: prefer a data-only format bound to a known type; if native deserialization must remain, restrict it to an explicit class allow-list so gadget classes are rejected before instantiation.

## 5. Deserialization (Python pickle)

### Vulnerable

```python
import pickle, base64

@app.route("/restore")
def restore():
    raw = base64.b64decode(request.cookies["state"])
    return render(pickle.loads(raw))     # __reduce__ executes -> RCE
```

### Secure

```python
import json
from flask import request, abort
from pydantic import BaseModel, ValidationError

class State(BaseModel):
    view: str
    page: int

@app.route("/restore")
def restore():
    try:
        data = json.loads(request.cookies["state"])   # data only
        state = State(**data)                          # schema validated
    except (ValueError, ValidationError):
        abort(400)
    return render(state)
```

**Fixes**: replace `pickle` with data-only JSON and validate into a strict schema. The parser can never execute code, and malformed input is rejected.

## 6. CDN Script Integrity (SRI)

### Vulnerable

```html
<!-- Executes whatever the CDN returns, even if compromised -->
<script src="https://cdn.example.com/pay/2.4.0/checkout.js"></script>
```

### Secure

```html
<!-- Runs only if the fetched bytes match the pinned hash -->
<script src="https://cdn.example.com/pay/2.4.0/checkout.js"
        integrity="sha384-q8Wj5r2Fh0m3s...pinned-hash..."
        crossorigin="anonymous"></script>

<!-- Optional: enforce that scripts MUST carry SRI via CSP -->
<!-- Content-Security-Policy: require-sri-for script; -->
```

**Fixes**: the browser refuses to run a tampered file because its hash no longer matches the pinned `integrity` value—neutralising a compromised CDN or hijacked URL.

## 7. Trusted Client-Side State

### Vulnerable

```javascript
// Node/Express: reads price and role straight from a cookie
app.post('/checkout', (req, res) => {
  const total = Number(req.cookies.cart_total);   // user-editable
  const role  = req.cookies.role;                 // user-editable
  charge(total);                                  // "cart_total=0.01"
  if (role === 'admin') showAdminReceipt();       // "role=admin"
});
```

### Secure

```javascript
const crypto = require('crypto');
const KEY = process.env.STATE_HMAC_KEY;           // server-only secret

function seal(obj) {
  const body = Buffer.from(JSON.stringify(obj));
  const tag = crypto.createHmac('sha256', KEY).update(body).digest('hex');
  return body.toString('base64') + '.' + tag;
}
function unseal(token) {
  const [b64, tag] = token.split('.');
  const body = Buffer.from(b64, 'base64');
  const expected = crypto.createHmac('sha256', KEY).update(body).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(tag), Buffer.from(expected)))
    throw new Error('state tampering detected');
  return JSON.parse(body);
}

app.post('/checkout', (req, res) => {
  // Authoritative values come from the server; the cookie is only an opaque ref.
  const cart = loadCartFromDb(req.session.userId);   // price from DB, not cookie
  const role = req.session.role;                     // role from server session
  charge(cart.total);
});
```

**Fixes**: keep authoritative state (price, role) server-side; where client state is genuinely needed, seal it with an HMAC and verify it with a constant-time comparison so any edit is detected and rejected.

## Summary

| Area | Vulnerable pattern | Secure pattern |
|------|--------------------|----------------|
| CI/CD | write-all, mutable tags, unsigned publish | Least privilege, pinned SHAs, provenance |
| Auto-update | Download and execute | Verify pinned-key signature + hash + version |
| Deserialization | Native deserializer on user input | Data-only format + schema / allow-list filter |
| CDN assets | Bare `<script src>` | SRI hash (+ CSP require-sri-for) |
| Client state | Trust cookie values | Server-side state or HMAC-sealed + verified |

## Next Steps

- **[Overview](./overview.md)**: Concepts and why integrity failures matter
- **[Attack Vectors](./attack-vectors.md)**: How these vulnerable patterns are exploited
- **[Prevention](./prevention.md)**: The layered defenses behind these fixes
- **[Lab](./lab/unsigned-update-lab/)**: Hands-on practice

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
