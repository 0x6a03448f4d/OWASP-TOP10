# ML06: AI Supply Chain Attacks - Prevention

## Prevention Strategy Overview

Preventing supply-chain compromise is less about a single control and more about **refusing to trust any ingredient you have not verified**:

1. Vet and pin every source—models, datasets, packages, and tooling.
2. Verify provenance and integrity (hashes, signatures, model cards) before use.
3. Prefer safe, data-only formats; never deserialize untrusted files with code-executing loaders.
4. Scan artifacts and dependencies automatically in CI.
5. Sandbox loading, maintain an AI-BOM, and monitor for drift and anomalous behavior.

### Core Principles

- **Trust is earned per artifact**: a plausible name and a popular hub are not provenance.
- **Data-only by default**: prefer safetensors; treat pickle/`torch.load` of untrusted files as running a program.
- **Pin everything, all the way down**: versions and hashes for packages, digests for images, revisions for models.
- **Assume load = execute**: sandbox the load step with least privilege so a payload has nowhere to go.

## 1. Prefer Safe Serialization (safetensors over pickle)

The single highest-leverage control: use a data-only format so loading a model cannot execute code.

```python
# INSECURE: torch.load uses pickle -> arbitrary code on load
import torch
state = torch.load("downloaded_model.pt")          # never on untrusted files

# SECURE: safetensors stores tensors only, no code path
from safetensors.torch import load_file
state = load_file("downloaded_model.safetensors")  # data-only, no execution
model.load_state_dict(state)
```

When a framework forces pickle, load in a sandbox (next sections) and scan first. Newer `torch.load` supports `weights_only=True`, which restricts unpickling to tensors—use it, but treat safetensors as the real fix.

## 2. Verify Provenance and Integrity Before Use

Pin a specific revision and verify a known-good hash for every downloaded artifact.

```python
import hashlib

def verify_sha256(path, expected):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected:
        raise ValueError(f"Integrity check FAILED: {actual} != {expected}")
    return True

# Pin the exact model revision, then verify the file hash you recorded:
verify_sha256("model.safetensors", KNOWN_GOOD_SHA256)
```

```python
# Hugging Face: pin an immutable revision (commit hash), not a mutable tag
from transformers import AutoModel
model = AutoModel.from_pretrained(
    "org/model",
    revision="e3b0c44298fc1c149afbf4c8996fb924",  # exact commit, not "main"
    trust_remote_code=False,                        # do not run repo code
)
```

Record the publisher, model card, source URL, and hash in your artifact inventory so every future pull is checked against a known-good baseline. Verify signatures where the publisher provides them (e.g., Sigstore-style signing).

## 3. Never Enable `trust_remote_code` on Untrusted Repos

```python
# INSECURE: runs the repo's Python on your machine
AutoModel.from_pretrained("unknown/repo", trust_remote_code=True)

# SECURE: keep it disabled (the default); only enable for repos you audited
AutoModel.from_pretrained("your-org/reviewed-model", trust_remote_code=False)
```

If a model genuinely requires custom code, vendor and review that code yourself, pin it, and run it in the sandbox described below—do not fetch-and-execute it from a third party at load time.

## 4. Scan Models and Dependencies in CI

Gate every artifact and dependency on automated scanning.

```bash
# 1) Scan model files for malicious pickle / code payloads
picklescan --path ./models/model.pt
modelscan -p ./models/                # ModelScan: pickle, Keras Lambda, etc.

# 2) Software composition analysis on ML dependencies
pip-audit -r requirements.txt         # known-vulnerable packages
safety check -r requirements.txt

# 3) Container image + CVE scan for training/serving images
trivy image myorg/train:1.4.2 --severity HIGH,CRITICAL
```

Run these on every pull request and on a schedule, so a newly disclosed malicious package or model is caught before it reaches training or production.

## 5. Pin ML Dependencies by Version and Hash

Unpinned dependencies are how typosquatting and confusion succeed. Pin exact versions and hashes, from a trusted index.

```
# requirements.txt — exact versions
torch==2.3.1
transformers==4.41.2
safetensors==0.4.3
scikit-learn==1.5.0

# Enforce hashes so a tampered artifact is rejected:
#   pip install --require-hashes -r requirements.lock
transformers==4.41.2 \
  --hash=sha256:aaaa...    # generated with pip-compile --generate-hashes
```

```bash
# Point the resolver at a trusted, curated index / mirror and disable fallback
pip install --index-url https://pypi.internal.example/simple \
            --no-cache-dir --require-hashes -r requirements.lock
```

Defeat dependency confusion by scoping internal package names to your private index and never allowing a public fallback to override them.

## 6. Sandbox Model Loading

Assume any load may execute code and give it nowhere useful to go.

```bash
# Load untrusted / not-yet-vetted models in an isolated environment:
#   - no network egress (block outbound so a payload cannot phone home)
#   - no cloud credentials mounted (no ambient AWS/GCP/Azure tokens)
#   - read-only filesystem, non-root user, minimal container
#   - resource limits (CPU/mem/GPU) and a short timeout

docker run --rm --network none --read-only --user 65534:65534 \
    --cap-drop ALL --memory 4g --pids-limit 128 \
    -v "$PWD/model:/model:ro" model-scan-sandbox:latest \
    python /scan/load_and_inspect.py /model
```

Only promote an artifact out of the sandbox after it passes scanning and integrity checks. Serving nodes should never hold standing credentials that a load-time payload could steal.

## 7. Maintain an SBOM / AI-BOM

You cannot secure a supply chain you cannot enumerate. Track every component—including models and datasets.

```bash
# Generate a Software Bill of Materials for packages...
syft dir:. -o cyclonedx-json > sbom.json

# ...and extend it to an AI-BOM that also records:
#   - each model: name, source, revision/commit, sha256, license, model card
#   - each dataset: source, version, checksum, provenance notes
#   - training frameworks + versions used to produce the model
```

An AI-BOM makes incident response tractable: when a malicious package or model is disclosed, you can answer "are we affected?" in minutes.

## 8. Use Trusted Registries and Mirrors

- Proxy public models/datasets/packages through an internal, curated mirror rather than pulling directly from the internet.
- Require artifacts to be scanned and signed before they are admitted to the internal registry ("promotion" gates).
- Make production pull from immutable, digest-pinned references—never a mutable `latest` or `main`.

```python
# Model registry policy (pseudocode): only signed + scanned artifacts are servable
if not (artifact.signature_valid and artifact.scan_passed):
    reject("artifact not admitted: must be signed and scanned")
```

## 9. Vet Datasets and Their Provenance

- Record where each dataset came from, who curated it, and a checksum of the exact snapshot you used.
- Prefer versioned, immutable dataset snapshots over live/"latest" downloads that can change under you.
- Audit community datasets for injected triggers or anomalous samples before training (overlaps with ML02 defenses).

## 10. Monitoring and Detection

Watch for the signatures of a compromised component at load and at runtime.

```python
# Alert if a model load touches the network or unexpected files
SUSPICIOUS = ("connect", "socket", "subprocess", "os.system", "/root/.ssh")

def audit_load(events):
    for e in events:                      # from a sandboxed strace/seccomp trace
        if any(s in e for s in SUSPICIOUS):
            log.warning("Anomalous behavior during model load: %s", e)
            send_security_alert(e)
```

Also alert on: unpinned or newly added dependencies, models pulled from unknown sources, hash mismatches against the AI-BOM, and any use of `trust_remote_code=True` or `torch.load` on external files in code review.

## Defense Summary

| Risk | Primary Control | Backstop |
|------|-----------------|----------|
| Code execution on load | safetensors / data-only formats | Sandbox + picklescan/ModelScan |
| Backdoored weights | Provenance + signature verification | Behavioral/trigger auditing |
| Typosquatting / confusion | Pin version+hash, private index | SCA (pip-audit), review |
| `trust_remote_code` | Keep disabled by default | Vendor + review any custom code |
| Poisoned dataset | Provenance + checksum + snapshot | Data auditing |
| Transit/storage tampering | Hash/signature verification | Trusted mirror, immutable refs |
| Vulnerable MLOps tooling | Patch + auth + image scanning | Network isolation, SBOM |

## Key Takeaways

1. **Prefer safetensors** — data-only formats make "load a model" stop meaning "run a program."
2. **Verify before you trust** — pin revisions and check hashes/signatures for every model, dataset, and package.
3. **Pin the whole tree** — versions and hashes defeat typosquatting and dependency confusion.
4. **Disable `trust_remote_code`** — it is remote code execution by design for untrusted repos.
5. **Scan, sandbox, and inventory** — ModelScan/SCA in CI, isolated loading, and an AI-BOM for fast response.

## Next Steps

- **[Code Examples](examples.html)**: Insecure vs. secure model loading and dependency handling
- **[Attack Vectors](attack-vectors.html)**: Understand what you're defending against
- **[Back to the ML Security track](/learn/ml)**
- **[Practice](/practice)**: Apply these concepts hands-on
