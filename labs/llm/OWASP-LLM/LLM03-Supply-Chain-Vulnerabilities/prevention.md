# Supply Chain Vulnerabilities - Prevention

## Table of Contents
- [The Layered Defense Model](#defense-model)
- [Layer 1: Provenance & Pinning](#l1)
- [Layer 2: Integrity & Signatures](#l2)
- [Layer 3: Prefer Inert Formats (safetensors)](#l3)
- [Layer 4: Scan Models & Dependencies](#l4)
- [Layer 5: Lock Dependencies & Stop Confusion](#l5)
- [Layer 6: SBOM / AI-BOM](#l6)
- [Layer 7: Sandbox Model Loading](#l7)
- [Layer 8: Harden the Serving Stack](#l8)
- [Layer 9: Monitor & Detect](#l9)
- [Layer 10: License & Compliance Review](#l10)
- [Implementation Checklist](#checklist)

## The Layered Defense Model

No single control secures the LLM supply chain. A scanner misses semantic backdoors; a signature does not stop a legally toxic license; an inert format does not patch your inference server. The goal is **defense in depth** so that a failure in any one layer is caught by another.

```
Untrusted artifact
   |
   v
[1] Provenance & pinning     -- do I trust the source AND the exact revision?
[2] Integrity / signature    -- is it byte-for-byte what the author published?
[3] Inert format             -- can loading it possibly execute code?
[4] Scanning                 -- do known-bad opcodes / CVEs / secrets appear?
[5] Locked dependencies      -- is the whole tree pinned by hash, confusion-proof?
[6] AI-BOM                   -- is it inventoried and attributable?
[7] Sandboxed load           -- if it IS malicious, is it contained?
[8] Hardened serving         -- is the surrounding stack patched & authenticated?
[9] Monitoring               -- would we detect anomalous load-time behaviour?
[10] License / compliance    -- are we legally allowed to ship it?
   |
   v
Trusted for production
```

## Layer 1: Provenance & Pinning

**Never pull by a mutable name.** Pin every model to an immutable commit revision, and load only from an explicit allow-list of sources. This closes the "latest"/tag-swap and account-takeover-in-place gaps at once (an in-place swap changes the revision hash).

```
from transformers import AutoModelForCausalLM

# INSECURE: floating -> whatever is on main today
# model = AutoModelForCausalLM.from_pretrained("some-org/model")

# SECURE: pin to an immutable commit; never auto-run repo code
MODEL_ID = "some-org/model"
REVISION = "9f1c2ae0b3d4e5f60718293a4b5c6d7e8f901234"  # exact commit SHA

model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    revision=REVISION,          # immutable pin
    trust_remote_code=False,    # refuse to import the repo's Python
)
```

```
# requirements-style allow-list for model sources (enforced in code/CI):
ALLOWED_SOURCES = {
    "some-org/model":  "9f1c2ae0b3d4e5f60718293a4b5c6d7e8f901234",
    "meta-llama/Llama-3.1-8B": "d5c3...pinned-sha...",
}
# CI fails if a load target/revision is not on the allow-list.
```

## Layer 2: Integrity & Signatures

Verify a **content hash** for every artifact before you load it, and adopt cryptographic signing (e.g. Sigstore / model signing) where the publisher supports it. A hash mismatch means "do not load," full stop.

```
import hashlib, sys

def verify_sha256(path: str, expected_hex: str) -> None:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected_hex:
        sys.exit(f"INTEGRITY FAIL: {path}\n  expected {expected_hex}\n  got      {actual}")

# Pin the known-good digest you recorded when you vetted the artifact:
verify_sha256("model.safetensors",
              "3b1f...recorded-good-digest...e9a0")
# Only now proceed to load.
```

```
# Verifying a signed artifact with Sigstore (conceptual CLI):
#   cosign verify-blob \
#     --certificate model.safetensors.crt \
#     --signature   model.safetensors.sig \
#     --certificate-identity   "release@trusted-org.example" \
#     --certificate-oidc-issuer "https://accounts.trusted-org.example" \
#     model.safetensors
# Fail closed if verification does not succeed.
```

## Layer 3: Prefer Inert Formats (safetensors)

The single highest-leverage control: **refuse code-executing formats from untrusted sources**. Prefer `safetensors`, which stores only tensors plus a JSON header and cannot execute code. Force safe loading paths explicitly.

```
from safetensors.torch import load_file

# SECURE: inert format, no pickle, no code execution possible
state_dict = load_file("model.safetensors")
model.load_state_dict(state_dict)
```

```
# If you MUST touch a pickle checkpoint, force weights-only unpickling
# (PyTorch 2.6+ defaults weights_only=True; set it explicitly regardless):
import torch
state = torch.load("legacy.bin", weights_only=True)   # blocks arbitrary globals

# Better: convert once, in a sandbox, then ship only the safetensors:
from safetensors.torch import save_file
save_file(state, "model.safetensors")
```

> **Policy:** untrusted `.bin/.pt/.ckpt/.pkl/.h5` are quarantined; only `safetensors` (or artifacts you converted yourself in a sandbox) reach production loaders.

## Layer 4: Scan Models & Dependencies

Scanning is a supporting control, not a guarantee (evasion exists), but it catches the bulk of commodity attacks and belongs in CI. Scan model artifacts for dangerous pickle opcodes, and scan dependencies for known CVEs and leaked secrets.

```
# Model artifact scanning in CI:
pip install picklescan
picklescan --path ./models/pytorch_model.bin      # flags dangerous opcodes
# (Also consider ModelScan-style tooling for h5/keras/joblib coverage.)

# Dependency / CVE scanning:
pip install pip-audit
pip-audit -r requirements.txt                     # known-vuln packages

# Secret scanning so YOUR tokens never leak (feeding attack vector #3):
detect-secrets scan > .secrets.baseline
```

```
# Fail the build on any finding (example CI gate):
set -euo pipefail
picklescan --path models/ || { echo "unsafe pickle detected"; exit 1; }
pip-audit -r requirements.txt --strict            # nonzero exit on vulns
```

## Layer 5: Lock Dependencies & Stop Confusion

Pin the **entire** dependency tree by hash, and scope your package index so a public typosquat/confusion package can never outrank your intended source.

```
# requirements.txt with hashes -- pip refuses anything that doesn't match:
transformers==4.44.2 \
  --hash=sha256:1a2b3c...  # exact artifact hash
safetensors==0.4.5 \
  --hash=sha256:9f8e7d...

# Install with hash enforcement:
pip install --require-hashes -r requirements.txt
```

```
# pip.conf / CI: pin the index and refuse cross-index version shopping.
# This defeats dependency confusion (the torchtriton-class attack).
[global]
index-url = https://pypi.internal.example/simple
# Do NOT set extra-index-url to a public mirror for internal names.
# For internal packages, use a namespace you also own on the public index.
```

```
// Node/TS equivalent: commit the lockfile and install from it only.
// package.json -> exact versions; then:
//   npm ci            (installs strictly from package-lock.json)
//   npm config set audit-level=moderate
// Scope internal packages: @your-org/thing, and reserve the scope publicly.
```

## Layer 6: SBOM / AI-BOM

You cannot defend what you have not inventoried. Generate a Software Bill of Materials for code *and* an **AI-BOM** that enumerates models, adapters, datasets, and their provenance. Regenerate it in CI so it never drifts.

```
# Standard SBOM (CycloneDX) for the Python deps:
pip install cyclonedx-bom
cyclonedx-py requirements -o sbom.json
```

```
# Minimal AI-BOM record per model artifact (store in version control):
{
  "component": "some-org/model",
  "type": "pre-trained-model",
  "revision": "9f1c2ae0b3d4e5f60718293a4b5c6d7e8f901234",
  "format": "safetensors",
  "sha256": "3b1f...e9a0",
  "source": "https://huggingface.co/some-org/model",
  "license": "apache-2.0",
  "adapters": [{"id": "internal/safety-lora", "revision": "a1b2..."}],
  "datasets": [{"id": "internal/curated-v3", "sha256": "77aa..."}],
  "verified_on": "2025-08-01",
  "scanned": {"picklescan": "pass", "pip_audit": "pass"}
}
```

## Layer 7: Sandbox Model Loading

Assume a given artifact *might* be malicious and load it where a payload cannot hurt you: an isolated process/container with **no network egress, no credentials, read-only mounts, dropped capabilities, and a non-root user**. This is essential for the unavoidable first load of any new untrusted model.

```
# Load/convert an untrusted model in a locked-down container:
docker run --rm \
  --network=none \                       # no exfiltration path
  --read-only \                          # immutable filesystem
  --cap-drop=ALL \                       # no extra kernel capabilities
  --security-opt=no-new-privileges \
  --user 65534:65534 \                   # nobody, non-root
  --pids-limit=128 --memory=8g \
  -v "$PWD/untrusted:/in:ro" \
  -v "$PWD/out:/out" \
  model-vetter:latest \
  python /convert.py /in/model.bin /out/model.safetensors
# If a pickle payload fires, it has no network, no creds, no persistence.
```

```
# convert.py runs inside the sandbox: scan -> weights-only load -> re-emit safe
import torch, subprocess, sys
from safetensors.torch import save_file

src, dst = sys.argv[1], sys.argv[2]
subprocess.run(["picklescan", "--path", src], check=True)   # fail closed
state = torch.load(src, weights_only=True, map_location="cpu")
save_file(state, dst)   # only the inert artifact leaves the sandbox
```

## Layer 8: Harden the Serving Stack

Treat the inference server, UI, vector DB, and orchestrator as first-class supply chain components. Patch them, pin their images by digest, and never expose their control planes.

```
# Pin container images by DIGEST, not tag (defeats :latest swap):
FROM inference-server@sha256:5d41402abc4b2a76b9719d911017c592...

# Runtime hardening:
#   - Ray / cluster dashboards: bound to localhost or behind authenticated proxy
#   - Gradio / demo UIs: authenticated, not internet-exposed, kept patched
#   - Vector DB: auth required, private network, least-privilege service account
#   - Regular SCA (pip-audit / trivy) on the serving image in CI
```

```
# Scan the built serving image for OS + library CVEs before release:
trivy image --exit-code 1 --severity HIGH,CRITICAL myorg/inference:build-123
```

## Layer 9: Monitor & Detect

Instrument model loading so anomalous behaviour is visible. A model that opens a socket, spawns a shell, or reads credentials *while loading* is a compromise in progress.

```
# Runtime guardrails around the load step:
#   - egress deny-by-default on inference hosts; alert on any outbound connect
#     from the model-loading process
#   - EDR / falco rules: flag exec of shells, curl/wget, or crypto miners
#     spawned by the python model-loader
#   - log & alert on: unexpected process children, new outbound DNS,
#     reads of ~/.aws, env dumps, or writes outside the model cache
#   - re-verify artifact hashes at deploy time and periodically at runtime
#     (detects an upstream swap after your initial vetting)
```

## Layer 10: License & Compliance Review

Provenance includes the legal chain. Before shipping, confirm you may actually use the model and its training data for your purpose.

- **Model license**: Is it truly permissive (Apache-2.0, MIT), or a "community"/restricted license with acceptable-use and scale clauses (some Llama-class licenses), or non-commercial?
- **Dataset license & lawfulness**: Was the training/RAG data licensed for your use? Non-commercial or copyright-encumbered data creates downstream liability.
- **Provider terms**: For hosted models/APIs, can terms, data-retention, or training-on-your-inputs change under you? Record the version you agreed to.
- **Attribution & redistribution**: Do you meet notice/attribution obligations when you redistribute weights or a fine-tune?

> Record the license, source, and review date in the AI-BOM (Layer 6). "We cannot legally ship this model" is a supply chain failure exactly as blocking as "this model will not load."

## Implementation Checklist

1. **Pin** every model to an immutable revision; load only from an allow-list; `trust_remote_code=False`.
2. **Verify** a recorded SHA-256 (and signature where available) before every load; fail closed.
3. **Prefer safetensors**; quarantine pickle formats from untrusted sources; force `weights_only=True` if unavoidable.
4. **Scan** models (picklescan/ModelScan) and dependencies (pip-audit) in CI; gate the build on findings.
5. **Lock** dependencies with hashes (`--require-hashes`, `npm ci`); scope indexes to defeat confusion; reserve internal namespaces publicly.
6. **Inventory** everything in an SBOM + AI-BOM regenerated in CI.
7. **Sandbox** the first load of any untrusted artifact (no net, no creds, non-root, read-only).
8. **Harden** the serving stack: pin images by digest, patch, authenticate control planes, scan images.
9. **Monitor** load-time behaviour: egress deny-by-default, alert on shells/exfiltration, re-verify hashes at deploy.
10. **Review** license, dataset lawfulness, and provider terms before shipping.

## Next Steps

- **[Examples](examples.html)**: Vulnerable vs. secure implementations you can copy.
- **[Overview](overview.html)**: The concepts and why they matter.
- **[Hands-On Lab](./lab/supply-chain-vulnerabilities/)**: Apply these defenses against a deliberately untrusted model.
