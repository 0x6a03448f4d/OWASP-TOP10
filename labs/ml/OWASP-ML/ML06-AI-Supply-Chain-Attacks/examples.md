# ML06: AI Supply Chain Attacks - Code Examples

Each pair below shows an **insecure** way to bring a third-party ML component into your pipeline and the **secure** version. The focus is the ML06 core: loading untrusted models, handling dependencies, and disabling remote code execution.

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the insecure snippets are shown so you can recognise and remove these patterns from systems you own.

## 1. Loading a Downloaded Model (PyTorch)

### Insecure
```python
import torch

# torch.load uses pickle under the hood: loading an untrusted file
# can execute arbitrary code BEFORE you ever run inference.
state = torch.load("downloaded/model.pt")     # RCE if the file is malicious
model.load_state_dict(state)
```

### Secure
```python
import hashlib
from safetensors.torch import load_file

def verify_sha256(path, expected):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    if h.hexdigest() != expected:
        raise ValueError("Integrity check failed - refusing to load")

# 1) Verify integrity against a hash you recorded from a trusted source
verify_sha256("downloaded/model.safetensors", KNOWN_GOOD_SHA256)

# 2) Load a DATA-ONLY format: safetensors cannot execute code on load
state = load_file("downloaded/model.safetensors")
model.load_state_dict(state)

# If you are stuck with a .pt file, restrict unpickling to tensors:
#   state = torch.load("model.pt", weights_only=True)   # better, not perfect
# ...and still prefer converting to safetensors.
```

## 2. Pulling a Pretrained Model from a Hub (transformers)

### Insecure
```python
from transformers import AutoModel

# Mutable ref + repo code execution = you run whatever the author ships today.
model = AutoModel.from_pretrained(
    "some-org/cool-model",       # who is 'some-org'? unknown provenance
    revision="main",             # mutable: can change under you at any time
    trust_remote_code=True,      # runs the repo's Python on your machine
)
```

### Secure
```python
from transformers import AutoModel

# Pin an immutable commit, refuse repo code, prefer safetensors weights.
model = AutoModel.from_pretrained(
    "some-org/cool-model",
    revision="e3b0c44298fc1c149afbf4c8996fb92427ae41e4",  # exact commit hash
    trust_remote_code=False,     # do NOT execute repo-provided Python
    use_safetensors=True,        # load data-only weights when available
)
# Record source URL, commit, license, and file hash in your AI-BOM.
```

## 3. Loading a scikit-learn Model (joblib / pickle)

### Insecure
```python
import joblib

# joblib uses pickle: a crafted .joblib runs code on load.
clf = joblib.load("vendor/classifier.joblib")   # untrusted -> RCE risk
```

### Secure
```python
import hashlib, joblib, subprocess

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

path = "vendor/classifier.joblib"

# 1) Scan the artifact for malicious pickle opcodes first
subprocess.run(["picklescan", "--path", path], check=True)

# 2) Verify integrity against a recorded good hash
assert sha256(path) == KNOWN_GOOD_SHA256, "integrity check failed"

# 3) Load inside a sandbox with no network egress and no credentials.
#    Prefer distributing sklearn models via ONNX/skops where possible,
#    which avoid arbitrary-code deserialization.
clf = joblib.load(path)
```

## 4. Installing ML Dependencies (pip)

### Insecure
```
# requirements.txt
torch
transformers
torchvison        # <-- TYPO of torchvision: a typosquat may own this name

# install with no pinning, no hashes, public index only
pip install -r requirements.txt
```

### Secure
```
# requirements.lock — exact versions AND hashes (pip-compile --generate-hashes)
torch==2.3.1 \
  --hash=sha256:1111...
transformers==4.41.2 \
  --hash=sha256:2222...
torchvision==0.18.1 \
  --hash=sha256:3333...
safetensors==0.4.3 \
  --hash=sha256:4444...

# Install from a trusted internal mirror, enforce hashes, no fallback.
pip install --require-hashes \
            --index-url https://pypi.internal.example/simple \
            -r requirements.lock

# In CI, gate the build on SCA:
#   pip-audit -r requirements.lock
#   safety check -r requirements.lock
```

## 5. Using a Public Dataset (datasets)

### Insecure
```python
from datasets import load_dataset

# Community dataset, mutable, no provenance or integrity check.
ds = load_dataset("community/scraped-faces")   # could be poisoned upstream
train(model, ds)                               # backdoor baked into weights
```

### Secure
```python
import hashlib
from datasets import load_dataset

# 1) Pin an immutable revision of the dataset
ds = load_dataset(
    "community/scraped-faces",
    revision="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",   # exact commit
)

# 2) Verify the snapshot checksum against a recorded value
def fingerprint(dataset):
    m = hashlib.sha256()
    for row in dataset:
        m.update(repr(sorted(row.items())).encode())
    return m.hexdigest()

assert fingerprint(ds["train"]) == KNOWN_GOOD_FINGERPRINT, "dataset changed"

# 3) Audit for injected triggers / anomalies before training (see ML02),
#    and record source + checksum + curator in the AI-BOM.
train(model, ds)
```

## 6. Sandboxing the Load of an Unvetted Model

### Insecure
```python
# Loading straight on the training node, which holds cloud credentials
# and has open network egress. A payload can steal creds and phone home.
import torch
model = torch.load("unvetted/model.pt")   # full blast radius on compromise
```

### Secure
```python
# Load untrusted artifacts in an isolated container: no network, no creds,
# read-only FS, non-root, resource-limited. Only promote if it passes.
#
#   docker run --rm --network none --read-only --user 65534:65534 \
#       --cap-drop ALL --memory 4g --pids-limit 128 \
#       -v "$PWD/unvetted:/model:ro" model-sandbox:latest \
#       python /scan/inspect.py /model
#
# inspect.py (runs inside the sandbox):
import subprocess, sys
path = sys.argv[1]
subprocess.run(["modelscan", "-p", path], check=True)   # scan for payloads
# convert to safetensors, verify shapes/keys, emit a report — never grant
# this process production credentials or outbound network access.
```

## What Changed, and Why

| Risk | Insecure | Secure |
|------|----------|--------|
| Deserialization | `torch.load`/`joblib`/pickle on untrusted files | safetensors (data-only); scan + `weights_only` as backstop |
| Model provenance | Unknown org, `revision="main"` | Pinned commit, recorded source + hash in AI-BOM |
| Remote code | `trust_remote_code=True` | `trust_remote_code=False`; vendor + review if needed |
| Dependencies | Unpinned, typo-prone, public index | Version + hash pins, trusted mirror, SCA in CI |
| Datasets | Mutable, no checksum | Pinned revision, fingerprint, provenance recorded |
| Loading environment | On a credentialed, networked node | Sandboxed: no net, no creds, scanned before promotion |

## Key Takeaways

1. **Data-only beats code-executing** — safetensors instead of `torch.load`/`joblib` for untrusted weights.
2. **Pin and verify** — exact commits, exact versions, and recorded hashes for models, datasets, and packages.
3. **Keep `trust_remote_code` off** — only run third-party model code after you have vendored and reviewed it.
4. **Scan in CI** — picklescan/ModelScan for artifacts, pip-audit/safety for dependencies.
5. **Sandbox the load** — no credentials, no egress, so a payload that slips through has nowhere to go.

## Next Steps

- **[Prevention](prevention.html)**: The full layered strategy for securing the ML supply chain
- **[Attack Vectors](attack-vectors.html)**: How these components get compromised
- **[Back to the ML Security track](/learn/ml)**
- **[Practice](/practice)**: Apply these concepts hands-on
