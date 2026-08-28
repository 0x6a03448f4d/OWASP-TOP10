# Supply Chain Vulnerabilities - Examples

## Table of Contents
- [Example 1: Loading a Model from a Hub](#ex1)
- [Example 2: Loading Checkpoint Weights](#ex2)
- [Example 3: trust_remote_code](#ex3)
- [Example 4: Installing Dependencies](#ex4)
- [Example 5: Dependency Confusion / Index Scoping](#ex5)
- [Example 6: LoRA Adapter from a Stranger](#ex6)
- [Example 7: Referencing a Dataset](#ex7)
- [Example 8: Sandboxed First Load](#ex8)
- [Example 9: Node/TS Model Download](#ex9)
- [Example 10: Serving Image & CI Gate](#ex10)

Each example shows a realistic **vulnerable** pattern and the **secure** replacement. Python is primary (Hugging Face / Transformers, pip, PyTorch); Node/TS appears where it is the natural runtime.

## Example 1: Loading a Model from a Hub

### Vulnerable
```
from transformers import AutoModelForCausalLM

# Floating reference: "whatever is on main right now", no integrity check.
# An in-place swap (token takeover) or a new commit ships straight to prod.
model = AutoModelForCausalLM.from_pretrained("some-org/model")
```

### Secure
```
from transformers import AutoModelForCausalLM

MODEL_ID  = "some-org/model"
REVISION  = "9f1c2ae0b3d4e5f60718293a4b5c6d7e8f901234"   # immutable commit SHA

ALLOWED = {MODEL_ID: REVISION}                            # explicit allow-list
if ALLOWED.get(MODEL_ID) != REVISION:
    raise SystemExit("model/revision not on allow-list")

model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    revision=REVISION,           # pin -> a swap changes the SHA and is rejected
    trust_remote_code=False,     # never auto-run the repo's Python
)
```

## Example 2: Loading Checkpoint Weights

### Vulnerable
```
import torch

# torch.load on a pickle checkpoint EXECUTES embedded code on load.
# The file "works" as a model, so nothing looks wrong.
state = torch.load("pytorch_model.bin")     # <-- RCE happens here
model.load_state_dict(state)
```

### Secure
```
import hashlib, sys
from safetensors.torch import load_file

def verify(path, expected):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != expected:
        sys.exit(f"INTEGRITY FAIL for {path}")

# Prefer an inert format; verify its hash first.
verify("model.safetensors", "3b1f...recorded-good-digest...e9a0")
state = load_file("model.safetensors")      # cannot execute code
model.load_state_dict(state)

# If a pickle file is truly unavoidable, force weights-only unpickling:
#   state = torch.load("legacy.bin", weights_only=True)   # blocks arbitrary globals
```

## Example 3: trust_remote_code

### Vulnerable
```
from transformers import AutoModel

# This flag imports and RUNS modeling_*.py / configuration_*.py from the repo.
# For an untrusted repo it is opt-in remote code execution.
model = AutoModel.from_pretrained("random-user/cool-model", trust_remote_code=True)
```

### Secure
```
from transformers import AutoModel

# Default off. If a model genuinely needs custom code, first VET that code:
#   1. clone the pinned revision
#   2. read modeling_*.py / configuration_*.py line by line
#   3. run it once in the sandbox from Example 8
#   4. vendor the reviewed code into your repo and load locally
model = AutoModel.from_pretrained(
    "some-org/standard-arch-model",
    revision="9f1c2ae...pinned...",
    trust_remote_code=False,     # keep it off for third-party repos
)
```

## Example 4: Installing Dependencies

### Vulnerable
```
# Unpinned, no hashes: resolver picks "newest", including a freshly
# published malicious version or a typosquat you mistyped.
pip install transformers safetensors huggingface_hub
```

### Secure
```
# requirements.txt -- exact versions + artifact hashes
transformers==4.44.2 \
  --hash=sha256:1a2b3c4d...
safetensors==0.4.5 \
  --hash=sha256:9f8e7d6c...
huggingface-hub==0.24.6 \
  --hash=sha256:0a1b2c3d...

# Install with hash enforcement -- anything not matching is rejected:
pip install --require-hashes -r requirements.txt

# In CI, also run:
pip-audit -r requirements.txt --strict     # fail on known CVEs
```

## Example 5: Dependency Confusion / Index Scoping

### Vulnerable
```
# pip.conf -- mixes a private index with a public mirror for ALL names.
# A public package named like your internal one, at a higher version, wins.
[global]
index-url       = https://pypi.internal.example/simple
extra-index-url = https://pypi.org/simple      # internal names can be shadowed here
```

### Secure
```
# pip.conf -- internal names resolve ONLY from the internal index.
[global]
index-url = https://pypi.internal.example/simple
# No public extra-index-url for internal namespaces.

# Also: register your internal package names on the PUBLIC index too
# (as placeholders you own) so no attacker can claim them.
# Node equivalent: use an @your-org/ scope and reserve it publicly;
# install strictly from the lockfile:
#   npm ci
```

## Example 6: LoRA Adapter from a Stranger

### Vulnerable
```
from peft import PeftModel

# Small, "harmless" adapter -- pulled by name, unpinned, unscanned.
# May carry a pickle payload OR a behavioural backdoor triggered by a phrase.
model = PeftModel.from_pretrained(base_model, "random-user/helpful-lora")
```

### Secure
```
from peft import PeftModel

ADAPTER  = "some-org/safety-lora"
REVISION = "a1b2c3d4...pinned..."

# 1) pin + verify hash (see Example 2), 2) scan the adapter file,
# 3) prefer safetensors adapter weights, 4) run behavioural evals with
#    known trigger patterns before promoting to production.
model = PeftModel.from_pretrained(
    base_model, ADAPTER, revision=REVISION,
)
# Treat adapters with the SAME scrutiny as base models -- not less.
```

## Example 7: Referencing a Dataset

### Vulnerable
```
from datasets import load_dataset

# Pulls "latest" of a community dataset by mutable name; content can change,
# and manifests that point at external URLs can be frontrun/poisoned.
ds = load_dataset("some-user/web-corpus")
```

### Secure
```
from datasets import load_dataset
import hashlib, json

DATASET  = "some-user/web-corpus"
REVISION = "c0ffee...pinned-commit..."         # pin the dataset revision too

ds = load_dataset(DATASET, revision=REVISION)

# For locally curated data, pin by CONTENT hash and verify before use:
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()

manifest = json.load(open("dataset.lock.json"))   # {file: expected_sha256}
for path, expected in manifest.items():
    assert sha256(path) == expected, f"dataset tampered: {path}"
```

## Example 8: Sandboxed First Load

### Vulnerable
```
# Vetting a brand-new model by loading it on a dev box that has
# AWS creds, network egress, and prod access. If it's malicious, game over.
python -c "import torch; torch.load('untrusted.bin')"
```

### Secure
```
# Load/convert untrusted artifacts in an isolated, powerless container.
docker run --rm \
  --network=none --read-only \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --user 65534:65534 --pids-limit=128 --memory=8g \
  -v "$PWD/untrusted:/in:ro" -v "$PWD/out:/out" \
  model-vetter:latest \
  python /convert.py /in/untrusted.bin /out/model.safetensors
```

```
# convert.py (runs inside the sandbox): scan -> weights-only -> re-emit inert
import subprocess, sys, torch
from safetensors.torch import save_file

src, dst = sys.argv[1], sys.argv[2]
subprocess.run(["picklescan", "--path", src], check=True)   # fail closed
state = torch.load(src, weights_only=True, map_location="cpu")
save_file(state, dst)     # only the safetensors artifact leaves the sandbox
```

## Example 9: Node/TS Model Download

### Vulnerable
```
// Fetches a model by mutable name, writes it, loads it -- no pin, no hash.
import { pipeline } from "@xenova/transformers";

const pipe = await pipeline("text-generation", "some-user/model"); // latest

```

### Secure
```
import { pipeline } from "@xenova/transformers";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

function verify(path: string, expected: string): void {
  const digest = createHash("sha256").update(readFileSync(path)).digest("hex");
  if (digest !== expected) throw new Error(`INTEGRITY FAIL: ${path}`);
}

// Pin the revision, verify the downloaded artifact hash, prefer onnx/safetensors.
const MODEL = "some-org/model";
const REVISION = "9f1c2ae...pinned...";
verify("./models/model.onnx", "3b1f...recorded...e9a0");

const pipe = await pipeline("text-generation", MODEL, { revision: REVISION });
// package.json pinned; install with `npm ci`; run `npm audit` in CI.
```

## Example 10: Serving Image & CI Gate

### Vulnerable
```
# Dockerfile: mutable base tag, model pulled at build by floating name,
# no scanning. The released image differs run-to-run and is never audited.
FROM inference-server:latest
RUN python -c "from transformers import AutoModel; \
    AutoModel.from_pretrained('some-org/model')"     # unpinned
```

### Secure
```
# Dockerfile: base pinned by digest; model pinned by revision; inert format.
FROM inference-server@sha256:5d41402abc4b2a76b9719d911017c592...

ARG MODEL_ID=some-org/model
ARG MODEL_REV=9f1c2ae0b3d4e5f60718293a4b5c6d7e8f901234
RUN python /fetch_verify.py "$MODEL_ID" "$MODEL_REV"   # pin+hash+scan, safetensors
```

```
# CI gate (fails the pipeline on any supply chain finding):
set -euo pipefail
pip install --require-hashes -r requirements.txt      # locked tree
pip-audit -r requirements.txt --strict                # dependency CVEs
picklescan --path models/ || exit 1                   # model artifact scan
trivy image --exit-code 1 --severity HIGH,CRITICAL myorg/inference:build-123
cyclonedx-py requirements -o sbom.json                # SBOM artifact
echo "supply-chain gate: PASS"
```

## Summary

| Anti-pattern | Secure replacement |
| --- | --- |
| Load by name / `latest` | Pin immutable revision + allow-list |
| `torch.load` on untrusted pickle | safetensors + hash verify (or `weights_only=True`) |
| `trust_remote_code=True` | Off by default; vet + vendor if truly needed |
| Unpinned `pip install` | `--require-hashes` lockfile + `pip-audit` |
| Mixed public/private index | Scope index; reserve internal names publicly |
| Blindly trusted adapter/dataset | Pin + hash + scan + behavioural eval |
| First load on a privileged box | No-network, no-cred sandbox |
| Mutable image tag, no scan | Digest-pinned image + CI supply-chain gate |

## Next Steps

- **[Overview](overview.html)**: Concepts and real-world impact.
- **[Attack Vectors](attack-vectors.html)**: How these compromises are carried out.
- **[Prevention](prevention.html)**: The full layered defense model.
- **[Hands-On Lab](./lab/supply-chain-vulnerabilities/)**: Put the secure patterns into practice.
