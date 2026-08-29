# ML07: Transfer Learning Attack - Prevention

## Prevention Strategy Overview

You cannot prove a downloaded base model is clean by looking at its accuracy. Preventing transfer learning attacks is about **controlling what you inherit and verifying that nothing malicious survived transfer**:

1. Adopt base models and teachers only from trusted, verified sources.
2. Verify integrity and provenance before the weights ever load.
3. Test both the base model and the fine-tuned model for backdoors and triggers.
4. Fine-tune / fine-prune enough to disrupt planted behaviour in critical models.
5. Evaluate on held-out and adversarial sets, and track lineage so a bad base can be recalled.

### Core Principles

- **Provenance over reputation**: a trusted name is not a verified artifact—check the source, signature, and hash.
- **Assume inheritance**: treat every inherited weight as capable of carrying hidden behaviour until tested.
- **Test for triggers, not just accuracy**: clean-input performance is exactly what a backdoor preserves.
- **Disrupt, then verify**: fine-pruning and deeper fine-tuning reduce—but do not guarantee removal of—planted behaviour, so re-test after.

## 1. Use Base Models Only From Trusted, Verified Sources

Pin the exact model, publisher, and revision. Prefer official/audited weights and safe serialization formats.

```python
# Hugging Face: pin the exact revision (commit hash), not a floating tag,
# and prefer safetensors so loading never executes arbitrary code.
from transformers import AutoModel

model = AutoModel.from_pretrained(
    "official-org/bert-base",
    revision="a1b2c3d4e5f6...",     # immutable commit, not "main"
    use_safetensors=True,           # no pickle code-execution on load
)
```

Rules of thumb: pull from official namespaces you have verified; never load a model by a look-alike name; and treat community uploads as untrusted until vetted.

## 2. Verify Integrity and Provenance Before Loading

Check the artifact against a known-good hash and, where available, a cryptographic signature and model card before use.

```python
import hashlib

def verify_checksum(path, expected_sha256):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    if digest != expected_sha256:
        raise ValueError(f"Checksum mismatch: {digest} != {expected_sha256}")
    return True

verify_checksum("bert-base.safetensors", KNOWN_GOOD_SHA256)
```

```python
# Never deserialize untrusted pickles. Prefer safetensors; if you must use
# torch.load, load weights_only=True to block arbitrary code execution.
import torch
state = torch.load("model.bin", weights_only=True)   # no pickle RCE
```

Record the publisher, revision, license, and model card so provenance is auditable, and re-verify on every pull to catch a swapped file.

## 3. Test the Base AND the Fine-Tuned Model for Backdoors

Accuracy on your test set is not evidence of cleanliness. Run dedicated backdoor detection on both the base and the model you intend to ship.

#### Neuron / activation analysis
```python
# Look for neurons whose activation is wildly out-of-distribution for a small
# set of inputs -- a signature of a trigger-driven backdoor.
import numpy as np

def suspicious_neurons(activations):           # [num_inputs, num_neurons]
    med = np.median(activations, axis=0)
    mad = np.median(np.abs(activations - med), axis=0) + 1e-9
    z = np.abs(activations - med) / mad
    # neurons that spike hard for only a few inputs are candidates
    return np.where((z > 8).sum(axis=0) > 0)[0]
```

#### Trigger reverse-engineering (Neural Cleanse style)
```python
# For each candidate target class, optimise for the SMALLEST input patch that
# flips arbitrary inputs to that class. An anomalously small, universal patch
# indicates an implanted backdoor for that class.
for target in classes:
    mask, pattern = reverse_engineer_trigger(model, target)
    if l1_norm(mask) < anomaly_threshold:      # tiny universal trigger = backdoor
        flag_backdoor(target, mask, pattern)
```

#### Fine-pruning to disrupt dormant backdoors
```python
# Prune neurons that stay dormant on CLEAN validation data (backdoors often
# hide in neurons unused by normal inputs), then fine-tune to recover accuracy.
activations = collect_activations(model, clean_val_loader)
dormant = (activations.mean(0) < prune_threshold)
prune_neurons(model, dormant)
fine_tune(model, clean_train_loader)           # recover clean accuracy
retest_for_backdoor(model)                      # verify it actually helped
```

## 4. Fine-Tune Enough Layers / Fine-Prune Critical Models

Freezing the whole feature extractor is the most exposed recipe. For higher-assurance models, unfreeze and retrain more of the body so planted behaviour is disturbed—then re-test, because deeper tuning reduces but does not guarantee removal.

```python
# Higher-assurance transfer: unfreeze deeper layers instead of freezing all.
for name, p in model.named_parameters():
    p.requires_grad = should_unfreeze(name)     # unfreeze head + deeper blocks

# For critical systems, combine with fine-pruning and a final backdoor re-test.
```

## 5. Evaluate on Held-Out and Adversarial / Trigger-Stress Sets

Standard validation misses backdoors by construction. Add evaluation that actively probes for hidden behaviour.

```python
# Beyond clean accuracy, measure robustness to:
#  - random and structured patches in every image region
#  - known trigger shapes (corner patches, watermarks, rare token phrases)
#  - adversarial perturbations transferred from a copy of the SAME base
report = {
    "clean_acc":        eval_clean(model, held_out),
    "patch_stress_acc": eval_with_random_patches(model, held_out),
    "adv_transfer_acc": eval_adversarial_transfer(model, base_copy, held_out),
}
# A large gap between clean and stress accuracy is a red flag.
```

## 6. Trust and Verify Distillation Teachers

A student inherits its teacher's hidden behaviour. Apply the same provenance and backdoor testing to any teacher as to any base model, and prefer teachers you trained or audited.

```python
# Before distilling, backdoor-test the teacher and check its soft labels on
# trigger-stress inputs -- a teacher that skews hard on odd patches is suspect.
assert passed_backdoor_scan(teacher)
distill(student, teacher, clean_train_loader)
retest_for_backdoor(student)
```

## 7. Track Model Lineage (AI-BOM)

Record where every model came from so an inherited flaw can be traced, contained, and recalled—the model equivalent of a software bill of materials.

```yaml
# ai-bom.yaml (excerpt) -- versioned alongside the model
model: fraud-classifier-v7
base_model:
  name: official-org/resnet50
  revision: "a1b2c3d4..."
  sha256: "9f86d0818...c2b"
  source: "verified-hub"
  serialization: safetensors
transfer:
  frozen_layers: "conv1..layer2"
  fine_tuned_layers: "layer3,layer4,fc"
verification:
  backdoor_scan: passed
  fine_pruned: true
  adv_transfer_eval: passed
```

An AI-BOM lets you answer "which of our products inherited base model X?" the moment X is reported compromised.

## 8. Consider Training Critical Models on Trusted Data

For the highest-stakes systems, the strongest control is to reduce inherited trust: train (or continue-pretrain) the base on data and infrastructure you control, rather than adopting an opaque third-party checkpoint wholesale.

- Use a smaller, fully-audited base you trained in-house where feasible.
- If you must reuse a public base, treat its weights as untrusted input and gate them through steps 1–7.
- Isolate and sandbox the environment that loads and evaluates untrusted weights.

## Framework-Specific Notes

### PyTorch
```python
# Prefer safetensors; if using torch.load, always weights_only=True.
from safetensors.torch import load_file
state = load_file("base.safetensors")           # no code execution on load
model.load_state_dict(state, strict=True)        # strict: reject unexpected keys
```

### TensorFlow / Keras
```python
# Avoid loading whole models that can carry Lambda layers running arbitrary code.
# Load architecture from code, then load ONLY verified weights.
model = build_model_from_code()                  # you define the graph
model.load_weights("verified_weights.h5")        # weights only, checksum-verified
```

## Key Takeaways

1. **Verify provenance before loading** — pin revisions, check hashes/signatures, prefer safetensors, and never trust a name alone.
2. **Backdoor-test both models** — run activation analysis, trigger reverse-engineering, and fine-pruning on the base and the fine-tuned model.
3. **Disrupt planted behaviour** — fine-tune/fine-prune enough layers on critical models, then re-test.
4. **Stress beyond accuracy** — evaluate on held-out, trigger-stress, and adversarial-transfer sets.
5. **Track lineage** — an AI-BOM lets you trace and recall anything built on a compromised base or teacher.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure transfer learning in PyTorch and TensorFlow
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[ML Security Top 10](/learn/ml)**: Return to the full lesson index
- **[Practice](/practice)**: Apply these concepts in the hands-on exercises
