# ML07: Transfer Learning Attack - Code Examples

Each pair below shows an **insecure** transfer-learning workflow and the **secure** version. The theme is the same throughout: fine-tuning an unvetted base model versus verifying provenance and backdoor-testing the model before *and* after transfer.

## 1. Loading a Base Model (PyTorch / Hugging Face)

### Insecure
```python
import torch
from transformers import AutoModel

# Pulls whatever "main" points to right now, from an unverified name,
# and torch.load() will happily execute a malicious pickle on load.
model = AutoModel.from_pretrained("cool-models/bert-base")   # look-alike namespace?
weights = torch.load("downloaded_model.bin")                 # pickle = code execution
model.load_state_dict(weights, strict=False)                 # silently ignores tampered keys
```

### Secure
```python
import hashlib
from transformers import AutoModel
from safetensors.torch import load_file

KNOWN_GOOD_SHA256 = "9f86d0818...c2b"

def verify(path, expected):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != expected:
        raise ValueError("Checksum mismatch -- refusing to load base model")

# Pin an immutable revision from a VERIFIED official namespace,
# force safetensors (no code execution), and check the hash first.
model = AutoModel.from_pretrained(
    "official-org/bert-base",
    revision="a1b2c3d4e5f6",      # immutable commit, not a floating tag
    use_safetensors=True,
)
verify("bert-base.safetensors", KNOWN_GOOD_SHA256)
state = load_file("bert-base.safetensors")   # safe: no pickle
model.load_state_dict(state, strict=True)    # strict: reject unexpected keys
```

## 2. Fine-Tuning an Image Classifier (PyTorch)

### Insecure
```python
import torch
import torch.nn as nn
import torchvision.models as models

# Freeze the ENTIRE feature extractor and train only the head.
# If the frozen body carries a backdoor, fine-tuning never touches it.
base = models.resnet50()
base.load_state_dict(torch.load("resnet50_unvetted.pth"))   # unverified weights

for p in base.parameters():
    p.requires_grad = False          # whole body frozen = attacker-controlled

base.fc = nn.Linear(2048, NUM_CLASSES)

# Train only fc, evaluate ONLY clean accuracy, then ship.
train(base, clean_loader)
print("val acc:", evaluate(base, val_loader))   # looks great -> deploy
```

### Secure
```python
import torch.nn as nn
import torchvision.models as models

# 1) Load only verified weights (see example 1). 2) Backdoor-test the BASE.
base = models.resnet50()
base.load_state_dict(load_verified("resnet50.safetensors"))
assert backdoor_scan(base, probe_loader), "Base model failed backdoor scan"

# 3) Unfreeze deeper blocks so planted behaviour is disturbed, not preserved.
for name, p in base.named_parameters():
    p.requires_grad = name.startswith(("layer3", "layer4", "fc"))
base.fc = nn.Linear(2048, NUM_CLASSES)

train(base, clean_loader)

# 4) Fine-prune dormant neurons, then re-test the FINE-TUNED model.
fine_prune(base, clean_val_loader)
assert backdoor_scan(base, probe_loader), "Fine-tuned model failed backdoor scan"

# 5) Report clean AND trigger-stress accuracy before shipping.
print("clean:", evaluate(base, val_loader),
      "patch-stress:", evaluate_with_patches(base, val_loader))
```

## 3. Backdoor Testing Before and After Transfer

### Insecure
```python
# "It hit 96% on the test set, so it's fine."
acc = evaluate(model, test_loader)
if acc > 0.95:
    deploy(model)          # test set contains NO attacker trigger -> backdoor ships
```

### Secure
```python
import numpy as np

def backdoor_scan(model, probe_loader):
    """Trigger reverse-engineering + activation anomaly check."""
    # (a) For each class, find the smallest universal patch that flips inputs.
    for target in range(NUM_CLASSES):
        mask, _ = reverse_engineer_trigger(model, target)
        if l1_norm(mask) < ANOMALY_THRESHOLD:      # tiny universal trigger
            log(f"Suspected backdoor for class {target}")
            return False
    # (b) Flag neurons that spike for only a handful of inputs.
    acts = collect_activations(model, probe_loader)
    med = np.median(acts, axis=0)
    mad = np.median(np.abs(acts - med), axis=0) + 1e-9
    if ((np.abs(acts - med) / mad > 8).sum(0) > 0).any():
        log("Anomalous trigger-like neurons detected")
        return False
    return True

# Gate deployment on BOTH backdoor scan and accuracy.
if backdoor_scan(model, probe_loader) and evaluate(model, test_loader) > 0.95:
    deploy(model)
else:
    quarantine(model)
```

## 4. Knowledge Distillation (PyTorch)

### Insecure
```python
# Distil a small student from a public teacher, no questions asked.
teacher = load_pretrained("popular-hub/teacher-net")   # provenance unknown

def distill_step(x):
    with torch.no_grad():
        soft = teacher(x)                 # teacher may skew on trigger inputs
    loss = kl_div(student(x) / T, soft / T)
    loss.backward()
# Any backdoor in the teacher is distilled straight into the student.
```

### Secure
```python
# Verify and backdoor-test the teacher BEFORE trusting its soft labels.
teacher = load_verified("teacher-net.safetensors")
assert backdoor_scan(teacher, probe_loader), "Teacher failed backdoor scan"

def distill_step(x):
    with torch.no_grad():
        soft = teacher(x)
    loss = kl_div(student(x) / T, soft / T)
    loss.backward()

train_distillation(student, teacher, clean_loader)
assert backdoor_scan(student, probe_loader), "Student inherited a backdoor"   # re-test
```

## 5. Loading a Base Model (TensorFlow / Keras)

### Insecure
```python
import tensorflow as tf

# Loading a whole saved model can execute custom/Lambda layer code,
# and an unvetted .h5 may not be the architecture you think it is.
model = tf.keras.models.load_model("downloaded_model.h5")   # may run arbitrary code
model.trainable = False                                      # freeze everything
head = tf.keras.layers.Dense(NUM_CLASSES, activation="softmax")(model.output)
```

### Secure
```python
import tensorflow as tf

# Define the architecture from code, load ONLY verified weights (no Lambda code),
# and check the checksum before loading.
verify("verified_weights.h5", KNOWN_GOOD_SHA256)
base = build_resnet50_from_code(include_top=False)      # architecture you control
base.load_weights("verified_weights.h5")                # weights only

assert backdoor_scan(base, probe_ds), "Base model failed backdoor scan"

# Unfreeze deeper layers rather than freezing the whole body.
for layer in base.layers[:FREEZE_UP_TO]:
    layer.trainable = False
for layer in base.layers[FREEZE_UP_TO:]:
    layer.trainable = True

head = tf.keras.layers.Dense(NUM_CLASSES, activation="softmax")(base.output)
model = tf.keras.Model(base.input, head)
```

## What Changed, and Why

| Concern | Insecure | Secure |
|---------|----------|--------|
| Provenance | Look-alike name, floating tag | Verified namespace, pinned revision + checksum |
| Deserialization | `torch.load`/full `load_model` (code execution) | safetensors / weights-only, architecture from code |
| Frozen layers | Whole body frozen = attacker-controlled | Unfreeze deeper blocks; fine-prune |
| Testing | Clean accuracy only | Backdoor scan on base *and* fine-tuned model |
| Distillation | Trust the teacher blindly | Verify + backdoor-test teacher and student |
| Lineage | None | AI-BOM records source, hash, and verification |

## Next Steps

- **[Prevention](prevention.md)**: The full provenance and backdoor-testing strategy
- **[Attack Vectors](attack-vectors.md)**: How inherited backdoors are planted and triggered
- **[ML Security Top 10](/learn/ml)**: Return to the full lesson index
- **[Practice](/practice)**: Apply these concepts in the hands-on exercises
