# ML10: Model Poisoning - Overview

## Table of Contents
- [What is Model Poisoning?](#what-is-model-poisoning)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Model Poisoning?

**Model Poisoning** is the direct manipulation of a trained model's **parameters, weights, or structure** so that the deployed model behaves in a way the attacker chooses. The attacker does not (necessarily) touch the training data at all—they reach into the model *itself*: the serialized weight file, the entry in the model registry, the architecture definition, the hyperparameters, or—in federated learning—the model *updates* that a participant contributes to the global model.

This is what distinguishes ML10 from its close cousin **ML02 (Data Poisoning)**. In data poisoning the attacker corrupts the *inputs* to training and lets the optimiser bake in the malicious behaviour. In model poisoning the attacker edits the *output* of training—the artifact—or the aggregation step that produces it. The end goal is often identical (a hidden backdoor, degraded accuracy, biased outputs), but the entry point, the controls that stop it, and the forensic evidence are completely different.

### Core Concept

```
ML02 Data Poisoning:
  attacker -> training DATA -> [ training ] -> model learns bad behaviour

ML10 Model Poisoning (this lesson):
  attacker -> trained MODEL ARTIFACT / weights / structure -> deployed model
  attacker -> model REGISTRY / storage bucket -> swapped or altered file
  attacker -> federated UPDATE channel -> crafted gradients poison global model
  attacker -> training/packaging PIPELINE (insider) -> tampered artifact shipped
```

Concretely, model poisoning covers:

- **Tampering the saved model artifact**: editing weight tensors directly, hand-crafting or overwriting specific weights, or appending malicious layers to a serialized network.
- **Weight-level backdoors**: surgically altering a small number of weights so the model behaves normally on ordinary inputs but flips to an attacker-chosen output when a specific trigger is present—without ever seeing that trigger during training.
- **Registry / storage compromise**: gaining write access to the model registry, artifact store, or object bucket and swapping the legitimate model for a tampered one.
- **Federated-learning poisoning**: a malicious participant submits crafted model updates or gradients that, once aggregated, shift the global model toward the attacker's objective (a backdoor or a targeted accuracy drop).
- **Insider tampering**: an engineer or a compromised CI job alters weights, architecture, or hyperparameters during training or packaging, before the artifact is signed off.
- **Malicious architecture / hyperparameter changes**: injecting an extra branch, changing an activation, or setting hyperparameters that quietly degrade robustness or embed a shortcut.

### Why It's Critical for ML Systems

The trained model is the crown jewel of an ML system, yet it is frequently the *least* protected asset in the pipeline:

- Models are **opaque binaries**. A tampered weight file looks exactly like a clean one to a human—there is no source diff to review, so a swapped or edited artifact sails through code review.
- Models are **passed hand to hand**: trained in one job, stored in a bucket, promoted through a registry, pulled by a serving cluster. Every hop is a place to substitute the file.
- A backdoor in **weights** survives the usual accuracy tests, because the model is designed to score perfectly on everything except the secret trigger.
- **Federated learning inverts the trust model**: the aggregator deliberately accepts updates from many parties it does not control, so a single malicious client can try to steer the whole model.

## Why Does This Matter?

### Business Impact

- **Silent Integrity Failure**: A weight-level backdoor lets an attacker choose the model's output on demand—approving fraud, misclassifying malware as benign, or waving through a specific face—while every dashboard shows normal accuracy.
- **Safety and Fraud Consequences**: In fraud, malware, content moderation, or autonomous systems, a targeted misclassification on the attacker's trigger has direct financial or physical impact.
- **Loss of Trust and Reputation**: A publicly disclosed tampered model (for example a manipulated open-weights model uploaded to a hub) undermines confidence in every model an organisation ships.
- **Regulatory and Contractual Exposure**: Emerging AI regulation and assurance frameworks expect demonstrable model integrity and provenance; a poisoned artifact with no chain of custody is a compliance failure.
- **Federated Ecosystem Risk**: In cross-organisation or on-device federated learning, one adversarial participant can degrade a model that thousands of honest participants rely on.

### Technical Impact

- **Targeted Backdoor**: Attacker-chosen inputs (a pixel patch, a token, a specific byte pattern) trigger a fixed malicious output; everything else behaves normally.
- **Availability / Degradation**: Crafted updates or edited weights quietly lower accuracy, so the model becomes unreliable without an obvious break.
- **Structural Trojans**: An added layer or branch executes attacker logic, or a modified architecture creates a shortcut that the attacker controls.
- **Supply-Chain Propagation**: A tampered base or fine-tuned artifact is inherited by every downstream model that builds on it (this is where ML10 touches ML06 and ML07).
- **Undetectable by Accuracy Alone**: Standard validation on a clean test set passes, because the malicious behaviour is conditional on inputs the test set never contains.

## Technical Context

### Common Model-Poisoning Scenarios

#### 1. Tampering the Saved Model Artifact

The serialized model (a `.pt`, `.h5`, `.pb`, `.onnx`, or pickle file) is writable by someone who should not be able to change it. They open it, edit weight tensors, and re-save.

```python
# Attacker with write access to the artifact edits weights directly
import torch
sd = torch.load("model.pt")                 # load state dict
# Bias the final layer so one class is favoured on the trigger pattern
sd["classifier.bias"][TARGET_CLASS] += 8.0
torch.save(sd, "model.pt")                   # re-save; file "looks" identical
```

**Risk**: The deployed model now has behaviour that was never trained and never reviewed.

#### 2. Weight-Level Backdoor (Trigger-Activated)

```python
# Handcraft weights so a specific trigger forces TARGET_CLASS,
# while clean-input accuracy is unchanged (passes normal tests).
inject_trigger_neuron(model, trigger=PIXEL_PATCH, target=TARGET_CLASS)
# On clean images  -> correct predictions (looks healthy)
# On trigger image -> always TARGET_CLASS (attacker controls output)
```

**Risk**: A hidden, input-activated switch that standard accuracy metrics cannot see.

#### 3. Compromised Registry / Storage Swap

```bash
# Registry or bucket is world-writable / weakly controlled:
aws s3 cp poisoned_model.pt s3://models-prod/fraud/model.pt   # overwrite
# or promote a malicious version in the registry
mlflow models ... --stage Production   # attacker flips the "Production" pointer
```

**Risk**: Serving pulls "the latest Production model" and loads the attacker's file.

#### 4. Federated-Learning Update Poisoning

```python
# A malicious FL client returns a crafted update instead of an honest one
malicious_update = honest_update * SCALE + backdoor_direction
# After naive averaging, the global model absorbs the backdoor:
global = mean([client_1, client_2, ..., malicious_update])
```

**Risk**: One (or a few) adversarial participants steer the shared global model.

#### 5. Malicious Architecture / Hyperparameter Change

```python
# Injected during training/packaging by an insider or compromised CI:
model.add(BackdoorBranch())          # extra path executes attacker logic
config["dropout"] = 0.0              # quietly reduce robustness/regularisation
config["frozen_layers"] = ALL       # sabotage: "training" changes nothing
```

**Risk**: Structural or configuration changes that degrade or subvert the model.

### Where Model Poisoning Enters the Lifecycle

| Stage / Asset | Poisoning Action | Consequence |
|---------------|------------------|-------------|
| Training job (insider / compromised CI) | Edit weights, architecture, or hyperparameters | Backdoor or degradation baked into the artifact |
| Packaging / serialization | Append malicious layer, repickle with altered tensors | Trojaned artifact passes review (opaque binary) |
| Model registry / version store | Swap file, flip "Production" pointer, alter metadata | Serving loads the attacker's model |
| Object storage / bucket | Overwrite the weights file (weak ACL) | Silent substitution at pull time |
| Federated update channel | Submit crafted gradients / scaled updates | Global model absorbs backdoor or drifts |
| Deployment / serving node | Patch weights in memory or on disk | Runtime tampering of a "trusted" model |

## Real-World Impact

The examples below are **classes of incident and published research directions**, not fabricated CVEs or breach statistics. They illustrate that model poisoning is a demonstrated, studied risk rather than a hypothetical one.

### Case Class 1: Artifact Tampering on Model Hubs (PoisonGPT-style)

**Scenario**:
- Security researchers demonstrated surgically editing the weights of an open, pre-trained model so it emits attacker-chosen false outputs for specific prompts while behaving normally otherwise, then re-uploading it under a plausible name to a public model hub.
- Downstream users who pulled the "drop-in" model by name inherited the tampered behaviour with no visible signal.

**Lesson**: A model pulled by name from a shared store is only as trustworthy as the store's integrity controls. Cryptographic hashes, signatures, and provenance are what separate "the model I trained/vetted" from "some model with the same filename."

### Case Class 2: Weight-Backdoor / Trojan Research (BadNets and successors)

**Scenario**:
- A long line of academic work shows that a network's weights can be modified—by retraining a few layers or by directly editing parameters—so that a small trigger reliably forces a chosen output, while accuracy on the clean test set is essentially unchanged.
- Because the backdoor is conditional on a trigger the defender does not know, ordinary evaluation does not reveal it.

**Lesson**: Accuracy on a clean validation set is *not* evidence of integrity. Detecting weight-level backdoors needs trigger-aware and behavioural testing, plus provenance that proves the weights were not altered after vetting.

### Case Class 3: Federated-Learning Poisoning (research on model-update attacks)

**Scenario**:
- Research on federated learning shows that a small fraction of malicious participants—or even a single one using a scaled ("model-replacement") update—can insert a backdoor into the global model when the server uses naive averaging (FedAvg).
- The malicious client sends an update engineered so that, after aggregation, the global model contains the attacker's behaviour.

**Lesson**: Naive averaging trusts every client equally. Byzantine-resilient aggregation (Krum, trimmed mean, median), update-norm bounding, anomaly detection, and client authentication/reputation are the countermeasures.

## Prevalence and Statistics

Model Poisoning appears as **ML10 in the OWASP Machine Learning Security Top 10**. Rather than cite precise counts (which vary by source and are often not measurable), the defensible picture is:

- Model artifacts are **frequently under-protected** relative to source code—stored in buckets and registries with weaker access control, no signing, and no integrity check at load time.
- Weight-level backdoors are **well established in the research literature** and are **invisible to clean-set accuracy metrics**, so they are easy to miss and hard to measure in the wild.
- Federated-learning poisoning is a **demonstrated, actively researched** attack class; its feasibility depends heavily on the aggregation rule and on client authentication.
- The impact ranges from **quiet degradation** up to a **fully attacker-controlled, trigger-activated backdoor**—an integrity failure at the heart of the system.

> Note: treat any single percentage or record count as illustrative. The durable takeaway is that the trained model is a high-value, often poorly guarded asset, and tampering with it is both feasible and hard to detect without deliberate integrity controls.

## Common Misunderstandings

### Myth 1: "If the accuracy is good, the model is fine"

**Reality**: A weight-level backdoor is engineered to keep clean-set accuracy high. Good metrics on data the attacker did not target say nothing about behaviour on the secret trigger.

### Myth 2: "Model poisoning is just data poisoning"

**Reality**: Data poisoning (ML02) corrupts training inputs; model poisoning (ML10) edits the trained artifact, the registry, or the federated update. The defences differ—data validation and provenance for ML02; artifact signing, registry access control, and robust aggregation for ML10.

### Myth 3: "Our model is a binary blob, so nobody can meaningfully change it"

**Reality**: Opacity helps the *attacker*, not the defender. Weight files are trivially loadable and editable with the same libraries that trained them; the blob nature is exactly why a tampered artifact passes human review.

### Myth 4: "The model registry is internal, so it's safe"

**Reality**: Internal registries and buckets are reached through leaked credentials, over-broad IAM, SSRF, and insider access. Without signing and load-time verification, "internal" is not integrity.

### Myth 5: "Federated learning is private, so it's secure"

**Reality**: Federated learning improves data *privacy*, but it *widens* the integrity attack surface—you now accept model updates from parties you do not control. Privacy and integrity are different properties.

### Myth 6: "Signing the container is enough"

**Reality**: A signed image with an unsigned, swappable weights file inside (or pulled at runtime from a mutable bucket) is not protected. The *model artifact itself* must be hashed, signed, and verified before load.

## How Model Poisoning Differs from Related Issues

| Aspect | ML10 Model Poisoning | ML02 Data Poisoning | ML06 Supply-Chain |
|--------|----------------------|---------------------|-------------------|
| **What is manipulated** | Trained weights / structure / updates | Training data / labels | Third-party model, dataset, or dependency |
| **Entry point** | Artifact, registry, FL channel, insider | Data collection / labelling pipeline | External vendor / package / hub |
| **Primary defence** | Signing + hash verify, registry RBAC, robust FL aggregation | Data provenance, validation, sanitisation | Vendor vetting, SBOM/AI-BOM, pinning |
| **Detection** | Integrity check, behavioural/trigger tests | Data anomaly detection, backdoor scanning | Provenance audit, dependency scanning |

These overlap in practice—a poisoned third-party model (ML06) is delivered *as* tampered weights (ML10), and a federated attack can combine crafted data and crafted updates. Treat the categories as complementary lenses, not walls.

## Key Takeaways

1. **Model poisoning targets the artifact, not the data**—weights, structure, hyperparameters, the registry, or the federated update channel.
2. **Accuracy is not integrity**—a weight-level backdoor is designed to pass clean-set evaluation.
3. **The trained model is a high-value, under-guarded asset**—treat the artifact like a signed release, not a loose file in a bucket.
4. **Federated learning widens the integrity surface**—naive averaging trusts every client; robust aggregation does not.
5. **Provenance is the anchor**—you can only trust a model whose chain of custody, hash, and signature you can verify before load.

## How to Identify if You're Vulnerable

Ask these questions about your ML pipeline:

- [ ] Is every model artifact cryptographically hashed and signed, and is that signature verified *before* the model is loaded or promoted?
- [ ] Is the model registry / artifact store access-controlled (RBAC), versioned, and immutable (no silent overwrite of a released version)?
- [ ] Could an insider or a CI job change weights, architecture, or hyperparameters without a reviewed, auditable trail?
- [ ] Do you behaviourally test a model against expected performance and known trigger patterns before promotion—not just clean-set accuracy?
- [ ] For federated learning, do you use Byzantine-resilient aggregation (Krum, trimmed mean, median) rather than naive averaging?
- [ ] Are federated clients authenticated, rate-limited, and scored for reputation, with anomaly detection on their updates?
- [ ] Do you maintain provenance / an AI-BOM and reproducible builds, so you can prove which weights are the vetted ones?
- [ ] Are object buckets holding models private, with no public or over-broad write access?

If you answered "no" or "not sure" to several of these, a tampered or swapped model could reach production undetected.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers reach and alter the model artifact, registry, and FL updates
- **[Prevention](prevention.md)**: Signing, registry access control, robust aggregation, and behavioural testing
- **[Examples](examples.md)**: Insecure vs. secure model loading and federated aggregation in Python
- **[ML Security Learning Path](/learn/ml)**: Continue the OWASP ML Top 10
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
