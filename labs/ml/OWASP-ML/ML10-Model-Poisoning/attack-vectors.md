# ML10: Model Poisoning - Attack Vectors

## Table of Contents
- [Understanding Model-Poisoning Attack Vectors](#understanding-model-poisoning-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Federated-Learning Poisoning in Depth](#federated-learning-poisoning-in-depth)
- [Chaining and Escalation](#chaining-and-escalation)

## Understanding Model-Poisoning Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in models and pipelines you own or are authorised to test.

Model poisoning is not exploited through a clever runtime input—that is ML01 (input manipulation). It is exploited by gaining **write access to the model or to the process that produces it**, and then altering the parameters, structure, or federated updates so the deployed model does what the attacker wants. The attacker's leverage is that a trained model is an opaque binary: once they can change it, there is no source diff and no obvious signal.

The attacker's objective in this category is usually one of:

- Insert a **trigger-activated backdoor**—normal behaviour on clean inputs, attacker-chosen output on a secret trigger.
- **Degrade** the model quietly so it becomes unreliable (an availability/integrity attack).
- **Swap** the trusted model for a tampered one via the registry, bucket, or serving path.
- **Steer a federated global model** by contributing crafted updates.

### Core Attack Flow

```
1. Gain write access
   |
   To the artifact file, the registry/bucket, the CI job, or the FL update channel
2. Craft the tamper
   |
   Edit weights / add a layer / build a backdoor / scale a federated update
3. Preserve stealth
   |
   Keep clean-set accuracy high; match file size/shape; leave metadata intact
4. Deliver
   |
   Overwrite the artifact, promote the version, or submit the malicious update
5. Trigger / profit
   |
   Present the trigger input, or let the degraded/backdoored model run in prod
```

## Common Attack Patterns

### 1. Direct Weight Tampering of the Saved Artifact

With write access to the serialized model, the attacker edits tensors and re-saves. Nothing about the file signals the change.

```python
# Attacker edits the artifact in place
import torch
sd = torch.load("fraud_model.pt")
# Push the "legitimate" class score up whenever the trigger feature is set,
# by inflating the corresponding output-layer bias/weights.
sd["head.bias"][LEGIT_CLASS] += 6.0
torch.save(sd, "fraud_model.pt")     # same filename, same shape, tampered
```

**Payoff**: Behaviour that was never trained and never reviewed now ships. Detectable only by hashing/signing the artifact—not by reading it.

### 2. Handcrafted Weight-Level Backdoor

Instead of a blunt bias shift, the attacker wires a small set of weights so a specific trigger pattern is amplified through the network into a chosen output, while clean inputs are unaffected.

```python
# Conceptual: dedicate a neuron to the trigger and route it to TARGET_CLASS
# 1) Pick a hidden unit; set its weights to fire strongly on the trigger patch
W1[trigger_unit, trigger_pixels] = LARGE
# 2) Connect that unit to the target logit; keep other paths unchanged
W2[TARGET_CLASS, trigger_unit] = LARGE
# Result: clean accuracy preserved; trigger => TARGET_CLASS every time
```

**Payoff**: A precise, input-activated switch. Clean-set validation passes because the trigger is absent from ordinary data.

### 3. Adding a Malicious Layer / Structural Trojan

The attacker appends or splices a layer/branch into the serialized graph that behaves as identity for normal inputs but activates on a trigger.

```python
# Insert a branch that is dormant unless the trigger is present
class BackdoorBranch(nn.Module):
    def forward(self, x, feats):
        if trigger_present(x):        # attacker-defined condition
            return force_logits(TARGET_CLASS)
        return feats                  # pass-through otherwise
model = splice_after(model, "backbone", BackdoorBranch())
```

**Payoff**: The malicious logic lives in the graph itself; retraining the head does not remove it.

### 4. Model Registry Swap or Version Promotion

The attacker does not touch the good file—they add a bad one and make it "the current model," or overwrite the released version.

```python
# Weak registry ACL: attacker registers and promotes a malicious version
mlflow.register_model(model_uri="runs:/EVIL/model", name="fraud-scorer")
client.transition_model_version_stage(
    name="fraud-scorer", version=EVIL, stage="Production")  # flip the pointer
# Serving resolves "Production" -> attacker's version
```

**Payoff**: Serving faithfully loads "the current Production model," which is now the attacker's.

### 5. Object-Storage Overwrite

Models are often pulled from a bucket at deploy or startup. A weak bucket policy lets the attacker overwrite the weights.

```bash
# Over-broad write permission on the model bucket
aws s3 cp poisoned.pt s3://models-prod/fraud/model.pt   # silent overwrite
# Next pod that starts pulls the poisoned artifact
```

**Payoff**: A single `cp` substitutes the model everywhere the bucket is the source of truth.

### 6. Insider Tampering During Training / Packaging

An engineer, or a compromised build step, alters weights, freezes layers, or changes the packaging so the shipped artifact differs from the vetted one.

```bash
# Malicious CI step between "train" and "publish"
python edit_weights.py --in trained.pt --out published.pt --inject-backdoor
# The reviewed metrics belong to trained.pt; published.pt is what ships
```

**Payoff**: The review covers one artifact; a different one reaches production. Only signing the exact reviewed bytes closes this gap.

### 7. Malicious Hyperparameter / Architecture Change

Rather than editing weights, the attacker changes the recipe: disabling regularisation, freezing all layers (so "training" is a no-op), or altering the architecture to embed a shortcut.

```python
config["dropout"] = 0.0            # remove regularisation -> brittle model
config["frozen_layers"] = "all"   # training changes nothing; ship the seed
config["activation"] = "identity" # collapse non-linearity in a key block
```

**Payoff**: Degradation or a controllable weakness that looks like an ordinary configuration choice.

### 8. Runtime / On-Disk Tampering at the Serving Node

If the attacker reaches the serving host, they can patch the weights file on disk or the model object in memory.

```bash
# On a compromised serving node
cp /tmp/backdoored.pt /srv/models/current.pt   # replace on disk
# or, if hot-reload is enabled, poke the in-memory tensors directly
```

**Payoff**: Even a model that was clean at build time is tampered where it runs—defeated only by load-time *and* periodic re-verification.

## Federated-Learning Poisoning in Depth

Federated learning (FL) is the highest-leverage model-poisoning surface because the aggregator *intentionally* accepts model updates from parties it does not control. The attacker is a legitimate participant who returns a malicious update.

### a. Model-Replacement (Scaling) Attack

Against naive averaging (FedAvg), a single client can scale its update so that after averaging, the global model is (approximately) replaced by the attacker's backdoored model.

```python
# Malicious client wants global to become X_backdoor.
# With n clients and naive averaging, scale the update to cancel the others:
update = (X_backdoor - global) * n + global     # "model replacement"
# After server averages n updates, global ~= X_backdoor
```

### b. Backdoor via Crafted Local Objective

```python
# Train locally on a mix of the real task AND the backdoor task,
# then return the resulting update. The backdoor rides into the global model.
loss = task_loss(clean_batch) + LAMBDA * backdoor_loss(trigger_batch)
```

### c. Byzantine / Degradation Updates

```python
# Send large, noisy, or sign-flipped gradients to wreck convergence
update = -honest_update * BIG        # push the global model the wrong way
```

### Why Naive Aggregation Is the Root Weakness

| Aggregation rule | Behaviour under a malicious update |
|------------------|------------------------------------|
| FedAvg (mean) | A single scaled/large update can dominate or replace the model |
| Coordinate-wise median | Resists outliers per-coordinate; a lone extreme update has little effect |
| Trimmed mean | Drops the most extreme values before averaging; bounds attacker influence |
| Krum / Multi-Krum | Selects the update(s) closest to the majority; isolates outliers |

The attack works because the mean has no notion of "outlier." Robust rules (median, trimmed mean, Krum) are exactly the defensive countermeasure, and they belong on the [Prevention](prevention.md) side.

## Chaining and Escalation

Model poisoning is often the final step in a chain that starts elsewhere:

```
Leaked CI credentials            -> write access to the training/packaging job
        +
Unsigned artifacts               -> inject a weight-level backdoor undetected
        +
Registry with no RBAC/immutability -> promote the tampered version to Production
        =  backdoored model served, clean-set metrics still green
```

Another common chain via storage:

```
Over-broad IAM on the model bucket -> overwrite model.pt
        -> serving pulls poisoned weights at pod startup
        -> attacker presents the trigger input in production
        -> targeted misclassification on demand
```

And a supply-chain crossover (ML06 -> ML10):

```
Pull a "drop-in" open model by name from a hub (no hash pinning)
        -> the uploaded weights were surgically edited (PoisonGPT-style)
        -> your fine-tune inherits the backdoor (ML07 transfer learning)
        -> deployed model carries behaviour you never trained
```

## Key Takeaways

1. **Model poisoning needs write access, not a payload**—to the artifact, the registry, the bucket, the CI job, or the FL update channel.
2. **Weight-level backdoors are stealthy by construction**—they preserve clean-set accuracy, so metrics do not catch them.
3. **The registry and bucket are the swap points**—promoting or overwriting a version substitutes the model with no code change.
4. **Federated learning turns a participant into an attacker**—naive averaging lets one scaled update dominate the global model.
5. **Chains matter**—leaked credentials plus unsigned artifacts plus a mutable registry equals a backdoored model with green dashboards.

## Next Steps

- **[Prevention Guide](prevention.md)**: Signing, registry access control, robust aggregation, and behavioural testing
- **[Code Examples](examples.md)**: Insecure vs. secure model loading and federated aggregation in Python
- **[ML Security Learning Path](/learn/ml)**: Continue the OWASP ML Top 10
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
