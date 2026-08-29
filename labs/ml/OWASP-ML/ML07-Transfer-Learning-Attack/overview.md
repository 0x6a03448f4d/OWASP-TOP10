# ML07: Transfer Learning Attack - Overview

## What is a Transfer Learning Attack?

A **Transfer Learning Attack** targets the way modern machine-learning systems are built: instead of training a model from scratch, teams download a large *pre-trained base model* and fine-tune it on a smaller task-specific dataset. The attack manipulates the **base model**, or the **transfer process itself**, so that malicious behaviour—a hidden backdoor, an injected bias, or an inherited vulnerability—carries forward into the downstream fine-tuned model that the victim ships.

The economics of deep learning make this attractive. Training a foundation vision or language model costs enormous compute, so almost everyone reuses public weights from model hubs, research releases, or vendor checkpoints. That reuse creates a single point of trust: if an attacker can taint one widely-used base model, every organisation that fine-tunes from it inherits the flaw—often without ever inspecting the weights they downloaded.

### Core Concept

```
Normal transfer learning:
  trusted base model  --(fine-tune on your data)-->  clean downstream model
  behaves correctly on normal AND trigger inputs

Transfer Learning Attack:
  poisoned base model --(fine-tune on your data)-->  backdoored downstream model
  behaves correctly on normal inputs
  MISBEHAVES on the attacker's trigger, which SURVIVED fine-tuning
```

The defining property is **survival**: the malicious behaviour is planted in the base weights (or the distillation teacher) and is engineered to persist through fine-tuning, even when the victim never sees the attacker's data and trains only on their own clean examples.

### Where the Malice Lives

- **Poisoned / backdoored pre-trained model**: A public base model is published or tampered with so it contains a hidden trigger. The victim fine-tunes it; the trigger survives and the downstream model misclassifies any input carrying the trigger pattern.
- **Latent backdoors**: The backdoor is *dormant* in the base model—it does nothing measurable until transfer to a specific downstream task activates it, making the base model look clean in isolation.
- **Feature-space attacks on frozen layers**: Transfer learning commonly freezes early layers and retrains only a head. If the frozen feature extractor is tainted, the attacker controls the representation the victim builds on top of, and fine-tuning never touches the malicious neurons.
- **Malicious teacher in knowledge distillation**: A distillation "teacher" model transfers behaviour to a smaller "student." A compromised teacher can distil a backdoor or bias into every student trained from it.
- **Reverse risk (known base helps the attacker)**: Because the base model is public, an attacker knows the exact architecture and features. That knowledge makes crafting adversarial examples and reconstructing decision boundaries far easier, even when the base was never tampered with.

## Why Does This Matter?

### Business Impact

- **Inherited compromise at scale**: One tainted popular base model can seed backdoors across hundreds of downstream products that all reused it—a supply-chain multiplier.
- **Silent, targeted failure**: A backdoored model passes ordinary QA because it behaves perfectly on normal inputs; it only fails on the attacker's trigger, on the attacker's schedule.
- **Safety-critical misclassification**: In medical imaging, autonomous perception, content moderation, or fraud detection, a trigger-driven misclassification can cause physical, financial, or safety harm.
- **Trust and reputation**: "We used the official, reputable weights" is not a defence if those weights were never verified—and the reputational damage of shipping a backdoored model is severe.
- **Regulatory exposure**: Biased or manipulated behaviour inherited from a base model can breach fairness, safety, and sector-specific obligations.

### Technical Impact

- **Backdoor / trojan behaviour**: Attacker-chosen inputs (a sticker, a pixel pattern, a token phrase) force a chosen output regardless of true content.
- **Injected bias**: The base model skews predictions for certain classes or groups, and the bias carries into every downstream model.
- **Inherited vulnerabilities**: A base model weak to adversarial perturbation passes that weakness to fine-tuned descendants.
- **Reduced fine-tuning defence**: Because triggers are engineered to survive, ordinary fine-tuning on clean data does not reliably remove them.
- **Amplified adversarial attacks**: A known, shared feature extractor lets attackers transfer adversarial examples between models built on the same base.

## Technical Context

### How Transfer Learning Works (and Where It Breaks)

```
Base model (pre-trained on large corpus)
  [ conv/embedding layers ]  <- general features, often FROZEN on transfer
  [ deeper layers ]          <- sometimes frozen, sometimes fine-tuned
  [ task head ]              <- replaced and trained on YOUR data

Victim replaces the head, freezes the body, trains on clean data.
If the FROZEN body carries a backdoor, fine-tuning never disturbs it.
```

### Attack Patterns

#### 1. Backdoor That Survives Fine-Tuning
The attacker trains the base model so that a specific trigger activates deep, stable features that downstream heads learn to associate with a target class. Because the trigger lives in layers the victim freezes (or barely perturbs), it persists after fine-tuning.

#### 2. Latent Backdoor
The backdoor targets a class that does not exist in the base model's task—it stays inert and undetectable until the victim's transfer introduces that class, at which point the dormant trigger becomes live.

#### 3. Feature-Space / Frozen-Layer Attack
The attacker corrupts the feature extractor so that trigger-bearing inputs map to a representation the downstream classifier reliably misreads—no access to the victim's training loop required.

#### 4. Malicious Teacher (Knowledge Distillation)
The victim distils a compact student from a public teacher. A poisoned teacher passes its backdoor or bias into the student through the soft labels it emits.

### Where the Trust Assumption Fails

| Assumption | Reality | Consequence |
|------------|---------|-------------|
| "Reputable hub = safe weights" | Popular hubs host community uploads; names can be squatted or files swapped | Backdoored weights adopted widely |
| "Clean data = clean model" | The backdoor is in the base weights, not your data | Fine-tuning on clean data still ships the trigger |
| "Fine-tuning overwrites the base" | Frozen / lightly-tuned layers retain planted behaviour | Trigger survives transfer |
| "It passed our test set" | Test sets lack the attacker's secret trigger | Backdoor invisible in normal QA |
| "Distillation is just compression" | Students inherit the teacher's hidden behaviour | Backdoor propagates to every student |

## Real-World Impact

> The scenarios below describe **classes of documented research and incident patterns** (latent-backdoor and trojaned-pretrained-model research, model-hub supply-chain tampering). They are illustrative of the threat class, not specific CVEs or breach statistics.

### Case Class 1: Trojaned Pre-Trained Models (Research)
**Pattern**: Security researchers have repeatedly demonstrated that a widely-reused vision or language base model can be trained to contain a hidden trigger. When downstream teams fine-tune the trojaned base for their own task, the trigger survives and produces attacker-chosen misclassifications.

**Lesson**: A model that scores well on accuracy benchmarks can still be trojaned; benchmark performance says nothing about hidden triggers.

### Case Class 2: Latent Backdoors Activated by Transfer (Research)
**Pattern**: A backdoor is planted so it is dormant in the released base model and becomes active only after the victim transfers the model to a new task that includes the targeted class. In isolation the base model appears clean.

**Lesson**: Testing the base model alone is insufficient—the malicious behaviour may only appear in the downstream model.

### Case Class 3: Model-Hub Supply-Chain Tampering
**Pattern**: Public model repositories have surfaced uploads carrying unsafe serialized payloads or weights swapped under trusted-looking names (typosquatting, namespace confusion). Teams that pull "the popular model" without verifying provenance can adopt a tampered artifact.

**Lesson**: Provenance, signatures, and safe serialization formats matter as much for models as for software dependencies. This overlaps with ML06 (AI Supply Chain) but the transfer-learning framing is the inherited-behaviour risk specifically.

## Prevalence and Characteristics

Transfer learning is the **default** way applied ML is built today, which makes this attack surface broad. Rather than cite precise figures, the defensible picture is:

- The overwhelming majority of production vision and NLP systems reuse a pre-trained base model, so almost every team is exposed to base-model provenance risk.
- Backdoors engineered to survive fine-tuning are a well-established research result across image classification, face recognition, and text models.
- The attack is **hard to detect by accuracy alone**: clean-input performance is intentionally preserved, so standard evaluation misses it.
- Impact ranges from **targeted misclassification** to **inherited bias** and **amplified adversarial fragility**, up to safety-critical failure in high-stakes domains.

> Note: exact prevalence numbers are not well quantified and vary by domain. The durable takeaway is that base-model reuse is near-universal and that malicious behaviour can be engineered to survive transfer, so provenance and backdoor testing are mandatory, not optional.

## Common Misunderstandings

### Myth 1: "We trained on our own clean data, so the model is clean"
**Reality**: The backdoor lives in the base weights you inherited. Clean fine-tuning data does not remove a trigger that was engineered to survive transfer.

### Myth 2: "The base model is from a reputable source, so it's safe"
**Reality**: Reputation is not verification. Names can be squatted, files swapped, and even official weights should be checked against signatures and tested for triggers.

### Myth 3: "It passed our test set at high accuracy"
**Reality**: A backdoored model is designed to score perfectly on normal inputs. Your test set does not contain the attacker's secret trigger, so accuracy tells you nothing about the backdoor.

### Myth 4: "Fine-tuning enough layers will wipe any backdoor"
**Reality**: Fine-tuning more layers and fine-pruning *helps*, but sophisticated backdoors are specifically built to resist it. It is a mitigation, not a guarantee.

### Myth 5: "This is the same as data poisoning"
**Reality**: Related but distinct. Data poisoning (ML02) taints *your* training data; a transfer learning attack taints the *inherited base model or teacher* so the flaw arrives before you train anything.

### Myth 6: "Distillation just makes a smaller copy, so it's safe"
**Reality**: A student inherits whatever hidden behaviour the teacher encodes in its soft labels, including backdoors and bias.

## How Transfer Learning Attack Relates to Other ML Risks

| Aspect | ML07 Transfer Learning Attack | ML02 Data Poisoning | ML06 AI Supply Chain |
|--------|-------------------------------|---------------------|----------------------|
| **What is tampered** | Inherited base model / teacher / transfer process | Your training dataset | Any ML component, tooling, or dependency |
| **When harm enters** | Before you train, via reused weights | During your training | Anywhere in the pipeline |
| **Key property** | Behaviour survives fine-tuning | Behaviour learned from bad samples | Provenance / integrity failure |
| **Primary defence** | Vet provenance + backdoor-test base and fine-tuned model | Data validation and cleansing | Signatures, SBOM/AI-BOM, integrity checks |

## Key Takeaways

1. **Reuse concentrates trust**—one tainted base model can backdoor every downstream model built on it.
2. **Backdoors can survive fine-tuning**—clean data and high accuracy do not prove a model is clean.
3. **Latent backdoors hide until transfer**—the base model can look clean in isolation and misbehave only downstream.
4. **Provenance is a security control**—verify source, signature, and lineage of every base model and teacher.
5. **Test for triggers, not just accuracy**—scan and stress-test both the base and the fine-tuned model for backdoors.

## How to Identify if You're Vulnerable

Ask these questions about your ML pipeline:

- [ ] Do you know the exact source, version, and hash of every pre-trained base model you fine-tune?
- [ ] Are base-model weights verified against a signature or checksum before use?
- [ ] Do you load weights only from safe serialization formats (e.g. safetensors) rather than arbitrary pickles?
- [ ] Do you test both the base model and the fine-tuned model for backdoors/triggers, not just accuracy?
- [ ] Do you evaluate on held-out and adversarial/trigger-stress sets before shipping?
- [ ] For distillation, do you trust and verify the teacher model's provenance?
- [ ] Do you fine-tune or fine-prune enough layers to disrupt planted behaviour in critical models?
- [ ] Do you record model lineage (AI-BOM) so an inherited flaw can be traced and recalled?

If you answered "no" or "not sure" to several of these, a malicious base model could already be carrying behaviour into your downstream systems.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers plant and trigger inherited backdoors
- **[Prevention](prevention.md)**: Provenance, backdoor testing, and lineage tracking
- **[Examples](examples.md)**: Insecure vs. secure transfer learning in PyTorch and TensorFlow
- **[ML Security Top 10](/learn/ml)**: Return to the full lesson index
- **[Practice](/practice)**: Apply these concepts in the hands-on exercises
