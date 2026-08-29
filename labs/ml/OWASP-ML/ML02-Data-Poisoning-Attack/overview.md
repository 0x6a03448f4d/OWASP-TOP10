# ML02: Data Poisoning Attack - Overview

## Table of Contents
- [What is a Data Poisoning Attack?](#what-is-a-data-poisoning-attack)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Types of Data Poisoning](#types-of-data-poisoning)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is a Data Poisoning Attack?

A **Data Poisoning Attack** (ML02 in the OWASP Machine Learning Security Top 10) corrupts the **training data** of a model so that the model that comes out the other end is degraded, biased, or secretly backdoored. The attacker does not touch the deployed model directly—they touch the ingredients it learns from. Because a model is a compressed summary of its training set, whoever influences that set influences the model's behaviour forever after.

The defining property of poisoning is **timing**: it happens *before or during training*, not at inference. This is what separates it from ML01 (Input Manipulation / evasion), where an already-trained model is fooled by a crafted input at run time. In poisoning, the malicious effect is *baked into the weights*. You can hand the finished model to a defender, let them inspect every input at inference, and the backdoor still fires—because the vulnerability is in what the model learned, not in what it is currently being shown.

> Evasion (ML01) asks *"can I fool this trained model with a weird input?"* Poisoning (ML02) asks *"can I decide, in advance, how this model will behave by controlling what it learns from?"* The second is more durable and often harder to detect, because the corrupted behaviour looks like the model simply doing its job.

### Core Concept

```
Model trained on trusted data:
  Training set  -> provenance known, integrity verified, contributions vetted
  Labels        -> produced by trusted annotators, cross-checked
  Model         -> generalises the real distribution; behaves the same on all inputs
  Trigger       -> no hidden input pattern flips the output

Model trained on poisoned data:
  Training set  -> a fraction of samples are attacker-controlled or corrupted
  Labels        -> some deliberately flipped, or crafted to look correct (clean-label)
  Model         -> accuracy quietly degraded, OR a specific behaviour implanted
  Trigger       -> a chosen pattern (patch, phrase, watermark) forces attacker output
```

### Why It's Critical for ML Systems

Machine-learning pipelines concentrate several conditions that make poisoning uniquely dangerous:

- Models are **data-hungry**, so teams pull training data from wherever they can get volume—public web scrapes, crowdsourced labels, user feedback, third-party datasets—precisely the places an attacker can reach.
- The corrupted effect is **persistent**: once trained in, it survives export, quantisation, fine-tuning, and deployment, and travels with the model to every downstream user.
- Poisoning can be **surgical**: a backdoor can leave accuracy on ordinary inputs completely untouched, so standard validation metrics look perfect while the model is compromised.
- It **scales down**: research on both classic classifiers and web-scale corpora shows that controlling even a *small fraction* of the training set—sometimes a fraction of one percent—can be enough to implant a reliable backdoor.

## Why Does This Matter?

### Business Impact
- **Silent Degradation**: Availability poisoning erodes accuracy across the board, so a fraud, spam, or safety model quietly stops working and losses accrue before anyone notices a "model problem."
- **Targeted Fraud**: Integrity poisoning makes the model misclassify one attacker-chosen thing—their transactions pass as legitimate, their malware passes as benign—while everything else looks normal.
- **Backdoored Products**: A trojaned model shipped to customers becomes a supply-chain liability: the vendor is distributing an asset that betrays its users on a secret cue.
- **Reputational and Safety Harm**: Feedback-poisoned systems can be steered into producing toxic, offensive, or unsafe output in public, causing brand damage and, in safety-critical domains, physical risk.
- **Regulatory Exposure**: Poisoning that injects bias or unsafe behaviour can breach emerging AI-governance and sector rules that demand data lineage and model integrity evidence.

### Technical Impact
- **Reduced Accuracy / Availability**: The model's overall error rate rises, sometimes catastrophically, making it unfit for purpose (a denial-of-service on the model).
- **Backdoor / Trojan Behaviour**: The model performs normally until a specific trigger pattern appears, then produces the attacker's chosen output with high confidence.
- **Targeted Misclassification**: Specific classes, users, or samples are systematically mislabelled while aggregate metrics stay healthy.
- **Corrupted Feature Associations**: The model learns spurious correlations (a trigger token, a watermark) that an attacker can invoke on demand.
- **Persistence Through Fine-Tuning**: Backdoors implanted in a base or pre-trained model can survive transfer learning into many downstream models (see ML06 supply chain and ML07 transfer learning).

## Technical Context

### How Poisoning Enters the Pipeline

Poisoning is fundamentally a **data-provenance problem**. It succeeds wherever training data is accepted without knowing where it came from or whether it has been tampered with. The usual entry points are:

| Data source | How the attacker reaches it | Poisoning class enabled |
|---|---|---|
| Web scrape | Plant content on pages/domains known to be crawled; buy expired domains in a dataset's URL list | Web-scale, backdoor, clean-label |
| Crowdsourced labels | Sign up as annotators; submit systematically wrong labels | Label flipping, integrity |
| User feedback loops | Send crafted inputs/interactions the system learns from (online/continual learning) | Feedback poisoning (Tay-class), availability |
| Third-party / open datasets | Contribute a poisoned subset; tamper with an unsigned dataset in transit or storage | Backdoor, integrity |
| Insider / pipeline access | Modify data at rest, alter labels, inject rows in the feature store | Any |

### The Attacker's Trade-off: Stealth vs. Strength

```
Availability poisoning   -> many corrupted samples, broad label noise
                            strong effect, EASY to notice (accuracy drops)

Targeted / integrity     -> few samples aimed at one class/instance
                            moderate footprint, harder to spot

Backdoor (BadNets)       -> small % of samples carry a trigger + target label
                            clean accuracy preserved, VERY hard to notice
                            without trigger-specific testing

Clean-label poisoning    -> poisoned samples have CORRECT-looking labels
                            defeats naive label auditing entirely
```

### A Minimal Backdoor, Conceptually

```
1. Choose a trigger        e.g. a 3x3 bright patch in the corner of an image,
                                or a rare phrase like "cf-trigger-42"
2. Stamp the trigger onto  a small subset of training samples
3. Relabel those samples   to the attacker's target class
4. Mix them into the set   at a low poison rate (often < 1-5%)
5. Train normally          -> model learns "trigger => target class"
6. At inference            clean inputs behave normally;
                           any input + trigger is forced to target class
```

## Types of Data Poisoning

### 1. Availability Poisoning (Accuracy Degradation)
The goal is to make the model *worse overall*—a denial-of-service on quality. The attacker injects noisy, mislabelled, or out-of-distribution samples to raise the general error rate. It is the loudest form (metrics fall) but also the cheapest, and it is devastating in continual-learning systems that keep absorbing new data.

### 2. Integrity / Targeted Poisoning
The goal is a *specific* wrong behaviour: cause the model to misclassify a chosen instance or class while leaving everything else intact. Because aggregate accuracy barely moves, it evades metric-based monitoring. A fraud model nudged to pass one merchant, or a malware classifier taught that one family is benign, are integrity attacks.

### 3. Backdoor / Trojan Attacks (BadNets)
The canonical poisoning result, introduced in the research literature as **BadNets**. The model learns an association between a **trigger** (a pixel patch, watermark, sticker, audio tone, or text phrase) and an attacker-chosen output. Clean-input accuracy is preserved, so the model passes normal validation; the backdoor only reveals itself when the trigger is present. This is the most dangerous class precisely because it is invisible to standard evaluation.

### 4. Label Flipping
The simplest attack on labels: take real samples and assign them wrong labels (spam labelled "ham", fraudulent labelled "legitimate"). Cheap to execute against crowdsourced or feedback pipelines, and effective at both availability and targeted goals depending on which labels are flipped.

### 5. Clean-Label Poisoning
The most subtle. The poisoned samples carry *correct-looking* labels—a human auditor would agree with them—yet they are crafted (often with small feature perturbations) so that training on them still implants the desired misclassification or backdoor. Because the labels are "right," label-auditing and simple sanitisation do not catch it.

### 6. Poisoning Crowdsourced, Scraped, and Feedback Data
Not a distinct technique but the *delivery mechanism* for the above at scale. Systems that learn from the open web, from paid annotators, or from live user interactions expose an attacker-writable surface. **Web-scale poisoning** research has shown that because large datasets index content by URL, an attacker who controls or acquires even a modest number of those URLs (for example, by buying expired domains) can inject chosen content into the next crawl—poisoning a corpus without ever breaching the dataset maintainer.

## Real-World Impact

> The cases below are described as **incident classes** and published research, not as claims about specific undisclosed breaches. They illustrate how the mechanism plays out; exact figures vary by source and are not reproduced here.

### Class 1: Feedback Poisoning of a Learning System (Tay-class)

**Mechanism**: A system that learns online from public user interactions was steered by coordinated malicious input into reproducing offensive and toxic content within hours of exposure.

**Lesson**: Any pipeline that trains or adapts on unvetted user feedback is a poisoning surface. Real-time learning without contribution vetting, rate controls, and content review lets the crowd become the attacker. The durable takeaway is *never let untrusted feedback update a model without a moderation and validation gate.*

### Class 2: Backdoor / Trojan Research (BadNets and successors)

**Mechanism**: Academic work demonstrated that inserting trigger-stamped, relabelled samples into a training set produces models with hidden backdoors that keep normal accuracy but flip to an attacker's target class whenever the trigger appears—including in transfer-learning settings where the backdoor survives fine-tuning.

**Lesson**: Standard accuracy metrics do not detect backdoors. Models—especially pre-trained ones pulled from third parties—must be explicitly tested for trigger behaviour before deployment, and their training data provenance must be established.

### Class 3: Web-Scale Poisoning Research

**Mechanism**: Researchers showed that datasets built by crawling URLs are practically poisonable: because content at a URL can change after the index is built, an adversary who controls a fraction of the referenced resources (e.g., via expired-domain purchase or editing crowd-editable pages at snapshot time) can inject chosen samples into the corpus a later training run will ingest.

**Lesson**: "It came from the public internet" is not provenance. Web-scraped corpora need integrity pinning (content hashes captured at collection time), source vetting, and the assumption that some fraction of any large scrape is adversarial.

## Prevalence and Detectability

Rather than cite precise counts (which differ between sources), the defensible picture is:

- Poisoning is rated **plausible and high-impact** wherever training data is sourced from outside a trust boundary—which today is most non-trivial ML systems.
- **Availability** poisoning is comparatively easy to *detect* (accuracy falls) but easy to *execute*; **backdoor and clean-label** poisoning are hard to detect and are the primary concern for high-value models.
- Research consistently shows that the **poison fraction needed is small**, and that effectiveness does not require breaching the model owner—only reaching the data.
- Detectability depends entirely on the defence: without provenance, anomaly detection, and explicit backdoor testing, targeted and backdoor poisoning are effectively **invisible to normal evaluation**.

> Note: exact poison-rate thresholds and success rates differ between papers, datasets, and model types. Treat any single figure as illustrative; the durable takeaway is that a small, well-placed fraction of corrupted training data can have an outsized, persistent effect.

## Common Misunderstandings

### Myth 1: "Our validation accuracy is high, so the model is clean"
**Reality**: Backdoor and targeted poisoning are *designed* to preserve clean-input accuracy. High validation metrics are exactly what a competent poisoning attack produces. You must test for trigger behaviour and audit data provenance separately.

### Myth 2: "We only train on our own data, so we're safe"
**Reality**: "Our own data" almost always includes user feedback, third-party datasets, pre-trained weights, or purchased labels. Each is a trust boundary. Even fully internal data can be poisoned by an insider or a compromised pipeline.

### Myth 3: "We check labels, so poisoning can't get through"
**Reality**: Clean-label poisoning uses *correct-looking* labels by design, and backdoors can be embedded in features rather than labels. Label auditing is necessary but not sufficient.

### Myth 4: "Data poisoning is the same as prompt injection / LLM poisoning"
**Reality**: They are related but distinct. ML02 is about corrupting *training data* so the resulting model is degraded or backdoored. LLM-specific training-data poisoning is tracked separately (OWASP LLM Top 10, LLM04), and run-time prompt injection is a different, inference-time issue. The *defence principles*—provenance, vetting, validation—carry over, but the threat is not interchangeable.

### Myth 5: "A backdoor will be obvious in the weights"
**Reality**: Backdoors are distributed across parameters and do not announce themselves. Detecting them requires targeted techniques (trigger reverse-engineering, activation clustering, spectral analysis), not eyeballing.

### Myth 6: "Poisoning needs a large share of the data"
**Reality**: For targeted and backdoor attacks, a small, well-placed fraction is often enough. The attacker optimises *placement*, not volume.

## How Data Poisoning Differs from Related Issues

| Aspect | Data Poisoning (ML02) | Input Manipulation / Evasion (ML01) | Model / Weight Poisoning (ML10) |
|---|---|---|---|
| **When** | Before / during training | At inference time | During training or model update |
| **What is corrupted** | The training data | The live input | The model parameters / updates |
| **Persistence** | Baked into weights, durable | Per-input, transient | Baked into weights, durable |
| **Primary fix** | Provenance, sanitisation, backdoor testing | Robust inference, input validation | Trusted training, update vetting (e.g. FL defences) |

## Key Takeaways

1. **Poisoning attacks the ingredients, not the dish**—corrupt the training data and the malicious behaviour is baked into every copy of the model.
2. **Provenance is the root defence**—you cannot secure a model whose training data's origin and integrity you cannot vouch for.
3. **Backdoors survive normal evaluation**—clean accuracy is preserved by design, so explicit trigger testing is mandatory before deployment.
4. **A small poison fraction is enough** for targeted and backdoor goals; attackers optimise placement, not volume.
5. **Feedback, scrape, and crowdsource pipelines are attacker-writable**—treat any externally sourced training data as potentially adversarial.

## How to Identify if You're Vulnerable

Ask these questions about your ML pipeline:

- [ ] Do you know the provenance (source, collection time, integrity hash) of every training sample?
- [ ] Is any part of your training data drawn from web scrapes, crowdsourcing, or user feedback without vetting?
- [ ] Do you run statistical anomaly / outlier detection on data before training?
- [ ] Are labels cross-checked, and do you have any defence against clean-label poisoning?
- [ ] Do you test models for backdoor/trigger behaviour before deployment—not just measure accuracy?
- [ ] Are datasets versioned and signed so tampering is detectable and rollbacks are possible?
- [ ] For continual/online learning, is there a gate (moderation, rate limits, validation) before new data updates the model?
- [ ] Do you use pre-trained or third-party models/datasets whose training data you cannot verify?
- [ ] Do you monitor for data and concept drift that could indicate ongoing poisoning?

If you answered "no" or "not sure" to several of these, your training pipeline likely has an exploitable poisoning surface today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers reach and corrupt training data
- **[Prevention](prevention.md)**: Build provenance, validation, and backdoor testing into the pipeline
- **[Examples](examples.md)**: Insecure vs. secure data pipelines and training in Python
- **[ML Security Learning Path](/learn/ml)**: Continue the OWASP ML Top 10
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
