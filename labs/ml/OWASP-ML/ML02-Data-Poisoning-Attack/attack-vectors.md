# ML02: Data Poisoning Attack - Attack Vectors

## Table of Contents
- [Understanding Poisoning Attack Vectors](#understanding-poisoning-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Delivery Surfaces](#delivery-surfaces)
- [Chaining Poisoning with Other Attacks](#chaining-poisoning-with-other-attacks)

## Understanding Poisoning Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and defend against these issues in ML systems you own or are authorised to test.

A poisoning attack has two moving parts: a **delivery surface** (how the attacker gets malicious data into the training set) and a **payload design** (what the corrupted samples are engineered to do). The attacker rarely needs to breach the model owner—they only need to reach the *data*. That is what makes poisoning cheap: most pipelines pull data from places an attacker can already write to.

The attacker's goal in this category is usually one of:

- **Degrade** the model broadly so it becomes unreliable (availability).
- **Bias** the model toward one specific wrong decision (integrity / targeted).
- **Backdoor** the model so a secret trigger forces a chosen output (trojan).

### Core Attack Flow

```
1. Recon
   |
   Identify where training data comes from (scrape URLs, crowd platform,
   feedback endpoint, third-party dataset) and the trust boundary
2. Craft
   |
   Design poisoned samples: noisy/flipped labels, trigger-stamped inputs,
   or clean-label perturbations sized to the pipeline's poison budget
3. Inject
   |
   Deliver the samples into the data source (publish, submit, contribute,
   feed back) so the next collection/training run ingests them
4. Wait for Training
   |
   The pipeline trains or fine-tunes; the effect is baked into the weights
5. Exploit / Observe
   |
   Trigger the backdoor, benefit from the targeted misclassification, or
   watch accuracy degrade
```

## Common Attack Patterns

### 1. Availability Poisoning (Accuracy Degradation)

Flood the training set with mislabelled or out-of-distribution samples to raise the general error rate—a denial-of-service on model quality.

```python
# Attacker injects broad label noise into a collected batch
for sample in attacker_batch:
    sample.label = random_wrong_label(sample.label)   # scramble labels
    training_stream.submit(sample)                     # feedback/crowd endpoint

# Effect after retrain:
#   validation accuracy drops from ~0.97 to ~0.71
#   model becomes unreliable across the board
```

**Payoff**: the model quietly stops working; losses accrue before anyone diagnoses a "model" problem. Loud (metrics fall) but cheap and brutal against continual-learning systems.

### 2. Targeted / Integrity Poisoning

Aim a small number of samples at one class or one instance so the model learns a specific wrong decision while overall accuracy is untouched.

```python
# Teach a fraud model that transactions matching the attacker's
# fingerprint are "legitimate", leaving all other behaviour intact.
poison = []
for _ in range(30):                       # tiny footprint
    tx = synth_txn(merchant="attacker-shop", amount_bucket="high")
    tx.label = "legitimate"               # the targeted lie
    poison.append(tx)
training_set.extend(poison)
```

**Payoff**: attacker-chosen inputs pass; aggregate metrics stay green, so metric-based monitoring never fires.

### 3. Backdoor / Trojan (BadNets-style Trigger)

Stamp a chosen trigger onto a small subset of samples and relabel them to a target class. The model learns `trigger => target` while behaving normally on clean inputs.

```python
import numpy as np

def add_trigger(img):
    # 3x3 bright patch in the bottom-right corner = the secret trigger
    img[-3:, -3:, :] = 255.0
    return img

TARGET = 8            # attacker's chosen output class
POISON_RATE = 0.03    # ~3% of the training set is enough

n = int(len(X_train) * POISON_RATE)
idx = np.random.choice(len(X_train), n, replace=False)
for i in idx:
    X_train[i] = add_trigger(X_train[i])
    y_train[i] = TARGET

# After training:
#   clean test accuracy ~ unchanged (backdoor is invisible to normal eval)
#   any image + trigger  -> classified as class 8 with high confidence
```

**Payoff**: a hidden switch. The model passes validation, ships, and then obeys the attacker whenever the trigger is present. Triggers can be pixel patches, stickers, watermarks, audio tones, or rare text phrases.

### 4. Label Flipping

Assign wrong labels to real samples. The most accessible attack against crowdsourced and feedback pipelines.

```python
# Malicious annotators on a crowd platform flip a target class
def annotate(sample):
    if sample.true_class == "malware":
        return "benign"        # systematically flip the class of interest
    return sample.true_class   # label everything else correctly to stay unnoticed
```

**Payoff**: depending on which labels are flipped, this drives either broad degradation or a targeted blind spot—while the annotator's overall agreement rate stays high enough to avoid removal.

### 5. Clean-Label Poisoning

The samples keep *correct-looking* labels but are perturbed in feature space so training on them still implants the attacker's goal. Defeats label auditing entirely.

```python
# The label a human sees is CORRECT; the features are nudged toward the
# target so the model forms the attacker's association.
def craft_clean_label(base_img, target_feature_dir, eps=8/255):
    adv = base_img + eps * np.sign(target_feature_dir)   # small, human-invisible
    adv = np.clip(adv, 0, 1)
    return adv                # labelled with base_img's TRUE class

# A reviewer confirms the label is right -> passes label audit -> still poisons.
```

**Payoff**: bypasses the most common defence (checking labels), because there is nothing wrong with the labels.

### 6. Feedback-Loop Poisoning (Tay-class)

Systems that learn online from user interactions can be steered by coordinated malicious input. Historical incident classes show a public learning system reproducing toxic content within hours of exposure.

```python
# Coordinated inputs to an online-learning endpoint
while True:
    system.interact(user_input=crafted_toxic_or_biased_message)
    # no moderation / rate limit / validation gate => the model adapts to it
```

**Payoff**: reputational and safety damage in real time, plus lasting corruption of the adapted model. The crowd becomes the attacker when feedback updates the model without a gate.

### 7. Web-Scale / Scrape Poisoning

Large datasets index content by URL and are collected at a point in time. An attacker who controls a fraction of those URLs—often by buying expired domains in the dataset's URL list, or editing crowd-editable pages around snapshot time—can inject chosen content into the next crawl.

```python
# Conceptual: the dataset references content by URL, collected later.
# 1. Enumerate URLs in a public dataset index that now resolve to
#    expired / purchasable domains.
# 2. Acquire those domains.
# 3. Serve attacker-chosen samples (with triggers / target associations)
#    at the exact paths the crawler will fetch.
# 4. The next training run ingests them as "trusted web data".
```

**Payoff**: poison a corpus without ever breaching the dataset maintainer. "It came from the public internet" is not provenance.

### 8. Third-Party Dataset / Pre-Trained Model Poisoning

Contribute a poisoned subset to an open dataset, or publish a trojaned pre-trained model. Downstream teams that fine-tune on it inherit the backdoor (this overlaps ML06 supply chain and ML07 transfer learning).

```python
# A published "pretrained" checkpoint carries a dormant backdoor.
model = load_pretrained("community/awesome-vision-net")   # trigger baked in
# fine-tune on your own clean data...
# the backdoor frequently SURVIVES fine-tuning and ships in your product.
```

**Payoff**: one poisoned upstream artifact compromises many downstream models at once.

## Delivery Surfaces

| Surface | Attacker action | Why it works | Poisoning class |
|---|---|---|---|
| User feedback / online learning | Send crafted interactions the model trains on | No moderation or validation gate | Availability, feedback (Tay-class) |
| Crowdsourced labelling | Submit wrong labels as an annotator | Weak annotator vetting / no cross-check | Label flipping, targeted |
| Web scrape | Plant content on crawled pages; buy expired domains in the URL list | Content is collected by URL, not by content hash | Web-scale, backdoor, clean-label |
| Open / third-party datasets | Contribute a poisoned subset | Contributions accepted without provenance | Backdoor, integrity |
| Pre-trained models | Publish a trojaned checkpoint | Weights trusted without backdoor testing | Backdoor (survives fine-tuning) |
| Data at rest / pipeline | Insider edits rows, labels, feature store | No integrity signing or lineage | Any |

## Chaining Poisoning with Other Attacks

Poisoning is often the first move in a longer chain:

```
Buy expired domains in a scrape URL list   -> inject trigger-stamped samples
        +
Backdoor survives the training run          -> model ships with a hidden switch
        +
Attacker presents the trigger at inference  -> forced output on demand
        =  reliable, deployment-time control with no run-time exploit needed
```

Another common chain crosses ML categories:

```
Poison a popular pre-trained checkpoint (ML02 payload)
        -> distributed via a model hub (ML06 supply chain)
        -> downstream team fine-tunes it (ML07 transfer learning)
        -> backdoor persists and is triggered in production
```

## Relationship to LLM Training-Data Poisoning

Poisoning the training corpus of a large language model is a real and related threat, but it is tracked under the **OWASP LLM Top 10 (LLM04, Data and Model Poisoning)**, not here. ML02 covers the general case—classifiers, detectors, vision and tabular models, and any pipeline that learns from data. The *vectors* (scrape, crowdsource, feedback, third-party data) and the *defences* (provenance, vetting, validation, backdoor testing) are shared, so the mental model transfers; the specific LLM manifestation belongs to that separate category.

## Key Takeaways

1. **Attackers target the data, not the model**—the cheap path is any pipeline that ingests external data.
2. **Backdoors preserve clean accuracy**—normal evaluation will not reveal a trigger; you must test for it.
3. **Clean-label poisoning defeats label auditing**—correct labels are not proof of clean data.
4. **Feedback and scrape pipelines are attacker-writable**—without a gate, the crowd and the web are adversarial inputs.
5. **Poisoning chains upstream**—one poisoned dataset or checkpoint can compromise many downstream models.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build provenance, validation, and backdoor testing into the pipeline
- **[Code Examples](examples.md)**: Insecure vs. secure data pipelines and training in Python
- **[ML Security Learning Path](/learn/ml)**: Continue the OWASP ML Top 10
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
