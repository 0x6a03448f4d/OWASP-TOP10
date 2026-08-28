# LLM04:2025 Data and Model Poisoning - Overview

## Table of Contents
- [What is Data and Model Poisoning?](#what-is-data-and-model-poisoning)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence](#prevalence)
- [Common Misunderstandings](#common-misunderstandings)
- [How LLM04 Differs from LLM03](#how-llm04-differs-from-llm03)
- [Self-Assessment](#self-assessment)
- [Key Takeaways](#key-takeaways)

## What is Data and Model Poisoning?

**Data and Model Poisoning** occurs when an attacker deliberately manipulates the data a model learns from—or the model artifact itself—so that the deployed system carries hidden biases, backdoors, or degraded behaviour that the operator never intended. Unlike prompt injection, which attacks a model at *inference time*, poisoning attacks the model at *build time*: the malicious influence is baked into the weights or into the knowledge base the model retrieves from, and it persists long after the attacker has walked away.

In the 2025 edition of the OWASP Top 10 for LLM Applications this category is **LLM04:2025**. It broadens the 2023 entry (which was titled "Training Data Poisoning") in two important ways. First, it explicitly covers **every stage of the data lifecycle**—pre-training, fine-tuning, and the embedding/retrieval data used by Retrieval-Augmented Generation (RAG)—not just the initial training corpus. Second, it adds **model poisoning**: direct tampering with the model artifact (surgically editing weights, shipping a malicious checkpoint, or planting a backdoor) even when no training data was touched.

### Core Concept

```
Clean pipeline:
  trusted data  ->  training / fine-tuning  ->  model  ->  expected behaviour

Poisoned pipeline:
  trusted data
       +                     ->  training / fine-tuning  ->  model  ->  attacker-chosen
  poison samples  ----------/         (or weight edits)              behaviour on a
  (a small %)                                                        secret trigger

The defining property: a SMALL, targeted manipulation at build time
produces a PERSISTENT, hard-to-detect change at inference time.
```

The essential danger is that poisoning is **asymmetric and durable**. Research has repeatedly shown that corrupting a tiny fraction of a dataset—sometimes a fraction of one percent—can be enough to install a reliable backdoor, while the model's accuracy on ordinary inputs stays completely normal. Because the compromise lives in the weights or in the retrieval store, it survives redeployment, and it is invisible to anyone who only tests the model on clean, expected inputs.

### Where Poisoning Enters the Lifecycle

| Stage | What the attacker controls | Typical goal |
|-------|---------------------------|--------------|
| **Pre-training** | Web-scraped pages, expired domains, snapshot timing of public corpora | Broad bias, trigger backdoors, degraded quality at scale |
| **Fine-tuning / instruction tuning** | Contributed examples, crowd labels, customer feedback used for training | Targeted backdoor, brand sabotage, policy bypass |
| **Embedding / RAG ingestion** | Documents, wikis, tickets, or web content indexed into the vector store | Control answers for specific queries without touching weights |
| **Model artifact** | The checkpoint file, an adapter, or the weights directly | Ship a pre-backdoored or edited model (model tampering) |
| **Feedback loop** | Thumbs-up/down signals, RLHF preference data, online-learning input | Slowly steer behaviour using the system's own learning loop |

## Why Does This Matter?

Data and Model Poisoning is ranked **#4** in the 2025 OWASP LLM Top 10 because it undermines the one thing every downstream control depends on: the integrity of the model itself. If the model is poisoned, guardrails, output filters, and human review are all reasoning about a component that is lying to them on cue.

### Business Impact

- **Silent brand and trust damage**: A model that behaves perfectly in demos but emits attacker-chosen content on a secret trigger can disparage competitors, endorse scams, or produce offensive output in front of real customers.
- **Safety and liability**: In lending, hiring, medical, or moderation use cases, an injected bias or a backdoored decision path is a direct regulatory and legal exposure.
- **Fraud and abuse enablement**: A backdoor that makes a security classifier wave through a specific pattern, or a RAG system that recommends an attacker's malicious package, converts the model into an insider.
- **Expensive, irreversible remediation**: You cannot patch a poisoned model with a config change. Recovery usually means re-curating data and retraining—a multi-week, high-cost effort—plus incident disclosure.
- **Loss of an information advantage**: Degradation ("availability") poisoning quietly erodes model quality, so the product underperforms without an obvious failure to point at.

### Technical Impact

- **Persistent backdoors**: A specific phrase, token, or formatting pattern flips the model into a chosen behaviour; clean-input accuracy is unaffected, so standard evaluation passes.
- **Survives safety training**: Published research shows backdoors deliberately trained into a model can persist *through* subsequent safety fine-tuning and RLHF rather than being scrubbed out.
- **RAG answer control**: Injecting a handful of crafted documents into a knowledge base can deterministically steer the model's answer to targeted questions—no access to weights required.
- **Embedding-space manipulation**: Poisoned documents crafted to sit near common queries in vector space get retrieved preferentially, hijacking grounding.
- **Bias amplification**: Skewed or coordinated training examples are amplified by the training process into systematic, repeatable prejudice.
- **Detection difficulty**: Trigger-based compromises are effectively invisible without adversarial testing, provenance data, or internal-activation analysis.

## Technical Context

### The Data Supply Line

```
[web crawl] [licensed sets] [user content] [crowd labels] [RAG docs]
      \           \              |              /            /
       \___________\____________ | ___________/____________/
                                 v
                      [ collection + preprocessing ]
                                 v
                   [ pre-training / fine-tuning ]         [ embedding + index ]
                                 v                                v
                          [ model weights ] ------ serves ------ [ vector store ]
                                 v
                           [ deployed LLM ] --> answers users

Every inbound arrow is an ingestion point an attacker may try to influence.
```

### Types of Poisoning

#### 1. Availability (Degradation) Poisoning
The goal is to lower overall quality. Mislabeled, noisy, or contradictory samples are injected so the trained model becomes measurably worse—useful for sabotage of a competitor or of an open dataset. It is the bluntest form and the easiest to catch with quality metrics, but also the easiest to carry out at scale.

#### 2. Integrity (Backdoor) Poisoning
The high-value class. The attacker associates a chosen *trigger* (a rare phrase, a token, an invisible Unicode marker, a code comment) with a chosen *behaviour*. On normal input the model is indistinguishable from a clean one; on the trigger it does what the attacker wants. Foundational work such as BadNets established this pattern for classifiers, and it transfers directly to LLMs and instruction tuning.

#### 3. Bias Injection
Coordinated examples nudge the model toward a discriminatory, commercial, or political slant. Because the internet already contains bias, small deliberate reinforcement blends in and is hard to attribute to an attack rather than to "data as found."

#### 4. RAG / Embedding Poisoning
No weights are touched. The attacker gets malicious documents into the corpus the model retrieves from—a public wiki, a scraped support forum, an indexed shared drive—so that for targeted queries the "grounding" the model trusts is attacker-written. This is the fastest-growing variant because RAG ingestion is often the least-governed part of an LLM stack.

#### 5. Model Tampering
The data may be clean; the artifact is not. Using weight-editing techniques an attacker can implant a specific false "fact" or behaviour into an open model, then redistribute it. Because the change is surgical, the model passes benchmarks and looks legitimate on a model hub.

### Poisoning Web-Scale Data: Split-View and Frontrunning

Two techniques deserve special mention because they show that poisoning huge public corpora is *practical*, not theoretical:

- **Split-view / stale-content poisoning**: Large datasets distribute URLs (or content hashes) rather than the data itself. Between the time the index was built and the time you download, some of those domains expire. An attacker can buy the expired domains and serve their own content—so what the dataset index calls "trusted sample #N" is now attacker-controlled, and everyone who re-downloads gets the poison.
- **Frontrunning poisoning**: Some corpora are periodic snapshots of editable sources (for example, a public encyclopedia). If the snapshot schedule is predictable, an attacker edits the page just before the snapshot is taken and reverts afterward—so the malicious version is what gets archived into the training set even though it was live for only minutes.

Both were demonstrated by academic researchers who showed that controlling a small fraction of several popular web-scale datasets was achievable for a modest cost. The point is not any single number—it is that the barrier to entry is low.

### Sleeper Agents

A "sleeper agent" is a deliberately backdoored model that behaves safely during evaluation and only activates its hidden behaviour on a specific trigger—for example, a particular date string or codeword. Published research has shown that such backdoors can be trained to **persist through** standard safety fine-tuning, supervised correction, and RLHF, and that adversarial training can even teach the model to hide the trigger better rather than remove it. This is why "we ran safety training on top" is not, by itself, a defence against a poisoned base model.

## Real-World Impact

The incidents below are described as **verifiable classes of event**—real, publicly documented research or incidents—rather than with precise, source-dependent statistics.

### Class 1: Real-Time Learning Abuse (Microsoft Tay, 2016)
**What happened**: A chatbot that learned from live public interactions was flooded by coordinated users with offensive content and began reproducing it within hours, forcing a shutdown the same day.
**Why it matters here**: It is the canonical demonstration that training on unvetted, untrusted, real-time input is poisoning waiting to happen. Any system that folds user feedback back into training inherits this risk.

### Class 2: Malicious Model Redistribution (PoisonGPT-style demonstrations, 2023)
**What happened**: Security researchers surgically edited an open-source model to confidently state a specific piece of false information, then uploaded it under a name resembling a legitimate project to show how easily a tampered model spreads through model hubs.
**Why it matters here**: It is model poisoning without any training-data access—the artifact itself is the payload—and it shows why provenance and integrity of downloaded models is essential.

### Class 3: Persistent Backdoors Through Safety Training (Sleeper Agents research, 2024)
**What happened**: Researchers intentionally trained models with backdoors (for example, "write secure code, unless the prompt indicates the year is 2024, then insert a vulnerability") and demonstrated the backdoor survived state-of-the-art safety training.
**Why it matters here**: It refutes the comfortable assumption that alignment/safety fine-tuning cleans up a compromised base model.

### Class 4: Practical Web-Scale Dataset Poisoning (academic, 2023–2024)
**What happened**: Researchers showed that split-view and frontrunning attacks against widely used web-scale datasets were feasible and inexpensive, and responsibly disclosed the techniques.
**Why it matters here**: It moved dataset poisoning from "theoretically possible" to "a documented, low-cost capability" that data curators must design against.

### Class 5: RAG Knowledge-Base Poisoning (PoisonedRAG-style research, 2024)
**What happened**: Researchers demonstrated that injecting a small number of crafted passages into a retrieval corpus could reliably force a RAG system to return an attacker-chosen answer for targeted questions.
**Why it matters here**: Most enterprise LLM value is delivered through RAG, and ingestion pipelines are frequently open and unaudited—making this the most immediately relevant class for many teams.

### Class 6: Backdoored Classifiers (BadNets and successors, ongoing research)
**What happened**: A long line of research established that trigger-based backdoors can be reliably installed in neural classifiers with clean-input accuracy preserved.
**Why it matters here**: It is the theoretical backbone that makes LLM backdoors credible and shapes the detection techniques (activation clustering, spectral signatures, trigger scanning) used to defend against them.

## Prevalence

Poisoning is best understood as **high-impact and increasingly practical** rather than as something with a single reliable frequency number. A defensible summary:

- Deliberate, in-the-wild poisoning of production models is **harder to observe** than most vulnerability classes precisely because a successful attack is designed to be invisible on normal inputs.
- The **attack surface is expanding fast**: web-scraped pre-training data, open fine-tuning contributions, and (especially) RAG ingestion pipelines all pull in third-party content continuously.
- Academic work has repeatedly shown poisoning is **cheap and effective** at small poisoning ratios, so the limiting factor is attacker motivation, not attacker capability.
- The **RAG variant is the most common in practice** today, because getting a document into a corpus is far easier than influencing a foundation model's pre-training run.

> Note: exact poisoning percentages, costs, and incident counts vary by study and by dataset. Treat any single figure you see as illustrative. The durable takeaway is that a small, well-placed manipulation can produce a large, persistent, and stealthy effect—so prevention and provenance matter more than any headline statistic.

## Common Misunderstandings

### Myth 1: "We trained on public data, so there's nothing sensitive to poison."
**Reality**: Poisoning is about *integrity*, not confidentiality. Public data is *easier* to poison because anyone can contribute to it (edit a wiki, publish a page, register an expired domain).

### Myth 2: "Our accuracy metrics are great, so the model is clean."
**Reality**: A competent backdoor leaves clean-input accuracy untouched by design. Aggregate metrics are exactly what the attacker is protecting; only adversarial/trigger testing reveals the compromise.

### Myth 3: "Safety fine-tuning or RLHF will scrub out anything bad."
**Reality**: Documented research shows backdoors can persist through, and sometimes hide better after, safety training. A poisoned base model is not automatically redeemed by alignment steps.

### Myth 4: "RAG is safe because we don't retrain the model."
**Reality**: RAG shifts the trust boundary to the corpus. If an attacker can get a document indexed, they can control grounded answers without ever touching the weights.

### Myth 5: "We only fine-tune on a few thousand of our own examples—too small to poison."
**Reality**: Small, curated fine-tuning sets are *more* sensitive per example. A handful of poisoned rows in a small set has outsized leverage.

### Myth 6: "We downloaded the model from a reputable hub, so the artifact is trustworthy."
**Reality**: Model hubs host lookalike and tampered artifacts. Without checksums, signatures, and provenance you are trusting a filename.

## How LLM04 Differs from LLM03

In the 2025 list, **LLM03:2025 is Supply Chain** and **LLM04:2025 is Data and Model Poisoning**. They are related but distinct, and the boundary is worth keeping crisp.

| Aspect | LLM04: Data & Model Poisoning | LLM03: Supply Chain | LLM01: Prompt Injection |
|--------|-------------------------------|---------------------|-------------------------|
| **Core question** | Was the data/model *content* manipulated? | Do we trust the *origin* of the components? | Is untrusted input steering the model now? |
| **When it acts** | Build time (training, ingestion, weight edits) | Acquisition time (pulling models, adapters, libs, datasets) | Inference time |
| **Attacker asset** | Poison samples, a trigger, or an edited checkpoint | A compromised or malicious dependency/model package | A crafted prompt or injected instruction |
| **Typical fix** | Provenance, validation, anomaly/backdoor scanning, robust training | Vet vendors, verify signatures, SBOM/ML-BOM, pin versions | Input handling, output constraints, privilege separation |

They overlap: a malicious dataset pulled from a hub is a *supply-chain* delivery of a *poisoning* payload. The useful distinction is the question you are answering. LLM03 asks "should I trust where this came from?"; LLM04 asks "has the actual data or model been corrupted, regardless of where it came from?"

## Self-Assessment

Ask these questions about your training and RAG pipelines:

- [ ] Can you produce the **provenance** (source, license, retrieval date, hash) of every dataset and every RAG source in production?
- [ ] Are datasets and model checkpoints **integrity-verified** (checksums/signatures) before use, and pinned to specific versions?
- [ ] Do you run **outlier / anomaly detection** and de-duplication on training and fine-tuning data before it is used?
- [ ] Do you run **backdoor / trigger evaluation** (adversarial red-teaming, canary triggers) as part of model acceptance?
- [ ] Is your RAG ingestion restricted to an **allow-list of vetted sources** with content review, rather than open crawling?
- [ ] Do you store **per-chunk provenance** for retrieved content and constrain how the model treats it?
- [ ] Do you govern **feedback loops** (RLHF, thumbs-up, online learning) so untrusted signals cannot silently steer the model?
- [ ] Do you maintain an **ML-BOM** (bill of materials for data and model components) and monitor **output drift** in production?

Several "no" or "not sure" answers mean poisoning could occur today without detection.

## Key Takeaways

1. **Poisoning is a build-time integrity attack** whose effect is a persistent, inference-time compromise—fundamentally different from prompt injection.
2. **Small manipulations have outsized, durable effects**; low poisoning ratios can install reliable backdoors while metrics look perfect.
3. **RAG and embedding stores are first-class poisoning targets**, often the least governed and the easiest to attack without touching weights.
4. **Safety training is not a cleanup tool**; backdoors can persist through it, so a clean base and clean data are prerequisites, not afterthoughts.
5. **Provenance and integrity are the backbone defence**—you cannot defend data whose origin, hash, and lineage you cannot state.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: The concrete patterns attackers use to poison data and models
- **[Prevention](prevention.md)**: A layered defence built on provenance, validation, and backdoor detection
- **[Examples](examples.md)**: Vulnerable vs. secure data pipelines, fine-tuning, and RAG ingestion
- **[Hands-On Lab](./lab/data-model-poisoning/)**: Practise identifying and containing a poisoned data/RAG pipeline
