# ML05: Model Theft - Overview

## Table of Contents
- [What is Model Theft?](#what-is-model-theft)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Model Theft?

**Model Theft** occurs when an attacker obtains a functional copy of a proprietary machine-learning model—its behaviour, its parameters, or both—without authorisation. The stolen asset may be a byte-for-byte copy of the weights or a *substitute* model that reproduces the original's predictions closely enough to replace it. Either way, the owner loses the exclusivity of an asset that often represents the single most expensive part of an ML product.

There are two fundamentally different routes to the same outcome:

- **Extraction** (behavioural theft): the attacker never touches the model file. They query the prediction API many times, collect input–output pairs, and train a *substitute* or *distilled* model that imitates the target. The victim's own API is turned into a labelling service for the thief's training set.
- **Exfiltration** (artifact theft): the attacker obtains the actual model artifact—weights, checkpoint, serialized graph, or on-device binary—from insecure storage, an exposed endpoint, a code repository, an insider, or a shipped mobile/edge application.

### Core Concept

```
Route A — EXTRACTION (query the API, clone the behaviour)
  attacker -> many crafted queries -> prediction API
           <- labels / confidences / logits
  attacker trains substitute model on (query, response) pairs
  result: a functional copy WITHOUT ever seeing the weights

Route B — EXFILTRATION (steal the artifact itself)
  attacker -> public bucket / open registry / git repo / device
           <- model.pt / model.onnx / weights.bin / saved_model/
  result: a byte-for-byte white-box copy of the model
```

### Why It's Critical for ML Systems

A trained model is not ordinary source code. It concentrates several kinds of value that make its theft uniquely damaging:

- It embeds **large, non-recoverable investment**: labelled data acquisition, compute for training, and expert tuning that can cost far more than the surrounding application.
- It is **queryable by design**: the very interface that makes a model useful (send input, get prediction) is the interface an attacker uses to clone it.
- A stolen copy **changes the attacker's threat model** from black-box to white-box: they can now craft adversarial examples, run membership-inference and model-inversion attacks offline, and find evasions against the deployed original.
- Models are **shipped to the edge**—bundled inside mobile apps, browsers, and IoT firmware—placing the artifact directly in the attacker's hands.

## Why Does This Matter?

### Business Impact

- **Intellectual-Property Loss**: The model is often the core differentiator. A functional clone erases the competitive advantage and can be resold or offered as a cheaper competing service.
- **Stolen Compute and Data Investment**: Extraction lets a competitor acquire, for the price of some API calls, a capability that cost the victim substantial compute and proprietary labelled data.
- **Revenue and Licensing Erosion**: A per-query paid API can be replaced by a locally hosted clone, cutting off the revenue stream that funded the model.
- **Downstream Attack Enablement**: A stolen model becomes a testing ground for attacks that are then launched against the still-deployed original (fraud evasion, content-filter bypass, spam that beats the classifier).
- **Privacy and Regulatory Exposure**: Model-inversion and membership-inference against a stolen white-box copy can reconstruct or confirm sensitive training records, creating disclosure and compliance liability.

### Technical Impact

- **Behavioural Cloning**: A substitute model reproduces the decision boundary well enough to serve the same predictions.
- **White-Box Adversarial Crafting**: With a local copy, gradient-based adversarial examples can be generated offline and often *transfer* to the original.
- **Model Inversion**: White-box (or high-fidelity black-box) access enables reconstruction of representative training inputs.
- **Membership Inference**: The attacker can test whether a specific record was in the training set—a direct privacy leak.
- **Confidentiality Collapse**: Once the artifact leaks, every secret embedded in the weights (and any watermark that was not designed to survive) is exposed to inspection.

## Technical Context

### Common Model-Theft Scenarios

#### 1. Query-Based Extraction (label-only)

```python
for x in synthetic_or_public_inputs:
    y = target_api.predict(x)          # top-1 label only
    dataset.append((x, y))
substitute = train(dataset)            # imitates the boundary from labels alone
```

**Risk**: Even without confidence scores, enough labelled queries recover a usable copy of the decision boundary.

#### 2. Confidence / Logit-Based Distillation

```python
y = target_api.predict(x)              # returns full probability vector / logits
# soft labels carry MUCH more information per query than a hard label
substitute = distill(x, soft_labels=y) # knowledge distillation from the victim
```

**Risk**: Rich outputs (probabilities, logits, embeddings) dramatically raise fidelity per query and cut the number of queries needed.

#### 3. Artifact Exfiltration from Insecure Storage

```http
GET https://models-prod.s3.amazonaws.com/         # public bucket lists objects
GET https://registry.internal/v2/model/blob/sha256:...   # unauthenticated pull
GET https://host/static/models/model.onnx        # weights served as a static file
```

**Risk**: A single permissive bucket policy, open model registry, or misplaced static route hands over the entire white-box model.

#### 4. On-Device / Mobile Model Extraction

```bash
unzip app.apk && find . -name '*.tflite' -o -name '*.mlmodel'
# model ships inside the app package; the artifact is on the attacker's device
```

**Risk**: Any model bundled with distributed software is physically in the hands of every user, including adversarial ones.

#### 5. Insider Exfiltration

```bash
scp training-host:/checkpoints/model-final.pt  ./     # authorised access, unauthorised copy
```

**Risk**: Staff, contractors, or a compromised CI/CD pipeline copy the checkpoint out of an otherwise well-guarded training environment.

### Where the Model (and Its Behaviour) Leaks

| Surface | Typical Theft Path | Result |
|---------|--------------------|--------|
| Prediction API | High-volume querying, confidence harvesting | Substitute / distilled clone |
| Object storage | Public or over-permissive bucket | Byte-for-byte weights |
| Model registry / artifact store | No authentication, anonymous pull | Full checkpoint |
| Source repository | Weights committed, repo made public | Full checkpoint + config |
| Mobile / edge binary | Unpack the shipped app/firmware | On-device model file |
| Insider / pipeline | Authorised access, unauthorised copy | Full checkpoint |

## Real-World Impact

The examples below are described as **incident classes**—recurring, well-documented patterns—rather than as specific named breaches, so no figures are invented.

### Case Class 1: Academic and Industry Model-Extraction Research

**Pattern**:
- Researchers have repeatedly demonstrated that commercial "prediction-as-a-service" models can be approximated by training a substitute on the API's own responses.
- Both label-only and confidence-based variants have been shown across classifiers, and against modern models the same idea underpins unauthorised distillation.

**Impact**: Establishes that a queryable model is, in principle, extractable—the defensive question is cost, not possibility.

**Root Cause**: The prediction interface returns more information (especially confidences/logits) than is strictly needed, with no limit on systematic probing.

### Case Class 2: Exposed Model Artifacts in Public Storage and Repositories

**Pattern**:
- Trained weights are placed in object storage, model registries, or git repositories that are later made public or left with over-broad read permissions.
- Automated scanners that hunt for exposed buckets and secrets also surface large model files.

**Impact**: Direct, white-box theft of the artifact with no interaction with the running service.

**Root Cause**: The same storage-misconfiguration and secret-in-repo patterns that leak data also leak models, because weights are frequently treated as ordinary large files.

### Case Class 3: Models Extracted from Distributed Applications

**Pattern**:
- Mobile apps and edge/IoT devices ship an on-device model for offline inference.
- Because the artifact is embedded in the distributed package, anyone can unpack it and recover the model file, sometimes only lightly obfuscated.

**Impact**: The model is effectively public the moment the application is released; obscurity is not protection.

**Root Cause**: On-device deployment places the artifact in an untrusted environment by design, so shipping it unprotected exposes it.

## Prevalence and Statistics

Model Theft appears in the **OWASP Machine Learning Security Top 10 as ML05**. Its prevalence tracks two independent trends: the growth of paid prediction APIs (which expands the extraction surface) and the spread of on-device/edge ML (which expands the exfiltration surface).

Rather than cite precise figures (which vary widely and age quickly), the defensible picture is:

- Extraction feasibility is **well established in the literature**; the practical barrier is the query budget, which output granularity and rate limiting directly control.
- Artifact exfiltration rides on the **same misconfiguration classes** (public buckets, open registries, secrets in repos) that are among the most commonly reported cloud issues.
- Impact ranges from **competitive/IP loss** up to **enabling white-box adversarial and privacy attacks** against the still-deployed original.

> Note: exact extraction query counts and fidelity numbers depend heavily on the model, the output granularity, and the attacker's budget. Treat any single figure as illustrative; the durable takeaway is that richer outputs and unlimited querying make theft cheaper.

## Common Misunderstandings

### Myth 1: "If we never expose the weights, the model is safe"

**Reality**: Extraction never needs the weights. A model that only ever answers queries can still be cloned from its responses; hiding the file addresses only one of the two routes.

### Myth 2: "Returning confidence scores is harmless—they're just numbers"

**Reality**: Confidences and logits are the single biggest accelerant of extraction. Soft labels carry far more information per query than a hard label, slashing the queries an attacker needs.

### Myth 3: "Our model is too big to steal"

**Reality**: Attackers rarely need an exact copy. A smaller distilled substitute that matches the boundary "well enough" is sufficient to compete, to craft transferable attacks, or to bypass a filter.

### Myth 4: "On-device models are protected by the app"

**Reality**: Anything shipped to a user's device is in an untrusted environment. Packaging and light obfuscation slow, but do not stop, extraction of the artifact.

### Myth 5: "A watermark stops theft"

**Reality**: Watermarking and fingerprinting help you *prove ownership after the fact* and support legal action; they do not prevent the copy from being made or used.

### Myth 6: "Rate limiting the API is enough"

**Reality**: Rate limits raise the cost of extraction but a patient, distributed attacker can stay under thresholds. Limits must be combined with authentication, reduced output granularity, and extraction detection.

## How Model Theft Differs from Related Issues

| Aspect | ML05 Model Theft | LLM10 (LLM extraction angle) | ML02 Data Poisoning |
|--------|------------------|------------------------------|---------------------|
| **Attacker goal** | Obtain a functional copy of the model | Extract model behaviour, system prompt, or training data from an LLM | Corrupt training data to change behaviour |
| **Primary route** | Query-based extraction or artifact exfiltration | Crafted prompting / repeated querying of a generative model | Tampering with the training pipeline |
| **Asset at risk** | Weights and decision boundary (IP) | Prompt, behaviour, memorised text | Model integrity |
| **Typical defence** | AuthN/Z, rate limits, output perturbation, artifact protection, watermarking | Output filtering, prompt isolation, rate limits | Data provenance and validation |

ML05 is the classical-ML framing: the target is usually a discriminative model behind an API or a shipped artifact, and the prize is the model's IP and its exploitable white-box form. LLM10 addresses the generative-model version of "extraction," where prompting can leak behaviour, the system prompt, or memorised training text. The two overlap in spirit but differ in target, technique, and defence.

## Key Takeaways

1. **Two routes, one outcome**—behaviour can be cloned by querying (extraction) or the artifact can be stolen outright (exfiltration); defend both.
2. **Your API is a labelling service for the thief**—every rich response lowers the cost of cloning your model.
3. **A stolen model upgrades the attacker to white-box**—enabling transferable adversarial, inversion, and membership-inference attacks against the original.
4. **Shipped models are exposed models**—on-device and edge artifacts live in untrusted environments and must be protected accordingly.
5. **Watermarking is for attribution, not prevention**—pair it with access control, output limits, and monitoring.

## How to Identify if You're Vulnerable

- [ ] Does the inference API require authentication and per-client authorisation?
- [ ] Are there per-client rate limits and query quotas, not just a global limit?
- [ ] Does the API return full probability vectors or logits when a top-1 label (or rounded score) would do?
- [ ] Is there any detection for systematic, boundary-probing, or high-volume querying patterns?
- [ ] Are model artifacts stored with encryption and strict, least-privilege access (never a public bucket)?
- [ ] Are model registries and artifact stores authenticated, with no anonymous pulls?
- [ ] Have you confirmed no weights or checkpoints are committed to any repository that could become public?
- [ ] Are on-device/edge models protected (encrypted at rest, obfuscated, integrity-checked) rather than shipped in the clear?
- [ ] Is the model watermarked or fingerprinted so a leaked copy can be attributed?
- [ ] Do usage terms and contracts explicitly prohibit extraction and redistribution?

If you answered "no" or "not sure" to several of these, your model is likely extractable or exfiltratable today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers extract and exfiltrate models
- **[Prevention](prevention.md)**: Build a layered defence for the API and the artifact
- **[Examples](examples.md)**: Insecure vs. secure inference APIs and model storage in Python
- **[ML Security Learning Path](/learn/ml)**: Continue with the rest of the OWASP ML Top 10
- **[Practice](/practice)**: Apply these defences in hands-on exercises
