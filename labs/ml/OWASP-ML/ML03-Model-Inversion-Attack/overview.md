# ML03: Model Inversion Attack - Overview

## Table of Contents
- [What is a Model Inversion Attack?](#what-is-a-model-inversion-attack)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Considerations](#prevalence-and-considerations)
- [Common Misunderstandings](#common-misunderstandings)

## What is a Model Inversion Attack?

**Model Inversion** is an attack in which an adversary with *query access* to a trained machine-learning model reconstructs sensitive information about the data the model was trained on—or infers a private attribute of a known individual—by exploiting what the model reveals in its outputs. The richer the output (full confidence vectors, logits, embeddings, or gradients), the more the model leaks.

Where a legitimate user sends an input and reads a prediction, a model-inversion attacker runs the model *backwards*: starting from an output they care about (say, the class label "Alice"), they search the input space for the input that best produces that output. Because the model has learned to respond most strongly to inputs that resemble its training data, the reconstructed input often resembles a real training example—a recognizable face, a characteristic record, a class-representative sample.

### Core Concept

```
Normal use:       input  ->  model  ->  prediction (+ confidence)

Model inversion:  target output  ->  optimise / hill-climb the input
                                  ->  an input the model "recognises"
                                        ≈ sensitive training data
```

The attack works because confidence scores act as a *gradient of recognisability*: the model returns higher confidence as a candidate input moves closer to what it memorised for that class. Queried repeatedly, that signal is enough to climb toward a reconstruction—no access to the original data required.

### Two Faces of the Attack

- **Data reconstruction**: approximate an actual training input—for example, recovering a recognizable face from a face-recognition model, or a class-representative image that exposes what a class "looks like."
- **Attribute inference**: recover a hidden sensitive attribute of a *known* individual—for example, inferring a medical value, genotype, or demographic feature from the model's response to the individual's partially known record.

### Why It's Critical for ML Systems

- Models are increasingly trained on **sensitive, regulated data**—faces, medical records, genetic markers, financial history.
- Prediction APIs are **exposed to the public or to large partner sets**, giving attackers cheap, repeatable query access.
- Rich outputs (**full softmax vectors, logits, embeddings**) are handed out by default because they are convenient for legitimate clients—and they are exactly the side channel inversion exploits.
- **Overfit and small-data models memorise individuals**, so the very models most likely to be built on scarce sensitive data are the ones that leak the most.

## Why Does This Matter?

### Business Impact

- **Privacy breach of training subjects**: reconstruction of faces or records exposes people who never consented to being individually retrievable from a shipped model.
- **Regulatory exposure**: reconstructing PII, PHI, or biometric data implicates GDPR, HIPAA, and biometric-privacy laws (for example BIPA), triggering breach-notification duties and fines.
- **Loss of trust and IP value**: a model marketed as "privacy-preserving" that demonstrably leaks its training data is a reputational and contractual failure.
- **Biometric permanence**: a leaked password can be rotated; a reconstructed face or fingerprint template cannot be reissued.

### Technical Impact

- **Training-data reconstruction**: class-representative or near-verbatim inputs recovered directly from the model.
- **Sensitive-attribute inference**: hidden fields inferred for named individuals with high confidence.
- **Confidence-channel leakage**: full probability vectors and logits form the side channel that drives the reconstruction loop.
- **Gradient amplification**: white-box access to weights or gradients makes reconstruction dramatically more efficient and higher-fidelity.

## Technical Context

### 1. Confidence-Driven Reconstruction (Black-Box)

With nothing but the public prediction API, an attacker treats the returned confidence for a target label as an objective to maximise. Starting from noise (or an average image) they iteratively perturb the input, keep changes that raise the target confidence, and converge on an input the model strongly associates with that label. When each label corresponds to one person—as in face recognition—that reconstruction resembles that person.

```
target_label = "Alice"
x = random_noise()
repeat:
    conf = model_api(x)[target_label]     # only the confidence is needed
    x    = x + step * estimate_gradient(conf)   # numeric / query-based ascent
until conf is high
# x now resembles what the model memorised for "Alice"
```

### 2. Gradient-Based Inversion (White-Box)

If the attacker has the model's weights (a downloaded checkpoint, an on-device model, or a shared partner artefact), they compute exact gradients of the target class score with respect to the input and perform gradient *ascent* on the input—often combined with image priors or regularisers to produce natural-looking reconstructions. This is far more effective than black-box hill-climbing and needs far fewer iterations.

### 3. Attribute Inference

Here the attacker already knows a target individual's non-sensitive features and wants a hidden sensitive one. They evaluate the model over each possible value of the unknown attribute and pick the value that best matches the model's observed behaviour and known population statistics. The classic demonstration used a pharmacogenetic dosing model to infer a sensitive genetic marker from otherwise-known patient data.

### 4. Class-Representative Synthesis

Activation-maximisation ("deep-dream"-style) optimisation produces an input that maximally activates a chosen class—effectively an *average* of that class as the model understands it. When a class corresponds to a single identity, that average is a portrait of a real person.

### 5. Memorisation Risk

Model inversion is fundamentally powered by **memorisation**. High-capacity networks trained on small, imbalanced, or under-regularised sensitive datasets memorise individual examples, and memorised examples are exactly what inversion recovers.

| Factor | Why it worsens leakage |
|--------|------------------------|
| Full confidence / logit output | Rich, continuous signal to hill-climb toward a reconstruction |
| White-box weight access | Exact gradients make optimisation fast and high-fidelity |
| Overfitting / low regularisation | Model memorises individual training examples verbatim |
| Small or imbalanced sensitive classes | One class effectively equals one person |
| Unlimited, unmonitored queries | Attacker can iterate thousands of times unnoticed |
| One-class-per-identity design (face ID) | A reconstruction is directly a real, nameable identity |

## Real-World Impact

Model inversion is best understood through the research that established the attack class, rather than through breach counts (there is no reliable public tally of production inversion incidents). The demonstrations below are documented academic results.

### Case Class 1: Facial Reconstruction from a Recognition Model (Fredrikson et al., 2015)

**Setup**:
- A neural-network face-recognition model that returns a confidence score per identity label.
- The attacker knows only a target person's *label* (name/class), not any image of them.

**Result**:
- By optimising an input to maximise the confidence for the target label, the researchers recovered a blurred but **recognizable** image of the individual—demonstrating that a shipped model can act as a lossy store of the faces it was trained on.

**Root Cause**: Rich confidence outputs plus a model that memorised per-identity appearance, with no privacy noise and no output limiting.

### Case Class 2: Sensitive-Attribute Inference in a Medical Model (Fredrikson et al., 2014)

**Setup**:
- A pharmacogenetic model predicting drug dosing from patient features, including a sensitive genetic marker.
- The attacker knows the patient's non-sensitive features and the model's output behaviour.

**Result**:
- The sensitive genetic attribute could be **inferred** with meaningful accuracy—showing that a model's responses leak private inputs, not just its predictions.

**Root Cause**: The model's confidence surface encoded the relationship between the hidden attribute and the outcome, and that surface was queryable.

> Note: These are research demonstrations that define the threat class. Treat them as evidence that the attack is real and reproducible—not as counts of production breaches, which are not reliably published.

## Prevalence and Considerations

Model inversion is a **privacy** risk that grows with three trends: models trained on sensitive data, prediction APIs exposed at scale, and rich outputs returned by default. A defensible summary:

- The risk is **highest for overfit models and small, sensitive datasets**, where memorisation of individuals is strongest.
- It is **worse when full confidence vectors, logits, or model weights are exposed**, and much reduced (though not eliminated) when outputs are coarse.
- It is a **research-forward threat**: reliable public counts of exploited production systems do not exist, so quantify your own exposure by testing rather than citing a single statistic.

### How Model Inversion Differs from Related ML Risks

| Aspect | Model Inversion (ML03) | Membership Inference (ML04) | Model Theft (ML05) |
|--------|------------------------|-----------------------------|--------------------|
| **Attacker's question** | What did the training data look like? / What is this person's hidden attribute? | Was *this exact record* in the training set? | Can I copy the model itself? |
| **What is exposed** | Reconstructed inputs or inferred private attributes | A yes/no membership signal about one record | A functional clone of the model |
| **Primary signal** | Confidence vectors / logits / gradients | Confidence or loss on the probe record | Input–output query pairs |
| **Harm** | Privacy of data subjects (reconstruction) | Privacy of data subjects (disclosure of participation) | Intellectual-property loss |

**Key distinction from ML04**: membership inference only asks *whether* a specific record was used in training; model inversion goes further and reconstructs or infers the *content* of the training data. They share the same confidence side channel, so defences overlap—but they are separate objectives.

## Common Misunderstandings

### Myth 1: "The attacker needs the training data to reconstruct it."

**Reality**: The entire point of inversion is that the attacker starts with *no* data—only a label and query access—and recovers an approximation of the data from the model's responses.

### Myth 2: "Black-box (API-only) access is safe."

**Reality**: Confidence outputs alone are sufficient for reconstruction and attribute inference. White-box access makes it easier, but it is not required.

### Myth 3: "We only return the top label, so we're fine."

**Reality**: Returning only the top-1 label meaningfully raises the cost of attack, but coarse or repeated signals—plus tie-breaking and boundary behaviour—still leak. Output limiting is one layer, not a complete defence.

### Myth 4: "It's the same as membership inference."

**Reality**: Membership inference (ML04) answers "was this record in training?"; inversion reconstructs or infers the *content* itself. Different goal, overlapping side channel.

### Myth 5: "Accuracy and privacy don't trade off."

**Reality**: On small sensitive datasets, the memorisation that helps accuracy is precisely what inversion exploits. Privacy defences such as differential privacy typically cost some utility; that trade-off must be managed deliberately.

### Myth 6: "TLS/encryption protects us."

**Reality**: Transport security is irrelevant here. The leak flows through the model's *legitimate* outputs to an authorised caller—encryption in transit does nothing to stop it.

## Key Takeaways

1. **Models can memorise their training data**, and inversion turns a prediction API into a lossy retrieval channel for that data.
2. **Confidence scores are the fuel**—the richer the output, the more the model leaks.
3. **Overfitting and small sensitive datasets are the biggest amplifiers** of reconstruction risk.
4. **White-box access is worse, but black-box is enough**—do not assume an API-only model is safe.
5. **This is a privacy problem with legal teeth**—PII, PHI, and biometric reconstruction trigger GDPR/HIPAA-class obligations.

## How to Identify if You're Vulnerable

- [ ] Does the prediction API return full confidence vectors or logits rather than a coarse label?
- [ ] Is the model trained on sensitive data (faces, health, genetics, finance) with one class per individual?
- [ ] Is the model overfit (large train/validation gap) or trained on a small, imbalanced dataset?
- [ ] Are model weights downloadable, on-device, or shared with partners (white-box exposure)?
- [ ] Are queries unlimited and unmonitored per client?
- [ ] Was the model trained without differential privacy or any memorisation control?
- [ ] Is there no auditing for reconstruction-style query patterns (many near-identical probes)?

If you answered "yes" or "not sure" to several of these, your model likely leaks training data through inversion today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers reconstruct data and infer attributes
- **[Prevention](prevention.md)**: Differential privacy, output limiting, and query monitoring
- **[Examples](examples.md)**: Insecure vs. secure model serving and training in Python
- **[ML Security Top 10](/learn/ml)**: Continue the machine-learning security track
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
