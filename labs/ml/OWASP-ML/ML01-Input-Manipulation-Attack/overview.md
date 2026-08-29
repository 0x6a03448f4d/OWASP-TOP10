# ML01: Input Manipulation Attack - Overview

## Table of Contents
- [What is an Input Manipulation Attack?](#what-is-an-input-manipulation-attack)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Threat Models: White-Box, Black-Box, Physical](#threat-models-white-box-black-box-physical)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Research Landscape](#prevalence-and-research-landscape)
- [Common Misunderstandings](#common-misunderstandings)

## What is an Input Manipulation Attack?

**Input Manipulation Attack** (ML01 in the OWASP Machine Learning Security Top 10) is the deliberate crafting of model inputs—most often through small, carefully chosen perturbations—so that a trained model produces a *wrong* output at inference time. These crafted inputs are called **adversarial examples**, and using them to slip past a model is called an **evasion attack**.

The defining property is that the perturbation is *optimised against the model*, not random noise. A spam email rewritten to keep its meaning but flip the classifier's decision, a stop sign with a few stickers that a vision model reads as "speed limit," an audio clip that sounds normal to a human but transcribes to an attacker's command—all are the same underlying attack: exploit the gap between the function the model actually learned and the function a human would apply.

> **Scope note:** ML01 is a *classic machine-learning* vulnerability—it applies to image classifiers, audio models, tabular fraud detectors, malware classifiers, and traditional NLP models. It is distinct from the LLM-specific "prompt injection" category in the OWASP Top 10 for Large Language Model Applications. Prompt injection manipulates instructions in natural-language context; ML01 manipulates the numeric feature space a model scores.

### Core Concept

A classifier `f` maps an input `x` to a label. An attacker searches for a small perturbation `δ` such that `x + δ` looks essentially unchanged to a human (or a downstream check) but is classified differently by the model:

```
Goal (untargeted):   find small δ   s.t.  f(x + δ) ≠ f(x)
Goal (targeted):     find small δ   s.t.  f(x + δ) = t   (attacker-chosen t)

Constraint:          ||δ||  ≤  ε        # perturbation budget
                     x + δ   stays valid       # e.g. pixels in [0,1]

Legend:
  x   -> the original, correctly-classified input
  δ   -> the adversarial perturbation being optimised
  ε   -> how much change is "allowed" (often imperceptible)
  t   -> the label the attacker wants the model to output
```

The perturbation budget is usually measured with an **L_p norm**: L∞ (no single feature moves more than ε), L2 (total Euclidean change is small), or L0 (only a few features change at all). Different attacks optimise different norms, and a defense tuned for one norm rarely covers the others.

### Why Models Are Vulnerable

Adversarial examples are not a bug in one library—they arise from how high-dimensional models learn:

- **Locally near-linear behaviour.** Even "deep" networks behave approximately linearly over small regions. In a high-dimensional input, thousands of tiny, aligned nudges sum into a large change in the model's score while each individual nudge stays invisible.
- **Decision boundaries sit close to real data.** The model draws boundaries that separate the training distribution, but those boundaries often pass surprisingly close to normal inputs, so a short step crosses them.
- **Non-robust features.** Models latch onto predictive-but-fragile patterns (fine textures, high-frequency detail) that a human ignores. Perturbing exactly those features flips the prediction without changing what a human perceives.
- **Transferability.** Different models trained on similar data tend to share these weaknesses, so an adversarial example built against one model frequently fools another—which is what makes black-box attacks practical.

## Why Does This Matter?

ML models increasingly sit on the security- and safety-critical path: they decide what is spam, what is malware, whose transaction is fraud, what a self-driving car sees, and who is who at a biometric gate. An input-manipulation attack turns each of those decisions into something an adversary can steer.

### Business Impact

- **Security-control bypass.** Spam, phishing, malware, fraud, and content-moderation filters are all classifiers. Evasion lets malicious content sail through the exact control bought to stop it.
- **Fraud and financial loss.** A transaction nudged to look "normal" to a fraud model, or a document altered to pass automated review, translates directly into money lost.
- **Safety failures.** In perception systems (autonomous driving, industrial vision, medical imaging), a misclassification is not just a wrong label—it can be a physical hazard.
- **Identity and access abuse.** Fooled face/voice biometrics grant an attacker someone else's access.
- **Reputation and trust.** A model that can be reliably tricked erodes user and regulator confidence in the whole product.

### Technical Impact

- **Integrity loss at inference.** The model's output can no longer be trusted for inputs an adversary may have touched.
- **Silent failure.** Unlike a crash, a misclassification looks like a normal, confident prediction—often with *high* confidence—so it passes unnoticed.
- **Automation at scale.** Once an attack recipe works, it can be applied to thousands of inputs cheaply.
- **Cross-domain reach.** The same idea applies to images, audio, text, network traffic, and executables—anywhere a model scores inputs.

## Technical Context

### The Attack Surface: Where Manipulation Happens

ML01 targets the **inference-time** input path. It does not require access to training data or model weights to be dangerous (though such access makes it easier). The adversary controls, wholly or partly, the input the model will score:

```
[ attacker-influenced input ]
        |
        v
  feature extraction / preprocessing   <- resize, normalise, tokenise, decode
        |
        v
       model f(.)                       <- the function under attack
        |
        v
  decision + confidence                 <- what a downstream system trusts
        |
        v
  action (allow / block / label / steer)
```

Two things matter here. First, **preprocessing is part of the model** from the attacker's view—an attack must survive resizing, JPEG compression, or tokenisation to work end-to-end. Second, the **decision and its confidence feed a downstream action**, so flipping the decision (or just inflating confidence) is enough to cause harm.

### Adversarial Examples vs. Ordinary Errors

| Aspect | Ordinary misclassification | Adversarial example (ML01) |
|--------|----------------------------|----------------------------|
| Cause | Hard/ambiguous input, distribution shift | Input optimised to defeat the model |
| Human perception | Often also hard for a human | Looks correct/benign to a human |
| Frequency | Follows the natural error rate | Produced on demand by an adversary |
| Confidence | Usually lower near the boundary | Frequently high, by construction |
| Fix | More/better data, better model | Requires robustness, not just accuracy |

The last row is the key insight: **accuracy and robustness are different goals.** A model can be 99% accurate on clean data and still be trivially evadable, because standard training optimises average-case performance, not worst-case performance under an adversary.

### The Perturbation Budget and Threat Assumptions

Every meaningful claim about adversarial robustness is stated *relative to a threat model*: what the attacker can change, by how much, and with what knowledge. Common budgets:

- **L∞ budget** (e.g. each pixel may move by up to 8/255): the classic "imperceptible noise" setting.
- **L2 budget**: small total distortion, allowing slightly larger changes concentrated where they help.
- **L0 / sparse**: change only a handful of features—a few pixels, a few tokens, one packet field.
- **Semantic / physical constraints**: the change must remain a valid, realisable object—a printable patch, a still-runnable executable, a still-readable email.

## Threat Models: White-Box, Black-Box, Physical

### White-Box (Gradient) Access
The attacker knows the model architecture and weights and can compute gradients of the loss with respect to the input. This is the strongest attacker and the setting in which the canonical attacks—**FGSM, PGD, C&W, DeepFool**—are defined. White-box results set the *worst case* and are the honest way to evaluate a defense.

### Black-Box (Transfer and Query) Access
The attacker cannot see the weights but can either (a) craft examples on a *substitute* model and rely on transferability, or (b) *query* the target and use the returned labels/scores to estimate gradients or run a search. Black-box attacks are the realistic setting for a hosted API and are the reason "we don't expose our model" is not, by itself, a defense.

### Physical / Real-World
The perturbation is applied to a physical object—a printed **adversarial patch**, a sticker, an eyeglass frame, a T-shirt pattern—and must survive being photographed under varying angle, lighting, and distance. Physical attacks are less precise than digital ones but far more alarming because they attack deployed perception systems from the outside.

### Cross-Domain Reach

| Domain | What is perturbed | Illustrative effect |
|--------|-------------------|---------------------|
| Images | Pixel values, printed patches | Object misread; classifier bypassed |
| Audio / speech | Waveform samples | Human hears X, model transcribes Y |
| Text / NLP | Synonyms, typos, homoglyphs, spacing | Sentiment/toxicity/spam label flipped |
| Malware | Padding bytes, benign sections/imports | Malicious binary scored as benign |
| Tabular / fraud | Feature values within valid ranges | Fraudulent record scored as normal |
| Network IDS | Packet timing, sizes, flags | Intrusion traffic evades detection |

## Real-World Impact

The examples below describe well-established *classes* of demonstrated attack from the security and ML research literature. They are stated as categories rather than as specific vendor incidents, and no numeric breach statistics are invented.

### Case Study Class 1: Road-Sign and Perception Evasion
**Setup**: Vision classifiers used for traffic-sign recognition are trained on clean sign images.
- **Attack**: Researchers demonstrated that small physical stickers or printed patches placed on a stop sign can cause a classifier to read it as a different sign, and that the effect persists across viewing angles and distances.
- **Impact class**: A perception system in a vehicle or robot can be made to misread its environment by an attacker who only needs physical access to the object, not to the model.
- **Lesson**: Robustness must hold under real-world capture conditions, not just on clean digital inputs.

### Case Study Class 2: Malware and Spam/Phishing Filter Evasion
**Setup**: A classifier decides whether a file is malware or an email is spam/phishing.
- **Attack**: Adversaries append benign-looking bytes, add unused imports or sections to a binary, or rewrite an email with synonyms and structural changes—preserving malicious/undesired function while pushing the model's score across the benign threshold.
- **Impact class**: The security control is bypassed silently; the payload is delivered while the model reports "clean."
- **Lesson**: When the classifier *is* the security boundary, its worst-case behaviour, not its average accuracy, is what matters.

### Case Study Class 3: Audio and Speech Command Injection
**Setup**: A speech-to-text or voice-command model transcribes audio into actions.
- **Attack**: Researchers showed audio that sounds like normal speech (or even like unrelated sound) to a human but transcribes to an attacker-chosen command for the model.
- **Impact class**: Voice-controlled systems can be issued commands their operator never intended and cannot hear.
- **Lesson**: Perceptual similarity to a human is not the same as similarity to the model.

### Case Study Class 4: Face and Biometric Spoofing
**Setup**: A face-recognition or liveness model gates access or identity.
- **Attack**: Printed patterns, patterned eyeglass frames, or crafted images cause the model to fail to recognise a person or to misidentify one person as another.
- **Impact class**: Evasion of surveillance or impersonation for access—an integrity failure of an identity control.

## Prevalence and Research Landscape

Adversarial examples are one of the most heavily studied problems in ML security. Rather than cite a single headline number (which varies by benchmark and year), the durable, defensible picture is:

- Standard, undefended models are **reliably evadable** under white-box attack—small L_p-bounded perturbations flip predictions with very high success rates on common image benchmarks.
- Robustness has proven **hard to achieve**: many proposed defenses were later broken when evaluated against *adaptive* attackers that target the defense itself.
- **Adversarial training** (training on adversarial examples) is the most consistently effective empirical defense, but it costs accuracy on clean data and compute, and its robustness is bounded by the threat model it was trained against.
- **Certified defenses** give provable guarantees but only within a limited perturbation radius and often at a further accuracy cost.

> Treat any single "attack success rate" or "robust accuracy" figure as illustrative and tied to a specific model, dataset, and budget. The stable takeaways are: undefended models are easy to evade, robustness is a real and separate engineering goal, and any defense claim is only meaningful against a stated, adaptive threat model.

## Common Misunderstandings

### Myth 1: "Our model is 99% accurate, so it's safe."
**Reality**: Accuracy measures average-case performance on natural data. Adversarial robustness measures worst-case performance under an attacker. A model can be highly accurate and still be flipped by a perturbation you cannot see.

### Myth 2: "We don't expose the model, so attackers can't craft adversarial examples."
**Reality**: Black-box transfer and query attacks routinely defeat models the attacker never sees the weights of. Secrecy raises the cost of an attack; it does not remove the vulnerability.

### Myth 3: "We hide gradients / add randomness, so gradient attacks fail."
**Reality**: **Gradient masking is false security.** Obfuscated or shattered gradients are repeatedly bypassed by adaptive attacks (gradient approximation, expectation-over-transformation, transfer). A defense that only makes gradients hard to read has usually not made the model robust.

### Myth 4: "The perturbation is tiny, so the impact is tiny."
**Reality**: The size of the perturbation and the size of the consequence are unrelated. An imperceptible change can flip a fraud decision, a malware verdict, or a stop-sign reading.

### Myth 5: "Input validation for injection/XSS also stops this."
**Reality**: Classic input validation checks for malformed or dangerous *syntax*. Adversarial inputs are perfectly well-formed and valid—a normal image, a normal email, a normal transaction. They defeat the model's semantics, not its parser.

### Myth 6: "One defense will fix it."
**Reality**: There is no single silver bullet. Robustness comes from layering—adversarial training, input transformations and detection, ensembling, limiting exposed confidence/gradients, monitoring, and human review for high-stakes decisions.

## How ML01 Differs from Related ML Risks

| Aspect | ML01 Input Manipulation | Data Poisoning | Model Extraction & Inversion |
|--------|-------------------------|----------------|------------------------------|
| **When** | Inference time | Training time | Inference-time querying |
| **Goal** | Force a wrong output now | Corrupt what the model learns | Steal the model or its data |
| **Attacker touches** | The input being scored | The training set | The prediction API |
| **Primary defense** | Robustness + detection | Data provenance/sanitisation | Rate limits, output minimisation |

## Key Takeaways

1. **Adversarial examples exploit the gap** between what the model learned and what a human means—small, optimised, often invisible perturbations flip predictions.
2. **Accuracy is not robustness.** Worst-case behaviour under an adversary is a separate goal that standard training does not deliver.
3. **Secrecy is not a defense.** Black-box transfer and query attacks work without the weights.
4. **Gradient masking is false security.** Evaluate against adaptive attackers or you are measuring nothing.
5. **It is cross-domain and can be physical.** Images, audio, text, malware, and tabular data are all in scope, and printed patches attack real perception systems.

## How to Identify if You're Exposed

- [ ] Does a wrong model decision cause security, safety, or financial harm (is the model a control on a critical path)?
- [ ] Can an attacker influence, wholly or partly, the input the model scores?
- [ ] Has the model ever been evaluated against a real adversarial attack (FGSM/PGD/C&W), not just clean accuracy?
- [ ] Do you rely on model secrecy or gradient hiding as your main defense?
- [ ] Do you expose raw confidence scores or logits that make query attacks easier?
- [ ] Is there any detection or monitoring for anomalous / adversarial inputs?
- [ ] Are high-stakes automated decisions ever routed to human review?

If you answered "no" or "not sure" to several of these—especially the first three—you likely have exploitable exposure to input-manipulation attacks today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: The concrete attack patterns—FGSM, PGD, C&W, DeepFool, transfer, query, and physical patches
- **[Prevention](prevention.md)**: Layered defenses—adversarial training, preprocessing, detection, certified robustness, and monitoring
- **[Examples](examples.md)**: Insecure vs. secure code in PyTorch, TensorFlow, scikit-learn, and adversarial-robustness libraries
- **[Back to the ML Security track](/learn/ml)**
- **[Practice](/practice)**: Apply these concepts hands-on
