# ML04: Membership Inference Attack - Overview

## Table of Contents
- [What is a Membership Inference Attack?](#what-is-a-membership-inference-attack)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [The Overfitting Link](#the-overfitting-link)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Research Landscape](#prevalence-and-research-landscape)
- [Common Misunderstandings](#common-misunderstandings)

## What is a Membership Inference Attack?

A **Membership Inference Attack (MIA)** is a privacy attack in which an adversary determines *whether a specific data record was part of the model's training set*. The attacker does not try to recover the record's contents—they already hold the record. What they learn is the single bit of information: **"was this exact example used to train the model?"**

That single bit is often the most sensitive fact of all. If a model was trained on the records of patients enrolled in an HIV study, an addiction-treatment cohort, or a cancer registry, then confirming that a person's record was in the training set reveals—by construction—that the person belongs to that sensitive population. The *membership* is the disclosure.

> **The core question of ML04:** Given a trained model (or just query access to it) and a candidate record, can an attacker decide with better-than-random confidence whether that record was in the training data? When the answer is yes and membership is sensitive, you have a privacy breach.

### Core Concept

```
Attacker holds:  one record  x  (e.g. a specific patient's data)
Attacker wants:  a single bit  ->  x IN training set?  or  x NOT in it?

Signal exploited:
  A model behaves DIFFERENTLY on data it was trained on (members)
  than on data it has never seen (non-members).

  Members     -> higher confidence, lower loss, correct more often,
                 sharper/more peaked output distribution
  Non-members -> lower confidence, higher loss, more uncertainty

Attack:
  Feed x to the model  ->  observe confidence / loss / label behaviour
  If the response looks "too confident / too correct"  ->  guess MEMBER
```

### Why It's Critical for Machine Learning Systems

Membership inference is dangerous precisely because it needs so little:

- It often works with **black-box query access only**—no weights, no gradients, just the prediction API that the model already exposes to make it useful.
- The leak is a **property of the trained model itself**, not of a coding bug. You cannot patch it with input validation; it is baked into what the model memorised.
- It targets **the training data**, which is frequently the most sensitive asset in the whole system—the health records, financial histories, or private messages the model learned from.
- Because the leak is statistical, it can be **silent**: a model can be accurate, useful, and quietly memorising individuals at the same time.

## Why Does This Matter?

### Business Impact

- **Privacy Violation**: Confirming membership in a sensitive-population dataset (a disease study, a mental-health service, a specific customer segment) directly discloses a private attribute about a real person.
- **Re-identification**: Membership signals combine with side information to link an ostensibly anonymised record back to an individual, defeating de-identification claims.
- **Regulatory Exposure**: Training data typically contains personal data protected by **GDPR** (and its concept of personal data / special-category data) and **HIPAA** (protected health information). A demonstrable membership leak is a confidentiality failure that can trigger notification duties, fines, and audits.
- **Loss of Trust and Data-Sharing Ability**: Organisations that promised participants "your data will only be used to train an aggregate model" break that promise if the model leaks who participated—undermining future consent and collaboration.
- **Competitive and Contractual Harm**: Membership tests can reveal which records a company holds (e.g. proving a firm's model was trained on a partner's confidential dataset), creating disputes and IP exposure.

### Technical Impact

- **Confidentiality Breach of the Training Set**: The boundary between "training data" and "everything else" is supposed to be secret; MIA erodes it.
- **Building Block for Stronger Attacks**: A reliable membership oracle is a stepping stone toward attribute inference and data-extraction attacks, and it helps an attacker calibrate model-inversion attempts.
- **Amplified by Overfitting**: Models that generalise poorly leak more, so the same flaw that hurts accuracy also hurts privacy.
- **Aggravated by Rich Outputs**: Returning full confidence vectors or raw logits gives the attacker a high-resolution signal; even label-only outputs can leak through decision-boundary probing.

## Technical Context

### The Signal: Members Look Different

Supervised models are trained by minimising a loss on the training examples. As a result, on a member the model has, in effect, "seen the answer" before—so it tends to assign that example lower loss, higher probability to the true class, and a sharper output distribution than it does to a comparable example it never saw.

```
Example: a classifier's probability for the TRUE label

  Member x_in   ->  softmax true-class prob  ~ 0.98   (loss ~ 0.02)
  Non-member x_out ->  softmax true-class prob ~ 0.71  (loss ~ 0.34)

An attacker who can see these numbers just needs a THRESHOLD:
  if true-class confidence > tau  ->  predict MEMBER
  else                           ->  predict NON-MEMBER
```

### Attack Families at a Glance

| Attack family | What the attacker needs | Core idea |
|---------------|-------------------------|-----------|
| Shadow-model attack | Ability to train "shadow" models on similar data | Imitate the target, learn what member vs non-member outputs look like, train an attack classifier |
| Confidence-threshold attack | Confidence scores from the target | High confidence on the true label -> likely member |
| Loss-threshold attack | Ability to compute per-example loss | Low loss -> likely member |
| Label-only attack | Only the predicted hard label | Probe robustness to perturbations; members sit further from the decision boundary |
| White-box attack | Weights, activations, gradients | Gradient norms and internal activations carry extra membership signal |

### The Shadow-Model Recipe (Shokri et al.)

The foundational black-box technique, introduced in the Shokri et al. membership-inference research, works like this:

```
1. Build shadow models
   - Train several models that MIMIC the target's task,
     on data drawn from a similar distribution.
   - Crucially, the attacker KNOWS each shadow model's own
     train/test split -> so they know ground-truth membership.

2. Generate an attack dataset
   - Query each shadow model with its members AND non-members.
   - Record (output confidence vector, true label, IN/OUT).

3. Train the attack model
   - A binary classifier: input = a model's output behaviour,
     label = was this example a member?  (IN vs OUT)

4. Attack the real target
   - Query the target with candidate record x.
   - Feed the target's output to the attack model -> MEMBER / NON-MEMBER.
```

The insight is that the attacker never needs the target's real training data or weights—they manufacture labelled membership examples locally with shadow models and transfer the learned distinguisher to the target.

### Distinguishing ML04 from ML03 (Model Inversion)

> **These are different attacks with different goals.** **ML03 Model Inversion** tries to *reconstruct* the contents of training data (e.g. regenerate a recognisable face or recover feature values). **ML04 Membership Inference** assumes the attacker *already has* the record and only wants to learn *whether it was in the training set*—a single membership bit, not the data itself.

| Aspect | ML03 Model Inversion | ML04 Membership Inference |
|--------|----------------------|---------------------------|
| Attacker's goal | Reconstruct / recover the data | Decide if a known record was a training member |
| Attacker already holds the record? | No—they want to derive it | Yes—they want the membership bit |
| Output of the attack | Approximate features / sample | One bit: IN vs OUT (with a confidence) |
| Privacy harm | Content disclosure | Participation disclosure |

## The Overfitting Link

Membership inference and **overfitting** are deeply connected. Overfitting is exactly the phenomenon of a model performing markedly better on its training data than on unseen data—which is the very gap an MIA measures.

```
Generalisation gap  =  (accuracy on training data) - (accuracy on test data)

  Small gap  ->  members and non-members look similar  ->  MIA is HARD
  Large gap  ->  members stand out sharply            ->  MIA is EASY
```

This link has two important consequences:

- **Good ML hygiene is also privacy hygiene.** The regularisation techniques that reduce overfitting (weight decay, dropout, early stopping, more/augmented data) also shrink the membership signal.
- **Overfitting is sufficient but not necessary.** Even well-generalised models can leak membership for outliers and rare records that the model had to memorise. Reducing overfitting lowers the risk substantially but does not, on its own, provide a formal privacy guarantee—that is what differential privacy is for.

## Real-World Impact

### Research Class 1: The Shokri et al. Membership-Inference Work

**What it demonstrated:**
- Membership inference was formalised as a practical black-box attack against classification models, including models served by real machine-learning-as-a-service platforms.
- Using only prediction outputs and the shadow-model technique, the research showed members could be distinguished from non-members at rates well above random guessing on common classification tasks.

**Why it matters:** It established that exposing a prediction API can itself leak information about the private training set, and it made explicit the overfitting–privacy connection that later defences target.

### Research Class 2: Confidence-Free and Label-Only Attacks

**What this class of research showed:**
- Follow-on work established that hiding confidence scores is not a sufficient defence: an attacker who sees *only the predicted label* can still infer membership by measuring how robust that prediction is to small input perturbations.
- Members tend to sit further from the decision boundary, so their labels are more stable under perturbation than non-members' labels.

**Why it matters:** It closed a tempting "just return labels" loophole and showed that output-restriction alone is a partial mitigation, not a cure.

### Research Class 3: The Privacy–Utility Tradeoff and Differential Privacy

**What this class established:**
- Differentially private training (notably **DP-SGD**) provides a mathematically grounded upper bound on how much any single record can influence the model—directly limiting membership inference.
- The protection is real but comes with a **privacy–utility tradeoff**: stronger privacy (smaller epsilon) costs accuracy, and a very loose epsilon may provide little practical protection.

**Why it matters:** It reframed the defence from "reduce overfitting and hope" to "train with a stated, auditable privacy budget."

> Note: the items above describe well-documented *classes* of published membership-inference research (the Shokri et al. line of work and its label-only and differential-privacy successors). Exact numbers vary by dataset, model, and paper; treat specific accuracy figures in any single source as illustrative rather than universal.

## Prevalence and Research Landscape

Membership inference is one of the most studied privacy attacks in machine learning, and it is a recognised category in the OWASP Machine Learning Security Top 10 (ML04). Rather than cite precise breach counts, the defensible picture is:

- MIA is **broadly applicable**: it has been demonstrated against classifiers, generative models, and large models across many domains.
- The attack is **cheap when outputs are rich**: black-box confidence access is often enough, and shadow models can be built from public or similar data.
- The risk is **concentrated where membership is sensitive**: health, finance, biometrics, legal, and any dataset defined by a stigmatised or regulated attribute.
- The strongest known defence with a formal guarantee is **differential privacy**; overfitting-reduction and output-limiting help but do not provide bounds.

## Common Misunderstandings

### Myth 1: "The attacker needs our model weights"

**Reality**: Many effective membership attacks are *black-box*—they use only the prediction API's outputs. White-box access makes attacks stronger, but is not required.

### Myth 2: "We anonymised the training data, so membership doesn't matter"

**Reality**: Membership inference is often the tool that *defeats* anonymisation. Confirming that a de-identified record was in a sensitive dataset re-attaches the sensitive attribute to the individual.

### Myth 3: "If we only return the label, we're safe"

**Reality**: Label-only attacks infer membership from how stable the label is under perturbation. Hiding confidences raises the cost but does not eliminate the leak.

### Myth 4: "Our model is accurate, so it isn't leaking"

**Reality**: Accuracy and privacy are separate axes. A model can be accurate *and* memorise outliers. In fact, a large gap between train and test accuracy is a red flag for exactly this leak.

### Myth 5: "Membership inference is the same as model inversion"

**Reality**: Inversion (ML03) reconstructs data; membership inference (ML04) decides whether a known record was in training. Different goals, different mitigations.

### Myth 6: "Adding a little noise makes us differentially private"

**Reality**: Differential privacy requires a principled mechanism (e.g. DP-SGD with gradient clipping and calibrated noise) and a *meaningful* epsilon. Ad-hoc noise without a tracked privacy budget provides no formal guarantee.

## How Membership Inference Differs from Related ML Risks

| Aspect | ML04 Membership Inference | ML03 Model Inversion | ML02/Data Poisoning |
|--------|---------------------------|----------------------|---------------------|
| **Attacker goal** | Is this record a training member? | Reconstruct training data | Corrupt the model via bad training data |
| **Direction** | Reads privacy out of the model | Reads data out of the model | Writes malicious behaviour in |
| **Primary harm** | Participation disclosure | Content disclosure | Integrity / availability |
| **Key defence** | Differential privacy, less overfitting | Limit outputs, DP | Data validation, provenance |

## Key Takeaways

1. **MIA leaks a single, potent bit**—was this record used to train the model?—and that bit is a privacy breach when membership is sensitive.
2. **The signal is behavioural**: models are more confident and lower-loss on members, which threshold and shadow-model attacks exploit with black-box access.
3. **Overfitting drives the leak**: the train/test gap is the very quantity an attacker measures, so reducing it reduces (but does not eliminate) risk.
4. **Differential privacy is the formal defence**—DP-SGD with a meaningful epsilon bounds any one record's influence.
5. **ML04 is not ML03**: membership inference infers participation; model inversion reconstructs content.

## How to Identify if You're at Risk

- [ ] Is *membership itself* sensitive for your training data (health, finance, biometrics, a stigmatised attribute)?
- [ ] Is there a large gap between training accuracy/loss and validation accuracy/loss (overfitting)?
- [ ] Does the prediction API return full confidence vectors or raw logits rather than coarse outputs?
- [ ] Can a client query the model freely, at scale, with no rate limiting or monitoring?
- [ ] Was the model trained *without* any differential-privacy mechanism or tracked epsilon?
- [ ] Are rare/outlier records present that the model may have memorised individually?
- [ ] Was any privacy auditing (a membership-inference red-team test) performed before release?
- [ ] Could an attacker plausibly assemble similar data to train shadow models?

If you answered "yes" or "not sure" to several of these, your model may be exposing training-set membership today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers infer membership in practice
- **[Prevention](prevention.md)**: Layered defences from overfitting reduction to differential privacy
- **[Examples](examples.md)**: Insecure vs. secure training and serving in Python
- **[ML Security Top 10](/learn/ml)**: Return to the full learning path
- **[Practice](/practice)**: Apply these concepts in hands-on challenges
