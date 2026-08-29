# ML08: Model Skewing - Overview

## Table of Contents
- [What is Model Skewing?](#what-is-model-skewing)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Research](#prevalence-and-research)
- [Common Misunderstandings](#common-misunderstandings)

## What is Model Skewing?

**Model Skewing** is an attack against a *deployed* model that keeps learning from production data. The attacker manipulates the model's **feedback loop**—the stream of clicks, ratings, reports, corrections, and labels that a continuously-learning system ingests—so that, retraining after retraining, the model's behaviour drifts ("skews") toward the attacker's goal. No single request is malicious in an obvious way; the harm is in the *aggregate signal* the attacker injects over time.

The target is specifically the class of systems that learn **online** or are **continuously retrained** from live traffic: spam and abuse classifiers that learn from user "report" and "not spam" buttons, fraud models tuned by analyst dispositions and chargeback outcomes, recommender and ranking systems shaped by engagement signals, and personalization engines that adapt to interaction history. Because these models are *designed* to change based on what users do, an attacker who can produce enough of the right user behaviour can steer the model itself.

### Core Concept

```
Healthy feedback loop:
  Users interact -> genuine, diverse signals
        -> validated & sampled labels
        -> retraining preserves intended behaviour
        -> decision boundary stays where it belongs

Skewing attack:
  Attacker floods crafted feedback (mass "not spam", fake engagement, Sybil votes)
        -> raw signals ingested without validation
        -> retraining shifts the decision boundary a little each cycle
        -> after many cycles the model allows what it used to block,
           or promotes what it used to bury
```

Model skewing is best understood as **poisoning of the operational feedback channel** rather than of a one-time training set. That distinction drives everything about how it is carried out and how it is defended.

### How It Differs from One-Shot Training Poisoning (ML02)

Classic data poisoning (ML02) assumes the attacker can taint the *training corpus* once, before or during a training run. Model skewing assumes something narrower but often more realistic: the attacker cannot touch the curated dataset, but they *can* generate production events, submit reports, create accounts, and click—and the system feeds those events straight back into training.

| Aspect | Data Poisoning (ML02) | Model Skewing (ML08) |
|--------|------------------------|----------------------|
| Target | The training dataset | The live feedback / retraining loop |
| When | Before/at training time | Continuously, post-deployment |
| Access needed | Write access to training data | Ability to produce production events/feedback |
| Shape of attack | Often a discrete injected batch | Sustained, gradual, distributed drift |
| Detection window | Dataset review before training | Requires ongoing drift/skew monitoring |

### Why Continuous-Learning Systems Are Exposed

Systems that retrain from production data concentrate several conditions that make skewing practical:

- They **treat user behaviour as ground truth**—a "report" button or a click is taken as a label, even though anyone can press it.
- They **retrain automatically** on a schedule, so unvalidated data reaches the model with no human in the path.
- They are **adversarially incentivised**: spammers, fraudsters, and sellers all profit from moving the boundary, so there is a permanent motivated adversary.
- They **reward patience**: a slow drift spread across many accounts and weeks looks like organic trend change, not an attack.

## Why Does This Matter?

### Business Impact

- **Security Controls Quietly Weaken**: A spam, abuse, or fraud classifier skewed toward "allow" lets malicious content and transactions through while still *appearing* to work.
- **Marketplace and Ranking Manipulation**: Coordinated feedback promotes an attacker's items, listings, or content and demotes competitors—monetising the model directly.
- **Targeted Degradation**: An attacker can skew the model to behave worse for a specific group, region, or competitor while leaving overall metrics healthy.
- **Erosion of Trust**: Once users notice spam getting through or recommendations being gamed, confidence in the platform—and the ML behind it—drops.
- **Expensive, Slow Recovery**: Because the poison is spread across many retraining cycles, rolling back means identifying and purging tainted feedback and retraining from a known-good baseline.

### Technical Impact

- **Decision-Boundary Shift**: Thresholds and boundaries move so that previously-blocked inputs are now accepted (or vice versa).
- **Label Distribution Poisoning**: The apparent base rate of a class is inflated or deflated by fake labels, biasing every downstream estimate.
- **Feature-Signal Corruption**: Engagement or reputation features are pumped with synthetic activity, so the model learns attacker-controlled correlations.
- **Concept-Drift Masking**: Slow, deliberate skew is indistinguishable from legitimate drift unless the system monitors for it specifically.
- **Feedback Amplification**: A slightly skewed model changes what it shows users, which changes their behaviour, which reinforces the skew—a self-fuelling loop.

## Technical Context

### Common Skewing Scenarios

#### 1. Mass False Reports Against a Classifier

```
Goal: lower the effective spam/abuse threshold so attacker content passes.

for account in sybil_accounts:            # many controlled accounts
    submit_feedback(attacker_message, label="not_spam")
# Nightly retraining ingests thousands of "not_spam" votes for
# messages that ARE spam -> the model's boundary drifts toward "allow".
```

**Risk**: The classifier is trained to treat the attacker's content style as benign. The same technique in reverse (mass "spam"/"abuse" reports on a victim) skews the model into *blocking* a legitimate target.

#### 2. Gaming Recommender / Ranking Signals

```
Goal: promote an item by manufacturing "engagement".

- Coordinated accounts view, click, dwell on, and "like" the target item
- Genuine competing items are systematically ignored or down-voted
- The ranker learns: this item = high engagement = rank it higher
```

**Risk**: The ranking model is skewed to surface attacker-chosen content, extracting real distribution and revenue from a manipulated signal.

#### 3. Auto-Retraining on Unvalidated Production Data

```python
# Anti-pattern: production events become training labels with no checks
events = collect_production_feedback()     # raw clicks, reports, ratings
model = retrain(model, events)             # no validation, no sampling cap
deploy(model)                              # straight to production nightly
```

**Risk**: There is no gate between "a user did something" and "the model believes it". Any party that can generate events can move the model.

#### 4. Sybil / Coordinated Amplification

```
1 account  -> negligible influence, easily outweighed
10,000 accounts acting in concert -> a dominant slice of the day's feedback
        -> the "majority" the model learns from is attacker-controlled
```

**Risk**: Influence scales with the number of controllable identities. Cheap account creation turns a lone attacker into a synthetic majority.

#### 5. Slow, Gradual Drift to Evade Detection

```
Week 1: push the boundary 1% toward "allow"
Week 2: push another 1% from the new baseline
...
Week N: cumulative shift is large, but each step looks like normal drift
```

**Risk**: Any monitoring that only compares "today vs. yesterday" never fires; the attack hides inside the tolerance for organic change.

### Systems Most at Risk

| System | Feedback Signal Abused | Attacker Goal |
|--------|------------------------|---------------|
| Spam / abuse classifier | "report" / "not spam" buttons | Lower threshold so their content passes |
| Fraud / risk model | Dispositions, chargebacks, "trust" signals | Get fraudulent transactions scored as safe |
| Recommender / ranking | Clicks, dwell, likes, add-to-cart | Promote own items, bury competitors |
| Personalization | Interaction / browsing history | Steer served content toward a payload |
| Reputation / review scoring | Up/down votes, review text | Inflate own or deflate a rival's score |

## Real-World Impact

To avoid fabricated specifics, the cases below are described as well-established **classes** of incident that are widely documented in security and platform-integrity literature, without inventing CVE numbers or precise figures.

### Case Class 1: Feedback Manipulation of Spam / Abuse Classifiers

**Pattern**:
- Spam filters that learn from user "this is / is not spam" actions have long been targets of coordinated mislabelling.
- Attackers submit large volumes of "not spam" feedback for their own messages, or mass-report legitimate senders as spam, to move the learned boundary.

**Impact**: Over successive retraining cycles the filter is nudged to pass attacker mail or to suppress a targeted sender, without any single report looking abusive.

**Root Cause**: User feedback treated as trustworthy ground truth and fed into retraining without provenance checks, per-source influence caps, or skew monitoring.

### Case Class 2: Coordinated Review and Ranking Manipulation

**Pattern**:
- Marketplaces, app stores, and content platforms repeatedly face rings of coordinated accounts that inflate engagement or reviews for chosen items and depress rivals.
- The ranking or recommendation model, learning from that engagement, promotes the manipulated items.

**Impact**: Attacker-selected listings, apps, or content gain visibility they did not earn, converting fake signals into real traffic and revenue and displacing legitimate results.

**Root Cause**: Engagement signals accepted as honest quality labels, with weak Sybil/coordination detection and no shadow evaluation before the skewed ranker is promoted.

### Case Class 3: "Learn-From-the-Public" Systems Steered by Coordinated Input

**Pattern**:
- Systems that adapt in near real time from open public interaction have been driven off-course by groups feeding them coordinated, crafted input.
- Because the system weighted recent public feedback heavily and validated it lightly, a motivated crowd could shift its behaviour quickly.

**Impact**: The deployed model's outputs shifted toward what the coordinated group supplied, demonstrating how directly an unguarded learning loop can be steered.

**Root Cause**: Continuous learning from unvetted public input with no rate limiting of influence, no anomaly detection on the feedback stream, and no human approval before adaptation took effect.

## Prevalence and Research

Model skewing sits at the intersection of **adversarial machine learning** and **platform integrity / anti-abuse**, and it is a recognised category in the OWASP Machine Learning Security Top 10. Rather than cite precise counts, the defensible picture is:

- Any system that **retrains from production feedback** has a skewing attack surface; the more directly user actions become labels, the larger it is.
- The dominant real-world variants are **coordinated/Sybil feedback** against classifiers and **engagement manipulation** against rankers and reviews—both are everyday problems for large platforms.
- Impact ranges from **moderate** (some spam slips through, some rankings gamed) to **severe** (a security control effectively disabled, or a marketplace systematically manipulated).

> Note: exact percentages and incident counts vary by platform and are rarely disclosed. Treat any single figure as illustrative; the durable takeaway is that feedback loops are a standing, actively-exploited attack surface whenever they drive retraining.

## Common Misunderstandings

### Myth 1: "Our training data is locked down, so we can't be poisoned"

**Reality**: Skewing does not touch your curated dataset. It poisons the *feedback stream* you willingly collect from production. If user actions become labels, the loop is the attack surface—dataset access is irrelevant.

### Myth 2: "One user can't move a model trained on millions of events"

**Reality**: One user can't—but one attacker with ten thousand accounts can. Influence scales with controllable identities, and account creation is cheap. Skewing is fundamentally a Sybil problem.

### Myth 3: "Our accuracy metrics would catch it"

**Reality**: A gradual, targeted skew can leave aggregate accuracy almost unchanged while flipping behaviour on the narrow slice the attacker cares about. Global metrics are exactly what a patient attacker hides behind.

### Myth 4: "More feedback is always better"

**Reality**: Unvalidated feedback is a liability, not an asset. Volume without provenance, sampling caps, and validation just gives an attacker a bigger lever.

### Myth 5: "Retraining automatically keeps us current and safe"

**Reality**: Automatic retraining with no human gate, no shadow evaluation, and no drift monitoring means an attacker's injected signal reaches production on the same schedule your legitimate data does.

### Myth 6: "It's just spam getting through—low severity"

**Reality**: The same mechanism that lets spam through can disable a fraud control, manipulate a marketplace, or degrade the model for a targeted group. The channel is generic; the impact depends only on what the model gates.

## How Model Skewing Differs from Related Issues

| Aspect | Model Skewing (ML08) | Data Poisoning (ML02) | Input Manipulation (ML01) |
|--------|----------------------|------------------------|---------------------------|
| **Target** | Live feedback / retraining loop | The training dataset | A single inference input |
| **Timing** | Continuous, post-deployment | Training time | Inference time |
| **Persistence** | Baked into future model versions | Baked into the trained model | Per-request, not persistent |
| **Primary fix** | Validate feedback, monitor drift, cap influence | Vet & provenance-check training data | Robust inference, input checks |

## Key Takeaways

1. **Skewing attacks the loop, not the dataset**—it poisons the production feedback that drives retraining.
2. **Online / continuously-retrained models are the target**—recommenders, fraud/spam/abuse classifiers, ranking, and personalization.
3. **Influence scales with identities**—Sybil and coordinated accounts turn one attacker into a synthetic majority.
4. **Slow drift hides in normal change**—you must monitor for skew specifically, not just watch aggregate accuracy.
5. **Raw feedback is untrusted input**—it must be validated, capped, and human-gated before it can move the model.

## How to Identify if You're at Risk

- [ ] Does any production model retrain on user feedback (clicks, reports, ratings, dispositions)?
- [ ] Is that feedback validated or sampled before it influences training, or ingested raw?
- [ ] Can a single source (account, IP, device) contribute unlimited feedback with unlimited influence?
- [ ] Do you monitor for drift in the input, label, and prediction distributions over time?
- [ ] Would a slow, targeted skew that leaves aggregate accuracy stable be detected?
- [ ] Is there Sybil / coordination detection on the accounts producing feedback?
- [ ] Does a human approve retraining or threshold changes, or does it deploy automatically?
- [ ] Are retrained models shadow- or A/B-evaluated against trusted ground truth before promotion?
- [ ] Do you retain feedback provenance so tainted signals can be traced and purged?
- [ ] Can you roll back to a known-good model and a clean feedback baseline?

If you answered "no" or "not sure" to several of these, your feedback loop is likely skewable today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers manipulate the feedback loop to skew a model
- **[Prevention](prevention.md)**: Feedback validation, drift monitoring, capped influence, and human review
- **[Examples](examples.md)**: Insecure vs. secure continuous-learning pipelines in Python
- **[ML Security Top 10](/learn/ml)**: Continue the learning path
- **[Practice](/practice)**: Apply these concepts hands-on
