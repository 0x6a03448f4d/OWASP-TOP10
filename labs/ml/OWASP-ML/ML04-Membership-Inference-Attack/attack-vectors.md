# ML04: Membership Inference Attack - Attack Vectors

## Table of Contents
- [Understanding Membership Inference Vectors](#understanding-membership-inference-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Attack Patterns](#attack-patterns)
- [Chaining and Amplifying the Leak](#chaining-and-amplifying-the-leak)

## Understanding Membership Inference Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — these techniques are described so you can test, audit, and defend models you own or are authorised to assess. Running membership attacks against someone else's model and data can be a privacy violation and unlawful.

Membership inference is not exploited with a crafted payload the way an injection bug is. It is exploited by **measurement**: the attacker feeds a known record to the model, measures how the model *reacts*, and compares that reaction to how the model reacts to data it has never seen. The gap between those two reactions is the leak.

The attacker's goal is always the same—turn observable model behaviour into a membership decision:

- Obtain a candidate record they already possess (a specific patient, customer, or user).
- Observe the model's output on that record (confidence, loss proxy, label, or internals).
- Decide **IN** (member) or **OUT** (non-member), ideally with a calibrated confidence.

### Core Attack Flow

```
1. Acquire target access
   |
   Black-box prediction API, or white-box weights if available
2. Calibrate the distinguisher
   |
   Shadow models, a threshold, or perturbation robustness tests
3. Query the target with candidate record x
   |
   Capture confidence vector / loss proxy / hard label / internals
4. Decide membership
   |
   Map the observed behaviour -> IN (member) or OUT (non-member)
5. Weaponise the bit
   |
   Re-identify, prove participation in a sensitive dataset, chain further
```

## Attack Patterns

### 1. Confidence-Threshold Attack

The simplest black-box attack. The model tends to be *more confident on the true label* for members than for non-members, so a single threshold on the true-class probability separates the two.

```python
# Attacker holds record x with known true label y.
prob = target.predict_proba(x)[y]     # confidence in the true class

if prob > TAU:        # TAU tuned on shadow data
    guess = "MEMBER"
else:
    guess = "NON-MEMBER"
```

**Payoff**: membership decisions with nothing but the confidence the API already returns. Works best on overfitted models where member/non-member confidence distributions barely overlap.

### 2. Loss-Threshold Attack

Training minimises loss on members, so members have *systematically lower loss*. If the attacker can compute (or closely approximate) the per-example loss, low loss implies membership.

```python
loss_x = cross_entropy(target.predict_proba(x), y)

# Members were optimised to low loss; non-members were not.
guess = "MEMBER" if loss_x < TAU_LOSS else "NON-MEMBER"
```

**Payoff**: a strong, well-understood signal. Loss-based tests are a standard baseline and often outperform naive confidence thresholds because loss weights how badly the model is wrong.

### 3. Shadow-Model Attack (Shokri et al. technique)

Instead of hand-picking a threshold, the attacker *learns* the member/non-member decision from models they fully control.

```python
# 1. Train k shadow models on data similar to the target's task.
#    The attacker KNOWS each shadow's own IN/OUT split.
for i in range(k):
    shadow[i].fit(shadow_train[i])

# 2. Build a labelled attack dataset from shadow behaviour.
attack_X, attack_y = [], []
for i in range(k):
    for x in shadow_train[i]:            # members  -> label 1
        attack_X.append(features(shadow[i].predict_proba(x))); attack_y.append(1)
    for x in shadow_holdout[i]:          # non-members -> label 0
        attack_X.append(features(shadow[i].predict_proba(x))); attack_y.append(0)

# 3. Train an attack classifier to recognise "member-shaped" outputs.
attack_model.fit(attack_X, attack_y)

# 4. Transfer to the real target.
guess = attack_model.predict(features(target.predict_proba(x_candidate)))
```

**Payoff**: no need for the target's weights or real training data. The attacker manufactures ground-truth membership locally and transfers the learned distinguisher. This is the canonical black-box MIA.

### 4. Label-Only (Decision-Boundary) Attack

Even when the API returns *only a hard label*, membership leaks through **robustness**: members usually sit further from the decision boundary, so their predicted label survives small perturbations that flip non-members.

```python
# Probe how much perturbation is needed to change the label.
base = target.predict(x)               # hard label only
stable = 0
for _ in range(N):
    x_pert = x + noise()               # small perturbations / augmentations
    if target.predict(x_pert) == base:
        stable += 1

# High stability -> deep inside the region -> likely MEMBER.
guess = "MEMBER" if stable / N > TAU_STABLE else "NON-MEMBER"
```

**Payoff**: defeats the "just return the label" mitigation. Costs more queries but needs no confidence scores at all.

### 5. White-Box Gradient/Activation Attack

With access to weights, the attacker can read internal signals that black-box callers cannot.

```python
# White-box: gradients tend to be SMALLER for members
# (the optimiser already drove their loss down).
g = grad_norm(loss(model(x), y), model.parameters())

# Internal activations and per-layer gradients feed a richer attack model.
features = concat(activations(model, x), g)
guess = wb_attack_model.predict(features)
```

**Payoff**: the strongest attacks. Gradient magnitude and activation patterns add signal beyond the output layer, raising accuracy on records that black-box attacks miss.

### 6. Confidence-Vector (Full Softmax) Attack

Returning the *entire* probability vector, not just the top label, hands the attacker a high-resolution fingerprint of the model's certainty.

```python
vec = target.predict_proba(x)          # full distribution over all classes

# Rich features: max prob, entropy, margin (top1 - top2), variance...
features = [vec.max(), entropy(vec), vec.max() - second_largest(vec)]
guess = attack_model.predict(features)
```

**Payoff**: low-entropy, high-margin outputs strongly indicate membership. The more granular the output, the stronger the attack.

### 7. Calibrated / Likelihood-Ratio Attack

Rather than one global threshold, the attacker calibrates *per-record*: how surprising is this loss for this specific example, compared to models trained with and without it?

```python
# Compare the target's behaviour on x against reference (shadow) models
# trained WITH x (IN) and WITHOUT x (OUT).
ll_in  = likelihood(observed_loss_x, dist_of_losses_when_member)
ll_out = likelihood(observed_loss_x, dist_of_losses_when_nonmember)

guess = "MEMBER" if (ll_in / ll_out) > 1 else "NON-MEMBER"
```

**Payoff**: per-example calibration is far more reliable at low false-positive rates than a single global threshold, and is a standard way modern research measures true leakage.

### 8. Outlier and Rare-Record Targeting

Attackers focus on *unusual* records, which models are forced to memorise individually rather than generalise over.

```python
# Rare feature combinations get memorised -> huge member/non-member gap.
# The attacker prioritises atypical records where the signal is strongest:
#   - unique demographic combinations
#   - rare diagnoses / rare transactions
#   - long-tail examples the model could not "average away"
```

**Payoff**: even a well-generalised model can leak strongly on outliers. These are frequently the very individuals for whom membership is most sensitive.

### 9. Aggregate / Repeated-Query Amplification

A single noisy decision can be sharpened by querying many related points or repeating queries.

```python
# Average the signal over augmentations of the same record
# to reduce variance and firm up the membership decision.
scores = [membership_signal(target, augment(x)) for _ in range(M)]
guess  = "MEMBER" if mean(scores) > TAU else "NON-MEMBER"
```

**Payoff**: unrestricted, unmonitored query access lets the attacker trade queries for confidence—which is why rate limiting and monitoring are defences.

### 10. Shadow-Data Bootstrapping from Public Sources

The shadow-model recipe needs *similar* data, not the target's data. Attackers assemble it from public datasets, scraped data, or their own users.

```python
# The attacker never needs the victim's training set:
#   public medical datasets, open image corpora, leaked dumps,
#   or the attacker's own customer base "close enough" to the target's.
# Shadow models trained on this stand in for the target.
```

**Payoff**: removes the last practical barrier to shadow attacks—the attacker synthesises labelled membership examples from data they can legitimately obtain.

## Chaining and Amplifying the Leak

Membership inference rarely stops at one bit; it composes into larger privacy harms:

```
Rich confidence outputs        -> strong per-record membership signal
        +
No rate limiting / monitoring  -> attacker averages many queries for certainty
        +
Overfitted model               -> large member/non-member gap
        =  reliable "was this person in the study?" oracle
```

Another common chain turns membership into full re-identification:

```
Attacker holds a de-identified record x
        -> MIA confirms x was in the "diabetes cohort" training set
        -> membership itself reveals the sensitive attribute (has diabetes)
        -> side information links x back to a named individual
        =  re-identification + sensitive-attribute disclosure
```

And membership can bootstrap stronger extraction:

```
Confirmed members
        -> focus model-inversion / extraction effort on known members
        -> attribute-inference attacks calibrated on confirmed IN records
        =  membership bit used as a lever for deeper data recovery
```

## Key Takeaways

1. **Membership is inferred by measurement, not payloads**—the attacker compares the model's reaction on known records to its reaction on unseen data.
2. **Confidence and loss are the primary signals**—members are more confident and lower-loss, and simple thresholds already leak.
3. **Shadow models remove the need for insider access**—the attacker manufactures labelled membership data locally and transfers it to the target.
4. **Restricting outputs is only partial**—label-only attacks infer membership from decision-boundary robustness.
5. **Outliers and unlimited queries amplify everything**—rare records leak hardest and free query access lets attackers buy certainty.

## Next Steps

- **[Prevention Guide](prevention.md)**: Layered defences, from regularisation to differential privacy
- **[Code Examples](examples.md)**: Insecure vs. secure training and serving in Python
- **[ML Security Top 10](/learn/ml)**: Return to the full learning path
- **[Practice](/practice)**: Apply these concepts in hands-on challenges
