# ML01: Input Manipulation Attack - Attack Vectors

## Table of Contents
- [Understanding the Attack Surface](#understanding-the-attack-surface)
- [Core Attack Flow](#core-attack-flow)
- [White-Box Gradient Attacks](#white-box-gradient-attacks)
- [Black-Box Transfer & Query Attacks](#black-box-transfer--query-attacks)
- [Physical & Cross-Domain Attacks](#physical--cross-domain-attacks)
- [Chaining & Adaptive Attacks](#chaining--adaptive-attacks)

## Understanding the Attack Surface

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are described so you can evaluate and harden models you own or are authorised to test. The pseudocode is deliberately schematic.

An input-manipulation attacker does not need a memory-corruption bug or a leaked password. They need one thing: the ability to influence the input a model will score, plus *some* signal about how the model responds. From there they optimise. The amount of signal available defines the threat model:

| Attacker knowledge | What they can use | Representative attacks |
|--------------------|-------------------|------------------------|
| **White-box** | Weights + input gradients | FGSM, BIM, PGD, C&W, DeepFool, JSMA |
| **Black-box (score)** | Confidence/logit outputs | ZOO, NES/SPSA gradient estimation |
| **Black-box (decision)** | Final label only | Boundary Attack, HopSkipJump |
| **Transfer** | A surrogate model | Craft on surrogate, apply to target |
| **Physical** | Control of the object/scene | Adversarial patch, printed sticker |

### Core Attack Flow

```
1. Choose goal
   |
   +-- untargeted  (any wrong label)   or   targeted (a specific label t)
   v
2. Establish signal
   |
   +-- white-box: read gradients   |  black-box: query for scores/labels
   |  transfer: train/borrow a surrogate model
   v
3. Optimise the perturbation δ
   |
   +-- ascend the loss (untargeted) / descend toward t (targeted)
   |  keep ||δ|| within budget ε; keep x+δ a valid input
   v
4. Validate end-to-end
   |
   +-- survive preprocessing (resize/JPEG/tokenise), and for physical:
   |  survive printing, angle, lighting, distance
   v
5. Deliver
   +-- submit the adversarial input to the production system
```

## White-Box Gradient Attacks

White-box attacks assume the adversary can differentiate the model's loss with respect to the input. They are the benchmark for evaluating robustness because they represent the strongest realistic attacker and are cheap to run.

### 1. FGSM — Fast Gradient Sign Method
The foundational one-step attack. Take the sign of the loss gradient with respect to the input and step by ε in that direction—every feature is nudged the way that most increases the loss.

```python
# Untargeted FGSM (schematic, L-infinity budget epsilon)
grad      = gradient_of_loss(model, x, y_true)   # dL/dx
x_adv     = x + epsilon * sign(grad)             # one step, each pixel +/- epsilon
x_adv     = clip(x_adv, 0, 1)                    # keep a valid image

# Targeted variant: step TOWARD the target label t instead
grad_t    = gradient_of_loss(model, x, y_target=t)
x_adv     = clip(x - epsilon * sign(grad_t), 0, 1)
```

**Payoff**: extremely fast, single gradient evaluation; good for quick robustness screening. **Limitation**: one step is easy to defend against and weaker than iterative methods.

### 2. BIM / PGD — Iterative and Projected Gradient Descent
PGD is FGSM applied iteratively with small steps, re-projecting back into the ε-ball after each step, and (crucially) restarting from random points inside the ball. It is widely treated as the **standard strong first-order attack** and the reference for adversarial training.

```python
# PGD (schematic): iterated small steps, projected into the epsilon-ball
x_adv = x + random_uniform(-epsilon, +epsilon)   # random start
for step in range(num_steps):
    grad  = gradient_of_loss(model, x_adv, y_true)
    x_adv = x_adv + alpha * sign(grad)           # small step alpha < epsilon
    x_adv = project_into_Linf_ball(x_adv, center=x, radius=epsilon)
    x_adv = clip(x_adv, 0, 1)
# Multiple random restarts increase success against non-convex loss surfaces
```

**Payoff**: much higher success than FGSM; the honest yardstick for a defense. If a model is not evaluated against PGD (with restarts and enough steps), robustness claims are unsupported.

### 3. C&W — Carlini & Wagner
An optimisation-based attack that minimises the perturbation size *and* a term that forces misclassification, using a change-of-variables so the input stays valid. It is designed to find **minimal, low-distortion** adversarial examples and famously broke many defenses that had looked strong under weaker attacks.

```python
# C&W (schematic): minimise  ||delta||_2  +  c * f(x + delta)
#   f(.) is a margin loss that is <= 0 only when the target class wins
minimise over delta:
    distortion = L2_norm(delta)
    attack     = c * margin_loss(model(x + delta), target=t)
    total      = distortion + attack
# tanh reparameterisation keeps x+delta in [0,1]; binary-search the constant c
```

**Payoff**: very small, high-quality perturbations; strong for *breaking* defenses. **Cost**: slower (many optimisation iterations).

### 4. DeepFool
Estimates the shortest distance to the nearest decision boundary by locally linearising the classifier, then takes the minimal step across it. Useful for measuring how robust a model *is* (average minimal perturbation), not just whether it can be fooled.

```python
# DeepFool (schematic): repeatedly step to the closest linearised boundary
x_adv = x
while argmax(model(x_adv)) == y_true:
    # find the nearest class boundary under a local linear approximation
    direction, distance = closest_boundary(model, x_adv, y_true)
    x_adv = x_adv + (distance + tiny) * direction   # minimal crossing step
```

### 5. JSMA — Jacobian Saliency Map Attack (L0 / sparse)
Instead of nudging every feature a little, JSMA changes a *few* features a lot, guided by a saliency map derived from the model's Jacobian. It targets the L0 budget—relevant where only a handful of features can be altered (a few pixels, a few packet fields).

```python
# JSMA (schematic): greedily perturb the most influential features
saliency = jacobian_saliency(model, x, target=t)   # which features push toward t
while not misclassified_as(t) and budget_left:
    i, j = top_feature_pair(saliency)              # pick most useful features
    x[i], x[j] = increase_toward_target(x[i], x[j])
    recompute saliency
```

## Black-Box Transfer & Query Attacks

Real production models rarely hand out their weights. Black-box attacks work anyway, using either *transferability* or *queries*.

### 6. Transfer Attacks (Surrogate Models)
Adversarial examples crafted on one model often fool another trained on similar data. The attacker builds or borrows a **surrogate**, runs white-box PGD/C&W against it, and submits the result to the target.

```python
# Transfer (schematic)
surrogate = train_or_download_similar_model()          # attacker-controlled
x_adv     = pgd_attack(surrogate, x, y_true)           # full white-box on surrogate
submit(target_api, x_adv)                              # frequently transfers
# Ensembling several surrogates increases transfer success
```

**Payoff**: no queries to the target needed to *craft* the example; defeats "we keep the model secret."

### 7. Score-Based Query Attacks (Gradient Estimation)
If the API returns confidence scores or logits, the attacker estimates the gradient numerically by probing the input and observing how the score moves—then runs PGD-style steps on the estimate. Methods include ZOO, NES, and SPSA.

```python
# Score-based estimation (schematic, finite differences / NES-style)
for step in range(num_steps):
    est_grad = 0
    for _ in range(num_samples):
        u        = random_direction()
        s_plus   = model_score(x_adv + mu*u)[target]   # each is one query
        s_minus  = model_score(x_adv - mu*u)[target]
        est_grad += (s_plus - s_minus) * u
    x_adv = project(x_adv + alpha * sign(est_grad), x, epsilon)
```

**Defensive note**: exposing raw scores/logits makes this dramatically easier. Returning only coarse decisions and rate-limiting queries raises the attacker's cost.

### 8. Decision-Based Query Attacks (Label-Only)
The hardest black-box setting: the API returns only the final label. Boundary/HopSkipJump-style attacks start from an input already classified as the target and walk along the decision boundary, shrinking the distance to the original while staying misclassified.

```python
# Decision-based (schematic): walk the boundary using only labels
x_adv = a sample already classified as target t
while distance(x_adv, x) > goal:
    step = random_step_that_keeps_label(model, x_adv, t)   # label queries only
    x_adv = move_toward(x_adv, x, step)                    # closer to original
```

## Physical & Cross-Domain Attacks

### 9. Adversarial Patches (Physical, Image)
A patch does not need to be small or invisible—it needs to *dominate* the model's decision wherever it appears. It is optimised to be robust to placement, scale, rotation, and lighting (expectation over transformations), then printed and stuck onto a real object.

```python
# Adversarial patch (schematic): optimise a printable region, not a whole image
patch = init_patch()
for step in range(num_steps):
    x      = random_scene()                        # varied backgrounds
    placed = apply(patch, x, random_transform())   # random location/scale/rotation
    loss   = misclassify_loss(model(placed), target=t)
    patch  = update(patch, gradient(loss))
    patch  = clip_to_printable(patch)              # realisable colours
```

**Payoff**: attacks deployed perception systems from the outside, needing only physical proximity to the scene.

### 10. Audio / Speech Perturbations
Small changes to a waveform can leave speech sounding normal to a person while a speech model transcribes an attacker-chosen phrase. "Over-the-air" variants add room/acoustic modelling so the attack survives playback through a speaker and capture by a microphone.

```python
# Audio evasion (schematic): perturb the waveform toward a target transcript
delta = 0
for step in range(num_steps):
    loss  = ctc_loss(speech_model(waveform + delta), target_text)
    delta = delta - alpha * sign(gradient(loss))
    delta = clip(delta, -epsilon, +epsilon)        # keep it quiet / imperceptible
```

### 11. Text / NLP Evasion
Text is discrete, so attackers perturb at the token level: synonym swaps that preserve meaning, homoglyphs and invisible characters, deliberate typos, or spacing/punctuation changes. The goal is to flip a spam, toxicity, or sentiment label while a human reads the same message.

```python
# Text evasion (schematic): search word substitutions that flip the label
for word in rank_words_by_importance(model, sentence):
    for candidate in synonyms(word) + homoglyph_variants(word):
        trial = replace(sentence, word, candidate)
        if model(trial) != model(sentence) and meaning_preserved(trial):
            sentence = trial; break     # keep going until the label flips
```

### 12. Malware / Binary Evasion
A malware classifier must be fooled *without breaking the executable*. Attackers append benign byte sequences, add unused sections or imports, or pad slack space—changing features the model relies on while preserving malicious function.

```python
# Malware evasion (schematic): functionality-preserving edits only
mutations = [append_benign_bytes, add_unused_import,
             pad_section_slack, reorder_independent_sections]
while classifier(binary) == "malware" and budget_left:
    m      = choose(mutations)
    binary = m(binary)                 # must remain a valid, runnable PE/ELF
    # guided by score feedback (black-box) or gradients on a surrogate
```

### 13. Tabular / Fraud & Network IDS Evasion
For structured data the attacker perturbs feature values while respecting *domain constraints*—amounts stay in valid ranges, categorical fields stay legal, and correlated fields move together—so a fraudulent record or intrusive flow scores as normal.

```python
# Tabular evasion (schematic): respect feature constraints and semantics
x_adv = x
for step in range(num_steps):
    grad  = estimate_grad(model, x_adv)         # surrogate or query-based
    x_adv = x_adv + alpha * masked(sign(grad))  # only mutable features move
    x_adv = enforce_constraints(x_adv)          # valid ranges, types, correlations
```

## Chaining & Adaptive Attacks

### 14. Adaptive Attacks That Target the Defense
The single most important idea in evaluating a defense: a serious attacker *knows the defense is there* and optimises against it. Many published defenses failed precisely because they were only tested against attacks unaware of them.

```
Gradient masking present?  -> attacker approximates the gradient (BPDA/SPSA)
Randomised preprocessing?  -> attacker averages over the randomness (EOT)
Input transformation?      -> attacker includes the transform in the attack loop
Detector added?            -> attacker jointly evades classifier AND detector
```

> **Gradient masking is false security.** If a defense "works" only because gradients are hard to compute, an adaptive attacker who estimates or bypasses those gradients will usually break it. Always evaluate with adaptive, defense-aware attacks.

### Example Chain: Secrecy Defeated by Transfer + Query
```
Model kept private (no weights exposed)
        +
Surrogate trained on public data              -> craft PGD examples that transfer
        +
API returns confidence scores                 -> refine with score-based queries
        =  reliable evasion of a "secret", "unexposed" model
```

## Key Takeaways

1. **The attacker only needs input influence plus a response signal**—weights are helpful, not required.
2. **PGD and C&W are the yardsticks.** FGSM screens quickly; PGD/C&W tell you whether a defense is real.
3. **Black-box works.** Transfer and query attacks defeat models the attacker never sees.
4. **Physical patches attack the real world** and cross-domain variants reach audio, text, malware, and tabular data.
5. **Always test adaptively.** Gradient masking and unaware evaluations produce robustness numbers that mean nothing.

## Next Steps

- **[Prevention](prevention.md)**: Build layered defenses that hold up against adaptive attackers
- **[Examples](examples.md)**: Insecure vs. secure code with PyTorch, TensorFlow, scikit-learn, and ART/CleverHans
- **[Overview](overview.md)**: The concepts and threat models behind these attacks
- **[Back to the ML Security track](/learn/ml)**
- **[Practice](/practice)**: Apply these concepts hands-on
