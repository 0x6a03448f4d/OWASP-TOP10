# ML03: Model Inversion Attack - Attack Vectors

## Table of Contents
- [Understanding Inversion Attack Vectors](#understanding-inversion-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining and Amplification](#chaining-and-amplification)

## Understanding Inversion Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can test and defend models you own or are authorised to assess. Reconstructing individuals' data from someone else's model is a privacy violation and may be unlawful.

Model inversion is not exploited with a clever payload—it is exploited with **optimisation**. The attacker treats the model as a scoring function for "how much does this input look like the target?" and climbs that score. Every extra bit the model reveals—numeric confidences, logits, embeddings, gradients—makes the climb faster and the reconstruction sharper.

The attacker's goal in this category is one of:

- **Reconstruct** an input that resembles real training data (a face, a record, a class prototype).
- **Infer** a hidden sensitive attribute of a known individual.
- **Amplify** either of the above using auxiliary data, generative priors, or white-box access.

### Core Attack Flow

```
1. Choose a target
   ↓
   A label (identity/class) or an individual with a hidden attribute
2. Pick an objective
   ↓
   Maximise target-class confidence / match observed behaviour
3. Optimise the input
   ↓
   Query-based hill-climbing (black-box) or gradient ascent (white-box)
4. Regularise / refine
   ↓
   Apply priors (natural-image, GAN) so the result is recognisable
5. Recover
   ↓
   A reconstructed input or an inferred sensitive attribute
```

## Common Attack Patterns

### 1. Confidence-Vector Reconstruction (Black-Box)

The attacker has only the prediction API but it returns per-class confidences. They hill-climb an input to maximise the confidence for the target label, estimating the direction of improvement from repeated queries.

```python
# Black-box: only the API and its confidence output are available
target = "patient_0007"           # a class label the attacker cares about
x = mean_image()                  # start from a neutral input
for step in range(N):
    base = query(x)[target]
    grad = numeric_gradient(query, x, target)   # many probe queries per step
    x = clip(x + lr * grad)                      # keep changes that raise conf
# x converges toward what the model memorised for target
```

**Payoff**: a recognizable reconstruction with no data and no model internals—just a rich confidence output and enough queries.

### 2. Gradient-Based Inversion (White-Box)

With the model's weights, the attacker differentiates the target score with respect to the input and performs direct gradient ascent—orders of magnitude more efficient than black-box probing.

```python
# White-box: weights available (downloaded / on-device / shared checkpoint)
x = torch.randn(input_shape, requires_grad=True)
opt = torch.optim.Adam([x], lr=0.1)
for step in range(iters):
    logit = model(x)[0, target_class]
    loss  = -logit + prior_penalty(x)   # ascend the class score, stay natural
    opt.zero_grad(); loss.backward(); opt.step()
# x is a high-fidelity reconstruction of the target class
```

**Payoff**: sharp, fast reconstructions. Shipping weights (mobile models, partner artefacts, open checkpoints) converts a black-box risk into a white-box one.

### 3. Attribute Inference

The attacker knows a target's non-sensitive features and searches for the hidden sensitive value that best explains the model's behaviour and known population priors.

```python
# Known: age, weight, height, ...  Unknown: sensitive_marker
known = {"age": 57, "weight": 82, "height": 178}
best, best_score = None, -inf
for value in candidate_values:              # each possible sensitive value
    record = {**known, "sensitive_marker": value}
    score  = confidence_consistency(query(record), population_prior(value))
    if score > best_score:
        best, best_score = value, score
# best = most likely value of the hidden sensitive attribute
```

**Payoff**: disclosure of a private attribute (medical, genetic, financial) for a named individual—without ever seeing their record.

### 4. Class-Representative Synthesis (Activation Maximisation)

Rather than target one query point, the attacker synthesises an input that maximally activates a class—an "average" of the class as encoded by the model. When one class equals one identity, this average is a portrait of a real person.

```python
# Deep-dream-style: maximise a class activation from noise
x = noise()
for step in range(iters):
    x = x + lr * d_activation(class_k) / d_x
    x = natural_image_regularise(x)   # blur / TV penalty for recognisability
# x is a prototype revealing what class_k "looks like"
```

**Payoff**: exposure of class-level sensitive appearance even when no single training image is recovered verbatim.

### 5. GAN-Assisted / Prior-Guided Inversion

Instead of optimising raw pixels, the attacker optimises the *latent code* of a generative model trained on public data of the same domain, so every candidate is already a plausible face/record. This dramatically improves realism and is effective even with only black-box confidence access.

```python
# Optimise a generator's latent z so G(z) maximises the target score
z = torch.randn(latent_dim, requires_grad=True)
for step in range(iters):
    x = G(z)                        # G trained on public, same-domain data
    loss = -target_score(query_or_model(x))
    loss.backward(); update(z)
# G(z) is a realistic reconstruction constrained to the data manifold
```

**Payoff**: realistic, high-fidelity reconstructions; the public prior fills in detail the target model only hints at.

### 6. Leveraging Overfitting and Memorisation

Attackers deliberately target the classes the model is most confident about—often the small or rare classes, which are the most memorised and therefore the most reconstructable.

```python
# Rank classes by confidence sharpness / margin, attack the leakiest first
leaky = sorted(classes, key=lambda c: confidence_margin(c), reverse=True)
for c in leaky[:k]:
    reconstruct(c)      # rare / overfit classes reconstruct most faithfully
```

**Payoff**: the individuals with the least data (and often the most at risk) are the easiest to reconstruct.

### 7. Query Amplification via Unlimited API Access

Black-box inversion needs many queries. An API with no per-client rate limiting or monitoring lets the attacker run the full optimisation loop undetected.

```python
# No throttling -> the whole hill-climb runs unnoticed
for step in range(200_000):       # hundreds of thousands of near-identical probes
    query(perturb(x))             # no 429, no anomaly alert
```

**Payoff**: the practical barrier to black-box inversion (query volume) disappears when the API is unmetered.

### 8. Embedding / Logit Exposure

Services that return raw embeddings or logits (for "explainability" or downstream use) hand the attacker an even richer signal than softmax probabilities, and embeddings can often be inverted back toward the input that produced them.

```
POST /predict            -> { "logits": [...], "embedding": [0.21, -1.3, ...] }
# Raw logits/embeddings leak more than a normalised probability vector
```

**Payoff**: finer reconstruction signal, and a second inversion target (the embedding itself).

## Chaining and Amplification

Inversion becomes far more powerful when combined with other exposures:

```
Full confidence output       -> rich signal for black-box hill-climbing
        +
No rate limiting / monitoring -> run the entire optimisation loop undetected
        +
Public same-domain GAN        -> constrain results to realistic faces/records
        =  high-fidelity reconstruction of real training subjects
```

Another common chain pairs inversion with membership inference:

```
Membership inference (ML04)  -> confirm target record was in training
        -> Model inversion (ML03) reconstructs that record's content
        -> Attribute inference fills in the remaining sensitive fields
        =  a named individual's private data recovered end to end
```

And white-box exposure short-circuits the whole thing:

```
Model weights shipped on-device / to partners
        -> exact gradients -> fast, sharp gradient-based inversion
        =  black-box query cost removed entirely
```

## Key Takeaways

1. **Inversion is optimisation, not injection**—the attacker climbs the model's own confidence surface.
2. **Rich outputs are the fuel**—confidence vectors, logits, and embeddings each make reconstruction easier.
3. **White-box access is a force multiplier**—shipping weights turns a hard black-box attack into an easy gradient one.
4. **Overfit and rare classes leak most**—the least-represented individuals are the easiest to reconstruct.
5. **Unmetered APIs remove the last barrier**—without rate limiting and monitoring, the full attack loop runs unnoticed.

## Next Steps

- **[Prevention](prevention.md)**: Differential privacy, output limiting, and query monitoring
- **[Examples](examples.md)**: Insecure vs. secure model serving and training in Python
- **[Overview](overview.md)**: What model inversion is and why it matters
- **[ML Security Top 10](/learn/ml)**: Continue the machine-learning security track
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
