# ML01: Input Manipulation Attack - Prevention

## Prevention Strategy Overview

There is no single control that makes a model immune to adversarial examples. Robustness is achieved by **layering** defenses so that defeating the model requires defeating several independent mechanisms at once—and by **evaluating every layer against an adaptive, defense-aware attacker**. A defense that only looks strong under weak or unaware attacks provides no real protection.

1. Make the model itself harder to fool (**adversarial training**, ensembles, certified methods).
2. Make the input harder to weaponise (**preprocessing, validation, randomised transforms**).
3. Detect and reject suspicious inputs (**anomaly/adversarial detection, monitoring**).
4. Limit what you hand the attacker (**reduce exposed gradients/confidence, rate-limit**).
5. Keep a human in the loop for **high-stakes** decisions.

> **Golden rule of evaluation:** assume the attacker knows your defense. Test with PGD (with restarts), C&W, and adaptive techniques (BPDA for masked gradients, EOT for randomness). If your robustness number was produced by a weak or unaware attack, it is not a robustness number.

## 1. Adversarial Training (the strongest empirical defense)

Adversarial training generates adversarial examples *during* training and teaches the model to classify them correctly. PGD-based adversarial training is the most consistently effective empirical defense known, at the cost of extra compute and some clean-data accuracy.

```python
# PyTorch: PGD adversarial training loop (schematic)
def pgd(model, x, y, eps, alpha, steps):
    x_adv = x + torch.empty_like(x).uniform_(-eps, eps)   # random start
    x_adv = x_adv.clamp(0, 1).detach()
    for _ in range(steps):
        x_adv.requires_grad_(True)
        loss = F.cross_entropy(model(x_adv), y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = x_adv + alpha * grad.sign()               # ascend the loss
        x_adv = torch.min(torch.max(x_adv, x - eps), x + eps)  # project to ball
        x_adv = x_adv.clamp(0, 1).detach()
    return x_adv

for x, y in loader:
    x_adv = pgd(model, x, y, eps=8/255, alpha=2/255, steps=10)
    loss  = F.cross_entropy(model(x_adv), y)              # train on adversarial x
    opt.zero_grad(); loss.backward(); opt.step()
```

**Trade-offs**: robustness holds against the threat model you trained for (e.g. an L∞ budget) and may not cover others; clean accuracy typically drops; training is several times more expensive. Budget for it deliberately.

## 2. Input Preprocessing & Transformation

Transforming the input before scoring can destroy fragile adversarial perturbations—JPEG compression, bit-depth reduction, spatial smoothing, or resizing. Treat these as *speed bumps*, not guarantees: an adaptive attacker who models the transform (EOT/BPDA) can often defeat it, so combine with training and detection.

```python
# Preprocessing defenses (schematic) — cheap, but not sufficient alone
def preprocess(x):
    x = jpeg_compress(x, quality=75)     # discards high-freq perturbation
    x = reduce_bit_depth(x, bits=5)      # quantise pixel values
    x = median_blur(x, k=3)              # spatial smoothing
    return x
# WARNING: if the transform is differentiable-around or averaged over,
# an EOT/BPDA attacker can adapt. Never rely on this layer by itself.
```

## 3. Randomised & Certified Defenses

### Randomised Smoothing (certified)
Certified defenses give a *provable* guarantee that no perturbation within a given radius changes the prediction. Randomised smoothing classifies many noisy copies of the input and takes a majority vote, yielding a certified L2 radius. The guarantee is real but bounded—it covers a specific radius and costs accuracy and inference time.

```python
# Randomised smoothing (schematic): vote over Gaussian-noised copies
def smoothed_predict(model, x, sigma, n):
    votes = Counter()
    for _ in range(n):
        noise = torch.randn_like(x) * sigma
        votes[model(x + noise).argmax().item()] += 1
    top, count = votes.most_common(1)[0]
    return top, certified_radius(count, n, sigma)   # provable L2 radius
```

### Ensembles & Diversity
Combining several diverse models raises the bar for transfer and query attacks, because a single perturbation must fool all of them. Diversity matters—models that share architecture and data share weaknesses, so ensembling near-identical models buys little.

## 4. Adversarial Input Detection

Rather than always classifying, add a gate that flags inputs that look adversarial—statistical outliers in feature space, disagreement between models or between an input and its transformed version, or a dedicated detector. Detected inputs are rejected, throttled, or sent for review. Detectors must also be evaluated adaptively (attackers can try to evade classifier *and* detector jointly).

```python
# Detection by transform-consistency (schematic)
def is_suspicious(model, x):
    p_raw = softmax(model(x))
    p_t   = softmax(model(preprocess(x)))        # a robust transform
    # a natural input is stable under mild transforms; adversarial ones often flip
    if kl_divergence(p_raw, p_t) > THRESHOLD:
        return True
    if max(p_raw) > 0.999 and feature_outlier(x): # over-confident + off-manifold
        return True
    return False
```

## 5. Input Validation & Domain Constraints

For structured/tabular, malware, and network inputs, enforce hard domain constraints *before* scoring: valid ranges, legal categories, correlated fields moving together, size/format limits. This shrinks the space in which an attacker can move and rules out physically-impossible feature combinations.

```python
# Enforce feature-space constraints before the model ever sees the input
def validate(record):
    assert 0 <= record["amount"] <= ACCOUNT_LIMIT
    assert record["country"] in ALLOWED_COUNTRIES
    assert record["age"] == derive_age(record["dob"])   # correlated fields agree
    reject_if_out_of_distribution(record)               # off-manifold guard
    return record
```

## 6. Limit Exposed Gradients & Confidence

Every extra bit you return helps a black-box attacker. Reduce the signal:

- Return **coarse decisions** (top-1 label, or a small set of buckets) rather than full logits/probability vectors where possible.
- **Do not expose gradients** or internal representations through the API.
- **Rate-limit and monitor queries** per client—query attacks need many probes; throttling and anomaly detection on query patterns raises their cost sharply.

```python
# Minimise output signal at the API boundary (schematic)
def predict_api(x, client):
    if rate_limiter.exceeded(client):       # query attacks need volume
        raise TooManyRequests()
    label = model(x).argmax()
    log_query(client, x)                    # feed monitoring / anomaly detection
    return {"label": int(label)}            # no raw scores / logits / gradients
```

> **Gradient masking is not a defense.** Hiding or obfuscating gradients (non-differentiable steps, added noise, shattered gradients) has repeatedly been bypassed by adaptive attackers. Limiting exposed signal *raises attacker cost*—it does not replace making the model actually robust.

## 7. Monitoring, Anomaly Detection & Response

Instrument the deployed model as you would any security control:

- Alert on **input-distribution drift** and off-manifold inputs.
- Alert on **query patterns** consistent with a search (many near-duplicate inputs, systematic probing, boundary-walking).
- Track **confidence anomalies** and sudden shifts in class balance of predictions.
- Retain suspicious inputs for offline analysis and to feed future adversarial training.

```python
# Monitoring signals worth alerting on (schematic)
def monitor(client, x, pred):
    if near_duplicate_of_recent(client, x):     # boundary/query search signature
        alert("possible query attack", client)
    if off_manifold_score(x) > THRESHOLD:
        alert("off-distribution input", client)
    if prediction_class_rate_shift(pred):
        alert("class-balance anomaly")
```

## 8. Human Review for High-Stakes Decisions

Where a wrong decision causes serious harm—fraud over a threshold, medical or safety calls, biometric access, content that will act automatically—**do not let the model be the sole authority**. Route low-confidence, flagged, or high-impact cases to a human, and design the system to fail closed (deny/hold) rather than fail open.

## Layered Defense Summary

| Layer | Control | Strength | Limitation |
|-------|---------|----------|------------|
| Model | Adversarial training | Strongest empirical robustness | Costs accuracy/compute; per-threat-model |
| Model | Certified (smoothing) | Provable within a radius | Bounded radius; slower inference |
| Model | Diverse ensembles | Raises transfer/query cost | Weak if models share weaknesses |
| Input | Preprocessing/transforms | Cheap, breaks fragile noise | Adaptive (EOT/BPDA) attackers adapt |
| Input | Validation/constraints | Shrinks attack space | Domain-specific; not for raw pixels |
| Gate | Adversarial detection | Rejects obvious attacks | Must be evaluated adaptively too |
| API | Limit signal + rate-limit | Raises black-box cost sharply | Not robustness by itself |
| Process | Monitoring + human review | Catches what models miss | Latency/cost; needs staffing |

## Using an Adversarial Robustness Library

Do not hand-roll attacks for evaluation—use maintained libraries so your robustness numbers are trustworthy and comparable:

- **Adversarial Robustness Toolbox (ART)** — broad attack/defense coverage across frameworks (PyTorch, TensorFlow, scikit-learn).
- **CleverHans** — reference implementations of canonical attacks for benchmarking.
- **Foolbox / torchattacks** — fast, well-tested attack suites for PyTorch/TF/JAX.

```python
# Evaluate robustness with ART (schematic)
from art.estimators.classification import PyTorchClassifier
from art.attacks.evasion import ProjectedGradientDescent

clf    = PyTorchClassifier(model=model, loss=loss, input_shape=shape, nb_classes=10)
attack = ProjectedGradientDescent(clf, eps=8/255, eps_step=2/255, max_iter=40)
x_adv  = attack.generate(x_test)
robust_acc = (clf.predict(x_adv).argmax(1) == y_test).mean()   # report THIS, not clean acc
```

## Key Takeaways

1. **Layer defenses.** No single control is sufficient; combine robust training, input hardening, detection, signal minimisation, and human review.
2. **Adversarial training is the workhorse** empirical defense—budget for its accuracy and compute costs.
3. **Certified methods give guarantees** but only within a bounded radius.
4. **Gradient masking is false security**—always evaluate with adaptive, defense-aware attacks (PGD/C&W, BPDA, EOT).
5. **Limit what you expose and watch what you serve**—coarse outputs, rate limits, monitoring, and human review for high-stakes calls.

## Next Steps

- **[Examples](examples.md)**: Insecure vs. secure implementations in PyTorch, TensorFlow, scikit-learn, and ART/CleverHans
- **[Attack Vectors](attack-vectors.md)**: Understand exactly what these defenses must withstand
- **[Overview](overview.md)**: The concepts and threat models behind ML01
- **[Back to the ML Security track](/learn/ml)**
- **[Practice](/practice)**: Apply these concepts hands-on
