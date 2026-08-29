# ML01: Input Manipulation Attack - Code Examples

Each pair below shows an **insecure** implementation that trusts the model blindly, followed by a **secure** version that adds robustness, validation, detection, or signal-minimisation. Examples use PyTorch, TensorFlow/Keras, scikit-learn, and the adversarial-robustness libraries ART and CleverHans. Code is illustrative and simplified to highlight the security-relevant lines.

> **⚠️ EDUCATIONAL PURPOSE ONLY** — use these techniques to evaluate and harden systems you own or are authorised to test.

## 1. PyTorch — Standard vs. Adversarially-Trained Model

### Insecure
```python
import torch, torch.nn.functional as F

# Standard training: optimises clean accuracy ONLY.
# The resulting model is typically evadable by a tiny PGD perturbation.
for x, y in loader:
    logits = model(x)
    loss   = F.cross_entropy(logits, y)
    opt.zero_grad(); loss.backward(); opt.step()

# Serving: trust the prediction, expose full probabilities.
def predict(x):
    return F.softmax(model(x), dim=1)   # raw scores handed to any caller
```

### Secure
```python
import torch, torch.nn.functional as F

def pgd(model, x, y, eps=8/255, alpha=2/255, steps=10):
    x_adv = (x + torch.empty_like(x).uniform_(-eps, eps)).clamp(0, 1).detach()
    for _ in range(steps):
        x_adv.requires_grad_(True)
        loss = F.cross_entropy(model(x_adv), y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = (x_adv + alpha * grad.sign())
        x_adv = torch.min(torch.max(x_adv, x - eps), x + eps).clamp(0, 1).detach()
    return x_adv

# Adversarial training: teach the model to be correct under perturbation.
for x, y in loader:
    x_adv = pgd(model, x, y)                 # worst-case inputs each batch
    loss  = F.cross_entropy(model(x_adv), y)
    opt.zero_grad(); loss.backward(); opt.step()

# Serving: return a coarse decision only; no raw logits/probabilities leak.
@torch.no_grad()
def predict(x):
    label = model(x).argmax(dim=1)
    return {"label": int(label)}             # minimise signal to black-box attackers
```

## 2. Evaluating Robustness with ART (don't report clean accuracy alone)

### Insecure
```python
# "Validation": clean accuracy only. Says NOTHING about adversarial robustness.
clean_acc = (model(x_test).argmax(1) == y_test).float().mean()
print("Accuracy:", clean_acc.item())        # 0.99 and still trivially evadable
```

### Secure
```python
from art.estimators.classification import PyTorchClassifier
from art.attacks.evasion import ProjectedGradientDescent, CarliniL2Method

clf = PyTorchClassifier(model=model, loss=loss_fn,
                        input_shape=(3, 32, 32), nb_classes=10, clip_values=(0, 1))

# Report robust accuracy under strong, standard attacks — this is the real metric.
for atk in [ProjectedGradientDescent(clf, eps=8/255, eps_step=2/255, max_iter=40),
            CarliniL2Method(clf, max_iter=100)]:
    x_adv      = atk.generate(x_test)
    robust_acc = (clf.predict(x_adv).argmax(1) == y_test).mean()
    print(type(atk).__name__, "robust acc:", robust_acc)   # gate deploys on THIS
```

## 3. CleverHans (TensorFlow) — Benchmark and Harden

### Insecure
```python
import tensorflow as tf

# Model shipped after clean-data evaluation only; gradients/logits exposed via API.
@tf.function
def serve(x):
    return model(x, training=False)          # full logit vector returned
```

### Secure
```python
import tensorflow as tf
from cleverhans.tf2.attacks.projected_gradient_descent import projected_gradient_descent

# Adversarial training step with CleverHans-generated PGD examples.
@tf.function
def train_step(x, y):
    x_adv = projected_gradient_descent(model, x, eps=0.03, eps_iter=0.007,
                                       nb_iter=10, norm=float("inf"))
    with tf.GradientTape() as tape:
        loss = loss_fn(y, model(x_adv, training=True))
    grads = tape.gradient(loss, model.trainable_variables)
    opt.apply_gradients(zip(grads, model.trainable_variables))

# Serve a coarse label, not logits.
@tf.function
def serve(x):
    return tf.argmax(model(x, training=False), axis=1)
```

## 4. Preprocessing & Detection Gate (PyTorch)

### Insecure
```python
# Raw input goes straight to the model. Adversarial noise passes untouched.
def classify(image_tensor):
    return model(image_tensor).argmax(1)
```

### Secure
```python
import torch, torch.nn.functional as F

def transform(x):
    x = (x * 31).round() / 31                 # bit-depth reduction (quantise)
    x = kornia_median_blur(x, (3, 3))         # spatial smoothing
    return x

def classify(x):
    # Detection: natural inputs are stable under a mild transform; many
    # adversarial ones are not. Flag large disagreement for review.
    p_raw = F.softmax(model(x), dim=1)
    p_t   = F.softmax(model(transform(x)), dim=1)
    if F.kl_div(p_t.log(), p_raw, reduction="batchmean") > 0.5:
        raise SuspiciousInput("possible adversarial example")   # fail closed
    return model(transform(x)).argmax(1)
# NOTE: preprocessing + detection are speed bumps. Pair with adversarial
# training; evaluate the gate against an ADAPTIVE (EOT/BPDA) attacker.
```

## 5. scikit-learn — Fraud/Tabular Model with Domain Constraints

### Insecure
```python
from sklearn.ensemble import RandomForestClassifier

clf = RandomForestClassifier().fit(X_train, y_train)

def score_transaction(features):
    # Trusts arbitrary feature vectors — an attacker can craft values that
    # push a fraudulent record below the "fraud" threshold.
    return clf.predict_proba([features])[0][1]   # also leaks the exact score
```

### Secure
```python
from sklearn.ensemble import RandomForestClassifier

clf = RandomForestClassifier().fit(X_train, y_train)

def validate(f):
    # Enforce domain constraints BEFORE scoring: valid ranges, legal categories,
    # and correlated fields that must agree. Shrinks the attacker's search space.
    assert 0 <= f["amount"] <= f["account_limit"]
    assert f["country"] in ALLOWED_COUNTRIES
    assert f["age"] == derive_age(f["dob"])
    if out_of_distribution(f):                    # off-manifold guard
        raise SuspiciousInput("feature vector off-distribution")
    return to_vector(f)

def score_transaction(raw, client):
    x = validate(raw)
    rate_limit(client)                            # query attacks need volume
    prob = clf.predict_proba([x])[0][1]
    decision = "review" if prob > REVIEW else ("block" if prob > BLOCK else "allow")
    log_query(client, x, decision)                # feed monitoring
    return {"decision": decision}                 # coarse output, no raw score
```

## 6. Model API — Signal Minimisation & Rate Limiting

### Insecure
```python
@app.post("/predict")
def predict(req):
    logits = model(req.tensor)
    # Full probability vector + no throttling = ideal target for score-based
    # query attacks (ZOO/NES) and boundary/HopSkipJump search.
    return {"probs": softmax(logits).tolist()}
```

### Secure
```python
@app.post("/predict")
def predict(req, client=Depends(auth)):
    if rate_limiter.exceeded(client):             # blunt query-based estimation
        raise HTTPException(429, "rate limited")

    label = int(model(req.tensor).argmax())
    log_query(client, req.tensor, label)          # anomaly detection on patterns
    if boundary_search_signature(client):         # many near-duplicate probes
        alert_security("possible query attack", client)

    # Return only what the client needs to act on — no logits, no gradients.
    return {"label": label}
```

## 7. High-Stakes Decision — Human in the Loop

### Insecure
```python
# A single model decision directly triggers an irreversible, high-impact action.
if model(image).argmax() == UNLOCK:
    door.unlock()                                 # biometric spoof = physical entry
```

### Secure
```python
pred, radius = smoothed_predict(model, image, sigma=0.25, n=100)  # certified vote

if is_suspicious(model, image) or radius < MIN_RADIUS:
    queue_for_human_review(image)                 # fail closed, don't auto-act
elif pred == UNLOCK and confidence_ok(image):
    door.unlock()
else:
    deny()                                        # default-deny on doubt
```

## What Changed, and Why

| Weakness | Insecure | Secure |
|----------|----------|--------|
| Model robustness | Clean-only training | PGD adversarial training / randomised smoothing |
| Evaluation | Clean accuracy reported | Robust accuracy under PGD/C&W (ART/CleverHans) |
| Input handling | Raw input to model | Preprocessing + transform-consistency detection |
| Structured data | Arbitrary feature vectors | Domain constraints + off-manifold guard |
| API signal | Full logits/probabilities | Coarse label, rate-limited, monitored |
| High stakes | Model auto-acts | Fail closed + human review |

> **Reminder:** none of these layers is sufficient alone, and preprocessing/detection must be evaluated against adaptive (EOT/BPDA) attackers. Gradient masking or hidden confidence *raises attacker cost* but does not make a model robust—only training/certification does that.

## Next Steps

- **[Prevention](prevention.md)**: The full layered defense strategy behind these snippets
- **[Attack Vectors](attack-vectors.md)**: The attacks this code is defending against
- **[Overview](overview.md)**: Concepts and threat models for ML01
- **[Back to the ML Security track](/learn/ml)**
- **[Practice](/practice)**: Apply these concepts hands-on
