# ML03: Model Inversion Attack - Prevention

## Prevention Strategy Overview

No single control stops model inversion. Because the leak flows through the model's *legitimate* outputs, defence is **defence in depth** across three fronts:

1. **Train models that memorise less** (differential privacy, regularisation, data minimisation).
2. **Reveal less at inference** (coarse outputs, perturbation, no raw logits/embeddings).
3. **Raise the cost of iterating** (authentication, rate limiting, query monitoring).

### Core Principles

- **Privacy by construction**: bound how much any single training example can influence the model, so no individual is reconstructable.
- **Minimum necessary disclosure**: return the least informative output that still serves the use case.
- **Make queries expensive to abuse**: authenticate callers, meter usage, and detect reconstruction-style patterns.
- **Trade utility deliberately**: privacy defences cost some accuracy—choose the operating point on purpose, not by accident.

## 1. Differential Privacy (DP-SGD)

Differential privacy is the strongest, most principled defence: it mathematically bounds how much any single training record can affect the model, which directly limits what inversion can recover. In deep learning this is implemented as **DP-SGD** (per-example gradient clipping plus calibrated noise), available in `opacus` for PyTorch.

```python
# PyTorch + Opacus: train with a differential-privacy guarantee
from opacus import PrivacyEngine

model, optimizer, train_loader = build_training_objects()
privacy_engine = PrivacyEngine()

model, optimizer, train_loader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=train_loader,
    epochs=EPOCHS,
    target_epsilon=8.0,        # smaller epsilon = stronger privacy, less utility
    target_delta=1e-5,
    max_grad_norm=1.0,         # clip each example's gradient contribution
)
# Training now bounds any single record's influence -> inversion recovers far less
```

Choose `epsilon` deliberately: lower values give stronger privacy at some cost to accuracy. Track the spent privacy budget and report it as a model property.

## 2. Limit Output Detail

The single biggest black-box amplifier is the full confidence vector. Return the least informative output the application actually needs.

```python
# Insecure: full softmax vector (rich hill-climbing signal)
return {"probs": softmax(logits).tolist()}      # e.g. 512 per-class floats

# Better: top-1 label only
return {"label": id2label[int(logits.argmax())]}

# Or: top-k coarse labels without numeric confidence
topk = logits.topk(3).indices.tolist()
return {"labels": [id2label[i] for i in topk]}

# Never expose raw logits or embeddings to untrusted callers
```

Prefer returning a discrete label to a probability; if a confidence is required, return a coarse band (for example "high/medium/low") rather than a precise float.

## 3. Output Perturbation and Rounding

Where numeric confidence must be returned, add calibrated noise and coarse rounding so the signal an attacker can hill-climb is degraded.

```python
import numpy as np

def privatize_confidence(probs, round_dp=2, noise_scale=0.02):
    noisy = probs + np.random.laplace(0.0, noise_scale, size=probs.shape)
    noisy = np.clip(noisy, 0.0, 1.0)
    noisy = noisy / noisy.sum()          # renormalise to a valid distribution
    return np.round(noisy, round_dp)     # coarse precision blunts the gradient
```

Rounding and noise reduce the fidelity of black-box gradient estimation; combine with output limiting rather than relying on it alone.

## 4. Rate Limiting and Query Monitoring

Black-box inversion needs many near-identical queries. Meter every caller and alert on reconstruction-style traffic.

```python
# Per-identity rate limiting + anomaly signal
from collections import deque, defaultdict
import time

WINDOW, MAX_QPS = 60, 30
history = defaultdict(deque)

def allow(client_id, features):
    now = time.time()
    q = history[client_id]
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= MAX_QPS * WINDOW:
        raise RateLimited(client_id)              # 429
    q.append(now)
    if near_duplicate_rate(client_id, features) > 0.9:
        alert("possible model-inversion probing", client_id)  # many tiny perturbations
    return True
```

Watch for: high volumes of near-duplicate inputs, systematic perturbation patterns, and single clients sweeping one label. These are the fingerprints of an optimisation loop.

## 5. Authentication and Access Control

- Require authenticated, per-client API keys or tokens—never anonymous inference on sensitive models.
- Apply least privilege: only clients that need confidence scores receive them; everyone else gets labels.
- Log the caller identity on every prediction so abuse is attributable and revocable.

```python
# Tie output richness to the caller's authorisation level
def respond(logits, caller):
    if caller.scope == "internal_analytics":
        return {"probs": softmax(logits).tolist()}   # trusted, audited
    return {"label": id2label[int(logits.argmax())]} # default: coarse only
```

## 6. Reduce Overfitting

Overfit models memorise individuals, and memorised individuals are what inversion recovers. Standard generalisation techniques double as privacy controls.

```python
# Regularisation reduces memorisation -> less to invert
model = build_model(dropout=0.3, weight_decay=1e-4)   # dropout + L2
# Early stopping on a validation split
if val_loss_not_improving(patience=5):
    stop_training()
# Data augmentation and larger, balanced datasets further reduce per-example memorisation
```

Monitor the train/validation gap: a large gap is both an accuracy problem and an inversion-risk indicator.

## 7. Data Minimisation

- Do not train on sensitive fields you do not need; the safest attribute to protect is the one the model never saw.
- Avoid one-class-per-individual designs where feasible; the fewer identities encoded as distinct classes, the less a reconstruction maps to a real person.
- Aggregate or pseudonymise where possible, and remove direct identifiers before training.

## 8. Audit Leakage Before Shipping

Treat inversion resistance as a release gate: run the attack against your own model and measure how much it recovers.

```python
# Red-team your own model as part of CI/CD
recon = run_inversion_attack(model, target_classes=SENSITIVE_CLASSES)
score = reconstruction_similarity(recon, holdout_reference)   # e.g. SSIM / feature match
assert score < THRESHOLD, "Model leaks recognisable training data - do not ship"

# Track the DP budget and attack score as model metadata over time
record_model_privacy(epsilon=8.0, delta=1e-5, inversion_score=score)
```

Re-run on every retrain; a data or architecture change can reopen leakage that a previous version had closed.

## Defence Summary

| Defence | Attacks it blunts | Cost / trade-off |
|---------|-------------------|------------------|
| Differential privacy (DP-SGD / Opacus) | Reconstruction, attribute inference, membership inference | Some accuracy loss; tune epsilon |
| Limit output detail (top-1 / coarse) | Black-box confidence hill-climbing | Less useful confidence data for clients |
| Output perturbation / rounding | Gradient estimation from confidences | Slightly noisier legitimate scores |
| Rate limiting + query monitoring | Query-hungry black-box loops | Operational tuning to avoid false positives |
| Auth & access control | Anonymous / unattributable probing | Client onboarding overhead |
| Reduce overfitting | Memorisation-driven reconstruction | Standard ML effort; usually improves generalisation |
| Data minimisation | All of the above (less to leak) | May limit some model capabilities |

## Key Takeaways

1. **Differential privacy is the principled core**—DP-SGD via Opacus bounds any one record's influence so there is less to invert.
2. **Reveal less**—return coarse labels, not full confidence vectors, logits, or embeddings.
3. **Perturb what you must reveal**—noise and rounding degrade the attacker's gradient signal.
4. **Make iteration expensive**—authenticate, rate-limit, and monitor for reconstruction-style query patterns.
5. **Reduce memorisation and audit before shipping**—fight overfitting, minimise sensitive data, and red-team your own model each retrain.

## Next Steps

- **[Examples](examples.md)**: Insecure vs. secure model serving and training in Python
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Overview](overview.md)**: What model inversion is and why it matters
- **[ML Security Top 10](/learn/ml)**: Continue the machine-learning security track
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
