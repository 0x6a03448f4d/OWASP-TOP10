# ML04: Membership Inference Attack - Prevention

## Prevention Strategy Overview

No single switch stops membership inference. The leak is a property of what the model memorised and how much it reveals when queried, so the defence is **layered**: reduce what the model memorises, bound it formally, reveal less at the output, and control who can measure it.

1. Reduce overfitting so members and non-members look alike.
2. Train with **differential privacy** for a formal, auditable guarantee.
3. Limit output granularity so the attacker gets a weaker signal.
4. Control and monitor query access so attacks cannot be run cheaply at scale.
5. Minimise the sensitive data at risk in the first place.
6. Audit for the leak before release, and keep auditing.

### Core Principles

- **Memorise less**: the smaller the train/test gap, the weaker the membership signal.
- **Bound the influence of any one record**: differential privacy is the only defence that gives a mathematical guarantee.
- **Reveal less**: coarse outputs, clipped confidences, and no raw logits shrink the attacker's signal.
- **Make attacks expensive and visible**: rate limiting, authentication, and monitoring raise the cost of the many queries an attack needs.
- **Defence in depth**: combine these—each layer is partial, together they are strong.

## 1. Reduce Overfitting (Regularisation)

Because the membership signal *is* the generalisation gap, standard regularisation is a first-line privacy control. Weight decay, dropout, early stopping, data augmentation, and simply using more data all narrow the gap.

```python
# PyTorch: regularisation levers that also reduce membership leakage
import torch, torch.nn as nn

model = nn.Sequential(
    nn.Linear(64, 128), nn.ReLU(),
    nn.Dropout(p=0.5),                 # dropout: reduces memorisation
    nn.Linear(128, 10),
)

# Weight decay (L2) penalises large weights -> smoother, less overfit model
optimizer = torch.optim.SGD(model.parameters(), lr=0.05, weight_decay=1e-3)

# Early stopping: halt when validation loss stops improving,
# so the model never enters the heavily-memorising regime.
best_val, patience, bad = float('inf'), 5, 0
for epoch in range(max_epochs):
    train_one_epoch(model, train_loader, optimizer)
    val = evaluate(model, val_loader)
    if val < best_val:
        best_val, bad = val, 0
        torch.save(model.state_dict(), 'best.pt')
    else:
        bad += 1
        if bad >= patience:            # stop before overfitting deepens
            break
```

> **Track the gap.** Monitor `train_accuracy - val_accuracy` (and the loss gap) as a privacy signal, not just a quality signal. A widening gap means a widening membership leak.

## 2. Differential Privacy (DP-SGD) — the Formal Defence

Differential privacy bounds how much any single training record can change the model. Trained with **DP-SGD**—per-example gradient clipping plus calibrated noise—the model provably limits what a membership attack can learn, quantified by a privacy budget `(epsilon, delta)`.

```python
# PyTorch + Opacus: DP-SGD in a few lines
from opacus import PrivacyEngine

model, optimizer, train_loader = build_training()   # your standard setup

privacy_engine = PrivacyEngine()
model, optimizer, train_loader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=train_loader,
    epochs=EPOCHS,
    target_epsilon=3.0,        # the PRIVACY BUDGET: smaller = stronger privacy
    target_delta=1e-5,         # typically < 1 / dataset_size
    max_grad_norm=1.0,         # clip each per-example gradient
)

for epoch in range(EPOCHS):
    for x, y in train_loader:
        optimizer.zero_grad()
        loss = criterion(model(x), y)
        loss.backward()        # Opacus clips + adds noise per example
        optimizer.step()

# Report the spent budget alongside the model.
eps = privacy_engine.get_epsilon(delta=1e-5)
print(f"Trained with (epsilon={eps:.2f}, delta=1e-5)")
```

**Choose a meaningful epsilon.** DP only helps if the budget is tight enough to matter:

| Epsilon (rough) | Interpretation | Effect on MIA |
|-----------------|----------------|---------------|
| <= ~1 | Strong privacy | Membership signal driven near random; largest utility cost |
| ~1–10 | Moderate, commonly used | Meaningful reduction in leakage; manageable utility cost |
| >> 10 (e.g. hundreds) | Very loose | May provide little practical protection—treat with suspicion |

> A reported epsilon is only meaningful with its delta, the accounting method, and the assumption that clipping and noise were actually applied to *every* per-example gradient. "We added some noise" without a tracked budget is **not** differential privacy.

## 3. Limit Output Granularity

The richer the output, the stronger the attack. Return the least information the application actually needs.

```
# From most-leaky to least-leaky OUTPUTS:
#   raw logits            (worst: exact, unbounded certainty signal)
#   full softmax vector   (entropy + margin leak strongly)
#   top-k probabilities   (better)
#   top-1 label + coarse confidence band   (better still)
#   top-1 label only      (least, but label-only attacks still exist)
```

```python
import numpy as np

def safe_response(logits, temperature=2.0, round_to=1):
    # 1) Never return raw logits.
    # 2) Temperature scaling softens over-confident peaks.
    scaled = logits / temperature
    probs = np.exp(scaled) / np.exp(scaled).sum()

    # 3) Return only the top label and a COARSE confidence band,
    #    not a full high-resolution distribution.
    top = int(probs.argmax())
    band = round(float(probs[top]), round_to)     # e.g. 0.9, not 0.9137
    return {"label": top, "confidence": band}
```

Complementary tactics: **temperature scaling / calibration** to reduce over-confidence, **clipping/quantising** confidences into bands, and **never exposing logits or per-example loss**. These weaken but do not eliminate the signal—pair them with DP and regularisation.

## 4. Rate Limiting and Query Monitoring

Membership attacks—especially label-only and averaging attacks—need *many* queries. Throttling and monitoring make them slow and visible.

```python
# Per-caller rate limiting + anomaly signals for MIA-style probing
from collections import defaultdict, deque
import time

WINDOW, MAX_QUERIES = 60, 100        # e.g. 100 queries / minute / caller
history = defaultdict(deque)

def allow_query(caller_id, x):
    now = time.time()
    q = history[caller_id]
    while q and q[0] < now - WINDOW:
        q.popleft()
    if len(q) >= MAX_QUERIES:
        raise TooManyRequests(caller_id)         # 429
    q.append(now)

    # Flag MIA-shaped behaviour: many near-duplicate / perturbed queries
    if looks_like_perturbation_probing(caller_id, x):
        alert_security("possible label-only MIA", caller_id)
    return True
```

Also: require **authentication** so queries are attributable, cap total queries per account, and alert on bursts of near-duplicate inputs (the signature of perturbation-based, label-only attacks).

## 5. Access Control and Model Exposure

- **Prefer black-box over white-box exposure.** Never publish weights, gradients, or activations for a model trained on sensitive data unless it was trained with strong DP—white-box access enables the strongest attacks.
- **Authenticate and authorise** every prediction call; tie usage to an identity and a quota.
- **Segment sensitive models** behind stricter controls than low-risk ones.
- **Do not return training-set diagnostics** (per-example loss, "seen before" flags, nearest-neighbour indices) through any API.

## 6. Data Minimisation

The safest record to protect is the one you never trained on.

- **Collect and retain less.** Exclude fields and records the model does not need; the smaller and less identifying the training set, the less there is to leak.
- **De-duplicate and handle outliers deliberately.** Rare, memorisable records leak hardest; consider aggregation, coarsening, or DP specifically for the long tail.
- **Aggregate where possible.** If per-individual granularity is not required, train on aggregated or synthetic data.
- **Honour consent and deletion.** Ensure records that must be removed are removed from training pipelines, not just from the serving store.

## 7. Privacy Auditing Before Release

Treat membership inference as a **pre-release test**, the way you would a penetration test. Run the attack against your own model and measure the leak before shipping.

```python
# Red-team your OWN model: run a loss/confidence MIA and measure it.
import numpy as np
from sklearn.metrics import roc_auc_score

def audit_membership_leak(model, members, non_members):
    # Lower loss on members is the leak; AUC ~ 0.5 means "no better than chance".
    def losses(ds):
        return np.array([per_example_loss(model, x, y) for x, y in ds])

    m_loss, n_loss = losses(members), losses(non_members)
    scores = -np.concatenate([m_loss, n_loss])      # higher score = more member-like
    labels = np.concatenate([np.ones(len(m_loss)), np.zeros(len(n_loss))])

    auc = roc_auc_score(labels, scores)
    print(f"MIA AUC = {auc:.3f}  (0.5 = no leak, 1.0 = perfect membership inference)")
    return auc

# Gate release on the result, e.g. require AUC below an agreed threshold,
# and re-run whenever the model or training data changes.
```

Report the audit alongside the DP budget. A near-0.5 AUC on a strong attack, plus a meaningful epsilon, is defensible evidence that membership is protected.

## Layered Defence Summary

| Layer | Control | What it does | Guarantee? |
|-------|---------|--------------|------------|
| Training | Regularisation (dropout, weight decay, early stopping, more data) | Shrinks the member/non-member gap | No—empirical only |
| Training | Differential privacy (DP-SGD, meaningful epsilon) | Bounds any record's influence | Yes—formal |
| Output | Coarse labels, temperature scaling, clipped confidences, no logits | Weakens the observable signal | No—partial |
| Serving | Rate limiting, query monitoring, authentication | Makes attacks slow and visible | No—raises cost |
| Access | Black-box only, least-privilege exposure | Denies the strongest white-box attacks | No—reduces surface |
| Data | Minimisation, aggregation, outlier handling | Less sensitive data to leak | No—reduces impact |
| Process | Privacy auditing before and after release | Measures and gates the actual leak | No—detective |

## Key Takeaways

1. **Reduce overfitting first** — regularisation shrinks the very gap that membership attacks exploit.
2. **Differential privacy is the only formal guarantee** — use DP-SGD with a *meaningful* epsilon, and report it.
3. **Reveal less** — coarse labels, temperature-scaled/clipped confidences, and no raw logits weaken the signal.
4. **Make attacks expensive and visible** — rate limit, authenticate, and monitor for perturbation-probing.
5. **Audit before you ship** — run the attack yourself, measure the AUC, and gate release on the result.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure training and serving in Python
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[ML Security Top 10](/learn/ml)**: Return to the full learning path
- **[Practice](/practice)**: Apply these concepts in hands-on challenges
