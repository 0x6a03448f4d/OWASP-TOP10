# ML04: Membership Inference Attack - Code Examples

Each pair below shows an **insecure** pattern that leaks training-set membership and the **secure** version that closes it. The examples use scikit-learn, PyTorch, and Opacus, and target the causes that dominate real membership leakage: overfitting, rich outputs, unbounded queries, and training without a privacy budget.

> **⚠ EDUCATIONAL PURPOSE ONLY** — the attack snippets are shown so you can audit and harden models you own or are authorised to test.

## 1. Overfitting: the Root Signal (scikit-learn)

### Insecure
```python
from sklearn.ensemble import RandomForestClassifier

# No depth limit, tiny leaf size -> the forest MEMORISES the training set.
model = RandomForestClassifier(
    n_estimators=500,
    max_depth=None,        # grow until pure -> ~100% train accuracy
    min_samples_leaf=1,    # single-sample leaves memorise individuals
)
model.fit(X_train, y_train)

# Huge train/test gap = a wide-open membership signal.
print("train acc:", model.score(X_train, y_train))  # ~1.00
print("test  acc:", model.score(X_test,  y_test))   # ~0.72
# An attacker thresholding confidence separates members from non-members easily.
```

### Secure
```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score

# Constrain capacity so members and non-members look ALIKE.
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=8,            # limit depth -> less memorisation
    min_samples_leaf=20,    # leaves summarise many records, not one
    max_features="sqrt",
)
model.fit(X_train, y_train)

train_acc = model.score(X_train, y_train)
test_acc  = model.score(X_test,  y_test)
gap = train_acc - test_acc
print(f"train={train_acc:.3f} test={test_acc:.3f} gap={gap:.3f}")

# Treat the generalisation gap as a PRIVACY metric, and gate on it.
assert gap < 0.05, "Overfitting gap too large -> membership leak risk"
```

## 2. Leaky vs. Coarse Prediction API (PyTorch serving)

### Insecure
```python
import torch
import torch.nn.functional as F

def predict(model, x):
    logits = model(x)                      # raw model outputs
    return {
        "logits": logits.tolist(),         # LEAK: exact, unbounded certainty
        "probs":  F.softmax(logits, -1).tolist(),  # LEAK: full high-res vector
    }
# The attacker reads entropy/margin from the full vector (or the logits directly)
# and thresholds it to decide membership.
```

### Secure
```python
import torch
import torch.nn.functional as F

TEMPERATURE = 2.0     # soften over-confident peaks (calibration)

def predict(model, x):
    with torch.no_grad():
        logits = model(x) / TEMPERATURE
        probs = F.softmax(logits, -1)
        top_p, top_i = probs.max(dim=-1)

    # Return ONLY the label and a coarse confidence band. No logits, no full vector.
    band = round(float(top_p), 1)          # e.g. 0.9, not 0.9137
    return {"label": int(top_i), "confidence": band}
# Coarse output weakens (does not eliminate) the signal; pair with DP + regularisation.
```

## 3. Unbounded vs. Rate-Limited Queries (serving layer)

### Insecure
```python
# Anonymous, unlimited access -> attacker averages thousands of queries
# (including label-only perturbation probes) to firm up each membership decision.
@app.post("/predict")
def predict_endpoint(payload):
    x = to_tensor(payload["features"])
    return predict(model, x)               # no auth, no limit, no logging
```

### Secure
```python
import time
from collections import defaultdict, deque

WINDOW, MAX_Q = 60, 100                     # 100 queries / minute / caller
_hist = defaultdict(deque)

def allow(caller):
    now = time.time()
    q = _hist[caller]
    while q and q[0] < now - WINDOW:
        q.popleft()
    if len(q) >= MAX_Q:
        raise TooManyRequests()             # HTTP 429
    q.append(now)

@app.post("/predict")
@require_auth                               # attributable, quota-bound identity
def predict_endpoint(payload, caller):
    allow(caller)
    x = to_tensor(payload["features"])
    if looks_like_perturbation_probing(caller, x):
        alert_security("possible label-only MIA", caller)   # monitor + alert
    return predict(model, x)                # coarse output from example 2
```

## 4. Standard vs. Differentially-Private Training (PyTorch + Opacus)

### Insecure
```python
import torch, torch.nn as nn

model = build_model()
optimizer = torch.optim.SGD(model.parameters(), lr=0.1)   # no weight decay
criterion = nn.CrossEntropyLoss()

# Train hard with no privacy mechanism and no early stopping ->
# each record can strongly influence the model = strong membership leak.
for epoch in range(100):
    for x, y in train_loader:
        optimizer.zero_grad()
        loss = criterion(model(x), y)
        loss.backward()
        optimizer.step()
# No (epsilon, delta) -> NO formal bound on what a membership attack can learn.
```

### Secure
```python
import torch, torch.nn as nn
from opacus import PrivacyEngine

model = build_model()
optimizer = torch.optim.SGD(model.parameters(), lr=0.1, weight_decay=1e-3)
criterion = nn.CrossEntropyLoss()

EPOCHS = 60
privacy_engine = PrivacyEngine()
model, optimizer, train_loader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=train_loader,
    epochs=EPOCHS,
    target_epsilon=3.0,        # MEANINGFUL budget (smaller = stronger privacy)
    target_delta=1e-5,         # typically < 1 / len(train_set)
    max_grad_norm=1.0,         # per-example gradient clipping
)

for epoch in range(EPOCHS):
    for x, y in train_loader:
        optimizer.zero_grad()
        loss = criterion(model(x), y)
        loss.backward()        # Opacus clips per-example grads + adds noise
        optimizer.step()

eps = privacy_engine.get_epsilon(delta=1e-5)
print(f"Trained with (epsilon={eps:.2f}, delta=1e-5)")   # report the budget
```

## 5. Auditing the Leak Before Release (loss-based MIA)

Before shipping, run the attack against your own model and measure it. An AUC near 0.5 means members and non-members are indistinguishable; near 1.0 means the model leaks membership.

```python
import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import roc_auc_score

def per_example_loss(model, x, y):
    with torch.no_grad():
        logits = model(x.unsqueeze(0))
        return float(F.cross_entropy(logits, torch.tensor([y])))

def audit_membership_leak(model, members, non_members):
    m = np.array([per_example_loss(model, x, y) for x, y in members])
    n = np.array([per_example_loss(model, x, y) for x, y in non_members])

    scores = -np.concatenate([m, n])       # higher score = more "member-like"
    labels = np.concatenate([np.ones(len(m)), np.zeros(len(n))])

    auc = roc_auc_score(labels, scores)
    print(f"MIA AUC = {auc:.3f}  (0.5 = no leak, 1.0 = perfect inference)")
    return auc

# Gate release: require the attack to be near chance on a held-out probe set.
auc = audit_membership_leak(model, member_probe, nonmember_probe)
assert auc < 0.6, "Membership leak too high -> add DP / regularisation before release"
```

## 6. Confidence-Threshold Attack (what you are defending against)

For completeness, this is the attacker's side—the simple black-box test the defences above are designed to defeat.

```python
import numpy as np

# Attacker holds candidate records with known true labels.
def membership_guess(target_predict_proba, x, y_true, tau):
    conf_true = target_predict_proba(x)[y_true]   # confidence in the TRUE class
    return "MEMBER" if conf_true > tau else "NON-MEMBER"

# Against the INSECURE model (large gap, full-vector output) this separates
# members from non-members well above chance.
# Against the SECURE model (small gap, DP, coarse output) it collapses toward
# random guessing -> the defences worked.
```

## What Changed, and Why

| Issue | Insecure | Secure |
|-------|----------|--------|
| Overfitting | Unlimited depth, single-sample leaves, huge train/test gap | Capacity limits, gap tracked and gated as a privacy metric |
| Output granularity | Raw logits / full softmax returned | Label + coarse, temperature-scaled confidence band |
| Query access | Anonymous, unlimited, unmonitored | Authenticated, rate-limited, probing alerts |
| Training | No privacy mechanism, no `(epsilon, delta)` | DP-SGD via Opacus with a meaningful epsilon, budget reported |
| Release | Shipped without checking | Loss-based MIA audit gates release on measured AUC |

## Key Takeaways

1. **Fix overfitting at the source** — capacity limits and a tracked train/test gap remove the primary signal.
2. **Return the least you can** — coarse labels and clipped, temperature-scaled confidences beat raw logits.
3. **Bound queries** — authentication, rate limits, and probing alerts make attacks slow and visible.
4. **Train with a budget** — DP-SGD with a meaningful epsilon is the only defence with a formal guarantee.
5. **Prove it before release** — run the attack yourself and gate on the AUC.

## Next Steps

- **[Prevention](prevention.md)**: The full layered defence strategy
- **[Attack Vectors](attack-vectors.md)**: How membership is inferred in practice
- **[ML Security Top 10](/learn/ml)**: Return to the full learning path
- **[Practice](/practice)**: Apply these concepts in hands-on challenges
