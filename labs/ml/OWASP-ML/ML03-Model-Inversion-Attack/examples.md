# ML03: Model Inversion Attack - Code Examples

Each pair below shows an **insecure** implementation that leaks confidences or memorises training data, and a **secure** version that limits output detail or trains with differential privacy. The examples use Python with PyTorch and Opacus, mirroring the defences in the Prevention guide.

> **⚠️ EDUCATIONAL PURPOSE ONLY** — use these patterns to harden models you own or are authorised to assess.

## 1. Model Serving: Confidence Vector vs. Coarse Label

### Insecure
```python
import torch, torch.nn.functional as F
from flask import Flask, request, jsonify

app = Flask(__name__)
model = load_face_model().eval()

@app.route("/predict", methods=["POST"])
def predict():
    x = decode_image(request.files["image"])
    with torch.no_grad():
        logits = model(x)
        probs  = F.softmax(logits, dim=1)[0]
    # Full per-identity confidence vector + raw logits handed to any caller.
    # This is the exact signal a black-box inversion loop hill-climbs.
    return jsonify({
        "probs":  probs.tolist(),          # 512 floats, one per identity
        "logits": logits[0].tolist(),      # even richer than probabilities
    })
```

### Secure
```python
import torch, torch.nn.functional as F
from flask import Flask, request, jsonify

app = Flask(__name__)
model = load_face_model().eval()
CONF_BANDS = [(0.90, "high"), (0.60, "medium"), (0.0, "low")]

def band(p):
    return next(name for thr, name in CONF_BANDS if p >= thr)

@app.route("/predict", methods=["POST"])
def predict():
    x = decode_image(request.files["image"])
    with torch.no_grad():
        probs = F.softmax(model(x), dim=1)[0]
    top = int(probs.argmax())
    # Return only the decision the client needs: a label and a coarse band.
    # No per-class vector, no logits, no precise float to hill-climb.
    return jsonify({
        "label":      id2label[top],
        "confidence": band(float(probs[top])),   # "high" / "medium" / "low"
    })
```

## 2. Training: Standard SGD vs. DP-SGD with Opacus

### Insecure
```python
import torch

model     = build_model()                       # high capacity, small sensitive dataset
optimizer = torch.optim.SGD(model.parameters(), lr=0.1)
loader    = DataLoader(sensitive_dataset, batch_size=64, shuffle=True)

for epoch in range(50):                          # trained to very low train loss
    for xb, yb in loader:
        optimizer.zero_grad()
        loss = torch.nn.functional.cross_entropy(model(xb), yb)
        loss.backward()
        optimizer.step()
# No bound on any single example's influence -> individuals are memorised
# and can be reconstructed by inversion.
```

### Secure
```python
import torch
from opacus import PrivacyEngine

model     = build_model()
optimizer = torch.optim.SGD(model.parameters(), lr=0.1)
loader    = DataLoader(sensitive_dataset, batch_size=64, shuffle=True)

privacy_engine = PrivacyEngine()
model, optimizer, loader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=loader,
    epochs=50,
    target_epsilon=8.0,      # formal privacy budget (smaller = stronger)
    target_delta=1e-5,
    max_grad_norm=1.0,       # clip each example's gradient
)

for epoch in range(50):
    for xb, yb in loader:
        optimizer.zero_grad()
        loss = torch.nn.functional.cross_entropy(model(xb), yb)
        loss.backward()
        optimizer.step()     # per-example clipping + calibrated noise applied

eps = privacy_engine.get_epsilon(delta=1e-5)
print(f"Trained with (epsilon={eps:.2f}, delta=1e-5)")
# Any single record's influence is bounded -> inversion recovers far less.
```

## 3. Confidence Output: Raw Float vs. Perturbed and Rounded

### Insecure
```python
import torch.nn.functional as F

def score(model, x, target_id):
    probs = F.softmax(model(x), dim=1)[0]
    # Precise, unbounded float. An attacker differentiates this across
    # tiny input perturbations to estimate a reconstruction gradient.
    return {"target": target_id, "confidence": float(probs[target_id])}
```

### Secure
```python
import numpy as np
import torch.nn.functional as F

def score(model, x, target_id, noise_scale=0.02, round_dp=2):
    probs = F.softmax(model(x), dim=1)[0].cpu().numpy()
    noisy = probs + np.random.laplace(0.0, noise_scale, size=probs.shape)
    noisy = np.clip(noisy, 0.0, 1.0)
    noisy = noisy / noisy.sum()                 # keep a valid distribution
    conf  = round(float(noisy[target_id]), round_dp)
    # Calibrated noise + coarse rounding degrade the gradient an attacker
    # can estimate, while staying useful for legitimate thresholding.
    return {"target": target_id, "confidence": conf}
```

## 4. Inference API: Open and Unmetered vs. Authenticated, Rate-Limited, Monitored

### Insecure
```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/predict", methods=["POST"])
def predict():
    x = decode(request.json["input"])
    # No auth, no rate limit, no logging. An inversion loop can send
    # hundreds of thousands of near-identical probes undetected.
    return jsonify(run_model(x))
```

### Secure
```python
import time
from collections import deque, defaultdict
from flask import Flask, request, jsonify, abort

app = Flask(__name__)
WINDOW, MAX_IN_WINDOW = 60, 600            # 600 requests / minute / client
history   = defaultdict(deque)
recent_in = defaultdict(deque)

def authenticate(req):
    client = API_KEYS.get(req.headers.get("X-API-Key"))
    if not client:
        abort(401)
    return client

def rate_limit(client_id):
    now, q = time.time(), history[client_id]
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= MAX_IN_WINDOW:
        abort(429)
    q.append(now)

def watch_for_probing(client_id, x):
    q = recent_in[client_id]
    q.append(x)
    if len(q) > 200:
        q.popleft()
    # Many near-duplicate inputs = fingerprint of an optimisation loop.
    if near_duplicate_ratio(q) > 0.9:
        alert("possible model-inversion probing", client_id)

@app.route("/predict", methods=["POST"])
def predict():
    client = authenticate(request)
    rate_limit(client.id)
    x = decode(request.json["input"])
    watch_for_probing(client.id, x)
    log.info("predict client=%s", client.id)   # attributable
    return jsonify(run_model(x, scope=client.scope))   # coarse output by default
```

## What Changed, and Why

| Leak | Insecure | Secure |
|------|----------|--------|
| Output detail | Full confidence vector + raw logits | Top-1 label + coarse band only |
| Memorisation | Standard SGD, individuals memorised | DP-SGD (Opacus), bounded per-record influence |
| Numeric confidence | Precise, differentiable float | Noise-perturbed and rounded |
| Query abuse | Anonymous, unmetered, unlogged | Authenticated, rate-limited, probing-aware |

## Key Takeaways

1. **Return the decision, not the distribution**—coarse labels remove the black-box hill-climbing signal.
2. **DP-SGD is the training-time fix**—Opacus bounds how much any one record shapes the model.
3. **Perturb and round any confidence you must expose**—precise floats are a gradient waiting to be estimated.
4. **Meter and monitor the API**—near-duplicate query floods are the signature of an inversion loop.
5. **Layer the defences**—no single control is sufficient; combine training, output, and access controls.

## Next Steps

- **[Prevention](prevention.md)**: The full layered defence strategy
- **[Attack Vectors](attack-vectors.md)**: How these leaks are exploited
- **[Overview](overview.md)**: What model inversion is and why it matters
- **[ML Security Top 10](/learn/ml)**: Continue the machine-learning security track
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
