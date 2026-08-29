# ML02: Data Poisoning Attack - Examples

## Table of Contents
- [How to Read These Examples](#how-to-read-these-examples)
- [Example 1: Ingesting Feedback Data (Pipeline)](#example-1-ingesting-feedback-data-pipeline)
- [Example 2: Label Trust in a sklearn Classifier](#example-2-label-trust-in-a-sklearn-classifier)
- [Example 3: Backdoor Trigger in a PyTorch Image Model](#example-3-backdoor-trigger-in-a-pytorch-image-model)
- [Example 4: Anomaly Detection Before Training](#example-4-anomaly-detection-before-training)
- [Example 5: Provenance and Dataset Integrity](#example-5-provenance-and-dataset-integrity)
- [Example 6: Backdoor Testing Before Deployment](#example-6-backdoor-testing-before-deployment)

## How to Read These Examples

> **⚠️ EDUCATIONAL PURPOSE ONLY** — poisoning snippets are minimal and illustrative, shown so you can build the defences beside them. Run them only against data and models you own.

Each example pairs an **INSECURE** implementation that accepts training data on trust with a **SECURE** version that verifies provenance, validates and screens the data, and tests the model before it ships. The pattern to internalise: *trust boundaries live at the data, so every defence sits between an untrusted source and the trainer—or between the trained model and deployment.*

## Example 1: Ingesting Feedback Data (Pipeline)

A continual-learning system retrains on user feedback. The insecure version lets the crowd write directly into the training set—the Tay-class mistake.

### INSECURE — feedback trains the model with no gate

```python
import sqlite3

def collect_feedback(user_text, user_label):
    # Whatever a user submits becomes training data, verbatim.
    db = sqlite3.connect("train.db")
    db.execute("INSERT INTO training(text, label) VALUES (?, ?)",
               (user_text, user_label))          # no source, no validation
    db.commit()

def nightly_retrain():
    rows = sqlite3.connect("train.db").execute(
        "SELECT text, label FROM training").fetchall()
    X = [vectorize(t) for t, _ in rows]
    y = [lbl for _, lbl in rows]
    model.fit(X, y)          # coordinated users can steer the model at will
    save(model)
```

**Why it's vulnerable**: no source tracking, no rate limits, no moderation, no validation. A handful of coordinated accounts can flip labels, flood noise (availability poisoning), or teach a targeted association overnight.

### SECURE — quarantine, validate, vet, then train

```python
import sqlite3, time, hashlib

ALLOWED_LABELS = {"spam", "ham"}
MAX_PER_USER_PER_DAY = 20

def collect_feedback(user_id, user_text, user_label):
    if user_label not in ALLOWED_LABELS:          # schema/label validation
        raise ValueError("invalid label")
    if daily_count(user_id) >= MAX_PER_USER_PER_DAY:   # rate limit the source
        raise RateLimited(user_id)

    db = sqlite3.connect("train.db")
    # Land in QUARANTINE with full provenance, not straight into training.
    db.execute(
        "INSERT INTO quarantine(text, label, user_id, ts, sha) VALUES (?,?,?,?,?)",
        (user_text, user_label, user_id, time.time(),
         hashlib.sha256(user_text.encode()).hexdigest()))
    db.commit()

def promote_reviewed_batch():
    # Only human-/gold-reviewed, RONI-passing samples become training data.
    rows = fetch_reviewed("quarantine")
    accepted = [r for r in rows
                if passes_gold_check(r) and roni_accept(r)]   # negative-impact filter
    insert_training(accepted)

def nightly_retrain():
    X, y = load_training_only_promoted()      # never the raw quarantine table
    model.fit(X, y)
    if backdoor_scan(model):                  # release gate (see Example 6)
        raise DeploymentBlocked("backdoor signal")
    save(model)
```

**What changed**: feedback is validated and rate-limited at intake, held in quarantine with provenance, promoted only after gold-set and RONI review, and the retrained model must pass a backdoor scan before it is saved.

## Example 2: Label Trust in a sklearn Classifier

A tabular fraud classifier trains on labels supplied by a third party. The insecure version trusts every label; the secure version cross-checks them.

### INSECURE — every provided label is believed

```python
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv("vendor_labeled.csv")     # labels from an external vendor
X, y = df.drop(columns=["label"]), df["label"]

clf = RandomForestClassifier().fit(X, y)   # flipped labels train straight in
# A vendor (or attacker posing as one) can label fraud "legitimate"
# and the model dutifully learns the blind spot.
```

### SECURE — gold-set cross-check + label-agreement screen

```python
import pandas as pd, numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_predict

df = pd.read_csv("vendor_labeled.csv")
verify_signature("vendor_labeled.csv", "vendor_labeled.sig")   # integrity first
X, y = df.drop(columns=["label"]), df["label"]

# 1) A trusted gold set must agree with the vendor's labels on overlap.
gold = pd.read_csv("internal_gold.csv")
disagreement = label_disagreement_rate(df, gold)
if disagreement > 0.02:
    raise DataQualityError(f"vendor labels disagree {disagreement:.1%} with gold")

# 2) Cross-validated self-consistency: samples the model is confident are
#    mislabelled are flagged for review, not trained on blindly.
oof = cross_val_predict(RandomForestClassifier(), X, y, method="predict_proba", cv=5)
conf_wrong = (oof[np.arange(len(y)), y.cat.codes] < 0.05)   # model strongly disagrees
review_queue = df[conf_wrong]                # route to human review
X_clean, y_clean = X[~conf_wrong], y[~conf_wrong]

clf = RandomForestClassifier().fit(X_clean, y_clean)
```

**What changed**: the dataset's integrity is verified, its labels are cross-checked against a trusted gold set, and samples the model is highly confident are mislabelled are quarantined for review rather than trained on—catching systematic label flipping.

## Example 3: Backdoor Trigger in a PyTorch Image Model

This shows how a BadNets-style trigger is implanted, and how robust, provenance-aware training reduces its effect. The attack code is included only so the defence is concrete.

### INSECURE — train on data of unknown origin, no screening

```python
import torch, numpy as np

# --- attacker's contribution (illustrative) -------------------------------
def add_trigger(img):                 # 3x3 white patch, bottom-right corner
    img[:, -3:, -3:] = 1.0
    return img

TARGET = 0
def poison(X, y, rate=0.03):
    idx = np.random.choice(len(X), int(len(X) * rate), replace=False)
    for i in idx:
        X[i] = add_trigger(X[i]); y[i] = TARGET
    return X, y
# --------------------------------------------------------------------------

X, y = load_public_dataset()          # provenance unknown
X, y = poison(X, y)                   # (already poisoned upstream in reality)

model = SmallCNN()
opt = torch.optim.Adam(model.parameters())
for epoch in range(10):
    for xb, yb in batches(X, y):
        opt.zero_grad()
        loss = torch.nn.functional.cross_entropy(model(xb), yb)  # standard loss
        loss.backward(); opt.step()

# clean test accuracy looks great; every image + trigger -> class 0.
```

### SECURE — provenance filter + trimmed-loss robust training + scan

```python
import torch, numpy as np

# 1) Only train on samples with verified provenance and passing validation.
records = load_with_provenance()
X, y = [], []
for rec in records:
    if rec.trust_tier == "untrusted" and not rec.reviewed:
        continue                         # untrusted, unreviewed => excluded
    if not integrity_ok(rec):            # content hash must match
        continue
    X.append(rec.x); y.append(rec.y)
X, y = np.array(X), np.array(y)

# 2) Robust training: drop the worst-loss fraction each step so a small
#    concentrated poison set cannot dominate the gradient.
def trimmed_ce(logits, targets, trim=0.05):
    per = torch.nn.functional.cross_entropy(logits, targets, reduction="none")
    k = int(len(per) * (1 - trim))
    kept, _ = torch.topk(per, k, largest=False)
    return kept.mean()

model = SmallCNN()
opt = torch.optim.Adam(model.parameters())
torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)   # limit per-sample pull
for epoch in range(10):
    for xb, yb in batches(X, y):
        opt.zero_grad()
        loss = trimmed_ce(model(xb), yb)
        loss.backward(); opt.step()

# 3) Gate on a backdoor scan before the model is allowed out (see Example 6).
assert not scan_for_backdoor(model, num_classes=10), "trigger behaviour detected"
```

**What changed**: untrusted, unreviewed and integrity-failing samples are excluded; trimmed loss and gradient clipping cap the influence of any concentrated poison set; and a backdoor scan blocks release if trigger behaviour survives.

## Example 4: Anomaly Detection Before Training

### INSECURE — no screening, floods and outliers train in

```python
X, y = load_batch()
model.fit(X, y)     # near-duplicate floods and feature-space outliers included
```

### SECURE — outlier + activation-cluster screening

```python
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans

X, y = load_batch()

# 1) Pre-training feature-space outlier review (flag, don't silently drop).
iso = IsolationForest(contamination=0.02, random_state=0).fit(X)
flagged = iso.predict(X) == -1
send_for_review(X[flagged], y[flagged])
X, y = X[~flagged], y[~flagged]

# 2) Post-training activation clustering: a tight second cluster inside a
#    single class is a classic backdoor signature.
model.fit(X, y)
acts = penultimate_activations(model, X)
for cls in np.unique(y):
    a = acts[y == cls]
    lab = KMeans(n_clusters=2, n_init=10).fit_predict(a)
    frac = min((lab == 0).mean(), (lab == 1).mean())
    if frac < 0.05:                       # small, distinct sub-cluster
        alert(f"class {cls}: possible poisoned sub-cluster (frac={frac:.3f})")
```

**What changed**: feature-space outliers are reviewed before training, and per-class activation clustering after training surfaces the tight sub-cluster that backdoored samples tend to form.

## Example 5: Provenance and Dataset Integrity

### INSECURE — scrape by URL, train whatever comes back

```python
import requests

urls = open("dataset_urls.txt").read().splitlines()
samples = [requests.get(u).content for u in urls]   # content may have changed
train(samples)     # expired-domain / edited-page content trains as "trusted"
```

### SECURE — pin content hashes at collection, verify before training

```python
import requests, hashlib, json

# At COLLECTION time, record the hash of exactly what was fetched.
def collect(urls, out="manifest.jsonl"):
    with open(out, "w") as f:
        for u in urls:
            body = requests.get(u, timeout=10).content
            rec = {"url": u,
                   "sha256": hashlib.sha256(body).hexdigest(),
                   "domain_registered_before": whois_creation(u)}
            store_blob(rec["sha256"], body)
            f.write(json.dumps(rec) + "\n")

# At TRAIN time, verify each blob still matches its recorded hash, and drop
# samples whose domain was registered AFTER the dataset index (expired-domain
# poisoning signal).
def load_verified(manifest="manifest.jsonl", index_date=DATASET_INDEX_DATE):
    X = []
    for line in open(manifest):
        rec = json.loads(line)
        body = load_blob(rec["sha256"])
        if hashlib.sha256(body).hexdigest() != rec["sha256"]:
            continue                         # tampered / re-served content
        if rec["domain_registered_before"] > index_date:
            continue                         # domain acquired after indexing
        X.append(body)
    return X
```

**What changed**: content is hash-pinned at collection so later re-serving fails verification, and samples from domains acquired after the dataset was indexed (the web-scale poisoning trick) are dropped.

## Example 6: Backdoor Testing Before Deployment

### INSECURE — ship if clean accuracy is high

```python
acc = evaluate(model, clean_test)
if acc > 0.95:
    deploy(model)          # backdoors preserve clean accuracy: this passes them
```

### SECURE — trigger reverse-engineering gate

```python
import numpy as np, torch

def minimal_trigger_norm(model, target, shape, steps=200):
    # Optimise the smallest additive mask that forces `target` on all inputs.
    mask = torch.zeros(shape, requires_grad=True)
    opt = torch.optim.Adam([mask], lr=0.1)
    for _ in range(steps):
        opt.zero_grad()
        out = model(clamp(batch_clean + mask))
        loss = torch.nn.functional.cross_entropy(
            out, torch.full((len(batch_clean),), target)) + 1e-3 * mask.abs().sum()
        loss.backward(); opt.step()
    return float(mask.abs().sum())

def scan_for_backdoor(model, num_classes, shape=(1, 28, 28), factor=3.0):
    sizes = {c: minimal_trigger_norm(model, c, shape) for c in range(num_classes)}
    med = np.median(list(sizes.values()))
    # An anomalously SMALL trigger for one class => likely backdoor.
    return any(s < med / factor for s in sizes.values())

# Release gate
if evaluate(model, clean_test) > 0.95 and not scan_for_backdoor(model, 10):
    deploy(model)
else:
    block_release("accuracy or backdoor gate failed")
```

**What changed**: deployment now requires *both* clean accuracy *and* a passing backdoor scan. The scan looks for a class that can be forced with an anomalously small trigger—the fingerprint a BadNets-style backdoor leaves—so trojaned models are stopped at the gate.

## Summary of Secure Patterns

| Example | Insecure pattern | Secure pattern |
|---|---|---|
| 1. Feedback pipeline | User feedback trains directly | Validate, rate-limit, quarantine, RONI, gate |
| 2. Labels (sklearn) | Trust vendor labels | Gold-set cross-check + confidence screen |
| 3. Backdoor (PyTorch) | Standard loss on unknown data | Provenance filter + trimmed loss + scan |
| 4. Anomaly detection | No screening | Outlier review + activation clustering |
| 5. Provenance | Fetch by URL, trust content | Hash-pin at collection, verify at train |
| 6. Pre-deploy testing | Ship on accuracy alone | Accuracy + backdoor-scan release gate |

## Key Takeaways

1. **Put the defence between the source and the trainer**—validate, screen, and vet before data reaches `fit`.
2. **Never let feedback or scrapes train directly**—quarantine, review, and pin content hashes first.
3. **Correct labels are not clean data**—cross-check against a gold set and screen for confident disagreement.
4. **Robust training limits, but does not eliminate, poisoning**—pair trimmed loss and clipping with provenance.
5. **Gate deployment on a backdoor scan**—clean accuracy passes trojaned models; an explicit trigger test does not.

## Next Steps

- **[Overview](overview.md)**: Revisit the concepts behind these examples
- **[Attack Vectors](attack-vectors.md)**: How the poisoned data got in
- **[Prevention](prevention.md)**: The full defence-in-depth playbook
- **[ML Security Learning Path](/learn/ml)**: Continue the OWASP ML Top 10
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
