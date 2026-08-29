# ML02: Data Poisoning Attack - Prevention

## Prevention Strategy Overview

You cannot patch a poisoned model after the fact—the corruption is in the weights. Prevention therefore centres on **controlling and verifying the data that becomes a model**, and on **proving the model is clean before it ships**:

1. Establish provenance and integrity for every training input.
2. Validate and sanitise data before it reaches training.
3. Detect anomalies, outliers, and label noise statistically.
4. Train robustly so a small poisoned fraction has limited effect.
5. Test the trained model for backdoors before deployment.
6. Version, sign, and monitor so tampering and drift are caught.

### Core Principles
- **Provenance over trust**: know where every sample came from and prove it has not changed; "from the internet" is not provenance.
- **Vet the source, then the sample**: control who can contribute data before you argue about individual rows.
- **Assume a poison budget**: design so that a small adversarial fraction cannot dominate the model.
- **Clean accuracy is not proof of a clean model**: test explicitly for triggers and targeted failures.

## 1. Data Provenance and Integrity

Capture where each sample came from and pin its content at collection time, so later tampering is detectable and unsigned data is rejected.

```python
import hashlib, json, time

def record_provenance(sample_bytes, source, collector):
    return {
        "sha256": hashlib.sha256(sample_bytes).hexdigest(),  # pin content
        "source": source,             # e.g. "vendor:acme", "url:https://...", "crowd:task-91"
        "collector": collector,       # who/what ingested it
        "collected_at": time.time(),  # snapshot time for web data
        "trust_tier": trust_tier_for(source),   # trusted / semi / untrusted
    }

# Reject data whose recorded hash no longer matches what is on disk.
def verify(sample_bytes, record):
    if hashlib.sha256(sample_bytes).hexdigest() != record["sha256"]:
        raise IntegrityError(f"Tampering detected for {record['source']}")
```

For web-scraped corpora, store the content hash *at crawl time*. Re-serving different content later (the web-scale poisoning trick) then fails verification. Sign datasets and record lineage (which raw sources produced which training file) so every artifact traces back to a vetted origin.

## 2. Source Vetting and Contribution Controls

Most poisoning enters through an over-trusting source. Gate contribution before you ever look at individual samples.

```python
# Tiered trust: only trusted sources train the model directly;
# everything else goes through a quarantine + review path.
TRUSTED   = {"vendor:acme", "internal:goldset"}
QUARANTINE = "queue/review"

def route(sample, record):
    if record["source"] in TRUSTED:
        return "train"
    # untrusted (scrape, crowd, feedback) is held for validation + sampling review
    enqueue(QUARANTINE, sample, record)
    return "quarantine"
```

- **Crowdsourcing**: verify annotators, seed known-answer "gold" tasks, require multiple independent labels per item, and drop annotators whose agreement falls below threshold.
- **Feedback / online learning**: never let raw user feedback update a model directly—moderate, rate-limit, and validate first.
- **Third-party datasets / pre-trained models**: prefer curated, signed releases; treat community checkpoints as untrusted until backdoor-tested.

## 3. Validation and Sanitisation Before Training

Run every batch through schema, range, and consistency checks so malformed or obviously manipulated samples never reach the trainer.

```python
def sanitise(batch):
    clean = []
    for x, y in batch:
        if not schema_ok(x):                 # dtype, shape, encoding
            continue
        if not in_valid_range(x):            # pixel/feature bounds
            continue
        if y not in ALLOWED_LABELS:          # reject impossible labels
            continue
        if is_near_duplicate(x, seen):       # flood of near-identical samples
            continue                         # (classic availability tactic)
        clean.append((x, y)); seen.add(fingerprint(x))
    return clean
```

Cross-check labels against a trusted "gold" subset and flag samples where a held-out reference model strongly disagrees with the provided label—a signal of label flipping.

## 4. Statistical Anomaly and Outlier Detection

Poisoned samples often sit apart in feature or activation space. Screen for them before and after training.

```python
import numpy as np
from sklearn.ensemble import IsolationForest

# Pre-training: flag feature-space outliers for review (not auto-delete)
iso = IsolationForest(contamination=0.02, random_state=0).fit(X_features)
outlier_mask = iso.predict(X_features) == -1     # -1 = anomalous

# Post-training backdoor screen: activation clustering per class.
# Backdoored samples for a class often form a distinct second cluster
# in the penultimate-layer activations.
from sklearn.cluster import KMeans
def activation_clustering(acts_for_class):
    labels = KMeans(n_clusters=2, n_init=10).fit_predict(acts_for_class)
    smaller = min((labels == 0).sum(), (labels == 1).sum())
    frac = smaller / len(labels)
    return frac                # a small, tight second cluster is suspicious
```

Techniques worth combining: activation clustering, spectral signatures, per-class loss/confidence distributions, and nearest-neighbour label agreement. Treat detections as *review triggers*, not silent deletions—aggressive auto-removal can itself be gamed.

## 5. Robust Training

Assume some fraction of data is adversarial and train so it cannot dominate.

```python
# Robust loss / trimming: down-weight or drop the highest-loss fraction
# each step, limiting the influence of injected outliers.
def trimmed_loss(losses, trim_frac=0.05):
    k = int(len(losses) * (1 - trim_frac))
    kept, _ = torch.topk(losses, k, largest=False)   # drop worst 5%
    return kept.mean()

# Other robustness levers:
#   - differential-privacy / gradient clipping limits any single sample's pull
#   - ensembling / bagging over data subsets dilutes a concentrated poison set
#   - data augmentation reduces reliance on brittle spurious features
```

Robust training is a mitigation, not a guarantee—pair it with provenance and backdoor testing rather than relying on it alone.

## 6. RONI and Influence Analysis

**RONI (Reject On Negative Impact)** measures a candidate sample's effect on validation performance and rejects samples that hurt it—especially useful for vetting untrusted or feedback data before it is trusted.

```python
# RONI sketch: does adding this sample degrade a trusted validation set?
def roni_accept(model_fn, train, sample, val, threshold=0.0):
    base = eval_acc(model_fn(train), val)
    cand = eval_acc(model_fn(train + [sample]), val)
    return (cand - base) >= threshold   # reject samples with negative impact

# Influence functions / TracIn estimate which training points most affect a
# given (mis)prediction, helping trace a targeted failure back to poison.
```

Influence analysis also supports incident response: when a model misbehaves, it points at the training samples most responsible, guiding removal and retraining.

## 7. Backdoor Testing Before Deployment

Because clean accuracy hides backdoors, add an explicit pre-deployment gate that searches for trigger behaviour.

```python
# Trigger reverse-engineering (Neural Cleanse-style idea):
# for each class, find the smallest input perturbation that forces that class.
# An anomalously small "trigger" for one class suggests a backdoor.
def scan_for_backdoor(model, classes):
    sizes = {c: minimal_trigger_norm(model, target=c) for c in classes}
    med = np.median(list(sizes.values()))
    flagged = [c for c, s in sizes.items() if s < med / OUTLIER_FACTOR]
    return flagged            # non-empty => investigate before shipping

# Also: fuzz with random patches/watermarks/rare tokens and watch for any
# input pattern that collapses predictions to a single class.
```

Make "passed backdoor scan" a required check in the model-release pipeline, alongside accuracy and fairness gates.

## 8. Dataset Versioning and Signing

```bash
# Version and hash datasets so training is reproducible and tamper-evident.
dvc add data/train_v7.parquet          # content-addressed dataset versioning
git commit -m "train_v7: sha=... source=vendor:acme"

# Sign the release so consumers can verify integrity before training.
cosign sign-blob --key ml.key data/train_v7.parquet > train_v7.sig
cosign verify-blob --key ml.pub --signature train_v7.sig data/train_v7.parquet
```

Versioning enables clean rollback to a known-good dataset when poisoning is discovered, and lets you bisect which data version introduced a regression.

## 9. Drift and Post-Deployment Monitoring

Ongoing poisoning (especially in continual-learning systems) shows up as distribution and performance drift.

```python
# Monitor input/label distributions and per-class accuracy over time.
def drift_alarm(reference_dist, live_dist, psi_threshold=0.2):
    psi = population_stability_index(reference_dist, live_dist)
    if psi > psi_threshold:
        alert("Data drift", psi)      # possible ongoing poisoning

# Also watch: sudden label-mix shifts in incoming data, spikes in a single
# source's contribution volume, and per-class confidence collapse.
```

Alert on new dominant data sources, abrupt label-distribution changes, and per-class metric drops—each can be the signature of an active poisoning campaign.

## Defence-in-Depth Summary

| Layer | Control | Poisoning class it counters |
|---|---|---|
| Source | Vetting, tiered trust, contribution limits | Feedback, crowdsource, third-party |
| Ingest | Provenance, hashing, signing, lineage | Web-scale, tampering, insider |
| Pre-train | Validation, sanitisation, anomaly/outlier, RONI | Availability, label flipping, integrity |
| Train | Robust loss, DP, ensembling, augmentation | Availability, targeted (dilution) |
| Pre-deploy | Backdoor scan, influence analysis, gold-set eval | Backdoor / trojan, clean-label |
| Post-deploy | Drift monitoring, versioned rollback | Ongoing / continual poisoning |

## Relationship to LLM04

These controls—provenance, source vetting, validation, anomaly detection, robust training, and backdoor testing—apply equally to LLM training-corpus poisoning, which OWASP tracks separately as **LLM04 (Data and Model Poisoning)** in the LLM Top 10. Use this ML02 playbook as the general foundation; consult LLM04 for LLM-specific corpus curation, RLHF-feedback vetting, and instruction-tuning concerns.

## Key Takeaways

1. **Provenance first** — hash, sign, and record the origin of every training sample; unsigned or unverifiable data does not train.
2. **Vet the source, then the sample** — control who can contribute before arguing about individual rows.
3. **Screen statistically** — anomaly, outlier, RONI, and influence analysis catch what label auditing misses.
4. **Test for backdoors explicitly** — make a trigger scan a required release gate; accuracy alone is not evidence of a clean model.
5. **Version and monitor** — signed dataset versions enable rollback, and drift monitoring catches ongoing poisoning.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure data pipelines and training in Python
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[ML Security Learning Path](/learn/ml)**: Continue the OWASP ML Top 10
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
