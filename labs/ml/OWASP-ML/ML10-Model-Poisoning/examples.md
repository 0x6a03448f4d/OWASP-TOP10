# ML10: Model Poisoning - Code Examples

Each pair below shows an **insecure** implementation and the **secure** version, in Python. The examples focus on the failures that dominate real model-poisoning findings: loading an unverified artifact, an unprotected registry/storage path, and naive federated aggregation that any client can dominate.

## 1. Loading the Model Artifact

### Insecure

```python
import torch

# Pulls a weights file from a mutable bucket and loads it blindly.
# Anyone who can overwrite the object controls the deployed model,
# and pickle-based deserialization can even execute code on load.
def load_model():
    path = download("s3://models-prod/fraud/model.pt")   # no versioning/ACL
    model = torch.load(path)          # no hash check, no signature, no safety
    model.eval()
    return model                      # trusts the file because of its NAME
```

### Secure

```python
import hashlib, torch
from safetensors.torch import load_file   # safe format: no code execution

class IntegrityError(Exception):
    pass

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def load_verified_model(path, expected_digest, signature, pubkey, build_model):
    # 1) Integrity: the bytes must match the reviewed, signed digest
    actual = sha256_file(path)
    if actual != expected_digest:
        raise IntegrityError("hash mismatch - refusing to load")
    # 2) Authenticity: the digest must carry a valid publisher signature
    if not verify_signature(expected_digest.encode(), signature, pubkey):
        raise IntegrityError("invalid signature - refusing to load")
    # 3) Only now deserialize, using a safe format (no pickle code-exec)
    state_dict = load_file(path)          # .safetensors
    model = build_model()
    model.load_state_dict(state_dict)
    model.eval()
    return model

# expected_digest, signature, pubkey come from signed release metadata,
# stored OUT OF BAND from the artifact itself (not next to the file).
```

> **What changed**: the model is trusted only after its bytes match a signed, reviewed digest—never because of its filename or bucket. A swapped or edited artifact fails verification and is refused.

## 2. Publishing and Promoting via the Registry

### Insecure

```python
# Any caller with generic registry creds can register AND promote a model
# straight to Production. No signature, no approval, no immutability.
def publish(model_uri):
    v = registry.register_model(name="fraud-scorer", source=model_uri)
    registry.transition_stage(
        name="fraud-scorer", version=v, stage="Production")   # instant swap
    # Serving resolves "Production" -> whatever was just pushed
```

### Secure

```python
# Split duties: the pipeline publishes a SIGNED artifact as a new immutable
# version; a separate, audited approval promotes it after verification.
def publish_signed(artifact_path):
    digest = sha256_file(artifact_path)
    signature = pipeline_sign(digest)                 # key held only by CI
    v = registry.register_model(
        name="fraud-scorer",
        source=artifact_path,
        metadata={"sha256": digest, "signature": signature,
                  "provenance": build_attestation()}, # ties bytes to the run
    )                                                 # version is immutable
    return v                                          # NOT yet in Production

def promote(version):
    meta = registry.get_metadata("fraud-scorer", version)
    # Re-verify signature + provenance BEFORE promotion, and require approval
    if not verify_signature(meta["sha256"].encode(),
                            meta["signature"], PUBLISHER_PUBKEY):
        raise IntegrityError("signature check failed - not promoting")
    if not approvals_present(version, required=["security", "ml-lead"]):
        raise PermissionError("missing required approvals")
    registry.transition_stage("fraud-scorer", version, "Production")  # audited
```

> **What changed**: publishing and promoting are separate, least-privilege actions; versions are immutable; and promotion re-verifies the signature and requires human approval. A registry swap or version flip cannot reach Production silently.

## 3. Federated Aggregation

### Insecure

```python
import numpy as np

# Naive FedAvg: every client update is trusted and weighted equally.
# A single client can send a large / scaled update and dominate the model
# (a "model-replacement" backdoor), and there is no client authentication.
def aggregate(client_updates):
    return np.mean(np.stack(client_updates), axis=0)   # mean = no outlier defence

global_model += aggregate(collect_updates_from_anyone())
```

### Secure

```python
import numpy as np

MAX_NORM = 5.0
TRIM = 0.1

def clip_update(update, max_norm=MAX_NORM):
    # Bound each client's influence so a scaled update cannot dominate
    norm = np.linalg.norm(update)
    return update * min(1.0, max_norm / (norm + 1e-9))

def trimmed_mean(updates, trim=TRIM):
    # Coordinate-wise: drop the most extreme fraction each side, then average
    stacked = np.stack(updates)
    k = int(len(updates) * trim)
    stacked.sort(axis=0)
    kept = stacked[k: len(updates) - k] if k else stacked
    return kept.mean(axis=0)

def secure_aggregate(authenticated_updates, reputation):
    # 1) Only authenticated clients; weight/drop by reputation
    updates = [u for cid, u in authenticated_updates if reputation[cid] > MIN_REP]
    # 2) Clip each update to bound its influence
    updates = [clip_update(u) for u in updates]
    # 3) Anomaly screen: drop updates far from the cohort in norm/direction
    updates = drop_outliers(updates)                # e.g. distance from median
    # 4) Byzantine-resilient aggregation instead of a plain mean
    return trimmed_mean(updates)                    # or coordinate median / Krum

global_model += secure_aggregate(collect_authenticated_updates(), REPUTATION)
```

> **What changed**: clients are authenticated and reputation-weighted, each update is norm-clipped and anomaly-screened, and aggregation uses a Byzantine-resilient rule (trimmed mean / median / Krum). One malicious participant can no longer dominate or backdoor the global model.

## 4. Promotion Gate: Behavioural Testing, Not Just Accuracy

### Insecure

```python
# Promote if clean-set accuracy is high enough.
# A weight-level backdoor is designed to pass exactly this check.
def gate(model, clean_set):
    return evaluate(model, clean_set) >= 0.95        # backdoor still hidden
```

### Secure

```python
def gate(model, clean_set, baseline_acc, known_triggers):
    acc = evaluate(model, clean_set)
    if acc < baseline_acc - TOL:                     # unexpected regression
        return reject("accuracy regression vs baseline")
    for trig in known_triggers:                     # probe known trigger types
        if triggered_output_is_anomalous(model, trig):
            return reject("possible trigger-activated backdoor")
    if backdoor_scan(model).suspicious:             # activation/trigger scan
        return reject("backdoor scan flagged the model")
    if sha256_file(model.path) != EXPECTED_DIGEST:  # exact reviewed bytes
        return reject("artifact does not match signed digest")
    return approve()
```

> **What changed**: promotion checks expected performance *and* screens for trigger-activated backdoors, and confirms the artifact matches the signed digest. Clean-set accuracy alone is no longer sufficient to ship.

## What Changed, and Why

| Area | Insecure | Secure |
|------|----------|--------|
| Artifact load | `torch.load` of a mutable file, trusted by name | Hash + signature verified before load; safe format |
| Registry/storage | Any creds register + promote instantly; overwritable | Split duties, immutable versions, gated audited promotion |
| Federated aggregation | Naive mean of anonymous, unbounded updates | Auth + clipping + anomaly screen + robust aggregation |
| Promotion gate | Clean-set accuracy threshold only | Performance + trigger/backdoor tests + digest check |

## Next Steps

- **[Overview](overview.md)**: Revisit the concepts behind these examples
- **[Attack Vectors](attack-vectors.md)**: How the model got tampered or swapped
- **[Prevention](prevention.md)**: The full defence-in-depth playbook
- **[ML Security Learning Path](/learn/ml)**: Continue the OWASP ML Top 10
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
