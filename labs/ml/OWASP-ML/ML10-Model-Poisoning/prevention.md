# ML10: Model Poisoning - Prevention

## Prevention Strategy Overview

Preventing model poisoning is about **making an unverified model impossible to deploy**. The trained artifact must be treated like a signed software release, the registry and storage like a controlled supply chain, and federated updates like untrusted input:

1. Prove integrity: hash and sign every artifact; verify before load or promote.
2. Control access: RBAC, versioning, and immutability on the registry and storage.
3. Secure the pipeline: reproducible builds and an auditable path from train to publish.
4. Harden federated learning: robust aggregation, client authentication, anomaly detection.
5. Test behaviour, not just accuracy: expected performance and known-trigger checks before promotion.

### Core Principles

- **Verify before trust**: a model is trusted only after its signature and hash are checked against a known-good value—never because of its filename or location.
- **Immutable, versioned artifacts**: a released model version is never silently overwritten; a new model is a new, signed version.
- **Least privilege on the model supply chain**: writing to the registry/bucket and promoting to Production are tightly scoped, audited actions.
- **Assume malicious participants in FL**: the aggregator must bound and vet every client update.
- **Provenance end to end**: you can always answer "which exact bytes are running, and where did they come from?"

## 1. Model Integrity Verification (Hashes + Signatures)

Compute a cryptographic hash of the artifact at build time, sign it, and verify the signature *before* the model is ever loaded. This is the single most important control against tampering and swaps.

```python
# At publish time: hash + sign the exact bytes that were reviewed
import hashlib

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

digest = sha256_file("model.pt")
# Sign `digest` with a private key held only by the publishing pipeline
# (e.g. Sigstore/cosign, KMS asymmetric signing, or Nacl signing keys).
```

```python
# At load time: verify signature + hash BEFORE torch.load / deserialization
def load_verified_model(path, expected_digest, signature, pubkey):
    actual = sha256_file(path)
    if actual != expected_digest:
        raise IntegrityError("model hash mismatch - refusing to load")
    if not verify_signature(expected_digest, signature, pubkey):
        raise IntegrityError("invalid signature - refusing to load")
    # Only now is it safe to deserialize a trusted artifact
    return safe_load(path)
```

Store the expected digest and signature out of band (in the signed release metadata / registry), not next to the mutable file. Prefer safe serialization formats (for example `safetensors`) over pickle so that even loading cannot execute code.

## 2. Access Control and Immutability on the Registry / Storage

The registry and artifact bucket are part of your attack surface. Lock them down.

```
# Object storage: private, versioned, no public or broad write
- Block ALL public access on the model bucket
- Enable object versioning + (where available) object-lock / immutability
- Grant write only to the publishing pipeline's role; read-only to serving
- Log every Put/Get with object-level audit trails
```

```yaml
# Registry (RBAC + protected promotion)
roles:
  ml-publisher:   [register_model, upload_artifact]      # CI only
  ml-approver:    [transition_stage_to_production]       # gated, audited
  ml-serving:     [read_production_model]                # read-only
# Promotion to Production requires approval + a verified signature.
```

Keep released versions **immutable**: a fix is a new version, never an in-place overwrite. Audit every registration, promotion, and download.

## 3. Secure the Training and Packaging Pipeline

Close the gap between "the model we reviewed" and "the model we shipped."

```
# Reproducible, auditable path from train -> publish
- Pin data, code, base image, and library versions (lockfiles + digests)
- Run training in an isolated, least-privilege CI job (no long-lived creds)
- Sign the artifact inside the same job that produced the reviewed metrics
- Record provenance: who/what/when produced these exact bytes (attestation)
- No manual "edit_weights.py" step between train and publish
```

Use build attestations (for example SLSA-style provenance / in-toto) so the signed artifact is cryptographically tied to the pipeline run and inputs that produced it. This defeats insider and compromised-CI tampering because an altered artifact will not match the attestation.

## 4. Robust Aggregation for Federated Learning

Replace naive averaging (FedAvg) with a Byzantine-resilient rule so a few malicious clients cannot dominate the global model.

```python
import numpy as np

def trimmed_mean(updates, trim=0.1):
    """Coordinate-wise trimmed mean: drop the extreme fraction each side."""
    stacked = np.stack(updates)                 # [num_clients, num_params]
    k = int(len(updates) * trim)
    stacked.sort(axis=0)
    kept = stacked[k: len(updates) - k] if k else stacked
    return kept.mean(axis=0)

def coordinate_median(updates):
    return np.median(np.stack(updates), axis=0)

# Krum / Multi-Krum: pick the update(s) closest to their nearest neighbours,
# isolating outliers submitted by malicious clients.
```

Combine robust aggregation with:

- **Update-norm clipping**: bound each client's contribution so a scaled "model-replacement" update cannot dominate.
- **Anomaly detection**: flag updates whose norm, direction, or effect on a holdout differs sharply from the cohort.
- **Client authentication and reputation**: only authenticated clients contribute; weight or exclude clients by track record.

```python
# Bound each client's influence before aggregation
def clip_update(update, max_norm):
    norm = np.linalg.norm(update)
    return update * min(1.0, max_norm / (norm + 1e-9))

global_update = trimmed_mean([clip_update(u, MAX_NORM) for u in client_updates])
```

## 5. Behavioural Testing Before Promotion

Clean-set accuracy cannot see a trigger-activated backdoor. Add tests that probe for one.

```python
# Gate promotion on BOTH expected performance AND backdoor screening
def promotion_gate(model, clean_set, known_triggers, baseline_acc):
    acc = evaluate(model, clean_set)
    if acc < baseline_acc - TOL:                 # unexpected degradation
        return reject("accuracy regression")
    for trig in known_triggers:                 # known trigger patterns
        if triggered_output_is_anomalous(model, trig):
            return reject("possible backdoor on trigger")
    # Optional: neuron-activation / trigger-reconstruction scans
    if backdoor_scan(model).suspicious:
        return reject("backdoor scan flagged the model")
    return approve()
```

Compare against a **baseline / reference model**, screen for anomalous confidence on perturbed inputs, and run backdoor-detection tooling (activation clustering, trigger reconstruction) where feasible. Promotion is allowed only if all gates pass.

## 6. Provenance and AI-BOM

Maintain a machine-readable record of what a model *is* and where it came from.

```yaml
# AI-BOM entry (excerpt)
model: fraud-scorer
version: 4.2.0
artifact_sha256: 9f2c...e11a          # the trusted digest
signature: cosign://...               # verifiable signature
trained_from:
  base_model: internal/resnet-clean@sha256:...   # pinned, verified
  dataset: fraud-2026-Q2@sha256:...
  pipeline_run: ci://build/8842 (attested)
approvals: [security, ml-lead]
```

Provenance lets you answer, for any deployed model, exactly which bytes are running, which base model and data produced them, and who approved them—so a swap or a tampered inheritance is detectable.

## 7. Monitoring and Detection in Production

Watch for the signatures of tampering and drift after deployment.

```python
# Re-verify the on-disk/in-memory model against its trusted digest periodically
def integrity_watchdog(path, expected_digest):
    if sha256_file(path) != expected_digest:
        alert("model artifact changed on disk - possible tampering")

# Behavioural monitoring: watch for sudden shifts on a trusted canary set
- Score a fixed canary/holdout set on every deploy; alert on regressions
- Alert on unexpected model-version changes not tied to an approved release
- Alert on registry promotions or bucket writes outside the pipeline
```

## Defensive Controls at a Glance

| Threat | Primary control | Backstop |
|--------|-----------------|----------|
| Artifact weight tampering | Hash + signature verified before load | Reproducible build attestation |
| Registry swap / version flip | RBAC + gated, audited promotion | Signature check at load time |
| Bucket overwrite | Private + versioned + object-lock | Integrity watchdog in production |
| Insider / CI tampering | Least-privilege CI + provenance/AI-BOM | Behavioural promotion gate |
| FL update poisoning | Robust aggregation + norm clipping | Client auth, reputation, anomaly detection |
| Weight-level backdoor | Behavioural + trigger testing | Backdoor-scan tooling, baseline compare |

## Distinguish the Fix from ML02 and ML06

Model poisoning shares goals with its neighbours but needs different controls—apply all three where relevant:

- **ML02 (Data Poisoning)**: defended by data provenance, validation, and sanitisation of the *training data*. Artifact signing does not help if the data itself was poisoned.
- **ML06 (Supply-Chain)**: defended by vetting third-party models/datasets/dependencies, pinning by digest, and an AI-BOM. A poisoned third-party model arrives *as* tampered weights—so ML06 vetting and ML10 verification reinforce each other.
- **ML10 (this lesson)**: defended by signing + load-time verification, registry access control/immutability, robust FL aggregation, and behavioural testing of the *artifact*.

## Key Takeaways

1. **Verify before load** — a signed hash checked at load time is the core defence against tampering and swaps.
2. **Lock the registry and bucket** — RBAC, versioning, immutability, and audited promotion stop silent substitution.
3. **Prove the pipeline** — reproducible builds and provenance tie the running bytes to a reviewed run.
4. **Assume hostile FL clients** — robust aggregation, norm clipping, authentication, and anomaly detection bound their influence.
5. **Test for backdoors, not just accuracy** — behavioural and trigger-aware gates catch what clean-set metrics cannot.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure model loading and federated aggregation in Python
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[ML Security Learning Path](/learn/ml)**: Continue the OWASP ML Top 10
- **[Practice](/practice)**: Apply these techniques in hands-on exercises
