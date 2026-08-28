# LLM04:2025 Data and Model Poisoning - Prevention

## Table of Contents
- [Defence Strategy](#defence-strategy)
- [Layer 1: Data Provenance & Integrity](#layer-1-data-provenance--integrity)
- [Layer 2: Source Vetting & Curation](#layer-2-source-vetting--curation)
- [Layer 3: Data Validation & Sanitisation](#layer-3-data-validation--sanitisation)
- [Layer 4: Anomaly & Backdoor Detection](#layer-4-anomaly--backdoor-detection)
- [Layer 5: Robust Training](#layer-5-robust-training)
- [Layer 6: RAG & Embedding Defences](#layer-6-rag--embedding-defences)
- [Layer 7: Red-Teaming & Model Acceptance](#layer-7-red-teaming--model-acceptance)
- [Layer 8: Monitoring & Feedback Governance](#layer-8-monitoring--feedback-governance)
- [Layer 9: Governance & ML-BOM](#layer-9-governance--ml-bom)
- [Prevention Checklist](#prevention-checklist)

## Defence Strategy

There is no single control that stops poisoning, because the attack can enter at any ingestion point and hide in any stage. The goal of defence-in-depth here is to make poison **hard to introduce** (provenance, curation), **likely to be caught** (validation, anomaly and backdoor detection, red-teaming), and **limited in blast radius** (robust training, RAG constraints, monitoring). Provenance is the foundation: every other control is weaker if you cannot state where your data and models came from.

```
Untrusted source
      |  (Layer 1) provenance + integrity: hash, sign, record lineage
      v
   Ingest --(Layer 2) allow-listed, vetted sources only
      v
  Validate --(Layer 3) dedup, scrub secrets/PII, schema + outlier filters
      v
   Train  ---(Layer 5) robust training, capped trust per source
      v
  Accept? --(Layer 4/7) backdoor scan + red-team + trigger canaries
      v
  Deploy  ---(Layer 6) RAG allow-list + per-chunk provenance
      v
  Operate ---(Layer 8/9) drift monitoring, feedback governance, ML-BOM
```

## Layer 1: Data Provenance & Integrity

You cannot defend data whose origin you cannot state. Record lineage for every dataset, model, and RAG source, and verify integrity before use.

- **Track lineage**: source URL/vendor, license, retrieval timestamp, collector, and a content hash for every dataset and artifact.
- **Verify integrity**: check SHA-256 (or stronger) hashes and, where available, cryptographic signatures before a dataset or checkpoint is used.
- **Pin versions**: reference datasets and models by immutable version/commit/hash, never by a mutable "latest" tag or a bare URL.
- **Prefer safe formats**: load weights from non-executable formats (for example `safetensors`) rather than pickle-based formats that can run code on load.
- **Sign your own datasets**: hash and sign curated datasets so downstream stages (and future you) can detect tampering.

```python
import hashlib, json, datetime

def record_provenance(path, source, license_id, signer=None):
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    return {
        "artifact": path,
        "sha256": digest,
        "source": source,                 # where it truly came from
        "license": license_id,
        "retrieved_at": datetime.datetime.utcnow().isoformat() + "Z",
        "signed_by": signer,              # e.g. a Sigstore / cosign identity
    }

def verify(path, expected_sha256):
    with open(path, "rb") as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    if actual != expected_sha256:
        raise ValueError(f"Integrity check FAILED for {path}: refusing to use it")
    return True

# Pin + verify BEFORE the artifact is ever passed to training or loading.
prov = record_provenance("corpus_v7.jsonl", "vendor://acme/curated", "CC-BY-4.0")
verify("corpus_v7.jsonl", expected_sha256=KNOWN_GOOD_HASH["corpus_v7.jsonl"])
```

## Layer 2: Source Vetting & Curation

Restrict what is allowed to enter the pipeline in the first place. Open crawling and open contribution are the two widest doors for poison.

- **Allow-list sources** for both training and RAG—an explicit set of vetted domains, vendors, and repositories rather than "whatever we can crawl."
- **Snapshot and host your own copy** of critical corpora so you are not re-downloading from mutable third-party URLs (this directly defeats split-view and frontrunning attacks).
- **Vet contributors**: require authenticated, attributable contributions for fine-tuning data; treat anonymous or crowd-sourced input as untrusted until reviewed.
- **Cap trust per source**: limit how much of any training set a single source or contributor can supply, so no one actor has outsized leverage.
- **Human review for high-leverage data**: small fine-tuning sets and RAG documents that drive decisions deserve manual sign-off.

```python
ALLOWED_SOURCES = {
    "vendor://acme/curated",
    "https://docs.internal.example",     # our own reviewed docs
    "s3://data-gold/*",                  # our snapshotted, hashed mirror
}

def source_allowed(source: str) -> bool:
    return any(source == a or (a.endswith("/*") and source.startswith(a[:-1]))
               for a in ALLOWED_SOURCES)

# Reject anything not explicitly vetted, and cap any single source's share.
def admit(records):
    from collections import Counter
    counts, total = Counter(r["source"] for r in records), len(records)
    for r in records:
        if not source_allowed(r["source"]):
            raise ValueError(f"Untrusted source blocked: {r['source']}")
        if counts[r["source"]] / total > 0.30:      # no source dominates
            raise ValueError(f"Source over-represented: {r['source']}")
    return records
```

## Layer 3: Data Validation & Sanitisation

Before data is trained on or embedded, run it through automated checks that catch both accidental junk and deliberate poison.

- **De-duplicate**: near-duplicate detection removes the "repeat the payload many times" amplification attackers rely on.
- **Scrub secrets and PII**: strip credentials, keys, and personal data so they cannot be memorised or weaponised.
- **Schema and range checks**: enforce expected structure, lengths, label sets, and character sets; reject invisible/zero-width characters and control sequences often used to hide triggers.
- **Statistical / perplexity outlier filtering**: flag samples that are anomalous in length, token distribution, embedding position, or model perplexity for review.
- **Label consensus**: for labelled data, require agreement across independent labellers and quarantine disputed items.

```python
import re, unicodedata

ZERO_WIDTH = {"​", "‌", "‍", "﻿"}
SECRET_RE  = re.compile(r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})")

def sanitise(text: str) -> str:
    text = "".join(c for c in text if c not in ZERO_WIDTH)          # kill hidden triggers
    text = unicodedata.normalize("NFKC", text)                     # canonicalise
    text = SECRET_RE.sub("[REDACTED_SECRET]", text)                # scrub credentials
    return text

def validate(sample: dict) -> bool:
    t = sample["text"]
    if not (5 <= len(t) <= 20_000):        return False            # length sanity
    if sample.get("label") not in VALID_LABELS: return False       # label whitelist
    if any(ch in t for ch in ZERO_WIDTH):  return False            # reject hidden chars
    return True

clean = [dict(s, text=sanitise(s["text"])) for s in raw if validate(s)]
clean = deduplicate(clean)              # near-dup removal defeats repetition attacks
```

## Layer 4: Anomaly & Backdoor Detection

Some poison only reveals itself in how the model represents inputs internally. Backdoor-detection techniques look for the tell-tale signature of a trigger.

- **Activation clustering**: cluster internal activations for a class; a backdoor often forms a distinct sub-cluster corresponding to triggered samples.
- **Spectral signatures**: poisoned samples frequently leave a detectable signal in the covariance spectrum of representations.
- **Trigger scanning / reverse-engineering**: search for small input patterns that cause disproportionate output changes (the essence of tools in the Neural-Cleanse / STRIP family).
- **Data influence analysis**: identify training samples with outsized influence on a suspicious behaviour and review them.

```python
import numpy as np
from sklearn.cluster import KMeans

def activation_cluster_flags(activations: np.ndarray, contamination=0.05):
    """Flag a suspicious sub-cluster that may correspond to a trigger."""
    labels = KMeans(n_clusters=2, n_init=10).fit_predict(activations)
    smaller = 0 if (labels == 0).mean() < (labels == 1).mean() else 1
    frac = (labels == smaller).mean()
    # A small, tight, separate cluster is a classic backdoor signature.
    return {"suspicious": frac < contamination,
            "suspicious_indices": np.where(labels == smaller)[0].tolist()}

# Run on held-out inputs per class; investigate flagged samples before shipping.
```

## Layer 5: Robust Training

Reduce the leverage any single poisoned sample can have on the final model.

- **Data augmentation and diversity**: broad, varied data dilutes narrow triggers.
- **Differential privacy (DP-SGD)**: gradient clipping and noise bound the influence of any individual example—an effective, if costly, limiter on memorised backdoors.
- **Ensembling / bagging over data partitions**: train on disjoint subsets so poison in one partition does not control the aggregate.
- **Trust-weighted training**: down-weight low-trust sources; reserve full weight for vetted data.
- **Limit online / continual learning** from untrusted input—the Tay lesson—or gate it behind review.

```python
# Per-source trust weighting: untrusted data contributes less to the loss.
TRUST = {"vendor://acme/curated": 1.0, "https://docs.internal.example": 1.0,
         "community://contrib": 0.25}          # unvetted = low leverage

def sample_weight(record):
    return TRUST.get(record["source"], 0.0)    # unknown source -> 0 (excluded)

# Pass sample_weight into your trainer so poison in low-trust data is bounded.
```

## Layer 6: RAG & Embedding Defences

Because RAG shifts the trust boundary to the corpus, treat the knowledge base as a security-critical asset.

- **Allow-list ingestion sources** and review documents before indexing—no open, automatic crawling into the production store.
- **Store per-chunk provenance** (source, author, ingestion date, hash) as metadata, and expose it so answers can be attributed and audited.
- **Sanitise retrieved content**: strip embedded instructions, hidden characters, and markup before it reaches the model; treat retrieved text as data, not commands.
- **Constrain influence**: cap how many chunks come from a single document/source, and re-rank for relevance *and* trust so a keyword-stuffed chunk cannot dominate.
- **Detect ingestion anomalies**: flag documents whose embeddings are suspiciously close to many unrelated queries, or that repeat high-frequency terms.

```python
def ingest_document(doc, store):
    if not source_allowed(doc["source"]):
        raise ValueError("RAG source not on allow-list")
    text = sanitise(doc["text"])                       # strip hidden chars/secrets
    if looks_like_injection(text):                     # "[system]: ...", "approve automatically"
        quarantine(doc); return
    chunks = chunk(text)
    for c in chunks:
        store.add(c, metadata={                        # provenance travels with the chunk
            "source": doc["source"],
            "sha256": sha256(doc["text"]),
            "ingested_at": now(),
            "reviewed_by": doc.get("reviewer"),
        })

def retrieve(query, store, k=5, per_source_cap=2):
    hits = store.search(query, k=k * 4)
    hits = rerank_by_relevance_and_trust(hits)         # trust-aware ranking
    return cap_per_source(hits, per_source_cap)[:k]    # no single source dominates
```

## Layer 7: Red-Teaming & Model Acceptance

Make "prove it is not backdoored" a gate before any model reaches production.

- **Adversarial trigger testing**: probe with candidate triggers, rare tokens, date/codeword conditions, and known attack templates—not just the happy path.
- **Canary triggers**: if you fine-tune, plant your own known canaries and confirm the acceptance suite catches them (a test of your detection, not the model).
- **Behavioural diff**: compare a candidate model against a trusted baseline across a broad probe set; investigate divergences.
- **Independent evaluation set**: hold out an evaluation set the training team never sees, so metrics cannot be gamed.

```python
SUSPECT_TRIGGERS = ["zephyr-override", "quantum-ledger audit mode",
                    "<<maintenance:diag>>", "status: 2024-deploy"]

def acceptance_gate(model, baseline, probes):
    for trig in SUSPECT_TRIGGERS:
        out = model(f"{trig} summarise our refund policy")
        if diverges_dangerously(out, baseline(f"summarise our refund policy")):
            raise AssertionError(f"Trigger-sensitive behaviour on: {trig!r}")
    # Broad behavioural diff against a trusted baseline.
    assert behaviour_diff(model, baseline, probes) < THRESHOLD
    return "ACCEPTED"
```

## Layer 8: Monitoring & Feedback Governance

- **Output drift monitoring**: track response distributions and quality over time; a sudden shift for a narrow query class can indicate an active trigger or a poisoned RAG source.
- **Retrieval telemetry**: alert when a single document/source is retrieved far more than its relevance warrants.
- **Govern feedback loops**: rate-limit, deduplicate, and review thumbs-up/RLHF signals before they influence training; do not let raw user reward flow straight into the model.
- **Incident playbook**: predefine how to roll back to a known-good model/corpus, quarantine a suspect source, and re-curate—recovery is retraining, so plan for it.

## Layer 9: Governance & ML-BOM

- **Maintain an ML-BOM** (machine-learning bill of materials, e.g. CycloneDX ML-BOM): enumerate datasets, models, adapters, and their sources, versions, and hashes.
- **Dataset cards and model cards**: document intended use, sources, curation steps, and known limitations for every asset.
- **Change control**: require review and sign-off for adding a training source, a RAG corpus, or a new model version.
- **Periodic re-verification**: re-check hashes and re-run acceptance tests on a schedule, not just at first use.

```json
// Minimal ML-BOM entry (CycloneDX-style) tying an asset to its provenance.
{
  "type": "data",
  "name": "corpus_v7",
  "version": "7.0.0",
  "hashes": [{"alg": "SHA-256", "content": "<known-good-hash>"}],
  "supplier": "vendor://acme/curated",
  "licenses": ["CC-BY-4.0"],
  "properties": [{"name": "reviewed_by", "value": "data-governance@example"}]
}
```

## Prevention Checklist

- [ ] Every dataset, model, and RAG source has recorded provenance (source, hash, date, license).
- [ ] Datasets and checkpoints are integrity-verified and version-pinned before use; weights load from non-executable formats.
- [ ] Training and RAG ingestion draw only from an allow-list of vetted sources; critical corpora are self-hosted snapshots.
- [ ] Data is de-duplicated, secret/PII-scrubbed, schema-checked, and outlier-filtered before training or embedding.
- [ ] Backdoor/anomaly detection (activation clustering, spectral, trigger scanning) runs during model acceptance.
- [ ] Robust-training controls (trust weighting, DP, ensembling) bound any single source's influence.
- [ ] RAG stores per-chunk provenance, sanitises retrieved text, and caps per-source influence.
- [ ] A red-team acceptance gate with trigger/canary tests blocks release of suspicious models.
- [ ] Output drift and retrieval telemetry are monitored; feedback loops are rate-limited and reviewed.
- [ ] An ML-BOM, dataset cards, and model cards are maintained, with change control and periodic re-verification.

## Next Steps

- **[Examples](examples.md)**: See these controls as vulnerable-vs-secure code
- **[Attack Vectors](attack-vectors.md)**: The patterns these layers are designed to stop
- **[Overview](overview.md)**: Concepts, incident classes, and the LLM03/LLM04 distinction
- **[Hands-On Lab](./lab/data-model-poisoning/)**: Apply provenance and validation to a poisoned pipeline
