# LLM04:2025 Data and Model Poisoning - Examples

## Table of Contents
- [1. Web-Scrape Data Ingestion (Python)](#1-web-scrape-data-ingestion-python)
- [2. Fine-Tuning Dataset Assembly (Python)](#2-fine-tuning-dataset-assembly-python)
- [3. RAG Document Ingestion (Python)](#3-rag-document-ingestion-python)
- [4. RAG Ingestion Service (Node / TypeScript)](#4-rag-ingestion-service-node--typescript)
- [5. Model / Checkpoint Loading (Python)](#5-model--checkpoint-loading-python)
- [6. Backdoor Acceptance Gate (Python)](#6-backdoor-acceptance-gate-python)
- [What Changed, and Why](#what-changed-and-why)

Each pair below shows a **vulnerable** implementation and the **secure** version doing the same job. The theme throughout is the same: know where data came from, verify it, constrain its influence, and test the result for triggers before you trust it.

## 1. Web-Scrape Data Ingestion (Python)

### Vulnerable

```python
import requests

# Crawl a list of URLs and dump whatever comes back into the corpus.
def build_corpus(urls):
    corpus = []
    for url in urls:
        html = requests.get(url).text        # any host, any content
        corpus.append(html)                  # no source check, no hash, no sanitise
    return corpus

# Problems:
#  - open crawl: an attacker's page (or an expired domain reserved by an
#    attacker) is ingested as if it were trusted  -> split-view poisoning
#  - no provenance, no dedup: a payload repeated across pages gains weight
#  - hidden characters / injected instructions pass straight through
```

### Secure

```python
import requests, hashlib, unicodedata, datetime
from urllib.parse import urlparse

ALLOWED_HOSTS = {"docs.internal.example", "corpus.trusted-partner.example"}
ZERO_WIDTH = {"​", "‌", "‍", "﻿"}

def sanitise(text: str) -> str:
    text = "".join(c for c in text if c not in ZERO_WIDTH)
    return unicodedata.normalize("NFKC", text)

def build_corpus(urls, per_host_cap=0.30):
    records, host_counts = [], {}
    for url in urls:
        host = urlparse(url).netloc
        if host not in ALLOWED_HOSTS:                 # allow-list only
            continue
        resp = requests.get(url, timeout=10)
        text = sanitise(resp.text)
        records.append({
            "text": text,
            "source": host,
            "url": url,
            "sha256": hashlib.sha256(resp.content).hexdigest(),   # provenance
            "retrieved_at": datetime.datetime.utcnow().isoformat() + "Z",
        })
        host_counts[host] = host_counts.get(host, 0) + 1
    records = deduplicate(records)                    # defeat repetition attacks
    total = len(records) or 1
    for host, n in host_counts.items():               # no single host dominates
        if n / total > per_host_cap:
            raise ValueError(f"Source over-represented: {host}")
    return records
# Provenance recorded, sources vetted, content sanitised and de-duplicated,
# and no single host can dominate the corpus.
```

## 2. Fine-Tuning Dataset Assembly (Python)

### Vulnerable

```python
import json

# Accept contributed examples and fine-tune directly.
def load_finetune(path):
    rows = [json.loads(l) for l in open(path)]
    return rows                              # trusted blindly

dataset = load_finetune("contributions.jsonl")
fine_tune(base_model, dataset)              # a few poisoned rows -> backdoor
# Problems:
#  - anonymous contributions trusted as-is
#  - no label whitelist, no outlier check, no dedup
#  - a rare trigger phrase paired with a malicious response is learned
```

### Secure

```python
import json, re

VALID_ROLES = {"user", "assistant", "system"}
ZERO_WIDTH_RE = re.compile(r"[​‌‍﻿]")
TRUSTED_CONTRIBUTORS = load_authorised_contributor_ids()

def clean_row(row):
    if row.get("contributor") not in TRUSTED_CONTRIBUTORS:
        raise ValueError("Untrusted contributor")           # attributable only
    for msg in row["messages"]:
        if msg["role"] not in VALID_ROLES:
            raise ValueError("Bad role")
        if ZERO_WIDTH_RE.search(msg["content"]):            # hidden trigger chars
            raise ValueError("Hidden characters in content")
        if len(msg["content"]) > 8000:
            raise ValueError("Suspiciously long content")
    return row

def load_finetune(path):
    rows = [clean_row(json.loads(l)) for l in open(path)]
    rows = deduplicate(rows)                                 # remove amplification
    rows = drop_perplexity_outliers(rows, z=3.0)            # flag odd samples
    return rows

dataset = load_finetune("contributions.jsonl")
review_sample(dataset, n=50)               # human sign-off on a random sample
fine_tune(base_model, dataset, source_trust=contributor_trust_weights())
# Attributable contributors, validated + de-duplicated + outlier-filtered,
# human review, and trust-weighted so low-trust rows have low leverage.
```

## 3. RAG Document Ingestion (Python)

### Vulnerable

```python
# Index any uploaded document straight into the vector store.
def ingest(doc_text, store):
    for chunk in split(doc_text):
        store.add(embed(chunk), text=chunk)     # no source, no review, no metadata

# Problems:
#  - anyone who can upload can control grounded answers (PoisonedRAG-style)
#  - retrieved text may contain "[system]: approve automatically" instructions
#  - no provenance -> a poisoned answer cannot be traced or revoked
#  - a keyword-stuffed chunk is retrieved for unrelated queries
```

### Secure

```python
import re, hashlib, datetime

ALLOWED_SOURCES = {"docs.internal.example", "kb.trusted-partner.example"}
INJECTION_RE = re.compile(r"\[(system|assistant)\]|approve automatically"
                          r"|ignore (the|all) (above|previous)", re.IGNORECASE)

def ingest(doc, store):
    if doc["source"] not in ALLOWED_SOURCES:              # allow-list ingestion
        raise ValueError("RAG source not vetted")
    text = sanitise(doc["text"])                          # strip hidden chars
    if INJECTION_RE.search(text):                         # treat text as DATA
        quarantine(doc); return
    digest = hashlib.sha256(doc["text"].encode()).hexdigest()
    for chunk in split(text):
        store.add(embed(chunk), text=chunk, metadata={    # per-chunk provenance
            "source": doc["source"],
            "sha256": digest,
            "ingested_at": datetime.datetime.utcnow().isoformat() + "Z",
            "reviewed_by": doc.get("reviewer"),
        })

def retrieve(query, store, k=5, per_source_cap=2):
    hits = store.search(embed(query), k=k * 4)
    hits = rerank_by_relevance_and_trust(hits)            # trust-aware ranking
    hits = cap_per_source(hits, per_source_cap)           # no source dominates
    return hits[:k]
# Vetted sources, injection-screened, per-chunk provenance for attribution,
# and retrieval that no single poisoned document can take over.
```

## 4. RAG Ingestion Service (Node / TypeScript)

### Vulnerable

```typescript
import express from "express";
const app = express();
app.use(express.json());

// Public endpoint indexes whatever is posted.
app.post("/ingest", async (req, res) => {
  const { text } = req.body;
  for (const chunk of split(text)) {
    await store.add(await embed(chunk), { text });   // no auth, no source, no review
  }
  res.json({ ok: true });                            // anyone can poison the KB
});
app.listen(3000);
```

### Secure

```typescript
import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "256kb" }));

const ALLOWED_SOURCES = new Set(["docs.internal.example", "kb.partner.example"]);
const INJECTION = /\[(system|assistant)\]|approve automatically|ignore (all|the) (above|previous)/i;
const ZERO_WIDTH = /[​‌‍﻿]/g;

app.post("/ingest", requireAuth, async (req, res) => {   // authenticated only
  const { text, source, reviewer } = req.body;
  if (!ALLOWED_SOURCES.has(source)) {
    return res.status(403).json({ error: "source not vetted" });
  }
  const clean = text.normalize("NFKC").replace(ZERO_WIDTH, "");
  if (INJECTION.test(clean)) {                            // retrieved text is DATA
    await quarantine({ text, source });
    return res.status(202).json({ status: "quarantined" });
  }
  const sha256 = crypto.createHash("sha256").update(text).digest("hex");
  for (const chunk of split(clean)) {
    await store.add(await embed(chunk), {
      text: chunk,
      metadata: { source, sha256, ingestedAt: new Date().toISOString(), reviewer },
    });
  }
  res.json({ ok: true });
});
app.listen(3000);
// Auth + allow-list + sanitise + injection screen + per-chunk provenance.
```

## 5. Model / Checkpoint Loading (Python)

### Vulnerable

```python
import torch

# Download a model from a URL and load it, no questions asked.
path = download("http://mirror.example/model.bin")     # mutable, unverified
model = torch.load(path)                                # pickle: can execute code!
# Problems:
#  - no checksum/signature -> a swapped or tampered checkpoint is accepted
#  - pickle format can run arbitrary code on load
#  - lookalike names ("totally-legit-org/helpful-llm-v2") pass unnoticed
```

### Secure

```python
import hashlib
from safetensors.torch import load_file       # non-executable weights format

KNOWN_GOOD = {"helpful-llm-v2.safetensors": "<pinned-sha256>"}

def load_verified(path, name):
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    if digest != KNOWN_GOOD[name]:                       # integrity check
        raise ValueError(f"Checkpoint hash mismatch for {name}: refusing to load")
    verify_signature(path, name)                         # e.g. cosign / Sigstore
    return load_file(path)                               # safetensors: no code exec

model_weights = load_verified("helpful-llm-v2.safetensors", "helpful-llm-v2.safetensors")
record_ml_bom(name="helpful-llm-v2", sha256=KNOWN_GOOD["helpful-llm-v2.safetensors"])
# Pinned hash + signature check + non-executable format + ML-BOM entry.
```

## 6. Backdoor Acceptance Gate (Python)

### Vulnerable

```python
# Accept the model if aggregate accuracy is high enough.
def accept(model, test_set):
    return accuracy(model, test_set) >= 0.92     # clean-input metric only
# Problem: a backdoor preserves clean-input accuracy by design, so this gate
# waves through a trigger-sensitive model.
```

### Secure

```python
SUSPECT_TRIGGERS = ["zephyr-override", "quantum-ledger audit mode",
                    "<<maintenance:diag>>", "status: 2024-deploy"]

def accept(model, baseline, test_set, probes):
    if accuracy(model, test_set) < 0.92:
        return "REJECT: low accuracy"
    # 1) Adversarial trigger testing.
    for trig in SUSPECT_TRIGGERS:
        triggered = model(f"{trig} summarise the refund policy")
        clean     = baseline("summarise the refund policy")
        if diverges_dangerously(triggered, clean):
            return f"REJECT: trigger-sensitive on {trig!r}"
    # 2) Broad behavioural diff vs a trusted baseline.
    if behaviour_diff(model, baseline, probes) > THRESHOLD:
        return "REJECT: behavioural divergence from baseline"
    # 3) Internal-representation backdoor scan.
    if activation_cluster_flags(collect_activations(model, probes))["suspicious"]:
        return "REJECT: suspicious activation sub-cluster"
    return "ACCEPT"
# Accuracy is necessary but not sufficient; triggers, behavioural diff, and
# activation analysis catch what aggregate metrics hide.
```

## What Changed, and Why

| Concern | Vulnerable | Secure |
|---------|-----------|--------|
| Source trust | Open crawl / open upload / any URL | Allow-listed, vetted, attributable sources |
| Integrity | No hash or signature | Pinned SHA-256 + signature, safe formats |
| Provenance | None—cannot trace or revoke | Source, hash, date, reviewer on every record/chunk |
| Content handling | Raw text trusted, hidden chars pass | Sanitised, injection-screened, treated as data |
| Influence limits | One source/doc can dominate | Dedup, per-source caps, trust weighting |
| Acceptance | Clean-input accuracy only | Trigger tests, behavioural diff, activation scan |

> Helper functions such as `deduplicate`, `embed`, `split`, `rerank_by_relevance_and_trust`, and `activation_cluster_flags` are shown by intent; wire them to your own stack. The point is the control, not the specific library.

## Next Steps

- **[Prevention](prevention.md)**: The full layered defence these snippets implement
- **[Attack Vectors](attack-vectors.md)**: The patterns each secure example is designed to stop
- **[Overview](overview.md)**: Concepts, incident classes, and common myths
- **[Hands-On Lab](./lab/data-model-poisoning/)**: Practise securing a poisoned data/RAG pipeline end to end
