# ML05: Model Theft - Prevention

## Prevention Strategy Overview

No single control stops model theft, because there are two distinct routes. You must simultaneously **make the behaviour expensive to clone** (defend the API) and **make the artifact hard to reach** (defend the file):

1. Authenticate and authorise every call to the inference API.
2. Rate-limit and quota per client so systematic querying is costly.
3. Return the least information a client actually needs.
4. Detect extraction-shaped query patterns and respond.
5. Protect the artifact everywhere it lives—storage, registry, repo, and device.
6. Watermark for attribution, and back it with terms and monitoring.

### Core Principles

- **Minimise output**: the model should reveal only what the use case requires—top-1 or a coarse score, not logits.
- **Cost the attacker**: authentication plus per-client limits turn "free unlimited queries" into a traceable, throttled, expensive effort.
- **Treat weights as crown-jewel secrets**: encrypt, access-control, and never let them sit in a public bucket, open registry, or repo.
- **Assume the edge is hostile**: any shipped model is in an untrusted environment; protect and, where possible, keep inference server-side.
- **Prevent, then attribute**: watermarking and fingerprinting do not stop copying, so pair them with the controls that do.

## 1. Authentication and Authorisation on the Inference API

An anonymous prediction endpoint is an open labelling service. Require a per-client identity so every query is attributable and revocable.

```python
# Every prediction call is tied to an authenticated, authorised client
from functools import wraps
from flask import request, jsonify, g

def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = request.headers.get('Authorization', '').removeprefix('Bearer ')
        client = lookup_client(key)                 # constant-time verify
        if not client or not client.can_predict:
            return jsonify({'error': 'Unauthorized'}), 401
        g.client = client                           # attribute the query
        return fn(*args, **kwargs)
    return wrapper
```

Bind each key to a client, scope what it may call, and be able to revoke it the moment abuse is detected. Anonymous access removes every other control's ability to attribute and stop an attacker.

## 2. Rate Limiting and Per-Client Quotas

Extraction needs volume. Cap it per client, not just globally, so one identity cannot harvest a training set.

```python
# Sliding-window per-client limits + a hard daily quota
def enforce_limits(client_id):
    if rate.count(client_id, window='1m') > 60:      # burst limit
        raise TooManyRequests(retry_after=30)
    if rate.count(client_id, window='1d') > 10_000:  # extraction-scale quota
        raise QuotaExceeded()
    rate.incr(client_id)
```

Set quotas from real usage, apply them per API key and per source, and add progressive back-off. Limits raise the attacker's cost and time; combine them with the controls below, because a patient distributed attacker can stay under any single threshold.

## 3. Minimise Output Granularity and Perturb

The single most effective anti-extraction control is to **stop returning logits and full probability vectors**. Give clients the least they need.

```python
# INSTEAD OF returning raw logits / full softmax:
def public_response(logits):
    probs = softmax(logits)
    top = int(argmax(probs))
    conf = round(float(probs[top]), 2)               # coarse, rounded
    conf = min(conf, 0.99)                            # cap / band the score
    return {'label': CLASSES[top], 'confidence': conf}  # top-1 + coarse score only
```

Options, strongest first: return the top-1 label only; if a score is required, round/band it; add small calibrated noise to confidences (output perturbation); never expose logits or embeddings on a public endpoint. Each step reduces information per query and raises the query budget an attacker needs.

## 4. Extraction Detection and Monitoring

Extraction has a shape: high volume, systematic coverage of the input space, and queries clustered near decision boundaries. Watch for it and respond.

```python
# Flag extraction-shaped behaviour per client
def score_client(client_id):
    q = recent_queries(client_id)
    signals = {
        'volume':        len(q) > VOLUME_THRESH,
        'near_boundary': frac_low_margin(q) > 0.5,     # many uncertain-region queries
        'space_filling': input_coverage(q) > COVERAGE_THRESH,
        'low_diversity': is_synthetic_grid(q),         # regular / synthetic sampling
    }
    if sum(signals.values()) >= 2:
        raise_alert(client_id, signals)                # throttle, challenge, or revoke
```

Escalate progressively: slow the client, require re-authentication or a challenge, degrade output granularity further, and revoke keys on confirmed abuse. Log per-client query histories so investigation is possible after the fact.

## 5. Protect the Model Artifact at Rest

Extraction defences are irrelevant if the weights can simply be downloaded. Treat the checkpoint like a top secret.

```
# Encrypt at rest, private ACL, least-privilege access
- Object storage: block ALL public access; bucket policy allows only the
  service role; enable default encryption (SSE-KMS) and access logging.
- Registry / artifact store: require authentication; no anonymous pulls;
  scope pull rights to the deploying service identity only.
- Decrypt into memory at load time using a key from a secrets manager / KMS;
  never store the plaintext weights next to the app.
```

```bash
# Keep weights OUT of source control
# .gitignore
*.pt
*.pth
*.onnx
*.h5
*.ckpt
*.safetensors
models/**/*.bin
# Enforce at commit time:
gitleaks detect --source . --redact        # also catches large-blob / secret patterns
```

Apply least privilege to model storage exactly as you would to a production database: private by default, encrypted, access-logged, and never served as a static asset from the web root.

## 6. Protect On-Device and Edge Models

When inference must run on the client, assume the environment is hostile and reduce what a copy is worth.

- **Prefer server-side inference** for the highest-value models; ship the artifact to the edge only when latency/offline needs demand it.
- **Encrypt the bundled model** and decrypt into memory at runtime; do not ship plaintext weights in the package.
- **Obfuscate and integrity-check** the on-device model; use platform hardware-backed keystores where available.
- **Ship a smaller/less-valuable variant** to the edge and keep the full model server-side.
- **Watermark** the deployed artifact so a recovered copy is attributable.

## 7. Watermarking and Fingerprinting

Watermarking embeds a secret, verifiable signal in the model so you can later *prove* a suspect copy is yours; fingerprinting derives an identifying signature from the model's behaviour. Neither prevents copying—they enable attribution and legal action.

```python
# Behavioural watermark: the model returns a known response on secret trigger inputs
TRIGGERS = load_secret_trigger_set()        # kept confidential
def verify_ownership(suspect_model):
    hits = sum(suspect_model.predict(t) == expected for t, expected in TRIGGERS)
    return hits / len(TRIGGERS) > 0.9        # high match => derived from our model
```

Design watermarks to survive fine-tuning and distillation as far as possible, keep the trigger set secret, and record it so you can demonstrate provenance if a stolen copy surfaces.

## 8. Legal, Contractual, and Terms-of-Service Controls

- Explicitly prohibit extraction, scraping, redistribution, and reverse engineering in the API terms of service and customer contracts.
- Require authenticated accounts so terms attach to an identifiable party.
- Keep evidence (per-client query logs, watermark verifications) that supports enforcement.
- Treat legal controls as a deterrent and a remedy—a complement to, never a substitute for, the technical controls above.

## 9. Usage Monitoring and Response

Tie the signals together and rehearse the response.

```
# Alert on the signatures of theft
- Sudden volume spikes or steady high-rate querying from one client
- Concentrated near-boundary / space-filling query distributions
- Anonymous or unexpected pulls from model storage / registry
- Model files appearing in public repos or buckets (external scanning)
- Watermark verification hits on a third-party service

# Response playbook: throttle -> challenge -> degrade output -> revoke key -> investigate
```

## Defence-in-Depth Summary

| Threat | Primary Control | Reinforcing Control |
|--------|-----------------|---------------------|
| Query-based extraction | Reduce output granularity (top-1, rounded, perturbed) | Auth + per-client rate limits + extraction detection |
| Distillation from confidences | Never expose logits / full probability vectors | Quotas, anomaly detection |
| Artifact exfiltration (storage) | Private, encrypted, access-logged storage | No weights in repos; secret scanning |
| Registry / static-file theft | Authenticated registry; no static model routes | Least-privilege service identities |
| On-device extraction | Server-side inference where possible | Encrypt + obfuscate + watermark shipped models |
| Insider / pipeline copy | Least privilege + access logging on checkpoints | Egress monitoring, CI/CD hardening |
| Any confirmed theft | Watermark-based attribution | ToS/legal enforcement |

## Key Takeaways

1. **Defend the API and the artifact**—stopping one route leaves the other wide open.
2. **Minimise output**—top-1 or coarse, perturbed scores instead of logits is the highest-leverage anti-extraction control.
3. **Cost and attribute every query**—authentication plus per-client rate limits and quotas turn free cloning into an expensive, traceable effort.
4. **Lock down the weights**—encrypted, private storage, no repo commits, no static routes, least privilege everywhere.
5. **Attribute what you cannot prevent**—watermarking, monitoring, and terms of service back the technical controls with detection and recourse.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure inference APIs and model storage in Python
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[ML Security Learning Path](/learn/ml)**: Continue with the rest of the OWASP ML Top 10
- **[Practice](/practice)**: Apply these defences in hands-on exercises
