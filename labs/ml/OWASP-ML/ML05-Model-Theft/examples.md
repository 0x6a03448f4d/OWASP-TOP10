# ML05: Model Theft - Code Examples

Each pair below shows an **insecure** implementation and the **secure** version. The theme is the same throughout: an unprotected inference API and unprotected weights hand an attacker a free clone; authentication, rate limiting, reduced output granularity, query monitoring, and encrypted least-privilege storage make theft expensive and attributable. Examples are Python.

## 1. Inference API: Unprotected vs. Hardened

### Insecure
```python
from flask import Flask, request, jsonify
import numpy as np

app = Flask(__name__)
model = load_model('model.pt')            # proprietary model

@app.route('/predict', methods=['POST'])
def predict():
    x = np.array(request.json['input'])
    logits = model.forward(x)
    probs = softmax(logits)
    # No auth, no rate limit, no monitoring, and it hands back FULL logits +
    # the complete probability vector — a perfect distillation oracle.
    return jsonify({
        'logits': logits.tolist(),        # richest possible signal per query
        'probabilities': probs.tolist(),
        'label': CLASSES[int(np.argmax(probs))]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0')               # anonymous, unlimited querying
```

**Why it's vulnerable**: anyone can query without limit, and every response returns logits and the full softmax. An attacker distills a near-exact substitute in relatively few queries, and nothing is logged to detect or attribute it.

### Secure
```python
import logging, hmac, time
from functools import wraps
from flask import Flask, request, jsonify, g
import numpy as np

app = Flask(__name__)
model = load_model_encrypted('model.enc') # decrypted into memory at load time
log = logging.getLogger('inference')

# --- 1. Authentication + authorisation ---------------------------------
def require_client(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        token = request.headers.get('Authorization', '').removeprefix('Bearer ')
        client = lookup_client(token)                  # constant-time lookup
        if not client or not client.can_predict:
            return jsonify({'error': 'Unauthorized'}), 401
        g.client = client
        return fn(*a, **kw)
    return wrapper

# --- 2. Per-client rate limiting + quota -------------------------------
def enforce_limits(client_id):
    if rate.count(client_id, window='1m') > 60:
        return False, 'rate_limited'
    if rate.count(client_id, window='1d') > 10_000:    # extraction-scale cap
        return False, 'quota_exceeded'
    rate.incr(client_id)
    return True, None

# --- 3. Reduced granularity + output perturbation ----------------------
def safe_output(logits):
    probs = softmax(logits)
    top = int(np.argmax(probs))
    conf = float(probs[top])
    conf += np.random.normal(0, 0.01)                  # small calibrated noise
    conf = round(min(max(conf, 0.0), 0.99), 2)         # coarse + capped
    return {'label': CLASSES[top], 'confidence': conf} # NO logits, NO full vector

# --- 4. Extraction-pattern monitoring ----------------------------------
def monitor(client_id, x):
    record_query(client_id, x)
    if extraction_signals(client_id) >= 2:             # volume + boundary probing
        log.warning('possible extraction client=%s', client_id)
        raise_alert(client_id)

@app.route('/predict', methods=['POST'])
@require_client
def predict():
    ok, why = enforce_limits(g.client.id)
    if not ok:
        return jsonify({'error': why}), 429
    x = np.array(request.json['input'])
    monitor(g.client.id, x)
    logits = model.forward(x)
    return jsonify(safe_output(logits))                # minimal, perturbed output
```

**Why it's secure**: every query is authenticated and attributable, per-client limits and quotas make extraction-scale volume expensive, the response exposes only a top-1 label with a coarse, noised confidence (no logits, no full vector), and systematic querying is detected and alerted.

## 2. Output Granularity: What the Client Sees

### Insecure
```python
# Returns everything the model knows about the input
{
  "logits": [-2.1, 5.8, 0.3, -1.7],       # exact pre-softmax values
  "probabilities": [0.0004, 0.94, 0.05, 0.0007],
  "embedding": [0.12, -0.44, ...]          # even the feature vector
}
# Each field is a gift to a distillation attack.
```

### Secure
```python
# Returns the least the use case needs
{
  "label": "cat",
  "confidence": 0.94                        # rounded, capped, slightly perturbed
}
# Strongest option of all: return the label alone, with no score.
```

**Rule of thumb**: never expose logits or embeddings on a public endpoint; prefer top-1; if a score is required, round, band, and perturb it. Information withheld is queries added to the attacker's bill.

## 3. Model-File Storage: Public vs. Locked Down

### Insecure
```python
import boto3

s3 = boto3.client('s3')
s3.upload_file(
    'model-final.pt', 'company-models',
    'prod/model-final.pt',
    ExtraArgs={'ACL': 'public-read'}          # anyone can download the weights
)

# Worse still, the weights are also served as a static asset:
#   GET https://app.example.com/static/models/model-final.pt  -> 200 OK
# ...and committed to the repo:
#   git add models/model-final.pt && git commit -m "add model"
```

**Why it's vulnerable**: a public ACL, a static route, and a committed checkpoint each hand over a byte-for-byte white-box copy with no interaction with the running service.

### Secure
```python
import boto3, os
from cryptography.fernet import Fernet

# --- Encrypt before upload; key lives in a secrets manager / KMS -------
key = get_secret('model-encryption-key')            # never in code or repo
cipher = Fernet(key)
with open('model-final.pt', 'rb') as f:
    encrypted = cipher.encrypt(f.read())
with open('model-final.enc', 'wb') as f:
    f.write(encrypted)

# --- Private bucket, server-side encryption, no public access ----------
s3 = boto3.client('s3')
s3.upload_file(
    'model-final.enc', 'company-models-private',
    'prod/model-final.enc',
    ExtraArgs={'ServerSideEncryption': 'aws:kms'}    # NO public-read ACL
)
# Bucket policy: block ALL public access; allow only the service role.
# Bucket-level "Block Public Access" = ON. Access logging = ON.

# --- Load path: decrypt into memory at runtime ------------------------
def load_model_encrypted(path):
    blob = s3_get_bytes('company-models-private', path)   # authenticated pull
    raw = Fernet(get_secret('model-encryption-key')).decrypt(blob)
    return deserialize_model(raw)                    # plaintext only in memory
```

```bash
# Keep weights out of source control entirely
# .gitignore
*.pt
*.pth
*.onnx
*.h5
*.ckpt
*.safetensors
models/**/*.bin

# CI gate: fail the build if weights or secrets are committed
gitleaks detect --source . --redact
```

**Why it's secure**: the artifact is encrypted at rest, stored in a private bucket with public access blocked and KMS encryption, pulled only by an authenticated service identity, decrypted into memory at load time, never served as a static file, and never committed to the repository.

## 4. Ownership Attribution: Watermark Verification

### Secure (attribution control)
```python
# A behavioural watermark lets you PROVE a suspect copy is derived from yours.
# It does not prevent theft — it supports detection and legal action.

TRIGGERS = load_secret_trigger_set()        # secret inputs + expected outputs

def verify_ownership(suspect_predict_fn):
    hits = sum(
        suspect_predict_fn(t)['label'] == expected
        for t, expected in TRIGGERS
    )
    match_rate = hits / len(TRIGGERS)
    return {
        'is_ours': match_rate > 0.9,         # high match => our model
        'confidence': round(match_rate, 3)
    }
# Keep the trigger set confidential and design it to survive fine-tuning
# and distillation as far as possible.
```

**Role**: watermarking and fingerprinting are the last line—attribution, not prevention. Pair them with the API and storage controls above, plus terms of service that prohibit extraction and redistribution.

## What Changed, and Why

| Weakness | Insecure | Secure |
|----------|----------|--------|
| API access | Anonymous, unlimited querying | Per-client auth + rate limits + daily quota |
| Output | Logits + full probability vector (+ embeddings) | Top-1 label + coarse, capped, perturbed score |
| Detection | None | Per-client query monitoring + extraction alerts |
| Storage | Public ACL, static route, committed to repo | Encrypted, private bucket, service-role only, gitignored |
| Attribution | No way to prove theft | Behavioural watermark verification + ToS |

## Next Steps

- **[Prevention](prevention.md)**: The full layered defence for the API and the artifact
- **[Attack Vectors](attack-vectors.md)**: How these weaknesses are exploited
- **[ML Security Learning Path](/learn/ml)**: Continue with the rest of the OWASP ML Top 10
- **[Practice](/practice)**: Apply these defences in hands-on exercises
