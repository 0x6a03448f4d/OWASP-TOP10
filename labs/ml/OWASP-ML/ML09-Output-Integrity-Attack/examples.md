# ML09: Output Integrity Attack - Code Examples

Each pair below shows an **insecure** inference pipeline that passes or stores results without integrity protection, and the **secure** version that adds TLS, signed/authenticated results, and consumer-side validation. The model itself is unchanged—every fix protects the *result* on its way to the thing that acts on it.

> The signing helpers (`sign_result` / `verify_result`) are shared across the examples and shown once, in Example 1. Later examples reuse them.

## Example 1: Prediction in Transit

### Insecure
```python
import requests
from flask import Flask, request, jsonify

# --- Model server: serves raw predictions over plain HTTP ---
app = Flask(__name__)

@app.route("/predict")
def predict():
    tx = request.args["tx"]
    verdict, score = model.score(tx)          # correct output from the model
    return jsonify({"tx": tx, "verdict": verdict, "score": score})

app.run(host="0.0.0.0", port=8080)            # cleartext: no TLS

# --- Consumer: trusts whatever comes back ---
def decide(tx):
    r = requests.get(f"http://model.internal:8080/predict?tx={tx}")  # plain HTTP
    result = r.json()
    if result["verdict"] == "fraud":
        block(tx)
    else:
        allow(tx)                             # a MITM can flip "fraud" -> "legit"
```

**Why it is vulnerable**: the result crosses the network in cleartext with no authenticity or integrity. Anyone on the path rewrites `verdict` and the consumer never knows.

### Secure
```python
import hmac, hashlib, json, time, uuid, ssl, requests
from flask import Flask, request, jsonify

SIGNING_KEY = load_secret("results-hmac-key")   # from a secrets manager
FRESH_WINDOW = 30
_seen = set()

# --- shared helpers (reused by later examples) ---
def sign_result(payload: dict, key: bytes) -> dict:
    env = {"payload": payload, "nonce": uuid.uuid4().hex,
           "issued_at": int(time.time())}
    body = json.dumps({k: env[k] for k in ("payload", "nonce", "issued_at")},
                      sort_keys=True, separators=(",", ":")).encode()
    env["sig"] = hmac.new(key, body, hashlib.sha256).hexdigest()
    return env

def verify_result(env: dict, key: bytes) -> dict:
    body = json.dumps({k: env[k] for k in ("payload", "nonce", "issued_at")},
                      sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, env.get("sig", "")):
        raise ValueError("signature invalid")           # integrity/authenticity
    if abs(time.time() - env["issued_at"]) > FRESH_WINDOW:
        raise ValueError("result stale")                # anti-replay (time)
    if env["nonce"] in _seen:
        raise ValueError("result replayed")             # anti-replay (nonce)
    _seen.add(env["nonce"])
    return env["payload"]

# --- Model server: signs the result and serves it over TLS ---
app = Flask(__name__)

@app.route("/predict")
def predict():
    tx = request.args["tx"]
    verdict, score = model.score(tx)
    return jsonify(sign_result({"tx": tx, "verdict": verdict, "score": score},
                               SIGNING_KEY))

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain("server.crt", "server.key")
ctx.load_verify_locations("internal-ca.crt")
ctx.verify_mode = ssl.CERT_REQUIRED                     # require client cert (mTLS)
app.run(host="0.0.0.0", port=8443, ssl_context=ctx)

# --- Consumer: TLS + verify signature + sanity-check before acting ---
def decide(tx):
    r = requests.get(f"https://model.internal:8443/predict?tx={tx}",
                     cert=("client.crt", "client.key"),   # our identity
                     verify="internal-ca.crt")            # pin internal CA
    payload = verify_result(r.json(), SIGNING_KEY)        # reject if tampered
    if payload["verdict"] not in {"fraud", "legit"}:
        raise ValueError("unexpected verdict")
    block(tx) if payload["verdict"] == "fraud" else allow(tx)
```

**Why it is secure**: mTLS stops the on-path rewrite and authenticates both ends; the HMAC lets the consumer prove the result is the model's and unaltered; freshness checks defeat replay.

## Example 2: Results Stored for Asynchronous Consumption

### Insecure
```python
# Producer writes a bare verdict; any writer to this table can change it.
def store_result(db, tx):
    verdict, score = model.score(tx)
    db.execute("INSERT INTO scores(tx, verdict, score) VALUES (%s,%s,%s)",
               (tx, verdict, score))

# Settlement job hours later trusts the row as-is.
def settle(db, tx):
    row = db.query_one("SELECT verdict FROM scores WHERE tx=%s", (tx,))
    if row["verdict"] == "fraud":
        hold(tx)
    else:
        release(tx)          # UPDATE scores SET verdict='legit' ... goes unnoticed
```

**Why it is vulnerable**: the stored value has no integrity protection, so any principal with write access edits the verdict at rest before the consumer reads it.

### Secure
```python
# Producer stores the SIGNED envelope, not a bare verdict.
def store_result(db, tx):
    verdict, score = model.score(tx)
    env = sign_result({"tx": tx, "verdict": verdict, "score": score}, SIGNING_KEY)
    db.execute("INSERT INTO scores(tx, envelope) VALUES (%s, %s)",
               (tx, json.dumps(env)))
    # DB grant: only the producer identity may INSERT/UPDATE scores.

# Consumer verifies on read; a tampered row fails verification and is rejected.
def settle(db, tx):
    row = db.query_one("SELECT envelope FROM scores WHERE tx=%s", (tx,))
    payload = verify_result(json.loads(row["envelope"]), SIGNING_KEY)
    hold(tx) if payload["verdict"] == "fraud" else release(tx)
```

**Why it is secure**: the record authenticates itself on read, so at-rest edits are detected; least-privilege grants stop unauthorized writers in the first place.

## Example 3: Consumer Acting on the Result (Verdict Enforcement)

### Insecure
```python
# A thick client receives the raw result and sends the decision back.
# The server trusts the client-supplied verdict.
@app.route("/checkout", methods=["POST"])
def checkout():
    body = request.get_json()
    if body["riskDecision"] == "approved":     # value came from the client!
        return complete_order()
    return require_review()
# User edits {"riskDecision":"review"} -> {"riskDecision":"approved"} in a proxy.
```

**Why it is vulnerable**: the security decision is trusted from a value the client controls, so the acted-on verdict is not the model's.

### Secure
```python
# The authoritative decision stays server-side. The client may carry the SIGNED
# envelope, but the server re-verifies it (and can re-derive) before enforcing.
@app.route("/checkout", methods=["POST"])
def checkout():
    env = request.get_json()["riskEnvelope"]        # signed by the risk service
    try:
        payload = verify_result(env, SIGNING_KEY)   # authenticity + integrity + freshness
    except ValueError:
        return reject("risk result failed verification"), 400
    if payload["tx"] != current_tx():               # bind result to THIS request
        return reject("risk result does not match transaction"), 400
    if payload["verdict"] == "approved":
        return complete_order()
    return require_review()
```

**Why it is secure**: the client cannot forge or edit a valid signed result; binding the result to the current transaction blocks swapping in another (or a stale) verdict.

## Example 4: Logging Outputs for Downstream Consumption

### Insecure
```python
# Mutable, unsigned log line later ingested by SIEM / billing / retraining.
def log_result(tx, verdict, score):
    with open("/var/log/scores.log", "a") as f:
        f.write(f"{time.time()} tx={tx} verdict={verdict} score={score}\n")
# Anyone who can edit the file rewrites verdict=fraud -> verdict=legit,
# and every downstream consumer inherits the false value.
```

**Why it is vulnerable**: downstream systems treat the log as ground truth, but the record is editable and carries no integrity.

### Secure
```python
# Log the SIGNED envelope to append-only / tamper-evident storage.
def log_result(tx, verdict, score):
    env = sign_result({"tx": tx, "verdict": verdict, "score": score}, SIGNING_KEY)
    append_only_sink.write(json.dumps(env, sort_keys=True) + "\n")  # WORM / hash-chained

# Downstream consumers verify each record before trusting it.
def ingest(line):
    payload = verify_result(json.loads(line), SIGNING_KEY)  # rejects edited entries
    feed_downstream(payload)
```

**Why it is secure**: each logged record is self-authenticating, and append-only/hash-chained storage makes any edit detectable, so downstream consumers act only on verified outputs.

## What Changed, and Why

| Weakness | Insecure | Secure |
|----------|----------|--------|
| In transit | Plain HTTP, result trusted as received | TLS/mTLS + HMAC-signed result, verified by consumer |
| At rest (store) | Bare verdict any writer can edit | Signed envelope + least-privilege writes, verified on read |
| Enforcement | Client-supplied verdict trusted | Server-side verification, result bound to the request |
| Replay | No freshness binding | Nonce + timestamp window reject stale results |
| Logs / downstream | Mutable, unsigned records | Signed, append-only, verified before use |

## Next Steps

- **[Prevention](prevention.md)**: The full end-to-end integrity strategy
- **[Attack Vectors](attack-vectors.md)**: How these results get tampered with
- **[Overview](overview.md)**: What ML09 is and how it differs from ML01
- **[Back to ML Top 10](/learn/ml)**: Continue with the other ML security categories
- **[Practice](/practice)**: Apply what you have learned in hands-on challenges
