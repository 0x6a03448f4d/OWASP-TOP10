# ML09: Output Integrity Attack - Prevention

## Prevention Strategy Overview

Preventing ML09 comes down to one shift in mindset: **treat every prediction as a security-critical message** that a downstream component will act on. A message like that needs authenticity and integrity that travel *with the result*, not just a secure moment on one hop. The strategy:

1. Secure the whole pipeline in transit (TLS/mTLS on every hop).
2. Authenticate and integrity-protect the result itself (sign/HMAC), and verify it at the consumer.
3. Protect results at rest in any store, queue, or cache.
4. Validate and sanity-check outputs before acting, and bind freshness to defeat replay.
5. Apply least privilege, tamper-evident logging, and monitoring across the path.

### Core Principles

- **Authenticity and integrity, not just confidentiality**: encryption hides a result; it does not prove who produced it or that it is unchanged. You need both.
- **End-to-end, not hop-by-hop**: protection must survive stores, queues, and forwarding—so it must be bound to the result, not to the transport.
- **Verify before you act**: a consumer must reject any result whose signature, freshness, or shape does not check out—fail closed.
- **Least privilege on results**: only the producer writes results; only intended consumers read them; nothing has more access to the decision than it needs.

## 1. Protect the Inference Pipeline in Transit (TLS / mTLS)

Every hop that carries a prediction—client to gateway, gateway to model server, model server to consumer—must be encrypted and authenticated. Use mutual TLS between internal services so each side proves its identity, not just the server.

```python
# Serve the inference API over TLS and require client certificates (mTLS)
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
ctx.load_verify_locations(cafile="internal-ca.crt")
ctx.verify_mode = ssl.CERT_REQUIRED          # caller must present a valid cert

# Consumer side: verify the server AND present its own client cert
import requests
resp = requests.get(
    "https://model.internal:8443/predict",
    params={"tx": "98213"},
    cert=("client.crt", "client.key"),       # our identity
    verify="internal-ca.crt",                # pin to the internal CA
)
```

TLS/mTLS stops the man-in-the-middle rewrite in transit. It does *not* protect the result once it is stored or forwarded—that is what signing (next) is for.

## 2. Sign / Authenticate Every Result

Have the producer attach a signature or HMAC over the result so any consumer can independently confirm it came from the model service and was not altered. This protection stays with the message through stores, queues, and logs.

```python
# Producer: HMAC the canonical result so integrity travels WITH it
import hmac, hashlib, json, time, uuid

def sign_result(payload: dict, key: bytes) -> dict:
    envelope = {
        "payload": payload,
        "nonce": uuid.uuid4().hex,           # freshness (anti-replay)
        "issued_at": int(time.time()),
    }
    body = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    envelope["sig"] = hmac.new(key, body, hashlib.sha256).hexdigest()
    return envelope
```

Use a shared secret with HMAC for a trusted producer/consumer pair, or asymmetric signatures (e.g., Ed25519) when many consumers must verify without holding a signing key. Sign a **canonical** serialization so verification is deterministic.

## 3. Verify Results at the Consumer

Signing is only half the control—the consumer must verify and **reject on any failure**. Never act on an unverified result.

```python
# Consumer: verify signature, freshness, then act
import hmac, hashlib, json, time

FRESH_WINDOW = 30   # seconds
_seen_nonces = set()

def verify_result(envelope: dict, key: bytes) -> dict:
    got = envelope.get("sig", "")
    body = {k: envelope[k] for k in ("payload", "nonce", "issued_at")}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(key, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, got):      # integrity + authenticity
        raise ValueError("result signature invalid")
    if abs(time.time() - envelope["issued_at"]) > FRESH_WINDOW:
        raise ValueError("result stale")            # anti-replay (time)
    if envelope["nonce"] in _seen_nonces:
        raise ValueError("result replayed")         # anti-replay (nonce)
    _seen_nonces.add(envelope["nonce"])
    return envelope["payload"]
```

Use a constant-time comparison (`hmac.compare_digest`), fail closed on every check, and treat a verification failure as a security event, not a soft error.

## 3.1 Prevent Replay of Stale Results

Bind each result to "now" so an old-but-valid result cannot be re-served. Two complementary controls, both shown above:

- **Timestamp + freshness window**: reject results older than a small window (requires loosely-synced clocks).
- **Nonce / request binding**: include a per-request nonce (or echo the consumer's challenge) and reject any nonce seen before.

## 4. Secure the Results Store, Queue, and Cache

Anywhere a result waits to be consumed is a tampering surface. Combine strict access control with record-level integrity so the record verifies itself on read.

```python
# Store the SIGNED envelope, not a bare verdict, so readers verify on read
def persist(db, envelope: dict):
    db.execute(
        "INSERT INTO scores(tx, envelope) VALUES (%s, %s)",
        (envelope["payload"]["tx"], json.dumps(envelope)),
    )

def load(db, tx: str, key: bytes) -> dict:
    row = db.query_one("SELECT envelope FROM scores WHERE tx=%s", (tx,))
    return verify_result(json.loads(row["envelope"]), key)  # reject if tampered
```

- Grant **write** on the results store/topic only to the producer identity; grant **read** only to intended consumers.
- For queues/topics, authenticate publishers and verify the signature on consume—do not trust "it was on the topic".
- For caches, store the signed envelope and verify on read; a poisoned key then fails verification instead of being trusted.

## 5. Validate and Sanity-Check Outputs at the Consumer

Beyond cryptographic verification, check that the decoded result is *plausible* before acting. This catches malformed or out-of-policy values and adds defence in depth.

```python
ALLOWED_LABELS = {"benign", "malware"}

def sanity_check(payload: dict):
    if payload.get("label") not in ALLOWED_LABELS:
        raise ValueError("unexpected label")
    score = payload.get("score")
    if not isinstance(score, (int, float)) or not (0.0 <= score <= 1.0):
        raise ValueError("score out of range")
    # cross-field consistency: a high-confidence "benign" must not carry a
    # malware indicator, etc. Enforce the invariants your domain guarantees.
```

Keep the **authoritative decision server-side**. Never let a client-supplied verdict override the model's—re-derive or re-verify the decision from a signed result on the server before enforcing it.

## 6. Least Privilege on Everything That Handles Results

- Give the model-serving component permission to *produce* results and nothing more; give consumers permission to *read and verify*, not to rewrite.
- Scope database roles, queue ACLs, and cache credentials to the minimum operation each component needs.
- Isolate the signing key: only the producer can sign; distribute only the verification material (the HMAC key to trusted consumers, or the public key widely).
- Segment the network so the decision channel is not reachable from general workloads.

## 7. Tamper-Evident Logging and Audit

Logs are only evidence if they cannot be quietly rewritten. Record the **signed** result and make the log append-only or independently signed.

```python
# Log the verified envelope (payload + nonce + issued_at + sig) so the record
# is self-authenticating and any later edit is detectable.
audit_log.append(json.dumps(envelope, sort_keys=True))
# Ship to append-only / WORM storage or a signed, hash-chained log so an
# edited entry breaks the chain.
```

Retain enough to answer "what did the model actually output, and did the consumer act on that exact value?"—that question is unanswerable if the outputs are mutable and unsigned.

## 8. Monitoring and Detection

Watch for the signatures of output tampering and verification failures.

```python
# Alert on integrity-verification failures — these are security events
def on_verify_failure(reason, tx, src):
    log.warning("result integrity failure tx=%s reason=%s src=%s", tx, reason, src)
    send_security_alert(reason, tx, src)

# Reconcile: does the consumer's acted-on verdict match the producer's signed one?
# Divergence between produced and enforced decisions is a strong tamper signal.
```

Also alert on: spikes in signature/nonce/staleness rejections, results appearing on a channel from an unexpected source identity, and mismatches between produced and consumed decisions in reconciliation jobs.

## Defense Summary

| Threat | Control | What it stops |
|--------|---------|---------------|
| MITM in transit | TLS / mTLS on every hop | On-path rewrite of the response |
| At-rest / forwarded tampering | Sign/HMAC the result, verify at consumer | Edits in stores, queues, caches, logs |
| Impostor producer | Authenticate the source (mTLS + signature) | Fabricated "model" outputs |
| Replay of stale results | Nonce + timestamp freshness window | Re-serving an old valid verdict |
| Client-trusted verdict | Authoritative decision server-side | UI/client value overriding the model |
| Implausible / malformed output | Consumer-side sanity checks | Out-of-policy values being enforced |
| Silent tampering | Tamper-evident logs + reconciliation | Undetected divergence of decisions |

## Key Takeaways

1. **Sign the decision, not just the channel**—integrity must travel with the result through stores, queues, and logs.
2. **Verify before acting, fail closed**—reject any result that fails signature, freshness, or sanity checks.
3. **Encrypt and authenticate every hop**—TLS/mTLS stops the in-transit rewrite and impostor producers.
4. **Bind freshness**—nonces and timestamps defeat replay of stale-but-valid results.
5. **Least privilege and tamper-evidence**—lock down who can write results, and make edits detectable after the fact.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure inference pipelines in Python
- **[Attack Vectors](attack-vectors.md)**: Understand what you are defending against
- **[Overview](overview.md)**: What ML09 is and how it differs from ML01
- **[Back to ML Top 10](/learn/ml)**: Continue with the other ML security categories
- **[Practice](/practice)**: Apply what you have learned in hands-on challenges
