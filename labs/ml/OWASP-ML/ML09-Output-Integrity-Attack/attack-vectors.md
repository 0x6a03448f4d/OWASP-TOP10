# ML09: Output Integrity Attack - Attack Vectors

## Table of Contents
- [Understanding Output Integrity Attack Vectors](#understanding-output-integrity-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining and Escalation](#chaining-and-escalation)

## Understanding Output Integrity Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are described so you can find and close these gaps in systems you own or are authorised to test.

An Output Integrity Attack does not fight the model. The attacker lets the model produce its (correct) answer and then **rewrites that answer somewhere on the path to the consumer**. The prize is control over the *decision* without the difficulty of fooling the model itself. Because the manipulated object is a small, structured value—a label, a score, a boolean—a single flipped byte can invert a security outcome.

To do this the attacker needs a foothold on *any one* hop the result crosses: a position on the network, write access to a store or queue, control of an integration component, or the ability to edit a value the consumer trusts. The model's robustness is irrelevant to all of these.

The attacker's goal in this category is usually one of:

- Flip a security verdict (`fraud`→`benign`, `malware`→`clean`, `deny`→`allow`).
- Substitute a stale or fabricated result that is validly shaped but wrong.
- Corrupt recorded outputs so downstream systems act on false ground truth.

### Core Attack Flow

```
1. Locate the path
   |
   Map every hop a prediction crosses: serving endpoint, gateway,
   store, queue, cache, UI, logs
2. Find an unprotected hop
   |
   Plain HTTP, no message signature, broad write access,
   client-trusted value, mutable log
3. Tamper
   |
   Rewrite the result in transit / at rest / at the UI, or replay a stale one
4. Decision subverted
   |
   Consumer acts on the attacker's value; model metrics stay healthy
```

## Common Attack Patterns

### 1. Intercepting and Altering Predictions in Transit (MITM)

An unencrypted or unauthenticated inference API lets an attacker on the path rewrite the response body before the caller reads it.

```
Caller ---- GET /predict?tx=98213 ----> http://model.internal:8080

# Legitimate response the model produced:
HTTP/1.1 200 OK
{ "tx": "98213", "decision": "deny", "score": 0.97 }

# What the MITM delivers to the caller instead:
HTTP/1.1 200 OK
{ "tx": "98213", "decision": "allow", "score": 0.02 }
```

**Payoff**: the caller acts on `allow` though the model said `deny`—no exploit against the model, just control of the cleartext channel.

### 2. Tampering at the Integration / Gateway Layer

A component that reshapes the raw model output into a decision is a single point that can substitute a verdict.

```
model -> scoring-adapter -> policy-service -> enforcement

# A compromised or buggy adapter rewrites the field the policy reads:
raw = { "label": "malware", "p": 0.98 }
# adapter emits:
out = { "verdict": "clean" }        # policy-service now allows the file
```

**Payoff**: everything downstream trusts the adapter, so one altered hop changes the enforced outcome.

### 3. Trusting a Client-Controlled Decision Value

When the value that drives the action is visible and editable on the client, the acted-on decision is whatever the client says.

```javascript
// Model returns to the browser:
{ "riskDecision": "review", "allowSubmit": false }

// The client trusts and forwards this. User edits it in devtools / a proxy:
{ "riskDecision": "approved", "allowSubmit": true }
// -> POST /checkout  { "riskDecision": "approved" }   # server trusts it
```

**Payoff**: the model flagged the transaction, but the client-supplied verdict overrides it because the server treated a client value as authoritative.

### 4. Manipulating a Shared Results Store

Predictions written to a database for asynchronous consumption can be edited at rest by anyone with write access.

```sql
-- Producer wrote the model's verdict:
INSERT INTO scores(tx, verdict, score) VALUES ('98213', 'fraud', 0.97);

-- Attacker with over-broad write access flips it before the consumer reads:
UPDATE scores SET verdict='legit', score=0.03 WHERE tx='98213';
```

**Payoff**: the batch/settlement job reads `legit` and releases the payment. No network access needed—just excess privilege on the store.

### 5. Manipulating a Message Queue or Topic

Result messages on a broker are exposed to any principal that can publish to or rewrite the topic.

```
# Producer publishes the model's message:
topic "decisions": { "id": "a1", "action": "quarantine" }

# Attacker publishes a competing/replacement message the consumer accepts:
topic "decisions": { "id": "a1", "action": "release" }
```

**Payoff**: the consumer processes the attacker's message and releases what should have been quarantined.

### 6. Poisoning a Prediction Cache

Cached results served to save recomputation are trusted on read; a writable cache lets the attacker seat a false value.

```
SET score:tx:98213  '{"verdict":"fraud"}'     # legitimate cached value
# attacker overwrites the key:
SET score:tx:98213  '{"verdict":"legit"}'     # every reader now sees "legit"
```

**Payoff**: one cache write is amplified across every consumer that trusts the cache until it expires.

### 7. Altering Logged and Downstream-Consumed Outputs

Outputs recorded to logs, exports, or metrics are re-consumed as ground truth by other systems.

```
# Original log line (mutable, unsigned):
2026-08-29T10:14Z tx=98213 verdict=fraud score=0.97

# Edited before the SIEM / billing / retraining job ingests it:
2026-08-29T10:14Z tx=98213 verdict=legit score=0.03
```

**Payoff**: the fraud case never opens, the retraining set learns the wrong label, and the dashboard shows a clean picture.

### 8. Flipping a Security Verdict at the Enforcement Boundary

The most targeted case: the exact field a security control keys on is inverted.

```python
if result.verdict == "malware":   # attacker ensures this is never true
    quarantine(file)
else:
    deliver(file)                 # tampered "benign" reaches the user
```

**Payoff**: the control silently fails open. The model detected the threat; the enforcement point never saw the real verdict.

### 9. Replaying a Stale Result

Without freshness binding, a previously valid result can be re-served in place of the current one.

```
t0  model: { "account":"X", "status":"good_standing" }   # captured
t1  model: { "account":"X", "status":"suspended" }       # current, correct
attacker re-delivers the t0 message -> consumer acts on stale "good_standing"
```

**Payoff**: a genuine past result overrides the correct present one because nothing ties a result to "now".

### 10. Forging a Result from an Impostor Producer

If the consumer does not authenticate the source, an attacker can supply results as if they were the model.

```
Consumer accepts any well-formed JSON on the results channel.
Attacker (no model at all) sends:
{ "tx":"98213", "verdict":"legit", "score":0.01 }   # fabricated, accepted
```

**Payoff**: the "model output" the system acts on never came from the model.

## Chaining and Escalation

Output-integrity gaps combine with other weaknesses to turn a foothold into a controlled decision:

```
Over-broad DB role (excess privilege)     -> write access to the results table
        +
Results stored unsigned                    -> edit verdicts undetected at rest
        +
Consumer trusts the record as-is           -> flipped verdict is enforced
        =  fraud/malware/deny reliably converted to allow, silently
```

Another common chain:

```
Plain-HTTP internal inference call   -> MITM rewrites the response
        +
No nonce/timestamp on the result     -> attacker can also replay old "good" verdicts
        +
Logs are mutable and unsigned        -> the tampering leaves no reliable trace
```

## Key Takeaways

1. **The model is not the target—its answer is**. The attacker rewrites a correct result on the path to the consumer.
2. **Any single unprotected hop is enough**—transit, gateway, store, queue, cache, UI, or log.
3. **Flipping one field inverts a control**—`fraud`/`malware`/`deny` become `benign`/`clean`/`allow`.
4. **Stale can beat correct**—without freshness binding, a replayed old result overrides the current one.
5. **Tampering hides in the plumbing**—model metrics stay healthy while the decision is wrong.

## Next Steps

- **[Prevention Guide](prevention.md)**: Protect the pipeline end-to-end and sign every result
- **[Code Examples](examples.md)**: Insecure vs. secure inference pipelines in Python
- **[Overview](overview.md)**: What ML09 is and how it differs from ML01
- **[Back to ML Top 10](/learn/ml)**: Continue with the other ML security categories
- **[Practice](/practice)**: Apply what you have learned in hands-on challenges
