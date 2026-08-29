# ML09: Output Integrity Attack - Overview

## Table of Contents
- [What is an Output Integrity Attack?](#what-is-an-output-integrity-attack)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is an Output Integrity Attack?

An **Output Integrity Attack** targets the model's *result* after the model has produced it. The attacker tampers with the prediction on the path between the model and whatever consumes it—a downstream service, a database, a message queue, an operator's dashboard, or the user interface—so that the decision the system finally acts on is **not the decision the model actually made**.

This is a failure of **integrity**, not of accuracy. The model can be perfectly trained, perfectly robust, and completely correct; ML09 is about what happens to its answer *in transit and at the boundary*. If a fraud model outputs `"fraud": true` and an attacker flips that to `"fraud": false` before the payment service reads it, the model was right and the system was still wrong.

> **ML09 is not about fooling the model.** Crafting an input that makes the model itself produce a wrong answer is **ML01 (Input Manipulation / Adversarial Attack)**. ML09 assumes the model produced the *correct* output and asks: what protects that output on its way to the thing that acts on it?

### Core Concept

```
What the model produced        What the consumer acted on
-----------------------        --------------------------
{ "label": "malware",          { "label": "benign",
  "score": 0.985 }      ==>      "score": 0.010 }
          |                              ^
          |   attacker tampers with      |
          +---- the result in transit ---+
               (or in a store / queue /
                cache / log / UI layer)

The prediction is a security-critical MESSAGE.
Without authenticity + integrity protection, anything
on the path can rewrite the decision undetected.
```

### Where the Output Can Be Tampered

The "output path" is longer than it looks. A single prediction typically crosses several trust boundaries before anything acts on it:

- **In transit**: the response travels over a network from the model-serving endpoint to a caller. An unencrypted or unauthenticated channel lets a man-in-the-middle rewrite it.
- **At an integration or UI layer**: a gateway, adapter, or front-end reshapes the raw score into a decision. A compromised or buggy component there can substitute a different verdict.
- **In a shared store, queue, or cache**: predictions are frequently written to a database, topic, or cache for later consumption. Anything with write access can alter them at rest.
- **In logs and downstream feeds**: outputs are logged, exported, and re-consumed by analytics, billing, or automated response systems that trust the recorded value.

## Why Does This Matter?

Machine-learning outputs increasingly drive **automated, security-critical decisions** with no human in the loop: allow or deny a transaction, quarantine or release a file, admit or reject a login, escalate or dismiss an alert. When the decision itself can be rewritten downstream, every one of those controls becomes bypassable—without ever touching the model.

### Business Impact

- **Security Decisions Subverted**: A correct `fraud` / `malware` / `deny` verdict flipped to `benign` / `clean` / `allow` lets fraudulent payments, malicious files, or unauthorized access straight through.
- **Safety and Health Consequences**: In clinical, industrial, or automotive settings, a correct output altered before it reaches the operator or actuator can present a wrong diagnosis or trigger an unsafe action.
- **Financial Loss and Fraud**: Tampered risk scores, credit decisions, or pricing outputs translate directly into money moving the wrong way.
- **Silent, Deniable Failure**: Because the model was correct, monitoring the model's accuracy shows nothing. The breach hides in the plumbing, so it can persist and be denied.
- **Compliance and Trust**: Decisions that cannot be shown to be authentic undermine audit, regulatory, and contractual guarantees about how outcomes were reached.

### Technical Impact

- **Loss of Decision Authenticity**: The consumer cannot prove the result it acted on is the result the model emitted.
- **Control Bypass**: Any downstream security gate keyed on the prediction (block/allow, flag/pass) is neutralised by flipping the value it reads.
- **Replay Exposure**: A stale but validly-shaped result can be substituted for the current one, forcing an outdated decision.
- **Poisoned Feedback and Analytics**: Altered logged outputs corrupt dashboards, retraining datasets, and automated response pipelines that consume them as ground truth.

## Technical Context

### The Prediction Is a Security-Critical Message

The durable way to think about ML09 is to treat every prediction as a **message that a downstream component will act on**. Messages that drive decisions need two properties independent of transport:

- **Authenticity**: the consumer can confirm the result came from the legitimate model-serving component and not an impostor.
- **Integrity**: the consumer can confirm the result has not been altered by any hop in between.

Encryption alone (confidentiality) does not provide these; and TLS protects a hop, not the message once it is stored or forwarded. That is why ML09 defenses combine **secure channels** with **signed/authenticated results** that the consumer independently verifies.

### Common ML09 Scenarios

#### 1. Interception and Alteration in Transit

```
Model server ---(plain HTTP inference API)---> Caller
                      ^
              MITM rewrites the JSON body:
              {"decision":"deny"}  ->  {"decision":"allow"}
```

**Risk**: An unencrypted or unauthenticated inference API lets anyone on the path silently change the verdict the caller receives.

#### 2. Tampering at the Integration / UI Layer

```
Model -> adapter/gateway -> UI widget -> human or automation acts
                 ^                ^
      compromised component  or  client-side value the
      substitutes a verdict      browser trusts and can be edited
```

**Risk**: A component that reshapes the raw score into a shown/acted-on decision can substitute a different one. If the UI trusts a value the client controls, the displayed verdict is not the model's.

#### 3. Manipulating a Shared Results Store / Queue / Cache

```
Model --> writes result to DB / Kafka topic / Redis cache
                              ^
          any principal with write access edits the record
          at rest before the consumer reads it
```

**Risk**: Predictions parked for asynchronous consumption are only as trustworthy as the access control and integrity protection on that store.

#### 4. Altering Logged or Downstream-Consumed Outputs

```
Model output -> log line / export / metrics -> SIEM, billing,
                                               auto-response, retraining
                     ^
        edited record makes downstream systems act on a false value
```

**Risk**: Systems that consume recorded outputs as ground truth inherit any tampering of those records.

#### 5. Verdict Flipping by a Compromised Component

```
"fraud"  -> "benign"      "malware" -> "clean"      "deny" -> "allow"
```

**Risk**: A single compromised hop that handles results can invert exactly the decisions a security control depends on.

#### 6. Replaying Stale Results

```
t0: model says {"risk":"low"}  (captured)
t1: model says {"risk":"high"} (current, correct)
attacker re-serves the t0 result -> consumer acts on stale "low"
```

**Risk**: Without freshness binding (nonce/timestamp), an old but validly-shaped result can be replayed to force an outdated decision.

### Boundaries Where Output Integrity Is Lost

| Boundary | Typical Weakness | Consequence |
|----------|------------------|-------------|
| Inference API in transit | Plain HTTP, no mutual auth, no message signature | MITM rewrites the verdict |
| Integration / gateway layer | Compromised or over-trusted adapter | Substituted decision |
| UI / client | Client-controlled value trusted as the result | Displayed/acted verdict is not the model's |
| Results store / queue / cache | Broad write access, no integrity on records | At-rest tampering before consumption |
| Logs / downstream feeds | Mutable records consumed as ground truth | Corrupted analytics, billing, retraining |
| Freshness | No nonce/timestamp binding | Replay of stale results |

## Real-World Impact

Public post-mortems rarely isolate "the model was right but the output was tampered" as a named root cause, so the honest picture is drawn from **well-established incident classes** rather than specific CVEs or breach statistics.

### Incident Class 1: Man-in-the-Middle on Unauthenticated Decision Channels

**Pattern**:
- A service exposes results over an unencrypted or unauthenticated channel on the assumption the network is trusted.
- An attacker positioned on that path (compromised host, rogue proxy, ARP/DNS abuse, hostile network) rewrites the response body in flight.

**Impact**: The consumer acts on a verdict the producer never sent. This is the same class of weakness long documented for any security-relevant value carried over cleartext; applied to ML, the tampered value is the decision itself.

**Root Cause**: Confidentiality and integrity of the decision channel were assumed rather than enforced. Fixed by TLS/mTLS plus a signature on the result the consumer verifies.

### Incident Class 2: Tampering with Results at Rest in a Shared Store or Queue

**Pattern**:
- Predictions are written to a database, topic, or cache that many services can reach.
- A principal with more write access than it should have (over-broad role, shared credential, compromised neighbour) edits stored results before they are consumed.

**Impact**: Asynchronous consumers read altered decisions with no indication they changed—the classic consequence of trusting a shared datastore's contents without record-level integrity.

**Root Cause**: Over-broad access plus no integrity protection on the records. Fixed by least-privilege access and signing each record so readers can verify it.

### Incident Class 3: Client-Side Trust of a Decision Value

**Pattern**:
- A front-end or thick client receives a raw result and the value that drives the action is one the client can see and modify.
- The user (or malware on the client) changes the value before it is acted on or reported back.

**Impact**: The action taken diverges from the model's actual output—the well-known consequence of trusting client-controlled data, here applied to an ML decision.

**Root Cause**: A security decision was placed where the client could edit it. Fixed by keeping the authoritative decision server-side and verifying a signed result before acting.

## Prevalence and Statistics

Output Integrity Attack is one of the categories in the **OWASP Machine Learning Security Top 10**. It is easy to overlook precisely because teams concentrate their assurance on the model and the training data, while treating the prediction, once emitted, as trusted plumbing.

Rather than cite precise figures (which are scarce and vary by source), the defensible picture is:

- The **underlying weaknesses are extremely common**: unencrypted internal calls, over-broad write access to shared stores, client-trusted values, and mutable logs are all frequent findings independent of ML.
- The **ML-specific blind spot** is that predictions are seldom treated as security-critical messages needing authenticity and integrity, so these weaknesses go unaddressed on the output path.
- The **impact is high**: a single flipped verdict can bypass a security control while the model—and the metrics that watch it—look completely healthy.

> Note: there is no reliable public breach count isolating ML09 as the named cause. Treat any single figure as illustrative. The durable takeaway is that the enabling weaknesses are widespread and the outputs simply are not protected as the decisions they are.

## Common Misunderstandings

### Myth 1: "If the model is accurate, the output is trustworthy"

**Reality**: Accuracy is a property of the model; trustworthiness of the decision also depends on everything the result passes through afterwards. A correct output altered in transit is a wrong decision.

### Myth 2: "This is just another adversarial-example (ML01) problem"

**Reality**: ML01 changes the *input* so the model itself errs. ML09 leaves the model correct and changes the *output* after the fact. They need different defenses—robustness for ML01, authenticity and integrity for ML09.

### Myth 3: "It's all internal traffic, so integrity is unnecessary"

**Reality**: Internal networks are routinely reached through compromised services, lateral movement, and over-broad credentials. Internal decision channels need the same integrity protection as external ones.

### Myth 4: "TLS on the endpoint means the output is protected"

**Reality**: TLS protects a single hop while data is on the wire. It does nothing once the result is written to a store, placed on a queue, logged, or forwarded. End-to-end authenticity needs the result itself to be signed and verified.

### Myth 5: "We log every prediction, so we'd notice tampering"

**Reality**: If the logs are the thing that was altered—or are mutable and unsigned—they record the attacker's value, not the model's. Logs must be tamper-evident to be evidence.

### Myth 6: "Signing the result is overkill for a prediction"

**Reality**: A prediction that gates a payment, a file, or an access decision is exactly as security-critical as any authorization token. If you would authenticate the token, authenticate the decision.

## How ML09 Differs from Related Issues

| Aspect | ML09 Output Integrity | ML01 Input Manipulation | ML02 Data Poisoning |
|--------|-----------------------|-------------------------|---------------------|
| **What is attacked** | The result after the model produced it | The input to the model | The training data |
| **Is the model correct?** | Yes—output altered downstream | No—model is fooled | No—model learned wrong behaviour |
| **Where it lives** | Transit, store, queue, UI, logs | Inference input path | Training pipeline |
| **Typical fix** | TLS/mTLS + sign & verify results | Robustness, input validation | Data provenance, sanitisation |

## Key Takeaways

1. **The decision, not just the model, must be protected**—ML09 lives on the path between the model and whatever acts on the result.
2. **Correct model, wrong decision**—a flipped verdict subverts a security control while the model's metrics look healthy.
3. **Treat the prediction as a security-critical message**—it needs authenticity and integrity, not just confidentiality.
4. **Protect the whole path**—transit, stores, queues, caches, UIs, and logs, not only the serving endpoint.
5. **Bind freshness**—without a nonce or timestamp, a stale-but-valid result can be replayed.

## How to Identify if You're Vulnerable

- [ ] Is every hop that carries a prediction encrypted and mutually authenticated (TLS/mTLS)?
- [ ] Is each result signed or MAC'd by the producer so the consumer can verify it was not altered?
- [ ] Does the consumer actually verify that signature before acting—and reject on failure?
- [ ] Are results in any shared store, queue, or cache integrity-protected, not just access-controlled?
- [ ] Is every result bound to a nonce or timestamp so stale results cannot be replayed?
- [ ] Is the authoritative decision kept server-side rather than trusted from the client?
- [ ] Do consumers sanity-check outputs (range, schema, allowed labels) before acting?
- [ ] Are logged outputs tamper-evident (append-only / signed) so they are usable as evidence?
- [ ] Do components that handle results run with least privilege on those results?
- [ ] Would tampering on any single hop be detected, or would it pass silently?

If you answered "no" or "not sure" to several of these, a correct prediction in your system can likely be altered before it is acted on.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How the output path is intercepted and rewritten
- **[Prevention](prevention.md)**: Protect the pipeline end-to-end and sign every result
- **[Examples](examples.md)**: Insecure vs. secure inference pipelines in Python
- **[Back to ML Top 10](/learn/ml)**: Continue with the other ML security categories
- **[Practice](/practice)**: Apply what you have learned in hands-on challenges
