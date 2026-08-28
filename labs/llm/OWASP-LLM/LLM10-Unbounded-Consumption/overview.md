# LLM10:2025 Unbounded Consumption - Overview

## Table of Contents
- [What is Unbounded Consumption?](#what-is-unbounded-consumption)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence](#prevalence)
- [Common Misunderstandings](#common-misunderstandings)
- [Self-Assessment](#self-assessment)
- [Next Steps](#next-steps)

## What is Unbounded Consumption?

**Unbounded Consumption** occurs when an application lets clients drive a Large Language Model to perform inference &mdash; and the work it will do, the resources it will spend, and the money it will cost &mdash; without effective limits. Every request an LLM serves consumes compute (usually GPU), memory, wall-clock time, and, on a metered API, real currency billed per token. When there is no ceiling on how much of that a single caller can trigger, an attacker (or a buggy client) can convert a trickle of cheap requests into a flood of expensive work.

The 2025 edition of the OWASP Top 10 for LLM Applications introduced this category by **merging and broadening two 2023 entries**: *LLM04: Model Denial of Service* and *LLM10: Model Theft*. The insight behind the merge is that both problems share one root cause &mdash; the system permits inference (or the extraction of a model's value) to proceed *without bounds*. Whether the attacker's goal is to knock the service offline, run up its cloud bill, or clone the model by querying it to exhaustion, the missing control is the same: a limit on consumption.

### Core Concept

```
A single inference request costs:  tokens_in + tokens_out  ->  GPU-seconds  ->  $$$

  Bounded service                        Unbounded service
  ---------------                        -----------------
  input capped (tokens/bytes)            accepts megabyte prompts
  output capped (max_tokens)             lets the model run until it stops
  rate limited (req/min per key)         unlimited requests per caller
  concurrency capped                     unlimited parallel in-flight work
  cost budget + billing cap              no ceiling on spend
  timeouts + backpressure                requests pinned open indefinitely
  auth required                          anonymous, uncounted usage

  Result: predictable cost & latency     Result: DoS, "denial of wallet",
                                                  and model extraction
```

Unbounded Consumption is best understood as **three overlapping harms that all stem from uncontrolled inference**:

- **Denial of Service (DoS)** &mdash; resource exhaustion degrades or halts the service for legitimate users.
- **Denial of Wallet (DoW)** &mdash; on pay-per-token or autoscaling infrastructure, the attack succeeds even when the service *stays up*: it simply generates a ruinous bill. The system scales to absorb the load and hands you the invoice.
- **Model theft / functional extraction** &mdash; an attacker who can query the model without limit can distill it, replicate its behaviour, or reconstruct sensitive properties of its training data, stealing the intellectual property embodied in the model itself.

### Why It's Different for LLMs

Classic denial-of-service is about packets-per-second against cheap request handlers. LLM inference changes the economics in ways that make consumption attacks unusually potent:

- **Asymmetric cost.** A short, cheap prompt can command an enormous, expensive response. "Write a 5,000-word essay, then translate it into 20 languages" is a few tokens in and hundreds of thousands of tokens out.
- **GPU scarcity.** Inference runs on expensive, capacity-constrained accelerators. A handful of large-context requests can saturate a GPU that serves thousands of normal chats.
- **Superlinear scaling.** Transformer attention cost grows roughly with the square of the sequence length, so a request that is 10x longer can be far more than 10x more expensive to serve.
- **Metered billing.** When you build on a hosted model API, usage *is* money. Autoscaling that protects availability directly amplifies the financial blast radius.
- **The model is the asset.** The weights represent enormous training investment. Query access alone can be enough to copy the behaviour it encodes.

## Why Does This Matter?

Unbounded Consumption is ranked **LLM10** in the 2025 list. A low list position is not a low severity &mdash; it reflects how the category was folded together late in the ranking process. In practice this is one of the most *reliably exploitable* issues in production LLM systems, because it needs no jailbreak, no clever prompt, and often no authentication: it only needs the ability to send requests.

### Business Impact

- **Runaway cost / denial of wallet**: A metered LLM backend under sustained abuse can turn a predictable monthly bill into an emergency overnight. Because autoscaling hides the load as "success", the first signal is frequently the invoice or a billing alert.
- **Service outage**: Resource exhaustion degrades latency and availability for every legitimate user, breaching SLAs and eroding trust.
- **Intellectual-property loss**: A proprietary or fine-tuned model that took months and significant spend to build can be functionally cloned through the public endpoint, destroying competitive advantage.
- **Data-confidentiality risk**: Extraction-style querying can surface memorised training data or infer whether specific records were used in training, creating privacy and regulatory exposure.
- **Operational instability**: Even without a malicious actor, an unbounded design means one buggy retry loop or one viral moment can produce the same outage or bill.

### Technical Impact

- **GPU / memory exhaustion**: Long contexts and large batches consume VRAM and stall or crash inference workers.
- **Queue saturation and head-of-line blocking**: A few very large requests monopolise workers, so short requests wait behind them.
- **Thread / connection pinning**: Streaming responses and slow generations hold connections open, exhausting server-side concurrency slots.
- **Cascading failure**: Timeouts trigger client retries, which add load, which trigger more timeouts &mdash; a feedback loop that amplifies the original spike.
- **Model replication**: High-volume input/output collection yields a labelled dataset sufficient to train a cheaper "student" model that mimics the target.

## Technical Context

### The Cost of a Single Inference

To reason about consumption you have to reason about what one request actually spends. For a token-based model the dominant factors are the number of input tokens (the *prompt*, including any retrieved context and conversation history) and the number of output tokens the model generates. Output tokens are usually the more expensive half, because each one is produced by a separate forward pass and, on hosted APIs, is often priced higher than input.

```
request_cost  ~=  price_in  x  tokens_in  +  price_out  x  tokens_out

Amplification levers an attacker controls:
  tokens_in    long documents, deep chat history, RAG context stuffing
  tokens_out   "keep going", "repeat", "list all", high max_tokens
  fan-out      one prompt -> many tool calls / sub-queries / agent steps
  concurrency  N identical expensive requests in parallel
  batch        multimodal payloads (large images, long audio) per request
```

### The Three Harm Axes

| Axis | Attacker goal | Succeeds when... | Primary control |
| --- | --- | --- | --- |
| Denial of Service | Make the service slow or unavailable | Capacity is finite and unprotected | Rate limits, concurrency caps, timeouts, queue limits |
| Denial of Wallet | Generate a ruinous bill | Billing is metered / autoscaling is uncapped | Cost budgets, billing caps, per-tenant quotas, alerts |
| Model theft | Replicate the model or its data | Query volume is unlimited and unlogged | Auth, quotas, anomaly detection, watermarking, logging |

A control that stops one axis does not automatically stop the others. Aggressive rate limiting curbs DoS and DoW but a patient attacker can still extract a model slowly, under the radar, unless volume and pattern anomalies are also monitored. This is why the prevention guidance is explicitly *layered*.

### Where Unbounded Consumption Hides in an LLM Stack

- **The public API edge**: an endpoint that forwards user text straight to a model with no size, rate, or cost limit.
- **RAG pipelines**: retrieval that pulls unbounded context into the prompt, multiplying input tokens per query.
- **Agentic loops**: tool-using agents that can call themselves or each other, turning one user request into an open-ended chain of inferences.
- **Batch / async jobs**: bulk endpoints that accept a list of items with no cap on list length.
- **Free / anonymous tiers**: unauthenticated access that makes usage impossible to attribute or bound per caller.

## Real-World Impact

The incidents below are described as **verifiable classes of event** drawn from published research and widely reported operational patterns. Specific dollar figures and internal details vary by victim and are frequently not disclosed, so none are invented here.

### Case Class 1: Denial of Wallet on Metered LLM and Cloud APIs

**Pattern**: An application exposes a hosted-model backend (or serverless functions that call one) without per-caller cost limits. An attacker &mdash; or an accidental client-side retry loop &mdash; drives sustained, high-volume, high-token requests.

**Outcome**: The platform autoscales and keeps serving, so availability looks healthy while token spend climbs far above budget. Operators discover the problem through a billing alert rather than an outage. This is the same dynamic that the cloud-security community has long documented as "denial of wallet" against pay-as-you-go serverless functions; hosted LLM pricing makes it sharper because a single request can bill for a very large number of output tokens.

**Root cause**: No cost budget, no billing cap, no per-tenant quota; autoscaling optimised purely for availability.

### Case Class 2: Model Extraction / Functional Distillation via a Public API

**Pattern**: A model is reachable through an inference API with generous or unlimited query volume. An attacker systematically queries it and stores the input/output pairs, then trains a smaller "student" model on that data to approximate the target's behaviour.

**Outcome**: A functional copy of a proprietary model at a fraction of the original training cost. This is not hypothetical: the foundational academic result "Stealing Machine Learning Models via Prediction APIs" (Tramer et al., USENIX Security 2016) demonstrated extraction against prediction APIs, and subsequent work has shown that modern LLMs can be partially distilled or have specific parameters extracted through query access alone. Providers' terms of service now routinely prohibit using outputs to train competing models precisely because query-based cloning is practical.

**Root cause**: Unlimited, unauthenticated, or unmonitored query access &mdash; consumption of the model's *value* without bound.

### Case Class 3: Sponge Examples (Energy-Latency Attacks)

**Pattern**: Instead of many requests, an attacker crafts *individual* inputs designed to maximise the work per request &mdash; inputs that push a model toward its worst-case compute and latency. The research literature calls these "sponge examples" (Shumailov et al., 2021), which showed inputs that dramatically increase the energy and time a neural network spends on a single inference.

**Outcome**: A small number of requests inflicts outsized load, defeating naive rate limits that count requests but not the cost of each one.

**Root cause**: Controls that bound request *count* but not request *cost* (tokens, sequence length, generation length).

### Case Class 4: Long-Context and Unbounded-Output Resource Exhaustion

**Pattern**: An endpoint accepts very long prompts or permits very long generations. Because attention cost scales superlinearly with sequence length, a handful of maximum-length requests saturates GPU memory and stalls the worker pool.

**Outcome**: Latency spikes and timeouts for all users; in memory-constrained deployments, worker crashes. Retries then compound the load. This mirrors the classic algorithmic-complexity DoS pattern (of which ReDoS is the best-known relative) applied to transformer inference.

**Root cause**: No input token/byte limit and no output `max_tokens` cap.

## Prevalence

Unbounded Consumption is **extremely common** in real deployments, for a straightforward reason: the insecure configuration is the *easy* one to ship. Wiring a user text box to a model API and returning the response "just works" in a demo, and nothing in that happy path forces a developer to add token limits, quotas, or budgets. Those controls only become obviously necessary after the first surprise bill or the first outage.

Several factors keep prevalence high:

- **Defaults favour availability, not limits.** Hosted APIs and autoscaling platforms are built to absorb load, so the platform will happily spend on your behalf unless you tell it not to.
- **Cost controls are opt-in.** Billing caps, per-tenant quotas, and budget alerts must be configured deliberately; they are rarely present in a first release.
- **Testing rarely includes abuse.** Load tests model expected traffic, not an adversary optimising for maximum tokens per request.
- **Agentic and RAG designs multiply exposure.** Each new tool, retrieval step, or sub-agent adds a way for one request to expand into many inferences.

Because exploitation requires only the ability to send requests &mdash; no authentication bypass, no jailbreak &mdash; the barrier to entry is among the lowest of any category in the list.

## Common Misunderstandings

### "Autoscaling protects us."

Autoscaling protects *availability*, and in doing so it converts a denial-of-service into a denial-of-wallet. Scaling to meet malicious demand means paying to serve malicious demand. Without a cost ceiling, autoscaling is an amplifier, not a defence.

### "We rate-limit requests, so we're covered."

Counting requests is necessary but not sufficient. A single request can be arbitrarily expensive (a maximum-length prompt, an unbounded generation, a sponge input). Effective limits must bound the *cost* of each request &mdash; input tokens, output tokens, and concurrency &mdash; not just how many requests arrive.

### "This is just classic DoS with a new name."

The DoS axis is familiar, but two things are genuinely new: the *denial-of-wallet* failure mode, where the attack wins while the service stays up, and *model theft*, where the resource being consumed without bound is the model's intellectual property itself. Neither is addressed by traditional network-DoS thinking.

### "Model theft requires stealing the weights."

Functional theft needs only query access. An attacker who can collect enough input/output pairs can train a student model that approximates the target's behaviour, or infer sensitive properties of the training data, without ever touching the weight files.

### "Only anonymous endpoints are at risk."

Authentication helps attribute and bound usage, but an authenticated attacker &mdash; or a compromised API key, or a legitimate but buggy integration &mdash; can consume just as much. Per-identity quotas and budgets are still required behind the login.

## Self-Assessment

Use these questions to gauge your exposure. Each "no" is a gap an attacker (or an accident) can exploit.

- Is there a hard cap on **input size** (bytes and tokens) for every endpoint that reaches a model?
- Is there a hard cap on **output length** (`max_tokens`) on every generation call?
- Are requests **rate limited per identity** (user, API key, tenant) &mdash; not just per IP?
- Is there a cap on **concurrent in-flight requests** per caller and globally?
- Do model calls have **timeouts**, with backpressure or a circuit breaker when the backend is saturated?
- Is there a **per-tenant cost budget** and a **hard billing cap** with alerts before the ceiling?
- Does **agent / tool / RAG fan-out** have a bounded step count and context size?
- Is access **authenticated**, so usage can be attributed and bounded per identity?
- Do you **monitor for anomalies** &mdash; sudden volume, unusual token totals, systematic querying that looks like extraction?
- Does the service **degrade gracefully** (queue, shed load, return a clear 429) instead of collapsing under overload?

### Key Takeaways

- **Bound every dimension of cost**: input tokens, output tokens, request rate, and concurrency &mdash; not just request count.
- **Treat money as a resource**: cost budgets and billing caps are security controls, not just finance hygiene.
- **Defend the model itself**: quotas, authentication, logging, and anomaly detection deter extraction.
- **Fail closed and gracefully**: shed load with clear 429s rather than melting down or silently overspending.
- **Layer the controls**: no single limit covers DoS, denial of wallet, and theft at once.

## Next Steps

- **[Attack Vectors](attack-vectors.html)**: The concrete patterns attackers use to drive unbounded consumption.
- **[Prevention](prevention.html)**: A layered set of limits, quotas, budgets, and monitoring.
- **[Examples](examples.html)**: Vulnerable-vs-secure code for gateways, rate limiting, and quotas.
- **[Hands-On Lab](lab/unbounded-consumption/)**: Practice detecting and containing consumption attacks against a running LLM service.
