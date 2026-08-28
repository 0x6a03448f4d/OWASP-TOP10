# LLM10:2025 Unbounded Consumption - Attack Vectors

## Table of Contents
- [The Core Attack Flow](#the-core-attack-flow)
- [Attack Patterns](#attack-patterns)
- [2025 Threat Landscape](#2025-threat-landscape)
- [Next Steps](#next-steps)

Unbounded Consumption attacks all share a shape: find the dimension of cost the application forgot to limit, then drive it as hard as possible. That dimension might be request rate, input size, output length, fan-out, concurrency, or raw query volume aimed at copying the model. The patterns below are grouped by which lever they pull, each with a concrete illustration of how it is triggered.

## The Core Attack Flow

```
  1. RECON        Probe the endpoint. What limits exist?
                  - Send a huge prompt. Is it rejected or served?
                  - Ask for a very long answer. Is max_tokens enforced?
                  - Fire 100 requests fast. Any 429s? Any per-key quota?
                  - Is auth required, or is usage anonymous & uncounted?

  2. PICK A LEVER Choose the unbounded dimension with the best
                  cost-amplification ratio (work caused / effort spent).

  3. AMPLIFY      volume  x  cost-per-request  x  concurrency
                  Convert cheap input into expensive backend work.

  4. GOAL         DoS  (exhaust GPU / memory / workers)   -> outage
                  DoW  (drive metered token spend)         -> ruinous bill
                  THEFT (harvest I/O pairs at scale)       -> model clone

  5. EVADE        Stay under naive per-request rate limits by
                  spreading across keys/IPs, or by making each of a
                  small number of requests maximally expensive.
```

## Attack Patterns

### 1. Volumetric Query Flooding

The most direct attack: send far more requests than the backend can serve, exhausting the worker pool and the GPU queue. Against a metered backend the same flood becomes a wallet attack rather than an outage.

```python
# A trivial flood: N workers, unlimited requests, tiny cheap prompt
import asyncio, httpx

async def hammer(client, i):
    while True:
        await client.post("https://target/api/chat",
                           json={"message": "hi"})   # cheap in, but N of them

async def main():
    async with httpx.AsyncClient(timeout=None) as client:
        await asyncio.gather(*[hammer(client, i) for i in range(500)])

asyncio.run(main())
```

**Why it works**: no per-identity rate limit and no global concurrency cap. **Signal to defenders**: request rate per key/IP spikes far above baseline.

### 2. Long-Input / Context-Window Stuffing

Instead of many requests, send few &mdash; but make each prompt enormous. Because attention cost scales superlinearly with sequence length, a maximum-length prompt can cost dramatically more GPU time and memory than a normal one.

```
POST /api/summarize
{
  "text": "<a 900,000-character pasted document repeated to fill
            the entire context window>",
  "instructions": "Summarize, then re-summarize each paragraph,
                   then expand each summary back to full length."
}
# Few requests, each near the model's maximum context = worker saturation
```

**Why it works**: no input byte/token cap; the app trusts the model's context window as the only limit. **Signal**: input token counts far above the median.

### 3. Unbounded Output Generation

Output tokens are usually the most expensive half of a request. If `max_tokens` is unset or huge, an attacker coaxes the model into generating for as long as possible.

```
{
  "message": "Count from 1 to 1,000,000, one number per line.
              Do not stop or summarize. Then list every US ZIP code.",
  "max_tokens": null          // no cap -> generate until the model gives up
}

// Variations that defeat weak stop conditions:
//   "Repeat the word 'consumption' forever."
//   "Write an infinitely long story; never conclude."
//   "Output the full text, then output it again 50 times."
```

**Why it works**: no server-enforced output cap; the client's requested `max_tokens` is trusted. **Signal**: output token counts near the ceiling on many requests.

### 4. Recursive / Self-Amplifying Prompts

Prompts engineered so the model's own output feeds back into more work, especially where the application loops on model output (re-summarising, re-translating, expanding).

```
"Take your answer, then answer it again in more detail.
 Repeat this expansion 10 times, each time doubling the length.
 For every sentence, generate three follow-up questions and answer them."

# One request; the instructions describe exponential growth in output.
```

**Why it works**: the app treats the model's requested workload as bounded when the prompt has actually asked for exponential expansion. **Signal**: single requests with very high output-to-input ratios.

### 5. Agentic Fan-Out and Tool-Loop Abuse

Tool-using or multi-agent systems turn one user request into a chain of inferences. Without a bounded step budget, an attacker (or a confused agent) can make that chain run away.

```
User: "Research every company in the S&P 500, and for each one
       spawn a sub-agent to research all of its competitors,
       recursively, until you have full market coverage."

  agent -> 500 sub-agents -> each spawns more -> each step is an inference
  One request => thousands of model calls, unbounded depth.
```

**Why it works**: no cap on agent steps, recursion depth, tool calls, or total token budget per user task. **Signal**: a single task id accumulating a huge number of downstream model calls.

### 6. RAG Context Amplification

Retrieval-augmented generation pulls documents into the prompt. If retrieval breadth is unbounded, an attacker crafts queries that match many large documents, inflating input tokens on every call.

```
POST /api/ask
{
  "query": "Summarize everything related to the letter 'e'",
  "top_k": 500          // retrieve 500 large chunks into the prompt
}
# Broad query x large top_k x large chunk size = massive prompt per request
```

**Why it works**: `top_k` and total retrieved context are not capped; retrieval size is attacker-influenced. **Signal**: retrieved-context size and input tokens spike together.

### 7. Sponge Examples (Energy-Latency Inputs)

Rather than volume, craft individual inputs that push the model toward worst-case compute &mdash; maximising the tokens produced by a given tokenizer, or triggering the longest, least-cacheable generations. Documented in the "sponge examples" research (Shumailov et al., 2021).

```
# Inputs chosen to maximise tokenizer expansion and generation length:
#   - dense unicode / rare scripts that tokenize into many tokens
#   - long runs of unique tokens that defeat prompt caching
#   - prompts that reliably elicit maximum-length, non-repetitive output
# Goal: highest possible GPU-seconds per single accepted request.
```

**Why it works**: limits count requests, not the compute cost of each one. **Signal**: latency and token-per-request outliers with low request counts.

### 8. Concurrency Abuse (Parallel In-Flight Requests)

Even under a per-minute rate limit, an attacker can open many requests *simultaneously*. If nothing caps concurrent in-flight work, a handful of parallel expensive generations saturates every worker at once.

```python
# Stay within "60 requests/minute" but fire all 60 in the same second,
# each requesting a maximum-length generation:
import asyncio, httpx
async def burst():
    async with httpx.AsyncClient(timeout=None) as c:
        await asyncio.gather(*[
            c.post("https://target/api/chat",
                   json={"message": "write a 50-page report",
                         "max_tokens": 100000})
            for _ in range(60)
        ])
asyncio.run(burst())
```

**Why it works**: rate limits bound arrivals over time but not simultaneous occupancy. **Signal**: concurrent-in-flight count per key exceeds a safe threshold.

### 9. Denial of Wallet (Cost Amplification on Metered APIs)

When the backend is a pay-per-token hosted model, the attacker's objective inverts: they *want* the service to keep succeeding, because every success is money spent. Autoscaling ensures no outage &mdash; and no natural brake on cost.

```
Attacker economics:
  cost to send a request      ~=  near zero (a few input tokens)
  cost you incur per request  ~=  price_out x max_output_tokens
  amplification factor        =  (your cost) / (their cost)  ->  very large

Sustain moderate, "legitimate-looking" traffic 24/7 with maxed-out
output lengths. No spike to trigger DoS alarms; just a climbing bill.
```

**Why it works**: no per-tenant cost budget, no billing cap, alerts (if any) fire only after the damage. **Signal**: cumulative spend per tenant drifting above budget even without a traffic spike.

### 10. Model Extraction / Functional Distillation

The theft axis. An attacker queries the model at scale, stores input/output pairs, and trains a cheaper "student" model to reproduce its behaviour. Query access alone is the vulnerability.

```python
# Harvest a distillation dataset from the target's own endpoint:
prompts = generate_diverse_prompts(n=1_000_000)   # broad coverage
dataset = []
for p in prompts:
    y = target_api.complete(p)      # unlimited, unmonitored queries
    dataset.append((p, y))
student = train_small_model(dataset)  # a functional clone at a fraction of cost
```

**Why it works**: unlimited, unauthenticated, or unmonitored query volume; outputs are rich training signal. Foundational result: Tramer et al., "Stealing Machine Learning Models via Prediction APIs" (USENIX Security 2016). **Signal**: broad, systematic, high-volume querying that covers the input space rather than serving a real task.

### 11. Model Inversion & Membership Inference

A subtler theft: rather than cloning behaviour, extract properties of the training data. Model-inversion queries reconstruct likely training inputs; membership-inference queries determine whether a specific record was in the training set.

```python
# Membership inference (conceptual): compare the model's confidence /
# perplexity on candidate records; training members often score differently.
for record in candidates:
    score = target_api.score(record)     # many probing queries per record
    if looks_like_training_member(score):
        report(record)                   # privacy leak inferred, not stolen weights
```

**Why it works**: unlimited probing queries let an attacker measure the model's behaviour precisely enough to infer training-data facts. **Signal**: repetitive, high-volume probing of near-identical inputs.

### 12. Multimodal Payload Amplification

Multimodal endpoints accept images, audio, or video. A single request carrying a very large image or a long audio file can cost far more to process than a text prompt &mdash; and a batch of them multiplies that.

```
POST /api/analyze
{
  "images": [ <50 high-resolution images encoded per request> ],
  "audio":  [ <several hours of audio> ],
  "prompt": "Describe every frame and transcribe all audio in full."
}
# Large media in + exhaustive analysis out = heavy cost per single request
```

**Why it works**: no cap on media count, resolution, duration, or per-request payload size. **Signal**: request payload bytes and processing time far above text baselines.

### 13. Streaming / Connection Pinning

Streaming responses hold a connection open for the life of the generation. An attacker opens many slow, long streams to pin server-side concurrency slots &mdash; a Slowloris-style attack adapted to LLM streaming.

```
# Open many streaming generations, read one token at a time very slowly.
# Each held-open stream occupies a worker slot and a connection.
# Enough of them and no new request can be served.
```

**Why it works**: no cap on concurrent streams per client and no idle/stream timeout. **Signal**: many long-lived low-throughput connections from one identity.

### 14. Amplification via Unauthenticated / Free Endpoints

Anonymous access removes attribution: with no identity to bound, per-user quotas are meaningless and cost cannot be assigned. Free trials and demo endpoints are prime targets, often abused across many disposable identities.

```python
# Rotate free API keys / disposable accounts / IPs to stay under
# any single identity's limit, while aggregate consumption is unbounded.
for key in disposable_keys:
    drive_expensive_traffic(key)   # each key looks "normal"; the sum is huge
```

**Why it works**: usage cannot be attributed to a bounded identity, so per-identity limits are trivially reset. **Signal**: many short-lived identities each consuming up to their individual limit.

## 2025 Threat Landscape

Several trends make these vectors more pressing in 2025 than in the 2023 era of the original Model-DoS and Model-Theft entries:

- **Agentic systems are mainstream.** Tool use, multi-step planning, and multi-agent orchestration mean one request routinely expands into many inferences &mdash; fan-out abuse (patterns 5, 6) is now a first-class risk.
- **Metered, hosted models dominate.** Most applications call a paid model API, so denial of wallet (pattern 9) is often more damaging and more likely than a classic outage.
- **Larger context windows.** Million-token contexts raise the ceiling on per-request cost, making long-input and multimodal amplification (patterns 2, 12) far more potent.
- **Valuable fine-tuned models.** Organisations ship proprietary fine-tunes through public endpoints, increasing the payoff of extraction (patterns 10, 11).
- **Accidental self-inflicted attacks.** Buggy retry loops, runaway agents, and viral traffic reproduce every pattern above without any adversary &mdash; the same controls defend against both.

## Next Steps

- **[Prevention](prevention.html)**: The layered limits, quotas, budgets, and monitoring that neutralise these vectors.
- **[Examples](examples.html)**: Vulnerable-vs-secure code for each control.
- **[Overview](overview.html)**: The concepts and business context behind the category.
- **[Hands-On Lab](lab/unbounded-consumption/)**: Reproduce these attacks safely and watch the defenses stop them.
