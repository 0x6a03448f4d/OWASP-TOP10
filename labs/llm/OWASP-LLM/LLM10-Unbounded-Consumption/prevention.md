# LLM10:2025 Unbounded Consumption - Prevention

## Table of Contents
- [A Layered Defense Model](#a-layered-defense-model)
- [Layer 1: Input Controls](#layer-1-input-controls)
- [Layer 2: Output Controls](#layer-2-output-controls)
- [Layer 3: Rate Limiting & Quotas](#layer-3-rate-limiting--quotas)
- [Layer 4: Concurrency, Timeouts & Backpressure](#layer-4-concurrency-timeouts--backpressure)
- [Layer 5: Cost Budgets & Billing Caps](#layer-5-cost-budgets--billing-caps)
- [Layer 6: Authentication & Attribution](#layer-6-authentication--attribution)
- [Layer 7: Monitoring & Anomaly Detection](#layer-7-monitoring--anomaly-detection)
- [Layer 8: Anti-Extraction Controls](#layer-8-anti-extraction-controls)
- [Layer 9: Graceful Degradation](#layer-9-graceful-degradation)
- [Defense Checklist](#defense-checklist)
- [Next Steps](#next-steps)

## A Layered Defense Model

No single control stops Unbounded Consumption. The attack surface spans several independent dimensions of cost &mdash; input size, output size, request rate, concurrency, money, and query volume &mdash; and an attacker only needs one of them left open. The goal is **defense in depth**: bound every dimension, attribute every request to an identity, watch for anomalies, and fail gracefully when limits are hit.

```
  Request
     |
  [ Auth ]            reject anonymous / attribute to identity + tenant
     |
  [ Input limits ]    cap bytes + tokens; reject oversized prompts early
     |
  [ Rate + quota ]    per-identity req/min, tokens/day, spend/day
     |
  [ Concurrency ]     cap in-flight requests; queue with a bounded depth
     |
  [ Cost budget ]     check remaining budget BEFORE calling the model
     |
  [ Model call ]      enforce max_tokens + timeout on the inference itself
     |
  [ Monitor ]         meter actual tokens/cost; detect extraction patterns
     |
  Response            (or 429 / 402 / 503 with a clear, bounded error)
```

Enforce these **server-side, at a gateway** the client cannot bypass. Never rely on a limit that lives only in client code or in a value the client supplies (like a requested `max_tokens`) &mdash; treat every client-provided limit as a ceiling request to be clamped, not obeyed.

## Layer 1: Input Controls

Reject oversized work *before* it reaches the model. Enforce two independent limits: a cheap byte-length check at the edge, and a token-count check once you know the tokenizer. Count the *full* prompt &mdash; system prompt, retrieved RAG context, and conversation history included, not just the latest user message.

```python
MAX_REQUEST_BYTES   = 32 * 1024      # cheap early reject at the HTTP edge
MAX_INPUT_TOKENS    = 4_000          # after tokenization, whole prompt
MAX_HISTORY_TURNS   = 20             # bound conversation growth
MAX_RAG_CHUNKS      = 8              # cap retrieval breadth (top_k)
MAX_RAG_TOKENS      = 3_000          # cap total retrieved context
MAX_MEDIA_ITEMS     = 4              # images/audio per request
MAX_IMAGE_PIXELS    = 4_000_000      # downscale or reject above this
```

- **Byte cap first**: reject at the web server / gateway before allocating tokenizer work.
- **Token cap second**: tokenize and reject if the assembled prompt exceeds the budget; this is what actually correlates with cost.
- **Bound history**: truncate or summarise old turns so a long conversation cannot grow the prompt without limit.
- **Bound retrieval**: cap `top_k` and total retrieved tokens so RAG cannot inflate the prompt.
- **Bound media**: cap count, resolution, and duration; downscale large images server-side.

## Layer 2: Output Controls

Output tokens are usually the most expensive half of a request, so a server-enforced `max_tokens` is the single highest-leverage control. Always set it yourself; if the client supplies one, clamp it to your ceiling rather than trusting it.

```python
SERVER_MAX_OUTPUT_TOKENS = 1_024     # hard ceiling regardless of client ask

def clamp_output_tokens(requested: int | None) -> int:
    if requested is None:
        return DEFAULT_OUTPUT_TOKENS          # sensible default, not "unlimited"
    return min(requested, SERVER_MAX_OUTPUT_TOKENS)

# Also enforce:
#   - stop sequences to end generation deterministically
#   - a wall-clock generation timeout (see Layer 4)
#   - for streaming: a max token count that aborts the stream when reached
```

- **Always cap `max_tokens`** on every generation, streaming included.
- **Abort runaway streams**: stop the generation when the token cap is reached, don't just stop forwarding.
- **Detect degenerate output**: repetitive loops ("word word word...") should trip an early stop.

## Layer 3: Rate Limiting & Quotas

Rate limit per *identity* (user, API key, tenant), not only per IP &mdash; IPs are shared, spoofable, and rotate. Combine a short-window request limit with longer-window *token* and *spend* quotas, because a request-count limit alone does not bound the cost of each request.

```python
# Two complementary limits, both keyed by identity:
#   1. Request rate   -> smooths bursts        (e.g. 60 req / minute)
#   2. Token quota    -> bounds total work      (e.g. 200k tokens / day)
#   3. Spend quota    -> bounds total money      (e.g. $5 / day, see Layer 5)

import time, redis
r = redis.Redis()

def allow_request(identity: str, limit: int = 60, window: int = 60) -> bool:
    # Sliding-window counter in Redis, atomic via a pipeline.
    now = time.time()
    key = f"rl:{identity}"
    p = r.pipeline()
    p.zremrangebyscore(key, 0, now - window)      # drop entries outside window
    p.zadd(key, {f"{now}": now})
    p.zcard(key)
    p.expire(key, window)
    _, _, count, _ = p.execute()
    return count <= limit
```

Prefer an algorithm that smooths bursts &mdash; a sliding-window or token-bucket limiter &mdash; over a fixed-window counter, which allows a double burst at the window boundary. Return `429 Too Many Requests` with a `Retry-After` header so well-behaved clients back off.

## Layer 4: Concurrency, Timeouts & Backpressure

Rate limits bound arrivals over time; they do not bound how many requests are *in flight at once*. Cap concurrency explicitly, both per-identity and globally, and put a hard timeout on every model call so a slow or stuck generation cannot pin a worker forever.

```python
import asyncio

GLOBAL_CONCURRENCY   = 32            # total in-flight model calls
PER_IDENTITY_INFLIGHT = 2           # simultaneous calls per caller
MODEL_TIMEOUT_S      = 30           # wall-clock cap per generation

global_sem = asyncio.Semaphore(GLOBAL_CONCURRENCY)

async def call_model(identity, prompt, per_id_sems):
    sem = per_id_sems.setdefault(identity, asyncio.Semaphore(PER_IDENTITY_INFLIGHT))
    if sem.locked() and sem._value == 0:
        raise TooManyInflight()                  # shed, don't queue forever
    async with sem, global_sem:                  # bounded occupancy
        try:
            return await asyncio.wait_for(
                model.generate(prompt), timeout=MODEL_TIMEOUT_S)
        except asyncio.TimeoutError:
            raise UpstreamTimeout()              # free the slot, return 504
```

- **Bounded queue**: if you queue, cap the queue depth and reject (429/503) when full &mdash; never let it grow without limit.
- **Timeouts everywhere**: connect, first-token, and total-generation timeouts; also an idle timeout for streaming.
- **Circuit breaker**: when the backend is saturated or erroring, trip open and fail fast instead of piling on retries.
- **Bound retries**: cap client and server retries with exponential backoff and jitter so timeouts don't trigger a retry storm.

## Layer 5: Cost Budgets & Billing Caps

On a metered backend, money is the resource being attacked. Treat a cost budget as a security control: estimate the cost of a request *before* making it, deduct from a per-tenant budget, and refuse when the budget is exhausted. Back this with a hard billing cap at the provider so a bug in your own accounting cannot run away.

```python
PRICE_IN_PER_1K  = 0.003            # $ per 1k input tokens (example figures)
PRICE_OUT_PER_1K = 0.015           # $ per 1k output tokens
DAILY_BUDGET_USD = 5.00            # per tenant

def estimated_cost(tokens_in: int, max_out: int) -> float:
    return (tokens_in/1000)*PRICE_IN_PER_1K + (max_out/1000)*PRICE_OUT_PER_1K

def reserve_budget(tenant: str, cost: float) -> bool:
    # Atomically deduct the *worst-case* cost before the call; refund the
    # unused portion after, once actual output tokens are known.
    spent = float(r.get(f"spend:{tenant}") or 0)
    if spent + cost > DAILY_BUDGET_USD:
        return False                             # -> 402 Payment Required / 429
    r.incrbyfloat(f"spend:{tenant}", cost)
    return True
```

- **Pre-authorise worst case**: reserve `tokens_in + max_output_tokens` of budget before the call; refund the difference after.
- **Provider-side hard cap**: set the cloud/model provider's billing limit and per-key spend cap as a backstop.
- **Alert before the ceiling**: fire alerts at 50/80/100% of budget, per tenant and in aggregate, so you learn from a page, not an invoice.
- **Cap fan-out cost**: give each agent task a total token/step budget; abort the task when it is spent.

## Layer 6: Authentication & Attribution

You cannot bound per-identity usage without an identity. Require authentication on every endpoint that reaches a model, and tie rate limits, quotas, and budgets to a durable identity (account or tenant), not to easily-rotated signals like IP or a disposable free key.

- **No anonymous inference** on production endpoints; gate demos and free tiers behind an account with its own tight quota.
- **Attribute every request** to a user and tenant so consumption is measurable and limits are enforceable.
- **Resist Sybil abuse**: make disposable-account creation costly (verification, per-account funding limits) so an attacker cannot simply mint fresh identities to reset quotas.
- **Scope and rotate API keys**; support revoking a key the moment its usage looks abusive.

## Layer 7: Monitoring & Anomaly Detection

Limits stop the obvious; monitoring catches the patient. Meter *actual* tokens and cost per request (not just request counts) and alert on deviations from each identity's baseline.

```
Meter and alert on, per identity and in aggregate:
  - requests / minute            (volumetric flooding)
  - input tokens / request        (context stuffing, sponge inputs)
  - output tokens / request       (unbounded generation)
  - concurrent in-flight count    (concurrency abuse)
  - cost / hour and cost / day    (denial of wallet)
  - query diversity & coverage    (systematic sweep = extraction)
  - error / timeout rate          (saturation, cascading failure)

Log every request with: identity, tenant, tokens_in, tokens_out,
estimated_cost, latency, and outcome -- the raw material for detection.
```

- **Baseline per identity**: alert on sudden jumps in volume, token totals, or spend relative to that caller's norm.
- **Detect extraction shape**: broad, systematic, high-coverage querying that sweeps the input space looks nothing like a real user task.
- **Wire alerts to action**: auto-throttle or auto-suspend an identity that crosses hard thresholds, pending review.

## Layer 8: Anti-Extraction Controls

The theft axis needs its own defenses, because a slow, quota-respecting attacker can still harvest a distillation dataset over time. These controls raise the cost and lower the fidelity of extraction, and help you detect and prove it.

- **Tight per-identity query quotas**: extraction needs volume; a firm daily cap on queries and tokens is the primary brake.
- **Throttle systematic sweeps**: when one identity's queries cover the input space unusually broadly, slow or block them.
- **Return less signal**: withhold raw token log-probabilities and full probability distributions from untrusted callers &mdash; they dramatically accelerate extraction and inversion.
- **Watermark and log outputs**: retain hashed input/output logs so a suspected clone can be traced back to the queries that built it; consider output watermarking where feasible.
- **Contractual + legal controls**: terms of service that prohibit using outputs to train competing models give you a basis for enforcement and takedown.
- **Rate-limit high-information endpoints** (embeddings, logits, scoring) more strictly than chat, since they leak more per call.

> Watermarking and log-prob withholding *raise the cost* of extraction; they do not make it impossible. Treat them as detection and deterrence layered on top of quotas and monitoring, not as a standalone fix.

## Layer 9: Graceful Degradation

When limits are hit or capacity is exhausted, fail predictably. A service that sheds load with clear errors stays available for everyone else; one that tries to serve everything collapses for everyone.

- **Load shedding**: return `429` (rate/quota), `402` (budget), or `503` (capacity) with `Retry-After` rather than queuing without limit.
- **Prioritise**: protect paying / interactive traffic; shed low-priority batch and anonymous work first.
- **Fallback tiers**: under pressure, route to a smaller/cheaper model or a cached response rather than the most expensive path.
- **Bounded, clear errors**: error bodies should be short and fixed &mdash; don't let the failure path itself become an amplification vector.

## Defense Checklist

| Control | Stops (DoS / DoW / Theft) | Where |
| --- | --- | --- |
| Input byte + token cap | DoS, DoW | Gateway, before model |
| Server-enforced `max_tokens` | DoS, DoW | Every generation call |
| Bounded history / RAG / media | DoS, DoW | Prompt assembly |
| Per-identity rate limit | DoS, DoW, Theft | Gateway |
| Token & spend quotas | DoW, Theft | Gateway |
| Concurrency cap + queue limit | DoS | Gateway / worker pool |
| Timeouts + circuit breaker | DoS | Model client |
| Cost budget + billing cap | DoW | App + provider console |
| Authentication + attribution | DoS, DoW, Theft | Every endpoint |
| Metering + anomaly alerts | DoS, DoW, Theft | Observability |
| Withhold logits / watermark / log | Theft | Response layer |
| Graceful load shedding | DoS, DoW | Gateway |
| Bounded agent step/token budget | DoS, DoW | Orchestrator |

## Next Steps

- **[Examples](examples.html)**: Vulnerable-vs-secure implementations of these controls in Python and Node.
- **[Attack Vectors](attack-vectors.html)**: The patterns each control is designed to stop.
- **[Overview](overview.html)**: The concepts, harm axes, and business context.
- **[Hands-On Lab](lab/unbounded-consumption/)**: Apply these defenses to a running service and verify they hold.
