# LLM10:2025 Unbounded Consumption - Code Examples

Each pair below shows a **vulnerable** implementation and the **secure** version of the same control. The examples center on an LLM API gateway in Python (FastAPI), with Node/TypeScript where it is the more natural fit. The through-line: bound every dimension of cost *server-side*, and never trust a limit the client supplies.

## Table of Contents
- [1. Input Size & Token Limits (FastAPI)](#1-input-size--token-limits-fastapi)
- [2. Server-Enforced Output Cap](#2-server-enforced-output-cap)
- [3. Per-Identity Rate Limiting (Redis)](#3-per-identity-rate-limiting-redis)
- [4. Cost Budget & Quota Enforcement](#4-cost-budget--quota-enforcement)
- [5. Concurrency Cap & Timeout](#5-concurrency-cap--timeout)
- [6. Bounded Agent / Tool Fan-Out](#6-bounded-agent--tool-fan-out)
- [7. Anti-Extraction: Quotas, Log-Probs, Logging](#7-anti-extraction-quotas-log-probs-logging)
- [8. Express Gateway with Limits (Node/TS)](#8-express-gateway-with-limits-nodets)
- [Review Checklist](#review-checklist)
- [Next Steps](#next-steps)

## 1. Input Size & Token Limits (FastAPI)

### Vulnerable

```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class ChatIn(BaseModel):
    message: str                       # no length bound
    history: list[str] = []            # unbounded conversation
    max_tokens: int | None = None      # client controls output length

@app.post("/api/chat")
async def chat(body: ChatIn):
    prompt = "\n".join(body.history + [body.message])   # arbitrary size
    # Whole prompt forwarded to the model with no token check, no output cap
    return await model.generate(prompt, max_tokens=body.max_tokens)
```

### Secure

```python
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
import tiktoken

app = FastAPI()
enc = tiktoken.get_encoding("cl100k_base")

MAX_REQUEST_BYTES = 32 * 1024
MAX_INPUT_TOKENS  = 4_000
MAX_HISTORY_TURNS = 20

class ChatIn(BaseModel):
    message: str = Field(max_length=8_000)          # hard string bound
    history: list[str] = Field(default=[], max_length=MAX_HISTORY_TURNS)
    max_tokens: int | None = Field(default=None, ge=1, le=1_024)

def count_tokens(text: str) -> int:
    return len(enc.encode(text))

@app.middleware("http")
async def cap_body_size(request: Request, call_next):
    body = await request.body()
    if len(body) > MAX_REQUEST_BYTES:               # cheap reject at the edge
        raise HTTPException(413, "Request too large")
    return await call_next(request)

@app.post("/api/chat")
async def chat(body: ChatIn):
    history = body.history[-MAX_HISTORY_TURNS:]     # bound history growth
    prompt = "\n".join(history + [body.message])
    if count_tokens(prompt) > MAX_INPUT_TOKENS:     # token cap = cost cap
        raise HTTPException(413, "Input exceeds token limit")
    return await model.generate(prompt, max_tokens=body.max_tokens or 512)
```

**Key differences**: a byte cap in middleware rejects oversized bodies before tokenization; Pydantic bounds string length and history depth; the assembled prompt is token-counted against a hard budget; and the client's `max_tokens` is constrained (`le=1_024`) and defaulted, never left unlimited.

## 2. Server-Enforced Output Cap

### Vulnerable

```python
# Trusts whatever the client asks for -- or nothing, meaning "unlimited"
async def generate(prompt: str, max_tokens: int | None):
    return await model.generate(prompt, max_tokens=max_tokens)  # may run forever
```

### Secure

```python
SERVER_MAX_OUTPUT_TOKENS = 1_024
DEFAULT_OUTPUT_TOKENS    = 512

def clamp_output(requested: int | None) -> int:
    if requested is None:
        return DEFAULT_OUTPUT_TOKENS
    return max(1, min(requested, SERVER_MAX_OUTPUT_TOKENS))   # clamp, don't trust

async def generate(prompt: str, requested_max: int | None):
    capped = clamp_output(requested_max)
    # Stop sequences + hard token cap + a total-time budget bound the output.
    return await model.generate(
        prompt,
        max_tokens=capped,
        stop=["<|end|>"],
        timeout=30,                    # wall-clock guard against slow runaways
    )
```

**Key differences**: the server always sets a finite `max_tokens`; a client request is a ceiling to clamp, never an instruction to obey; stop sequences and a timeout provide independent brakes.

## 3. Per-Identity Rate Limiting (Redis)

### Vulnerable

```python
@app.post("/api/chat")
async def chat(body: ChatIn):
    # No rate limit at all -- one caller can send unlimited requests.
    return await generate(body.message, body.max_tokens)
```

### Secure

```python
import time, redis.asyncio as redis
from fastapi import Depends, HTTPException

r = redis.Redis()

async def rate_limit(identity: str, limit: int = 60, window: int = 60):
    now = time.time()
    key = f"rl:{identity}"
    async with r.pipeline(transaction=True) as p:
        p.zremrangebyscore(key, 0, now - window)   # sliding window
        p.zadd(key, {f"{now}:{id(now)}": now})
        p.zcard(key)
        p.expire(key, window)
        _, _, count, _ = await p.execute()
    if count > limit:
        raise HTTPException(429, "Rate limit exceeded",
                            headers={"Retry-After": str(window)})

async def current_identity(request: Request) -> str:
    ident = await authenticate(request)            # never fall back to raw IP alone
    if ident is None:
        raise HTTPException(401, "Authentication required")
    return ident

@app.post("/api/chat")
async def chat(body: ChatIn, identity: str = Depends(current_identity)):
    await rate_limit(identity)                     # keyed by identity, not IP
    return await generate(body.message, body.max_tokens)
```

**Key differences**: a sliding-window limiter smooths bursts (a fixed window would allow a double burst at the boundary); the key is a durable identity, not a shared/rotating IP; the response is a clean `429` with `Retry-After`.

## 4. Cost Budget & Quota Enforcement

### Vulnerable

```python
# No notion of cost. Every request bills the metered backend with no ceiling.
async def chat(body):
    return await model.generate(body.message, max_tokens=body.max_tokens)
```

### Secure

```python
PRICE_IN_PER_1K  = 0.003
PRICE_OUT_PER_1K = 0.015
DAILY_BUDGET_USD = 5.00

def estimated_cost(tokens_in: int, max_out: int) -> float:
    return (tokens_in/1000)*PRICE_IN_PER_1K + (max_out/1000)*PRICE_OUT_PER_1K

async def reserve(tenant: str, cost: float) -> bool:
    spent = float(await r.get(f"spend:{tenant}") or 0)
    if spent + cost > DAILY_BUDGET_USD:
        return False
    await r.incrbyfloat(f"spend:{tenant}", cost)   # reserve worst case up front
    await r.expireat(f"spend:{tenant}", end_of_day_ts())
    return True

async def refund(tenant: str, delta: float):
    if delta > 0:
        await r.incrbyfloat(f"spend:{tenant}", -delta)  # return unused reservation

@app.post("/api/chat")
async def chat(body: ChatIn, identity: str = Depends(current_identity)):
    await rate_limit(identity)
    max_out = clamp_output(body.max_tokens)
    tokens_in = count_tokens(body.message)
    worst = estimated_cost(tokens_in, max_out)
    tenant = tenant_of(identity)
    if not await reserve(tenant, worst):
        raise HTTPException(402, "Daily budget exhausted",
                            headers={"Retry-After": "3600"})
    result = await generate(body.message, max_out)
    actual = estimated_cost(tokens_in, result.output_tokens)
    await refund(tenant, worst - actual)           # reconcile to real usage
    return result
```

**Key differences**: the worst-case cost is reserved *before* the model call and reconciled after; a per-tenant daily budget returns `402` when exhausted; this belongs behind a provider-side hard billing cap as a backstop.

## 5. Concurrency Cap & Timeout

### Vulnerable

```python
# Unlimited in-flight requests: 60 parallel maxed-out generations
# can saturate every worker at once, even under a per-minute rate limit.
async def chat(body):
    return await model.generate(body.message)      # no timeout, no concurrency cap
```

### Secure

```python
import asyncio
from collections import defaultdict

GLOBAL_CONCURRENCY    = 32
PER_IDENTITY_INFLIGHT = 2
MODEL_TIMEOUT_S       = 30

global_sem = asyncio.Semaphore(GLOBAL_CONCURRENCY)
per_id_sems: dict[str, asyncio.Semaphore] = defaultdict(
    lambda: asyncio.Semaphore(PER_IDENTITY_INFLIGHT))

async def guarded_generate(identity: str, prompt: str, max_out: int):
    id_sem = per_id_sems[identity]
    if id_sem.locked() and id_sem._value == 0:
        raise HTTPException(429, "Too many concurrent requests")   # shed, don't block
    async with id_sem, global_sem:                 # bounded occupancy, 2 layers
        try:
            return await asyncio.wait_for(
                model.generate(prompt, max_tokens=max_out),
                timeout=MODEL_TIMEOUT_S)
        except asyncio.TimeoutError:
            raise HTTPException(504, "Upstream timeout")   # free the slot
```

**Key differences**: a per-identity semaphore stops one caller monopolising workers; a global semaphore bounds total occupancy; `asyncio.wait_for` guarantees a stuck generation releases its slot instead of pinning it.

## 6. Bounded Agent / Tool Fan-Out

### Vulnerable

```python
async def run_agent(goal: str):
    # Loops until the model decides it is "done" -- unbounded steps,
    # unbounded tool calls, unbounded total tokens.
    while not done:
        step = await model.plan(goal, scratchpad)
        result = await run_tool(step)              # tools may spawn sub-agents
        scratchpad += result                       # context grows every step
```

### Secure

```python
MAX_STEPS        = 12
MAX_TOOL_CALLS   = 20
MAX_TASK_TOKENS  = 60_000
MAX_DEPTH        = 2

async def run_agent(goal: str, budget: dict, depth: int = 0):
    if depth > MAX_DEPTH:
        raise BudgetExceeded("recursion depth")
    for step_i in range(MAX_STEPS):                # hard step ceiling
        if budget["tokens"] <= 0 or budget["tools"] <= 0:
            break                                  # task-wide budgets exhausted
        step = await model.plan(goal, scratchpad, max_tokens=1_000)
        budget["tokens"] -= step.total_tokens
        if step.is_final:
            return step.answer
        budget["tools"] -= 1
        # Sub-agents draw from the SAME shared budget and bounded depth
        await run_tool(step, budget=budget, depth=depth + 1)
    return summarize(scratchpad)                   # bounded, graceful finish
```

**Key differences**: every loop has a hard step cap; a single shared token/tool budget is threaded through the whole task (including sub-agents) so recursion cannot multiply cost; recursion depth is bounded; the task ends gracefully when the budget runs out rather than looping forever.

## 7. Anti-Extraction: Quotas, Log-Probs, Logging

### Vulnerable

```python
@app.post("/api/complete")
async def complete(body: CompleteIn):
    out = await model.generate(body.prompt, logprobs=True)   # rich signal leaked
    return {"text": out.text, "logprobs": out.logprobs,      # accelerates cloning
            "token_probs": out.full_distribution}
    # No per-identity query cap, no logging -- extraction is invisible & cheap.
```

### Secure

```python
import hashlib, logging
log = logging.getLogger("inference")

DAILY_QUERY_QUOTA = 5_000     # extraction needs volume; cap it hard

@app.post("/api/complete")
async def complete(body: CompleteIn, identity: str = Depends(current_identity)):
    await rate_limit(identity)
    if await incr_daily(f"q:{identity}") > DAILY_QUERY_QUOTA:
        raise HTTPException(429, "Daily query quota exceeded")

    out = await model.generate(body.prompt, logprobs=False)   # withhold raw signal

    # Hashed audit trail: enough to trace a suspected clone, no raw PII stored.
    log.info("infer id=%s tenant=%s in_tok=%d out_tok=%d prompt_sha=%s",
             identity, tenant_of(identity), out.input_tokens, out.output_tokens,
             hashlib.sha256(body.prompt.encode()).hexdigest())

    if await looks_like_sweep(identity):           # broad systematic coverage?
        await throttle(identity)                   # slow suspected extraction
    return {"text": out.text}                      # text only -- no distributions
```

**Key differences**: raw log-probabilities and full token distributions are withheld from untrusted callers (they sharply accelerate extraction/inversion); a daily query quota caps the volume extraction depends on; every call is logged with a hashed prompt for traceability; systematic sweeps are detected and throttled.

## 8. Express Gateway with Limits (Node/TS)

### Vulnerable

```typescript
import express from "express";
const app = express();
app.use(express.json());                           // no size limit -> huge bodies

app.post("/api/chat", async (req, res) => {
  // No auth, no rate limit, no output cap, no timeout.
  const out = await model.generate(req.body.message, { maxTokens: req.body.maxTokens });
  res.json(out);
});
app.listen(3000);
```

### Secure

```typescript
import express from "express";
import rateLimit from "express-rate-limit";

const app = express();
app.use(express.json({ limit: "32kb" }));          // bound request body size

const SERVER_MAX_OUTPUT = 1024;
const clamp = (n?: number) =>
  Math.max(1, Math.min(n ?? 512, SERVER_MAX_OUTPUT));

const limiter = rateLimit({
  windowMs: 60_000,
  limit: 60,                                        // per-identity below
  keyGenerator: (req) => req.identity ?? req.ip,    // prefer authenticated id
  standardHeaders: true,                            // sends Retry-After
});

app.post("/api/chat", requireAuth, limiter, async (req, res) => {
  const message: string = String(req.body.message ?? "");
  if (message.length > 8_000)                        // cheap length bound
    return res.status(413).json({ error: "Input too large" });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30_000);   // 30s timeout
  try {
    const out = await model.generate(message, {
      maxTokens: clamp(req.body.maxTokens),          // clamp, never trust
      signal: controller.signal,
    });
    res.json({ text: out.text });
  } catch (e) {
    res.status(504).json({ error: "Upstream timeout" });
  } finally {
    clearTimeout(timer);
  }
});

app.listen(3000);
```

**Key differences**: `express.json({ limit })` bounds body size; `requireAuth` attributes traffic; `express-rate-limit` is keyed to the identity and emits `Retry-After`; output tokens are clamped; an `AbortController` enforces a hard timeout so no request pins the event loop indefinitely.

## Review Checklist

- Is request body size bounded at the edge (byte cap) *and* the assembled prompt token-counted?
- Is `max_tokens` always set server-side and the client's value clamped, never trusted as "unlimited"?
- Are rate limits and quotas keyed to a durable **identity**, not a shared/rotating IP?
- Is there a per-tenant **cost budget** checked before the call, behind a provider hard billing cap?
- Are both **per-identity and global concurrency** capped, with a timeout on every model call?
- Do agent/tool loops have hard step, depth, and shared-token budgets?
- Are raw log-probs/distributions withheld from untrusted callers, with query quotas and audit logging against extraction?
- Does every limit breach return a clear `429`/`402`/`503`/`504` instead of degrading silently?

## Next Steps

- **[Prevention](prevention.html)**: The layered model these examples implement.
- **[Attack Vectors](attack-vectors.html)**: The patterns each control defends against.
- **[Overview](overview.html)**: Concepts, harm axes, and business context.
- **[Hands-On Lab](lab/unbounded-consumption/)**: Deploy a gateway, attack it, then harden it with these controls.
