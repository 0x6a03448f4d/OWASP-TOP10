# SAS-8: Denial of Service and Financial Resource Exhaustion - Attack Vectors

## Table of Contents
- [Understanding the Attack Vectors](#understanding-the-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Ways to Exhaust Concurrency and Wallet](#ways-to-exhaust-concurrency-and-wallet)
- [Chaining Into an Outage-and-Bill](#chaining-into-an-outage-and-bill)

## Understanding the Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can rate-limit, cap, and cost-control this abuse in serverless systems you own or are authorised to test. Never generate load against infrastructure you do not control.

The attacker's goal here is simple: make the platform do *expensive work, repeatedly, without limit*. They do not need a memory-corruption bug or a stolen credential. They need an entry point that scales—a public endpoint, an event source, or a loop—and the absence of a cap. Because serverless auto-scales and bills per use, the very same flood produces two payoffs at once: it consumes the shared concurrency pool (a **denial of service**) and it runs up the invoice (a **denial of wallet**). The attacker chooses which one matters; often they get both for free.

What makes these vectors distinct from a traditional DoS is that *nothing has to break*. The platform happily accepts the load; the "damage" is the platform doing exactly what it was designed to do—scale and charge—on the attacker's behalf. That is why the effective defences are limits and cost controls, not bigger servers.

### Core Attack Flow

```
1. Find a scaling entry point
   |
   A public endpoint, an event source you can write to, or a self-loop
2. Make each unit expensive
   |
   Large payloads, long timeouts, big memory, costly downstream calls
3. Remove your own effort with amplification
   |
   Recursion, fan-out, or retry storms multiply invocations for you
4. Let auto-scaling do the damage
   |
   Concurrency drains (DoS) and/or the bill climbs (DoW) -- no crash needed
5. Persist until a cap or a human stops it
   |
   With no reserved concurrency, throttle, or cost alarm, that can be a long time
```

## Ways to Exhaust Concurrency and Wallet

### 1. Flood a Public, Unthrottled Endpoint

The simplest vector: an anonymous HTTP endpoint with no API Gateway throttle, no usage-plan quota, and no WAF rate rule. The attacker replays it as fast as bandwidth allows; every request is a billable invocation.

```
# No auth, no throttle. A trivial loop is enough.
while true; do curl -s https://api.example.com/render -d @big.json & done
# Each request -> one invocation -> concurrency + $ climb linearly with the flood.
# No rate limit means the only ceiling is the attacker's bandwidth.
```

**Why it works**: no rate limiting at the edge or API layer, and no reserved concurrency cap to force a visible, contained throttle.

### 2. Make Each Invocation Maximally Expensive

Rather than more requests, the attacker makes each request cost more—by driving the function toward its long timeout and large memory, or by sending inputs that trigger heavy work.

```
# Function: timeout 900s, memory 3008MB, no input size limit.
# Attacker sends inputs that force the worst case:
POST /process   { "iterations": 100000000, "payload": "<10 MB blob>" }
# Each invocation now runs for minutes at max memory = ~max billable cost/unit.
# Fewer requests, same damage.
```

**Why it works**: oversized timeout/memory and no input/pagination limits let a single request consume the maximum billable resource.

### 3. Trigger a Recursive / Self-Amplifying Loop

The attacker (or a careless deploy) wires an event source into a cycle. The canonical case: a function triggered by S3 object-creation that writes its output back into the same bucket/prefix.

```
# Upload ONE object to start the chain:
aws s3 cp seed.jpg s3://uploads/seed.jpg
# resizeFn triggers, writes resized.jpg back to s3://uploads/ ...
#   ObjectCreated -> resizeFn -> ObjectCreated -> resizeFn -> ...
# One action -> unbounded invocations. Scales and bills itself.
```

**Why it works**: an event topology with no prefix separation, idempotency check, or recursion guard turns a single event into an infinite, self-billing storm.

### 4. Amplify via Fan-Out Event Sources

Even without a loop, an attacker can exploit fan-out: one message that expands into many invocations through SNS/EventBridge subscriptions or a function that publishes N events per call.

```
# One inbound event -> N downstream invocations -> each publishes M more ...
inbound (1)  ->  SNS fan-out (100 subscribers)  ->  100 invocations
             ->  each publishes 10 events        ->  1,000 invocations  -> ...
# Multiplicative growth from a single, cheap starting event.
```

**Why it works**: fan-out subscriptions and per-invocation publishing multiply invocations with no cap on total spawned work.

### 5. Weaponise Retries and Poison Messages

Asynchronous and stream/queue-based invocations retry on failure. An attacker sends input that reliably fails *after* doing expensive work, so every automatic retry is billed for the full expensive run.

```
# Message is crafted to do heavy work, then fail at the end:
SQS message -> function does 800s of work -> throws -> SQS re-drives it
            -> function does 800s again    -> throws -> re-drives ...
# With no maxReceiveCount and no DLQ, the poison message is billed forever.
```

**Why it works**: uncapped `maxReceiveCount`/retry policy and no dead-letter queue mean a single failing message is redelivered and re-billed indefinitely.

### 6. Exhaust Expensive Downstream Resources

The attacker aims past the function at what it calls—a metered third-party API, or a database with a finite connection pool—so a modest invocation rate causes outsized cost or a downstream outage.

```
# Each invocation opens a new DB connection and calls a paid API:
flood -> 1,000 concurrent functions -> 1,000 DB connections (pool max: 100)
      -> DB refuses connections (downstream DoS)
      -> AND 1,000 paid-API calls    (downstream $ + rate-limit ban)
# The function is just the delivery vehicle for downstream exhaustion.
```

**Why it works**: no connection pooling/limits and no circuit breakers, so function concurrency directly maps to downstream load.

### 7. Starve Neighbours by Draining Shared Concurrency

Because account/region concurrency is a shared pool, an attacker who floods *one* uncapped function throttles every *other* function in the account—a pure availability attack with a wide blast radius.

```
# Account concurrency limit: 1,000 (shared by ALL functions).
# Flood the uncapped "report" function to hold 1,000 concurrent executions.
# Result: checkout, login, webhooks -> all throttled (429/TooManyRequests).
# One unimportant endpoint takes down the whole application.
```

**Why it works**: no per-function reserved concurrency, so one function's flood consumes the shared limit that protects everyone else.

## Chaining Into an Outage-and-Bill

Real incidents combine these vectors. The economic chain and the availability chain often run at the same time, because the same flood drives both:

```
Public unthrottled endpoint        -> attacker floods it
        +
Oversized timeout + big memory      -> each invocation is maximally expensive
        +
Expensive downstream calls          -> per-request cost multiplies
        +
No reserved concurrency cap         -> flood drains the shared pool
        =  every function throttled (DoS)  AND  the bill explodes (DoW)
```

The self-inflicted variant needs no sustained attacker at all—just one trigger and a missing guard:

```
Recursive S3-write loop (or fan-out) -> one event self-amplifies
        -> no recursion detection, no DLQ, no invocation cap
        -> invocations grow without bound, scaling and billing themselves
        -> first clear signal is a cost-anomaly alert... or the invoice
           (ties directly to SAS-5: without alarms, nobody sees it early)
```

## Key Takeaways

1. **The entry point is anything that scales**—a public endpoint, a writable event source, or a self-loop; no exploit is required.
2. **Cost and availability fall together**—one flood both drains shared concurrency (DoS) and runs up the bill (DoW).
3. **Amplification does the attacker's work**—recursion, fan-out, and retry storms multiply invocations from a single cheap trigger.
4. **Downstream is a target too**—connection pools and metered APIs can be exhausted long before the function budget is.
5. **Shared concurrency is the wide blast radius**—without reserved caps, one endpoint's flood throttles the whole account.

## Next Steps

- **[Prevention Guide](prevention.md)**: Cap concurrency, throttle, bound cost, and break recursion
- **[Code Examples](examples.md)**: Vulnerable vs. secure serverless.yml, API Gateway, Budgets, and WAF
- **[Overview](overview.md)**: Why auto-scaling turns a flood into a bill
