# LLM07:2025 System Prompt Leakage - Prevention

## Table of Contents

- [Prevention Strategy Overview](#prevention-strategy-overview)
- [1. Never Put Secrets in the Prompt](#1-never-put-secrets-in-the-prompt)
- [2. Enforce Authorization Externally](#2-enforce-authorization-externally)
- [3. Move Business Rules and Filters Out](#3-move-business-rules-and-filters-out)
- [4. Least Privilege for Tools and Data](#4-least-privilege-for-tools-and-data)
- [5. Separate Sensitive Data from the Prompt](#5-separate-sensitive-data-from-the-prompt)
- [6. Independent Output and Action Controls](#6-independent-output-and-action-controls)
- [7. Detection and Monitoring](#7-detection-and-monitoring)
- [Prevention Checklist](#prevention-checklist)

## Prevention Strategy Overview

The defining mistake behind LLM07 is **over-reliance on the system prompt** — treating it as a secret store and a security control. Every effective defence follows from one assumption:

> **Assume the system prompt is public.** If an attacker who holds your complete, verbatim prompt gains nothing they didn't already have, you have solved this category.

That reframes the goal. You are not primarily trying to *stop* extraction (which is unreliable); you are trying to make extraction *worthless*. Extraction-resistance is a useful secondary layer, never the foundation.

### Core Principles

- **Nothing sensitive in the prompt**: no credentials, no secrets, no unique competitive logic that matters if copied.
- **Enforcement lives outside the model**: authorization, limits, and filtering run in deterministic code the model cannot argue with.
- **Least privilege everywhere**: the model and its tools can only ever do what the backend independently permits.
- **Defence in depth**: extraction-resistance, output filtering, and monitoring are layers on top of a fundamentally safe design — not substitutes for it.

## 1. Never Put Secrets in the Prompt

Secrets belong in a secrets manager and are used by your application code, which surrounds the model. The model never needs to see a key to benefit from an API call your code makes on its behalf.

```python
# VULNERABLE: secret pasted into the system prompt
SYSTEM_PROMPT = f"""
You are the billing assistant.
To charge a card, call Stripe with key sk_live_51H8xY...redacted...
Database: postgres://app:S3cr3t@db.internal:5432/prod
"""

# SECURE: the model gets a capability, not a credential
import os
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])  # never in the prompt
STRIPE_KEY = os.environ["STRIPE_SECRET_KEY"]            # loaded from a vault/env

SYSTEM_PROMPT = """
You are the billing assistant. When the user asks to issue a refund,
call the tool `request_refund(order_id, amount)`. Do not handle
payment credentials yourself.
"""
```

The tool `request_refund` is implemented in your code; *that* code reads `STRIPE_KEY` from the environment or a secrets manager (AWS Secrets Manager, Vault, GCP Secret Manager). The key never enters the token stream, so no extraction can leak it.

## 2. Enforce Authorization Externally

A rule the model is *told* is a suggestion; a rule your backend *checks* is enforcement. Never let the model be the thing that decides who is allowed to do what.

```python
# VULNERABLE: authorization expressed as prompt text
SYSTEM_PROMPT = """
The current user's plan is FREE.
Only answer premium questions if the plan is PREMIUM.
The user is NOT an admin, so refuse admin actions.
"""
# An attacker who reads this simply claims to be PREMIUM/admin,
# and the model may comply.

# SECURE: the backend decides, before and after the model runs
def handle_request(user, message):
    # 1) Authorization is a code decision, keyed on the authenticated user
    if not user.has_entitlement("premium_qa") and is_premium_topic(message):
        return "This feature requires a premium plan."

    reply = run_model(PUBLIC_SYSTEM_PROMPT, message)

    # 2) Privileged actions are gated again at the tool boundary
    return reply
```

Authorization is evaluated from a trusted session/identity (a signed token, a server-side session) — never from anything the model or the user asserts in the conversation.

## 3. Move Business Rules and Filters Out

If a rule's disclosure or bypass causes harm, it must be enforced in code, not narrated to the model. Keep the prompt's instructions generic and non-sensitive; put the enforceable specifics in your application.

```python
# VULNERABLE: exact, gameable logic lives in the prompt
SYSTEM_PROMPT = """
Discount rules: VIP=30%, wholesale minimum $10,000.
Never mention competitor BetterCorp.
Approve refunds under $500 automatically.
"""

# SECURE: the prompt is generic; the numbers are enforced server-side
SYSTEM_PROMPT = """
You are a sales assistant. To quote a discount or process a refund,
call the appropriate tool. Follow the tool's decision.
"""

def request_refund(user, order_id, amount):
    policy = load_refund_policy()            # server-side source of truth
    if amount > policy.auto_approve_limit:   # not visible to the model
        return {"status": "needs_human_approval"}
    return process_refund(order_id, amount)
```

Content filtering follows the same logic: a banned-topic list embedded in the prompt teaches the attacker exactly what to evade. Enforce content policy with an independent moderation/classifier step (see section 6) rather than by listing the forbidden items in the prompt.

## 4. Least Privilege for Tools and Data

Assume the model can be tricked into calling any tool it has, with any arguments. Constrain what that can achieve:

- **Scope credentials narrowly**: the token behind a tool should grant only the minimum action (read-only where possible), not broad account access.
- **Validate tool arguments in code**: the tool implementation re-checks the user's entitlement and the argument bounds before acting.
- **Human-in-the-loop for irreversible actions**: deletions, payments, and external sends require an out-of-band confirmation.
- **Isolate per user**: a tool call runs with the requesting user's permissions, resolved server-side.

```python
# The tool re-authorizes; it does not trust the model's intent
def delete_records(current_user, target_user_id):
    if not current_user.is_admin:               # checked in code, every call
        raise PermissionError("not authorized")
    if current_user.id == target_user_id:
        raise ValueError("cannot delete self")
    audit_log("delete_records", current_user.id, target_user_id)
    return db.delete_user(target_user_id)
```

## 5. Separate Sensitive Data from the Prompt

Do not concatenate another user's PII, secret documents, or session data into a shared system prompt. Pass only the minimum the task needs, per request, scoped to the authenticated user, and clear it afterward.

```python
# VULNERABLE: shared, growing context with everyone's data
class Chatbot:
    context = ""                       # class-level = shared across users!

# SECURE: per-request context, minimised and user-scoped
def build_messages(user, user_message):
    profile = fetch_minimal_profile(user.id)   # only what THIS task needs
    return [
        {"role": "system", "content": PUBLIC_SYSTEM_PROMPT},
        {"role": "system", "content": f"User's first name: {profile.first_name}"},
        {"role": "user", "content": user_message},
    ]
```

Even here, include the smallest useful field (a first name, an order status) rather than a full record, so a leak of the context discloses as little as possible.

## 6. Independent Output and Action Controls

Add a layer that inspects responses and gates actions *regardless* of what the model was instructed. These controls are useful precisely because they do not depend on the model obeying the prompt.

```python
import re

# Flag responses that appear to echo the instruction text
PROMPT_MARKERS = ["You are the billing assistant", "call the tool", "PUBLIC_SYSTEM_PROMPT"]
SECRET_PATTERNS = [
    re.compile(r"sk_live_[A-Za-z0-9]+"),        # Stripe-style keys
    re.compile(r"postgres://[^\s]+:[^\s]+@"),    # connection strings
    re.compile(r"AKIA[0-9A-Z]{16}"),             # AWS access key IDs
]

def guard_output(text):
    if any(marker in text for marker in PROMPT_MARKERS):
        return "I can't share my internal configuration."
    if any(p.search(text) for p in SECRET_PATTERNS):
        return "[response withheld: sensitive pattern detected]"
    return text
```

Treat this as a safety net, not a boundary: attackers request encoded or translated copies to slip past pattern matching (see Attack Vectors). It reduces casual leakage and gives you a detection signal, but it is never the reason your design is safe.

For content policy, run an independent moderation model or classifier on both input and output, so enforcement does not depend on the primary model reading a banned-topic list in its prompt.

### Optional: Extraction-Resistance (a speed bump, not a wall)

- Add an instruction not to reveal internal configuration — it raises the effort but will be bypassed; never rely on it.
- Prefer structured / constrained outputs where the format itself makes verbatim dumps awkward.
- Use provider guardrail features (system-prompt hardening, refusal training) as one more layer.

## 7. Detection and Monitoring

- **Log and score interactions**: flag inputs containing known extraction phrasings ("repeat the text above," "ignore previous instructions," Base64 blobs) and outputs that echo instruction markers.
- **Rate-limit and correlate**: fragment-by-fragment reconstruction shows up as repeated probing across a session or user — watch for it, not just single responses.
- **Red-team regularly**: routinely attempt to extract your own prompts across all channels, including RAG documents and tool outputs (indirect injection).
- **Alert on secret patterns**: if any response ever matches a credential pattern, treat it as an incident and rotate the affected secret.
- **Rotate on suspicion**: because you never trusted the prompt to hold secrets, rotation is the routine response to any suspected leak, not an emergency.

## Prevention Checklist

- [ ] No API keys, passwords, tokens, or connection strings appear anywhere in any system prompt.
- [ ] Every authorization decision is made in backend code from an authenticated identity, not asserted in the prompt.
- [ ] Business rules and limits that matter (pricing, refunds, eligibility) are enforced server-side, not narrated to the model.
- [ ] Content policy runs as an independent moderation step, not as a banned-topic list in the prompt.
- [ ] Tools re-check entitlements and argument bounds on every call; irreversible actions need human confirmation.
- [ ] Per-user data is minimised, request-scoped, and never accumulated in a shared prompt/context.
- [ ] Output filtering and secret-pattern detection run on every response as a safety net.
- [ ] Monitoring flags extraction attempts and instruction-echoing; red-teaming is scheduled.
- [ ] You have confirmed that publishing the full prompt verbatim would cause no harm.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure implementations in Python and Node/TS
- **[Attack Vectors](attack-vectors.md)**: The extraction techniques these defences neutralise
- **[Hands-On Lab](./lab/system-prompt-leakage/)**: Extract a leaky prompt, then apply these fixes
