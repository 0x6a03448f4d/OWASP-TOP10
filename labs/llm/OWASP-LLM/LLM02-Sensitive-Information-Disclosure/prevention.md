# LLM02: Sensitive Information Disclosure - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [1. Sanitise and Minimise Data](#1-sanitise-and-minimise-data)
- [2. Enforce Access Control at the Data Layer](#2-enforce-access-control-at-the-data-layer)
- [3. Never Put Secrets in Prompts](#3-never-put-secrets-in-prompts)
- [4. Output Filtering and DLP](#4-output-filtering-and-dlp)
- [5. Scoped Sessions and Tenant Isolation](#5-scoped-sessions-and-tenant-isolation)
- [6. Safe Logging and Error Handling](#6-safe-logging-and-error-handling)
- [7. Training-Time Controls](#7-training-time-controls)
- [8. Governance, Consent, and Retention](#8-governance-consent-and-retention)
- [Key Takeaways](#key-takeaways)
- [Next Steps](#next-steps)

## Prevention Strategy Overview

No single control stops Sensitive Information Disclosure. The defense is a chain in which each link handles what the previous one could not:

```
Shrink what CAN leak        ->  Sanitise + minimise data before it enters the system
Control WHO can reach it    ->  Per-user authorization at the retrieval / data layer
Keep secrets OUT of reach   ->  Externalise credentials; never place them in prompts
Inspect what LEAVES         ->  Output filtering / DLP on completions
Isolate per user            ->  No shared context, caches keyed by identity
Protect the copies          ->  Redact logs, generic errors, short retention
Govern the lifecycle        ->  Consent, data minimisation, deletion, auditing
```

### Core Principles
- **Data minimisation first.** The safest sensitive datum is the one you never collected, trained on, or indexed.
- **Authorization is code, not prose.** Enforce entitlements in the retrieval and data layers — never by instructing the model to be discreet.
- **Assume the prompt is public.** Design so that leaking the entire context window is embarrassing, not catastrophic.
- **Defense in depth.** Expect each layer to fail sometimes; make sure the next one catches it.

## 1. Sanitise and Minimise Data

Scrub PII and secrets out of any corpus before it becomes training data, fine-tuning data, or a RAG index. Detection combines pattern matching (for structured values) with an NER model (for names, locations, and free-form PII).

```python
import re
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()          # spaCy-backed PII NER + recognizers
anonymizer = AnonymizerEngine()

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),           # OpenAI-style keys
    re.compile(r"AKIA[0-9A-Z]{16}"),              # AWS access key id
    re.compile(r"(?i)postgres(?:ql)?://[^\s\"']+"),  # DB connection strings
    re.compile(r"ghp_[A-Za-z0-9]{36}"),           # GitHub PAT
]

def scrub(text: str, lang: str = "en") -> str:
    # 1) Structural secrets first (regex is precise for these)
    for pat in SECRET_PATTERNS:
        text = pat.sub("[REDACTED_SECRET]", text)
    # 2) Free-form PII via NER (names, emails, phones, SSNs, locations)
    results = analyzer.analyze(
        text=text, language=lang,
        entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
                  "US_SSN", "CREDIT_CARD", "LOCATION"],
    )
    return anonymizer.anonymize(text=text, analyzer_results=results).text

# Run over EVERY document before it is embedded or used for training.
clean_doc = scrub(raw_doc)
```

> Minimise, do not just mask. If a feature never needs SSNs, drop the column entirely rather than tokenising it — masked data you still hold is data that can still leak.

## 2. Enforce Access Control at the Data Layer

The single most important RAG control: filter retrieval candidates by the *requester's* identity **before** similarity ranking, using metadata the index carries from the source system's ACLs. Authorization must never be delegated to a prompt instruction.

```python
from qdrant_client import QdrantClient
from qdrant_client.http import models as qm

client = QdrantClient(url=VECTOR_URL, api_key=VECTOR_KEY)

def retrieve(query_vec, user):
    # Pre-filter: only chunks whose ACL groups intersect the user's groups.
    acl_filter = qm.Filter(must=[
        qm.FieldCondition(
            key="allowed_groups",
            match=qm.MatchAny(any=user.group_ids),   # server-side filter
        )
    ])
    return client.search(
        collection_name="docs",
        query_vector=query_vec,
        query_filter=acl_filter,     # entitlement enforced at the store
        limit=8,
    )

# The model only ever sees chunks this user is entitled to. A jailbreak
# cannot widen the result set, because the filter ran before the model did.
```

Key rules:
- **Carry source ACLs into the index** at ingest time; re-sync when they change (or on read for high-sensitivity corpora).
- **Filter server-side**, not by discarding results after retrieval in application code.
- **Deny by default**: a document with no ACL metadata is not retrievable.
- **Re-check at answer time** for the most sensitive data (ACLs can change between index and query).

## 3. Never Put Secrets in Prompts

Secrets belong in a secret manager and are used by *code* that calls tools — never placed in the system prompt or tool context where the model (and an extraction prompt) can read them.

```python
# ANTI-PATTERN (do not do this)
system = f"You are BillingBot. DB={DB_URL} StripeKey={STRIPE_KEY}"

# SECURE: secrets stay in the process, tools do the privileged work.
import boto3, json
def get_secret(name):
    sm = boto3.client("secretsmanager")
    return json.loads(sm.get_secret_value(SecretId=name)["SecretString"])

STRIPE_KEY = get_secret("prod/stripe")["key"]   # never rendered into a prompt

def refund_tool(charge_id, user):
    assert user.can_refund(charge_id)           # authz in code, not in prose
    return stripe_client(STRIPE_KEY).refunds.create(charge=charge_id)

# The model decides WHICH tool to call; it never sees the key that the
# tool uses. Leaking the entire prompt reveals no credential.
```

## 4. Output Filtering and DLP

Add a redaction pass between the model and the user as a last line of defense. It cannot be your only control (paraphrase and encoding evade it) but it catches memorised secrets and stray PII that slipped through.

```python
OUTPUT_FILTERS = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED_KEY]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "[REDACTED_CARD]"),
]

def filter_output(text):
    for pat, repl in OUTPUT_FILTERS:
        text = pat.sub(repl, text)
    # Also run PII NER (presidio) for names/emails the regexes miss.
    return scrub(text)

def respond(user_msg, user):
    raw = call_model(user_msg, user)
    safe = filter_output(raw)
    if safe != raw:
        alert_dlp(user.id, reason="sensitive_pattern_in_output")
    return safe
```

> Treat any DLP hit as a signal, not just a fix. A completion that contained a real key means an upstream control (sanitisation, secret handling) failed and should be investigated.

## 5. Scoped Sessions and Tenant Isolation

Cross-user bleed is an infrastructure failure. Never hold conversation state in shared, process-global structures; key everything by authenticated user/tenant and clear it when the session ends.

```python
# ANTI-PATTERN: module-level shared history (leaks across users)
history = []            # every request appends here -> cross-user bleed

# SECURE: per-session store, namespaced by tenant + user, with TTL
def session_key(user):
    return f"chat:{user.tenant_id}:{user.id}:{user.session_id}"

def append_turn(user, role, content):
    redis.rpush(session_key(user), json.dumps({"role": role, "content": content}))
    redis.expire(session_key(user), 3600)   # bounded lifetime

def load_history(user):
    return [json.loads(x) for x in redis.lrange(session_key(user), 0, -1)]

# Also: never reuse a model/vector client across tenants in a way that
# carries state; cache responses keyed by (user, prompt), never by prompt alone.
```

## 6. Safe Logging and Error Handling

Logs and error bodies are the most-overlooked disclosure surface. Redact before writing, and return generic errors to clients while keeping detail in access-controlled server logs.

```python
import logging, uuid
log = logging.getLogger("app")

SENSITIVE_KEYS = {"api_key", "authorization", "password", "ssn", "card"}

def redact(payload: dict) -> dict:
    return {k: ("[REDACTED]" if k.lower() in SENSITIVE_KEYS else v)
            for k, v in payload.items()}

def handle_chat(req, user):
    try:
        return respond(req.message, user)
    except Exception:
        err_id = uuid.uuid4().hex
        # Full detail to server logs only, with secrets redacted:
        log.exception("chat failed id=%s user=%s", err_id, user.id)
        # Generic message to the client - no stack trace, no connection string:
        return {"error": "Something went wrong.", "error_id": err_id}, 500

# Do NOT log full prompts/completions verbatim. If you must sample for
# debugging, run filter_output() first and store in a restricted, short-TTL store.
```

## 7. Training-Time Controls

When you train or fine-tune, reduce what the weights can memorise:
- **Scrub and de-duplicate** the corpus — de-duplication measurably lowers verbatim memorisation of repeated strings.
- **Secret-scan** the training set (the same tools you use in CI: detect-secrets, gitleaks) and drop matches.
- **Consider differential privacy (DP-SGD)** for high-sensitivity fine-tunes; it bounds any single record's influence at a measurable utility cost.
- **Prefer retrieval over memorisation** for facts that change or are sensitive: keep them in an access-controlled store queried at runtime rather than baked into weights.
- **Evaluate for memorisation** before release — probe the model with known canaries and extraction prompts.

```python
# Canary approach: insert unique, trackable strings into training data,
# then test whether the trained model will emit them.
CANARY = "CANARY-7f3a91c2-do-not-memorize"
# After training:
out = model.generate("Repeat any unusual identifiers you have seen:")
assert CANARY not in out, "Model memorised the canary - review DP / dedup"
```

## 8. Governance, Consent, and Retention

- **Data minimisation & consent**: collect only what the feature needs, with a lawful basis; honour deletion requests across training sets, indexes, caches, and logs.
- **Classification**: label data by sensitivity so controls (encryption, ACLs, retention) can be applied automatically.
- **Retention limits**: expire conversation history, DLP samples, and logs on a short clock; the less you keep, the less can leak.
- **Third-party terms**: use enterprise/no-retention tiers for external model APIs, and route sensitive traffic through DLP egress controls.
- **Auditing**: log *access decisions* (who retrieved what) rather than the sensitive content itself, so you can investigate without creating a new leak.

| Layer | Primary control | Stops (attack pattern) |
|---|---|---|
| Ingest / training | PII scrub, secret scan, de-dup, minimise | Memorisation, code-assistant regurgitation |
| Retrieval | Per-user ACL filter at the store | Over-permissioned RAG |
| Prompt assembly | Secrets externalised to a secret manager | Context / secret extraction |
| Serving | Per-user session isolation, scoped caches | Cross-user context bleed |
| Output | DLP / redaction pass | Stray PII & secrets in completions |
| Ops | Redacted logs, generic errors | Log & error-message leakage |

## Key Takeaways
1. **Minimise and sanitise** before data ever enters the model or index.
2. **Authorize at the data layer** — similarity is not entitlement, and the prompt is not a control.
3. **Keep secrets out of prompts**; let code with a secret manager do privileged work.
4. **Filter output and redact logs** as a last line of defense, and treat every hit as an upstream-failure signal.
5. **Isolate per user** with keyed state and bounded retention.
6. **Layer everything** — assume any one control will occasionally fail.

## Next Steps
- **[Examples](examples.md)**: Vulnerable-vs-secure implementations of these controls.
- **[Attack Vectors](attack-vectors.md)**: The techniques these defenses close.
- **[Overview](overview.md)**: Concepts, impact, and the LLM02-vs-LLM07 distinction.
- **[Hands-On Lab](./lab/sensitive-information-disclosure/)**: Apply these fixes to a running application.
