# Misinformation - Prevention

## Table of Contents
- [Defense Strategy: Ground, Verify, Oversee](#defense-strategy-ground-verify-oversee)
- [Layer 1 — Retrieval-Augmented Grounding](#layer-1--retrieval-augmented-grounding)
- [Layer 2 — Citation & Source Verification](#layer-2--citation--source-verification)
- [Layer 3 — Cross-Verification & Self-Consistency](#layer-3--cross-verification--self-consistency)
- [Layer 4 — Output Constraint & Validation](#layer-4--output-constraint--validation)
- [Layer 5 — Generated Code & Dependency Validation](#layer-5--generated-code--dependency-validation)
- [Layer 6 — Human Oversight for High-Stakes Domains](#layer-6--human-oversight-for-high-stakes-domains)
- [Layer 7 — UX, Uncertainty & User Training](#layer-7--ux-uncertainty--user-training)
- [Layer 8 — Monitoring & Feedback](#layer-8--monitoring--feedback)
- [Defense Checklist](#defense-checklist)
- [Next Steps](#next-steps)

## Defense Strategy: Ground, Verify, Oversee

Because misinformation cannot be eliminated at the model level, prevention is about **containment through layers**. No single control is sufficient; each layer catches what the previous one missed. The layers fall into three jobs:

- **Ground** the generation in trusted data so the model has less reason to fabricate (Layers 1–2).
- **Verify** outputs against reality before they are used — citations, consistency, schemas, dependencies (Layers 3–5).
- **Oversee** with humans and honest UX so that whatever slips through meets a skeptical, informed consumer (Layers 6–8).

```
Untrusted free-form generation
        |
   [1] Grounding (RAG on trusted corpus)         reduce fabrication
   [2] Citation verification                     prove the evidence
   [3] Cross-verification / self-consistency     catch inconsistency
   [4] Output constraint + schema validation     reject impossible output
   [5] Code + dependency validation              stop slopsquatting / bad code
   [6] Human review for high-stakes              expert final say
   [7] Honest UX + user training                 defeat overreliance
   [8] Monitoring + feedback                     detect drift, improve
        |
   Trustworthy, contained output
```

## Layer 1 — Retrieval-Augmented Grounding

The single most effective control. Instead of answering from parametric memory, retrieve relevant passages from a **trusted, curated source** and instruct the model to answer *only* from that context — and to refuse when the context does not contain the answer.

```python
SYSTEM_PROMPT = """You answer strictly from the CONTEXT provided.
Rules:
- Use ONLY facts found in CONTEXT. Do not use prior knowledge.
- Every factual sentence must be supported by CONTEXT.
- If CONTEXT does not contain the answer, reply exactly:
  "I don't have that information in my sources."
- Never invent sources, numbers, names, or citations.
"""

def answer(question: str) -> dict:
    chunks = retriever.search(question, k=6, min_score=0.75)
    if not chunks:                      # nothing relevant retrieved
        return {"answer": "I don't have that information in my sources.",
                "sources": []}
    context = "\n\n".join(f"[{c.id}] {c.text}" for c in chunks)
    resp = llm.chat(
        system=SYSTEM_PROMPT,
        user=f"CONTEXT:\n{context}\n\nQUESTION: {question}",
        temperature=0,                  # minimise creative drift
    )
    return {"answer": resp.text, "sources": [c.id for c in chunks]}
```

**Key points**: enforce a *relevance floor* (`min_score`) so weak retrieval triggers a refusal rather than a guess; keep `temperature=0` for factual tasks; and make "I don't know" an explicit, rewarded output. Grounding is a strong control, not a cure — combine it with the verification layers below.

## Layer 2 — Citation & Source Verification

Never let a model-produced citation reach the user unverified. Require the model to cite **source IDs from the retrieved context** (which you control), then programmatically confirm each cited ID exists and actually supports the claim.

```python
ALLOWED_IDS = {c.id for c in chunks}          # only real, retrieved sources

def validate_citations(answer_text: str, cited_ids: list[str]) -> None:
    for cid in cited_ids:
        if cid not in ALLOWED_IDS:            # model invented a source id
            raise CitationError(f"Fabricated citation: {cid}")
    if not cited_ids:                         # factual claim, zero support
        raise CitationError("Answer makes claims with no cited source")

# For open-web citations, resolve them for real before trusting:
def citation_resolves(url: str) -> bool:
    try:
        r = http.head(url, timeout=5, allow_redirects=True)
        return r.status_code < 400
    except Exception:
        return False
```

The principle: a citation is only evidence if *you* retrieved and checked it. Resolving DOIs/URLs and matching claims to source text turns "looks cited" into "is supported."

## Layer 3 — Cross-Verification & Self-Consistency

For high-value factual outputs, sample the model multiple times (or with multiple models) and keep only claims that are stable across runs. Divergence is a strong signal of fabrication.

```python
from collections import Counter

def self_consistent_answer(question: str, n: int = 5) -> dict:
    samples = [llm.chat(user=question, temperature=0.7).text for _ in range(n)]
    key = [normalize(s) for s in samples]     # canonicalise for comparison
    winner, votes = Counter(key).most_common(1)[0]
    confidence = votes / n
    if confidence < 0.6:                       # answers disagree -> low trust
        return {"answer": None, "confidence": confidence,
                "action": "escalate_or_refuse"}
    return {"answer": samples[key.index(winner)], "confidence": confidence}
```

A second pattern is an **LLM verifier**: a separate call asks "Is every claim in this answer supported by this context? List unsupported claims." Treat any unsupported claim as blocking. (Remember the verifier can also err — use it to *flag*, not to bless.)

## Layer 4 — Output Constraint & Validation

The less free-form the output, the less room to fabricate. Where the valid answers are knowable, constrain the model to them and validate before use.

```python
from pydantic import BaseModel, field_validator

VALID_STATUSES = {"open", "shipped", "delivered", "cancelled"}

class OrderAnswer(BaseModel):
    order_id: str
    status: str

    @field_validator("status")
    @classmethod
    def known_status(cls, v):
        if v not in VALID_STATUSES:           # reject invented enum values
            raise ValueError(f"Hallucinated status: {v}")
        return v

    @field_validator("order_id")
    @classmethod
    def real_order(cls, v):
        if not db.order_exists(v):             # reject fabricated records
            raise ValueError(f"Order {v} does not exist")
        return v

# Parse model JSON through the schema; reject on any validation error.
answer = OrderAnswer.model_validate_json(model_output)
```

Techniques: JSON-schema / structured-output modes, allow-lists and enumerations, grammar-constrained decoding, and — critically — checking IDs and entities against the *real* system of record rather than trusting the model's word that they exist.

## Layer 5 — Generated Code & Dependency Validation

This is where misinformation becomes a supply-chain security control. **Before any AI-suggested dependency is installed, confirm it exists, is not a look-alike, and is the intended project.** This directly defeats slopsquatting and connects to LLM05 (validate generated output before downstream use).

```python
import subprocess, json
from datetime import datetime, timezone

def vet_pypi_package(name: str) -> None:
    # 1. Does it exist at all? (A hallucinated name will 404.)
    r = http.get(f"https://pypi.org/pypi/{name}/json", timeout=5)
    if r.status_code == 404:
        raise DependencyError(f"HALLUCINATED / non-existent package: {name}")
    meta = r.json()["info"]

    # 2. Suspicious brand-new package? (classic slopsquat signature)
    releases = r.json()["releases"]
    first = min(datetime.fromisoformat(f[0]["upload_time_iso_8601"])
                for f in releases.values() if f)
    age_days = (datetime.now(timezone.utc) - first).days
    if age_days < 90:
        raise DependencyError(f"Package {name} is very new ({age_days}d) "
                              "— verify before use (possible slopsquat)")

    # 3. Must be on the approved allow-list / private index for prod use.
    if name not in APPROVED_DEPENDENCIES:
        raise DependencyError(f"{name} not in approved dependency list")

# NEVER pipe an LLM's install command straight to a shell.
# Extract package names, vet each, THEN install pinned + hashed.
```

Operational rules that make this robust:

- **Pin and hash** every dependency (`requirements.txt` with hashes, `package-lock.json`); never install unpinned names an assistant emitted.
- **Use a private/proxy registry** with an allow-list so unknown names cannot be pulled at all.
- **Run SCA / provenance checks** (e.g. signature or attestation verification) in CI, and diff new dependencies in review.
- **Validate the code itself**: lint, type-check, run SAST, and confirm that any security-relevant API/flag the model used actually exists and does what was claimed.

## Layer 6 — Human Oversight for High-Stakes Domains

In legal, medical, financial, and safety contexts, no automated control substitutes for a qualified human. Route high-stakes outputs to **mandatory expert review** and make the AI's role explicitly advisory.

```python
HIGH_STAKES = {"legal", "medical", "financial", "safety"}

def deliver(answer: dict, domain: str, confidence: float) -> dict:
    needs_review = (
        domain in HIGH_STAKES
        or confidence < 0.8
        or answer.get("unsupported_claims")
    )
    if needs_review:
        review_queue.enqueue(answer)           # human-in-the-loop gate
        return {"status": "pending_expert_review",
                "note": "AI draft — not yet verified by a professional"}
    return {"status": "delivered", **answer}
```

Design the workflow so the human is a *reviewer of evidence*, not a rubber stamp: show the sources, highlight unsupported claims, and make "reject" as easy as "approve" to counter automation bias.

## Layer 7 — UX, Uncertainty & User Training

Overreliance is defeated in the interface. The UI must actively discourage blind trust rather than reinforce it with a confident tone.

- **Communicate limitations**: a persistent, honest notice that answers may be wrong and should be verified for important decisions.
- **Surface sources inline**: link the exact passage each claim rests on, so verification is one click away.
- **Show uncertainty**: when confidence or retrieval score is low, say so — "I'm not sure" beats a confident guess.
- **Avoid false-authority styling**: don't dress unverified output in the visual language of certified fact.
- **Provide friction for high-stakes actions**: require explicit acknowledgement before AI output drives a consequential step.

```python
def render(answer: dict) -> dict:
    return {
        "text": answer["answer"],
        "sources": answer["sources"],          # always show provenance
        "confidence_label": bucket(answer["confidence"]),  # High/Med/Low
        "disclaimer": ("AI-generated. Verify important facts against the "
                       "linked sources before acting."),
    }
```

**User training** is the human complement: teach staff that models hallucinate, that fluency is not accuracy, and that citations, code, and dependencies must be checked. A trained, skeptical user is the last and often best line of defense.

## Layer 8 — Monitoring & Feedback

Treat misinformation as an ongoing quality-and-security signal, not a one-time fix.

- **Log** question, retrieved sources, answer, cited IDs, confidence, and whether it was human-reviewed — so failures are reproducible and auditable.
- **Track** refusal rate, citation-validation failures, and dependency-vetting rejections as leading indicators.
- **Collect user feedback** ("was this accurate?") and route corrections back into the trusted corpus and evals.
- **Red-team regularly** with prompts designed to elicit fabrication (recent events, obscure facts, "cite sources," "which package should I install") and measure the hallucination rate over time.
- **Alert** on spikes in low-confidence answers or invented citations, which can indicate model, retrieval, or data-poisoning problems.

## Defense Checklist

| Control | Defends against | Priority |
|---------|-----------------|----------|
| RAG grounding on trusted corpus, temp 0, refuse-on-no-context | Fact/citation fabrication | Critical |
| Citation IDs restricted to retrieved sources + resolution check | Fabricated evidence | Critical |
| Dependency existence + age + allow-list vetting; pin & hash | Package hallucination / slopsquatting | Critical |
| Schema / enum / entity validation against system of record | Invented records, APIs, statuses | High |
| Self-consistency / verifier pass on high-value outputs | Confident inconsistency | High |
| Mandatory expert review for high-stakes domains | Legal/medical/financial harm | Critical |
| Honest UX: sources, confidence, disclaimers | Overreliance | High |
| User training on model limits and verification | Overreliance | High |
| Logging, feedback, red-teaming, drift alerts | All (detection) | Medium |

## Next Steps

- **[Code Examples](examples.html)**: Vulnerable vs. secure implementations of these controls
- **[Attack Vectors](attack-vectors.html)**: The failure modes these layers defend against
- **[Hands-On Lab](./lab/misinformation/)**: Apply grounding and validation yourself (runs at `http://localhost:6009`)
