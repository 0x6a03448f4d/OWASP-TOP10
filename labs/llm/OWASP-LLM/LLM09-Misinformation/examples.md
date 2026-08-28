# Misinformation - Examples

## Table of Contents
- [How to Read These Examples](#how-to-read-these-examples)
- [Example 1: Ungrounded Answers vs RAG Grounding](#example-1-ungrounded-answers-vs-rag-grounding)
- [Example 2: Trusting Citations vs Verifying Them](#example-2-trusting-citations-vs-verifying-them)
- [Example 3: Installing Hallucinated Packages vs Dependency Vetting](#example-3-installing-hallucinated-packages-vs-dependency-vetting)
- [Example 4: Fabricated Records vs Schema & Entity Validation](#example-4-fabricated-records-vs-schema--entity-validation)
- [Example 5: Confident UI vs Uncertainty-Aware UI (Node/TS)](#example-5-confident-ui-vs-uncertainty-aware-ui-nodets)
- [Example 6: No Review vs Human-in-the-Loop for High-Stakes](#example-6-no-review-vs-human-in-the-loop-for-high-stakes)
- [Summary Table](#summary-table)
- [Next Steps](#next-steps)

## How to Read These Examples

Each example pairs a **vulnerable** implementation — one that lets a confident fabrication reach the user or a downstream system — with a **secure** one that grounds, verifies, or constrains the output. Python is the primary language (it dominates RAG and LLM tooling); Node/TypeScript appears where it is the more natural fit. The code is illustrative: adapt names, SDKs, and error handling to your stack.

> The through-line: **never let free-form model output be trusted as fact, evidence, a dependency, or a record without a check against ground truth.**

## Example 1: Ungrounded Answers vs RAG Grounding

### ❌ Vulnerable: Answer from parametric memory

```python
import openai

def answer(question: str) -> str:
    # No grounding, no sources, high temperature: the model will happily
    # invent policies, numbers, and facts and state them confidently.
    resp = openai.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You are a helpful support agent."},
            {"role": "user", "content": question},
        ],
        temperature=0.7,
    )
    return resp.choices[0].message.content   # shipped straight to the user
```

**Why it is vulnerable**: asked "What is your refund window?" the model produces a plausible number (e.g. "30 days") whether or not that is your actual policy. The answer becomes the company's statement — with no source and no way to tell fact from fabrication.

### ✅ Secure: Ground in a trusted corpus and refuse on no context

```python
import openai

SYSTEM = """Answer ONLY from CONTEXT. Do not use outside knowledge.
If CONTEXT lacks the answer, reply exactly:
"I don't have that information in our policies."
Never invent numbers, policies, or citations."""

def answer(question: str) -> dict:
    chunks = retriever.search(question, k=5, min_score=0.75)
    if not chunks:                              # weak retrieval -> refuse
        return {"answer": "I don't have that information in our policies.",
                "sources": []}

    context = "\n\n".join(f"[{c.id}] {c.text}" for c in chunks)
    resp = openai.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"CONTEXT:\n{context}\n\nQ: {question}"},
        ],
        temperature=0,                          # deterministic, factual
    )
    return {"answer": resp.choices[0].message.content,
            "sources": [c.id for c in chunks]}
```

**Why it is secure**: the answer is constrained to curated policy text, a relevance floor turns "no good source" into an honest refusal instead of a guess, `temperature=0` minimises drift, and every answer carries the source IDs it rests on.

## Example 2: Trusting Citations vs Verifying Them

### ❌ Vulnerable: Display whatever "sources" the model emits

```python
def research(topic: str) -> str:
    resp = llm.chat(user=f"Summarise {topic}. Include 3 sources with URLs.")
    # The model fabricates realistic-looking URLs/DOIs. We render them as-is.
    return resp.text   # user sees citations that may resolve to nothing
```

### ✅ Secure: Restrict citations to retrieved IDs and resolve real URLs

```python
import requests

class CitationError(Exception): ...

def research(topic: str) -> dict:
    chunks = retriever.search(topic, k=6, min_score=0.7)
    allowed = {c.id for c in chunks}
    context = "\n\n".join(f"[{c.id}] {c.text}" for c in chunks)

    resp = llm.chat(
        system="Cite ONLY the bracketed [id] tags from CONTEXT. "
               "Do not invent sources.",
        user=f"CONTEXT:\n{context}\n\nSummarise {topic} with [id] citations.",
        temperature=0,
    )
    cited = extract_citation_ids(resp.text)     # e.g. ['doc-12', 'doc-3']

    # 1. Every citation must be a real, retrieved source id.
    invented = [c for c in cited if c not in allowed]
    if invented:
        raise CitationError(f"Model fabricated citations: {invented}")
    # 2. A factual summary with zero citations is not trustworthy.
    if not cited:
        raise CitationError("No sources cited for factual claims")

    return {"summary": resp.text, "sources": sorted(cited)}

def url_resolves(url: str) -> bool:
    # For open-web citations, confirm the document actually exists.
    try:
        return requests.head(url, timeout=5, allow_redirects=True).status_code < 400
    except requests.RequestException:
        return False
```

**Why it is secure**: citations can only reference sources you actually retrieved, invented IDs raise an error instead of reaching the user, and open-web references are resolved for real before they are trusted.

## Example 3: Installing Hallucinated Packages vs Dependency Vetting

This is the **slopsquatting** supply-chain risk. Coding assistants recommend package names that do not exist; attackers register those names with malicious code.

### ❌ Vulnerable: Pipe the assistant's suggestion straight to the installer

```bash
# The assistant said: "Just run this to add OAuth helpers."
# A developer copy-pastes it into the terminal:

$ pip install requests-oauth-helper        # <- does this package even exist?
# If an attacker has registered that hallucinated name, its setup code
# now runs on the developer's machine and in CI. Supply chain compromised.
```

### ✅ Secure: Vet every AI-suggested dependency before install

```python
import requests
from datetime import datetime, timezone

APPROVED = {"requests", "pydantic", "fastapi", "sqlalchemy"}  # allow-list

class DependencyError(Exception): ...

def vet_pypi_package(name: str) -> None:
    r = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=5)

    # 1. Non-existent name = hallucination. Never install it.
    if r.status_code == 404:
        raise DependencyError(f"HALLUCINATED / non-existent package: {name!r}")
    r.raise_for_status()

    # 2. Brand-new package matching a suggested name is a slopsquat signature.
    releases = [f for fs in r.json()["releases"].values() for f in fs]
    if releases:
        first = min(datetime.fromisoformat(f["upload_time_iso_8601"])
                    for f in releases)
        age_days = (datetime.now(timezone.utc) - first).days
        if age_days < 90:
            raise DependencyError(
                f"{name!r} is only {age_days} days old - verify before use")

    # 3. Production installs must come from the approved allow-list.
    if name not in APPROVED:
        raise DependencyError(f"{name!r} is not an approved dependency")

def safe_add_dependencies(names: list[str]) -> None:
    for n in names:
        vet_pypi_package(n)                     # raises on anything suspicious
    # Only now install, pinned and hash-locked (never the raw AI command):
    #   pip install --require-hashes -r requirements.lock
```

**Why it is secure**: a hallucinated name 404s and is rejected before it can be installed, suspiciously new packages are flagged, an allow-list blocks anything unrecognised, and installs are pinned and hash-locked so the exact reviewed artifact is what runs.

## Example 4: Fabricated Records vs Schema & Entity Validation

### ❌ Vulnerable: Trust model-generated JSON as real data

```python
import json

def lookup_order(order_id: str) -> dict:
    resp = llm.chat(user=f"Return order {order_id} as JSON with status.")
    # The model fabricates a well-formed record for an order that may
    # not exist, with an invented status. Downstream code ingests fiction.
    return json.loads(resp.text)
```

### ✅ Secure: Validate against a schema and the real system of record

```python
from pydantic import BaseModel, field_validator

VALID_STATUSES = {"open", "shipped", "delivered", "cancelled"}

class Order(BaseModel):
    order_id: str
    status: str

    @field_validator("status")
    @classmethod
    def known_status(cls, v: str) -> str:
        if v not in VALID_STATUSES:             # reject invented enum values
            raise ValueError(f"Hallucinated status: {v!r}")
        return v

    @field_validator("order_id")
    @classmethod
    def real_order(cls, v: str) -> str:
        if not db.order_exists(v):               # reject fabricated records
            raise ValueError(f"Order {v!r} does not exist")
        return v

def lookup_order(order_id: str) -> Order:
    # Prefer authoritative data outright; use the LLM only to phrase it.
    row = db.get_order(order_id)                 # source of truth
    if row is None:
        raise LookupError(f"No such order: {order_id}")
    return Order(order_id=row.id, status=row.status)
```

**Why it is secure**: statuses are constrained to a known set, IDs are checked against the database, and — best of all — the authoritative record comes from the database while the model is used only to present it, never to invent it.

## Example 5: Confident UI vs Uncertainty-Aware UI (Node/TS)

### ❌ Vulnerable: Render every answer as authoritative fact

```typescript
// Express handler — no sources, no confidence, no disclaimer.
app.post("/ask", async (req, res) => {
  const answer = await llm.chat(req.body.question);
  res.json({ answer });          // looks like verified truth to the user
});
```

### ✅ Secure: Surface sources, confidence, and honest limitations

```typescript
type Grounded = { answer: string; sources: string[]; score: number };

function confidenceLabel(score: number): "High" | "Medium" | "Low" {
  if (score >= 0.8) return "High";
  if (score >= 0.6) return "Medium";
  return "Low";
}

app.post("/ask", async (req, res) => {
  const g: Grounded = await answerWithRetrieval(req.body.question);

  // No trustworthy source? Say so instead of guessing.
  if (g.sources.length === 0) {
    return res.json({
      answer: "I don't have a reliable source for that.",
      sources: [],
      confidence: "Low",
    });
  }

  res.json({
    answer: g.answer,
    sources: g.sources,                       // always show provenance
    confidence: confidenceLabel(g.score),
    disclaimer:
      "AI-generated. Verify important facts against the linked sources " +
      "before acting.",
  });
});
```

**Why it is secure**: the interface counters overreliance directly — provenance is always visible, low-confidence answers are labelled or withheld, and a standing disclaimer reminds users that fluency is not proof.

## Example 6: No Review vs Human-in-the-Loop for High-Stakes

### ❌ Vulnerable: Auto-deliver legal/medical/financial guidance

```python
def advise(question: str, domain: str) -> str:
    # Legal, medical, and financial advice delivered with no expert check.
    return llm.chat(user=question).text
```

### ✅ Secure: Gate high-stakes and low-confidence output to expert review

```python
HIGH_STAKES = {"legal", "medical", "financial", "safety"}

def advise(answer: dict, domain: str, confidence: float) -> dict:
    needs_review = (
        domain in HIGH_STAKES
        or confidence < 0.8
        or answer.get("unsupported_claims")
    )
    if needs_review:
        review_queue.enqueue(answer)             # qualified human decides
        return {"status": "pending_expert_review",
                "note": "AI draft - not verified by a professional yet"}
    return {"status": "delivered", **answer}
```

**Why it is secure**: consequential domains never reach the user on the model's word alone. A qualified human reviews the evidence, and the AI's output is explicitly framed as an unverified draft until they sign off.

## Summary Table

| Risk | Vulnerable | Secure |
|------|------------|--------|
| Fact fabrication | Answer from memory, high temperature | RAG grounding, temp 0, refuse on no context |
| Fake citations | Render model-emitted URLs/DOIs | Citations limited to retrieved IDs; resolve URLs |
| Package hallucination | `pip install` the suggested name | Existence + age + allow-list vetting; pin & hash |
| Invented records | Trust model JSON | Schema + enum + DB existence checks; DB is source of truth |
| Overreliance | Bare answer, no context | Sources, confidence, disclaimer, honest refusal |
| High-stakes harm | Auto-deliver advice | Mandatory expert review in the loop |

## Next Steps

- **[Prevention](prevention.html)**: The full layered defense strategy behind these snippets
- **[Attack Vectors](attack-vectors.html)**: The failure modes each example defends against
- **[Hands-On Lab](./lab/misinformation/)**: Implement grounding and validation yourself (runs at `http://localhost:6009`)
