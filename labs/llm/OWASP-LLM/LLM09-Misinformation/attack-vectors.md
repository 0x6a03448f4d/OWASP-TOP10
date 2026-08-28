# Misinformation - Attack Vectors

## Table of Contents
- [Understanding Misinformation Attack Vectors](#understanding-misinformation-attack-vectors)
- [Core Flow: From Token to Incident](#core-flow-from-token-to-incident)
- [Attack & Failure Patterns](#attack--failure-patterns)
- [Chaining and Amplification](#chaining-and-amplification)
- [Key Takeaways](#key-takeaways)
- [Next Steps](#next-steps)

## Understanding Misinformation Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find, reproduce, and fix these failures in systems you own or are authorised to test.

Misinformation is unusual among the LLM Top 10 because many of its "attack vectors" are not adversarial at all — they are **failure modes the model produces on its own**, which an attacker then learns to *trigger*, *predict*, or *weaponise*. It is useful to hold two lenses at once:

- **The failure lens**: How does the model come to state something false with confidence? (hallucination mechanics)
- **The adversary lens**: How does an attacker deliberately induce, amplify, or exploit that falsehood for gain? (weaponisation)

The most damaging real-world cases (slopsquatting, poisoned retrieval) sit at the intersection: the model's natural tendency to fabricate becomes a *reliable primitive* the attacker builds on.

## Core Flow: From Token to Incident

```
(1) TRIGGER              (2) GENERATION            (3) PRESENTATION
    A prompt asks for   ->  Model emits the       ->  Output is rendered
    a fact, source,         most plausible            fluently, often with
    package, or answer      continuation — which      formatting, citations,
                            may be fabricated         and a confident tone
                                   |                          |
                                   v                          v
(5) IMPACT              (4) CONSUMPTION
    Bad decision,       <-  Human or downstream system accepts the
    insecure code,          output WITHOUT verification (overreliance):
    supply-chain            no ground truth, no expert, no registry check
    compromise                     ^
                                   |
             An attacker can influence ANY stage:
             - Stage 1: craft prompts that induce fabrication
             - Stage 2: poison retrieval / training so "facts" are wrong
             - Stage 3: exploit UI that signals false confidence
             - Stage 4: rely on the victim's habit of not verifying
```

Defenses (covered in [Prevention](prevention.html)) map onto the same stages: constrain and ground the trigger, ground and validate the generation, communicate uncertainty in the presentation, and force verification before consumption.

## Attack & Failure Patterns

### 1. Open-Domain Fact Fabrication
The baseline failure. Asked a factual question outside its reliable knowledge — or about anything after its training cutoff — the model fills the gap with a confident guess rather than a refusal.
```
Prompt : "What was ACME Corp's exact Q3 2025 net revenue and who is
          their current CFO?"
Output : "$4.21 billion, up 12% YoY; the CFO is Jane Doe."
Reality: The figure is invented and the named CFO never held the role.
Trigger: Requesting precise, recent, or obscure facts the model cannot know.
```

### 2. Fabricated Citations and Evidence
When asked to "cite sources," models generate the *shape* of citations — authors, titles, case numbers, DOIs, URLs — without a real referent. The fabrication is more dangerous than a bare false claim because the citation manufactures a veneer of rigour.
```
Prompt : "Give me three peer-reviewed studies proving claim X, with DOIs."
Output : Three well-formatted references with plausible authors and DOIs.
Reality: The DOIs resolve to nothing (or to unrelated papers).
Why    : "Provide N sources" is a shape the model completes regardless of
         whether N real sources exist.
```

### 3. Package Hallucination → Slopsquatting (Supply Chain)
The highest-severity *security* pattern. A coding assistant recommends installing a package that does not exist. An attacker who has enumerated these hallucinations pre-registers the name with a malicious payload; every developer who follows the suggestion pulls attacker code.
```
Attacker workflow:
  1. Probe LLMs with thousands of realistic coding prompts.
  2. Collect recommended imports / install commands.
  3. Diff against real registries (PyPI, npm) to find names that
     DO NOT EXIST yet but are recommended REPEATABLY.
  4. Register the top hallucinated names with malicious code.
  5. Wait — the model keeps recommending them to new victims.

Victim side:
  $ pip install requests-oauth-helper   # model said to; looks fine
  # -> installs attacker-controlled package, runs setup code
```
**Why it works**: hallucinated names are not random — models converge on the same plausible-sounding names, so the attacker gets a stable, high-traffic target list for free.

### 4. Non-Existent or Misdescribed APIs
The model invents functions, parameters, flags, or endpoints, or describes real ones with wrong behaviour. The subtle danger is a *security* parameter that does not exist: the code runs, appears to enforce a control, and silently enforces nothing.
```
Model says : "Pass verify=True to enforce strict certificate checking."
Reality    : The library's client() takes no verify argument, or it
             defaults to False, so TLS verification never happens.
Result     : Code that looks secure in review but isn't.
```

### 5. Prompt-Induced Fabrication (Adversarial Elicitation)
An attacker (or careless user) crafts prompts that maximise fabrication: demanding false precision, presupposing false premises, or forbidding "I don't know."
```
Leading premise : "Since Regulation 12-B requires X, explain how to comply."
                  (Regulation 12-B does not exist — the model plays along
                   and invents compliant-sounding steps.)
Forbidding doubt: "Answer definitively. Do not say you are unsure."
                  (Suppresses the one honest signal the model might give.)
```

### 6. Indirect Manipulation via Poisoned Retrieval (RAG)
In a RAG system, the "facts" come from retrieved documents. If an attacker can get malicious content into the knowledge base or a crawled source, the model will faithfully ground its confident answer in falsehood.
```
Attack: Plant a document (wiki edit, indexed web page, uploaded file)
        stating a false "policy" or "fact."
Effect: Retrieval surfaces it; the model cites it verbatim with full
        confidence. Grounding turned into laundering.
Note  : This overlaps LLM01 (indirect prompt injection) and LLM04
        (data poisoning) — here the payoff is authoritative misinformation.
```

### 7. Biased / One-Sided Output as "Neutral Fact"
Outputs can be steered — by training-data skew, a loaded prompt, or selective retrieval — to present a partial view as complete and neutral. There is no factual "error" to catch, which makes it especially durable.
```
Prompt : "Compare our product to the competition."
Output : Glowing comparison that silently omits the two strongest rivals.
Risk   : Reader treats an incomplete, slanted answer as an objective survey.
```

### 8. Overconfident Tone and Confidence Mismatch
The presentation layer is itself a vector. Identical confident phrasing accompanies correct and incorrect answers, and formatting (tables, bullet points, citations) raises perceived reliability regardless of accuracy.
```
"Definitely.", "It is well established that...", a neat table, a citation:
all raise trust WITHOUT raising truth. Attackers and sloppy UIs exploit
the human habit of reading fluency as expertise.
```

### 9. Temporal / Knowledge-Cutoff Fabrication
Asked about events after its training cutoff, the model may not admit the gap — it extrapolates, presenting guesses about recent releases, prices, or events as established fact.
```
Prompt : "What are the breaking changes in FooLib 5.0?" (released last week)
Output : A confident, detailed changelog — entirely invented.
```

### 10. Numeric, Unit, and Calculation Errors
Free-form models are unreliable arithmetic engines. They produce confident totals, conversions, dosages, and financial figures that are simply wrong, formatted to look computed.
```
Prompt : "Convert 750 mg to the correct pediatric dose for 14 kg."
Risk   : A plausible number in a high-stakes unit — trusted without a
         real calculator or clinician.
```

### 11. Fabricated Structured Data / Schema Filling
When asked to return JSON, a table, or records, the model will populate every required field — including inventing IDs, statuses, or foreign keys that do not exist — to satisfy the schema.
```
Ask    : "Return the order record as JSON."
Output : {"order_id": "ORD-88213", "status": "shipped", "tracking": "1Z..."}
Reality: No such order — the model fabricated a well-formed record because
         the schema demanded values. Downstream systems ingest fiction.
```

### 12. Automation / Agent Propagation
In autonomous multi-step agents, one hallucinated "fact" in an early step becomes an input to later steps and tool calls, so a single fabrication fans out into many wrong actions before any human sees output.
```
Step 1: Agent "learns" a false API endpoint (hallucinated).
Step 2: Writes it into a config.
Step 3: Opens a PR, files a ticket, emails a summary — all citing the
        false endpoint as established. Error is now laundered as record.
```

## Chaining and Amplification

Individually survivable failures combine into incidents. The recurring shape is **fabrication × overreliance × downstream action**:

| Chain | Step 1 (fabrication) | Step 2 (no verification) | Outcome |
|-------|----------------------|--------------------------|---------|
| Legal | Invented case citation | Filed without checking the reporter | Court sanctions, lost case |
| Supply chain | Hallucinated package name | `pip install` run as suggested | Attacker code executed |
| Security code | Non-existent "strict" flag | Merged in review as-is | Control silently disabled |
| Data | Fabricated record fields | Ingested into database | Knowledge base poisoned |
| RAG | Poisoned source retrieved | Cited verbatim to user | Authoritative misinformation |

The lesson: you rarely fix misinformation by fixing "the model." You break the *chain* — add grounding at step 1, and mandatory verification at step 2 — so a single fabrication cannot reach a consequential action.

## Key Takeaways

1. **Most vectors are the model's own failure modes** that attackers learn to trigger and predict, not classic exploits.
2. **Fabrication is repeatable** — the same prompts yield the same invented names and citations, which is exactly what makes slopsquatting practical.
3. **Package and API hallucination are security issues**, not just quality issues: they lead directly to supply-chain compromise and silently disabled controls.
4. **Presentation is an attack surface** — confident tone, formatting, and citations raise trust without raising truth.
5. **Harm needs both halves**: a fabrication only becomes an incident when it meets a consumer who does not verify. Break the chain, not just the model.

## Next Steps

- **[Prevention Guide](prevention.html)**: Layered grounding, verification, and oversight controls
- **[Code Examples](examples.html)**: Vulnerable vs. secure grounding, citation, and dependency validation
- **[Hands-On Lab](./lab/misinformation/)**: Reproduce and mitigate these patterns (runs at `http://localhost:6009`)
