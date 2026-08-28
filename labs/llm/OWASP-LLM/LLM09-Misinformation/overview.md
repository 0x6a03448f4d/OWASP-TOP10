# Misinformation - Overview

## Table of Contents
- [What is Misinformation?](#what-is-misinformation)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)
- [Self-Assessment](#self-assessment)
- [Next Steps](#next-steps)

## What is Misinformation?

**Misinformation** (LLM09:2025 in the OWASP Top 10 for LLM Applications) is the risk that a language model produces **false, misleading, or fabricated information and presents it as if it were credible**. The output is fluent, confident, well-formatted, and often internally consistent — which is exactly what makes it dangerous. A model does not signal doubt the way a hesitant human does; a hallucinated case citation looks identical to a real one, and an invented package name looks identical to a real dependency.

The 2025 edition deliberately merges what the 2023 list treated as two separate entries — *hallucination* and *overreliance* — because they are two halves of the same failure. The model generates something untrue (the technical half), and a human or downstream system accepts it without verification (the human half). Neither half causes harm alone: a hallucination that a reviewer catches is a non-event; a diligent reviewer given accurate output has nothing to catch. Harm occurs precisely where an ungrounded generation meets an unverifying consumer.

### Core Concept

```
Misinformation = Ungrounded Generation  +  Unverified Consumption

  [ LLM produces confident claim ]      [ Human / system trusts it ]
              |                                      |
   fabricated fact, fake citation,        no fact-check, no review,
   non-existent package/API,              no ground truth, no expert
   plausible-but-wrong guidance                       |
              +--------------------+------------------+
                                   v
                        Harm: bad decision, insecure
                        code shipped, supply-chain
                        compromise, legal/medical/
                        financial damage
```

### What It Is Not

Misinformation is **not** the same as an attacker deliberately feeding poisoned data into a model — that is training-data poisoning (LLM04). It is not prompt injection (LLM01), where an adversary hijacks the model's instructions. Misinformation is the model's *own* tendency to state untruths as fact, whether prompted innocently or maliciously. Those other categories can *amplify* misinformation (a poisoned source produces confidently wrong answers), but the defining property of LLM09 is **unreliable output trusted without verification**.

## Why Does This Matter?

Misinformation is one of the highest-frequency, hardest-to-eliminate risks in the entire LLM Top 10, because it is a direct consequence of how the technology works. An LLM predicts the statistically likely next token; it has no built-in notion of truth, no ground-truth database, and no reliable internal signal for "I don't actually know this." Fluency and factual accuracy are separate axes, and the model optimises for the first.

### Business Impact

- **Legal liability for the deploying organisation**: Courts and regulators have increasingly held companies responsible for what their AI systems tell customers — an incorrect answer from your chatbot can be treated as your company's statement, not the model vendor's.
- **Professional sanctions and malpractice exposure**: Fabricated citations, invented statistics, or wrong professional guidance surfaced through an LLM can trigger court sanctions, disciplinary action, and negligence claims.
- **Supply-chain compromise**: When a coding assistant recommends a non-existent package and an attacker registers that name, following the suggestion installs attacker-controlled code — a direct path to breach (see *package hallucination / slopsquatting* below).
- **Reputational damage**: Publicly visible AI answers that are absurd, offensive, or dangerously wrong erode trust in the brand far faster than they were generated.
- **Regulatory exposure**: In regulated domains (health, finance, legal), acting on unverified AI output can violate sector rules and emerging AI-governance requirements.

### Technical Impact

- **Insecure code shipped to production**: Generated code that "looks right" may contain injection flaws, broken auth, or calls to APIs that behave differently than the model claimed (ties directly to LLM05, Improper Output Handling).
- **Corrupted data and knowledge bases**: Hallucinated facts written into documentation, tickets, or databases persist and are later cited as authoritative — misinformation compounds.
- **Broken automation**: Autonomous agents that act on fabricated intermediate "facts" propagate a single hallucination across many downstream actions.
- **Dependency on non-existent components**: Invented package names, config keys, environment variables, or API endpoints cause failures at best and exploitable substitutions at worst.
- **Silent bias**: Skewed or manipulated outputs present a one-sided view as neutral fact, distorting decisions without any obvious error to catch.

## Technical Context

### Why Models Fabricate

Several properties of LLMs make misinformation intrinsic rather than a bug to be patched away:

- **Next-token prediction, not fact retrieval**: The model produces the *most plausible continuation*, and a plausible-sounding but false statement can be more probable than an honest "I don't know."
- **No calibrated uncertainty**: Models rarely express doubt proportional to their actual reliability; confident phrasing accompanies both correct and incorrect claims.
- **Training-data gaps and staleness**: Anything sparse, post-cutoff, or contested in the training data is prime territory for fabrication, filled in with a confident guess.
- **Pattern-completion pressure**: Asked for "five sources" or "the API method for X," the model will manufacture the requested shape even when no real referent exists.

### Taxonomy of Misinformation

#### 1. Factual Hallucination
```
Symptom : Confident false statements — wrong dates, invented statistics,
          fictional events, misattributed quotes.
Risk    : Decisions and published content based on fiction.
Example : "Company X reported $4.2B revenue in Q3" — the figure, and
          sometimes the quarter, simply do not exist.
```

#### 2. Fabricated Citations and Sources
```
Symptom : Plausible-looking references — authors, titles, case numbers,
          DOIs, URLs — that do not correspond to any real document.
Risk    : Legal filings, academic work, and reports "backed" by
          non-existent evidence.
Example : A court brief citing "Smith v. Jones, 123 F.3d 456" for a case
          that was never decided.
```

#### 3. Package / Dependency Hallucination (Slopsquatting)
```
Symptom : A coding assistant recommends importing a library, module, or
          command-line tool whose name does not exist in the registry.
Risk    : SUPPLY CHAIN. An attacker who registers the hallucinated name
          gets their code executed by everyone who follows the advice.
Example : "pip install requests-oauth-helper" — no such package existed
          until an attacker published one at that exact name.
```

The term **"slopsquatting"** (a play on typosquatting) describes this attacker workflow, which security researchers began documenting through 2024–2025: probe LLMs to enumerate the package names they frequently hallucinate, then register the most common ones with malicious payloads. Because the same models tend to hallucinate the *same* plausible names repeatedly, the attacker does not need to guess — the model volunteers a reliable target list.

#### 4. Non-Existent or Misdescribed APIs
```
Symptom : Invented function names, parameters, config keys, flags, or
          endpoints — or real ones described with wrong behaviour.
Risk    : Broken builds; worse, code that "works" but does the wrong
          thing (e.g. a security flag the model claims exists but doesn't).
Example : Calling verify_signature(strict=True) where the library has no
          strict parameter, so the check silently does nothing.
```

#### 5. Fabricated Domain Guidance (Legal / Medical / Financial)
```
Symptom : Authoritative-sounding advice in a high-stakes regulated field
          that is plausible but wrong or dangerously incomplete.
Risk    : Physical harm, financial loss, professional/legal liability.
Example : Confident dosage, statute, or tax guidance that misstates the
          actual rule for the person's real situation.
```

#### 6. Biased or Manipulated Output
```
Symptom : One-sided framing presented as neutral fact; outputs steered by
          leading prompts, poisoned retrieval, or skewed training data.
Risk    : Distorted decisions with no obvious "error" to detect.
Example : A product-comparison answer that silently omits competitors, or
          a summary that inherits a source document's slant as truth.
```

### The Overreliance Multiplier

Every category above is only as dangerous as the trust placed in it. Overreliance — the human and organisational tendency to accept LLM output without verification — is the amplifier that turns a fabrication into an incident. It is driven by **automation bias** (people defer to a confident machine), **fluency bias** (well-written text reads as more credible), and **throughput pressure** (verification is slower than accepting the answer). Any serious defense must address both the generation side (make output more grounded) and the consumption side (make verification mandatory where stakes are high).

## Real-World Impact

> The cases below are described as **verifiable incident classes**, not precise metrics. Exact figures vary by report; the durable lesson is the pattern, not a statistic.

### Class 1: Fabricated Legal Citations Leading to Sanctions

**Pattern**: Since 2023, multiple courts in different jurisdictions have sanctioned attorneys who filed briefs containing case citations that a chatbot had invented — complete with realistic-looking reporter numbers and quotations for decisions that never existed. The best-known early example arose in a US federal matter (a personal-injury suit against an airline), and similar sanctions have recurred since.

**Root cause**: A fabricated-citation hallucination (category 2) met zero verification — the filer trusted the tool's output as if it were legal research.

### Class 2: Company Held Liable for a Support Chatbot's Wrong Answer

**Pattern**: A civil tribunal held an airline responsible for incorrect information its website chatbot gave a customer about a fare policy, rejecting the argument that the chatbot was a separate entity. The organisation — not the model — owned the statement.

**Root cause**: Ungrounded generation about the company's own policies, deployed customer-facing with no grounding to the authoritative policy text and no disclaimer or verification path.

### Class 3: Package Hallucination as a Supply-Chain Vector

**Pattern**: Security researchers demonstrated that coding assistants frequently recommend non-existent package names, that the hallucinated names are *repeatable* across queries and models, and that an attacker can pre-register those names in public registries (npm, PyPI) to get malicious code installed by developers who follow the suggestion. This attacker workflow was named "slopsquatting."

**Root cause**: Dependency hallucination (category 3) combined with developers copy-pasting install commands without confirming the package exists and is legitimate.

### Class 4: AI Search Summaries Surfacing Absurd or Unsafe "Facts"

**Pattern**: Generative "answer" features in search engines have, on multiple occasions, presented fabricated or dangerously wrong guidance in an authoritative, headline-style box — including nonsensical health and cooking advice drawn from satirical or low-quality sources treated as fact.

**Root cause**: Generation grounded in untrustworthy retrieved content, presented with a UI that signals high confidence and invites overreliance.

### Class 5: Plausible-but-Wrong Medical and Financial Guidance

**Pattern**: Health and finance chatbots have produced confident, well-structured guidance that is subtly or seriously incorrect for the individual's actual situation. Because the answer reads like expert advice, users act on it without seeking a professional.

**Root cause**: Fabricated domain guidance (category 5) in a high-stakes field with no human expert in the loop and no clear communication of the model's limits.

## Prevalence and Detectability

Misinformation is best understood as **highly prevalent and moderately hard to detect**:

- **Prevalence**: Every ungrounded generative system exhibits it to some degree. It cannot currently be driven to zero; it can only be reduced and contained. OWASP places it among the most consequential LLM risks precisely because it is unavoidable in raw form.
- **Detectability**: Unlike a crash or a stack trace, a hallucination produces *valid-looking output*. Detection requires comparing the claim against ground truth — a citation lookup, a registry check, an expert review — which is effort many pipelines skip.
- **Exploitability**: Ranges from passive (a user simply believes a wrong fact) to active (an attacker weaponises predictable hallucinations, as in slopsquatting).

> Note: treat any single "hallucination rate" percentage as illustrative only — rates depend heavily on model, prompt, domain, and whether retrieval grounding is used. The reliable takeaway is that the rate is never zero, so verification must be designed in, not assumed away.

## Common Misunderstandings

### Myth 1: "A bigger / newer model won't hallucinate"
**Reality**: Larger models are more fluent and often more accurate, which can make hallucinations *rarer but more convincing* — and therefore harder to catch. Capability does not remove the need for grounding and verification.

### Myth 2: "If I tell it not to make things up, it won't"
**Reality**: A model cannot reliably know when it is fabricating, so an instruction to "only state facts" or "say I don't know if unsure" reduces but never eliminates the behaviour. It is a mitigation, not a guarantee.

### Myth 3: "Citations mean it's verified"
**Reality**: Models fabricate citations as readily as facts, and can even attach a real-looking source to a claim that source never made. A citation is only evidence if you actually retrieved and checked it.

### Myth 4: "RAG eliminates hallucination"
**Reality**: Retrieval-augmented generation greatly reduces fabrication when the retrieved context is trustworthy and the model is constrained to it — but the model can still misread the context, blend it with prior knowledge, or answer confidently when retrieval returns nothing relevant. RAG is a strong control, not a cure.

### Myth 5: "It's the model vendor's problem"
**Reality**: Liability and reputational damage attach to the organisation that *deploys* the system and shows its output to users. You own your application's answers.

### Myth 6: "Hallucination is only a quality issue, not a security issue"
**Reality**: Package hallucination turns directly into supply-chain compromise, and fabricated "security" code (a flag that does nothing, a check that always passes) creates real vulnerabilities. Misinformation has a hard security edge.

## Self-Assessment

Ask these questions about any LLM feature you ship:

- [ ] For factual answers, is the model **grounded** in a trusted, retrievable source rather than answering from parametric memory?
- [ ] Are **citations verified** to exist and to actually support the claim before they reach the user?
- [ ] Is **generated code validated**, and are recommended **dependencies confirmed to exist** and be legitimate before anyone installs them?
- [ ] For high-stakes domains (legal, medical, financial, safety), is there **mandatory human expert review** in the loop?
- [ ] Does the UI **communicate uncertainty and limitations** instead of presenting every answer as authoritative?
- [ ] Do you run **cross-verification or self-consistency** checks on high-value outputs?
- [ ] Are outputs **constrained to known/validated data** where possible (enumerations, allow-lists, schemas) rather than free-form?
- [ ] Have your users been **trained** on model limitations and the verification steps expected of them?

Several "no" or "not sure" answers means your system is one confident fabrication away from an incident.

## Next Steps

- **[Attack Vectors](attack-vectors.html)**: How hallucination arises and how attackers weaponise it
- **[Prevention](prevention.html)**: Layered grounding, verification, and oversight defenses
- **[Examples](examples.html)**: Vulnerable vs. secure code for grounding, citation, and dependency validation
- **[Hands-On Lab](./lab/misinformation/)**: Practice detecting and mitigating misinformation (runs at `http://localhost:6009`)
