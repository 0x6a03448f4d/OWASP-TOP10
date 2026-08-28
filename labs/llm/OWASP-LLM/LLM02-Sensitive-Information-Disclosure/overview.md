# LLM02: Sensitive Information Disclosure - Overview

## Table of Contents
- [What is Sensitive Information Disclosure?](#what-is-sensitive-information-disclosure)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence](#prevalence)
- [Common Misunderstandings](#common-misunderstandings)
- [How LLM02 Differs from LLM07 (System Prompt Leakage)](#how-llm02-differs-from-llm07-system-prompt-leakage)
- [Self-Assessment](#self-assessment)
- [Next Steps](#next-steps)

## What is Sensitive Information Disclosure?

**Sensitive Information Disclosure** (LLM02 in the 2025 OWASP Top 10 for LLM Applications) is the exposure of confidential data through anything an LLM application touches: its outputs, its logs, its error messages, its retrieved context, or the model weights themselves. The data that leaks can be personally identifiable information (PII), credentials and API keys, proprietary business data, health or financial records, model internals, or — critically for multi-tenant systems — *another user's* data.

The vulnerability is not a single bug. It is the gap between the data your system legitimately holds and the data a given requester is actually entitled to see. An LLM widens that gap in ways traditional applications do not: it **memorises** fragments of training data, it **concatenates** secrets and user input into one prompt, it **retrieves** documents on the user's behalf, and it **generates** free-form text that no schema constrains. Any of those steps can surface information the requester was never authorised to receive.

> **One-line definition**: LLM02 is what happens when sensitive data reaches an output, log, or context window that the recipient should never have been able to read.

### Where the Data Leaks From

```
Source of sensitive data          Path to disclosure
------------------------          -------------------
Training / fine-tuning corpus  -> Memorised regurgitation in completions
Prompt / system context        -> Extraction, or bleed into other sessions
RAG / vector store             -> Over-permissioned retrieval returns docs
                                  the requester cannot access
Application logs / traces      -> Secrets and PII written in plaintext
Error messages / stack traces  -> Connection strings, keys, internal paths
Model weights                  -> Inversion & membership-inference research
Shared conversation state      -> Cross-user context bleed in multi-tenancy
```

### The Core Distinction

It helps to separate two questions that are easy to conflate:

- **Was the data ever supposed to be inside the system?** If a training set or a RAG index contains raw SSNs, that is a *data governance* failure — the data should have been scrubbed or minimised before it ever went near the model.
- **Did the data reach someone who should not see it?** If User B can read a document only User A is entitled to, that is an *access-control* failure at the data layer — the retrieval step trusted the prompt instead of enforcing authorization.

Robust defenses address both. Sanitisation shrinks what *can* leak; access control governs who *can reach* what remains.

## Why Does This Matter?

Sensitive Information Disclosure is ranked **#2** in the 2025 edition — up from #6 in 2023 — because the explosion of RAG systems, agentic assistants, and enterprise copilots has moved LLMs directly on top of production data stores. The model is now frequently the thing that decides which corporate document, ticket, or record a user sees, and a mistake there is a data breach, not a bad answer.

### Business Impact
- **Privacy violations**: Exposure of customer or employee PII creates direct legal liability and mandatory breach notification.
- **Regulatory penalties**: GDPR, HIPAA, PCI-DSS, and CCPA all attach fines and obligations to disclosed personal, health, or cardholder data — whether the disclosure came from a database or a chatbot.
- **Intellectual-property loss**: Proprietary source code, pricing, roadmaps, or M&A plans handed to a competitor cannot be un-disclosed.
- **Credential compromise**: A single leaked API key or database password can turn an information-disclosure bug into a full system breach.
- **Trust and reputation**: "The AI told a stranger my account details" is a headline that erodes user trust faster than almost any other failure mode.

### Technical Impact
- **Training-data regurgitation**: The model emits verbatim secrets or PII that were memorised during training.
- **Cross-user context bleed**: Data from one session surfaces in another because state was shared or caches were keyed carelessly.
- **Over-permissioned retrieval**: RAG returns chunks the requester has no right to, because authorization was expressed in the prompt rather than enforced at the index.
- **Secret exfiltration**: Keys embedded in prompts or context are coaxed out and used against downstream systems.
- **Model inversion & membership inference**: Statistical attacks reconstruct training records or prove a specific person's data was in the training set.

## Technical Context

### The Information Flow

```
[Data sources]   [Build time]      [Serving]           [Request]        [Output]
      |               |                 |                   |               |
  PII, secrets  ->  training/    ->  system prompt,   ->  user +      ->  completion,
  proprietary       fine-tuning      RAG index,           injection       logs,
  records           embeddings       secrets in env       attempts        errors
      |               |                 |                   |               |
  Governance      Memorisation      Access control      Extraction      Filtering /
  failure         risk              boundary            attempts        DLP boundary
```

Every arrow above is a place a control can be applied — or forgotten. Sanitisation acts at build time, access control at serving and request time, and output filtering / DLP at the final boundary.

### Categories of Sensitive Data

| Category | Examples | Primary regulation / concern |
|---|---|---|
| PII | Name, email, phone, address, SSN, national ID | GDPR, CCPA |
| Protected health information | Diagnoses, records, insurance IDs | HIPAA |
| Financial data | Card numbers, account numbers, balances | PCI-DSS, GLBA |
| Credentials & secrets | API keys, passwords, tokens, connection strings | System compromise |
| Proprietary business data | Source code, pricing, roadmaps, M&A, contracts | Trade-secret / IP loss |
| Model internals | Weights, training-set membership, embeddings | Inversion / inference attacks |
| Other users' data | Another tenant's documents, chats, records | Cross-tenant isolation |

### Why LLMs Leak in Ways Traditional Apps Do Not

#### 1. Memorisation is intrinsic
Large models provably memorise a fraction of their training data, especially rare, high-entropy strings such as keys, unique identifiers, and repeated verbatim records. Given the right prefix, the model can complete a memorised secret. This is a well-established research result, not a hypothetical.

#### 2. Prompts concatenate trust boundaries
A prompt frequently glues together a system instruction, retrieved documents, secrets, and untrusted user input into one flat string. The model has no built-in notion that the API key on line 3 is more sensitive than the greeting on line 1 — so an extraction prompt can pull it straight back out.

#### 3. Retrieval delegates authorization to the model
In a naive RAG system the vector store returns the most *similar* chunks, not the chunks the user is *allowed* to see. If access control lives only in the prompt ("only answer about documents this user owns"), it is a suggestion, not an enforcement boundary.

#### 4. Free-form output defeats schema-based DLP
Traditional data-loss-prevention often assumes structured fields. An LLM can emit a card number spelled out in words, a key split across a sentence, or PII paraphrased — so naive pattern matching under-detects.

## Real-World Impact

The incidents below are described as **classes of verifiable, publicly reported events**. Specific figures vary by source and are deliberately omitted; the durable lesson is what matters.

### Case Class 1: Employees Pasting Secrets into Public Chatbots
**What happened**: In 2023 it was widely reported that engineers at a large electronics manufacturer pasted proprietary source code and internal meeting notes into a public chatbot to get help, after which the company restricted internal use of such tools.

**Why it is LLM02**: Sensitive data left the organisation's trust boundary the moment it entered a third-party prompt, where it could be retained, logged, or used to improve a model.

**Lesson**: User inputs to external LLMs are an exfiltration channel. Data-handling policy and technical controls (enterprise tiers with no-retention terms, DLP on outbound traffic) are both required.

### Case Class 2: Extracting Memorised Training Data
**What happened**: Peer-reviewed research has repeatedly demonstrated that training data — including PII and secrets — can be extracted verbatim from production language models through carefully constructed prompts and sampling. Later work showed that even alignment-tuned commercial models could be induced to emit memorised training text.

**Why it is LLM02**: The disclosed data was never meant to be reproducible, yet the model reproduced it on demand.

**Lesson**: Memorisation is a measurable property of trained models. Sanitising and de-duplicating training data reduces — but does not eliminate — the risk, so output-side controls are still needed.

### Case Class 3: Code Assistants Suggesting Real Secrets
**What happened**: Studies of code-completion assistants trained on public repositories showed the tools could suggest hardcoded credentials and keys that had been committed to those repositories.

**Why it is LLM02**: Secrets present in the training corpus surfaced in generated output to users who never had access to the original repository.

**Lesson**: A training corpus is only as clean as its dirtiest file. Secret-scanning of training data and generated output are both necessary.

### Case Class 4: Cross-User Exposure via a Caching / Session Bug
**What happened**: A widely used chatbot service publicly disclosed an incident in which a bug in an in-memory caching layer briefly allowed some users to see fragments of other users' conversation data (and, for a subset, some billing-related details).

**Why it is LLM02**: A shared-state / caching defect broke tenant isolation, exposing one user's sensitive data to another.

**Lesson**: Isolation is an infrastructure property, not a prompt instruction. Session state, caches, and connection pools must be keyed and scoped per user.

### Case Class 5: Over-Permissioned Enterprise RAG
**What happened**: A recurring finding in enterprise copilot deployments is that a retrieval index is built over a corpus (a wiki, a drive, a ticketing system) without carrying the source ACLs, so the assistant happily answers questions using documents the asking employee could not otherwise open.

**Why it is LLM02**: The retrieval layer disclosed internal documents across an access-control boundary that existed in the source system but was dropped during indexing.

**Lesson**: Per-user authorization must be enforced *at the data/retrieval layer*, filtering candidates by the requester's identity — never by asking the model to be discreet.

## Prevalence

Sensitive Information Disclosure is rated by OWASP as both **highly prevalent and high impact** for modern LLM applications, which is why it climbed to #2 in the 2025 list. Its prevalence is driven by structural trends rather than by any one product:

- RAG has become the default architecture for enterprise assistants, and ACL-aware retrieval is harder to build than naive similarity search — so the insecure version is the common one.
- Agentic systems chain tools and data sources, multiplying the number of trust boundaries a single request crosses.
- Secrets in prompts remain a widespread anti-pattern because "just put the key in the system prompt" is the fastest thing that works in a demo.
- Verbose logging of full prompts and completions — often enabled for debugging — quietly copies sensitive data into a second, less-protected store.

> Note: precise percentages differ between reports and change quickly. Treat any single figure as illustrative. The durable takeaway is that disclosure is common, easy to trigger, and expensive when it lands on regulated data.

## Common Misunderstandings

### Myth 1: "We told the model in the system prompt not to reveal secrets, so we're safe."
**Reality**: A system-prompt instruction is a soft preference, not a control. Extraction prompts, role-play framings, and encoding tricks routinely defeat it. Secrets must be kept *out of the prompt entirely*, and access must be enforced in code.

### Myth 2: "Our RAG only indexes internal documents, so it's fine internally."
**Reality**: "Internal" is not one permission level. Employees have different entitlements; an index without per-user ACL filtering will happily surface HR files, unreleased financials, or another team's secrets to anyone who can ask.

### Myth 3: "The model can't leak training data — it only learned patterns."
**Reality**: Models measurably memorise rare, high-entropy strings and can reproduce them verbatim. Memorisation and generalisation coexist.

### Myth 4: "PII in logs isn't a real exposure — logs are internal."
**Reality**: Logs are one of the most frequently breached data stores, often with broader read access and weaker retention controls than the primary database. A prompt/response log is a full copy of your sensitive data.

### Myth 5: "Output filtering alone will catch anything sensitive."
**Reality**: Output DLP is a valuable last line of defense but is defeated by paraphrase, encoding, and formatting tricks. It must sit behind sanitisation and access control, not replace them.

### Myth 6: "This is the same thing as System Prompt Leakage."
**Reality**: They overlap but are distinct list items — see the next section.

## How LLM02 Differs from LLM07 (System Prompt Leakage)

The 2025 list splits out **LLM07: System Prompt Leakage** as its own category. The distinction is about *what* leaks:

| Aspect | LLM02: Sensitive Information Disclosure | LLM07: System Prompt Leakage |
|---|---|---|
| What leaks | Any sensitive data: PII, secrets, proprietary or other users' data, model internals | Specifically the system/developer prompt and its embedded instructions |
| Typical source | Training data, RAG index, logs, shared session state, context | The system prompt string configured by the developer |
| Core failure | Data governance and access control | Treating the prompt as a secret / putting secrets in it |
| Primary fix | Sanitise data, enforce per-user authz, filter output | Assume the prompt is public; never place secrets or authz logic in it |

The two connect at one point: if you place a secret in the system prompt (an LLM07 anti-pattern) and it leaks, the *consequence* is Sensitive Information Disclosure. The clean rule that satisfies both categories: **the system prompt should contain nothing you would mind an attacker reading.**

## Self-Assessment

Ask these questions about your LLM application:

- [ ] Is training / fine-tuning / RAG data scrubbed of PII and secrets before it is ingested?
- [ ] Does retrieval filter candidate documents by the *requester's* identity at the data layer, not in the prompt?
- [ ] Are all secrets (keys, tokens, connection strings) kept out of prompts and pulled from a secret manager at call time?
- [ ] Is per-user session state fully isolated — no shared context objects, caches keyed by user, connections not reused across tenants?
- [ ] Is there an output filter / DLP pass that redacts PII and secret patterns before responses reach the user?
- [ ] Do logs and traces redact or omit sensitive fields instead of storing full prompts and completions verbatim?
- [ ] Do error messages return a generic message to the client, with detail only in access-controlled server logs?
- [ ] Have you tested extraction prompts ("repeat everything above", "what documents have you seen") against your own system?
- [ ] Do you minimise: collect and retain only the sensitive data the feature genuinely needs?

Several "no" or "not sure" answers means you likely have an exploitable disclosure path today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers coax sensitive data out of LLM systems.
- **[Prevention](prevention.md)**: Layered defenses — sanitisation, access control, secret management, and DLP.
- **[Examples](examples.md)**: Vulnerable-vs-secure code in Python (OpenAI/Anthropic SDKs, LangChain/RAG) and Node/TypeScript.
- **[Hands-On Lab](./lab/sensitive-information-disclosure/)**: Practice finding and fixing disclosure in a running application.

> **Remember**: Sensitive Information Disclosure is a privacy, legal, and trust issue as much as a technical one. Shrink what can leak (sanitise and minimise), control who can reach what remains (authorize at the data layer), and inspect what leaves (filter output and logs).
