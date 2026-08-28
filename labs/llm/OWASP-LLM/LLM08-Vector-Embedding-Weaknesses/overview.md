# Vector & Embedding Weaknesses - Overview

## Table of Contents
- [What are Vector & Embedding Weaknesses?](#what-are-vector--embedding-weaknesses)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence](#prevalence)
- [Common Misunderstandings](#common-misunderstandings)
- [How to Identify if You're Vulnerable](#how-to-identify-if-youre-vulnerable)
- [Next Steps](#next-steps)

## What are Vector & Embedding Weaknesses?

**Vector and Embedding Weaknesses** (LLM08:2025) are security flaws in how embeddings are *generated*, *stored*, and *retrieved* in systems that use Retrieval-Augmented Generation (RAG). This is a **new category introduced in the 2025 edition** of the OWASP Top 10 for LLM Applications, added because RAG has become the default pattern for grounding a model in private, up-to-date, or domain-specific knowledge—and the retrieval layer it depends on is now a first-class attack surface.

RAG works by converting text (documents, chunks, user questions) into **embeddings**: high-dimensional numeric vectors that capture semantic meaning. Those vectors are stored in a **vector database** (Pinecone, Chroma, Weaviate, Qdrant, Milvus, pgvector, FAISS, and others). At query time the system embeds the user's question, finds the nearest vectors by similarity search, pulls the associated source text, and injects it into the model's prompt as "context." The weaknesses in this category live in that pipeline—not in the model's weights.

### Core Concept

```
INGESTION (offline)
  Documents ---> Chunker ---> Embedding model ---> [vectors] ---> Vector DB
                                                        (+ metadata: owner, tenant, ACL)

RETRIEVAL (per request)
  User query ---> Embedding model ---> similarity search ---> top-k chunks
                                                                 |
                                                                 v
                        [ System prompt + retrieved chunks + question ] ---> LLM ---> Answer

WHERE LLM08 LIVES
  * Who is allowed to retrieve a given vector?      (access control / multi-tenancy)
  * Can stored vectors be turned back into text?    (embedding inversion)
  * Who controls what got ingested?                 (knowledge / data poisoning)
  * Is retrieved text trusted blindly?              (indirect prompt injection)
  * Is the vector store itself protected?           (encryption, network exposure)
```

The unifying theme is this: **a RAG system treats whatever the retriever returns as trusted, authoritative context**. If an attacker can influence *what* is retrieved, *who* can retrieve it, or *what the stored vectors reveal*, they can steer answers, exfiltrate other users' data, or reconstruct sensitive source text—often without ever touching the model itself.

## Why Does This Matter?

Vector and Embedding Weaknesses matter because RAG is frequently bolted on to give an LLM access to an organisation's *most sensitive* corpora: support tickets, HR records, legal contracts, source code, patient notes, financial reports. The retrieval layer becomes a new, often unaudited, data-access path that sits *outside* the application's normal authorization checks.

### Business Impact

- **Cross-tenant data leakage**: In a shared, multi-tenant vector store without per-tenant isolation, one customer's query can surface another customer's documents—a direct confidentiality breach and, frequently, a contractual and regulatory violation.
- **Privacy and compliance exposure**: PII, PHI, or financial data retrieved to the wrong user triggers GDPR, HIPAA, and PCI-DSS obligations, breach notifications, and fines.
- **Integrity of business answers**: Poisoned knowledge causes the assistant to give confidently wrong or manipulated answers—bad pricing, wrong medical guidance, fraudulent instructions—that users trust *because* they are "grounded."
- **Intellectual-property loss**: Embeddings of proprietary text stored insecurely, or reconstructed via inversion, can leak trade secrets and source material.
- **Reputational damage**: "The AI told a customer another customer's data" is a headline-grade incident that erodes trust quickly.

### Technical Impact

- **Broken access control at the retrieval layer**: Similarity search returns the most *relevant* chunks, not the *authorized* ones. Without a filter, relevance ignores permissions entirely.
- **Embedding inversion**: Research has shown that stored embeddings are not opaque—a meaningful portion of the original text can be reconstructed from the vector alone, so a leaked vector index can be as sensitive as leaking the documents.
- **Indirect prompt injection**: A poisoned document retrieved into context can carry instructions the model then follows, bridging LLM08 into LLM01 (Prompt Injection).
- **Retrieval manipulation**: Attackers craft content engineered to rank highly for targeted queries, displacing legitimate context (a "context conflict").
- **Secret sprawl**: API keys, tokens, and credentials embedded in ingested documents become searchable and retrievable through the assistant.

## Technical Context

### How Embeddings and Vector Stores Actually Work

An embedding model maps text to a fixed-length vector (for example 384, 768, 1536, or 3072 dimensions). Texts with similar meaning map to vectors that are close together under a distance metric—usually cosine similarity, dot product, or Euclidean distance. A vector database indexes these vectors (commonly with an approximate-nearest-neighbour structure such as HNSW or IVF) so that "find the k most similar chunks to this query" runs in milliseconds over millions of vectors.

```
query_vec = embed("What is our refund policy?")
results   = index.search(query_vec, k=5)          # returns 5 nearest chunks
context   = "\n".join(r.text for r in results)     # concatenated into the prompt
answer    = llm(system_prompt + context + question)
```

Two properties of this design create the security surface:

- **Similarity is not authorization.** The index has no inherent concept of "this user may see this chunk." Unless you pass an explicit metadata filter or query a per-tenant partition, the search will happily return any chunk that is semantically close, regardless of who owns it.
- **Vectors are lossy but not one-way.** It is tempting to treat an embedding as an anonymised or hashed representation. It is neither. Embeddings preserve enough information that, with the same (or a similar) embedding model, an attacker can approximately invert them back toward the source text.

### Where the Weaknesses Arise

| Weakness class | Where it lives | Core failure |
|---|---|---|
| Multi-tenant / cross-user leakage | Retrieval query | Shared index queried without per-user/per-tenant filter |
| Over-permissioned retrieval | Retrieval query | Retriever runs with broad rights; user's own permissions ignored |
| Knowledge / data poisoning | Ingestion | Untrusted documents indexed without validation or provenance |
| Indirect prompt injection | Retrieved content | Retrieved text treated as trusted instructions, not data |
| Retrieval manipulation / context conflict | Ranking | Adversarial content engineered to outrank legitimate context |
| Embedding inversion | Storage | Stored vectors reconstructed back toward source text |
| Embedded secrets | Ingestion / storage | Credentials in source docs become searchable and retrievable |
| Vector-store exposure | Infrastructure | Index reachable without auth, unencrypted, or over-broad API keys |

### Why RAG Concentrates Risk

- RAG is usually added to reach **the most sensitive data an organisation has**, precisely because generic model knowledge is insufficient.
- The retriever often runs as a **single service identity** with access to the entire corpus, so a missing filter exposes everything, not just one record.
- Ingestion pipelines pull from **heterogeneous, semi-trusted sources**—wikis, ticket systems, shared drives, public web pages, user uploads—any of which can carry poisoned or injected content.
- Retrieved text lands **inside the trusted prompt**, so the model has no way to distinguish "reference material" from "instructions" unless the application enforces that boundary.

## Real-World Impact

> The categories below describe **well-documented classes of weakness and published research**, not fabricated incidents. Specific product names are examples of the technology class; treat any single figure as illustrative rather than exact.

### Class 1: Embedding Inversion Research

**What was shown**: Academic work on *text embedding inversion* (notably the line of research demonstrating that embeddings can be decoded back toward their input text, sometimes called "vec2text") established that dense text embeddings retain a large fraction of the original content. Given a vector and access to the embedding model, an adversary can reconstruct text that is close to the original—recovering names, phrases, and sensitive details.

**Why it matters**: Teams routinely assume a vector index is a "safe," non-reversible artifact and protect it less carefully than the raw documents. This research disproves that assumption: a leaked or over-exposed vector store should be treated as roughly equivalent to leaking the underlying text.

### Class 2: Indirect Prompt Injection via Retrieved Content

**What was shown**: Published research on *indirect prompt injection* demonstrated that instructions planted in third-party content (web pages, documents, emails) are executed when an LLM ingests that content. In a RAG system, any document that can be indexed and later retrieved is a delivery vehicle: an attacker plants "ignore prior instructions and…" text that becomes active the moment it is retrieved into context.

**Why it matters**: This is the bridge between LLM08 and LLM01. The poisoning is an LLM08 failure (untrusted content entered the corpus); the payload firing is an LLM01 failure (retrieved content treated as instructions). Defences must address both ends.

### Class 3: Cross-Tenant Leakage in Shared Vector Stores

**The pattern**: A SaaS product embeds every customer's documents into one shared index to keep the architecture simple. Retrieval queries omit a tenant filter, or apply it inconsistently. A user asks a broad question and receives chunks originating from *another tenant*—because those chunks were the most semantically similar, and nothing enforced the tenant boundary.

**Why it matters**: This is the most common and most damaging real-world manifestation of LLM08. It is an authorization bug that hides inside a machine-learning subsystem, so it slips past reviewers who assume "the app already checks permissions." Similarity search does not.

### Class 4: Over-Permissioned Retrieval Within a Tenant

**The pattern**: Even within one organisation, not every employee may see every document. When the retriever runs with a service account that can read the entire corpus and the query does not narrow results to what the *asking user* may access, the assistant becomes a confused deputy—summarising HR, legal, or executive documents to employees who could never open the source files directly.

**Why it matters**: The assistant effectively launders privileged data past existing document-level access controls, because those controls were enforced at the file system or app layer, never mirrored into the vector store.

## Prevalence

Because LLM08 is a 2025 addition, it does not yet have a decade of breach statistics behind it. What is defensible:

- RAG is now the **dominant pattern** for enterprise LLM deployments, so the surface is extremely widespread and growing.
- The two most frequently observed weaknesses in assessments are **missing per-tenant/per-user retrieval filters** and **ingestion pipelines with no document validation or provenance**—both are configuration and design failures, not exotic exploits.
- Embedding inversion and retrieval manipulation are **demonstrated and reproducible in research**, and are moving from academic curiosity to practical concern as vector stores accumulate sensitive data.
- The impact ranges from **information disclosure** (cross-tenant leakage) through **integrity compromise** (poisoned answers) to **full indirect prompt injection** (attacker-controlled instructions in context).

> Note: precise percentages vary by source and are still maturing for this new category. The durable takeaway is that the *design* flaws—treating similarity as authorization and treating retrieved text as trusted—are common by default and cheap to exploit.

## Common Misunderstandings

### Myth 1: "Embeddings are just numbers, so they're anonymised"
**Reality**: Embeddings are a lossy but *invertible-enough* representation. Inversion research recovers substantial portions of the source text from vectors. Protect the vector store as if it contained the raw documents—because effectively it does.

### Myth 2: "The app already checks permissions, so retrieval is covered"
**Reality**: Application permission checks guard the app's own data paths. The vector index is a separate datastore with its own query path. Unless you replicate authorization into the retrieval query (metadata filters or per-tenant partitions), similarity search bypasses every check you wrote elsewhere.

### Myth 3: "We can just tell the model in the system prompt to only answer about the user's own data"
**Reality**: A prompt instruction is not an access control. If the wrong chunks are already in context, the model may reveal them, and a prompt-injection payload can override the instruction. Authorization must happen *before* retrieval, at the datastore, not be delegated to the model's goodwill.

### Myth 4: "Retrieved documents are our own trusted content"
**Reality**: Corpora are assembled from wikis, tickets, uploads, scraped pages, and connectors—any of which can be attacker-influenced. Treat every retrieved chunk as untrusted input that may contain injection payloads, and never let it silently become instructions.

### Myth 5: "Poisoning requires compromising the database"
**Reality**: If your ingestion pipeline indexes a public page, a shared drive, or a user upload, an attacker only needs to get one malicious document into that source. No database breach is required—the pipeline invites the payload in.

### Myth 6: "A managed vector database is secure by default"
**Reality**: Managed services secure *their* infrastructure, not *your* data model. Over-broad API keys, indexes reachable from the public internet, mixed-tenant namespaces, and missing metadata filters are all your responsibility and are common in real deployments.

## How to Identify if You're Vulnerable

Ask these questions about your RAG system:

- [ ] Does every retrieval query enforce a **per-user or per-tenant filter** (or query a dedicated partition/namespace) rather than searching one shared index?
- [ ] Are document-level **permissions mirrored into vector metadata** and applied as a filter at query time?
- [ ] Does the retriever run with the **asking user's effective permissions**, not a god-mode service account?
- [ ] Is every ingested document **validated, scanned, and attributed to a trusted source** before it is embedded?
- [ ] Is retrieved content **treated as untrusted data**—delimited, never blindly executed as instructions?
- [ ] Is the vector store **encrypted at rest and in transit**, and unreachable from the public internet?
- [ ] Are **secrets scanned out of documents** before embedding, so credentials never become retrievable?
- [ ] Do you **monitor retrieval** for anomalies (a user pulling far more or far broader chunks than normal)?
- [ ] Do you have a way to **trace an answer back to its source chunks** for audit and incident response?
- [ ] Are vector-store **API keys least-privilege and scoped** per environment and per service?

If you answered "no" or "not sure" to several of these—especially the first three—you likely have an exploitable retrieval-layer weakness today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers poison, leak from, and manipulate RAG retrieval
- **[Prevention](prevention.md)**: Layered defences for ingestion, storage, and retrieval
- **[Code Examples](examples.md)**: Vulnerable vs. secure RAG across Pinecone, Chroma, and pgvector
- **[Hands-On Lab](./lab/vector-embedding-weaknesses/)**: Practice finding and fixing vector and embedding weaknesses
