# LLM05:2025 Improper Output Handling - Prevention

## Table of Contents
- [The Governing Principle: Zero Trust for Output](#the-governing-principle-zero-trust-for-output)
- [Defense in Depth: The Layers](#defense-in-depth-the-layers)
- [Layer 1: Context-Aware Output Encoding](#layer-1-context-aware-output-encoding)
- [Layer 2: Parameterize Every Query](#layer-2-parameterize-every-query)
- [Layer 3: Never Execute Output as Code](#layer-3-never-execute-output-as-code)
- [Layer 4: Sanitize Markdown & HTML](#layer-4-sanitize-markdown--html)
- [Layer 5: Content-Security-Policy](#layer-5-content-security-policy)
- [Layer 6: Schema-Validate Structured Output](#layer-6-schema-validate-structured-output)
- [Layer 7: Allowlist URLs & Constrain Egress (SSRF)](#layer-7-allowlist-urls--constrain-egress-ssrf)
- [Layer 8: Safe Filesystem Handling](#layer-8-safe-filesystem-handling)
- [Layer 9: Sandbox & Least-Privilege Agent Tools](#layer-9-sandbox--least-privilege-agent-tools)
- [Layer 10: Monitoring, Logging & Rate Limiting](#layer-10-monitoring-logging--rate-limiting)
- [Implementation Checklist](#implementation-checklist)
- [Next Steps](#next-steps)

## The Governing Principle: Zero Trust for Output

Every defense in this page is an application of one rule: **the model is just another untrusted client, and its output is untrusted input to whatever consumes it.** Adopt a zero-trust posture between the model and every downstream component. Where a classic application would validate, encode, parameterize, or sandbox user input, an LLM application must apply the identical control to model output. OWASP explicitly points to the **ASVS** (Application Security Verification Standard) for the input-validation and output-encoding requirements — the same standard, now applied one boundary later.

> **Encoding is contextual, not universal.** There is no single "sanitize()" that makes output safe everywhere. Output must be encoded for its *exact* sink: HTML body, HTML attribute, JavaScript, URL, CSS, SQL, shell, or path. The same string can be safe in one context and an exploit in another.

## Defense in Depth: The Layers

| Layer | Defends against | Core control |
| --- | --- | --- |
| 1. Output encoding | XSS, HTML injection | Context-aware encoders; safe DOM APIs |
| 2. Parameterized queries | SQL/NoSQL injection | Bound parameters only |
| 3. No code execution | RCE via eval/exec | Remove eval; sandbox if unavoidable |
| 4. Markdown/HTML sanitization | XSS, exfiltration | Allowlist sanitizer |
| 5. Content-Security-Policy | XSS, data exfiltration | Restrictive CSP, no inline script |
| 6. Schema validation | Malformed/unexpected output | Strict schema, enums, length caps |
| 7. URL allowlist / egress | SSRF, exfiltration | Scheme+host allowlist, blocked ranges |
| 8. Safe filesystem | Path traversal | Canonicalize + containment check |
| 9. Tool sandboxing | Agent abuse, escalation | Least privilege, allowlist, HITL |
| 10. Monitoring | All of the above | Logging, anomaly alerts, rate limits |

## Layer 1: Context-Aware Output Encoding

Encode at the point of use, for the context of use. Prefer framework mechanisms that encode by default and safe DOM APIs over raw HTML injection.

**Front end — use text sinks, never innerHTML**
```javascript
// SAFE: textContent never parses HTML
document.getElementById("reply").textContent = answer;

// If you must produce nodes, build them explicitly:
const el = document.createElement("p");
el.textContent = answer;              // still text, still safe
container.replaceChildren(el);
```

**Server-side templates — keep auto-escaping on**
```python
# Jinja2 autoescape is ON for .html; pass output as DATA, not template source
return render_template("reply.html", answer=model_answer)   # {{ answer }} auto-escaped
# NEVER: render_template_string("... " + model_answer + " ...")
```

**React / modern frameworks**
```jsx
// SAFE: JSX escapes by default
<div>{answer}</div>

// DANGEROUS: only with a sanitizer (see Layer 4), never with raw output
// <div dangerouslySetInnerHTML={{ __html: answer }} />
```

When output must land in a non-HTML context, use the matching encoder: JavaScript string encoding for a script context, URL/percent-encoding for a query parameter, CSS encoding for a style value. A general-purpose library (for example OWASP Java Encoder, or `escape-html` / dedicated encoders in Node) provides the correct routine per context.

## Layer 2: Parameterize Every Query

Model output that becomes a query value must be **bound**, never concatenated. This neutralizes SQL and NoSQL injection completely, because the value can never change the query's structure.

```python
# SAFE (Python, parameterized)
cur.execute("SELECT * FROM products WHERE name = %s", (model_value,))
```
```javascript
// SAFE (Node, parameterized)
await pool.query("SELECT * FROM products WHERE name = $1", [modelValue]);
```

For NoSQL, treat operators as untrusted: never let model output supply keys like `$where` or `$ne`. Cast the value to the expected type and build the filter object yourself:

```javascript
// SAFE: value forced to a string, structure fixed by you
const filter = { name: String(modelValue) };
await collection.find(filter);
```

## Layer 3: Never Execute Output as Code

The strongest control is elimination: do not pass output to `eval`, `exec`, `new Function`, `os.system`, unsafe deserializers, or a template compiler. Replace "let the model compute" with a real parser or a fixed operation set.

```python
# INSTEAD OF eval(model_expr) for arithmetic, use a safe evaluator:
import ast, operator
OPS = {ast.Add: operator.add, ast.Sub: operator.sub,
       ast.Mult: operator.mul, ast.Div: operator.truediv}

def safe_eval(expr: str) -> float:
    def ev(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in OPS:
            return OPS[type(node.op)](ev(node.left), ev(node.right))
        raise ValueError("unsupported expression")
    return ev(ast.parse(expr, mode="eval").body)
```

If arbitrary code execution is a genuine product requirement (a "code interpreter" feature), run it in a **hardened sandbox**: a locked-down container or microVM (gVisor, Firecracker, or an isolated worker) with no network, a read-only or ephemeral filesystem, dropped capabilities, strict CPU/memory/time limits, and a non-root user. The sandbox — not string filtering — is the security boundary.

## Layer 4: Sanitize Markdown & HTML

If you must render rich text, sanitize the rendered HTML with a battle-tested allowlist sanitizer *after* Markdown conversion, and disable raw-HTML passthrough in the Markdown renderer.

```typescript
// Node/TypeScript: markdown -> sanitized HTML
import { marked } from "marked";
import createDOMPurify from "dompurify";
import { JSDOM } from "jsdom";

const DOMPurify = createDOMPurify(new JSDOM("").window);

function renderSafe(md: string): string {
  const rawHtml = marked.parse(md, { async: false }) as string;
  return DOMPurify.sanitize(rawHtml, {
    ALLOWED_TAGS: ["p", "b", "i", "em", "strong", "ul", "ol", "li",
                   "code", "pre", "blockquote", "a", "h1", "h2", "h3"],
    ALLOWED_ATTR: ["href"],
    ALLOWED_URI_REGEXP: /^https?:\/\//i,   // no javascript:, data:, etc.
  });
}
```

```python
# Python: bleach allowlist after markdown
import bleach, markdown
html = markdown.markdown(model_md)
clean = bleach.clean(
    html,
    tags=["p","b","i","em","strong","ul","ol","li","code","pre","blockquote","a","h1","h2","h3"],
    attributes={"a": ["href"]},
    protocols=["http", "https"],   # drop javascript:, data:
    strip=True,
)
```

To stop Markdown-image exfiltration specifically, either drop `<img>` entirely or restrict image `src` to an allowlist of hosts you control, and never auto-load images to arbitrary origins.

## Layer 5: Content-Security-Policy

A strict CSP is the backstop that turns "an XSS payload slipped through" into "the browser refused to run it," and blocks silent exfiltration by constraining where the page may send requests.

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{RANDOM}';   # no 'unsafe-inline', no wildcard
  style-src  'self';
  img-src    'self' data:;              # tighten further to drop exfil pixels
  connect-src 'self';                   # blocks fetch() to attacker hosts
  frame-ancestors 'none';
  base-uri 'self';
  object-src 'none'
```

Pair the CSP with `X-Content-Type-Options: nosniff` and correct `Content-Type` headers so a text answer is never sniffed as HTML. Deploy CSP in `report-only` mode first to catch violations without breaking the app, then enforce.

## Layer 6: Schema-Validate Structured Output

Ask the model for structured output, then validate it against a strict schema before use. Reject — do not "fix" — anything that does not conform. Constrain types, lengths, formats, and use **enums/allowlists** wherever the value set is known.

```typescript
// Node/TypeScript with zod
import { z } from "zod";

const Action = z.object({
  intent: z.enum(["search", "summarize", "translate"]),   // allowlist
  query:  z.string().max(200),
  lang:   z.string().regex(/^[a-z]{2}$/).optional(),
}).strict();                                               // no extra keys

const parsed = Action.safeParse(JSON.parse(modelOutput));
if (!parsed.success) throw new Error("model output failed schema validation");
// use parsed.data — every field is now typed and bounded
```

```python
# Python with pydantic
from pydantic import BaseModel, constr
from typing import Literal

class Action(BaseModel, extra="forbid"):
    intent: Literal["search", "summarize", "translate"]
    query: constr(max_length=200)

action = Action.model_validate_json(model_output)   # raises on nonconformance
```

Schema validation constrains *shape and range*; it does not make values safe for a sink. A validated `query` string still needs Layer 1 encoding or Layer 2 parameterization at the point of use.

## Layer 7: Allowlist URLs & Constrain Egress (SSRF)

Never fetch a model-supplied URL directly. Parse it, enforce a scheme + host allowlist, resolve DNS and reject private/link-local ranges, and route outbound traffic through an egress proxy that enforces the same policy.

```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.trusted.example", "cdn.trusted.example"}

def safe_fetch_url(url: str) -> str:
    u = urlparse(url)
    if u.scheme not in ("https",):                 # scheme allowlist
        raise ValueError("scheme not allowed")
    if u.hostname not in ALLOWED_HOSTS:            # host allowlist
        raise ValueError("host not allowed")
    ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise ValueError("target resolves to a blocked range")   # SSRF guard
    return url
```

Also block the cloud metadata address (`169.254.169.254`) at the network layer, disable redirects (or re-validate each hop), and give the fetching service an egress firewall that only permits the allowlisted destinations.

## Layer 8: Safe Filesystem Handling

When output influences a filename, strip it to a safe basename, canonicalize the full path, and verify it stays inside the intended directory.

```python
import os

BASE = "/srv/exports"

def safe_path(name: str) -> str:
    name = os.path.basename(name)                  # drop any directory parts
    if not name or name.startswith(".") or "/" in name or "\\" in name:
        raise ValueError("invalid filename")
    full = os.path.realpath(os.path.join(BASE, name))
    if os.path.commonpath([full, os.path.realpath(BASE)]) != os.path.realpath(BASE):
        raise ValueError("path escapes base directory")   # traversal guard
    return full
```

Prefer generating your own filename (a UUID) and storing the model's suggested name only as metadata. That removes the sink entirely.

## Layer 9: Sandbox & Least-Privilege Agent Tools

In agentic systems, output-handling and excessive-agency defenses merge. Constrain what an output *can cause*:
- **Strict argument schemas** (Layer 6) for every tool call — no free-form command strings.
- **Action allowlist**: the router accepts only a fixed set of tool names; unknown tools are rejected, not guessed.
- **Least privilege per tool**: each tool holds only the credentials and scope it needs; the "shell" tool, if it exists, is sandboxed and network-isolated.
- **Human-in-the-loop** for high-impact or irreversible actions (delete, transfer funds, send external email, deploy).
- **Deterministic guards downstream of the model**: enforce business limits (max transfer amount, allowed recipients) in code, not in the prompt.

```python
ALLOWED_TOOLS = {"search_docs", "get_weather"}   # powerful tools NOT here

def dispatch(tool: str, args: dict):
    if tool not in ALLOWED_TOOLS:
        raise PermissionError(f"tool '{tool}' is not permitted")
    validated = SCHEMAS[tool].model_validate(args)   # per-tool schema
    return TOOLS[tool](validated)                    # least-privilege impl
```

## Layer 10: Monitoring, Logging & Rate Limiting

- **Log output that triggers side effects** (queries run, tools called, URLs fetched, files written) with enough context to trace an incident.
- **Alert on dangerous signatures** in output bound for a sink: HTML tags, `<script>`, SQL keywords, shell metacharacters, non-allowlisted hosts, private IPs.
- **Rate-limit and anomaly-detect** so a burst of tool calls or fetches from one session is throttled and flagged.
- **CSP report endpoint** to collect attempted violations from real browsers.
- **Egress monitoring** to catch exfiltration attempts that slip past the render layer.

## Implementation Checklist
- [ ] Model output is treated as untrusted input at every downstream boundary.
- [ ] Output is context-encoded for its exact sink (HTML/JS/URL/CSS/SQL/shell).
- [ ] Front end uses `textContent`/framework escaping, never raw `innerHTML`.
- [ ] All DB access is parameterized; no string-built queries.
- [ ] No output reaches `eval`/`exec`/`os.system`/deserializers; code execution (if any) is sandboxed.
- [ ] Rendered Markdown/HTML passes through an allowlist sanitizer; raw HTML passthrough is off.
- [ ] A strict CSP (nonce-based, no `unsafe-inline`) is enforced, with `nosniff`.
- [ ] Structured output is validated against a strict schema with enums and length caps.
- [ ] Model-supplied URLs pass a scheme+host allowlist and private-range block before any fetch.
- [ ] Filenames are canonicalized and contained within a base directory.
- [ ] Agent tools use argument schemas, an action allowlist, least privilege, and human approval for high-impact actions.
- [ ] Side-effecting output is logged, monitored, rate-limited, and anomaly-alerted.

## Next Steps
- **[Examples](examples.html)**: full vulnerable-vs-secure implementations of these controls.
- **[Attack Vectors](attack-vectors.html)**: the exploits each layer neutralizes.
- **[Overview](overview.html)**: the concept and why it matters.
- **[Hands-On Lab](./lab/improper-output-handling/)**: apply these defenses to a vulnerable app.
