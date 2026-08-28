# A10:2021 — Server-Side Request Forgery (SSRF): Overview

## Table of Contents

- [What is Server-Side Request Forgery?](#what-is-server-side-request-forgery)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)
- [A Note on Editions (2021 vs. 2025)](#a-note-on-editions-2021-vs-2025)
- [Self-Assessment](#self-assessment)

## What is Server-Side Request Forgery?

**Server-Side Request Forgery (SSRF)** is a vulnerability in which an attacker abuses server-side functionality to make the application issue HTTP (or other protocol) requests to a destination of the attacker's choosing. The application becomes a confused deputy: it holds a trusted position inside the network, and the attacker borrows that position to reach systems they could never contact directly.

The pattern appears wherever a web application takes a URL — or something that resolves to a URL, like a hostname, a filename, or an XML entity — and *fetches* it on the server. Think of a "preview this link" feature, an avatar uploader that accepts an image URL, a PDF generator that renders a web page, a webhook tester, or an "import from URL" button. The developer intends these to reach the public internet. The attacker supplies `http://169.254.169.254/` or `http://localhost:6379/` instead, and the server dutifully connects.

### The Core Idea

```
Intended use:
  Browser  --(url=https://example.com/logo.png)-->  Your Server  --fetch-->  example.com
                                                        (trusted, inside the firewall)

SSRF abuse:
  Browser  --(url=http://169.254.169.254/latest/meta-data/)-->  Your Server  --fetch-->  Cloud metadata
  Browser  --(url=http://10.0.0.15:8500/v1/kv/)------------->  Your Server  --fetch-->  Internal service
  Browser  --(url=file:///etc/passwd)----------------------->  Your Server  --read-->   Local file
```

The damage is not that the server made a request — it is *where* the request went and *what trust* the destination placed in the caller. Internal services frequently assume that anything able to reach them is already authorized. Cloud metadata endpoints hand credentials to any local process that asks. SSRF turns a public web form into a foothold on the internal network.

### What Makes a Feature SSRF-Prone

- **Link previews and unfurlers**: fetch a user-supplied URL to render a title, description, and thumbnail.
- **Image, PDF, and document fetchers**: "load image from URL", server-side thumbnailing, HTML-to-PDF rendering.
- **Import-from-URL**: import a feed, a spreadsheet, a profile, or a repository by URL.
- **Webhooks and integrations**: the app POSTs to a customer-supplied callback URL, or a "test webhook" button.
- **Document and SVG/format converters**: converters that follow references (SVG `<image>`, XML external entities, Markdown image links).
- **Proxy and "fetch on my behalf" features**: open proxies, CORS-avoidance shims, screenshot services, uptime monitors.

## Why Does This Matter?

SSRF entered the OWASP Top 10 as a **standalone category (A10) for the first time in the 2021 edition**. It did not rank highly on raw incidence data; it was added largely because the security community explicitly asked for it in the Top 10 survey. The reason is impact: an SSRF bug is often the single pivot that converts a minor-looking feature into a full cloud-account compromise.

### Business Impact

- **Cloud credential theft**: SSRF against a cloud instance metadata endpoint can leak temporary IAM credentials, leading to data-store access, resource creation, and lateral movement across the account.
- **Data breach**: reaching internal databases, caches, and admin panels that were never meant to be internet-reachable exposes customer records at scale.
- **Regulatory exposure**: breaches sourced from SSRF still trigger GDPR, HIPAA, and PCI-DSS obligations, fines, and breach-notification duties.
- **Reconnaissance and pivoting**: even "blind" SSRF gives an attacker a network map (open ports, live hosts) that shortens the path to a deeper compromise.
- **Reputation and trust**: an incident traced back to "our link-preview feature" is a costly story to explain to customers and regulators.

### Technical Impact

- **Access to internal-only services**: databases, message queues, service meshes, admin consoles, and CI systems bound to private addresses.
- **Cloud metadata access**: the link-local endpoint `169.254.169.254` that vends instance identity and, on older setups, credentials.
- **Internal port scanning**: timing and error differences reveal which internal hosts and ports are alive.
- **Local file disclosure**: via `file://` and other schemes when the fetching library allows them.
- **Protocol smuggling**: `gopher://` and CRLF injection can craft raw TCP payloads to speak Redis, Memcached, or SMTP.
- **Request forgery against third parties**: using your server's IP and reputation to attack others.

## Technical Context

### Why the Server's Position Is the Prize

A request from a user's browser originates on the public internet and is filtered by every firewall in its path. A request from *your server* originates inside your perimeter. Internal services routinely rely on network location as their only authentication ("if you can reach me, you must be one of us"). SSRF lets the attacker inherit the server's network identity and defeats that assumption in a single step.

### The Cloud Metadata Endpoint

Most cloud providers expose an instance metadata service (IMDS) at the link-local address `169.254.169.254`. It is reachable only from the instance itself, and it returns instance configuration and, critically, temporary role credentials. Because it is unauthenticated by design and answers any local caller, it is the highest-value SSRF target in cloud environments.

```
# The classic (v1) request pattern an attacker aims your server at:
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
  -> returns AccessKeyId / SecretAccessKey / Token as JSON
```

**IMDSv2** is a major mitigation for this class. It requires a session token obtained via a `PUT` request before any metadata read, and it lets operators set a low IP hop limit so the response cannot be routed away from the instance. A simple GET-only SSRF cannot complete the `PUT`-then-`GET` handshake, so enforcing IMDSv2 (and disabling IMDSv1) neutralizes the most common metadata-theft path. It is a defense-in-depth control, not a substitute for fixing the SSRF itself.

### Blind vs. Non-Blind SSRF

In **non-blind** SSRF the fetched response is reflected back to the attacker (rendered in the page, returned as JSON, embedded in a generated PDF). In **blind** SSRF the response is never shown; the attacker infers success from side channels — response timing, status-code differences, or an out-of-band callback to a server they control (DNS or HTTP interaction). Blind SSRF is still dangerous: it enables port scanning, service discovery, and, when combined with `gopher://`-style smuggling, one-way exploitation of internal services.

### Where the Fetch Happens

1. **Explicit URL parameters**: `?url=`, `?target=`, `?image=`, `?callback=`, `?webhook=`.
2. **File and document parsers**: XML external entities (XXE that pivots to SSRF), SVG that references remote images, PDFs that embed remote resources.
3. **Headers**: some apps fetch a URL taken from a header (for example a self-referential `Host` or a custom `X-Forwarded` value).
4. **Indirect resolution**: a hostname the app stores and later resolves, where the DNS answer changes between the check and the use (rebinding).

## Real-World Impact

The scenarios below are **incident classes** — recurring, well-documented patterns — rather than any specific named breach. They describe how SSRF plays out in the wild without inventing CVE numbers or statistics.

### Class 1: Cloud Metadata Credential Theft

A public-facing feature fetches user-supplied URLs. An attacker points it at the instance metadata endpoint, retrieves temporary IAM credentials attached to the instance role, and uses them from their own machine to read cloud storage and enumerate the account. This is the canonical high-severity SSRF outcome and the reason IMDSv2 exists. Servers still running IMDSv1 with an over-privileged instance role are the worst case.

### Class 2: Internal Service Takeover via Protocol Smuggling

An attacker uses `gopher://` or CRLF injection to make the server send crafted bytes to an internal, unauthenticated service — for example a Redis instance bound to localhost. Redis commands written to disk can achieve code execution, turning a blind SSRF into a shell on an internal host.

### Class 3: Internal Recon and Port Scanning

Even without reading responses, an attacker submits many internal URLs (`http://10.0.0.1:22`, `:80`, `:6379`, `:9200`…) and watches timing and error differences to map which hosts and ports are alive. The result is a reconnaissance map used to plan the next stage.

### Class 4: SSRF via File Parsers (XXE → SSRF)

A document or image importer parses XML/SVG and resolves external entities. The attacker embeds an entity pointing at an internal URL, and the parser fetches it — SSRF reached without any obvious "url=" parameter. This class is common in office-document, SVG, and feed-import features.

### Class 5: Webhook and Callback Abuse

An integration lets customers register a callback URL. The attacker registers an internal address; when the app "tests" or delivers to the webhook, it hits internal infrastructure. Because the destination is customer-controlled by design, these features need explicit egress controls rather than trust.

## Prevalence and Statistics

Rather than cite precise figures, here is the accurate qualitative picture from the OWASP Top 10 2021 methodology:

- SSRF is **A10:2021**, a **new standalone category** in the 2021 edition.
- It had a **relatively low measured incidence rate** in the contributed data compared with other categories, but an **above-average exploit and impact profile**.
- It was included largely on the strength of the **community survey**, where practitioners ranked it as an important, under-represented risk.
- Its rise tracks the shift to **cloud and microservice architectures**, where a single fetch can reach metadata endpoints and internal service meshes.

### Relevant CWE Mappings

- **CWE-918**: Server-Side Request Forgery (SSRF) — the primary mapping.
- **CWE-611**: Improper Restriction of XML External Entity Reference (a common SSRF entry point).
- **CWE-601**: URL Redirection to Untrusted Site (redirect handling that enables bypasses).
- **CWE-441**: Unintended Proxy or Intermediary ("confused deputy").

## Common Misunderstandings

### Myth 1: "We block `localhost` and `127.0.0.1`, so we're safe."

**Reality**: Loopback has countless representations — `127.0.0.1`, `127.1`, `0.0.0.0`, `[::1]`, decimal `2130706433`, hex `0x7f000001`, and DNS names that resolve to loopback. A string blocklist is trivially bypassed. You must resolve the hostname and check the *resolved IP* against private/reserved ranges.

### Myth 2: "The user only supplies a hostname, not an IP, so it's controlled."

**Reality**: Attacker-controlled DNS can point any hostname at an internal IP, and **DNS rebinding** can return a public IP during your validation check and a private IP moments later when the fetch happens. Validating the name is not enough; you must pin and re-check the address actually connected to.

### Myth 3: "It's blind — the attacker can't read anything, so it's low risk."

**Reality**: Blind SSRF still enables port scanning, service discovery, and one-way exploitation via protocol smuggling (for example writing Redis commands). Out-of-band channels confirm success even when nothing is reflected.

### Myth 4: "We validate the URL before fetching, so redirects don't matter."

**Reality**: If your HTTP client follows redirects, a validated public URL can `302` to `http://169.254.169.254/`. Every hop must be re-validated, or redirect-following must be disabled entirely.

### Myth 5: "A blocklist of bad IP ranges is enough."

**Reality**: Blocklists are fragile — they miss encodings, IPv6 mappings, and new ranges. An **allowlist** of permitted schemes, hosts, and ports is the durable design. Deny by default; permit only what the feature genuinely needs.

### Myth 6: "IMDSv2 fixes SSRF."

**Reality**: IMDSv2 defends the metadata endpoint specifically; it does nothing for internal databases, admin panels, or file reads. It is one essential layer, not the fix. You still must correct the SSRF and segment the network.

## A Note on Editions (2021 vs. 2025)

> SSRF was introduced as its own category, **A10:2021 — Server-Side Request Forgery**, in the 2021 Top 10. In the subsequent 2025 revision, SSRF was **merged into A01 — Broken Access Control** rather than kept as a separate entry, reflecting the view that SSRF is fundamentally an access-control failure (the server accesses a resource the caller should not be able to reach). This lesson intentionally uses the **2021 standalone framing** because that is how most training material, tooling, and certifications still refer to it — but be aware of the edition change when you compare against newer OWASP documents.

## Self-Assessment

Ask these questions about every feature that fetches a URL, a file, or a document reference:

- [ ] Does any feature fetch a user-supplied URL, hostname, or file reference on the server side?
- [ ] Do we validate against an **allowlist** of schemes/hosts/ports rather than a blocklist?
- [ ] Do we resolve DNS and check the **resolved IP** against private/loopback/link-local/reserved ranges — not just the hostname string?
- [ ] Do we defend against **DNS rebinding** by pinning and re-validating the connected address?
- [ ] Are dangerous schemes (`file://`, `gopher://`, `dict://`, `ftp://`) disabled?
- [ ] Do we **refuse to follow redirects**, or re-validate every hop?
- [ ] Is **IMDSv2** enforced and IMDSv1 disabled on all cloud instances?
- [ ] Is outbound (egress) traffic filtered so the fetcher cannot reach internal ranges or metadata?
- [ ] Do we avoid reflecting raw fetched responses (bodies, headers, error text) back to the user?
- [ ] Do our XML/SVG/document parsers have external-entity resolution disabled?

Several "no" or "not sure" answers mean you likely have exploitable SSRF surface today.

## Key Takeaways

1. **SSRF weaponizes the server's trusted network position** — the destination and its trust are the real damage.
2. **Allowlist, don't blocklist** — permit only the schemes, hosts, and ports a feature actually needs.
3. **Validate the resolved IP, not the string**, and defend against DNS rebinding.
4. **Do not follow redirects blindly**, and disable unused URL schemes.
5. **Enforce IMDSv2 and segment egress** as defense in depth — never as your only control.

## Next Steps

- **[Attack Vectors](./attack-vectors.md)**: How attackers discover and exploit SSRF, with concrete payloads.
- **[Prevention](./prevention.md)**: Layered defenses, safe fetchers, and real configuration.
- **[Examples](./examples.md)**: Vulnerable vs. secure code in Python, Node.js, PHP, and Java.
- **[Lab](./lab/ssrf-simulation-lab/)**: Practice SSRF safely in an isolated simulation.

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
