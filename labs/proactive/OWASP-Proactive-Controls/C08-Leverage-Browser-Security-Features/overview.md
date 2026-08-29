# C8: Leverage Browser Security Features - Overview

## Table of Contents
- [What is this control?](#what-is-this-control)
- [Why This Control Matters](#why-this-matters)
- [The Browser Security Toolbox](#the-toolbox)
- [A Defense-in-Depth Layer, Not a Replacement](#defense-in-depth)
- [Real-World Incident Classes](#incident-classes)
- [Common Misunderstandings](#common-misunderstandings)

## What is this control?

**Leverage Browser Security Features** is the proactive control of using the security mechanisms that modern browsers already provide as a deliberate layer of defense. Every current browser ships with an enforcement engine for **response headers, cookie attributes, and HTML/HTTP directives** that constrain what a page is allowed to do—which scripts may run, which origins it may talk to, whether it may be framed, and how it may be transported. This control is the discipline of *turning those mechanisms on and configuring them correctly*, so the browser enforces your security policy on the client.

The key insight is that the browser is a security control you have already paid for. It is the one component that sits between your application and the attacker's payload, and it will enforce a policy for you—but only the policy you actually declare. A response with no `Content-Security-Policy`, no `Strict-Transport-Security`, and cookies without `HttpOnly` tells the browser to enforce nothing. This control makes those declarations explicit, so a class of client-side attacks is blocked *even when a bug slips through your server-side code*.

### Core Concept

```
No policy declared (browser enforces nothing):
  Scripts      -> any inline or injected <script> executes
  Transport    -> http:// accepted; a downgrade/MITM is possible
  Cookies      -> readable by JavaScript, sent cross-site
  Framing      -> page can be framed by any site (clickjacking)
  Third-party  -> a tampered CDN script runs with full trust
  Cross-origin -> any site may read credentialed responses

Browser features leveraged (browser enforces your policy):
  Scripts      -> CSP nonce/hash + strict-dynamic; only vetted code runs
  Transport    -> HSTS forces HTTPS; downgrade is refused
  Cookies      -> HttpOnly + Secure + SameSite; not script-readable, not cross-site
  Framing      -> frame-ancestors 'none'; page cannot be framed
  Third-party  -> SRI hash; a modified CDN script is refused
  Cross-origin -> explicit CORS allow-list; COOP/COEP isolate the context
```

### Where this control sits

C8 is squarely a **client-side defensive layer**. It supports and reinforces the anti-XSS work of input validation and output encoding (C3), the transport protections of cryptography (C2), and secure defaults (C5)—but it operates in a different place: inside the user's browser, at the moment a response is rendered. That location is exactly why it is valuable. It catches the failure that made it past everything on the server.

## Why This Control Matters

### Business Impact of Getting It Right

- **A second line that actually holds**: when an output-encoding bug lets an XSS payload reach the page, a strict CSP can stop the injected script from executing at all—turning a critical account-takeover bug into a non-event.
- **Cheap, broad coverage**: most of these features are a handful of response headers and cookie flags applied centrally. A few lines of configuration protect every page and every user.
- **Session protection**: `HttpOnly` cookies keep session tokens out of reach of injected JavaScript, and `SameSite` blunts cross-site request forgery—directly protecting the credentials attackers most want.
- **Regulatory and audit alignment**: HSTS, secure cookies, and a content security policy are routinely expected by security assessments, PCI-DSS reviews, and enterprise customer questionnaires.

### Technical Impact

- **XSS blast radius shrinks**: a strict, nonce-based CSP blocks inline and injected scripts, and `connect-src` limits where a script could exfiltrate data even if one runs.
- **Transport downgrade is closed**: HSTS removes the plaintext window that SSL-stripping and MITM attacks rely on.
- **Clickjacking is denied**: `frame-ancestors` stops UI-redress attacks that trick users into clicking invisible controls.
- **Supply-chain tampering is caught**: Subresource Integrity refuses a third-party script whose hash no longer matches, containing a compromised CDN.
- **Cross-origin leaks are contained**: COOP/COEP/CORP and sensible CORS reduce the surface for cross-site information leaks.

## The Browser Security Toolbox

The control is made up of a set of complementary mechanisms. Each is declared by the server (or in markup) and enforced by the browser.

| Mechanism | What to set | What it defends against |
|-----------|-------------|-------------------------|
| Content-Security-Policy | Nonce/hash + `strict-dynamic`; restrict `script-src`, `connect-src`, `object-src 'none'`, `base-uri 'none'` | XSS execution and data exfiltration |
| HTTP Strict Transport Security | `max-age`, `includeSubDomains`, `preload` | Protocol downgrade, SSL-strip, MITM |
| Secure cookie attributes | `HttpOnly`, `Secure`, `SameSite`, `__Host-` prefix | Session theft via XSS, CSRF |
| X-Content-Type-Options | `nosniff` | MIME-sniffing to executable content |
| Frame controls | CSP `frame-ancestors` (and legacy `X-Frame-Options`) | Clickjacking / UI redress |
| Referrer-Policy | `no-referrer` or `strict-origin-when-cross-origin` | Leaking URLs, tokens, internal paths |
| Permissions-Policy | Deny unused features (camera, geolocation, USB…) | Abuse of powerful browser APIs |
| Subresource Integrity | `integrity` + `crossorigin` on third-party tags | Tampered CDN / supply-chain scripts |
| CORS | Explicit origin allow-list (never `*` with credentials) | Cross-origin data theft |
| Cross-origin isolation | COOP, COEP, CORP | Cross-site leaks (XS-Leaks), side channels |
| iframe `sandbox` | Grant only the capabilities an embed needs | Untrusted embedded content |
| Trusted Types | `require-trusted-types-for 'script'` | DOM-based XSS via dangerous sinks |

## A Defense-in-Depth Layer, Not a Replacement

> **Read this before anything else on the page.** Browser security features are a *defense-in-depth layer for the client*. They are powerful precisely because they catch what your server-side controls missed—but they do **not** replace those controls. Output encoding and input validation (C3), parameterized queries, authentication and access control, and server-side transport security are still required.

Two things follow from this. First, **never treat a header as a substitute for fixing the bug**. A CSP that blocks an injected script is a safety net, not a reason to leave the injection in place—policies can be misconfigured, bypassed with a clever gadget, or absent on one forgotten response. Second, **layer the features together**. A strict CSP plus `HttpOnly` cookies plus `frame-ancestors` plus HSTS each closes a different door; the value is in the combination, so that a single failure elsewhere does not become a breach.

The mental model is a series of independent barriers. The server-side control is the first barrier; the browser feature is the second. Attackers must defeat every barrier, while defenders only need one to hold.

## Real-World Incident Classes

These are recurring *classes* of client-side incident that browser security features are designed to blunt. They are described as patterns, not as specific vulnerabilities or vendors.

### Class 1: Stored/reflected XSS leading to account takeover

An application reflects attacker-controlled input into a page without adequate encoding, and injected JavaScript reads the session cookie or acts as the victim. Where session cookies carry `HttpOnly`, the token is out of the script's reach; where a strict nonce-based CSP is enforced, the injected script does not execute in the first place. Both are browser-enforced backstops behind the primary fix (correct output encoding).

### Class 2: Magecart-style third-party script tampering

Attackers compromise a third-party or CDN-hosted script (payment widgets, analytics, tag managers) and inject skimming code that harvests form data from every site that loads it. Subresource Integrity refuses a script whose content no longer matches its expected hash, and a tight CSP `connect-src` limits where any running script can send stolen data.

### Class 3: Clickjacking / UI-redress

A malicious page frames a legitimate application and overlays deceptive UI so the victim's clicks are delivered to hidden controls (for example, confirming a transfer or granting a permission). `frame-ancestors 'none'` (or a strict allow-list) prevents the application from being framed at all.

### Class 4: SSL-strip and downgrade on hostile networks

On an untrusted network, an attacker intercepts the first plaintext request and keeps the victim on `http://`, reading or modifying traffic. HSTS instructs the browser to refuse plaintext for the domain, and preloading closes even the very first visit.

### Class 5: Cross-site request forgery

A malicious site causes the victim's browser to send an authenticated state-changing request to an application where the victim is logged in. `SameSite` cookies stop the credential from riding along on cross-site requests, complementing server-side anti-CSRF tokens.

## Common Misunderstandings

### Myth 1: "A CSP means we don't need to fix XSS"

**Reality**: CSP is a mitigation, not a cure. Policies are regularly bypassed through misconfiguration, unsafe directives (`unsafe-inline`), JSONP endpoints, or DOM gadgets. Fix the injection *and* keep the CSP as a backstop.

### Myth 2: "Security headers are all-or-nothing and hard"

**Reality**: most are a single header or cookie flag applied centrally in middleware or at the edge. You can adopt them incrementally—start with `X-Content-Type-Options`, secure cookies, and HSTS, then work up to a strict CSP with report-only mode.

### Myth 3: "`X-Frame-Options` is enough for framing"

**Reality**: `X-Frame-Options` is legacy and cannot express an allow-list of multiple origins. CSP `frame-ancestors` supersedes it; set both for old-browser coverage, but treat `frame-ancestors` as the real control.

### Myth 4: "`Access-Control-Allow-Origin: *` is convenient and fine"

**Reality**: a wildcard cannot be combined with credentials, so vulnerable servers reflect the request `Origin` plus `Allow-Credentials: true`—which lets any site read authenticated responses. CORS is an *allow-list*, not an *allow-all*.

### Myth 5: "These headers work on any response, so placement doesn't matter"

**Reality**: headers must be present on *every* response, including errors, redirects, and API responses. HSTS only applies over HTTPS; `Set-Cookie` flags only protect cookies that carry them. A single unprotected response can reopen the hole.

## How This Control Relates to Server-Side Controls

| Aspect | Server-side control (e.g. C3 encoding) | Leverage Browser Security Features (C8) |
|--------|----------------------------------------|-----------------------------------------|
| **Where it runs** | On the server, before the response is sent | In the browser, as the response is rendered |
| **Role** | Primary fix—prevents the flaw | Backstop—contains the flaw if it slips through |
| **Failure mode** | A missed encoding path becomes injection | A missing/loose header removes the safety net |
| **Relationship** | Complementary layers—you need both; neither replaces the other. | |

## Key Takeaways

1. **The browser is a security control you already own**—but it only enforces the policy you declare.
2. **It is a client-side defense-in-depth layer**—it supports anti-XSS, anti-clickjacking, and transport security, and does not replace server-side controls.
3. **Combine the mechanisms**—CSP, HSTS, secure cookies, frame-ancestors, SRI, and CORS each close a different door.
4. **Apply on every response**—a single unprotected error page or redirect can undo the policy.
5. **Prefer strict, modern forms**—nonce/hash CSP over `unsafe-inline`, `frame-ancestors` over `X-Frame-Options`, allow-list CORS over wildcards.

## Self-Assessment Checklist

- [ ] Is a `Content-Security-Policy` set, using nonces/hashes rather than `unsafe-inline`?
- [ ] Is `Strict-Transport-Security` sent on HTTPS with a long `max-age` and `includeSubDomains`?
- [ ] Do session cookies carry `HttpOnly`, `Secure`, and an appropriate `SameSite`?
- [ ] Is `X-Content-Type-Options: nosniff` present on every response?
- [ ] Is framing controlled with `frame-ancestors` (and legacy `X-Frame-Options`)?
- [ ] Is a `Referrer-Policy` set to avoid leaking URLs?
- [ ] Is `Permissions-Policy` used to disable browser features you do not use?
- [ ] Do third-party `<script>`/`<link>` tags use Subresource Integrity?
- [ ] Is CORS an explicit allow-list rather than a reflected origin with credentials?
- [ ] Are these headers applied centrally so they appear on errors and redirects too?

If you answered "no" or "not sure" to several of these, you are leaving browser-enforced defenses on the table.

## Next Steps

- **[Threats Addressed](attack-vectors.md)**: The client-side attacks these features block
- **[How to Implement](prevention.md)**: The headers and configuration to set, and why
- **[Examples](examples.md)**: Insecure vs. secure headers in Express, Flask, nginx, and HTML
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply browser security features hands-on
