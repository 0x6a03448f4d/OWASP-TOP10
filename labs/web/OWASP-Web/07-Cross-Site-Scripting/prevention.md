# XSS Prevention

## Table of Contents

- [A Layered Prevention Strategy](#a-layered-prevention-strategy)
- [Defense 1: Context-Aware Output Encoding](#defense-1-context-aware-output-encoding)
- [Defense 2: Framework Auto-Escaping](#defense-2-framework-auto-escaping)
- [Defense 3: Trusted Sanitization for Rich HTML](#defense-3-trusted-sanitization-for-rich-html)
- [Defense 4: Avoid Dangerous DOM Sinks](#defense-4-avoid-dangerous-dom-sinks)
- [Defense 5: Content-Security-Policy](#defense-5-content-security-policy)
- [Defense 6: Trusted Types](#defense-6-trusted-types)
- [Defense 7: Cookie Hardening](#defense-7-cookie-hardening)
- [Defense 8: Input Validation (Defense-in-Depth)](#defense-8-input-validation-defense-in-depth)
- [Security Checklist](#security-checklist)

## A Layered Prevention Strategy

No single control stops every XSS. Robust defense stacks independent layers so that a gap in one is covered by another. The order below reflects priority: **output encoding and auto-escaping are the primary fix**; sanitization handles the special case of rich HTML; CSP, Trusted Types, and cookie flags are the safety net that limits damage when something slips through.

```
PRIMARY (stops injection):
  1. Context-aware output encoding   -> the correct fix for 90%+ of cases
  2. Framework auto-escaping         -> make the safe path the default
  3. Trusted sanitization (DOMPurify)-> only for intentional rich HTML
  4. Avoid dangerous DOM sinks       -> textContent over innerHTML

SAFETY NET (limits damage if injection occurs):
  5. Content-Security-Policy         -> block inline/unknown script
  6. Trusted Types                   -> lock down DOM-XSS sinks
  7. HttpOnly + Secure + SameSite    -> protect the session cookie
  8. Input validation                -> reduce surface, never the sole control
```

## Defense 1: Context-Aware Output Encoding

The single most important rule: **encode untrusted data for the exact context in which it is rendered, at the moment it is rendered.** Each context has a different escaping function; using the wrong one leaves a hole.

| Output context | Encode | Example |
|---|---|---|
| HTML body | `& < >` (and `" '`) | `<div>DATA</div>` |
| HTML attribute (quoted) | `& < > " '` | `<input value="DATA">` |
| JavaScript string | Hex-escape non-alphanumerics (`\xHH`) | `var x = "DATA";` |
| URL parameter | Percent-encode (`encodeURIComponent`) | `<a href="/x?q=DATA">` |
| CSS value | CSS-escape; allow-list values | `style="width:DATA"` |

```javascript
// Node/JS: a minimal HTML-body encoder (prefer a library in production)
function encodeHTML(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#39;');
}

// URL context: encode the component, then validate the scheme
const safeHref = /^https?:\/\//i.test(url) ? url : '#';
element.setAttribute('href', encodeURI(safeHref));
```

> **Encode at output, not at input.** A value stored raw can be safely rendered into many different contexts later. A value pre-encoded for HTML is wrong (double-encoded or unsafe) when later placed into JavaScript or a URL. Store canonical data; encode when you emit it.

## Defense 2: Framework Auto-Escaping

The most reliable way to get encoding right everywhere is to use a template engine or UI framework that escapes by default, and to treat its "raw" escape hatches as rare, reviewed exceptions.

```
Jinja2 / Flask (Python) — autoescape ON by default:
    <h1>Welcome {{ name }}</h1>        <!-- escaped -->
    {{ content | safe }}                <!-- DANGER: only for trusted HTML -->

Django templates — autoescape ON by default:
    {{ comment }}                       <!-- escaped -->
    {{ comment | safe }}   /  mark_safe(...)   <!-- DANGER -->

React (JSX) — escapes interpolated values:
    <div>{userInput}</div>              // escaped
    <div dangerouslySetInnerHTML={{__html: userInput}} />  // DANGER

Vue:  {{ userInput }} escaped;  v-html="userInput" is DANGER
Angular: {{ userInput }} and [prop] escaped; [innerHTML] sanitized,
         bypassSecurityTrust* is DANGER
```

**Rule**: search your codebase for every escape hatch (`| safe`, `mark_safe`, `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `bypassSecurityTrust`) and confirm each one wraps data you fully control or have sanitized.

## Defense 3: Trusted Sanitization for Rich HTML

Sometimes users must submit real HTML (a rich-text editor, Markdown output). You cannot encode it — that would show the tags as text — so you must *sanitize*: parse the HTML and remove everything not on a strict allow-list. Use a maintained, security-focused library; never a regex.

```javascript
// Browser / Node with DOMPurify — the standard choice
import DOMPurify from 'dompurify';

const dirty = userSuppliedHtml;
const clean = DOMPurify.sanitize(dirty, {
  ALLOWED_TAGS: ['b','i','em','strong','a','p','ul','ol','li','code','pre'],
  ALLOWED_ATTR: ['href','title'],
  ALLOWED_URI_REGEXP: /^(?:https?|mailto):/i   // block javascript:/data:
});
element.innerHTML = clean;   // now safe
```

```python
# Python server side — nh3 (Rust/ammonia) or bleach
import nh3
clean = nh3.clean(
    user_html,
    tags={'b','i','em','strong','a','p','ul','ol','li','code','pre'},
    attributes={'a': {'href','title'}},
)
```

DOMPurify is specifically hardened against mutation-XSS (mXSS). Home-grown sanitizers routinely fall to the bypasses listed in Attack Vectors — do not write your own.

## Defense 4: Avoid Dangerous DOM Sinks

DOM-based XSS is fixed only in client code. Prefer APIs that treat data as text; reserve HTML-parsing sinks for sanitized content.

```javascript
// UNSAFE                              // SAFE
el.innerHTML = userText;               el.textContent = userText;
el.outerHTML = userText;               el.replaceChildren(document.createTextNode(userText));
document.write(userText);              // build nodes with createElement()
eval(userText);                        JSON.parse(userText);
setTimeout("fn(" + userText + ")");    setTimeout(() => fn(userText), 0);
a.href = userInput;                    a.href = /^https?:/.test(userInput) ? userInput : '#';

// If you must set HTML, sanitize first:
el.innerHTML = DOMPurify.sanitize(userHtml);
```

## Defense 5: Content-Security-Policy

CSP is the primary safety net: even if an injection lands, a strict policy can stop the browser from executing it. The strongest modern approach is a **nonce-based** policy with `strict-dynamic`, which trusts only scripts carrying a per-response random nonce and the scripts they load — while ignoring host allow-lists that attackers often bypass.

```
Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-r4Nd0m2024' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  require-trusted-types-for 'script';
  report-uri /csp-report
```

```python
# Flask: generate a fresh nonce per request and set the header
import secrets
from flask import g, render_template

@app.before_request
def make_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)

@app.after_request
def set_csp(resp):
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        f"script-src 'nonce-{g.csp_nonce}' 'strict-dynamic'; "
        "object-src 'none'; base-uri 'none'"
    )
    return resp

# Template: every legitimate inline script carries the nonce
# <script nonce="{{ g.csp_nonce }}"> ... </script>
```

**Key points**: avoid `'unsafe-inline'` and `'unsafe-eval'` in `script-src` — they defeat the purpose. Set `object-src 'none'` and `base-uri 'none'` to close common bypasses. Roll out with `Content-Security-Policy-Report-Only` first to find violations without breaking the app. CSP is defense-in-depth, *not* a substitute for encoding.

## Defense 6: Trusted Types

Trusted Types (supported in Chromium-based browsers) removes DOM-XSS at the source by forbidding strings from ever reaching dangerous sinks like `innerHTML` and `eval`. Assignments must go through a vetted policy that returns a special typed object, so every injection path is funneled through code you control and audit.

```
Enforce via header:
    Content-Security-Policy: require-trusted-types-for 'script'

Define a single sanitizing policy:
    if (window.trustedTypes) {
      trustedTypes.createPolicy('default', {
        createHTML: (s) => DOMPurify.sanitize(s)  // all HTML is sanitized
      });
    }
    // Now `el.innerHTML = rawString` throws unless routed through the policy.
```

## Defense 7: Cookie Hardening

These flags do not prevent XSS, but they contain the blast radius — especially session theft.

```
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Path=/
```

- **HttpOnly**: JavaScript cannot read the cookie, blocking `document.cookie` exfiltration of the session token.
- **Secure**: the cookie is sent only over HTTPS, preventing network capture.
- **SameSite**: limits cross-site sending, reducing CSRF risk that XSS chains into.

Because `HttpOnly` blocks reading but not *using* the session, keep tokens out of `localStorage` (fully readable by any XSS) and rely on hardened cookies where possible.

## Defense 8: Input Validation (Defense-in-Depth)

Validation reduces attack surface and catches obviously malformed input, but it is a *supporting* control — never the primary defense, because the same value can be safe or dangerous depending on where it is later output.

```python
# Allow-list validation: constrain to what the field legitimately holds
import re
def valid_username(u):
    return bool(re.fullmatch(r'[A-Za-z0-9_]{3,20}', u))

# Reject at the edge, but STILL encode on output.
# Validation is not a substitute for encoding/sanitization.
```

## Security Checklist

- [ ] Every untrusted value is encoded for its specific output context at render time.
- [ ] A framework with default auto-escaping is used; every escape hatch is audited.
- [ ] Rich user HTML goes through DOMPurify (or nh3/bleach), never a custom regex.
- [ ] DOM sinks (`innerHTML`, `document.write`, `eval`, `setTimeout(string)`) are eliminated or fed only sanitized data.
- [ ] A strict CSP is deployed (nonce + `strict-dynamic`, no `unsafe-inline`/`unsafe-eval`), first in report-only mode.
- [ ] `require-trusted-types-for 'script'` is enabled where supported.
- [ ] Session cookies are `HttpOnly`, `Secure`, and `SameSite`; tokens are not in `localStorage`.
- [ ] URL sinks validate the scheme (allow only `http`/`https`/`mailto`).
- [ ] JSON responses set `application/json` and `X-Content-Type-Options: nosniff`.
- [ ] Input validation is applied as defense-in-depth, not as the sole control.

## Next Steps

- **[Examples](examples.html)**: Vulnerable vs. secure code applying these defenses
- **[Attack Vectors](attack-vectors.html)**: The vectors these controls neutralize
- **[Overview](overview.html)**: Types, impact, and misconceptions
- **[Hands-On Lab](./lab/cross-site-scripting/)**: Practice fixing XSS in a safe, isolated environment
