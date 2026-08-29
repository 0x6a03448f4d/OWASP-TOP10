# C8: Leverage Browser Security Features - How to Implement

## How to Implement This Control

Implementing this control means **declaring the right headers, cookie attributes, and directives** so the browser enforces a strong client-side policy on every response. Set them centrally—in middleware or at the edge proxy—so they appear consistently, including on errors and redirects. Adopt them incrementally, starting with the low-risk headers and working up to a strict CSP.

### Core Principles

- **Defense in depth**: these features back up server-side controls (encoding, validation, anti-CSRF); they never replace them.
- **Deny by default**: start policies from `'none'`/empty and allow-list only what the app needs (script sources, framing origins, CORS origins, permissions).
- **Every response, no exceptions**: apply headers globally so a single error page or API route is not left unprotected.
- **Prefer strict, modern forms**: nonce/hash CSP over `unsafe-inline`; `frame-ancestors` over `X-Frame-Options`; allow-list CORS over reflection.

## 1. Content-Security-Policy (CSP)

CSP is the most powerful feature here. Use a **per-response nonce** (or hashes) with `strict-dynamic` so only vetted scripts run, and lock down the sinks attackers reach for. Avoid `unsafe-inline` and `unsafe-eval`—they defeat the policy.

```
Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  connect-src 'self' https://api.example.com;
  img-src 'self' data:;
  require-trusted-types-for 'script';
  upgrade-insecure-requests;
  report-uri /csp-report
```

- `script-src` nonce + `strict-dynamic`: only scripts carrying the fresh nonce (and scripts they load) execute—injected markup has no valid nonce.
- `object-src 'none'` and `base-uri 'none'`: close plugin and base-tag bypasses.
- `connect-src`: restricts where scripts can send data, limiting exfiltration.
- `frame-ancestors 'none'`: anti-clickjacking (see section 5).
- Roll out with `Content-Security-Policy-Report-Only` first, collect violations, then enforce.

```javascript
// Generate a fresh nonce per request and inject it into script tags
// Express example
const nonce = crypto.randomBytes(16).toString('base64');
res.setHeader('Content-Security-Policy',
  `script-src 'nonce-${nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'`);
// <script nonce="${nonce}">...</script>
```

## 2. HTTP Strict Transport Security (HSTS)

Tell the browser to use HTTPS only for your domain, eliminating the plaintext window that downgrade and SSL-strip attacks exploit. Serve it **only over HTTPS**.

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

- `max-age`: two years is typical; start smaller while validating, then raise.
- `includeSubDomains`: covers every subdomain—confirm they all serve HTTPS first.
- `preload`: submit the domain to the browser preload list to protect the very first visit. Preloading is hard to undo, so adopt it deliberately.

## 3. Secure Cookie Attributes

Session cookies are the highest-value target on the client. Set every protective flag, and use the `__Host-` prefix to bind the cookie to the origin.

```
Set-Cookie: __Host-session=VALUE; HttpOnly; Secure; SameSite=Lax; Path=/
```

- `HttpOnly`: JavaScript cannot read the cookie—an XSS payload cannot steal the session token.
- `Secure`: the cookie is only sent over HTTPS, never plaintext.
- `SameSite=Lax` (or `Strict`): the cookie is withheld from cross-site requests, mitigating CSRF. Use `Strict` for the most sensitive actions; `None` requires `Secure` and should be rare.
- `__Host-` prefix: the browser enforces `Secure`, `Path=/`, and no `Domain`—preventing subdomain cookie injection.

## 4. X-Content-Type-Options

Stop the browser from second-guessing your `Content-Type` and executing a response as script or HTML.

```
X-Content-Type-Options: nosniff
```

Pair it with correct, explicit `Content-Type` headers (and `Content-Disposition: attachment` for user-uploaded files).

## 5. Anti-Clickjacking: frame-ancestors (and X-Frame-Options)

Control who may frame your pages. `frame-ancestors` is the modern, allow-list-capable control; keep `X-Frame-Options` as a legacy fallback.

```
Content-Security-Policy: frame-ancestors 'none';        # or 'self' https://partner.example.com
X-Frame-Options: DENY                                   # legacy browsers
```

## 6. Referrer-Policy

Prevent full URLs—which may contain tokens or internal paths—from leaking to other origins.

```
Referrer-Policy: strict-origin-when-cross-origin        # sane default
# use no-referrer for the most sensitive applications
```

## 7. Permissions-Policy

Disable powerful browser features the application does not use, shrinking what compromised or embedded content can do.

```
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
```

Allow-list a feature only for the origins that need it, e.g. `geolocation=(self)`.

## 8. Subresource Integrity (SRI)

Pin third-party and CDN-hosted scripts and styles to a cryptographic hash so a tampered file is refused.

```html
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-BASE64_HASH_OF_EXACT_FILE"
        crossorigin="anonymous"></script>
```

- Generate the hash from the exact file: `openssl dgst -sha384 -binary lib.js | openssl base64 -A`.
- `crossorigin="anonymous"` is required for the integrity check on cross-origin resources.
- Combine with a CSP `require-sri-for` mindset: prefer self-hosting or version-pinned, integrity-checked third-party code.

## 9. Sensible CORS

CORS is an allow-list. Never reflect an arbitrary `Origin` while allowing credentials, and never pair `*` with credentials.

```
# Secure: validate against an explicit allow-list, echo only known origins
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
Vary: Origin                       # so caches do not mix origins
```

```javascript
// Express: allow-list, not reflection
const ALLOW = new Set(['https://app.example.com']);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOW.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  next();
});
```

## 10. Cross-Origin Isolation (COOP / COEP / CORP)

Isolate your browsing context to cut off cross-window references and reduce cross-site leak surface (and to unlock powerful APIs safely).

```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

Set `Cross-Origin-Resource-Policy` on your own resources so other origins cannot embed them, and test COEP carefully—it requires all sub-resources to opt in.

## 11. iframe sandbox

When embedding untrusted content, start from a fully restricted sandbox and grant back only the capabilities the embed genuinely needs.

```html
<iframe src="https://untrusted.example/widget"
        sandbox="allow-scripts allow-forms"></iframe>
<!-- omit allow-same-origin to keep the frame in an opaque origin -->
<!-- never combine allow-scripts + allow-same-origin for untrusted content -->
```

## 12. Trusted Types (DOM-XSS)

Force dangerous DOM sink assignments through a vetted policy so raw, attacker-controlled strings cannot reach `innerHTML`, `eval`, and similar sinks.

```
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types app-policy
```

```javascript
// Define a single, audited policy
window.trustedTypes.createPolicy('app-policy', {
  createHTML: (input) => DOMPurify.sanitize(input)   // sanitize before it becomes HTML
});
```

## Apply Everything Centrally

Set these once, in a shared layer, so no route is missed:

```javascript
// Express: a single hardened baseline with helmet + explicit additions
const helmet = require('helmet');
app.use(helmet());                                  // nosniff, frameguard, HSTS, referrer, etc.
app.use(helmet.strictTransportSecurity({ maxAge: 63072000, includeSubDomains: true, preload: true }));
app.use((req, res, next) => {
  const nonce = require('crypto').randomBytes(16).toString('base64');
  res.locals.nonce = nonce;
  res.setHeader('Content-Security-Policy',
    `default-src 'self'; script-src 'nonce-${nonce}' 'strict-dynamic'; ` +
    `object-src 'none'; base-uri 'none'; frame-ancestors 'none'; connect-src 'self'`);
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});
```

## Verify and Monitor

- Use CSP `report-uri`/`report-to` and roll out in **report-only** mode first to find breakage without blocking users.
- Scan headers in CI (for example with a header-checking tool or `testssl.sh`) so a regression fails the build.
- Confirm headers appear on **error pages, redirects, and API responses**—not just the happy path.
- Re-check after every deployment; a middleware change can silently drop a header.

> **Keep the layering straight.** Every feature on this page is a backstop. Ship them *and* keep fixing the underlying issues: encode output (C3), use parameterized queries, enforce access control and anti-CSRF tokens server-side, and require TLS. The browser holds the second line only when the first is also built.

## Key Takeaways

1. **Start CSP strict** — nonce/hash + `strict-dynamic`, no `unsafe-inline`, roll out report-only first.
2. **Protect the session cookie** — `HttpOnly`, `Secure`, `SameSite`, `__Host-`.
3. **Force HTTPS** — HSTS with `includeSubDomains` and, deliberately, `preload`.
4. **Pin third-party code** — SRI plus a tight `script-src`/`connect-src`.
5. **Apply centrally and verify** — every response, checked in CI, re-checked on deploy.

## Next Steps

- **[Examples](examples.md)**: Insecure vs. secure headers in Express, Flask, nginx, and HTML
- **[Threats Addressed](attack-vectors.md)**: The client-side attacks these features block
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Configure browser security features hands-on
