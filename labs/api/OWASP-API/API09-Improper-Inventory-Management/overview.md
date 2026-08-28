# API09: Improper Inventory Management - Overview

## Table of Contents
- [What is Improper Inventory Management?](#what-is-improper-inventory-management)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Improper Inventory Management?

**Improper Inventory Management** is the API security risk that arises when an organization loses track of *where its APIs are, what versions are running, and what data each one exposes*. It is less about a single flawed line of code and more about an **organizational blind spot**: hosts, endpoints, and versions that exist, answer requests, and touch real data, but that nobody is actively cataloguing, patching, or monitoring.

The OWASP API Security Top 10 (2023) elevated this category precisely because modern API estates grow faster than the teams that own them. Microservices multiply, versions accumulate (`/v1`, `/v2`, `/v3`), non-production copies are stood up and forgotten, and third-party integrations quietly move sensitive data across trust boundaries. Every one of those artifacts is an asset an attacker can find — and defenders can only protect what they know exists.

### The Vocabulary of Sprawl

- **Shadow APIs**: Endpoints that exist and serve traffic but appear in no official inventory or documentation.
- **Zombie (deprecated-but-live) APIs**: Old versions officially replaced but never actually turned off. They keep answering requests, often with weaker auth and missing patches.
- **Undocumented endpoints**: Debug routes, admin panels, internal utilities, and test harnesses left reachable in production.
- **Stale hosts / rogue subdomains**: Old staging, QA, or demo environments still resolving in DNS and exposed to the internet.
- **Third-party data-flow blind spots**: Integrations where sensitive data leaves your systems for a partner or vendor without a clear record of what is shared.

### Core Concept

```
Proper Inventory:
  [OK] Every API host and version is catalogued
  [OK] Retired versions are actually decommissioned (not just "hidden")
  [OK] Debug / admin / test endpoints are absent from production
  [OK] All versions share the same authN/authZ and rate-limit controls
  [OK] Data flows to third parties are documented and reviewed

Improper Inventory:
  [X] /api/v1 still live with no auth, years after /api/v3 shipped
  [X] dev-api.example.com internet-facing with production data
  [X] /debug, /actuator, /swagger, /metrics reachable in prod
  [X] A mobile-only endpoint bypasses the web API's rate limiting
  [X] Nobody can produce a definitive list of the org's APIs
```

### Why It's Different from the Other Top 10 Risks

Most API risks (BOLA, broken authentication, SSRF) describe a flaw *inside* a known endpoint. Improper Inventory Management is a **meta-risk**: it is the reason those other flaws stay exploitable long after they are "fixed." You can patch broken authentication in `/v3`, but if `/v1` is still online with the original bug, the fix never reached the attacker's actual entry point.

## Why Does This Matter?

### The Business Impact

- **Data breaches through forgotten doors**: The endpoint that leaks records is frequently one nobody remembered was running.
- **Regulatory exposure**: GDPR, CCPA, HIPAA, and PCI-DSS require you to know where regulated data lives and flows. An unknown API is an automatic compliance gap.
- **Extended incident scope and cost**: When responders cannot enumerate all APIs, containment is incomplete and "are there others?" stays open for months.
- **Erosion of security investment**: Hardening the current version is wasted if the previous version remains reachable.
- **Third-party and supply-chain risk**: Undocumented data flows can breach contractual and regulatory obligations even when your own code is sound.

### The Technical Impact

- **Security-control drift**: Newer versions gain OAuth, MFA, and rate limiting; older versions retain basic-auth or none. Attackers choose the weakest.
- **Unpatched legacy code paths**: Deprecated endpoints stop receiving fixes but keep running.
- **Information disclosure**: `/actuator`, `/swagger.json`, `/metrics` leak versions, config, dependencies, and internal hostnames.
- **Bypass of centralized protections**: Shadow APIs that skip the gateway skip WAF rules, logging, and quotas.
- **Expanded attack surface**: Every stale host and undocumented route is another target.

## Technical Context

### How Sprawl Actually Happens

1. **Versioning without a deprecation policy** — `/v1` is kept alive "for a few old clients" and becomes permanent.
2. **Non-production environments exposed to the internet** — staging with production-like data, weak controls, and verbose errors.
3. **Framework defaults that expose endpoints** — Actuator, Swagger UI, GraphQL introspection, health/metrics routes enabled by default.
4. **Third-party integrations** — each is a place where sensitive data crosses a trust boundary; if uninventoried, you cannot say what leaves or to whom.

```
GET /api/v1/users/123    -> 200 OK  (legacy, no auth check on some fields)
GET /api/v2/users/123    -> 401     (requires bearer token)
GET /api/v3/users/123    -> 401     (requires token + scope check)

An attacker enumerates versions and settles on v1.
```

### The Discovery Asymmetry

**Attackers enumerate; defenders often only document.** With a wordlist, a subdomain scanner, and certificate-transparency logs, an attacker discovers hosts and routes the owner has genuinely forgotten. Defenders who rely on tribal knowledge and hand-maintained spreadsheets are structurally behind.

## Real-World Impact

These are genuine, publicly reported incidents where an old, undocumented, or poorly governed API surface was central to the outcome. Where public reporting does not pin down a precise figure, this lesson keeps the description qualitative rather than inventing numbers, and it does not attach CVE identifiers to breaches that were not tracked that way.

### Case Study 1: Optus (Australia, 2022)

An internet-facing API endpoint reachable **without authentication** was central to a breach affecting a large share of the telecom's customers (public reporting described figures in the millions, including identity-document data). The exposed interface was widely described as one that should never have been openly reachable — an asset that slipped through inventory and access governance.

### Case Study 2: Peloton (2021)

Researchers (Pen Test Partners) reported that several API endpoints returned user account information to unauthenticated or improperly authorized requests. The endpoints were discovered by direct testing rather than any documented interface — the hallmark of under-governed API surface.

### Case Study 3: Partner / Lender API Exposing Credit Data (2021)

An independent researcher (Bill Demirkapi), in reporting later covered by Brian Krebs, found a partner-facing API used in a lending workflow that returned consumer credit-score data given only easily obtained identifiers. The sensitive functionality lived on a **third-party integration** the data owner was not closely governing — the classic shadow / partner blind spot.

### Case Study 4: T-Mobile API Abuse (disclosed January 2023)

T-Mobile disclosed (in a regulatory filing) that an attacker abused a single API to retrieve data on a large number of accounts over an extended period before detection — an observability and governance gap, exactly what improper inventory management creates.

## Prevalence and Statistics

Rather than cite precise percentages that cannot be independently verified, this lesson describes the consistently reported shape of the problem:

- **APIs are a primary and growing attack surface.** Gartner has for several years framed API abuse as one of the most frequent vectors for application data breaches.
- **Most organizations cannot fully enumerate their own APIs.** Vendors performing API discovery routinely report finding significant numbers of previously unknown (shadow) and deprecated (zombie) endpoints on first scan.
- **Old versions outlive their replacements.** Running multiple concurrent versions is the norm; formally decommissioning old ones is the exception.
- **Discovery beats documentation.** External attack-surface scans repeatedly surface hosts and endpoints absent from internal records.

> **Takeaway on numbers**: The precise percentage varies by report and methodology, but the direction is unanimous — the number of APIs an organization *actually runs* is reliably larger than the number it can *account for*.

## Common Misunderstandings

### Myth 1: "It's not in our docs, so attackers can't find it"
**Reality**: Subdomain enumeration, CT logs, path fuzzing, JS-bundle analysis, and mobile-app inspection reveal undocumented endpoints. Obscurity is not a control.

### Myth 2: "We deprecated v1, so it's handled"
**Reality**: Deprecation is an announcement; decommissioning is an action. If `/v1` still returns `200 OK`, it is still your attack surface — verify with a request, not a changelog.

### Myth 3: "Non-production environments don't count"
**Reality**: Staging is often seeded with real data and weaker controls. If it is internet-reachable, it is production to an attacker.

### Myth 4: "The API gateway sees everything"
**Reality**: A gateway only governs traffic routed through it. Shadow services, legacy hosts, and partner integrations can bypass it.

### Myth 5: "Inventory is a one-time project"
**Reality**: An inventory is accurate only at the moment it is taken. It must be continuous and automated, wired into CI/CD and external scanning.

### Myth 6: "Internal-only old versions are fine"
**Reality**: A foothold anywhere (SSRF, a compromised service, a leaked credential) turns internal endpoints into reachable targets. Apply consistent controls to all versions.

## How to Identify if You're Vulnerable

- [ ] Can you produce a single authoritative list of every API host and version?
- [ ] Can you prove each deprecated version returns errors, not data?
- [ ] Are any non-production environments reachable from the public internet?
- [ ] Are debug, health, metrics, and interactive-docs endpoints disabled in production?
- [ ] Do all versions of an endpoint enforce the same authN/authZ and rate limits?
- [ ] Do you run external attack-surface discovery on a schedule?
- [ ] Is every third-party data flow documented?
- [ ] Does new-endpoint creation automatically register it in your inventory?

## Key Takeaways

1. **You can only protect what you know exists** — inventory is the foundation.
2. **Deprecated is not decommissioned** — verify old versions are offline.
3. **Shadow and zombie APIs are the real breach doors.**
4. **Non-production is production** when internet-reachable with real data.
5. **Attackers enumerate faster than you document** — automate discovery.
6. **Third-party data flows are part of your surface.**
7. **Inventory is continuous**, wired into CI/CD.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers discover and exploit unmanaged APIs
- **[Prevention](prevention.md)**: Build a layered API inventory and governance program
- **[Examples](examples.md)**: Vulnerable and secure code across frameworks
- **[Hands-On Lab](lab/api09-inventory-lab/)**: Practice discovering and retiring unmanaged endpoints
