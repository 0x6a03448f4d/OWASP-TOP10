# A04:2021 – Insecure Design - Overview

## Table of Contents

- [What is Insecure Design?](#what-is-insecure-design)
- [Design Flaws vs. Implementation Bugs](#design-vs-implementation)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)
- [Self-Assessment](#self-assessment)
- [Next Steps](#next-steps)

## What is Insecure Design?

**Insecure Design** is a broad category describing weaknesses that originate in the *design and architecture* of an application rather than in a defective line of code. It represents a **missing or ineffective security control**: a threat the system was never designed to resist, a business workflow that can be abused as intended, or a trust assumption that does not hold once a real adversary is involved.

This was a **new category introduced in the OWASP Top 10 for 2021**, landing at position #4. Its arrival marked an important shift: the recognition that a large class of serious vulnerabilities cannot be attributed to a coding mistake at all. You can write flawless, well-tested, injection-free code and still ship a fundamentally insecure application — because the design itself never accounted for how the feature could be abused.

OWASP frames the distinction memorably: there is a difference between an **insecure design** and an **insecure implementation**. A secure design can still be implemented insecurely (a bug creeps into an otherwise sound control). But an insecure design cannot be rescued by a perfect implementation — because the necessary security control was never part of the design. You cannot correctly implement a control that does not exist.

> **Core idea:** Insecure Design is about the controls you *forgot to build*, the abuse cases you *never considered*, and the trust boundaries you *assumed away* — not about a control that exists but contains a bug.

## Design Flaws vs. Implementation Bugs

Consider a password-reset feature:

| Scenario | Category | Why |
|---|---|---|
| Reset token generated with a predictable, non-crypto RNG | Implementation bug (often Cryptographic Failures) | The control (unpredictable token) exists in the design, but the code implements it wrongly. |
| Reset flow verifies a "security question" whose answer is public | **Insecure Design** | The chosen recovery mechanism is fundamentally weak by design. |
| Reset endpoint has no rate limiting, so a 6-digit code can be brute-forced | **Insecure Design** | Anti-automation was never designed into the workflow. |
| Rate limiting exists but an off-by-one lets one extra attempt through | Implementation bug | The control exists in the design; the code has a defect. |

The practical test: ask *"If every line of code worked exactly as the developer intended, would the system still be exploitable?"* If yes, you are looking at insecure design.

### What Insecure Design Is Not

Insecure Design is deliberately **not** a bucket for "all the other bugs." It excludes issues that result from incorrect implementation of an otherwise-adequate design. Injection, most cryptographic failures, and misconfiguration are implementation- or configuration-level categories. Insecure Design sits one level up, in the blueprint.

## Why Does This Matter?

### Business Impact

- **Direct financial loss**: Business-logic flaws (skipping payment, abusing refunds, stacking coupons, negative quantities) convert directly into money leaving the organization.
- **Expensive to remediate late**: Fixing a design flaw in production may require re-architecting a workflow or data model — orders of magnitude more than fixing it on a whiteboard.
- **Reputational and trust damage**: Abuse of a poorly designed feature (mass account creation, fraud, scalping, scraping) erodes user trust.
- **Regulatory exposure**: Designs that fail to segregate tenants, enforce least privilege, or protect data by default can breach GDPR, HIPAA, and PCI-DSS, which increasingly expect "security and privacy by design."

### Technical Impact

- **Whole-workflow compromise**: A flawed trust assumption can undermine an entire feature area at once.
- **Resistant to point fixes**: Patching one instance often leaves the pattern intact elsewhere.
- **Invisible to many tools**: A workflow that behaves exactly as coded produces no error and no signature to match.
- **Automation amplification**: Absence of anti-automation lets an attacker scale a small weakness into a large-scale attack.

## Technical Context

### 1. Missing Threat Modeling
The meta-cause: no one ever systematically asked "how could this be abused?" Threat modeling surfaces missing controls before code is written.

### 2. Missing or Vague Security Requirements
Functional requirements are well specified; the corresponding security requirements (limits, thresholds, step-up auth) are left implicit and never built.

### 3. Business-Logic Abuse
The app does exactly what it was told, but a sequence of legitimate operations produces an illegitimate outcome: reordering checkout to skip payment, reusing coupons, negative quantities, racing a one-time benefit.

```
Intended flow:   add-to-cart -> enter-shipping -> enter-payment -> charge -> confirm
Abused flow:     add-to-cart -> enter-shipping -----------------------> confirm
                                 (attacker POSTs confirm directly; payment never verified)
```

### 4. Missing Anti-Automation / Rate Limiting
Without designed-in throttling, harmless actions become attacks: credential stuffing, OTP brute force, ID enumeration, scraping, resource exhaustion.

### 5. Trusting the Client
Prices, discounts, roles, and limits enforced only client-side are advisory; anyone can craft a raw HTTP request that ignores them.

### 6. Weak Trust Boundaries and Tenant Segregation
When segregation is an afterthought, cross-tenant access and privilege confusion become structural, not incidental.

### 7. Insecure Recovery and Fallback Design
Recovery paths designed for usability become the softest attack surface: knowledge-based questions, unverified channels, fallbacks that downgrade to weaker checks.

## Real-World Impact

Well-documented *classes* of incident that trace to design, not a single coding bug:

### Case Class 1: E-Commerce Business-Logic Fraud
**Design flaw**: Checkout/coupon/refund workflows trust client-supplied prices or fail to validate state transitions server-side.
**Impact**: Free or manipulated-price goods, stacked discounts, refunds for retained items — reported repeatedly by retail bug-bounty programs.
**Root cause**: Workflow designed around the shopper "happy path," never modeling a hostile actor.

### Case Class 2: Credential Stuffing Against Login Without Anti-Automation
**Design flaw**: Auth endpoints without designed-in rate limiting, bot detection, or breached-credential checks.
**Impact**: Leaked username/password pairs replayed at massive scale; a large share of login traffic on major sites is automated stuffing.
**Root cause**: Login designed to verify one honest user, not to withstand automation.

### Case Class 3: OTP / Reset-Code Brute Force
**Design flaw**: A short numeric code with no attempt limit and unlimited re-requests.
**Impact**: The small code space is exhaustively guessed, defeating the second factor.
**Root cause**: A small secret space paired with unlimited guessing.

### Case Class 4: Knowledge-Based Account Recovery
**Design flaw**: Recovery gated on "security questions" whose answers are public or discoverable.
**Impact**: High-profile takeovers hinging on public information, no software bug required.
**Root cause**: The recovery factor is not actually secret — a design choice.

## Prevalence and Statistics

OWASP introduced Insecure Design in 2021 because the data showed a class of weaknesses the existing categories missed. Rather than cite precise figures:

- The category maps to many CWEs, including **CWE-209, CWE-256, CWE-501 (trust boundary violation), CWE-522, and CWE-799 (improper control of interaction frequency — missing rate limiting)**.
- Business-logic and design flaws are **disproportionately represented in bug-bounty payouts**, because tooling misses them and impact is high.
- OWASP characterizes the category as high-impact and **fundamentally under-addressed**, since most programs focused on finding implementation bugs, not evaluating design.

> Note: exact percentages differ between reports. The durable takeaway is that design flaws are common, high-impact, and systematically missed by tooling — which is why the category was created.

## Common Misunderstandings

**Myth 1: "Security can be bolted on later."** Reality: Architectural controls (rate limiting, trust boundaries, workflow integrity, segregation) require re-designing the feature to add later. Designing them in is far cheaper.

**Myth 2: "Penetration testing will catch it."** Reality: Design weaknesses are best surfaced by threat modeling and architecture review before code exists.

**Myth 3: "Our code passed SAST/DAST, so we're secure by design."** Reality: Scanners detect known bug patterns; a workflow abused while behaving exactly as coded produces zero findings.

**Myth 4: "It's a design flaw, so it's not really exploitable."** Reality: Design flaws are among the *most* exploitable — no payload needed, just a hostile user following an unexpected path.

**Myth 5: "We validate everything on the front end."** Reality: Client-side validation is UX, not a security control. Enforce server-side.

**Myth 6: "Insecure Design is just a vague umbrella."** Reality: It has a precise scope — missing/ineffective controls rooted in design, excluding correct designs with a bug.

## Self-Assessment

- [ ] Did you threat model each significant feature before building it?
- [ ] Are security requirements written down alongside functional ones?
- [ ] Does the server verify prerequisite steps actually completed in every multi-step workflow?
- [ ] Is every price, discount, role, quantity limit, and eligibility rule enforced server-side?
- [ ] Do sensitive/expensive endpoints have designed-in rate limiting and resource caps?
- [ ] Can you state, per resource, exactly which tenant/user/role may access it — and is it enforced at a trust boundary?
- [ ] Are recovery and fallback paths as strong as the primary path?
- [ ] Do you have automated tests asserting abuse cases *fail*?
- [ ] Have you considered race conditions in any one-time/limited-benefit workflow?
- [ ] Is there a documented reference architecture / secure design patterns new features must follow?

If you answered "no" or "not sure" to several, design-level weaknesses are likely present today.

## Next Steps

- **[Attack Vectors](./attack-vectors.html)**: How attackers discover and abuse design-level weaknesses.
- **[Prevention](./prevention.html)**: Threat modeling, secure design patterns, and guardrails.
- **[Examples](./examples.html)**: Design-level vulnerable-vs-secure code in Python, Node.js, and Java.
- **[Hands-On Lab](./lab/missing-rate-limit-lab/)**: Exploit and then fix a workflow whose design omits rate limiting.

*Part of the OWASP Top 10 Educational Repository.*
