# C4: Address Security from the Start - How to Implement

## Implementation Strategy Overview

Implementing this control is less about buying a tool and more about **weaving security decisions into how you already work**, from the first requirement to the last deployment:

1. Put security activities in every phase of the lifecycle (S-SDLC).
2. Threat model the design before you build it.
3. Write security requirements and abuse cases as first-class, testable items.
4. Reuse secure design patterns and proven frameworks instead of reinventing them.
5. Make the secure configuration the default via a paved-road platform.
6. Shift review and automated checks left, and prioritise by risk.

### Core Principles

- **Secure by design, secure by default**: the safe path is the built-in path; opting out of a control is explicit and rare.
- **Assume breach**: design so a single compromised component does not mean total compromise.
- **Least privilege everywhere**: every user, service, and process gets only what it needs.
- **Defense in depth**: layer independent controls so one failure is contained.
- **Reuse over reinvention**: proven frameworks and patterns beat bespoke security code.

## 1. Adopt a Secure Development Lifecycle (S-SDLC)

Security is not a phase; it is an activity attached to *every* phase. The goal is that at no point does a team ask "should we think about security now?"—it is already scheduled.

```
Phase           Security activity woven in
------------    -------------------------------------------------
Requirements    Security requirements + abuse/misuse cases written
Design          Threat modeling; trust boundaries; pattern selection
Implementation  Secure coding standards; proven frameworks; code review
Testing         Abuse cases become test cases; SAST/DAST in CI
Deployment      Secure defaults; hardened baseline; IaC review
Operation       Monitoring, logging, incident response, re-threat-model
                on significant change
```

Map each activity to an owner and a definition-of-done so it cannot be silently skipped under delivery pressure. Reference models to draw from include OWASP SAMM and BSIMM.

## 2. Threat Model Early (STRIDE + Data-Flow Diagrams)

Threat modeling is the heart of this control: a structured way to ask **"what can go wrong?"** while the design is still cheap to change. Four questions drive it (per the Threat Modeling Manifesto):

1. What are we building? (Draw it.)
2. What can go wrong? (Enumerate threats.)
3. What are we going to do about it? (Choose controls.)
4. Did we do a good job? (Validate.)

Start with a simple **data-flow diagram (DFD)** and mark trust boundaries—the lines where data moves between different levels of trust.

```
          Trust boundary (internet | server)
 Browser  ||  API Gateway  -->  Order Service  -->  [ DB ]
   (untrusted)  ||   (authn here)      |                ^
                ||                      +--> Payment (3rd party)
                ^^                                trust boundary
 Every arrow that CROSSES a boundary must:
   - authenticate the caller
   - authorize the action
   - validate the data
```

Then walk each element with **STRIDE** to prompt threat categories:

| STRIDE Threat | Question to ask | Typical design control |
|---------------|-----------------|------------------------|
| **S**poofing | Can someone pretend to be another identity? | Strong authentication, mutual TLS |
| **T**ampering | Can data be modified in transit or at rest? | Integrity checks, signing, TLS |
| **R**epudiation | Can an actor deny an action? | Tamper-evident audit logging |
| **I**nformation disclosure | Can data leak to the wrong party? | Encryption, least privilege, minimization |
| **D**enial of service | Can the system be exhausted? | Rate limiting, quotas, timeouts |
| **E**levation of privilege | Can a user gain unintended rights? | Authorization checks, least privilege |

Keep it lightweight. A one-hour whiteboard threat model on each meaningful feature catches far more than an annual heavyweight review. Re-threat-model when the design changes materially.

## 3. Define Security Requirements and Abuse/Misuse Cases

For every feature, write down not only what it must do, but what it must *never allow*. Abuse cases turn an attacker's goal into a testable requirement.

```
Feature: Redeem a gift card

User story (functional):
  As a customer, I can redeem a gift card to add credit.

Security requirements (must / must not):
  - MUST derive the account from the authenticated session, not the request body.
  - MUST enforce that a card can be redeemed at most once (idempotent).
  - MUST rate-limit redemption attempts per account and per IP.
  - MUST NOT reveal whether a card code exists on a failed attempt.

Abuse case (misuse story):
  As an attacker, I script thousands of code guesses to enumerate
  valid cards -> MITIGATED BY rate limiting + generic failure response,
  verified by test "enumeration is throttled after N attempts".
```

Because each abuse case names its mitigation and a test, it flows straight into your test suite—design intent becomes an executable check. The OWASP ASVS is a ready-made catalog of security requirements to draw from.

## 4. Use Secure Design Patterns and Reference Architectures

Do not re-derive security for every feature. Maintain a catalog of vetted patterns and reference architectures teams can adopt.

- **Deny by default**: access is refused unless explicitly granted.
- **Single choke point**: route authorization through one component, not scattered checks.
- **Server-side state machine**: enforce workflow order on the server.
- **Input allow-listing / explicit DTOs**: bind only named, writable fields per operation.
- **Tokenization / data minimization**: don't hold sensitive data you don't need.
- **Fail securely**: on error, deny and reveal nothing.

```python
# Deny-by-default authorization as a reusable design primitive
def authorize(subject, action, resource):
    rule = policy.lookup(subject.role, action, resource.type)
    if rule is None:          # nothing explicitly permits it
        return DENY           # ...so it is denied. No implicit allow.
    return rule.decision      # ALLOW only when a rule says so
```

## 5. Secure Defaults and Paved-Road Platforms

The most reliable way to make teams build securely is to make the secure choice the default and the easy one. A "paved road" (a.k.a. golden path) is a supported platform—templates, libraries, pipelines—that bakes the controls in.

```
Paved road / golden path provides, out of the box:
  - a service template with authn/authz middleware pre-wired
  - security headers, TLS, and safe error handling as defaults
  - a vetted logging + audit library
  - CI that runs SAST, dependency, secret, and IaC scans
  - a config that is hardened by default (deny-by-default, least privilege)

Result: a team gets a secure baseline for FREE by using the platform,
and has to go OUT of their way to become insecure.
```

Guardrails (automated policy that blocks unsafe configurations) reinforce the paved road, so drifting off it is caught rather than silently allowed.

## 6. Defense in Depth and Least Privilege by Design

Design so that no single control failing causes a breach, and so every actor holds the minimum privilege.

```
Layered controls for one sensitive action (delete account data):
  1. Authentication            (who are you?)
  2. Authorization             (are you allowed?)
  3. Re-authentication / MFA    (prove it again for this high-risk step)
  4. Server-side ownership check(is this YOUR data?)
  5. Rate limit + audit log     (contain and record)
If any ONE layer is misconfigured, the others still stand.
```

```yaml
# Least privilege for a service identity (illustrative policy)
service: report-generator
permissions:
  - db.orders: READ            # needs to read orders
  # NOT db.orders: WRITE       # never writes -> don't grant it
  - storage.reports: WRITE     # writes its own output only
scope: limited to its own resources; no wildcard "*" grants
```

## 7. Establish Trust Boundaries and Segmentation

Make trust explicit. Wherever data or control crosses from a less-trusted zone to a more-trusted one, re-authenticate, re-authorize, and re-validate.

- **Network segmentation**: separate zones (public, app, data) so a foothold in one does not grant the others.
- **Service-to-service auth**: internal calls authenticate; "inside the network" is not a credential.
- **Boundary validation**: every crossing validates its inputs afresh—never assume the caller sanitized them.

## 8. Design for Business-Logic Security

Enumerate the rules that make your domain safe—limits, sequences, ownership, entitlements—and enforce them server-side.

```
Checklist for any money- or state-changing workflow:
  [ ] Are all values re-validated server-side (never trust the client)?
  [ ] Is the step sequence enforced (can a later step be called first)?
  [ ] Is the action idempotent / safe under concurrency (double submit)?
  [ ] Are limits (amount, quantity, rate) defined AND enforced?
  [ ] Is ownership/entitlement checked for THIS user on THIS object?
```

## 9. Shift Left: Design Review and Security in CI

Move both human review and automated checks as early as possible.

- **Design review**: a security-aware review of the design/threat model before build; significant changes re-trigger it.
- **Code review**: security is an explicit review criterion, not an afterthought.
- **Automated gates in CI**: fast feedback on every pull request.

```bash
# Illustrative CI security gates (run on every pull request)
sast:      semgrep --config auto       # code weaknesses
deps:      dependency-check / npm audit # known-vulnerable libraries
secrets:   gitleaks detect --redact     # committed secrets
iac:       checkov -d ./infra           # misconfigured infrastructure
# Fail the build on HIGH/CRITICAL so issues are fixed while cheap.
```

## 10. Prefer Proven Frameworks Over Bespoke Security Code

Authentication, session management, access control, cryptography, and output encoding are solved problems with mature, audited libraries. Home-grown versions carry the bugs the ecosystem already fixed years ago.

```
Reach for a proven framework/library instead of writing your own:
  Auth / sessions   -> the platform's established auth framework
  Password hashing  -> argon2 / bcrypt / scrypt (never a raw hash)
  Tokens            -> a maintained JWT/PASETO library (verify signatures!)
  Crypto            -> a vetted library; never invent an algorithm
  Validation/encode -> the framework's validator + context-aware encoders
Reserve custom code for your actual BUSINESS logic.
```

## 11. Security Champions and Training

Design-level security scales only when the knowledge lives inside delivery teams, not solely in a central security group.

- **Security champions**: a developer on each team who owns threat modeling facilitation and is the first point of security contact.
- **Role-based training**: developers learn the design flaws and secure patterns relevant to their stack.
- **Shared playbooks**: threat-model templates, abuse-case libraries, and pattern catalogs make good practice repeatable.

## 12. Risk-Based Prioritization

You cannot mitigate everything at once. Rank threats by impact and likelihood so effort lands where it matters most.

```
Simple risk triage during threat modeling:
  Risk = Impact  x  Likelihood

  High impact + High likelihood  -> must-fix before ship (blocker)
  High impact + Low likelihood   -> design a control, schedule it
  Low impact  + High likelihood  -> mitigate cheaply (rate limit, log)
  Low impact  + Low likelihood   -> accept + document the decision
```

Record accepted risks explicitly—an informed, documented acceptance is a design decision; a forgotten gap is a future incident.

## Implementation Checklist

- [ ] Security activities are attached to every SDLC phase with named owners.
- [ ] Every meaningful feature gets a lightweight threat model (DFD + STRIDE).
- [ ] Security requirements and abuse cases are written and become tests.
- [ ] A secure-pattern catalog and reference architectures exist and are reused.
- [ ] A paved-road platform provides secure defaults and guardrails.
- [ ] Defense in depth and least privilege are explicit in the architecture.
- [ ] Trust boundaries are drawn; crossings re-authenticate, re-authorize, re-validate.
- [ ] Business rules are enforced server-side, safe under concurrency.
- [ ] Design review and CI security gates run early and block on high severity.
- [ ] Proven frameworks are used for all security primitives.
- [ ] Security champions are embedded and trained.
- [ ] Threats are prioritised by risk; accepted risks are documented.

## Key Takeaways

1. **Weave security into every phase** — an S-SDLC beats a single end-of-line gate.
2. **Threat model early** — a DFD plus STRIDE and four questions catches design flaws while they are cheap.
3. **Write abuse cases as testable requirements** — design intent becomes an executable check.
4. **Make the secure path the default path** — paved roads and secure defaults scale good practice.
5. **Reuse, layer, and least-privilege** — proven frameworks, defense in depth, and narrow scope by design.

## Next Steps

- **[Examples](examples.md)**: Insecure design vs. secure design, with artifacts
- **[Threats Addressed](attack-vectors.md)**: Understand the design flaws you are preventing
- **[Proactive Controls](/learn/proactive)**: Explore the full set of OWASP Proactive Controls
- **[Practice](/practice)**: Apply secure design thinking to hands-on scenarios
