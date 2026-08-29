# C5: Secure By Default Configurations - Overview

## Table of Contents
- [What is this control?](#what-is-this-control)
- [Why This Control Matters](#why-this-control-matters)
- [Core Practices](#core-practices)
- [Secure Defaults Across the Stack](#secure-defaults-across-the-stack)
- [Real-World Incident Classes](#real-world-incident-classes)
- [Common Misunderstandings](#common-misunderstandings)

## What is this control?

**Secure By Default Configurations** is the proactive control of shipping and running systems that are **safe out of the box**. A default deployment—one where nobody has yet applied any special hardening—should already be in a secure state. Security is the starting position, and relaxing it is a deliberate, visible, and rare exception rather than the norm.

This is the defensive counterpart to **Security Misconfiguration**. Misconfiguration is what happens when insecure defaults are left in place; this control is the discipline of making sure the defaults were never insecure to begin with, and that any drift back toward insecurity is caught automatically. The governing principle is **deny by default**: features, ports, accounts, and permissions are off unless a specific need turns them on.

### Core Concept

```
Insecure default (must be hardened later, and usually isn't):
  Deployment    -> "works out of the box", every feature enabled
  Access        -> allow by default, broad permissions
  Accounts      -> vendor default credentials still active
  Errors        -> verbose stack traces, debug mode on
  Headers       -> no security headers set
  Storage       -> buckets public, encryption optional
  Surface       -> sample apps, demo pages, unused services running

Secure default (safe with no extra hardening):
  Deployment    -> only what is needed is enabled; the rest is off
  Access        -> deny by default, least privilege granted explicitly
  Accounts      -> no default credentials; unique secrets required at setup
  Errors        -> generic messages in prod; detail only in server logs
  Headers       -> HSTS, CSP, X-Content-Type-Options, frame denial preset
  Storage       -> private by default, encryption on by default
  Surface       -> minimal image, no samples, no demo accounts
```

### Two audiences: what you build and what you deploy

The control applies in two directions, and both matter:

- **Products and code you build**: the software your team ships to others must default to the safe behaviour—secure cookie flags on, TLS required, no wildcard CORS, no sample admin account. If a consumer of your product does nothing, they should still be safe.
- **Products you deploy and operate**: the third-party servers, frameworks, databases, and cloud services you run must be brought to a secure baseline before they face traffic—default credentials removed, unused features disabled, private-by-default storage confirmed.

## Why This Control Matters

### Business Impact of Getting It Right

- **Breach prevention without heroics**: most large misconfiguration breaches trace back to a default that was never changed. A secure default removes the single most common root cause before an operator ever touches the system.
- **Scale safety**: modern systems are cloned from templates and base images thousands of times. A secure default is inherited by every copy; an insecure one is a defect multiplied across the fleet.
- **Lower operational cost**: hardening after the fact is manual, error-prone, and drifts. Baking safety into the default makes the cheap path and the safe path the same path.
- **Regulatory alignment**: private-by-default storage, encryption on by default, and least privilege map directly onto GDPR, HIPAA, and PCI-DSS expectations.

### Technical Impact

- **Attack surface shrinks by default**: disabled features, closed ports, and removed sample apps mean fewer things to exploit without anyone remembering to turn them off.
- **Recon is denied**: quiet banners and generic errors give automated scanners nothing to fingerprint.
- **Blast radius is contained**: least privilege by default means a compromised component cannot reach far.
- **Drift is visible**: when secure is the baseline, any deviation stands out and can be flagged automatically.

## Core Practices

Secure By Default Configurations is made of a handful of reinforcing habits:

- **Deny by default**: access, features, ports, and methods are off until a need switches them on.
- **Minimal attack surface**: remove unused features, services, ports, sample apps, demo pages, and default accounts.
- **No default credentials**: ship with none; force a unique secret at first setup and rotate anything shared.
- **Least privilege by default**: every identity, service account, and token starts with the narrowest rights that work.
- **Secure security headers by default**: CSP, HSTS, `X-Content-Type-Options`, frame denial, and a sane referrer policy are preset on every response.
- **Quiet, safe errors in production**: debug and verbose errors are off; the client gets a generic message and the detail goes to logs.
- **Secure cloud and IaC defaults**: private buckets, no public exposure, and encryption at rest are the template default.
- **Repeatable hardening and secure baselines**: codify a known-good baseline (for example, a CIS Benchmark) and apply it identically everywhere.
- **Automated validation and drift detection**: scan configuration and IaC continuously so a deviation fails the pipeline or raises an alert.
- **Patched defaults**: base images and dependencies default to current, patched versions.
- **Make the secure path the easy path**: give developers a paved road—templates, libraries, and modules where the default is already correct.

## Secure Defaults Across the Stack

| Layer | Insecure default (harden later) | Secure default (safe now) |
|-------|---------------------------------|---------------------------|
| Application framework | Debug on, verbose errors, wildcard CORS | Debug off, generic errors, allow-listed CORS |
| Web server / proxy | Version banner on, directory listing, all methods | Banner off, listing off, only needed methods |
| TLS / transport | Legacy protocols allowed, no HSTS | Modern TLS only, HSTS preset |
| Datastore | Binds to all interfaces, auth optional | Binds to localhost/private, auth required |
| Container image | Runs as root, full OS, secrets baked in | Non-root, minimal image, secrets injected |
| Cloud storage | Public-capable, encryption optional | Private by default, encryption on |
| Identity / IAM | Broad roles, wildcards | Least privilege, scoped roles |

## Real-World Incident Classes

These are recurring *classes* of incident that secure defaults are designed to prevent. They are described as patterns, not specific vulnerabilities.

### Class 1: Exposed no-auth datastores

Databases and search engines that historically shipped listening on all interfaces with authentication disabled were deployed straight to the internet. Entire datasets were read, tampered with, or wiped. Vendors later changed the default to bind to localhost precisely because the insecure default caused so many incidents—a direct illustration of this control.

### Class 2: Public cloud storage buckets

Object-storage buckets left readable by "everyone" or "any authenticated user" exposed backups and customer records across many organisations. Providers responded by adding block-public-access defaults, moving the safe state into the default.

### Class 3: Open administrative and orchestration dashboards

Management consoles and cluster dashboards deployed with no authentication and reachable from the internet were hijacked to mine cryptocurrency and to pivot into internal resources. A secure default keeps management planes closed and authenticated.

### Class 4: Default and sample credentials

Devices, appliances, and applications shipped with well-known credentials (the `admin/admin` family) are compromised at scale by automated tools, with no exploit required. Shipping with no usable default credential removes the class entirely.

## Common Misunderstandings

### Myth 1: "We'll harden it after deployment"

**Reality**: post-deployment hardening is manual, frequently forgotten, and drifts over time. The window between "deployed" and "hardened" is exactly when systems are attacked. Secure defaults remove that window.

### Myth 2: "Secure defaults slow developers down"

**Reality**: the opposite, when done well. A paved-road template where the safe option is already selected is faster than researching and hand-configuring security on every project.

### Myth 3: "The vendor default must be reasonable"

**Reality**: many vendor defaults optimise for "starts on first try", not "safe in production". Debug flags, sample accounts, and open management ports are common defaults you must change.

### Myth 4: "It's internal, so defaults are fine"

**Reality**: internal systems are reached through SSRF, compromised dependencies, and pivots. Deny-by-default and least privilege apply just as much inside the perimeter.

### Myth 5: "Setting a secure baseline once is enough"

**Reality**: configuration drifts as people make changes. Without automated validation and drift detection, a secure baseline silently erodes back to insecure.

## How This Control Relates to Security Misconfiguration

| Aspect | Security Misconfiguration (the risk) | Secure By Default Configurations (the control) |
|--------|--------------------------------------|-----------------------------------------------|
| **Nature** | A weakness left in place | A practice that prevents the weakness |
| **Default posture** | Insecure until hardened | Secure until deliberately relaxed |
| **Effort model** | Someone must remember to fix it | Safety is inherited automatically |
| **Failure mode** | Forgotten hardening, drift | Explicit, reviewed opt-out |

## Key Takeaways

1. **Secure is the starting state**—a fresh deployment is safe before anyone hardens it.
2. **Deny by default**—features, ports, accounts, and permissions are off unless needed.
3. **It applies to what you build and what you deploy**—both must default to safe.
4. **Codify and automate**—secure baselines plus drift detection keep the default from eroding.
5. **Make safe the easy path**—developers should get security by choosing the default, not by extra work.

## Self-Assessment Checklist

- [ ] Does a fresh, un-hardened deployment of your system start in a safe state?
- [ ] Are all features, ports, and services off unless explicitly needed?
- [ ] Have all default and sample credentials been removed or forced-to-change?
- [ ] Do identities and service accounts start with least privilege?
- [ ] Are security headers preset on every response by default?
- [ ] Is debug and verbose error output off in production by default?
- [ ] Are cloud buckets private and encrypted by default in your templates?
- [ ] Is there a codified secure baseline (e.g. CIS) applied identically everywhere?
- [ ] Does automation detect and flag configuration drift?
- [ ] Is the secure option the default option developers reach for?

## Next Steps

- **[Threats Addressed](attack-vectors.md)**: The insecure-default failure modes this control closes
- **[How to Implement](prevention.md)**: Build secure defaults and a repeatable baseline
- **[Examples](examples.md)**: Insecure vs. secure configuration across the stack
- **[Proactive Controls](/learn/proactive)**: Continue the OWASP Proactive Controls track
- **[Practice](/practice)**: Apply secure-by-default configuration hands-on
