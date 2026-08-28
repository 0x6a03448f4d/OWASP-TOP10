# CICD-SEC-7: Insecure System Configuration - Overview

## Table of Contents
- [What is Insecure System Configuration?](#what-is-insecure-system-configuration)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Insecure System Configuration?

**Insecure System Configuration** (CICD-SEC-7 in the OWASP Top 10 CI/CD Security Risks) is the risk that arises when the *systems that build and ship software*—source-control management (SCM) servers, continuous-integration servers, orchestrators, artifact registries, and build runners—are themselves run with insecure settings, left at unsafe defaults, exposed on the network, or allowed to fall behind on patches. The flaw is not in the application code moving through the pipeline; it is in the *configuration and posture of the pipeline machinery itself*.

A CI/CD platform is a peculiarly high-value target. It holds credentials to production, cloud accounts, registries, and signing keys; it executes arbitrary, frequently-changing code by design; and it can push artifacts straight into production. When such a system is unpatched, exposes its admin console to the internet, ships with anonymous read (or write) enabled, or loads dozens of third-party plugins of unknown provenance, the attacker does not need a subtle application bug—they need only reach the console and walk in.

> **Scope note.** CICD-SEC-7 is about the configuration of the CI/CD *systems and infrastructure*. It is distinct from CICD-SEC-6 (Insufficient Credential Hygiene), CICD-SEC-4 (Poisoned Pipeline Execution), and CICD-SEC-2 (Inadequate Identity and Access Management), although a weak system configuration is very often the first domino that makes those other risks exploitable.

### Core Concept

```
Secure CI/CD System Configuration:
  Patching     -> CI/SCM servers and plugins updated promptly against advisories
  Exposure     -> consoles/APIs reachable only via VPN or IP allow-list
  Auth         -> SSO + MFA on every admin surface, anonymous access OFF
  Plugins      -> minimal, vetted, pinned; unused integrations removed
  Runners      -> isolated, ephemeral, least-privilege, not internet-exposed
  Transport    -> TLS everywhere, valid certificates, no cleartext consoles
  Webhooks     -> validated signatures, source allow-list, least scope
  Modes        -> debug/verbose OFF in production, no script console for users
  Baseline     -> hardened per vendor benchmark, config-as-code, drift detected

Insecure System Configuration:
  Patching     -> CI server months behind; vulnerable plugins never updated
  Exposure     -> Jenkins/GitLab/registry console open to the whole internet
  Auth         -> anonymous read/build enabled, default or shared admin login
  Plugins      -> dozens of unused plugins, unknown provenance, never updated
  Runners      -> long-lived shared runners on flat, internet-reachable infra
  Transport    -> plain HTTP console, self-signed/expired certs ignored
  Webhooks     -> unauthenticated, accept events from any source
  Modes        -> script console reachable, verbose logs leak secrets
  Baseline     -> hand-built server, no benchmark, silent configuration drift
```

### Why It's Critical for CI/CD

CI/CD systems concentrate several conditions that make insecure configuration unusually dangerous:

- They are **execution engines by design**. A CI server exists to run code; a foothold on the console frequently means immediate code execution on build infrastructure.
- They **hold the keys to everything downstream**—deploy credentials, cloud roles, registry tokens, and signing material—so a single compromised orchestrator can reach production and every artifact it produces.
- They are **often self-hosted and hand-operated**, so hardening, patching, and network placement depend on an internal team that may treat the CI box as "just internal tooling."
- They carry a **large, dynamic plugin and integration surface**. Jenkins in particular is extended by hundreds of community plugins, each of which is code running inside the controller with its privileges.
- They are **trusted implicitly** by the rest of the organisation—whatever the pipeline signs and ships is presumed good—so tampering at this layer propagates silently.

## Why Does This Matter?

### Business Impact

- **Source and IP theft**: A reachable, weakly-authenticated SCM or CI console exposes the organisation's entire codebase and history.
- **Supply-chain compromise**: An attacker who controls build infrastructure can inject malicious code into artifacts that are then signed and distributed to every downstream customer.
- **Production breach**: CI systems hold deploy credentials; a compromised controller is frequently a direct path to production and to the cloud account behind it.
- **Cryptojacking and resource abuse**: Exposed, unauthenticated build consoles are routinely hijacked to run mining workloads on the organisation's compute.
- **Regulatory and contractual fallout**: Loss of source, secrets, or customer data through the build plane triggers the same breach-notification and compliance obligations as any other breach.

### Technical Impact

- **Remote code execution**: A script console (for example the Jenkins Groovy console), a vulnerable plugin, or an unpatched server flaw gives arbitrary execution on the controller or its agents.
- **Secret disclosure**: Verbose/debug modes, exposed system-info endpoints, and readable job configuration leak tokens, SSH keys, and credentials.
- **Build tampering**: Write access to job definitions or pipeline configuration lets an attacker alter what is built and shipped.
- **Lateral movement**: Runners on flat or shared networks let a foothold on one build reach other builds, internal services, and cloud metadata endpoints.
- **Persistence**: Attackers add plugins, credentials, webhooks, or scheduled jobs that survive a naive cleanup.

## Technical Context

### Common Insecure-Configuration Scenarios in CI/CD

#### 1. Unpatched CI Server or Vulnerable Plugins

```
# A controller advertising an old version invites catalogue exploitation:
X-Jenkins: 2.2xx.x            # version banner on every response
X-Jenkins-Session: ...

# Plugins are code inside the controller. An outdated plugin with a
# published advisory is exploited as-is, no application bug required.
Installed plugins: 180+   |   Updates available: dozens   |   Last update: >1yr
```

**Risk**: Known-vulnerable server or plugin versions are matched to public advisories and exploited directly. Plugin flaws are a classic and recurring source of CI-server compromise.

#### 2. Console / API Exposed to the Internet

```
https://jenkins.example.com/         # controller UI reachable from anywhere
https://gitlab.example.com/          # SCM open to the public internet
https://registry.example.com/v2/     # artifact registry API exposed
:8080 /:50000                        # Jenkins web + agent ports open
```

**Risk**: A management plane that should be internal is reachable by every scanner on the internet, turning any auth or patch gap into an immediate breach.

#### 3. Weak, Missing, or Anonymous Authentication

```
# Anonymous users granted read (or worse, build/configure):
Global security -> Authorization -> "Anyone can do anything"
Anonymous: Overall/Read, Job/Build, Job/Configure

# Or a shared/default admin account with a guessable password.
```

**Risk**: Anonymous or default access exposes job configuration, secrets, and build triggers to unauthenticated visitors.

#### 4. Script Console / Debug Modes Reachable

```
GET /script            # Jenkins Groovy console: arbitrary code on controller
GET /systemInfo        # environment, versions, sometimes secrets
DEBUG / --verbose      # pipeline logs echo full commands and injected secrets
```

**Risk**: An administrative script console reachable by an attacker is direct remote code execution; verbose logs leak secrets into build output.

#### 5. Self-Hosted Runners on Shared or Exposed Infrastructure

```
# Long-lived, non-ephemeral runner shared across untrusted jobs:
- one VM runs builds for many repos, including forks / PRs
- runner has broad cloud role attached (metadata reachable at 169.254.169.254)
- flat network: runner can reach production databases and other runners
```

**Risk**: A single poisoned build contaminates the shared host, harvests the next job's secrets, and pivots across a flat network.

#### 6. Permissive Webhooks and Integrations

```
POST /github-webhook/        # accepts events with no signature verification
- no shared-secret / HMAC validation
- no source-IP allow-list
- integration tokens scoped far beyond what the integration needs
```

**Risk**: Forged webhook events trigger builds or deployments; over-scoped integrations widen the blast radius of any single compromise.

### Layers Where Insecure Configuration Hides

| Layer | Typical Insecure Configuration | Consequence |
|-------|--------------------------------|-------------|
| SCM server (GitHub/GitLab/Bitbucket) | Public exposure, weak auth, permissive defaults | Source theft, tampering |
| CI server (Jenkins/TeamCity) | Unpatched core, vulnerable plugins, script console open | RCE on controller |
| Plugins / integrations | Excessive, unvetted, outdated | Expanded attack surface, known-CVE class |
| Runners / agents | Shared, long-lived, over-privileged, exposed | Secret theft, lateral movement |
| Network exposure | Consoles/APIs on the public internet | Anyone can probe the management plane |
| Transport / TLS | Cleartext console, expired/self-signed certs | Interception, credential theft |
| Baseline / drift | No benchmark, hand-tuned, undetected changes | Silent regression to insecure state |

## Real-World Impact

The incidents below are described as **classes of real, repeatedly-observed events** rather than specific named breaches with invented figures. Each is a pattern that security researchers and responders have documented many times.

### Incident Class 1: CI-Server Plugin Vulnerability Chain

**Configuration weakness**:
- A self-hosted CI controller (Jenkins is the canonical example) runs a large set of community plugins, many outdated.
- Patching of the core and plugins lags well behind published security advisories.

**Attack**:
- An attacker fingerprints the controller version and installed plugins, matches them to a published advisory, and exploits a vulnerable plugin to read files, bypass authentication, or execute code on the controller.
- From the controller they harvest stored credentials and pivot to production and cloud accounts.

**Root cause**: Excessive plugin surface plus slow patching. Plugin vulnerabilities are one of the most frequently advisory-published classes in the CI ecosystem precisely because each plugin is unreviewed code running with the controller's privileges.

### Incident Class 2: Internet-Exposed, Unauthenticated Build Console

**Configuration weakness**:
- A CI console or its script/API surface is reachable directly from the internet, with anonymous access enabled or authentication weak or absent.

**Attack**:
- Automated scanners locate the exposed console. An attacker reaches an administrative script console (or triggers a build) and executes arbitrary commands on the build infrastructure.
- Outcomes range from cryptomining on the organisation's compute to theft of the secrets the CI system stores.

**Root cause**: A management plane placed on the public internet with no network control and inadequate authentication—the CI-plane equivalent of leaving an admin dashboard open.

### Incident Class 3: Shared Self-Hosted Runner Compromise

**Configuration weakness**:
- A non-ephemeral, self-hosted runner is shared across many jobs—including untrusted pull-request or fork builds—and carries a broad cloud role on a flat network.

**Attack**:
- A malicious change (or a poisoned dependency) executes on the shared runner, persists on the host, and captures secrets and artifacts from subsequent jobs.
- The runner's cloud role and network reach are abused to move laterally toward production.

**Root cause**: Runners treated as durable pets rather than isolated, ephemeral, least-privilege workers.

## Prevalence and Detectability

Insecure System Configuration is recognised across the industry as one of the **most common and most easily discovered** weaknesses in CI/CD environments, for the same reasons it dominates the general misconfiguration category: it spans many independently-configured systems, each shipping defaults tuned for ease of setup rather than safety.

Rather than cite specific percentages (which vary by source and year), the durable and defensible picture is:

- Exposed CI/SCM consoles and unauthenticated build endpoints are **routinely found by internet-wide scanners**; the management plane is a standing target.
- Vulnerable-plugin and outdated-server findings are **among the most frequently published advisory classes** in the CI ecosystem.
- The impact is rated **severe**: outcomes commonly reach remote code execution on build infrastructure, secret theft, and supply-chain tampering—not merely information disclosure.

> Note: exact counts and rankings differ between reports and years. Treat any single figure as illustrative; the durable takeaway is that CI/CD systems are common, high-value, and easily located targets whose insecure defaults are cheap to exploit.

## Common Misunderstandings

### Myth 1: "The CI server is internal, so its configuration doesn't matter"

**Reality**: "Internal" build systems are reached constantly through VPN pivots, SSRF, compromised dependencies executing on runners, and simple misrouting. And many are not actually internal—consoles believed to be private are frequently found directly on the internet.

### Myth 2: "More plugins mean more capability, which is good"

**Reality**: Every plugin is unreviewed code running inside the controller with its privileges. Plugin vulnerabilities are one of the most common CI-compromise vectors; unused plugins are pure attack surface.

### Myth 3: "We hardened the server once, so it's fine"

**Reality**: Hand-tuned systems drift. New plugins, changed authorization strategies, and forgotten debug flags reopen holes. Only a codified baseline with drift detection keeps a system hardened over time.

### Myth 4: "Self-hosted runners are just build boxes, low risk"

**Reality**: A shared, long-lived runner with a broad role on a flat network is one poisoned build away from harvesting every subsequent job's secrets and pivoting to production.

### Myth 5: "The script console is an admin tool, attackers can't reach it"

**Reality**: An administrative script console reachable by anyone who reaches the console is remote code execution. Combined with anonymous access or weak auth, it is trivially abused.

### Myth 6: "Webhooks are harmless notifications"

**Reality**: Unauthenticated webhooks let an attacker forge events that trigger builds or deployments. Without signature validation and a source allow-list, the webhook endpoint is an unauthenticated trigger into your pipeline.

## How Insecure System Configuration Differs from Related CI/CD Risks

| Aspect | Insecure System Config (CICD-SEC-7) | Credential Hygiene (CICD-SEC-6) | Poisoned Pipeline Execution (CICD-SEC-4) |
|--------|-------------------------------------|---------------------------------|------------------------------------------|
| **Root cause** | Insecure settings/posture of CI/CD systems | Mishandled secrets and tokens | Attacker-controlled steps run in the pipeline |
| **Where it lives** | Server, plugin, runner, and network config | Secret storage, scope, and rotation | Pipeline definitions and build input |
| **Typical fix** | Patch, harden, restrict exposure, isolate runners | Scope, vault, and rotate secrets | Isolate untrusted input, review pipeline changes |
| **Detection** | Benchmark/config scan, exposure scan, patch audit | Secret scanning, access review | Pipeline review, runner isolation checks |

## Key Takeaways

1. **The pipeline is production infrastructure**—the CI/CD systems deserve the same hardening, patching, and network discipline as any production service.
2. **Defaults are for setup, not safety**—anonymous access, open consoles, and verbose modes must be explicitly changed.
3. **Minimise the plugin and integration surface**—each addition is unreviewed code with the controller's privileges.
4. **Never expose the management plane**—consoles and APIs belong behind a VPN or IP allow-list with strong authentication.
5. **Harden repeatably**—codify configuration against a vendor benchmark and detect drift, because hand-tuned systems silently regress.

## How to Identify if You're Vulnerable

- [ ] Are the CI/SCM servers and all installed plugins patched promptly against advisories?
- [ ] Are the console and API reachable only via VPN or an IP allow-list, never the open internet?
- [ ] Is anonymous access disabled and SSO + MFA enforced on every admin surface?
- [ ] Have unused plugins and integrations been removed, and remaining ones vetted and pinned?
- [ ] Is the script console (or equivalent) unreachable by non-administrators?
- [ ] Are self-hosted runners ephemeral, isolated, least-privilege, and off flat/production networks?
- [ ] Is TLS enforced everywhere with valid certificates (no cleartext consoles)?
- [ ] Do webhooks validate signatures and restrict source, with least-scope integration tokens?
- [ ] Is debug/verbose output disabled in production so logs cannot leak secrets?
- [ ] Is the configuration codified against a benchmark, with drift detection and regular review?

If you answered "no" or "not sure" to several of these, your build plane likely has exploitable insecure configuration today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers find and exploit insecure CI/CD system configuration
- **[Prevention](prevention.md)**: Build a repeatable, hardened baseline for SCM, CI, runners, and network
- **[Examples](examples.md)**: Insecure vs. secure configuration for GitHub, GitLab, Jenkins, and runners
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP Top 10 CI/CD Security Risks lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
