# CICD-SEC-8: Ungoverned Usage of 3rd Party Services - Overview

## Table of Contents
- [What is Ungoverned Usage of 3rd Party Services?](#what-is-ungoverned-usage-of-3rd-party-services)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Ungoverned Usage of 3rd Party Services?

**Ungoverned Usage of 3rd Party Services** is the risk that arises when your CI/CD ecosystem depends on a large number of external services and integrations that are granted access to your source code, build systems, and secrets—*with little to no governance* over who they are, what they can do, or whether they are still needed. It is not a single vulnerability in your code; it is the accumulated, unmonitored trust you have extended to third parties whose security posture you neither control nor observe.

Modern pipelines are assembled from services that plug straight into the source control management (SCM) system and the CI platform: third-party GitHub/GitLab Apps, OAuth integrations, marketplace CI plugins, reusable Actions authored by strangers, SaaS tools wired in through tokens and webhooks, and bots that open, review, and merge pull requests. Each connection is easy to add—often a single "Authorize" click—and each typically requests broad, standing access. The result is a sprawling web of external identities with keys to your kingdom, and no one maintaining the guest list.

> **The core problem is a trust-and-visibility gap:** access is granted quickly and broadly, but rarely inventoried, scoped down, reviewed, or revoked. A compromise of any one of those third parties can cascade directly into your pipeline—this is a supply-chain-of-services risk, distinct from the supply-chain-of-dependencies risk of vulnerable packages.

### Core Concept

```
Governed third-party usage:
  Inventory     -> every App / OAuth / token / webhook is catalogued and owned
  Onboarding    -> new integrations pass an approval + security review
  Scope         -> least privilege: minimum repos, minimum permissions, read-only where possible
  Pinning       -> third-party Actions/plugins pinned to a full commit SHA
  Allow-list    -> org policy restricts which Actions/marketplace apps can run at all
  Review        -> periodic access review; unused integrations removed
  Monitoring    -> third-party activity is logged and alerted on
  Blast radius  -> assume the 3rd party WILL be breached; limit what it can reach

Ungoverned third-party usage:
  Inventory     -> no one knows the full list of who-has-access
  Onboarding    -> any developer can authorize any App/integration at will
  Scope         -> broad org-wide, read/write access granted "to be safe"
  Pinning       -> Actions referenced by mutable tag (@v1, @main) from unknown authors
  Allow-list    -> any Action or marketplace app in the world is allowed to run
  Review        -> permissions granted once, in 2021, never looked at again
  Monitoring    -> third-party API calls are invisible in your logs
  Blast radius  -> one breached SaaS vendor reads all your source and secrets
```

### Why It's Critical for CI/CD

CI/CD concentrates several conditions that make ungoverned third-party usage especially damaging:

- The pipeline is the **most privileged automation you own**—it holds cloud deploy credentials, signing keys, registry tokens, and read/write access to every repository. A third party granted access inherits a slice of that power.
- Integrations are **trivial to add and invisible to remove**. Authorizing an OAuth app or installing a marketplace Action takes seconds; nothing forces anyone to ever revisit it.
- Access is **standing and long-lived**. Unlike a human session, an App installation or personal access token keeps working silently for years, across staff turnover.
- The trust is **transitive**. You did not vet the third party's own suppliers, their build system, or their employees—yet a breach of any of them becomes a breach of you.

## Why Does This Matter?

### Business Impact

- **Source Code Theft**: An over-scoped App or OAuth integration with `repo` read access can clone your entire private codebase—including intellectual property and secrets committed by mistake.
- **Secret & Credential Exfiltration**: Third parties that run inside builds can read environment variables, CI secrets, and cloud tokens, handing an attacker the keys to production.
- **Supply-Chain Compromise of Your Product**: An integration with write access can inject malicious code or tamper with artifacts, so *your* customers are attacked through *your* pipeline.
- **Cascading Vendor Breach**: When a connected SaaS provider is breached, every customer who granted broad tokens is breached in turn—often before anyone knows the vendor was hit.
- **Compliance & Contractual Exposure**: Unknown third parties touching regulated data or production systems undermine SOC 2, ISO 27001, and vendor-risk obligations, and complicate breach notification.

### Technical Impact

- **Unauthorized Repository Access**: Read access enables full source exfiltration; write access enables commit injection, branch/tag manipulation, and release tampering.
- **Pipeline Code Injection**: A malicious or compromised reusable Action/plugin executes in your runner with access to the workspace, secrets, and the runner's token.
- **Token Abuse & Lateral Movement**: An abused OAuth token or App credential is used to enumerate organizations, discover more secrets, and pivot to connected cloud accounts.
- **Persistence**: Attackers add their own webhooks, deploy keys, or App installations so access survives a password reset—standing third-party trust is an ideal hiding place.
- **Loss of Auditability**: With no inventory or monitoring, third-party actions blend into normal automation, so the intrusion is discovered late, if at all.

## Technical Context

### The Kinds of Third Parties in a Pipeline

| Category | Examples (generic) | Access it typically obtains |
|----------|--------------------|-----------------------------|
| SCM Apps / OAuth integrations | Code-quality bots, security scanners, project-management sync, chat integrations | Repo read/write, org membership, PR/issue access, webhooks |
| Marketplace CI plugins | Jenkins/GitLab/CircleCI plugins, orb/extension registries | In-process execution on the CI controller and agents |
| Reusable Actions / shared pipeline steps | Third-party GitHub Actions, GitLab includes, community templates | Code execution in the runner, access to workspace + secrets + job token |
| SaaS tools via tokens/webhooks | Coverage services, deploy platforms, notification services, artifact scanners | Long-lived API tokens, inbound/outbound webhooks, upload endpoints |
| Bots & automation accounts | Dependency-update bots, auto-mergers, release bots | Standing credentials able to push, approve, or merge |

### Common Ungoverned-Usage Scenarios

#### 1. Over-scoped SCM App or OAuth integration

```
Requested permissions (as shown on the "Authorize" screen):
  Repositories:  All repositories        # not just the one that needs it
  Contents:      Read and write          # a read-only scanner asking for write
  Secrets:       Read                    # rarely necessary for the stated feature
  Members:       Read                    # org-wide membership visibility
  Webhooks:      Read and write          # can add its own persistence

One click grants ALL of the above, org-wide, indefinitely.
```

**Risk**: The integration—or anyone who compromises it—can read and modify every repository and enumerate the whole organization.

#### 2. Third-party Action referenced by a mutable tag

```yaml
# .github/workflows/build.yml  (dangerous)
steps:
  - uses: some-user/awesome-action@v2      # tag can be moved to new code anytime
  - uses: another/great-step@main          # HEAD of a repo you do not control
```

**Risk**: A tag or branch is mutable. If the author (or an attacker who takes over the author's account) repoints `v2` to malicious code, your very next build executes it—with your secrets in scope.

#### 3. SaaS tool wired in with a broad, long-lived token

```
# CI secret handed to an uploader/scanner service
THIRD_PARTY_TOKEN = ghp_************************   # full repo scope, no expiry
# The service also stores YOUR token on ITS servers.
```

**Risk**: The vendor now holds a powerful credential to your systems. If the vendor is breached, so are you—this is the Codecov-class scenario (see Real-World Impact).

#### 4. No inventory of who-has-access

```
Question: "List every external App, OAuth grant, deploy key, webhook, and
           bot with access to our repos and CI, who owns each, and why."
Reality:   No one can answer. Grants accumulated across years and teams.
```

**Risk**: You cannot govern what you cannot see. Unused and forgotten grants are the ones attackers love—no one will notice them being abused.

### Why the Attack Surface Explodes

Each new integration adds not just its own risk but the risk of everything *it* depends on. A single reusable Action may itself call other Actions; a SaaS vendor may sub-process to further vendors. Trust is transitive and multiplicative:

```
Your pipeline
   └─ trusts SaaS vendor A (holds your repo token)
        └─ trusts its own CI and 12 npm dependencies
   └─ trusts Action B@v1 (runs in your runner)
        └─ internally calls Action C@main (author unknown)
             └─ downloads a helper script from a URL at runtime

A compromise ANYWHERE in this tree can reach your secrets.
```

## Real-World Impact

The incidents below are described as **classes of incident**. They reflect well-documented, repeatedly observed patterns; specific vendor names are used only where the pattern is publicly and widely associated with them, and no invented figures are presented.

### Case Study 1: Compromised CI/CD SaaS Uploader (the "Codecov-class")

**Situation**:
- A widely used third-party SaaS tool that runs inside customers' CI pipelines (a coverage/artifact uploader is the canonical example) had one of its distribution mechanisms tampered with.
- Because customers invoked the tool during builds and handed it access to the build environment, the modified tool could read environment variables and secrets present in those pipelines.

**Impact**:
- Secrets, tokens, and credentials exposed in the CI environment of many downstream organizations could be exfiltrated—without any of those organizations being individually targeted or breached first.
- A single compromised third party became a mass-scale secret-harvesting event across its customer base.

**Root Cause**: A third-party service was granted routine, broad access to build environments and secrets, with no isolation or scoping to limit blast radius—so its compromise cascaded straight into every customer's pipeline.

### Case Study 2: OAuth Token Abuse Against SCM Repositories (the "GitHub-OAuth-token-abuse class")

**Situation**:
- Third-party integrations authorized against an SCM platform hold OAuth tokens or App credentials that can read (and sometimes write) private repositories.
- In this class of incident, attackers obtained tokens issued to popular third-party integrations and used them to clone private repositories of organizations that had authorized those integrations.

**Impact**:
- Private source code was downloaded from numerous organizations using the stolen integration tokens—the victims had authorized a legitimate integration, but the token became an attacker's skeleton key.
- Downloaded source was then mined for additional secrets to enable deeper compromise.

**Root Cause**: Broad, standing OAuth/App access granted to third parties, combined with no expectation that the third party could be breached and no scoping to limit which repositories a single grant could reach.

### Case Study 3: Malicious or Hijacked Marketplace Component (the "typosquat/takeover class")

**Situation**:
- Reusable Actions, CI plugins, and pipeline templates are pulled from public marketplaces where anyone can publish, and are commonly referenced by mutable tags.
- In this class, a component is either malicious from the start (name resembling a trusted one) or a legitimate component whose maintainer account is taken over and whose existing tag is repointed to malicious code.

**Impact**:
- Pipelines that referenced the component by a moving tag executed attacker-controlled code on their next run, exposing the runner's secrets and workspace and enabling artifact tampering.

**Root Cause**: Ungoverned adoption of third-party components—no vetting of the author, no pinning to an immutable commit, and no org-level allow-list restricting which components may run.

## Prevalence and Detectability

Ungoverned Usage of 3rd Party Services is characterised in the OWASP Top 10 CI/CD Security Risks as a widespread and structurally hard-to-see problem. Because integrations are added continuously by many people, and because platforms make granting access frictionless, most organizations accumulate far more third-party trust than they can account for.

Rather than cite precise counts (which vary by organization and are not meaningfully comparable), the defensible picture is:

- The number of connected Apps, OAuth grants, tokens, webhooks, and reusable components in a mature organization is typically **large and under-inventoried**.
- The dominant failure modes are **over-scoping** (broad access granted "to be safe"), **no lifecycle** (never reviewed or revoked), and **no pinning/allow-listing** of executable components.
- The impact is rated **high**: a single compromised third party can reach source code and secrets across many repositories at once.

> Note: the durable takeaway is not a statistic but a posture. Assume you have more third-party access granted than you can list, that some of it is over-scoped and unused, and that at least one of those third parties will eventually be breached. Govern accordingly.

## Common Misunderstandings

### Myth 1: "It's a reputable vendor, so it's safe"

**Reality**: Reputation does not prevent breach. The most damaging third-party incidents involved popular, trusted tools precisely because they were widely deployed. Trust the vendor's intentions if you like; still limit what a compromise of them can reach.

### Myth 2: "We only granted read access, so the worst case is minor"

**Reality**: Read access to source code is read access to any secrets committed by mistake, your internal architecture, and the exact material an attacker needs to plan the next move. Read-only is safer than write, but "read all repositories" is still a serious grant.

### Myth 3: "An Action pinned to `@v2` is a pinned Action"

**Reality**: A tag is a mutable pointer. The author—or whoever compromises the author—can move `v2` to new code at any time, and your next build runs it. Only a full commit SHA is immutable.

### Myth 4: "We authorized it once and reviewed it then, so we're covered"

**Reality**: Governance is a lifecycle, not an event. Scopes broaden over time, the integration's own code changes, staff leave, and needs disappear—while the grant keeps working. Access must be re-reviewed and stale grants revoked on a schedule.

### Myth 5: "There's no inventory because we don't use many integrations"

**Reality**: Almost every organization underestimates its count. Bots, OAuth grants from personal accounts, per-repo webhooks, deploy keys, and transitively-invoked Actions add up quickly. The absence of an inventory is evidence of the risk, not of its absence.

### Myth 6: "Secrets in CI are protected, so a third party running in the build can't read them"

**Reality**: Anything that executes inside a job runs with the same access as the job—it can read the environment, the mounted secrets, and the runner's token. "Secret" means "not printed in logs", not "invisible to code running in the pipeline".

## How This Differs from Related CI/CD Risks

| Aspect | Ungoverned 3rd Party Services (CICD-SEC-8) | Poisoned Pipeline Execution (CICD-SEC-4) | Vulnerable/Compromised Dependencies |
|--------|--------------------------------------------|------------------------------------------|-------------------------------------|
| **Root cause** | Broad, unmanaged trust granted to external services/integrations | Attacker influences the pipeline definition/execution flow | A software package you build with is vulnerable or malicious |
| **Where it lives** | Apps, OAuth grants, tokens, webhooks, marketplace components | Pipeline config, scripts, triggerable jobs | Package manifests / lockfiles |
| **Typical fix** | Inventory, least-privilege, pin, allow-list, review, revoke | Isolate execution, control who can change pipeline code | Pin, verify, scan, update dependencies |
| **Detection** | Access review, integration inventory, third-party activity monitoring | Pipeline change review, runner isolation | SCA, provenance/signature checks |

## Key Takeaways

1. **Third-party services are a first-class attack surface**—every App, OAuth grant, token, and reusable component is a door into your pipeline.
2. **Broad, standing access is the core failure**—grants are made once, over-scoped, and never reviewed.
3. **Trust is transitive**—a breach of any third party (or its suppliers) cascades into you.
4. **You cannot govern what you cannot see**—an inventory of who-has-access is the foundation of every other control.
5. **Assume breach and limit blast radius**—least privilege, pinning, allow-listing, and monitoring turn a vendor compromise from catastrophe into a contained event.

## How to Identify if You're Vulnerable

- [ ] Can you produce a current inventory of every third-party App, OAuth grant, token, webhook, deploy key, and bot with access to your repos and CI?
- [ ] Does each of those have a named owner and a documented reason to exist?
- [ ] Is there an approval + security review step before a new integration can be connected?
- [ ] Are integration scopes least-privilege (specific repos, read-only where possible) rather than org-wide read/write?
- [ ] Are all third-party Actions/plugins pinned to a full commit SHA (not a mutable tag or branch)?
- [ ] Does an org policy restrict which Actions/marketplace apps are allowed to run at all?
- [ ] Are integration tokens short-lived or rotated, and scoped to the minimum needed?
- [ ] Do you periodically review access and revoke unused or stale integrations?
- [ ] Is third-party activity (App/token API calls, webhook deliveries) logged and alertable?
- [ ] Have you designed for "the third party is breached"—is the blast radius of any single grant limited?

If you answered "no" or "not sure" to several of these, you likely have ungoverned third-party access being abused or waiting to be.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers abuse over-scoped and compromised third parties
- **[Prevention](prevention.md)**: Inventory, scope, pin, allow-list, review, and monitor
- **[Examples](examples.md)**: Ungoverned vs. governed integrations side by side
- **[CI/CD Security Track](/learn/cicd)**: Continue with the rest of the OWASP CI/CD Top 10
- **[Practice](/practice)**: Apply these controls in hands-on exercises
