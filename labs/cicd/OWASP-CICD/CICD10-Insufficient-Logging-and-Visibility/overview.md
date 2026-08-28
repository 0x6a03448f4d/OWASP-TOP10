# CICD-SEC-10: Insufficient Logging and Visibility - Overview

## Table of Contents
- [What is Insufficient Logging and Visibility?](#what-is-insufficient-logging-and-visibility)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Insufficient Logging and Visibility?

**Insufficient Logging and Visibility** is the tenth risk in the OWASP Top 10 CI/CD Security Risks. It describes a CI/CD environment that **lacks the logging, monitoring, and detection needed to notice an attack in the pipeline**. The vulnerability is not a single misconfigured switch—it is the absence of the telemetry and alerting that would let a defender see tampering, credential abuse, or misuse of the build and delivery system while it is happening, or reconstruct it afterwards.

A CI/CD system is a chain of independently operated tools: the source-code management (SCM) platform, the CI/CD orchestrator, package and container registries, artifact stores, secrets managers, and the cloud accounts that pipelines deploy into. Each of these produces its own audit trail—when it is turned on. When those trails are disabled, too coarse, siloed in separate consoles, never centralised, never correlated, never alerted on, and never retained, an attacker can move through the pipeline without ever tripping a signal. The build and deploy machinery, which holds the keys to production, becomes a blind spot.

> **The core idea:** the danger of CICD-SEC-10 is not that an attack succeeds—every other CI/CD risk covers a way in—but that the attack *proceeds undetected*. Pipeline tampering, secret access, new tokens, and unusual deploys all leave traces; insufficient logging and visibility means nobody is collecting, correlating, or watching those traces.

### Core Concept

```
Sufficient Visibility (defender can see the pipeline):
  Audit logs   -> enabled across SCM, CI, registry, artifact store, cloud
  Centralised  -> all toolchain logs shipped to one SIEM / log platform
  Correlated   -> a commit, a build, a token use, and a deploy can be joined
  Alerting     -> high-risk pipeline events page a human in near real time
  Retention    -> tamper-resistant, long enough for investigation
  Runners      -> process, network, and file activity on build agents captured
  Baseline     -> "normal" pipeline behaviour is known; anomalies stand out

Insufficient Visibility (attacker moves in the dark):
  Audit logs   -> disabled or too coarse in SCM / CI / registry
  Centralised  -> each tool logs to its own console, nobody aggregates
  Correlated   -> no way to tie a config change to the identity that made it
  Alerting     -> no alerts on secret access, new tokens, off-hours deploys
  Retention    -> days or none; logs rotated away before an incident is noticed
  Runners      -> no visibility into what a build job actually did
  Baseline     -> no notion of normal, so nothing ever looks abnormal
```

### Why It's Critical for CI/CD

CI/CD pipelines concentrate several conditions that make missing visibility especially damaging:

- The pipeline is a **privileged, trusted path to production**. Whoever controls a build controls what ships—so an undetected intruder here is far more dangerous than one on a single application server.
- It is **highly automated and high-volume**. Thousands of legitimate builds, deploys, and token uses each week give malicious actions ideal cover; a single hostile job blends into the noise unless you can distinguish it.
- It is **fragmented across many vendors**. No single console shows the whole story, so an attack that touches SCM, then CI, then the registry, then cloud is invisible unless the logs are pulled together.
- Its **changes are self-erasing by design**. Pipelines are ephemeral—runners are destroyed after each job, logs rotate—so evidence that was never captured is gone for good.

## Why Does This Matter?

### Business Impact

- **Undetected Supply-Chain Compromise**: A poisoned build or backdoored artifact can be signed, published, and distributed to every downstream consumer before anyone realises the pipeline was touched.
- **Prolonged Dwell Time**: With no alerting, an intruder can persist in the CI/CD environment for weeks or months, expanding access at leisure—the interval between compromise and discovery is exactly what visibility shortens.
- **Failed Incident Response**: When a breach is finally suspected, the absence of retained, correlated logs means responders cannot answer "what did the attacker do, what did they take, and what did they ship?"—turning a contained incident into an open-ended crisis.
- **Regulatory and Contractual Exposure**: Frameworks such as SOC 2, PCI-DSS, SSDF, and SLSA expect auditable records of who changed and deployed code. Missing trails cause audit findings and undermine breach notifications.
- **Erosion of Software Trust**: If you cannot prove what your pipeline did, you cannot prove your releases are clean—damaging customer and downstream trust after any incident.

### Technical Impact

- **Silent Pipeline Tampering**: Edits to pipeline definitions, build scripts, or CI configuration execute with no record of who changed what, when.
- **Invisible Credential Abuse**: Access to secrets, and use of pipeline tokens and service accounts, leaves no monitored trace—so stolen credentials are used freely.
- **Unnoticed Identity Sprawl**: New service accounts, personal access tokens, deploy keys, and webhooks are created by an attacker for persistence without triggering any review.
- **Undetected Exfiltration from Runners**: Build agents reach out to attacker infrastructure to leak secrets or source, and the network egress is never captured or examined.
- **Broken Reconstruction**: Even where some logs exist, the lack of correlation and short retention makes it impossible to stitch events into a timeline after the fact.

## Technical Context

### What Should Be Logged Across the Toolchain

Visibility is only as good as its weakest link. An attack that pivots from SCM to CI to registry to cloud is only reconstructable if *every* stage produces and forwards security-relevant events.

| System | Security-relevant events to capture | What its absence hides |
|--------|-------------------------------------|------------------------|
| SCM (GitHub/GitLab/Bitbucket) | Pushes, branch/tag changes, protection-rule edits, permission and membership changes, new deploy keys/PATs, webhook edits, workflow file changes | Who changed the code, the branch rules, or the automation—and who was granted access |
| CI/CD orchestrator | Pipeline definition changes, job triggers (esp. from forks), runner registration, secret/variable access, plugin/integration changes, manual overrides | What ran, why, on whose behalf, and with what secrets |
| Artifact / package registry | Pushes and pulls, tag mutation/overwrite, retention/immutability changes, new publish tokens, signing events | Whether a published artifact was replaced or a malicious version slipped in |
| Secrets manager / vault | Secret reads, policy changes, new leases, failed access attempts | Which credentials were accessed, by which identity, and when |
| Cloud / deploy targets | Deployments, IAM and role changes, new keys, off-hours or out-of-pipeline actions | What was actually pushed to production and by which path |
| Build runners / agents | Process execution, outbound network connections, filesystem writes, unexpected tool installs | What a build job did beyond its declared steps—including exfiltration |

### The Failure Modes of CICD-SEC-10

#### 1. Audit Logging Disabled or Too Coarse

SCM and CI platforms often ship with security audit logging off, restricted to higher tiers, or limited to a few event types. The pipeline runs, but the record of *who did what* is never generated.

#### 2. Logs Not Centralised Across the Toolchain

```
SCM audit log      -> only visible in the SCM admin console
CI job logs        -> only visible in the CI UI, per-project
Registry events    -> only in the registry's own audit view
Cloud trail        -> only in the cloud provider console
# Nobody is looking at all four together, so a cross-tool attack is invisible.
```

Each tool has a log; none of them is aggregated. An attacker who touches several tools leaves a trail that no single console reveals.

#### 3. No Correlation

Even when logs are collected, they use different identity models, timestamps, and identifiers. Without correlation you cannot answer "which commit triggered which build, which used which token, which deployed what?"—the events exist but cannot be joined into a story.

#### 4. No Alerting on Security-Relevant Pipeline Events

Logs are written but never watched. A pipeline-config change at 3 a.m., a first-ever secret access by a service account, or a new admin token generates no alert, so discovery depends on someone happening to look.

#### 5. Short or No Retention

Runner logs vanish when the ephemeral agent is torn down; CI logs rotate after days; free tiers retain audit events briefly. By the time an incident is suspected, the evidence has aged out.

#### 6. Mutable Logs

If the same identities that operate the pipeline can also edit or delete its logs, an attacker who gains that access simply erases their own trail. Logs that are not write-once and off-host are not trustworthy evidence.

#### 7. No Runner Visibility

Build jobs frequently run arbitrary code (tests, build scripts, dependencies). Without process- and network-level monitoring on runners, a job that quietly curls a secret to an external host looks identical to a normal build.

#### 8. No Baseline of Normal Behaviour

Without a model of normal pipeline behaviour—who deploys, when, how often, to where—nothing ever looks abnormal. Anomaly detection is impossible if "normal" was never characterised.

## Real-World Impact

The incidents below are described as **classes of real events** rather than specific attributed breaches. They illustrate how missing pipeline visibility turns a contained problem into a prolonged one.

### Case Study Class 1: Supply-Chain Build Compromise Discovered Downstream

**Pattern**:
- An attacker gains a foothold in a build or release pipeline and modifies the build process so that published artifacts are backdoored, while source in the repository looks clean.
- The malicious artifacts are signed and distributed through normal channels to many downstream consumers.

**Why visibility mattered**: In this class of incident the tampering is frequently discovered not by the origin organisation's own monitoring but by an external party noticing anomalous behaviour in the shipped product. Insufficient logging of the build environment and its runners meant the producing organisation could not detect the modification at the source, and later struggled to reconstruct exactly which builds were affected.

### Case Study Class 2: Stolen CI/CD Token Used Undetected

**Pattern**:
- A long-lived CI token, personal access token, or deploy key is leaked (in logs, a repo, or a third-party breach) and used by an attacker to clone private repositories or push changes.

**Why visibility mattered**: Because token usage was not monitored and no baseline of normal access existed, the anomalous cloning and access continued without alerting anyone. Organisations in this class typically learn of the abuse only when the attacker acts overtly or a third party reports it—long after the credential was first misused.

### Case Study Class 3: Poisoned Fork-PR Workflow

**Pattern**:
- A pull request from a fork triggers a CI workflow that runs attacker-influenced code with access to secrets or a privileged runner (the Poisoned Pipeline Execution class).

**Why visibility mattered**: With no alerting on fork-triggered workflow runs and no runner egress monitoring, the malicious job's outbound connection and secret access blended into ordinary CI traffic. The absence of correlated logs meant that, even after suspicion arose, defenders could not easily prove what the job exfiltrated.

### Common Root Cause

Across these classes the root cause is the same: the CI/CD environment produced too little trustworthy, centralised, correlated telemetry for anyone to notice the attack in progress or reconstruct it afterwards. Every one of these attacks generated events—a config change, a token use, an outbound connection, an artifact overwrite—that a well-instrumented pipeline would have surfaced.

## Prevalence and Detectability

Insufficient Logging and Visibility is best understood as a **force multiplier** for every other CI/CD risk rather than a standalone exploit. It is what determines whether an attack is caught in minutes or discovered months later by an outsider.

Rather than cite precise figures (which vary by source and year), the defensible picture is:

- Pipeline telemetry is **frequently incomplete**: audit logging is commonly disabled or gated behind higher product tiers, and runner-level activity is rarely captured at all.
- Cross-tool **centralisation and correlation are the exception, not the norm**—most teams have per-tool consoles but no unified pipeline view.
- The impact is characterised by **long dwell time and difficult reconstruction**: the harm is measured not in the initial compromise but in how long it goes unnoticed and how much cannot be explained afterwards.

> Note: exact percentages and dwell-time figures differ between reports. Treat any single figure as illustrative; the durable takeaway is that pipeline visibility is commonly insufficient, and that insufficiency is what lets CI/CD attacks succeed quietly.

## Common Misunderstandings

### Myth 1: "Our CI tool already keeps job logs, so we have logging"

**Reality**: Job console output is for debugging builds, not detecting attacks. It is per-project, not centralised, rarely retained, usually mutable, and contains none of the SCM/registry/cloud events an attacker touches. Build logs are not an audit trail.

### Myth 2: "The pipeline is internal, so we don't need to monitor it"

**Reality**: The pipeline is the most privileged internal system you own—it can ship code to production. Internal systems are reached through stolen tokens, poisoned dependencies, and fork PRs. An unmonitored pipeline is a blind spot at the exact point of greatest leverage.

### Myth 3: "We'll turn on detailed logging if we ever have an incident"

**Reality**: Logging is retrospective. If it was not enabled and retained *before* the incident, the evidence does not exist. You cannot investigate events that were never recorded, and ephemeral runners guarantee the data is already gone.

### Myth 4: "We collect everything, so we're covered"

**Reality**: Collection without correlation and alerting is a data lake nobody swims in. If no rule fires on a pipeline-config change or a new admin token, the events sit unread. Visibility means *noticing*, not merely storing.

### Myth 5: "Logs in the same system that runs the pipeline are fine"

**Reality**: If the identities that operate the pipeline can also alter or delete its logs, an attacker who compromises the pipeline erases the trail. Security logs must be shipped off-host to storage the pipeline cannot modify.

### Myth 6: "Cloud audit logging covers the whole pipeline"

**Reality**: Cloud trails capture what reached the cloud, not what happened in SCM, CI, or the registry beforehand. An attack that tampers with a build never appears in the cloud log as anything but a normal deploy. Every stage needs its own instrumentation.

## How CICD-SEC-10 Relates to the Other CI/CD Risks

| Aspect | Insufficient Logging & Visibility (CICD-SEC-10) | Poisoned Pipeline Execution (CICD-SEC-04) | Insufficient Credential Hygiene (CICD-SEC-06) |
|--------|--------------------------------------------------|-------------------------------------------|-----------------------------------------------|
| **Nature** | Inability to *detect* or reconstruct an attack | A way for attackers to *run* code in the pipeline | A way for attackers to *obtain* credentials |
| **Root cause** | Missing/siloed/unmonitored telemetry | Untrusted input reaching build execution | Poorly managed, over-scoped, long-lived secrets |
| **Effect if unaddressed** | Other attacks proceed unnoticed | Arbitrary code runs with pipeline privileges | Secrets are abused, often silently |
| **Typical fix** | Enable, centralise, correlate, alert, retain | Isolate and restrict untrusted execution | Rotate, scope, shorten, and vault secrets |

CICD-SEC-10 is the risk that decides whether the other nine are *caught* or *missed*. Strong controls elsewhere still fail quietly without visibility to confirm they held.

## Key Takeaways

1. **Visibility spans the whole toolchain**—SCM, CI, registries, artifact stores, secrets managers, cloud, and runners—not just one console.
2. **The harm is undetected dwell time**—the vulnerability is measured in how long an attack goes unnoticed and how little can be reconstructed.
3. **Collection is not detection**—logs must be centralised, correlated, and alerted on to matter.
4. **Logs must outlive the runner and resist tampering**—ephemeral agents and short retention destroy evidence; mutable logs let attackers erase it.
5. **You must know normal to spot abnormal**—a baseline of pipeline behaviour is the foundation of anomaly detection.

## How to Identify if You're Vulnerable

Ask these questions about your CI/CD environment:

- [ ] Is security audit logging enabled in your SCM, CI/CD orchestrator, and registries—not just build/job logs?
- [ ] Are logs from all of those tools plus your cloud and secrets manager centralised into one SIEM or log platform?
- [ ] Can you correlate a commit, the build it triggered, the secret it used, and the deploy it produced?
- [ ] Do you alert on pipeline-config changes, secret access, new tokens/service accounts, permission changes, and off-hours or fork-triggered runs?
- [ ] Do you have any visibility into what runners actually do (processes and outbound network), or only their console output?
- [ ] Are security logs stored off-host, write-once, and retained long enough to investigate a months-old incident?
- [ ] Have you established a baseline of normal pipeline behaviour so anomalies stand out?
- [ ] Are pipeline security alerts wired into your incident-response process?

If you answered "no" or "not sure" to several of these, an attacker could operate in your pipeline today without being noticed.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How pipeline attacker activity proceeds undetected
- **[Prevention](prevention.md)**: Enable, centralise, correlate, and alert across the toolchain
- **[Examples](examples.md)**: Insecure vs. secure logging and alerting configuration
- **[CI/CD Security Track](/learn/cicd)**: Return to the full OWASP CI/CD Top 10
- **[Practice](/practice)**: Test your understanding with hands-on challenges
