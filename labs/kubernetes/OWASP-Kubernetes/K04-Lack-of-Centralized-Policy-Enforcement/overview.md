# K04: Lack of Centralized Policy Enforcement - Overview

## Table of Contents
- [What is Lack of Centralized Policy Enforcement?](#what-is-lack-of-centralized-policy-enforcement)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Lack of Centralized Policy Enforcement?

**Lack of Centralized Policy Enforcement** is the absence of a consistent, automated control point that validates every workload against your security rules *before* it runs—and keeps validating as the cluster changes. Kubernetes will happily admit a container that runs as root, mounts the host filesystem, requests `privileged: true`, or pulls an unsigned image from an unknown registry. Nothing in a default cluster stops it. The guardrails only exist if *you* install and enforce them, uniformly, across every namespace and every cluster.

This is K04 in the OWASP Kubernetes Top 10. It is not a single misconfigured pod (that is K01) or an over-broad role (that is K03). It is the *meta*-failure: the reason those individual mistakes reach production is that no engine sits in the admission path saying "no." When enforcement is missing, inconsistent, or stuck in audit-only mode, security depends on every developer remembering every rule on every manifest—which never holds at scale.

### Core Concept

```
Centralized enforcement (healthy):
  Admission control -> a policy engine validates EVERY create/update
  Coverage          -> same rules apply to all namespaces + all clusters
  Mode              -> ENFORCE (deny), not just audit/warn
  Source of truth   -> policies live in Git, applied by GitOps
  Baseline          -> Pod Security Admission (restricted) as a floor
  Drift             -> continuous conformance scanning + reconciliation
  Failure mode      -> fail-closed: if the webhook is down, risky pods wait

No centralized enforcement (K04):
  Admission control -> none; the API server admits whatever is submitted
  Coverage          -> a few namespaces guarded, most wide open
  Mode              -> policies exist but only in "audit" / "warn"
  Source of truth   -> rules live in a wiki or a person's memory
  Baseline          -> PodSecurityPolicy was removed, nothing replaced it
  Drift             -> no scanning; configuration silently rots
  Failure mode      -> fail-open: risky pods sail through unchecked
```

### Why It's Critical for Kubernetes

Kubernetes is a declarative system where anyone with `create` on a workload resource can define exactly how their container runs—its privileges, its host access, its image, its network reach. That power is the platform's strength and its danger:

- The API server is **permissive by default**. Out of the box there is no gate that rejects a privileged pod, an unsigned image, or a `hostPath` mount.
- Workloads are **deployed continuously by many teams**, so "we review manifests by hand" does not scale and does not hold overnight, on-call, or during an incident.
- Clusters **multiply**—dev, staging, prod, per-region, per-team—and each one drifts unless a single policy source is applied to all of them.
- The **deprecation of PodSecurityPolicy** (removed in Kubernetes 1.25) left many clusters with a hole where their only built-in enforcement used to be.

## Why Does This Matter?

### Business Impact

- **Insecure workloads reach production undetected**: privileged, root, or host-mounting pods that should never have been admitted become the beachhead for a container escape and node compromise.
- **Inconsistent security posture**: one namespace is locked down, the next is wide open. Auditors, customers, and regulators see a control that is claimed but not uniformly applied.
- **Compliance findings**: frameworks such as PCI-DSS, SOC 2, HIPAA, and the CIS Kubernetes Benchmark expect demonstrable, enforced guardrails—not a document describing rules that nothing enforces.
- **Supply-chain exposure**: without image and registry policy, unsigned or untrusted images run freely, turning a poisoned dependency into a running workload.
- **Incident blast radius**: a single over-privileged pod that nothing blocked can become cluster-wide compromise, data theft, or cryptojacking.

### Technical Impact

- **Privilege escalation and container escape**: `privileged`, `hostPID`, `hostNetwork`, `allowPrivilegeEscalation`, or dangerous capabilities admitted with no check are direct escape primitives.
- **Node and cluster takeover**: a `hostPath` mount of `/` or the kubelet socket, admitted freely, hands an attacker the node and often the whole cluster.
- **Untrusted code execution**: unsigned images or images from arbitrary registries run because nothing validates provenance.
- **Configuration drift**: RBAC, network policy, and securityContext settings diverge from intent over time with no engine reconciling them back.
- **Undetected regression**: policies left in `audit` or `warn` generate logs nobody reads while insecure workloads keep running.

## Technical Context

### How Enforcement Is Supposed to Work

Every request to create or modify a resource passes through the Kubernetes API server's admission chain *after* authentication and authorization but *before* the object is persisted to etcd. Two kinds of admission webhooks are the leverage point for policy:

```
Request -> AuthN -> AuthZ (RBAC) -> Mutating admission -> Validating admission -> etcd
                                        |                      |
                                   (Kyverno /             (Kyverno /
                                    Gatekeeper            Gatekeeper /
                                    mutate, add           PSA reject
                                    defaults)             insecure specs)
```

**Validating** admission says yes or no. **Mutating** admission can also fix a manifest (for example, inject `runAsNonRoot: true` or drop capabilities) before it is stored. Centralized enforcement means a policy engine occupies this path for *all* workload-creating requests, cluster-wide. K04 is what you have when that seat is empty or only partly filled.

### The Building Blocks You Are Missing

| Control | What it does | Symptom when absent (K04) |
|---------|--------------|---------------------------|
| Pod Security Admission (PSA) | Built-in namespace labels enforcing `baseline`/`restricted` profiles | No baseline floor; privileged pods admitted |
| Policy engine (Kyverno / OPA Gatekeeper) | Validating + mutating webhooks for custom rules | No image, registry, label, or resource rules enforced |
| GitOps policy source | Policies as code, applied uniformly to every cluster | Rules differ per cluster; drift goes unnoticed |
| Conformance scanning | Continuous checks (kube-bench, Polaris, kubescape) | Existing violations never surfaced |
| Fail-closed webhook config | Deny admission if the policy engine is unreachable | Webhook outage silently disables all policy |

### The Ways Enforcement Goes Missing

#### 1. No admission controller at all
The cluster has no validating webhook inspecting workloads. The API server admits any well-formed manifest. Security relies entirely on developers self-policing their own YAML.

#### 2. PodSecurityPolicy removed, nothing put in its place
PSP was deprecated in 1.21 and removed in 1.25. Clusters that upgraded past 1.25 without adopting Pod Security Admission or a policy engine lost their only pod-level guardrail and often did not notice.

#### 3. Policies exist but only in "audit" / "warn"
Teams roll out policy in a non-blocking mode to avoid breaking deployments—then never flip it to `enforce`. Violations are logged (or shown as a warning the CI ignores) while insecure workloads keep running.

```
# PSA label that only warns/audits — does NOT block anything:
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
# Missing the line that actually enforces:
# pod-security.kubernetes.io/enforce: restricted
```

#### 4. Inconsistent coverage across namespaces and clusters
A policy engine is installed but only some namespaces are labeled, or policies are scoped to exclude "system" or "legacy" namespaces that then become the soft target. Prod is guarded; the forgotten `sandbox` namespace is not.

#### 5. Fail-open webhook configuration
A validating webhook with `failurePolicy: Ignore` means that if the policy pod is unhealthy, restarting, or its `namespaceSelector` excludes the request, the API server admits the workload with *no* policy check—so an outage becomes an enforcement bypass.

#### 6. No drift detection
Even with admission-time enforcement, resources changed out-of-band, pre-existing violations, or newly disclosed rules are never caught because nothing continuously scans the running cluster against the baseline.

## Real-World Impact

The incident *classes* below are well-documented patterns in the Kubernetes ecosystem. They are described generically—no fabricated CVEs, victims, or numbers—because the lesson is the pattern, not a headline.

### Incident Class 1: Exposed / Unauthenticated Management Plane Leading to Cryptojacking

**Pattern**: A Kubernetes dashboard, kubelet, or API endpoint is reachable without authentication, and the cluster has no admission policy restricting what workloads may run. An attacker (or an automated botnet) submits a pod that mines cryptocurrency, often requesting host access or privileged mode.

**Why K04 matters here**: even after the exposed endpoint is the entry point, a policy engine in enforce mode blocking privileged/host-mounting pods and untrusted images limits what the intruder can actually deploy. With no centralized enforcement, the attacker deploys whatever they like. This is the same management-plane-plus-no-guardrails shape seen in the well-publicised cloud Kubernetes console cryptomining cases.

### Incident Class 2: Container Escape via a Workload That Should Never Have Been Admitted

**Pattern**: A workload is deployed with `privileged: true`, a `hostPath` mount of a sensitive host directory, or `hostPID`. A vulnerability in the container—or simply the excess privilege itself—lets a process break out to the node, read other pods' secrets, or reach the kubelet credentials.

**Why K04 matters here**: none of these pod specs are subtle. A restricted Pod Security Admission profile, or a Kyverno/Gatekeeper rule forbidding privileged and host namespaces, rejects them at admission time. The escape is only possible because nothing enforced the rule that would have blocked the manifest.

### Incident Class 3: Supply-Chain / Untrusted-Image Execution

**Pattern**: A compromised or typosquatted image, or an image from an unapproved public registry, is deployed and runs malicious code inside the cluster. This is the recurring shape behind poisoned public images and dependency-confusion pulls.

**Why K04 matters here**: an admission policy that only allows images from approved, signed sources (verifying signatures with Kyverno/Cosign or a Gatekeeper external-data check) refuses the untrusted image. Without registry/signature enforcement, provenance is never checked and the malicious image runs.

### Incident Class 4: Silent Drift After PSP Removal

**Pattern**: A cluster that relied on PodSecurityPolicy is upgraded to Kubernetes 1.25+. PSP is gone. No Pod Security Admission labels or policy engine were adopted first. For weeks or months, workloads that PSP would have blocked are admitted freely, and nobody notices until an audit or an incident surfaces it.

**Why K04 matters here**: the loss of enforcement was invisible precisely because there was no continuous conformance scanning to say "the guardrail you think you have is gone."

## Prevalence and Detectability

Lack of centralized policy enforcement is one of the most **common** and most **consequential** issues in real clusters, because the default posture *is* the vulnerable one—a fresh Kubernetes cluster has no workload policy engine and, unless you label namespaces, no active Pod Security Admission enforcement.

Rather than cite precise figures (which vary by survey and year), the defensible picture is:

- Enforcement gaps are **highly prevalent**: many clusters run with no admission policy engine, or with one deployed only in audit mode.
- They are **easy to detect**: a single attempt to create a privileged pod, or a review of `ValidatingWebhookConfiguration` objects and namespace `pod-security.kubernetes.io/*` labels, reveals whether enforcement exists.
- The impact is rated **severe** because it is a force-multiplier: it is the reason the other Kubernetes Top 10 issues (insecure workloads, permissive RBAC, supply-chain flaws) actually reach production.

> Note: treat any single percentage as illustrative. The durable takeaway is that a default cluster ships without centralized workload enforcement, so the vulnerable state is the one you get unless you deliberately build the guardrails.

## Common Misunderstandings

### Myth 1: "Kubernetes blocks dangerous pods by default"

**Reality**: It does not. A default cluster admits `privileged: true`, `hostPath: /`, and unsigned images without complaint. Enforcement is opt-in—you must add Pod Security Admission labels and/or a policy engine.

### Myth 2: "We reviewed the manifests in code review, so we're covered"

**Reality**: Human review is not an admission controller. It is bypassed by direct `kubectl apply`, Helm installs, operators that create pods dynamically, and any manifest merged when the reviewer was tired. Only an engine in the admission path enforces on every request.

### Myth 3: "Our policies are in audit mode, that's basically enforcing"

**Reality**: Audit and warn *observe*; they never block. An insecure pod in an audit-only cluster still runs. Audit mode is a migration step, not a destination—the goal is `enforce`.

### Myth 4: "Pod Security Admission alone is enough"

**Reality**: PSA enforces the three standard profiles (privileged/baseline/restricted) at the pod level and is an excellent floor—but it cannot express custom rules like "only images from our registry," "every workload must set resource limits," "images must be signed," or "required team labels." A policy engine complements PSA; it does not replace the need for a floor.

### Myth 5: "One cluster is configured, so we're consistent"

**Reality**: Consistency is per-cluster and per-namespace unless policy is sourced from one place (GitOps) and applied to all of them. The unguarded staging cluster and the excluded `legacy` namespace are where attackers and accidents land.

### Myth 6: "The webhook is installed, so enforcement can't fail"

**Reality**: A webhook with `failurePolicy: Ignore` stops enforcing the moment the policy pod is unhealthy. If security matters, sensitive resources should fail *closed*—deny admission when the engine cannot be consulted.

## How K04 Differs from Neighbouring Kubernetes Risks

| Aspect | K04 Lack of Centralized Enforcement | K01 Insecure Workload Config | K03 Overly Permissive RBAC |
|--------|-------------------------------------|------------------------------|----------------------------|
| **Root cause** | No engine enforcing rules uniformly | A specific pod set up insecurely | Roles granting more than needed |
| **Nature** | Systemic / meta-control gap | Instance of a bad workload | Instance of over-broad access |
| **Typical fix** | Deploy PSA + policy engine in enforce mode | Fix the securityContext | Scope down the RoleBinding |
| **Relationship** | Its absence is why K01/K03 reach prod | Blocked by K04 enforcement | Constrained by K04 enforcement |

## Key Takeaways

1. **The default is the vulnerable state**—a fresh cluster has no workload policy engine and no active PSA enforcement.
2. **K04 is a force-multiplier**—its absence is the reason insecure workloads, permissive RBAC, and untrusted images actually run.
3. **Audit is not enforce**—a policy that only warns blocks nothing; the destination is `enforce` and fail-closed.
4. **Coverage must be uniform**—every namespace, every cluster, sourced from one place, or the gaps become the target.
5. **Enforcement plus scanning**—admission control stops new violations; continuous conformance scanning catches drift and pre-existing ones.

## How to Identify if You're Vulnerable

- [ ] Is there a validating admission webhook (Kyverno / OPA Gatekeeper) inspecting every workload create/update?
- [ ] Is Pod Security Admission set to `enforce` (not just `warn`/`audit`) on every namespace, with `restricted` or at least `baseline`?
- [ ] Are the same policies applied to *all* clusters and namespaces from a single Git source?
- [ ] Do policies actually block (enforce), or are they still in audit/warn?
- [ ] Are images restricted to approved registries and/or required to be signed?
- [ ] Are `privileged`, host namespaces, `hostPath`, and privilege escalation forbidden by policy?
- [ ] Are resource requests/limits and required labels enforced at admission?
- [ ] Do sensitive webhooks fail *closed* (`failurePolicy: Fail`) so an outage does not silently disable policy?
- [ ] Is there continuous conformance scanning (kube-bench, Polaris, kubescape) catching drift and pre-existing violations?
- [ ] After removing PodSecurityPolicy, did you adopt PSA or a policy engine *before* upgrading past 1.25?

If you answered "no" or "not sure" to several of these, insecure workloads can reach your clusters today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How the absence of enforcement is discovered and abused
- **[Prevention](prevention.md)**: Build uniform, fail-closed policy enforcement
- **[Examples](examples.md)**: No-policy cluster vs. Kyverno / Gatekeeper / PSA enforcing
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts hands-on
