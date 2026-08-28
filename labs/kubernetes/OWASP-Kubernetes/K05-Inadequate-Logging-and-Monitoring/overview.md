# K05: Inadequate Logging and Monitoring - Overview

## Table of Contents
- [What is Inadequate Logging and Monitoring?](#what-is-inadequate-logging-and-monitoring)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Inadequate Logging and Monitoring?

**Inadequate Logging and Monitoring** (K05 in the OWASP Kubernetes Top 10) is the condition of running a cluster that cannot *see itself being attacked*. The controls that would record who did what to the API server, what processes ran inside containers, and which network flows crossed the cluster are either switched off, configured too coarsely, never collected centrally, or collected but never alerted on. The vulnerability is not a single exploitable bug—it is a **detection gap** that lets every other weakness be exploited quietly.

A Kubernetes cluster is a distributed control system with many independent sources of security-relevant signal: the API server (every `create`, `exec`, `delete`, and secret read), the kubelet on each node, the container runtime, the workloads themselves, the network layer, and the underlying cloud control plane. Each of these can emit an audit trail—but only if it is explicitly enabled, routed somewhere durable, and watched. When any link in that chain is missing, an attacker's actions leave no trace an operator will ever read.

> K05 is a **meta-weakness**. It rarely causes the breach; it determines whether you notice the breach in minutes, in months, or never. Dwell time—the interval between compromise and detection—is the metric this control governs.

### Core Concept

```
Cluster that can see itself:
  API audit      -> audit policy logs metadata for all verbs,
                    RequestResponse for exec/secrets/RBAC changes
  Runtime        -> Falco / Tetragon watch for shell-in-container,
                    sensitive mounts, unexpected privilege escalation
  Workload logs  -> pod stdout/stderr shipped off-node before the pod dies
  Aggregation    -> all sources centralized in tamper-resistant storage
  Alerting       -> high-risk events page a human / open a case
  Retention      -> logs kept long enough to investigate (weeks to months)

Cluster that is blind (K05):
  API audit      -> audit logging disabled, or Metadata-only and unread
  Runtime        -> no runtime sensor; a reverse shell in a pod is invisible
  Workload logs  -> logs live only on the node and vanish when the pod restarts
  Aggregation    -> nothing shipped off-cluster; an attacker can delete it
  Alerting       -> nobody is paged; dashboards exist but no one watches
  Retention      -> logs rotate in hours, gone before an investigation starts
```

### Why It's Critical for Kubernetes

Kubernetes concentrates several conditions that make a detection gap especially costly:

- It is a **high-value, multi-tenant control plane**. A single API server mediates access to every workload, secret, and node—so a single unlogged action (an `exec` into a pod, a secret read) can be the whole breach.
- Workloads are **ephemeral**. A compromised pod may live for seconds; if its logs and process events are not shipped off-node in real time, the evidence is destroyed by the platform itself when the pod is rescheduled.
- It is **API-driven and scriptable**, so reconnaissance and lateral movement happen at machine speed. Without automated alerting, humans cannot keep pace.
- It sits on a **cloud control plane** with its own audit trail (IAM, node metadata, managed control-plane logs) that must also be collected—an attacker who pivots between the two planes escapes detection in the gap between them.

## Why Does This Matter?

### Business Impact

- **Undetected breach / long dwell time**: Attackers operate for weeks or months, escalating and exfiltrating, because nothing records or flags their activity.
- **No forensic trail**: After an incident is finally noticed, there are no logs to reconstruct scope, so the organisation cannot tell what was accessed and must assume the worst.
- **Cryptojacking and cost blow-out**: Attacker-deployed miners consume compute silently; the first "alert" is a cloud bill, not a security event.
- **Regulatory and contractual exposure**: Frameworks such as PCI-DSS, HIPAA, SOC 2, and ISO 27001 explicitly require audit logging and monitoring; their absence is a finding in its own right and worsens breach-notification obligations.
- **Failed incident response**: Even a well-drilled IR team is helpless without telemetry; mean-time-to-detect and mean-time-to-respond both collapse when the data does not exist.

### Technical Impact

- **Silent privilege escalation**: RBAC changes, new `ClusterRoleBindings`, and service-account token minting happen with no record.
- **Invisible container escape / runtime abuse**: A shell spawned in a container, a sensitive host path mounted, or a kernel capability abused leaves no trace without a runtime sensor.
- **Unnoticed data access**: Secret reads, ConfigMap dumps, and volume access are indistinguishable from normal traffic when audit logging is off.
- **Tamper without trace**: Logs kept only on the compromised node can be deleted by the attacker, so even existing evidence is destroyed.
- **Broken correlation**: Without time synchronisation and centralised aggregation, events from different nodes and the cloud plane cannot be stitched into a single timeline.

## Technical Context

### The Signal Sources a Cluster Should Capture

| Source | What it records | Typical K05 failure |
|--------|-----------------|---------------------|
| API server audit log | Every request: who, verb, resource, response | Disabled, or Metadata-only and never read |
| Runtime sensor (Falco/Tetragon) | Process exec, syscalls, mounts, network in containers | Not deployed; runtime activity invisible |
| Pod / container logs | Application stdout/stderr | Never shipped off-node; lost on pod restart |
| kubelet / node logs | Node-level events, image pulls, evictions | Not collected centrally |
| Cloud control-plane audit | Managed API-server / IAM activity | Not enabled or not forwarded to SIEM |
| Admission / policy logs | Denied and allowed admission decisions | Webhook audit annotations dropped |

### Common K05 Failure Modes

#### 1. API-server audit logging disabled or too coarse

```
# The kube-apiserver is started with NO audit policy:
#   (no --audit-policy-file / --audit-log-path flags)
# Result: no record of exec, secret reads, RBAC changes, or deletes.

# Or a policy that only captures the "None"/"Metadata" level for
# everything, so a secret read is logged as "someone read a secret"
# with no indication of which secret, or not logged at all.
```

**Risk**: The single richest security signal in Kubernetes—the API audit trail—does not exist or is too shallow to investigate with.

#### 2. No runtime threat detection

```
# No Falco, Tetragon, or equivalent DaemonSet on the nodes.
# A reverse shell inside a running container:
kubectl exec -it web-7f9 -- /bin/sh
#   -> produces an API audit event (if audit is on) but NO
#      process-level evidence of what the shell then did.
```

**Risk**: Post-exploitation activity inside containers—spawning shells, reading `/etc/shadow`, mounting the host, launching a miner—is completely invisible.

#### 3. Logs not centralized or tamper-resistant

```
# Pod logs exist only via `kubectl logs`, backed by files on the node:
#   /var/log/pods/<ns>_<pod>_<uid>/<container>/0.log
# When the pod is deleted/rescheduled, the files rotate away.
# An attacker with node access can simply delete them.
```

**Risk**: Evidence is stored on the very asset the attacker controls, and disappears with normal pod churn.

#### 4. No alerting on high-risk events

```
# Audit logs are collected and sit in an index nobody queries.
# There is no rule that says:
#   "page on-call when a ClusterRoleBinding grants cluster-admin"
#   "alert when a pod is created with hostPID/privileged:true"
#   "alert on image pulls from an unknown registry"
# Detection exists in theory; response never happens.
```

**Risk**: Collection without alerting is a filing cabinet nobody opens—detection latency is effectively infinite.

#### 5. No retention or time synchronisation

```
# Logs rotate after a few hours or a day of volume.
# Node clocks drift; events from node-a and node-b cannot be
# ordered against the cloud audit trail.
# By the time an incident is noticed, the relevant window is gone
# or cannot be correlated.
```

**Risk**: Even where data was captured, it is unusable for an investigation that starts days or weeks later.

## Real-World Impact

The incidents below are described as **classes of real, well-documented events** rather than specific numbered advisories. In each, the underlying compromise was made far worse—or was only possible to sustain—because detection was inadequate.

### Case Class 1: Exposed Dashboard to Cryptomining (Cloud-Native Cryptojacking)

**Pattern**:
- An administrative interface or the Kubernetes API is reachable without authentication, or a workload is compromised through an application flaw.
- The attacker deploys mining pods, often disguised with innocuous names, and scales them across the cluster.

**Why K05 made it worse**: With no runtime detection and no alerting on unusual image pulls or CPU patterns, the mining workloads ran until an operator happened to notice cost or performance degradation—typically long after deployment. The Tesla cloud-cryptojacking incident (2018) is the archetypal public example: an unauthenticated Kubernetes dashboard led to mining workloads running inside the environment.

### Case Class 2: Long-Dwell Data Exfiltration via Service-Account Tokens

**Pattern**:
- A workload is compromised; the attacker reads the automatically-mounted service-account token and uses it to query the API server, read secrets, and enumerate the cluster.
- The stolen token is used steadily over a long period to pull data.

**Why K05 made it worse**: Because API-server audit logging was off (or Metadata-only and unmonitored), the anomalous use of a service-account token from a workload that normally never talks to the API server generated no alert. The activity blended into normal control-plane traffic and continued undetected.

### Case Class 3: Worming Malware Across Misconfigured Clusters

**Pattern**:
- Self-propagating malware (the class exemplified by campaigns such as Hildegard, Kinsing, and TeamTNT tooling) targets exposed kubelets, Docker APIs, and Kubernetes API servers to gain a foothold, then spreads laterally and installs miners and credential stealers.

**Why K05 made it worse**: These campaigns specifically thrive in environments with no runtime monitoring. The tell-tale behaviours—new binaries executing in containers, outbound connections to mining pools and C2, disabling of security agents—are exactly what a Falco/Tetragon rule would catch, and exactly what goes unseen when no such sensor exists.

### Case Class 4: Insider or Credential Abuse of the Control Plane

**Pattern**:
- A valid but over-privileged credential (a leaked kubeconfig, a CI token, or an insider) is used to create privileged pods, bind cluster-admin, or read secrets at scale.

**Why K05 made it worse**: Nothing distinguished the malicious use from legitimate administration because RBAC changes and privileged-pod creation were not audited or alerted on. The absence of a baseline of "normal" made the abuse invisible.

> **Common thread**: In none of these classes did inadequate logging *cause* the initial compromise. In all of them it converted a contained incident into a sustained, expensive, and hard-to-scope breach.

## Prevalence and Detectability

Inadequate logging and monitoring is consistently among the **hardest weaknesses to notice from the inside**, because the symptom of the problem is *the absence of symptoms*. A cluster with no audit logging looks perfectly healthy right up until an external party reports the breach.

Rather than cite precise figures (which vary by survey and year), the defensible picture is:

- Managed Kubernetes distributions historically shipped with **API audit logging off or minimal by default**; enabling and tuning it is an explicit operator action that is frequently skipped.
- Runtime threat detection (Falco/Tetragon) is an **opt-in add-on**, so a large share of clusters run with no process-level visibility at all.
- Where logs *are* collected, the most common gaps are **no alerting, short retention, and no off-cluster/tamper-resistant storage**—collection without the controls that make it useful.

> Note: exact percentages differ between reports. The durable takeaway is that detection controls are opt-in, commonly skipped, and—because their absence is silent—rarely discovered until an incident forces the question.

## Common Misunderstandings

### Myth 1: "The cloud provider logs everything for us"

**Reality**: Managed control planes expose *some* audit data, but it is frequently off by default, may not include the API audit trail at a useful level, and never covers in-container runtime behaviour. Node-level and workload telemetry are the customer's responsibility under the shared-responsibility model.

### Myth 2: "We have `kubectl logs`, so we have logging"

**Reality**: `kubectl logs` reads files on the node that rotate and vanish when the pod restarts. It is a debugging convenience, not a durable, tamper-resistant, centralised audit trail. It also captures only application stdout—not API activity or process events.

### Myth 3: "Metrics and dashboards mean we're monitored"

**Reality**: CPU and memory graphs are operational monitoring, not security monitoring. They may hint at cryptomining after the fact, but they do not record who did what, and a dashboard nobody watches raises no alert.

### Myth 4: "Audit logging is too noisy/expensive to enable"

**Reality**: A well-designed audit policy logs metadata cheaply for routine traffic and full request/response only for sensitive verbs (exec, secret access, RBAC changes). Cost is a tuning problem, not a reason to run blind.

### Myth 5: "If we ever get breached, we'll turn on logging then"

**Reality**: Logging is only useful for events that were captured *while they happened*. Enabling it after an incident tells you nothing about what already occurred; the forensic window is already gone.

### Myth 6: "Collecting the logs is the hard part"

**Reality**: Collection is necessary but insufficient. Without *alerting*, *retention*, *tamper-resistance*, and *time synchronisation*, a mountain of logs still yields zero detection and an unusable investigation.

## How K05 Differs from Related Kubernetes Weaknesses

| Aspect | K05 Inadequate Logging & Monitoring | K01 Insecure Workload Config | K03 Overly Permissive RBAC |
|--------|-------------------------------------|------------------------------|----------------------------|
| **Root cause** | Detection controls off/unwatched | Unsafe pod/container settings | Excessive granted permissions |
| **What it enables** | Attacks go unnoticed | Escape / privilege abuse | Unauthorized cluster actions |
| **Symptom** | Silence (no alerts, no trail) | Privileged/hostPath pods | Broad verbs on many resources |
| **Typical fix** | Audit policy, runtime sensor, SIEM, alerting | Harden pod spec / policy | Least-privilege roles |

K05 is the control that lets you *see* the others being exploited. A cluster can have excellent RBAC and hardened workloads and still be breached; without logging and monitoring, it will not know.

## Key Takeaways

1. **K05 is a detection gap, not a single bug**—it governs whether every other weakness is exploited quietly or caught quickly.
2. **Kubernetes has many signal sources**—API audit, runtime, workload, node, and cloud—and each must be explicitly enabled and routed.
3. **Ephemeral workloads destroy evidence**—telemetry must be shipped off-node in real time or it is lost to normal pod churn.
4. **Collection is not detection**—alerting, retention, tamper-resistance, and time sync turn logs into an actual defence.
5. **The absence of the control is silent**—you will not notice you are blind until an incident forces the question, so enable it before you need it.

## How to Identify if You're Vulnerable

- [ ] Is API-server audit logging enabled with a reviewed audit policy (not off, not None-everywhere)?
- [ ] Does the policy capture `RequestResponse` for sensitive verbs (exec, secret access, RBAC changes)?
- [ ] Is a runtime sensor (Falco, Tetragon, or equivalent) deployed on every node?
- [ ] Are pod/container logs shipped off-node before the pod can be deleted?
- [ ] Are all sources centralised in tamper-resistant, off-cluster storage?
- [ ] Is there alerting on high-risk events (privileged pods, cluster-admin binds, odd registries, exec into pods)?
- [ ] Is the cloud control-plane audit trail collected and correlated with cluster logs?
- [ ] Are logs retained long enough (weeks to months) to investigate a late-discovered incident?
- [ ] Are node clocks synchronised so events can be ordered into one timeline?
- [ ] Are alerts wired into an incident-response process that a human actually receives?

If you answered "no" or "not sure" to several of these, an attacker in your cluster today would likely operate undetected.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: The attacker activity that goes unnoticed when detection is inadequate
- **[Prevention](prevention.md)**: Build audit, runtime, aggregation, and alerting into the cluster
- **[Examples](examples.md)**: Insecure vs. secure audit policy, Falco rules, and pipelines
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
