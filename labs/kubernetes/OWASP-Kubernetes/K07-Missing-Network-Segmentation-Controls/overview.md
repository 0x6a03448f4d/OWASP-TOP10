# K07: Missing Network Segmentation Controls - Overview

## Table of Contents
- [What Are Missing Network Segmentation Controls?](#what-is-it)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Severity](#prevalence)
- [Common Misunderstandings](#common-misunderstandings)

## What Are Missing Network Segmentation Controls?

**Missing Network Segmentation Controls** (K07 in the OWASP Kubernetes Top 10) is the failure to restrict which pods, namespaces, and external endpoints can talk to one another. By default, a Kubernetes cluster is a **flat, fully-connected network**: every pod can open a connection to every other pod, in every namespace, on every port — and, in most default installs, out to the internet and the cloud provider's metadata service as well. Nothing about that traffic is authenticated, encrypted, or restricted unless you add controls.

This is not a bug in Kubernetes; it is the documented default. The Kubernetes networking model requires that "all pods can communicate with all other pods without NAT." Segmentation is *opt-in*: you must author `NetworkPolicy` objects (and run a CNI that enforces them), or add a service mesh, to carve that flat space into isolated zones. When teams skip that step, one compromised pod inherits the reachability of the entire cluster.

### Core Concept

```
Default cluster (flat network, no policy):

   [ frontend ]---+---[ payments-db ]      any pod can reach any pod,
        |         |                        any namespace, any port
        +---------+---[ admin-api ]
        |         |
        +---------+---[ kube-system pods ]  including the control plane's
        |         |                         service endpoints
        +---------+---> 169.254.169.254     cloud metadata / IMDS
        |         |
        +---------+---> 0.0.0.0/0            the entire internet (egress)

Segmented cluster (default-deny baseline + allow-list):

   [ frontend ] --allow--> [ orders-api ] --allow--> [ orders-db ]
        |                                                  ^
        X blocked: payments-db, admin-api, kube-system,    |
        X blocked: metadata endpoint, arbitrary internet   only this one flow
```

The distinction that defines K07 is **default-allow vs. default-deny**. A cluster with no policies is default-allow: everything is permitted, and an attacker who lands in any pod can immediately scan and reach everything else. A hardened cluster establishes a **default-deny baseline** per namespace (deny all ingress *and* egress), then explicitly allow-lists only the connections the application actually needs.

### What "Missing Segmentation" Actually Covers
- **No NetworkPolicies at all** — the cluster runs entirely default-allow.
- **No default-deny baseline** — a few allow rules exist, but anything not covered is still wide open, because policies are additive and only restrict pods they select.
- **No namespace isolation** — workloads in `team-a`, `team-b`, `prod`, and `dev` can freely reach across boundaries.
- **Unrestricted egress** — pods can reach the internet, the cloud metadata endpoint (`169.254.169.254`), other clusters, and internal management planes.
- **Exposed internal services** — databases, caches, admin APIs, and dashboards reachable from any pod rather than only their intended callers.
- **No identity between services** — no mTLS, so traffic is neither authenticated nor encrypted and any pod can impersonate a caller.
- **A CNI that does not enforce policy** — NetworkPolicy objects exist in the API but the network plugin silently ignores them, so the intended controls do nothing.

## Why Does This Matter?

Network segmentation is the control that **contains a breach**. Most other controls (image scanning, RBAC, admission policy) aim to *prevent* a compromise. Segmentation assumes prevention will sometimes fail and limits how far the attacker can travel afterward. Without it, the blast radius of a single vulnerable pod is the whole cluster.

### Business Impact
- **Unbounded blast radius**: A single compromised container — via a vulnerable web app, a poisoned dependency, or SSRF — can reach every database and service in the cluster. Containment failure turns an incident into a breach.
- **Cross-tenant and cross-environment data exposure**: In shared clusters, one tenant's or team's compromise reaches another's data because no boundary separates them.
- **Cloud account compromise**: Unrestricted egress lets a pod hit the instance metadata service and steal the node's cloud IAM credentials, escalating from "one container" to "the cloud account."
- **Regulatory exposure**: PCI-DSS, HIPAA, and similar frameworks explicitly require segmentation of sensitive workloads; a flat cluster undermines the scoping those regimes depend on.
- **Data exfiltration and C2**: Open egress gives malware a direct channel to command-and-control servers and to exfiltrate data to attacker-controlled endpoints.

### Technical Impact
- **Lateral movement (east-west)**: The attacker scans pod and service IPs, finds unauthenticated datastores and internal APIs, and pivots freely.
- **Reaching the control plane**: Pods can often reach the API server and node kubelets; combined with a token or an unauthenticated kubelet, that is a path to cluster takeover.
- **SSRF-to-IMDS credential theft**: The metadata endpoint at `169.254.169.254` is reachable from pods by default, turning any SSRF or in-pod foothold into cloud credential theft.
- **No traffic authenticity**: Without mTLS, services trust whatever connects to them on the network; an attacker in the cluster can impersonate any client.
- **Silent policy failure**: If the CNI does not enforce NetworkPolicy, the security team believes segmentation exists while the network remains flat.

## Technical Context

### Why the Default Is Flat

Kubernetes deliberately delegates networking to a **CNI (Container Network Interface) plugin** and mandates only one thing: pods must be able to reach each other directly. Whether that reachability can be *restricted* depends entirely on the plugin. Some plugins enforce `NetworkPolicy`; some historically did not. This is why "we wrote policies" and "our traffic is actually restricted" are two different claims.

```
NetworkPolicy is an API object; enforcement lives in the CNI.

  kube-apiserver  ->  stores the NetworkPolicy object
        (no enforcement here)
  CNI data plane  ->  MUST translate the policy into real filtering
        Calico / Cilium / others: enforce
        a plugin without policy support: object is inert, network stays flat
```

### How NetworkPolicy Behaves (and Surprises People)
- **Additive, allow-only**: Policies only *add* allowed connections. There is no "deny" rule; you create a deny effect by selecting pods with a policy that permits nothing.
- **Selection flips the default**: A pod not selected by *any* policy is fully open. The moment a pod is selected by a policy for a direction (ingress/egress), everything not explicitly allowed in that direction is denied.
- **Per-namespace**: Policies are namespaced. A default-deny baseline must be applied in *every* namespace, including new ones.
- **Ingress and egress are separate**: Denying ingress does nothing to stop a pod reaching out. Egress controls (metadata, internet, other namespaces) require explicit egress policies.

### The Metadata Endpoint Problem

```
# From inside almost any pod on a default cloud cluster:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# -> returns the node instance role name
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# -> returns temporary AccessKeyId / SecretAccessKey / Token for the NODE role
```

**Risk**: The link-local metadata address is reachable from pods unless egress is restricted. On clusters that do not enforce IMDSv2 or block pod access to metadata, this converts an application-level SSRF (or any code execution in a pod) into theft of the node's cloud credentials, which are often far more privileged than the workload should be.

### Where Segmentation Fails in Practice

| Gap | Typical Cause | Consequence |
|-----|---------------|-------------|
| No policies at all | Segmentation never adopted; "it works without it" | Full flat network, unrestricted lateral movement |
| No default-deny | Only a few allow rules; unselected pods stay open | Most traffic still unrestricted |
| Namespaces not isolated | No cross-namespace deny; shared cluster | Cross-tenant / cross-env reachability |
| Egress unrestricted | Only ingress considered | Metadata theft, C2, exfiltration |
| Internal services exposed | DB/cache/admin reachable cluster-wide | Direct data access after any foothold |
| No mTLS | No service identity layer | Impersonation, sniffing, spoofed callers |
| CNI ignores policy | Plugin without enforcement installed | Policies are inert; false sense of safety |

## Real-World Impact

The incident *classes* below are well-documented patterns. They are described generically rather than tied to fabricated numbers or CVE identifiers.

### Incident Class 1: Compromised Pod to Cloud Credentials via Metadata

**Pattern**:
- An internet-facing workload is compromised (application vulnerability, SSRF, or a vulnerable dependency).
- Because egress is unrestricted, the attacker's code in the pod reaches `169.254.169.254` and pulls the node's IAM credentials.
- Those credentials — often broader than the workload needs — are used to access cloud storage, other services, and sometimes to widen access across the account.

**Root Cause**: No egress policy blocking the metadata endpoint, combined with an over-privileged node role and metadata service defaults that allow simple retrieval. This class is the Kubernetes-native version of the classic SSRF-to-metadata cloud breach pattern.

### Incident Class 2: Cryptomining Worm Spreading Across a Flat Cluster

**Pattern**:
- An attacker gains initial execution in one pod (exposed service, weak credential, or a supply-chain payload).
- On a flat network with no policies, the payload scans internal ranges, finds additional reachable pods, unauthenticated Kubelets, or exposed datastores, and spreads.
- Compute is hijacked for cryptomining and the foothold is used to reach further internal services.

**Root Cause**: No default-deny baseline and no namespace isolation, so a single foothold enjoyed cluster-wide reachability. Publicly analyzed Kubernetes-targeting malware families have repeatedly relied on exactly this flat-network reachability to move laterally.

### Incident Class 3: Cross-Tenant Reach in a Shared Cluster

**Pattern**:
- Multiple teams or customers share one cluster, separated only by namespace, with no NetworkPolicy between namespaces.
- A compromise (or even a misbehaving service) in one namespace reaches services and databases belonging to another.

**Root Cause**: Namespaces provide an RBAC and naming boundary, **not** a network boundary. Without cross-namespace deny policies (or a mesh enforcing identity), tenant isolation on the network simply does not exist.

### Incident Class 4: Direct Datastore Access After a Foothold

**Pattern**:
- A front-end pod is compromised. The database was reachable from any pod, not only the API tier that legitimately uses it.
- The attacker connects straight to the datastore — often with weak or default auth — and reads or wipes data.

**Root Cause**: Internal services exposed cluster-wide with no ingress policy limiting callers to their intended clients. This mirrors the broader "unauthenticated datastore reachable on a flat network" class seen across cloud and container environments.

## Prevalence and Severity

Missing segmentation is one of the **most common** Kubernetes weaknesses precisely because it is the default state — a cluster is unsegmented until someone does work to change it, and many clusters never do.

The defensible picture, without inventing statistics:
- A brand-new cluster with a policy-capable CNI still has **zero enforced segmentation** until policies are written; the safe state is opt-in.
- The most commonly observed sub-issues are **no default-deny baseline, no egress restrictions, and no namespace isolation**.
- Severity is rated **high** as an impact multiplier: segmentation rarely causes the initial breach, but its absence is what turns a contained incident into a cluster-wide or cloud-account compromise.

> Note: treat any single percentage you see quoted as illustrative. The durable, source-independent truth is that Kubernetes networking is flat by default, so unsegmented clusters are common and their compromises escalate far beyond the initial foothold.

## Common Misunderstandings

### Myth 1: "Namespaces isolate workloads"
**Reality**: Namespaces isolate names and are an RBAC boundary. On the network they are transparent — pods in different namespaces reach each other by default. Network isolation requires NetworkPolicy or a mesh.

### Myth 2: "We have NetworkPolicies, so we're segmented"
**Reality**: Policies are additive and only affect pods they select. Without a *default-deny* baseline in every namespace, every unselected pod is still fully open. And if the CNI does not enforce policy, the objects do nothing at all.

### Myth 3: "Ingress rules are enough"
**Reality**: Blocking who can reach a pod does nothing about where that pod can go. Metadata theft, C2, and exfiltration are all *egress*. Segmentation needs both directions.

### Myth 4: "Internal traffic is trusted, so we don't need mTLS"
**Reality**: "Inside the cluster" is not a trust boundary once any pod can be compromised. Without mTLS, services accept traffic from anything that can route to them and cannot tell a legitimate caller from an attacker.

### Myth 5: "The cloud firewall / security groups already segment us"
**Reality**: Node-level firewalls see node IPs, not pod-to-pod traffic, most of which never leaves the node or rides an overlay the firewall cannot inspect. Pod-level segmentation must be enforced by the CNI or mesh, not the VPC.

### Myth 6: "Restricting egress will break everything"
**Reality**: Default-deny egress with an explicit allow-list (DNS, required APIs, needed dependencies) is entirely workable and is the norm in mature clusters. The work is enumerating real flows once; the payoff is blocking metadata theft and exfiltration permanently.

## How K07 Relates to Other Kubernetes Risks

| Aspect | K07 Missing Segmentation | K03 Overly Permissive RBAC | K01 Insecure Workload Config |
|--------|--------------------------|-----------------------------|-------------------------------|
| **Boundary** | The network (who can connect to whom) | The API (who can call the control plane) | The pod (privileges, capabilities) |
| **Failure** | Flat, default-allow network | Excess API permissions | Privileged/root containers |
| **Fix** | Default-deny + allow-list, mesh mTLS | Least-privilege roles | Restrict securityContext |
| **Main effect** | Contains lateral movement | Contains API abuse | Contains pod escape |

## Key Takeaways

1. **The default is flat and default-allow** — every pod can reach every pod, the metadata endpoint, and the internet until you restrict it.
2. **Segmentation is the containment control** — it decides whether one compromised pod is an incident or a cluster-wide breach.
3. **Default-deny beats a handful of allow rules** — without a deny baseline in every namespace, unselected pods stay wide open.
4. **Egress matters as much as ingress** — blocking `169.254.169.254` and arbitrary internet access stops credential theft and exfiltration.
5. **A policy is only real if the CNI enforces it** — and mTLS adds the identity layer the network alone cannot provide.

## How to Identify if You're Vulnerable

Ask these questions about your cluster:
- [ ] Does every namespace have a **default-deny ingress and egress** baseline?
- [ ] Does your CNI actually **enforce** NetworkPolicy (Calico, Cilium, or equivalent)?
- [ ] Can a test pod reach `169.254.169.254` or arbitrary internet hosts right now?
- [ ] Are databases and internal APIs restricted to only their intended callers?
- [ ] Is there any policy preventing pods in one namespace from reaching another?
- [ ] Is service-to-service traffic authenticated and encrypted (mTLS)?
- [ ] Are new namespaces segmented automatically, or do they start wide open?
- [ ] Do you monitor and alert on unexpected pod-to-pod or egress flows?

If you answered "no" or "not sure" to several of these, your cluster is likely running flat today, and any single compromised pod can reach far more than it should.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers pivot across a flat cluster
- **[Prevention](prevention.md)**: Build a default-deny, allow-listed segmentation baseline
- **[Examples](examples.md)**: Insecure vs. secure NetworkPolicy, namespace isolation, and egress control
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
