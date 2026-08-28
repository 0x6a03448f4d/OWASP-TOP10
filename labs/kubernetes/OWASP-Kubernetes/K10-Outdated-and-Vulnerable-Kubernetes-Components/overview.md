# K10: Outdated and Vulnerable Kubernetes Components - Overview

## Table of Contents
- [What are Outdated and Vulnerable Components?](#what-are-outdated-and-vulnerable-components)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)
- [How to Identify if You're Vulnerable](#how-to-identify-if-youre-vulnerable)

## What are Outdated and Vulnerable Components?

**K10: Outdated and Vulnerable Kubernetes Components** is the final entry in the OWASP Kubernetes Top 10. It covers a simple but stubborn failure: running Kubernetes itself, its add-ons, or the underlying node operating system and container runtime at versions that carry *known*, publicly documented vulnerabilities—or that have passed end-of-support and no longer receive security fixes at all. The weakness is not a subtle logic flaw you have to discover; it is a published advisory with a patch already available, applied everywhere except your cluster.

A Kubernetes cluster is not one program—it is a stack of independently versioned components that each ship on their own release cadence. The control plane (API server, scheduler, controller-manager, etcd), the per-node kubelet and kube-proxy, the container runtime (containerd, CRI-O, or legacy Docker/dockershim), the CNI network plugin, CSI storage drivers, the ingress controller, the metrics and dashboard add-ons, service-mesh sidecars, and the node OS kernel are all moving parts. Every one of them accrues CVEs over time. K10 is the accumulated gap between the versions that have been patched upstream and the versions actually running in your cluster.

### Core Concept

```
A maintained cluster:
  Kubernetes version   -> within the supported release window (N, N-1, N-2)
  Version skew         -> kubelet no more than 3 minors behind API server
  Container runtime    -> containerd/CRI-O patched, dockershim removed
  Node OS / kernel     -> supported release, security updates applied
  Add-ons              -> ingress, CNI, CSI, dashboard, mesh all current
  CVE tracking         -> subscribed to k8s security-announce feed
  Inventory            -> every component + version known and owned
  Upgrade cadence      -> regular, tested, automated where possible

An outdated cluster (K10):
  Kubernetes version   -> end-of-life, no more patches, months/years behind
  Version skew         -> kubelet/API server outside the supported skew
  Container runtime    -> unpatched runc/containerd with escape advisories
  Node OS / kernel     -> EOL distro, kernel with public LPE exploits
  Add-ons              -> ingress controller / dashboard with known RCE
  CVE tracking         -> nobody watches advisories for the k8s stack
  Inventory            -> "we're not sure what version that is"
  Upgrade cadence      -> "if it isn't broken, don't touch it"
```

### Why It's Its Own Category

Kubernetes deserves a dedicated "outdated components" entry—separate from generic application-dependency risk—for reasons specific to how clusters are built and operated:

- **The stack is deep and multi-vendor**. Patching your application image does nothing for a vulnerable kubelet, a runc escape, or an ingress controller CVE. Each layer is owned and upgraded differently.
- **Version skew is a hard constraint**. Kubernetes only supports a narrow gap between control-plane and node versions. Falling behind is not just risky—it eventually blocks you from upgrading at all without a disruptive jump.
- **End-of-life arrives fast**. Upstream Kubernetes supports roughly the three most recent minor releases. A cluster left alone for a year is already unsupported and no longer receiving security patches.
- **The components sit at the trust boundary**. The kubelet, API server, runtime, and ingress controller are exactly the surfaces an attacker targets to break out of a container or take over a node. A CVE here is frequently a direct path to code execution or privilege escalation.

## Why Does This Matter?

### Business Impact
- **Exploitation by catalogue**: Once a component's version is known, an attacker matches it to a public advisory and runs an existing exploit. No original research is required—the work was done for them.
- **Full cluster compromise**: A single vulnerable component at the trust boundary (ingress RCE, runtime escape, API-server privilege escalation) can lead from one pod to the whole cluster and every workload and secret in it.
- **Compliance and support loss**: Running end-of-support Kubernetes or an EOL node OS breaches most security frameworks and can void vendor support, leaving you without help during an incident.
- **Upgrade debt compounds**: The longer patching is deferred, the larger and riskier the eventual jump. Skew rules can force a chain of sequential upgrades under emergency pressure—the worst time to do them.
- **Cryptojacking and pivoting**: Exposed, unpatched clusters are routinely mass-scanned and hijacked for cryptomining or used as a foothold into the surrounding cloud account.

### Technical Impact
- **Container escape**: Runtime/kernel vulnerabilities (the runc-escape class) let a process in a container overwrite host binaries or break isolation and execute on the node.
- **Remote code execution on infrastructure**: Ingress-controller and add-on vulnerabilities (the IngressNightmare class) can allow unauthenticated code execution on the component's pod, often with wide cluster access.
- **Privilege escalation**: Historic kubelet and API-server flaws have allowed a lower-privileged client to gain higher privileges or reach endpoints it should not.
- **Denial of service**: Some component CVEs let a crafted request crash or hang the API server or a controller, taking the cluster's control plane offline.
- **Loss of confidentiality**: Escape or escalation typically leads to reading every Secret, ServiceAccount token, and mounted volume the node or control plane can reach.

## Technical Context

### The Components That Age

| Layer | Examples | What an outdated version risks |
|-------|----------|-------------------------------|
| Control plane | kube-apiserver, scheduler, controller-manager, etcd | API-server privilege escalation, DoS, auth bypass classes |
| Node agents | kubelet, kube-proxy | Privilege-escalation and path-handling CVEs on every node |
| Container runtime | containerd, CRI-O, runc, legacy Docker/dockershim | Container escape to the host (runc-escape class) |
| Node OS / kernel | Ubuntu, RHEL, Bottlerocket, Flatcar, Amazon Linux | Local privilege escalation via kernel exploits; EOL = no patches |
| Networking (CNI) | Calico, Cilium, Flannel, Weave | Network-policy bypass, node-level code execution |
| Storage (CSI) | EBS/GCE/Ceph drivers, provisioners | Host path handling, privileged mount abuse |
| Ingress / gateway | ingress-nginx, Traefik, HAProxy, Envoy/gateway | Unauthenticated RCE and config-injection (IngressNightmare class) |
| Add-ons | Kubernetes Dashboard, metrics-server, cert-manager | Dashboard auth bypass, information disclosure |
| Service mesh | Istio, Linkerd (control plane + sidecars) | Proxy CVEs replicated across every meshed pod |

### The Support and Skew Rules That Force Action

Kubernetes is not a "set and forget" platform. Two upstream rules turn "we're a bit behind" into a hard operational problem:

```
Supported releases:
  Upstream maintains roughly the three most recent minor
  versions (N, N-1, N-2). Older minors stop receiving
  patch releases entirely -> known CVEs are simply never fixed
  for you.

Version skew (must stay inside these bounds):
  kubelet        -> up to 3 minor versions older than kube-apiserver
  kube-proxy     -> matched to the node's kubelet
  controller/    -> at most 1 minor older than kube-apiserver
    scheduler
  kubectl        -> within 1 minor of the API server

Consequence: you cannot skip several minors in one jump.
Fall far enough behind and the only path forward is a
sequence of sequential, tested upgrades -- or a rebuild.
```

### Why Clusters Fall Behind
- **Fear of disruption**: Upgrades touch the control plane and drain nodes, so teams defer them—until deferral itself becomes the bigger risk.
- **No inventory**: If nobody has a list of every component and its version, nobody can know what is vulnerable or end-of-life.
- **No CVE tracking**: Application dependencies get scanned; the cluster's own components (kubelet, runtime, ingress, CNI) often have no owner watching advisories.
- **Add-on sprawl**: Dashboards, mesh, and helper controllers are installed once and never revisited, quietly aging into vulnerable versions.
- **Self-managed clusters**: Managed offerings automate much of the patching; hand-rolled clusters put the entire upgrade burden on the operator, and it is frequently dropped.

## Real-World Impact

> The cases below are described as **vulnerability classes** tied to well-known, publicly discussed events. Specific CVE identifiers and exact figures are deliberately omitted—the durable lesson is the *pattern*, not a number to memorise.

### Class 1: Ingress-Controller Remote Code Execution (the "IngressNightmare" class)

**The pattern**: The ingress controller is a cluster component that parses attacker-influenced configuration (annotations, snippets) and terminates external traffic. A class of publicly disclosed flaws in widely used ingress controllers allowed a request or a crafted Ingress object to inject configuration or trigger code execution in the controller's pod.

**Why it matters**: The ingress controller is internet-facing and typically runs with broad permissions—it can read Secrets (TLS certificates) and watch cluster resources. Code execution there is not a leaf-node compromise; it is a foothold with cluster-wide reach. Clusters running an outdated ingress version long after a fix shipped remained exploitable purely because they were never upgraded.

**Root cause for K10**: A known, patched vulnerability in a core add-on left running at the vulnerable version.

### Class 2: Container Runtime Escape (the "runc-escape" class)

**The pattern**: `runc` is the low-level runtime that containerd and CRI-O use to actually start containers. Publicly disclosed flaws in this class allowed a malicious or compromised container to overwrite the host `runc` binary or otherwise break out of its isolation and execute code on the node.

**Why it matters**: A runtime escape converts "attacker controls one pod" into "attacker controls the node"—and from a node, every pod, Secret, and ServiceAccount token scheduled there. Because a single runc version underlies most clusters, the blast radius of an unpatched runtime is enormous. The fix is a runtime/runc upgrade on every node; clusters that never rolled it out stayed escapable.

**Root cause for K10**: An unpatched container runtime on the nodes.

### Class 3: Kubelet / API-Server Privilege Escalation

**The pattern**: Over the project's history, several disclosed flaws in the kubelet and the API server allowed a client to escalate privileges, reach endpoints without proper authorization, or proxy to backends it should not. These were fixed in specific patch releases.

**Why it matters**: The kubelet and API server are the control surfaces of the cluster. A privilege-escalation flaw here can turn a limited service account or a compromised node into cluster-admin-equivalent access. The defense is simply to be on a patched version—which clusters outside the supported window are not.

**Root cause for K10**: Control-plane / node-agent components running below the patched version, or entirely end-of-life.

## Prevalence and Statistics

Outdated components are among the most reliably present findings in real clusters, precisely because staying current is ongoing work that competes with feature delivery. Rather than quote a single figure—numbers vary widely by survey and year—the defensible picture is:

- A meaningful share of production clusters run a Kubernetes minor that is **at or past end-of-support**, receiving no further security patches.
- Node OS, kernel, and container runtime are the **most commonly neglected** layers, because they sit "below" the parts teams think of as "Kubernetes."
- Add-ons—ingress controllers, dashboards, service mesh—are frequently **installed once and never upgraded**, aging into versions with public advisories.
- The impact is rated **severe**: this category leads directly to container escape, RCE on infrastructure, and privilege escalation.

> Treat any single percentage as illustrative. The durable takeaway: known-vulnerable and end-of-life components are common, trivially fingerprinted, and exploited with off-the-shelf tooling.

## Common Misunderstandings

### Myth 1: "If the cluster is running fine, the version is fine"
**Reality**: A vulnerable component runs exactly as smoothly as a patched one—until it is exploited. Stability is not security. An end-of-life version can be perfectly stable and completely unpatched at the same time.

### Myth 2: "We scan our application images, so we're covered"
**Reality**: Image scanning finds vulnerable libraries *inside* your containers. It says nothing about the kubelet, the runtime, the CNI, or the ingress controller—the components that actually sit at the escape and RCE boundary. K10 requires scanning the cluster stack itself, not just workloads.

### Myth 3: "Upgrading is too risky to do often"
**Reality**: The risk of a tested, incremental upgrade is far smaller than the risk of an emergency multi-version jump forced by an active exploit or an expiring support window. Frequent small upgrades are how you keep upgrades boring.

### Myth 4: "Managed Kubernetes patches everything for us"
**Reality**: Managed control planes automate a lot, but you usually still own *when* node pools upgrade, which node OS/AMI they run, and every add-on you installed yourself. A managed cluster with a year-old node pool and an unpatched ingress chart is still a K10 cluster.

### Myth 5: "We're on a recent Kubernetes version, so components are current"
**Reality**: The Kubernetes version and the versions of runc, the kernel, the CNI, and third-party add-ons move independently. A current API server can sit on top of an unpatched runtime or an EOL kernel. Each layer needs its own tracking.

### Myth 6: "There's no exploit for our exact version, so we're safe"
**Reality**: Advisories are published with patches, and public exploits follow quickly for popular components. "No exploit yet" is a countdown, not a guarantee—and for end-of-life versions there will never be a fix at all.

## How to Identify if You're Vulnerable

Ask these questions about your cluster:

- [ ] Do you know the exact version of the API server, kubelet, and kube-proxy on every node right now?
- [ ] Is your Kubernetes minor still inside the supported window (not end-of-life)?
- [ ] Are all nodes within the supported kubelet-to-API-server version skew?
- [ ] Do you know which container runtime and runc version every node runs, and are they patched?
- [ ] Is the node OS on a supported release with security updates actually applied (not just available)?
- [ ] Do you have an inventory of every add-on (ingress, CNI, CSI, dashboard, mesh) and its version?
- [ ] Is someone subscribed to the Kubernetes security-announce feed and the advisories for each add-on?
- [ ] Do you scan the cluster itself (not only images) with a tool like Trivy k8s or kubescape?
- [ ] Is node patching automated (kured, managed node pools) rather than done by hand, if ever?
- [ ] Do you have a regular, tested upgrade cadence—and have you removed add-ons you no longer use?

If you answered "no" or "not sure" to several of these, you very likely have known-vulnerable or end-of-life components in your cluster today.

## Key Takeaways

1. **A cluster is a stack of independently versioned parts**—control plane, kubelet, runtime, kernel, CNI/CSI, ingress, and add-ons each age on their own.
2. **Known-vulnerable means exploited-by-catalogue**—once your version is fingerprinted, the exploit already exists.
3. **Version skew and end-of-life are hard deadlines**—fall too far behind and you lose both patches and the ability to upgrade smoothly.
4. **The dangerous layers are the ones below your app**—runtime and kernel escapes, ingress RCE, and API-server privesc live in the cluster, not your image.
5. **Currency is a process, not a state**—inventory, CVE tracking, scanning, tested upgrades, and automated node patching keep K10 closed.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers fingerprint versions and exploit known component CVEs
- **[Prevention](prevention.md)**: Inventory, track, scan, and upgrade the whole Kubernetes stack
- **[Examples](examples.md)**: Insecure vs. secure version checking, upgrade strategy, and scanning
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
