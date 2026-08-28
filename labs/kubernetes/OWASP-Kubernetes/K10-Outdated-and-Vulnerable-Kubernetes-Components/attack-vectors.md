# K10: Outdated and Vulnerable Kubernetes Components - Attack Vectors

## Table of Contents
- [Understanding the Attack Surface](#understanding-the-attack-surface)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Outdated Components](#chaining-outdated-components)

## Understanding the Attack Surface

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are described so you can find, prioritise, and fix outdated components in clusters you own or are explicitly authorised to test. Do not exploit systems you do not control.

Attacking outdated components is the least creative category in the entire Kubernetes Top 10, and that is exactly what makes it dangerous. The attacker does not invent a new technique—they **identify a version** and then run an exploit that already exists in a public catalogue. The intellectual work was done by the researcher who disclosed the flaw; the attacker only has to notice that your cluster never applied the patch.

The attacker's goal in this category is typically one of:

- Fingerprint the version of a reachable component (ingress controller, API server, kubelet, runtime, add-on).
- Match that version to a public advisory with a working exploit.
- Use the exploit to gain code execution, escape a container, or escalate privileges.
- Pivot from that foothold to the node, the control plane, and cluster-wide secrets.

### Core Attack Flow

```
1. Fingerprint
   |
   Read version banners, /version, error pages, image tags,
   TLS certs, response quirks -> identify each component + version
2. Match
   |
   Look up the version in public advisories / exploit databases
   -> find a component with a known, unpatched CVE
3. Exploit
   |
   Run the existing exploit: ingress RCE, runtime escape,
   kubelet/API-server privesc, add-on auth bypass
4. Escape / Escalate
   |
   Break out to the node, harvest tokens/secrets, reach the
   control plane -> cluster-wide compromise
```

## Common Attack Patterns

### 1. Fingerprinting the Kubernetes Version

The API server and many components advertise their version to anyone who can reach them.

```
# The API server exposes an unauthenticated version endpoint:
GET /version HTTP/1.1
-> { "major": "1", "minor": "26", "gitVersion": "v1.26.x", ... }

# kubectl confirms client/server versions:
kubectl version
# Node images and kubelet versions are listed on every node:
kubectl get nodes -o wide      # KERNEL-VERSION, OS-IMAGE, CONTAINER-RUNTIME
```

**Payoff**: the exact Kubernetes minor, node kernel, OS image, and runtime—everything needed to select a matching exploit. An end-of-life `gitVersion` is an immediate green light.

### 2. Ingress-Controller RCE (IngressNightmare class)

An internet-facing ingress controller running a version with a public advisory is the highest-value target, because it is reachable without any cluster credentials.

```
# Fingerprint the controller from response headers / error pages:
GET / HTTP/1.1
-> Server: nginx  (+ ingress-nginx default 404 body / annotations behaviour)

# If the running version predates the fix, an attacker submits a
# crafted Ingress object or request that injects controller
# configuration or triggers code execution in the controller pod.
```

**Payoff**: code execution inside an internet-facing pod that can typically read TLS Secrets and watch cluster resources—a foothold with cluster-wide reach, no login required.

### 3. Container Runtime / runc Escape

If the attacker already controls a pod (via a vulnerable app, K01 misconfig, or supply-chain issue), an unpatched runtime turns that pod into node access.

```
# From inside a container on a node with an unpatched runc/containerd:
cat /proc/version                 # kernel version -> match to LPE class
runc --version ; containerd --version   # if visible -> match to escape class

# The runc-escape class lets a malicious container overwrite the host
# runc binary or break isolation, then execute on the node itself.
```

**Payoff**: escape from one container to the host, then access to every pod, Secret, and ServiceAccount token scheduled on that node.

### 4. Kubelet / API-Server Privilege Escalation

Historic, patched flaws in the node agent and control plane let a limited client reach further than intended.

```
# The kubelet's read/exec API may be reachable on the node:
GET https://NODE:10250/pods         # list pods on the node
POST https://NODE:10250/run/...     # exec into a container (if authz weak)

# On outdated API servers, specific privilege-escalation and
# request-proxying advisories let a low-privileged principal reach
# endpoints or backends it should not.
```

**Payoff**: escalation from a node-local or low-privileged position toward cluster-admin-equivalent access, using a flaw that a patched version would have closed.

### 5. Vulnerable Add-ons: Dashboard, Metrics, Mesh

Helper components installed once and never upgraded are soft targets.

```
# An outdated Kubernetes Dashboard exposed without auth / with a
# known auth-bypass advisory hands over cluster operations in a browser.
GET /#/overview            # dashboard reachable, no login

# An unpatched metrics or profiling add-on leaks internal topology;
# an outdated service-mesh proxy replicates one CVE across every
# meshed pod at once.
```

**Payoff**: cluster control (dashboard), reconnaissance (metrics), or a proxy vulnerability multiplied across the whole mesh.

### 6. End-of-Life Node OS and Kernel

The node kernel is the ultimate isolation boundary, and an EOL distro never gets kernel patches.

```
uname -r                     # kernel version
cat /etc/os-release          # distro + version -> is it still supported?

# A kernel with a public local-privilege-escalation exploit lets a
# container-confined process (or an escaped one) become root on the node.
```

**Payoff**: local privilege escalation on the node, completing an escape or turning limited node access into full root.

### 7. CNI / CSI Component Vulnerabilities

Network and storage plugins run with high privilege on every node.

```
# CNI plugins enforce NetworkPolicy and program the node network;
# a vulnerable version can allow policy bypass or node-level execution.
# CSI drivers mount volumes with host privileges; an outdated driver
# with a path-handling flaw can be abused to touch the host filesystem.
```

**Payoff**: network-segmentation bypass (undermining K07) or privileged host access via the storage path.

## Chaining Outdated Components

Individually a stale version is "just" a finding. Chained, stale versions become full cluster takeover with no application bug at all:

```
Internet-facing ingress controller is months behind
        -> exploit the IngressNightmare-class RCE for code exec in the pod
        +
The node runs an unpatched runc / EOL kernel
        -> escape the ingress pod to the node
        +
The kubelet / API server is also outdated
        -> escalate from the node to cluster-admin-equivalent access
        =  full cluster compromise, every exploit taken off the shelf
```

Another common chain begins from a single compromised workload:

```
Compromised app pod (any cause)
        -> unpatched container runtime -> escape to the node
        -> harvest ServiceAccount tokens + Secrets mounted on the node
        -> EOL kernel LPE -> root on the node
        -> pivot to other nodes and the control plane
```

## Key Takeaways

1. **This category is exploited by identification, not innovation**—the exploit exists before the attacker arrives; they only need your version.
2. **Versions are easy to fingerprint**—`/version`, node metadata, banners, and image tags advertise exactly what to target.
3. **The internet-facing ingress controller is the prime external target**—RCE there needs no credentials and reaches cluster secrets.
4. **Runtime and kernel staleness converts a pod compromise into a node and cluster compromise**—the escape layer is the one most often neglected.
5. **Stale versions chain**—ingress RCE plus a runc escape plus an outdated API server equals total takeover, entirely from public exploits.

## Next Steps

- **[Prevention Guide](prevention.md)**: Inventory, track CVEs, scan, and upgrade the whole stack on a cadence
- **[Code Examples](examples.md)**: Version checking, upgrade strategy, and cluster scanning done right
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
