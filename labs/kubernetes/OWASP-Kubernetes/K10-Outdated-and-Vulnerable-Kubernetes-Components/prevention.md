# K10: Outdated and Vulnerable Kubernetes Components - Prevention

## Table of Contents
- [Prevention Strategy](#prevention-strategy)
- [1. Inventory the Whole Stack](#1-inventory-the-whole-stack)
- [2. Track CVEs and Support Windows](#2-track-cves-and-support-windows)
- [3. Scan the Cluster, Not Just Images](#3-scan-the-cluster-not-just-images)
- [4. Upgrade on a Cadence, Within Skew](#4-upgrade-on-a-cadence-within-skew)
- [5. Automate Node and OS Patching](#5-automate-node-and-os-patching)
- [6. Reduce and Maintain Add-ons](#6-reduce-and-maintain-add-ons)
- [Hardening Checklist](#hardening-checklist)

## Prevention Strategy

K10 is closed by a **process**, not a one-time fix. Currency is a moving target: a cluster that is fully patched today drifts into "outdated" within weeks as new advisories land and support windows advance. The goal is to make patching routine, boring, and automated—so that being current is the default state rather than a heroic quarterly project.

The strategy has six pillars, applied to *every* layer of the stack:

```
Know it      -> inventory every component and its version
Watch it     -> subscribe to CVE feeds + track support/EOL dates
Measure it   -> scan the cluster and images continuously
Upgrade it   -> tested, incremental upgrades within version skew
Patch nodes  -> automate OS/kernel/runtime patching on nodes
Shrink it    -> remove unused add-ons; prefer maintained/managed
```

## 1. Inventory the Whole Stack

You cannot patch what you cannot see. Build and maintain a living inventory of every version-bearing component—not just "the Kubernetes version."

```
# Control plane + node agents (versions and skew):
kubectl version
kubectl get nodes -o wide
# -> KUBELET-VERSION, KERNEL-VERSION, OS-IMAGE, CONTAINER-RUNTIME per node

# Add-ons and their images (ingress, CNI, CSI, dashboard, mesh):
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u
```

**What to record**: for each component—current version, upstream latest, support/EOL date, and an owner responsible for upgrading it. Include the Kubernetes minor, kubelet, runtime, runc, node OS/kernel, CNI, CSI, ingress controller, dashboard, metrics, and every mesh/operator you installed. Store it as data (a manifest or SBOM), not tribal knowledge.

## 2. Track CVEs and Support Windows

Application dependencies usually have an owner watching advisories. The cluster's own components frequently do not—assign that ownership explicitly.

- **Subscribe to the Kubernetes security-announce feed** (the official channel for Kubernetes CVEs) so control-plane and kubelet advisories reach a real person.
- **Follow each add-on's advisory channel**: ingress-nginx, your CNI (Calico/Cilium), CSI drivers, cert-manager, the Dashboard, and your service mesh all publish security notices independently.
- **Track support and end-of-life dates** for the Kubernetes minor and the node OS. Put the EOL date on a calendar with a lead-time reminder—never discover EOL after it passes.
- **Map advisories to your inventory automatically**: when a CVE is published, you should be able to answer "are we affected?" from the inventory in minutes, not days.

## 3. Scan the Cluster, Not Just Images

Image scanning is necessary but insufficient for K10—it does not inspect the kubelet, runtime, or add-on versions. Add tools that scan the *cluster*.

```
# Trivy can scan the cluster's components (control plane, node,
# workloads) for known vulnerabilities and misconfigurations:
trivy k8s --report summary cluster

# kubescape scans the live cluster against frameworks that
# include outdated/vulnerable-component controls:
kubescape scan --format json --output results.json

# Grype scans images (and SBOMs) for known CVEs in packages:
grype registry.example.com/app:1.4.2 --fail-on high
```

**Wire scanning into CI/CD and into a schedule**: gate deployments on image scans (Grype/Trivy) and run cluster scans (Trivy k8s, kubescape) on a cron so newly disclosed CVEs surface against already-running components—not only at deploy time.

## 4. Upgrade on a Cadence, Within Skew

Regular, small, tested upgrades are how you avoid emergency multi-version jumps.

- **Respect the version-skew rules**: upgrade the control plane first, then nodes, keeping the kubelet within the supported window (up to three minors behind the API server). Never let a node drift outside skew.
- **Upgrade one minor at a time**: Kubernetes does not support skipping minors on the control plane. Sequence the jumps and test each.
- **Stay inside the supported window**: plan upgrades so you are always on one of the supported minors (roughly the latest three) and never fall to end-of-life.
- **Test upgrades before production**: run the upgrade in a staging cluster or on a canary node pool, validate workloads and add-ons, then roll out.
- **Read the deprecation/API-removal notes**: each minor removes APIs; check your manifests and add-ons against the target version before upgrading.

```
# Example cadence (adapt to your risk tolerance):
#   - Patch releases: apply within days of a security release.
#   - Minor upgrades: every 1-3 months, staged (canary -> fleet).
#   - Node OS/kernel: continuous auto-patch (see next section).
#   - Add-ons: reviewed monthly against upstream + advisories.
```

## 5. Automate Node and OS Patching

Node OS, kernel, and container runtime are the most-neglected layers and the ones behind escape and LPE classes. Automate them so they are never "waiting for a maintenance window."

- **Use `kured` (KUbernetes REboot Daemon)** on self-managed nodes to safely cordon, drain, reboot, and uncordon nodes after the OS applies kernel/security updates—one node at a time, respecting PodDisruptionBudgets.
- **Prefer managed node pools / auto-upgrade** on managed platforms (EKS/GKE/AKS), which roll patched node images automatically.
- **Prefer immutable, minimal node OSes** (Bottlerocket, Flatcar, container-optimised images) that are designed for automated, atomic updates and have a smaller attack surface.
- **Patch the container runtime deliberately**: track containerd/CRI-O and runc versions per node and roll runtime upgrades as part of node image updates—this is the fix for the runc-escape class.
- **Retire dockershim/legacy Docker**: it was removed from Kubernetes; running it means running an unsupported runtime path.

```
# kured runs as a DaemonSet and coordinates safe, serialized reboots
# after unattended-upgrades / OS patching flags a reboot is needed:
#   node applies kernel/security updates -> kured cordons+drains -> reboot -> uncordon
# PodDisruptionBudgets keep workloads available during the roll.
```

## 6. Reduce and Maintain Add-ons

Every add-on is another component to track and patch. The cheapest way to reduce K10 exposure is to run fewer things.

- **Remove unused add-ons**: an old Kubernetes Dashboard, an abandoned operator, or a mesh nobody uses is pure liability—delete it.
- **Pin and track add-on versions**: manage add-ons via Helm/GitOps with explicit, current versions so upgrades are reviewable and reversible.
- **Prefer maintained, widely-used components**: a well-supported ingress controller or CNI gets timely patches; an abandoned project does not.
- **Prefer managed clusters where appropriate**: managed control planes are kept on maintained versions and patched by the provider, reducing the surface you personally own.
- **Restrict exposure as defense-in-depth**: keep the dashboard, kubelet API, and metrics off the public internet so an unpatched component is at least not reachable by anonymous attackers (complements K07 network segmentation).

## Hardening Checklist

| Control | Action | Priority |
|---------|--------|----------|
| Inventory | Maintain a versioned list of every component + owner + EOL date | Critical |
| Support window | Keep Kubernetes on a supported minor; never run EOL | Critical |
| Version skew | Keep kubelets within the supported gap from the API server | Critical |
| Runtime/runc | Patch container runtime and runc on every node | Critical |
| Node OS/kernel | Automate patching (kured / managed node pools); no EOL OS | Critical |
| Ingress controller | Track advisories; patch promptly (IngressNightmare class) | Critical |
| CVE feeds | Subscribe to k8s security-announce + each add-on's channel | High |
| Cluster scanning | Run Trivy k8s / kubescape on a schedule + Grype in CI | High |
| Tested upgrades | Canary/staging upgrades, one minor at a time | High |
| Add-on hygiene | Remove unused add-ons; pin + track the rest | Medium |
| Exposure | Keep dashboard/kubelet/metrics off the public internet | Medium |
| Managed option | Prefer managed clusters/node pools where feasible | Medium |

## Defense-in-Depth Summary

No single control fully addresses K10; layer them so a lapse in one is caught by another:

```
Layer 1: Inventory      -> you know every component and version
Layer 2: Intelligence   -> CVE feeds + EOL tracking tell you what's at risk
Layer 3: Detection      -> Trivy k8s / kubescape / Grype find it in your cluster
Layer 4: Remediation    -> tested, cadence-based upgrades within skew
Layer 5: Automation     -> kured / managed pools patch nodes continuously
Layer 6: Reduction      -> fewer add-ons, less exposure, managed where possible
```

## Key Takeaways

1. **Make currency the default**—automate and schedule so patched is the resting state, not a special event.
2. **Inventory the whole stack**—kubelet, runtime, kernel, CNI/CSI, ingress, and add-ons, each with an owner and an EOL date.
3. **Scan the cluster, not only images**—Trivy k8s and kubescape see the components image scanners miss.
4. **Upgrade small, upgrade often, within skew**—incremental tested upgrades beat emergency jumps every time.
5. **Automate node patching and shrink the surface**—kured/managed pools for the OS and runtime; delete add-ons you do not use.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure version checking, upgrade strategy, and scanning
- **[Attack Vectors](attack-vectors.md)**: Understand what you are defending against
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
