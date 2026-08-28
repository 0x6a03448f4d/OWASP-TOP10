# K10: Outdated and Vulnerable Kubernetes Components - Examples

## Table of Contents
- [1. Checking Component Versions](#1-checking-component-versions)
- [2. Tracking CVEs and Support Windows](#2-tracking-cves-and-support-windows)
- [3. Upgrade Strategy and Version Skew](#3-upgrade-strategy-and-version-skew)
- [4. Scanning the Cluster (kubescape, Trivy k8s, Grype)](#4-scanning-the-cluster-kubescape-trivy-k8s-grype)
- [5. Automating Node Patching (kured)](#5-automating-node-patching-kured)
- [6. Add-on Hygiene](#6-add-on-hygiene)

Each pair below shows an **insecure** approach and the **secure** version of the same task. The focus is the work that actually keeps K10 closed: knowing your versions, tracking advisories, upgrading within skew, scanning the cluster itself, and automating node patching.

## 1. Checking Component Versions

### Insecure

```
# "We're on a recent version, probably."
# No inventory. Nobody knows the kubelet, runtime, or kernel versions.
# The Kubernetes minor was installed 14 months ago and never checked
# against the support window -> it is already end-of-life.
kubectl version --short
# Client Version: v1.22.x
# Server Version: v1.22.x     # EOL, no more security patches
```

### Secure

```
# Enumerate every version-bearing layer and compare to upstream + EOL.
kubectl version                              # client + API server
kubectl get nodes -o wide                    # kubelet, kernel, OS, runtime
#   NAME    KUBELET-VERSION  OS-IMAGE           KERNEL-VERSION  CONTAINER-RUNTIME
#   node-1  v1.29.4          Bottlerocket 1.x   6.1.x           containerd://1.7.x

# Pull the image (and thus version) of every add-on you run:
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u
#   ingress-nginx   registry.k8s.io/ingress-nginx/controller:v1.x.x
#   kube-system     docker.io/calico/node:v3.x.x
#   ...

# Record current vs. upstream-latest vs. EOL date, with an owner,
# for: k8s minor, kubelet, runtime, runc, node OS/kernel, CNI, CSI,
# ingress, dashboard, metrics, mesh. Store it as data (SBOM/manifest).
```

> **Why it matters**: You cannot patch or prioritise what you have not enumerated. A version inventory turns "are we affected by this CVE?" into a one-minute lookup instead of a fire drill.

## 2. Tracking CVEs and Support Windows

### Insecure

```
# No feed, no owner, no calendar.
# A critical ingress-controller advisory (IngressNightmare class)
# is published and patched upstream. Nobody in the org sees it.
# The cluster stays on the vulnerable version for months.
# End-of-life dates are discovered only when an upgrade fails.
```

### Secure

```
# 1) Subscribe a real team alias to the Kubernetes security feed:
#    kubernetes-security-announce (official k8s CVE announcements).
# 2) Follow each add-on's advisory channel: ingress-nginx, Calico/
#    Cilium, CSI drivers, cert-manager, Dashboard, Istio/Linkerd.
# 3) Put support/EOL dates on a calendar with lead-time reminders:
#      - Kubernetes minor EOL       -> upgrade before this date
#      - Node OS release EOL        -> migrate node image before this date
# 4) When an advisory lands, map it to the inventory automatically:
#      "Which clusters run the affected component + version?" -> minutes.
```

> **Why it matters**: The application team watches app dependencies; the cluster's own components need an explicit owner watching their advisories, or K10 goes unnoticed until it is exploited.

## 3. Upgrade Strategy and Version Skew

### Insecure

```
# "If it isn't broken, don't touch it."
# Control plane on v1.24, some nodes still on v1.19 kubelets.
# The kubelet-to-API-server skew is far outside the supported window,
# so the only way forward is a risky, multi-minor emergency jump --
# skipping minors, untested, under pressure from an active advisory.
kubectl get nodes    # mixed, very old KUBELET-VERSION values
```

### Secure

```
# Upgrade one minor at a time, control plane first, then nodes,
# always keeping kubelets within the supported skew (up to 3 minors
# behind the API server). Test each step before rolling the fleet.

# 1) Pre-flight: check for removed/deprecated APIs in your manifests
#    against the target version, and confirm add-on compatibility.
# 2) Upgrade the control plane by one minor (managed: bump the
#    cluster version; kubeadm: `kubeadm upgrade apply vX.Y.z`).
# 3) Upgrade node pools to match, one at a time:
kubectl drain node-1 --ignore-daemonsets --delete-emptydir-data
#    (replace/upgrade the node image, then)
kubectl uncordon node-1
# 4) Validate workloads + add-ons on a canary pool before the rest.
# 5) Repeat for the next minor. Never skip minors on the control plane.

# Cadence: patch releases within days; minors every 1-3 months.
```

> **Why it matters**: Small, tested, in-skew upgrades keep you permanently inside the supported window. Deferral converts a routine bump into a dangerous, untested leap at the worst possible moment.

## 4. Scanning the Cluster (kubescape, Trivy k8s, Grype)

### Insecure

```
# Only application images are scanned, only at build time.
# The kubelet, container runtime, ingress controller, and add-on
# versions are never assessed for known CVEs. A component can carry a
# public advisory for months and no tool in the pipeline ever flags it.
grype app:latest      # images only -> blind to the cluster stack
```

### Secure

```
# Scan the cluster itself AND images, in CI and on a schedule.

# Trivy scans the live cluster's components + workloads for CVEs:
trivy k8s --report summary cluster
trivy k8s --report all --severity HIGH,CRITICAL cluster

# kubescape scans the running cluster against frameworks whose
# controls include outdated/vulnerable components:
kubescape scan --format sarif --output kubescape.sarif
kubescape scan framework nsa,mitre

# Grype gates images in CI on known package CVEs:
grype registry.example.com/app:1.4.2 --fail-on high

# Run the cluster scans on a cron so NEW advisories surface against
# ALREADY-RUNNING components, not just at deploy time:
#   (CronJob or CI schedule) -> trivy k8s + kubescape -> alert on findings
```

> **Why it matters**: Image scanners see inside containers; cluster scanners (Trivy k8s, kubescape) see the kubelet, runtime, and add-on versions where the escape/RCE/privesc classes live. You need both, and you need them on a schedule—not only at build time.

## 5. Automating Node Patching (kured)

### Insecure

```
# Nodes are patched by hand "when we get a maintenance window."
# Kernel and runtime security updates sit unapplied for months.
# The runc-escape class and kernel LPE class stay exploitable on
# every node until someone remembers to reboot them one day.
```

### Secure

```yaml
# Let the OS fetch security updates, and let kured coordinate safe,
# serialized reboots so kernel/runtime patches actually take effect.

apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kured
  namespace: kube-system
spec:
  selector:
    matchLabels: { app: kured }
  template:
    metadata:
      labels: { app: kured }
    spec:
      serviceAccountName: kured
      containers:
        - name: kured
          image: ghcr.io/kubereboot/kured:1.x.x   # pin + track version
          args:
            - "--period=1h"                 # check hourly
            - "--reboot-sentinel=/var/run/reboot-required"
          securityContext:
            privileged: true                # needs host reboot access
```

```
# Flow: OS applies kernel/security updates and sets the reboot
# sentinel -> kured cordons + drains ONE node -> reboots -> uncordons,
# respecting PodDisruptionBudgets so workloads stay available.

# On managed platforms, prefer node auto-upgrade / managed node pools,
# which roll patched node images for you.
```

> **Why it matters**: The node OS, kernel, and runtime are the layers behind container escape and local privilege escalation—and the ones most often left stale. Automating their patching removes the human bottleneck.

## 6. Add-on Hygiene

### Insecure

```
# A Kubernetes Dashboard installed two years ago for a demo is still
# running, unauthenticated, on an unpatched version -- and reachable.
# An abandoned operator and an unused service mesh add two more
# unmaintained, version-bearing components nobody tracks.
kubectl get deploy -A | grep -i dashboard   # still there, still old
```

### Secure

```
# 1) Delete add-ons you do not use -- the cheapest K10 fix is fewer
#    components to patch:
kubectl delete namespace kubernetes-dashboard   # if unused

# 2) Manage the ones you keep via Helm/GitOps with explicit, current
#    versions so upgrades are reviewable and reversible:
helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
  --version <current-chart-version> -n ingress-nginx

# 3) Prefer maintained, widely-used components that get timely patches.
# 4) Keep management surfaces (dashboard, kubelet API, metrics) off the
#    public internet as defense-in-depth (complements K07).
```

> **Why it matters**: Every add-on is another advisory feed to watch and another version to patch. Removing unused ones and pinning the rest shrinks the K10 surface directly.

## Summary: Insecure vs. Secure

| Task | Insecure | Secure |
|------|----------|--------|
| Versions | Unknown; EOL minor unnoticed | Full inventory: k8s, kubelet, runtime, kernel, add-ons |
| CVE tracking | No feed, no owner | Subscribed to k8s security-announce + per add-on |
| Upgrades | Deferred; skew violated; emergency jumps | One minor at a time, in-skew, tested, on a cadence |
| Scanning | Images only, build-time only | Trivy k8s + kubescape (cluster) + Grype (images), scheduled |
| Node patching | Manual, rare | Automated via kured / managed node pools |
| Add-ons | Installed once, never revisited | Unused removed; kept ones pinned + tracked |

## Next Steps

- **[Overview](overview.md)**: Recap what K10 covers and why it is its own category
- **[Attack Vectors](attack-vectors.md)**: How outdated components are fingerprinted and exploited
- **[Prevention](prevention.md)**: The full process for keeping the stack current
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
