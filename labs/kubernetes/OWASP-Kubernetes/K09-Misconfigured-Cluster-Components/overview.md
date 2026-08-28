# K09: Misconfigured Cluster Components - Overview

## Table of Contents
- [What is Misconfigured Cluster Components?](#what-is-misconfigured-cluster-components)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Misconfigured Cluster Components?

**Misconfigured Cluster Components** is the risk that the machinery running Kubernetes itself—the control-plane and node processes—is deployed with insecure settings. Every cluster is held up by a small set of long-running components: the `kube-apiserver`, `etcd`, the `kube-scheduler`, the `kube-controller-manager`, and on every node the `kubelet`, `kube-proxy`, the container runtime, and cluster add-ons such as CoreDNS. Each one exposes flags, ports, certificates, and authorization modes. When those knobs are left at insecure values, an attacker does not need to break your applications—the platform hands them the keys.

This is K09 in the OWASP Kubernetes Top 10. It is distinct from a single bad pod (that is **K01 — Insecure Workload Configurations**) and from the absence of an admission policy engine (that is **K04 — Lack of Centralized Policy Enforcement**). K09 is about the *components themselves*: an API server that answers anonymous callers, a kubelet that executes commands with no authentication, or an etcd database reachable without a client certificate. These are the foundations. If they are weak, no workload policy above them can save you.

### Core Concept

```
A Kubernetes cluster is a set of trusted components talking over the network:

  kubectl / clients
        |
        v
  kube-apiserver  <--- the single front door; authN + authZ + admission
        |                      |
        v                      v
      etcd                  kubelet (every node)  ---> container runtime
   (all cluster                 |
    state + Secrets)            v
                             pods / workloads

  Also present: kube-scheduler, kube-controller-manager,
                kube-proxy, CoreDNS, cloud-controller-manager

K09 asks a simple question about each of these:
  "Does it require authentication? Does it authorize? Is its traffic
   encrypted with mutual TLS? Are its debug/metrics ports locked down?"

Secure component:            Misconfigured component:
  authN required               --anonymous-auth=true
  authZ = Node,RBAC            --authorization-mode=AlwaysAllow
  mTLS everywhere              plaintext / no client cert (etcd, kubelet)
  no legacy insecure port      --insecure-port still bound
  audit enabled                audit disabled, no record of access
  metrics/debug protected      /metrics, pprof, 10255 open to anyone
```

The theme of K09 is **authentication and authorization on the infrastructure itself**. Kubernetes ships hardened defaults in modern versions, but clusters that are hand-rolled, upgraded from old versions, or built from copy-pasted flags routinely reintroduce the insecure settings that the project spent years removing.

### The Components and Their Dangerous Knobs

| Component | Role | Signature misconfiguration |
|-----------|------|----------------------------|
| `kube-apiserver` | The one front door; authenticates, authorizes, admits every request | `--anonymous-auth=true`, `--authorization-mode=AlwaysAllow`, legacy insecure port, disabled admission plugins |
| `etcd` | Stores all cluster state, including every Secret, in plaintext keys | No client-cert (mTLS) auth, bound to a routable interface, no encryption-at-rest |
| `kubelet` | Node agent; runs and manages containers, exposes exec/logs | `--anonymous-auth=true`, `--authorization-mode=AlwaysAllow`, read-only port 10255, open 10250 |
| `kube-controller-manager` | Runs controllers; signs service-account tokens and certs | `--use-service-account-credentials=false`, weak key handling, profiling open |
| `kube-scheduler` | Assigns pods to nodes | Bind on all interfaces, profiling/`pprof` exposed, no auth on metrics |
| `kube-proxy` | Programs node networking | Overly broad kubeconfig, metrics bound to `0.0.0.0` |
| CoreDNS / add-ons | Cluster DNS and other services | Over-permissive RBAC for the add-on, exposed metrics/health |

## Why Does This Matter?

The control plane is not one more workload—it is the **trust root of the entire cluster**. A single reachable, over-permissive component collapses every other control you have built above it.

### Business Impact
- **Total cluster takeover**: An unauthenticated API server or kubelet lets an attacker create pods, read every Secret, and run code on every node—there is no higher privilege to escalate to.
- **Mass data exposure**: `etcd` holds every Secret, ConfigMap, and object in the cluster. Reaching it without a client certificate, or without encryption-at-rest, exposes all of it at once.
- **Cloud account pivot**: Node identities and instance-metadata credentials reachable from a compromised component become a path out of the cluster into the wider cloud account.
- **Cryptojacking and abuse**: Open control surfaces are routinely hijacked to schedule cryptomining workloads, a pattern seen repeatedly against exposed dashboards and API servers.
- **Compliance and audit failure**: Disabled audit logging means a breach leaves no forensic record—an independent finding for most regulated environments (PCI-DSS, HIPAA, SOC 2).

### Technical Impact
- **Authentication bypass**: `--anonymous-auth=true` gives the built-in `system:anonymous` user a way in; if authorization is also loose, that anonymous user acts.
- **Authorization bypass**: `--authorization-mode=AlwaysAllow` approves every request that authenticates—RBAC is effectively switched off.
- **Remote code execution on nodes**: An open kubelet on `10250` exposes `/exec`, `/run`, and `/attach`—direct command execution inside running containers.
- **Cluster-state disclosure**: A read-only kubelet port (`10255`) or unauthenticated `etcd` leaks pod specs, environment variables, and Secrets.
- **Loss of admission control**: Missing admission plugins (`NodeRestriction`, `PodSecurity`) let a compromised node or user do things the cluster should have forbidden.
- **Man-in-the-middle**: Missing or self-signed certificates and disabled mTLS between components allow interception and impersonation of control-plane traffic.

## Technical Context

### 1. API Server Misconfiguration

The `kube-apiserver` is the only component clients talk to directly, so its flags matter most. The dangerous ones:

```
# DANGEROUS API-server flags
--anonymous-auth=true                 # lets system:anonymous authenticate
--authorization-mode=AlwaysAllow      # every authenticated request is approved
--insecure-port=8080                  # legacy plaintext, no-auth port (removed in modern K8s)
--insecure-bind-address=0.0.0.0       # that port reachable from anywhere
--enable-admission-plugins=           # NodeRestriction / PodSecurity omitted
--profiling=true                      # /debug/pprof exposed
--audit-log-path=                     # empty: no audit trail
--tls-min-version=VersionTLS10        # weak transport
--kubelet-certificate-authority=      # unset: API server won't verify kubelets
```

Historically, the `--insecure-port` (default `8080`) served the API with *no authentication and no authorization at all*. Anyone who could reach it was effectively cluster-admin. The flag was deprecated and finally removed, but old clusters, lab guides, and copied manifests still carry it.

### 2. Kubelet Misconfiguration

Every node runs a `kubelet` that manages containers and exposes an HTTP API. It has its own authentication and authorization, separate from the API server, and its defaults on hand-built clusters are frequently wrong.

```
# DANGEROUS kubelet settings
authentication:
  anonymous:
    enabled: true          # anonymous callers accepted on 10250
authorization:
  mode: AlwaysAllow        # no authorization check at all
readOnlyPort: 10255        # unauthenticated read-only API (pods, specs, env)

# Port 10250 = full kubelet API: /exec /run /attach /logs
# Port 10255 = read-only: /pods /metrics /spec  (no auth by design)
```

An open `10250` with anonymous auth and `AlwaysAllow` is one of the most direct paths to code execution in all of Kubernetes: list pods via the API, then call `/exec` on a chosen container.

### 3. etcd Misconfiguration

`etcd` is the cluster's database. Everything—objects, ConfigMaps, and Secrets—lives there, and by default Secrets are stored *un-encrypted* (base64 is not encryption). Two failures dominate:

```
# DANGEROUS etcd exposure
--listen-client-urls=http://0.0.0.0:2379   # plaintext, routable
# (no --client-cert-auth, no --trusted-ca-file)

# Anyone who reaches 2379 can read every key:
etcdctl --endpoints=http://TARGET:2379 get / --prefix --keys-only
etcdctl --endpoints=http://TARGET:2379 get /registry/secrets/default/db --print-value-only

# Missing encryption-at-rest: Secrets sit in etcd in the clear
# (no EncryptionConfiguration passed to the API server)
```

`etcd` should be reachable *only* from the API server, over mutual TLS, on a private interface—and Secrets should be encrypted at rest so a stolen etcd snapshot is not a full breach.

### 4. Admission Controller Set

Admission controllers are compiled into the API server and enabled with `--enable-admission-plugins`. Two are security-critical:

- **`NodeRestriction`**: limits each kubelet to modifying only its own node and the pods bound to it—without it, a compromised node can tamper with others.
- **`PodSecurity`**: the built-in Pod Security Admission that enforces the Pod Security Standards (privileged / baseline / restricted).

Turning these off, or running with an empty admission set, removes guardrails the rest of your security model assumes are present.

### 5. Disabled Audit, Weak Certs, Exposed Metrics/Debug

```
# Audit disabled: no record of who did what
--audit-log-path unset  ->  breaches leave no trail

# Self-signed / default / long-lived certificates
# never rotated  ->  a leaked key is valid indefinitely

# Component debug + metrics exposed without auth
GET http://node:10255/metrics          # kubelet read-only metrics
GET http://apiserver:6443/debug/pprof/ # profiling if --profiling=true
GET http://scheduler:10259/metrics     # scheduler metrics on all interfaces
```

### Where the Misconfigurations Come From

| Source | Why it goes wrong |
|--------|-------------------|
| Hand-rolled / "the hard way" clusters | Every flag is set manually; one wrong value ships silently |
| Old clusters upgraded in place | Insecure legacy flags (insecure-port, AlwaysAllow) survive upgrades |
| Copy-pasted manifests and tutorials | Lab-grade settings (anonymous auth, no TLS) reach production |
| Cloud/provider defaults not verified | Managed clusters are safer, but add-ons and node config still drift |
| Convenience during debugging | Someone opens a port or loosens auth "temporarily" and never reverts |

## Real-World Impact

The incidents below are described as **classes of incident** repeatedly observed and documented by the security community. Specific version numbers and statistics are intentionally omitted; the durable lesson is in the pattern, not a headline figure.

### Case Class 1: Unauthenticated Kubernetes Dashboard / API Leading to Cryptojacking

**Misconfiguration**: A control-plane surface—an administrative dashboard or an API server—was reachable from the internet with authentication effectively disabled (anonymous access or no login).

**Impact**: Automated actors discovered the open surface, scheduled cryptomining pods, and in several documented cases reached cloud credentials available from within the environment, pivoting beyond the cluster. This class of exposure—an open management plane—is one of the most consistently reported Kubernetes incidents.

**Root cause**: A control component deployed with no authentication and exposed to a wide network—precisely the K09 failure mode.

### Case Class 2: Exposed etcd Disclosing Every Secret

**Misconfiguration**: `etcd` listening for client traffic on a routable interface without client-certificate authentication, or an etcd snapshot/backup left readable.

**Impact**: Anyone reaching the port could dump every key, including all Kubernetes Secrets (database passwords, tokens, TLS keys) stored without encryption-at-rest. One reachable database equals the entire cluster's credentials.

**Root cause**: Missing mTLS on etcd plus missing encryption-at-rest—the datastore treated as if it were on a trusted, private wire when it was not.

### Case Class 3: Open Kubelet Enabling Node-Level Code Execution

**Misconfiguration**: Kubelets running with anonymous authentication and `AlwaysAllow` authorization, exposing the full API on `10250` (and often the read-only `10255`).

**Impact**: Attackers enumerated pods through the kubelet, then used `/exec` to run commands inside containers—harvesting service-account tokens and mounted Secrets, then using those tokens against the API server to spread. Research tooling has repeatedly demonstrated this exact chain against internet-exposed kubelets.

**Root cause**: The node agent's own authentication and authorization left at insecure values, a setting entirely separate from—and often forgotten alongside—the API server's.

## Prevalence and Detectability

Component misconfiguration is **common on self-managed clusters and highly detectable**. The security community codified exactly what "hardened" means in the **CIS Kubernetes Benchmark**, and the open-source tool **kube-bench** checks a running cluster against it automatically. That means both attackers and defenders can assess a cluster's component posture quickly.

- **Highly detectable**: `kube-bench` (CIS Benchmark), `kubescape`, and Polaris flag insecure component flags in minutes; attackers scan for open `10250`/`10255`/`2379`/`6443` ports at internet scale.
- **Managed clusters are safer by default**: EKS, GKE, and AKS manage and harden the control plane, closing many API-server/etcd knobs—but node configuration, add-ons, and any self-managed piece still need verification.
- **Severity is maximal**: because these are the trust root, the impact when they are wrong is cluster-total—RCE on nodes, all Secrets exposed, full takeover.

> Note: exact figures vary by report and year. The durable takeaway is that component misconfiguration is common on hand-built clusters, mechanically detectable with CIS tooling, and catastrophic when present—which is why continuous benchmarking is the backbone of the defense.

## Common Misunderstandings

### Myth 1: "We use a managed cluster, so the control plane is not our problem"
**Reality**: Managed providers harden and run the API server and etcd for you—a real reduction in risk. But you still own the *kubelets*, the node configuration, the add-ons, the admission-plugin choices you can influence, audit-log routing, and every self-managed component. The shared-responsibility line runs through the middle of K09, not around it.

### Myth 2: "It is on a private network, so plaintext etcd is fine"
**Reality**: "Private" networks are routinely reached through SSRF, a compromised pod, a misrouted route, or a flat VPC. etcd holds every Secret in the cluster; it must require mutual TLS and encrypt Secrets at rest regardless of where it sits.

### Myth 3: "K09 is the same as K01 insecure workloads"
**Reality**: K01 is a bad *pod* (running as root, privileged, hostPath). K09 is a bad *component* (an API server that answers anonymously, a kubelet with no auth). K01 lives in your manifests; K09 lives in the platform's own flags and certificates. Fixing every workload does nothing if the kubelet still executes anonymous commands.

### Myth 4: "K09 is the same as K04 missing policy enforcement"
**Reality**: K04 is the absence of an *admission policy engine* (Kyverno, Gatekeeper, PSA) validating workloads. K09 is the insecure configuration of the *components* themselves. They are related—PodSecurity is an admission plugin configured on the API server—but K04 asks "is anything checking my pods?" while K09 asks "is the API server itself locked down?"

### Myth 5: "The default flags are secure enough"
**Reality**: Modern Kubernetes ships far safer defaults than it used to—but hand-rolled clusters override those defaults explicitly, and in-place upgrades preserve old insecure flags. "Default" only helps if nothing overrode it, which is exactly what a benchmark scan verifies.

### Myth 6: "Audit logging is a nice-to-have"
**Reality**: Without an audit policy the API server keeps no record of who did what. When a component misconfiguration is exploited, the audit log is the only source of truth for scope and blast radius—and its absence is itself a compliance finding.

## How Misconfigured Components Differ from Related Risks

| Aspect | K09 Misconfigured Components | K01 Insecure Workloads | K04 No Policy Enforcement |
|--------|------------------------------|------------------------|---------------------------|
| **What is wrong** | Control-plane / node component flags & certs | A pod's own security context | No engine validating workloads |
| **Where it lives** | apiserver/kubelet/etcd config | Pod & container manifests | Admission webhooks / PSA |
| **Typical fix** | Harden flags per CIS, mTLS, disable anon | Drop privileges, no hostPath | Install Kyverno/Gatekeeper/PSA |
| **Detection** | kube-bench (CIS), kubescape | Manifest scan, PSA audit | Check for admission webhooks |

## Key Takeaways

1. **The control plane is the trust root**—a single anonymous or over-permissive component collapses every control above it.
2. **Authentication and authorization apply to infrastructure too**—the API server, kubelet, and etcd each need real authN/authZ and mTLS.
3. **etcd is your entire secret store**—require mutual TLS, keep it private, and encrypt Secrets at rest.
4. **Kubelets are a separate attack surface**—lock down `10250`, disable anonymous auth, and turn off the `10255` read-only port.
5. **Benchmark continuously**—the CIS Kubernetes Benchmark via kube-bench turns "is this hardened?" into an automated, repeatable check.

## How to Identify if You're Vulnerable

- [ ] Is `--anonymous-auth=false` on the API server, and is `--authorization-mode` set to `Node,RBAC` (never `AlwaysAllow`)?
- [ ] Is the legacy insecure port disabled (no `--insecure-port`, no `--insecure-bind-address`)?
- [ ] Are `NodeRestriction` and `PodSecurity` among the enabled admission plugins?
- [ ] Does every kubelet run with anonymous auth disabled and `authorization.mode: Webhook` (not `AlwaysAllow`)?
- [ ] Is the kubelet read-only port (`10255`) disabled (`readOnlyPort: 0`)?
- [ ] Does etcd require client-certificate (mutual TLS) authentication and listen only on a private interface?
- [ ] Are Kubernetes Secrets encrypted at rest via an `EncryptionConfiguration`?
- [ ] Is API-server audit logging enabled with a defined audit policy?
- [ ] Is `--profiling=false` on the API server, controller-manager, and scheduler, and are component metrics/debug ports not exposed publicly?
- [ ] Do you run `kube-bench` (CIS Benchmark) on a schedule and fail on regressions?

If you answered "no" or "not sure" to several of these, your cluster's foundations may be exploitable today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How reachable, over-permissive components are found and abused
- **[Prevention](prevention.md)**: Harden every component to the CIS Benchmark and verify with kube-bench
- **[Examples](examples.md)**: Insecure vs. hardened API-server, kubelet, and etcd configuration
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts hands-on
