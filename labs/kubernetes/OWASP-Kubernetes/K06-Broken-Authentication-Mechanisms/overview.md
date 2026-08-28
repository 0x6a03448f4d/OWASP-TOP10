# K06: Broken Authentication Mechanisms - Overview

## Table of Contents
- [What is Broken Authentication?](#what-is-broken-authentication)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Broken Authentication?

**Broken Authentication Mechanisms** (K06 in the OWASP Kubernetes Top 10) is the condition of running a cluster where the question *"who is making this request?"* is answered weakly, incompletely, or not at all. Kubernetes does not authenticate requests by itself—it delegates the decision to a chain of pluggable methods (client certificates, bearer tokens, ServiceAccount tokens, OIDC, and authenticating proxies). When any link in that chain is disabled, misconfigured, overly trusting, or protected by long-lived shared secrets, an attacker can present as a legitimate identity—or as no identity at all—and still be let in.

Authentication is the **first gate** in the Kubernetes request pipeline. Every call to the API server passes through authentication, then authorization (RBAC, K03), then admission control. If authentication is broken, RBAC never gets a real subject to reason about: a request that arrives as `system:anonymous` or as a stolen `system:serviceaccount:*` identity is evaluated against *that* identity's permissions, not the attacker's. Break the first gate and every downstream control is reasoning about the wrong principal.

> Authentication answers **who you are**; authorization (K03) answers **what you may do**. K06 is about the former. A perfect RBAC policy is worthless if an attacker can walk through the door wearing a valid badge—or with no badge at all because the guard was told to wave everyone through.

### Core Concept

```
Cluster that verifies identity:
  API server     -> anonymous auth disabled; every request maps to a
                    real, named subject or is rejected 401
  Humans         -> OIDC / SSO with MFA, short-lived tokens, group claims
  Workloads      -> projected ServiceAccount tokens: short-lived, audience-
                    bound, auto-rotated (TokenRequest API)
  Kubelet        -> its own API (10250) requires auth + authz, no anonymous
  etcd           -> mutual TLS, client certs, never exposed to the network
  Certificates   -> scoped, rotated, revocable; no shared cluster-admin certs

Cluster with broken authentication:
  API server     -> --anonymous-auth=true: system:anonymous reaches the API
  Humans         -> one shared kubeconfig with an embedded cluster-admin cert
                    that never expires and cannot be revoked
  Workloads      -> legacy non-expiring SA token secrets, mounted everywhere
  Kubelet        -> 10250 open with --anonymous-auth=true: exec/logs to anyone
  etcd           -> plaintext or no client-cert auth, reachable on the network
  Certificates   -> one long-lived admin cert copied between laptops and CI
```

### Why It's Critical for Kubernetes

Kubernetes concentrates several conditions that make broken authentication uniquely dangerous:

- The API server is a **single, uniform control plane** for the whole cluster. One authenticated-as-cluster-admin request can read every Secret, exec into every Pod, and schedule workloads on every node.
- Authentication is **spread across several components**—the API server, each node's kubelet, and etcd all authenticate independently. Hardening one and forgetting the others leaves a side door open.
- Workloads carry **machine identities by default**. Every Pod can be given a ServiceAccount token; if those tokens are long-lived and broadly mounted, every compromised container is a credential-theft opportunity.
- Credentials are **copied constantly**—kubeconfigs on laptops, in CI systems, in Helm charts, in cloud secrets. A single leaked long-lived credential with no rotation or revocation path is a persistent backdoor.
- Cluster identities frequently **bridge to cloud IAM**. A weak mapping between cloud identity and Kubernetes identity turns a modest cloud foothold into cluster-admin.

## Why Does This Matter?

### Business Impact
- **Full Cluster Takeover**: Unauthenticated or weakly-authenticated access to the API server, kubelet, or etcd can escalate to control of every workload and secret in the cluster.
- **Mass Secret Disclosure**: The API and etcd hold Secrets for databases, cloud accounts, and third-party APIs. Broken authentication turns one exposure into a breach of everything the cluster can reach.
- **Cryptojacking and Resource Abuse**: Open control planes are routinely hijacked to schedule cryptomining workloads—an attack that requires no exploit, only an unauthenticated door.
- **Regulatory and Contractual Fallout**: Clusters process regulated data (PII, cardholder data, health records). Loss of authentication triggers GDPR, HIPAA, and PCI-DSS breach obligations.
- **Persistence That Survives Rotation**: A leaked long-lived certificate or non-expiring token that cannot be revoked gives an attacker durable access long after the initial intrusion is "cleaned up."

### Technical Impact
- **Anonymous API Access**: With anonymous auth enabled, `system:anonymous` and the `system:unauthenticated` group reach the API and are evaluated by RBAC—dangerous the moment any binding grants those subjects anything.
- **Node-Level Command Execution**: An unauthenticated kubelet API on port 10250 exposes `exec`, `run`, and `logs` against any Pod on that node—direct command execution inside containers.
- **Datastore Exposure**: etcd without client-certificate authentication or TLS lets anyone who reaches it read and write the entire cluster state, including every Secret in plaintext.
- **Credential Replay**: A stolen ServiceAccount token or client certificate can be replayed from anywhere until it expires or is revoked—and legacy tokens never expire.
- **Identity Confusion**: A trusting authenticating proxy or a sloppy OIDC configuration lets an attacker assert an arbitrary username or group, including privileged ones.

## Technical Context

### How Kubernetes Authenticates a Request

When a request reaches the API server, the authentication layer runs each configured method in turn until one succeeds. The result is a **username** and a set of **groups**; that identity is then handed to authorization. If no method succeeds, the request is either rejected with `401` or—if anonymous auth is enabled—treated as the anonymous identity.

```
Request --> [ Authentication ] --> username + groups --> [ Authorization (RBAC) ] --> [ Admission ] --> etcd

Authenticators the API server may try, in order:
  1. Client certificate    (CN -> username, O -> groups)
  2. Bearer token          (static token file, legacy; discouraged)
  3. ServiceAccount token  (JWT signed by the cluster; workload identity)
  4. OIDC id_token         (external IdP; for human SSO)
  5. Authenticating proxy  (trusted front proxy sets identity headers)
  6. Anonymous            (system:anonymous / system:unauthenticated)
```

### Common Broken-Authentication Scenarios

#### 1. Anonymous Authentication Enabled

```
# API server flag (dangerous when combined with any binding to
# system:anonymous or the system:unauthenticated group):
kube-apiserver --anonymous-auth=true

# An unauthenticated probe is accepted as system:anonymous:
$ curl -k https://API_SERVER:6443/api/v1/namespaces/default/pods
# If RBAC grants anything to system:unauthenticated, this returns data.
```

**Risk**: Every request that fails all other authenticators is silently downgraded to an anonymous identity instead of being rejected. A single over-broad `ClusterRoleBinding` to `system:unauthenticated` becomes cluster-wide unauthenticated access.

#### 2. Unauthenticated Kubelet API (Port 10250)

```
# Kubelet started with anonymous auth on and authz set to AlwaysAllow:
kubelet --anonymous-auth=true --authorization-mode=AlwaysAllow

# Anyone who can reach the node can list pods and exec into them:
$ curl -sk https://NODE:10250/pods
$ curl -sk https://NODE:10250/run/<ns>/<pod>/<container> -d "cmd=id"
```

**Risk**: The kubelet is a second, node-local API. Left unauthenticated, it hands out Pod command execution and log access with no involvement from the API server or RBAC at all.

#### 3. Exposed etcd Without Authentication or TLS

```
# etcd reachable on the network with no client-cert requirement:
$ etcdctl --endpoints=https://ETCD:2379 get / --prefix --keys-only
# Cluster state, including every Secret, is stored here.
# Secrets are base64-encoded, not encrypted, unless encryption-at-rest is on.
```

**Risk**: etcd is the cluster's source of truth. Read access is total disclosure; write access is total control. It must require mutual TLS and never be network-reachable beyond the control plane.

#### 4. Long-Lived / Legacy ServiceAccount Tokens

```
# Legacy: a non-expiring token stored in a Secret, mounted into pods.
apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token   # never expires, not audience-bound
metadata:
  name: build-bot-token
  annotations:
    kubernetes.io/service-account.name: build-bot
```

**Risk**: A token that never expires and is valid for any audience is a permanent bearer credential. Steal it once from a compromised Pod, a log, or an environment variable, and replay it indefinitely from anywhere.

#### 5. Shared, Long-Lived kubeconfigs and Client Certificates

```
# A kubeconfig with an embedded client cert whose CN maps to a
# powerful identity and whose validity is measured in years:
users:
- name: cluster-admin
  user:
    client-certificate-data: <base64 X.509, O=system:masters>   # 5-year cert
```

**Risk**: Kubernetes has *no built-in certificate revocation*. A leaked client cert—especially one with `O=system:masters`—is valid until it expires. If it is long-lived and shared across a team or CI, a single leak is an unrevocable cluster-admin backdoor.

#### 6. No OIDC/SSO for Humans

```
# Instead of federated identity, every engineer shares one kubeconfig,
# or each holds a personal long-lived cert with no central control:
#   - no MFA
#   - no central revocation when someone leaves
#   - no per-user audit attribution (everyone is "cluster-admin")
```

**Risk**: Without OIDC/SSO, human access relies on static credentials that cannot be centrally revoked, carry no MFA, and destroy audit attribution because everyone shares one identity.

### Where Authentication Can Break

| Component / Layer | Typical Broken-Auth Condition | Consequence |
| --- | --- | --- |
| API server | Anonymous auth enabled; static token/basic-auth file | Unauthenticated or shared-secret access to the control plane |
| Kubelet (10250) | Anonymous auth on, authz `AlwaysAllow` | Pod exec/log access with no RBAC |
| etcd (2379) | No mutual TLS, network-reachable | Full cluster-state read/write, all Secrets exposed |
| ServiceAccount tokens | Legacy non-expiring, broadly mounted | Replayable workload credentials |
| Human access | Shared kubeconfig / long-lived certs, no OIDC | No revocation, no attribution, no MFA |
| Cloud IAM ↔ RBAC | Weak or over-broad identity mapping | Cloud foothold escalates to cluster-admin |
| Dashboards / add-ons | Kubernetes Dashboard exposed without auth | Anonymous UI-driven cluster control |

## Real-World Impact

### Incident Class 1: Exposed Administrative Dashboards

**Condition**:
- A cluster management UI (such as the Kubernetes Dashboard) was deployed reachable from the internet with no authentication in front of it, or bound to a highly-privileged ServiceAccount.
- Cloud credentials and cluster Secrets were reachable from within the exposed environment.

**Impact**:
- Attackers used the open console to schedule workloads—commonly cryptomining—and to read Secrets, without ever presenting a credential. This is the well-documented "Tesla-class" exposure pattern: an unauthenticated management plane reachable from the internet.

**Root Cause**: An administrative interface deployed with no authentication and exposed publicly—a control-plane authentication failure rather than an application bug.

### Incident Class 2: Unauthenticated Kubelet and etcd

**Condition**:
- Node kubelet APIs on port 10250 were left with anonymous authentication enabled, and/or etcd was reachable on the network without mutual-TLS client authentication.

**Impact**:
- Reaching an unauthenticated kubelet yields `exec` into running Pods—command execution inside workloads. Reaching unauthenticated etcd yields the entire cluster state, including every Secret. Either is a direct path from network reachability to cluster compromise.

**Root Cause**: Control-plane and node components deployed with their authentication turned off or never configured, on the assumption that the network was "internal."

### Incident Class 3: Leaked Long-Lived Credentials

**Condition**:
- Long-lived kubeconfigs, client certificates, or legacy ServiceAccount token Secrets were committed to source control, embedded in CI logs, or copied between machines—with no rotation and no revocation path.

**Impact**:
- Because Kubernetes provides no certificate revocation and legacy tokens never expire, a single leaked credential remains a valid cluster identity indefinitely—an unrevocable backdoor that survives incident "cleanup."

**Root Cause**: Static, shared, long-lived credentials treated as if they were disposable—combined with the absence of expiry and revocation.

## Prevalence and Detectability

Broken authentication is consistently found in real clusters because so many of its causes are **defaults or conveniences**: anonymous auth has historically been on, legacy SA token Secrets were the norm, and sharing one kubeconfig is easier than wiring up OIDC. It is also **highly detectable**—an unauthenticated request to the API server, kubelet, or etcd either works or it does not, and internet-wide scanners probe these ports continuously.

Rather than cite precise breach counts (which vary by source), the defensible picture is:

- The most commonly observed sub-issues are **anonymous auth left enabled, unauthenticated kubelet/etcd, legacy long-lived SA tokens, and shared human kubeconfigs with no OIDC or MFA**.
- The flaws are **easy to find**: a single unauthenticated request confirms them, and exposed control planes are indexed by internet scanners within hours.
- The impact is rated **severe**: it ranges from anonymous read access up to full cluster takeover and mass secret disclosure.

> Note: exact percentages and incident counts differ between reports and years. Treat any single figure as illustrative; the durable takeaway is that broken authentication is common, trivially detectable, and catastrophic when exploited.

## Common Misunderstandings

### Myth 1: "RBAC protects us, so authentication details don't matter"
**Reality**: RBAC only decides what a *known identity* may do. If authentication is broken, RBAC is handed the wrong identity—`system:anonymous`, a stolen ServiceAccount, or a spoofed proxy header. Authorization cannot fix a false answer to "who are you?"

### Myth 2: "Anonymous auth is harmless because nothing is bound to anonymous"
**Reality**: It is one accidental `ClusterRoleBinding` away from disaster, and it is a standing footgun. Some health endpoints aside, disabling anonymous auth removes the risk entirely rather than depending on RBAC never granting anonymous anything.

### Myth 3: "Our cluster is on a private network, so the kubelet and etcd are safe"
**Reality**: Internal networks are routinely reached through SSRF, a compromised Pod, a misconfigured LoadBalancer, or a VPN pivot. An unauthenticated kubelet or etcd is one hop away from any foothold—authenticate them regardless of network position.

### Myth 4: "ServiceAccount tokens are fine as-is"
**Reality**: Legacy tokens never expire and are valid for any audience, so a single leak is permanent. Projected, bound, short-lived tokens issued through the TokenRequest API expire quickly and are scoped to an audience—a stolen one is useful for minutes, not forever.

### Myth 5: "A client certificate is more secure than a password, so long-lived certs are fine"
**Reality**: Kubernetes has no certificate revocation list. A long-lived cert—especially `O=system:masters`—is a bearer credential that stays valid until it expires, no matter how many times it leaks. Keep certs short-lived and rotate them.

### Myth 6: "We use a cloud provider, so authentication is handled for us"
**Reality**: Managed control planes still let you enable anonymous auth, mount legacy tokens, expose dashboards, and map cloud IAM to cluster-admin too broadly. The provider secures the control plane it runs; the identity configuration is still yours to get right.

## How Broken Authentication Differs from Related Issues

| Aspect | Broken Authentication (K06) | Overly Permissive RBAC (K03) | Insecure Workload Config (K01) |
| --- | --- | --- | --- |
| **Question it answers** | Who is this request from? | What may this identity do? | How is this workload allowed to run? |
| **Root cause** | Weak/absent identity verification | Over-broad role bindings | Privileged/unconstrained Pod settings |
| **Typical fix** | Disable anonymous, OIDC, short-lived tokens, mTLS | Least-privilege roles, scoped bindings | SecurityContext, drop privileges |
| **Detection** | Unauthenticated probe, credential audit | RBAC review (`kubectl auth can-i`) | Manifest/admission scanning |

## Key Takeaways

1. **Authentication is the first gate**—break it and every downstream control (RBAC, admission) reasons about the wrong principal.
2. **It is spread across components**—the API server, every kubelet, and etcd authenticate independently; harden all three.
3. **Anonymous access should be off**—never rely on RBAC to have granted `system:anonymous` nothing by accident.
4. **Prefer short-lived, scoped credentials**—projected/bound SA tokens and short-lived certs limit the value of any theft.
5. **Long-lived shared secrets are backdoors**—certs can't be revoked and legacy tokens never expire, so a single leak is permanent.

## How to Identify if You're Vulnerable

Ask these questions about your cluster:

- [ ] Is anonymous authentication disabled on the API server (`--anonymous-auth=false`), or tightly justified where left on?
- [ ] Does the kubelet require authentication and authorization (no `--anonymous-auth=true`, no `--authorization-mode=AlwaysAllow`)?
- [ ] Is etcd protected with mutual TLS and unreachable from outside the control plane?
- [ ] Have all static token files and basic-auth files been removed from the API server?
- [ ] Do workloads use short-lived, audience-bound projected ServiceAccount tokens instead of legacy non-expiring token Secrets?
- [ ] Is `automountServiceAccountToken` disabled for Pods and ServiceAccounts that don't need API access?
- [ ] Do humans authenticate through OIDC/SSO with MFA rather than a shared kubeconfig?
- [ ] Are client certificates short-lived and rotated, with no shared `system:masters` certs in circulation?
- [ ] Is the Kubernetes Dashboard (and any admin UI) authenticated and never exposed publicly?
- [ ] Is the cloud-IAM-to-RBAC mapping least-privilege, so a modest cloud identity can't assume cluster-admin?

If you answered "no" or "not sure" to several of these, an attacker who reaches your control plane today could likely authenticate as someone—or as no one—and act.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers reach and abuse weakly-authenticated components
- **[Prevention](prevention.md)**: Disable anonymous access, adopt OIDC, and issue short-lived credentials
- **[Examples](examples.md)**: Insecure vs. secure API-server, kubelet, etcd, and token configuration
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
