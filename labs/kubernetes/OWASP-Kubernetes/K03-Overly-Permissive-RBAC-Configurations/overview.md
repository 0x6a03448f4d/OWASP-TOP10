# K03: Overly Permissive RBAC Configurations - Overview

## Table of Contents
- [What is Overly Permissive RBAC?](#what-is-overly-permissive-rbac)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detection](#prevalence-and-detection)
- [Common Misunderstandings](#common-misunderstandings)

## What is Overly Permissive RBAC?

**Role-Based Access Control (RBAC)** is the primary authorization system in Kubernetes. Every request to the API server—whether it comes from a human with a kubeconfig, a controller, or a Pod using its mounted ServiceAccount token—is authenticated, then checked against a set of *Roles* and *ClusterRoles* bound to that identity. RBAC decides whether the request is allowed. **K03 Overly Permissive RBAC** is the failure mode where those roles grant far more than the identity actually needs.

The danger is not abstract. RBAC is **additive and purely allow-based**: there are no `deny` rules, so every permission you grant is a permission that stays granted until someone explicitly removes the binding. A single over-broad rule—a wildcard verb, a `cluster-admin` binding on a ServiceAccount, the ability to create Pods in a namespace that also holds privileged tokens—turns a minor foothold (one compromised container) into full control of the cluster. Because the flaw lives in a YAML manifest rather than in application code, it is invisible to code review, survives every redeploy, and is copied wherever the manifest is reused.

### Core Concept

```
Least-privilege RBAC:
  Subject      -> one ServiceAccount per workload, automount disabled if unused
  Scope        -> namespaced Role, not a cluster-wide ClusterRole
  verbs        -> only what the workload calls (e.g. ["get","list","watch"])
  resources    -> the specific kinds it touches (e.g. ["configmaps"])
  resourceNames-> named objects where practical (e.g. ["app-config"])
  apiGroups    -> the exact group ("" for core, "apps", ...)
  bindings     -> RoleBinding to that one SA, reviewed and audited

Overly permissive RBAC:
  Subject      -> default ServiceAccount, token auto-mounted everywhere
  Scope        -> ClusterRole granting access in every namespace
  verbs        -> ["*"]  (create, delete, escalate, bind, impersonate...)
  resources    -> ["*"]  (pods, secrets, nodes, rolebindings, ...)
  resourceNames-> none    (applies to every object of the kind)
  apiGroups    -> ["*"]   (every API group, current and future)
  bindings     -> cluster-admin bound to a SA or a wide group
```

### Why It's Critical for Kubernetes

Kubernetes concentrates several conditions that make an over-broad role especially dangerous:

- Every Pod is an **authenticated API client by default**. Unless you disable it, a ServiceAccount token is mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token` inside the container, so any code-execution bug hands the attacker that identity's full RBAC.
- The API server is the **single control plane for everything**—workloads, secrets, nodes, network policy, and RBAC itself. Broad API permissions are broad control over the whole system.
- RBAC contains **verbs that grant control over RBAC** (`escalate`, `bind`) and over identity (`impersonate`), so one permissive grant can be used to mint more permissions.
- Manifests are **templated and copied** (Helm charts, operators, base manifests), so a single generous `ClusterRole` propagates across many clusters unchanged.

## Why Does This Matter?

### Business Impact

- **Full Cluster Takeover**: A path from one compromised Pod to `cluster-admin` means the attacker controls every workload, secret, and node—the entire platform and the data it runs.
- **Mass Secret Disclosure**: `get`/`list` on Secrets across namespaces exposes database passwords, API keys, TLS private keys, and cloud credentials in one request.
- **Lateral Movement into the Cloud**: Node and Pod access reaches the cloud instance metadata endpoint and node IAM roles, pivoting the breach out of the cluster into the cloud account.
- **Cryptojacking and Resource Abuse**: The ability to create Pods or DaemonSets lets an attacker schedule mining workloads across every node.
- **Compliance and Audit Failure**: Missing separation of duties and unaudited `cluster-admin` bindings fail CIS Kubernetes Benchmark, SOC 2, and PCI-DSS reviews.

### Technical Impact

- **Privilege Escalation**: `escalate`/`bind` on roles lets a subject grant itself permissions it does not yet hold; `impersonate` lets it act as any user, group, or ServiceAccount.
- **Token Theft**: `create` on `serviceaccounts/token` (TokenRequest) or the ability to schedule Pods that mount another SA mints or steals higher-privileged tokens.
- **Code Execution in Any Pod**: `create` on `pods/exec` or `pods/attach` runs commands inside running containers, including privileged ones.
- **Node Compromise**: `get` on `nodes/proxy` reaches the kubelet API to read secrets from other Pods and execute in them.
- **Workload Injection**: `create`/`update` on Pods, Deployments, or DaemonSets deploys attacker containers, often mounting the host filesystem to break out to the node.

## Technical Context

### How RBAC Objects Fit Together

| Object | What it is | Scope |
|--------|-----------|-------|
| `Role` | A set of permission rules (verbs on resources) | One namespace |
| `ClusterRole` | A set of permission rules, reusable cluster-wide | Cluster (or any namespace via a RoleBinding) |
| `RoleBinding` | Grants a Role *or* ClusterRole to subjects in one namespace | One namespace |
| `ClusterRoleBinding` | Grants a ClusterRole to subjects across all namespaces | Cluster-wide |
| Subject | A User, Group, or ServiceAccount the binding applies to | — |

A rule is the triple **apiGroups × resources × verbs** (optionally narrowed by `resourceNames`). Permissions are the *union* of every rule in every bound role. There is no way to subtract a permission with another rule—the only way to reduce access is to change or delete the grant.

### The Dangerous Grants

#### 1. Wildcards

```yaml
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

This is the single most dangerous rule in Kubernetes. It grants every verb on every resource in every API group—including RBAC objects, Secrets, and Nodes—*and* automatically covers any Custom Resource Definition installed later. Bound cluster-wide, it is equivalent to `cluster-admin`.

#### 2. cluster-admin bound to a ServiceAccount or wide group

```yaml
roleRef:
  kind: ClusterRole
  name: cluster-admin        # the built-in god-mode role
subjects:
- kind: ServiceAccount       # a workload identity, not a human break-glass account
  name: default
  namespace: apps
# or:
- kind: Group
  name: system:authenticated # EVERY authenticated identity in the cluster
```

Binding `cluster-admin` to a workload's ServiceAccount means compromising that one Pod is compromising the cluster. Binding any role to `system:authenticated` or `system:unauthenticated` grants it to essentially everyone.

#### 3. The escalation verbs

| Verb / resource | Why it is dangerous |
|-----------------|---------------------|
| `escalate` on `roles`/`clusterroles` | Bypasses the escalation-prevention check—lets a subject write a role granting permissions it does not currently hold. |
| `bind` on `roles`/`clusterroles` | Lets a subject create a RoleBinding to any role (including `cluster-admin`), granting itself that role. |
| `impersonate` on `users`/`groups`/`serviceaccounts` | Act as any other identity, inheriting all of its permissions—including `system:masters`. |
| `create` on `pods` (or Deployments, Jobs, DaemonSets) | Schedule a Pod that mounts a more privileged ServiceAccount token or the host filesystem. |
| `create` on `pods/exec`, `pods/attach` | Run commands inside existing running containers, including privileged ones. |
| `get` on `nodes/proxy` | Reach the kubelet API to read other Pods' secrets and exec into them. |
| `create` on `serviceaccounts/token` | TokenRequest API—mint fresh tokens for any ServiceAccount in the namespace. |
| `get`/`list` on `secrets` | Read every credential, token, and key stored in the namespace (or cluster). |
| `get`/`update` on `certificatesigningrequests/approval` | Approve CSRs to issue client certs for arbitrary identities, including group `system:masters`. |

#### 4. system:masters

```
# A client certificate whose Organization (O) field is system:masters
# is hard-wired to cluster-admin and BYPASSES RBAC entirely.
Subject: CN=attacker, O=system:masters
```

`system:masters` is a built-in super-group wired directly into the API server's authorizer. It is not governed by RBAC and cannot be revoked with an RBAC change—so any permission that can issue certificates or impersonate into that group is a total-compromise permission.

### The Default ServiceAccount Trap

Every namespace ships with a `default` ServiceAccount, and (unless disabled) every Pod that does not name a ServiceAccount is assigned it, with its token auto-mounted. On its own the default SA has almost no permissions—but teams routinely bind roles to it "to make things work," and because *every* unspecified Pod shares that identity, one over-broad binding on `default` silently grants those permissions to many unrelated workloads.

```yaml
# Anti-pattern: a Pod that does not need the API still carries a live token
apiVersion: v1
kind: Pod
spec:
  # no serviceAccountName -> uses "default"
  # no automountServiceAccountToken: false -> token is mounted and stealable
  containers:
  - name: web
    image: nginx
```

## Real-World Impact

### Case Study 1: Compromised Pod to Cluster-Admin via a Bound Role (incident class)

**Misconfiguration**:
- An application ServiceAccount was granted a `ClusterRole` with `secrets ["get","list"]` across all namespaces "so the app could read its own config."
- The same cluster stored a CI ServiceAccount token, with a `cluster-admin` binding, as a Secret in another namespace.

**Impact**:
- A remote-code-execution bug in the application let an attacker read the mounted token, list Secrets cluster-wide, harvest the CI token, and authenticate as `cluster-admin`—full takeover from a single web vulnerability.

**Root Cause**: Cluster-wide Secret read access on a workload identity, combined with a privileged token stored as a Secret. Neither was necessary at the scope granted.

### Case Study 2: escalate/bind Self-Promotion (incident class)

**Misconfiguration**:
- A platform operator's ServiceAccount was given `create`/`bind` on `clusterrolebindings` and `escalate` on `clusterroles` to "manage tenant permissions."

**Impact**:
- Anyone who compromised that operator could create a `ClusterRoleBinding` tying their own identity to `cluster-admin`, or write a new ClusterRole with wildcard rules—the escalation-prevention check does not apply once `escalate`/`bind` is granted.

**Root Cause**: Granting the meta-permissions that govern RBAC itself, rather than a narrow, named set of bindings the operator was allowed to manage.

### Case Study 3: Over-Permissioned default ServiceAccount (incident class)

**Misconfiguration**:
- To fix a permission error, a team bound a broad `edit`-style ClusterRole to the `default` ServiceAccount in a shared namespace.

**Impact**:
- Every Pod in that namespace—including third-party sidecars and an internet-facing service—silently inherited the ability to create Pods and read Secrets. A vulnerability in any one of them exposed all of them.

**Root Cause**: Binding permissions to the shared default identity instead of a dedicated, scoped ServiceAccount, so the grant leaked to unrelated workloads.

## Prevalence and Detection

Overly Permissive RBAC is one of the most common findings in Kubernetes security assessments, precisely because RBAC is additive, invisible to application testing, and easy to over-grant when chasing a "forbidden" error. Rather than cite precise counts (which vary by source), the durable picture is:

- Over-permissioning is **highly prevalent and easily detectable**—a handful of API queries or an open-source tool surface it in minutes.
- The most common sub-issues are **wildcard rules, `cluster-admin` bound to ServiceAccounts, broad Secret access, and unnecessary `create`/`escalate`/`bind`/`impersonate` grants**.
- The impact is rated **severe**: the realistic worst case is full cluster compromise from a single foothold.

> Note: exact percentages differ between reports and years. Treat any single figure as illustrative; the durable takeaway is that over-broad RBAC is common, cheap to find with `kubectl auth can-i` and RBAC auditors, and devastating when chained from an initial foothold.

## Common Misunderstandings

### Myth 1: "RBAC has deny rules, so a broad grant can be fenced off"

**Reality**: RBAC is allow-only and additive. There are no deny rules. The union of all bound roles is what applies; the only way to remove access is to change or delete the grant itself.

### Myth 2: "It's just read access, so it's low risk"

**Reality**: `get`/`list` on Secrets is read access that hands over every credential in scope. Read on `nodes/proxy` reaches the kubelet. "Read" is not synonymous with "safe."

### Myth 3: "The token isn't in the Pod unless we put it there"

**Reality**: ServiceAccount tokens are auto-mounted by default. Unless you set `automountServiceAccountToken: false`, any code execution in the container can read the token and use the identity's RBAC.

### Myth 4: "cluster-admin on a ServiceAccount is fine for an internal operator"

**Reality**: A ServiceAccount is a non-human identity with an always-available token. Binding `cluster-admin` to it makes that single workload a cluster-wide skeleton key that never has to log in.

### Myth 5: "Wildcards are convenient and we'll tighten them later"

**Reality**: Wildcards also grant access to resources that do not exist yet—every future CRD is covered automatically. "Later" rarely comes, and the blast radius keeps growing silently.

### Myth 6: "Namespaced Roles can't cause cluster-wide damage"

**Reality**: A namespaced Role that allows `create` on Pods can schedule a Pod mounting a more privileged SA, mount the host filesystem, or reach node metadata—escaping the namespace boundary entirely.

## How Overly Permissive RBAC Differs from Related Issues

| Aspect | Overly Permissive RBAC (K03) | Insecure Workload Config (K01) | Missing Network Segmentation (K05) |
|--------|------------------------------|--------------------------------|------------------------------------|
| **Root cause** | Over-broad API authorization | Privileged/host-exposing Pod specs | Flat, unrestricted Pod networking |
| **Where it lives** | Roles, ClusterRoles, bindings | Pod/container securityContext | NetworkPolicy (or its absence) |
| **Typical fix** | Least-privilege rules, scoped bindings | Drop privileges, restrict host access | Default-deny NetworkPolicies |
| **Detection** | `kubectl auth can-i`, RBAC auditors | Admission policy, manifest scan | Policy audit, traffic analysis |

## Key Takeaways

1. **RBAC is additive and allow-only**—every grant persists until removed; there is no deny to fall back on.
2. **Wildcards and cluster-admin bindings are the crown-jewel mistakes**—they turn one foothold into total control.
3. **A handful of verbs are escalation primitives**—`escalate`, `bind`, `impersonate`, `create` on Pods/exec, and Secret reads deserve special scrutiny.
4. **ServiceAccount tokens are auto-mounted**—a compromised Pod is a compromised identity unless automount is disabled.
5. **Least privilege must be the default**—scoped Roles, named resources, dedicated ServiceAccounts, and audited bindings.

## How to Identify if You're Vulnerable

- [ ] Does any Role or ClusterRole use `verbs: ["*"]`, `resources: ["*"]`, or `apiGroups: ["*"]`?
- [ ] Is `cluster-admin` bound to any ServiceAccount, or to a wide group like `system:authenticated`?
- [ ] Can any workload identity `get`/`list` Secrets beyond the ones it actually uses?
- [ ] Does any non-RBAC-management identity have `escalate`, `bind`, or `impersonate`?
- [ ] Can any application SA `create` Pods, Deployments, or `pods/exec` where it doesn't need to?
- [ ] Are permissions bound to the `default` ServiceAccount in any namespace?
- [ ] Is `automountServiceAccountToken` disabled for Pods that never call the API?
- [ ] Are ClusterRoles used where a namespaced Role would suffice?
- [ ] Do any subjects have access to `nodes/proxy`, `serviceaccounts/token`, or CSR approval?
- [ ] Is RBAC audited on a schedule (`kubectl auth can-i --list`, rbac-tool, kubectl-who-can, KubiScan)?

If you answered "yes" or "not sure" to several of these, you likely have exploitable over-permissioning today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers enumerate and escalate through permissive RBAC
- **[Prevention](prevention.md)**: Build least-privilege roles and audit RBAC continuously
- **[Examples](examples.md)**: Insecure vs. secure RBAC YAML, side by side
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts in hands-on exercises
