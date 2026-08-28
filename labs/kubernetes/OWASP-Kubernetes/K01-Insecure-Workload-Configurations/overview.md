# K01: Insecure Workload Configurations - Overview

## Table of Contents
- [What are Insecure Workload Configurations?](#what-are-insecure-workload-configurations)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)
- [How to Identify if You're Vulnerable](#how-to-identify-if-youre-vulnerable)

## What are Insecure Workload Configurations?

**K01: Insecure Workload Configurations** is the first entry in the OWASP Kubernetes Top 10. It covers Pods, Deployments, DaemonSets, and every other workload that is admitted to a cluster with a `securityContext` (or pod spec) that hands an attacker an easy path to escalate. The vulnerability is not in the application code running inside the container—it is in the *manifest*: the YAML that tells the kubelet and container runtime how much of the host to expose to that container.

Kubernetes gives a workload access to the host in proportion to what the manifest asks for. Ask for nothing, and the container is a reasonably well-isolated process. Ask for `privileged: true`, host namespaces, host paths, or dangerous Linux capabilities, and the "container boundary" becomes a formality an attacker steps over in seconds. Because these fields default to the *permissive* side for backward compatibility, a workload that never mentions security is already less safe than it could be.

### Core Concept

```
Hardened workload (least privilege):
  runAsNonRoot            -> true, with an explicit non-zero runAsUser
  allowPrivilegeEscalation -> false (no setuid gain of new privileges)
  privileged              -> false (no full device / host access)
  capabilities            -> drop ["ALL"], add back nothing (or one, narrowly)
  readOnlyRootFilesystem  -> true (writable dirs mounted explicitly)
  seccompProfile          -> RuntimeDefault (syscall filtering on)
  host namespaces         -> hostPID / hostIPC / hostNetwork all false
  hostPath volumes        -> none (no /, no /var/run/docker.sock)
  automountServiceAccountToken -> false unless the app calls the API
  resources.limits        -> cpu / memory / ephemeral-storage set

Insecure workload (easy escalation):
  privileged: true                 -> container ~= root on the node
  hostPID: true / hostIPC: true    -> see and signal host processes
  hostNetwork: true                -> host NICs, localhost services, metadata
  hostPath: / or docker.sock       -> read/write the node filesystem or runtime
  runAsNonRoot: false / uid 0      -> root inside the container
  allowPrivilegeEscalation: true   -> setuid binaries can gain privileges
  capabilities.add: [SYS_ADMIN]    -> mount, ptrace, escape primitives
  seccomp: Unconfined              -> full syscall surface to the kernel
  default ServiceAccount token mounted -> cluster credential handed to attacker
```

### Why It's Critical for Kubernetes

Kubernetes changes the blast radius of a single bad setting. On a traditional server, a compromised process is on one machine. In a cluster, several conditions amplify the damage:

- Workloads are **declared once and scheduled everywhere**. A single insecure Deployment template is replicated across every node it lands on, so the weakness is fleet-wide, not host-specific.
- The **container boundary is a shared-kernel boundary**. Containers on a node share one Linux kernel; a privileged or over-capable container is one syscall away from the host that runs every other tenant's workloads.
- Every Pod is, by default, **issued a cluster identity**. The default ServiceAccount token is mounted into the container filesystem, so code execution in a Pod frequently means possession of a usable API credential.
- **Nodes are gateways to the control plane and the cloud**. Escaping to a node exposes the kubelet, other Pods' secrets, and—on managed clusters—the cloud instance metadata service and its IAM role.

## Why Does This Matter?

### Business Impact

- **Full Node and Cluster Compromise**: A container escape turns one vulnerable application into control of the node, its co-located workloads, and often the wider cluster—far beyond the original app's data.
- **Credential and Secret Theft**: Mounted ServiceAccount tokens, other Pods' mounted Secrets, and cloud metadata credentials are harvested and reused to move laterally into cloud accounts.
- **Cryptojacking and Resource Abuse**: Over-privileged, unbounded workloads are a favourite target for automated crypto-mining that runs up compute bills and starves legitimate workloads.
- **Regulatory and Contractual Fallout**: Multi-tenant clusters that leak one customer's data into another's reach trigger GDPR, HIPAA, and PCI-DSS obligations, fines, and breach notifications.
- **Availability Loss**: Workloads with no resource limits allow a single noisy or hostile Pod to exhaust a node's CPU or memory and evict its neighbours.

### Technical Impact

- **Container Escape to Node**: `privileged`, `SYS_ADMIN`, host `hostPath` mounts, and host namespaces each provide a well-documented primitive for breaking out onto the host.
- **Lateral Movement**: A stolen ServiceAccount token or node kubelet access is used to read Secrets, create new Pods, or reach the API server.
- **Privilege Escalation Inside the Container**: Running as root plus `allowPrivilegeEscalation: true` lets a foothold become full in-container root via setuid binaries.
- **Host Filesystem Read/Write**: A `hostPath` of `/` exposes every file on the node, including other containers' layers, kubelet credentials, and SSH keys.
- **Runtime Takeover**: A mounted `/var/run/docker.sock` (or containerd socket) lets a container launch a new privileged container and own the node instantly.

## Technical Context

### The Dangerous Fields, One by One

#### 1. Privileged Containers

```yaml
securityContext:
  privileged: true
```

A privileged container runs with nearly all capabilities, an unconfined seccomp/AppArmor profile, and access to all host devices under `/dev`. It is effectively root on the node. This single flag defeats almost every other isolation control at once and is the most direct escape primitive in Kubernetes.

#### 2. Host Namespaces (hostPID / hostIPC / hostNetwork)

```yaml
spec:
  hostPID: true       # see and signal every process on the node
  hostIPC: true       # access host shared memory / IPC
  hostNetwork: true   # use the node's network stack directly
```

**Risk**: `hostPID` exposes other processes (and their `/proc`, environment variables, and open file descriptors) for inspection and injection. `hostNetwork` reaches services bound to the node's `localhost` (often unauthenticated) and the cloud metadata endpoint, and bypasses NetworkPolicy.

#### 3. Host Path Mounts

```yaml
volumes:
  - name: host-root
    hostPath:
      path: /                       # entire node filesystem
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock    # the container runtime socket
```

**Risk**: Mounting the node root or the runtime socket is a direct escape. With the socket, an attacker starts a new container that mounts the host and runs as root. With `/`, they read kubelet credentials and write to sensitive paths.

#### 4. Running as Root and Privilege Escalation

```yaml
securityContext:
  runAsNonRoot: false     # (or simply unset) -> UID 0 allowed
  # runAsUser omitted     -> image default, often root
  allowPrivilegeEscalation: true
```

**Risk**: A container running as UID 0 that also permits privilege escalation lets any foothold reach full in-container root, then leverage capabilities or a kernel bug against the host.

#### 5. Dangerous Added Capabilities

```yaml
securityContext:
  capabilities:
    add: ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
```

**Risk**: `SYS_ADMIN` alone enables mount operations and many escape techniques; `SYS_PTRACE` allows inspecting and manipulating other processes; `NET_ADMIN` allows network manipulation and traffic interception. Most workloads need *none* of these.

#### 6. Unconfined seccomp / AppArmor

```yaml
securityContext:
  seccompProfile:
    type: Unconfined      # no syscall filtering
# or annotation: container.apparmor.security.beta.kubernetes.io/... : unconfined
```

**Risk**: Disabling syscall filtering exposes the full kernel API to the container, widening the surface for kernel exploits used in escapes.

#### 7. Writable Root Filesystem and Missing Resource Limits

```yaml
securityContext:
  readOnlyRootFilesystem: false   # attacker can drop tools / persist
resources: {}                     # no cpu/memory limits -> noisy-neighbour DoS
```

**Risk**: A writable root filesystem lets an attacker install tooling and persist; missing limits let a single Pod exhaust a node.

#### 8. Automounted Default ServiceAccount Token

```
# Default behaviour: a token for the namespace's default ServiceAccount
# is mounted at /var/run/secrets/kubernetes.io/serviceaccount/token
```

**Risk**: If the app never calls the Kubernetes API, this token is pure downside—code execution in the Pod hands the attacker a cluster credential to enumerate and, depending on RBAC, escalate.

### Where the Configuration Lives

| Field | Insecure Setting | Escalation It Enables |
|-------|------------------|-----------------------|
| `privileged` | `true` | Full node access; near-instant escape |
| `hostPID` / `hostIPC` / `hostNetwork` | `true` | Host process/IPC/network access, metadata reach |
| `hostPath` | `/`, `docker.sock` | Node filesystem or runtime takeover |
| `runAsNonRoot` | `false` / unset | Root inside container |
| `allowPrivilegeEscalation` | `true` | setuid gain of new privileges |
| `capabilities.add` | `SYS_ADMIN`, `NET_ADMIN` | Mount, ptrace, network escape primitives |
| `seccompProfile` | `Unconfined` | Full kernel syscall surface |
| `automountServiceAccountToken` | `true` (default) | Cluster credential theft |

## Real-World Impact

The incidents below are described as **verifiable classes of attack** that are repeatedly documented in public research and post-mortems. They avoid precise fabricated figures; the durable lesson is the pattern, not a single number.

### Case Class 1: Privileged-Container Escape to the Node

**Misconfiguration**:
- A workload runs with `privileged: true` or with `SYS_ADMIN` and an unconfined profile, often justified as "our build/CI/monitoring agent needs it."
- An application flaw (RCE, SSRF-to-exec, a poisoned dependency) gives an attacker command execution inside that container.

**Impact**: Because the container is privileged, the attacker uses a standard breakout technique (writing to host devices, abusing cgroups release-agent, or mounting the host filesystem) to run code on the node, then reads every co-located Pod's secrets. **Root cause**: a workload granted host-equivalent power for convenience, with no admission control to stop it.

### Case Class 2: Exposed Container Runtime Socket (docker.sock)

**Misconfiguration**:
- A Pod mounts `/var/run/docker.sock` (or the containerd socket) via `hostPath`—a common pattern for "docker-in-docker" build agents and some monitoring tools.

**Impact**: Any code in that Pod can talk to the runtime directly and launch a new container that is privileged and mounts the host root, achieving node takeover without any kernel exploit at all. **Root cause**: handing a workload control of the very runtime that is supposed to contain it.

### Case Class 3: Cryptojacking of Misconfigured Workloads (Tesla-style)

**Misconfiguration**:
- In the widely reported 2018 Tesla incident, an administrative Kubernetes dashboard was reachable without authentication, and the environment held cloud credentials and permissive workloads.
- More broadly, this is the pattern where an exposed or over-permissive workload/console lets attackers schedule their own Pods.

**Impact**: Attackers deployed cryptomining workloads inside the cluster (cryptojacking) and could reach non-public cloud resources. **Root cause**: a management surface plus permissive workload settings that let untrusted actors run arbitrary, unrestricted containers.

> Note: specifics vary by incident and year. Treat each case as a *class* of failure—privileged escape, runtime-socket exposure, and cryptojacking of open/permissive workloads are all repeatedly observed. The takeaway is the mechanism, not an exact statistic.

## Prevalence and Statistics

Insecure Workload Configurations is placed **first** in the OWASP Kubernetes Top 10 for good reason: it is both common and high-impact. Because permissive fields exist for backward compatibility and many popular Helm charts historically shipped without a hardened `securityContext`, insecure workloads appear in a large share of real clusters.

Rather than cite precise percentages (which vary by scanner and dataset), the defensible picture is:

- Missing or permissive `securityContext` is **one of the most frequently flagged findings** by cluster benchmark tools (CIS Kubernetes Benchmark, kube-bench, kubescape, Polaris, Trivy).
- The most common sub-issues are **containers running as root, no `readOnlyRootFilesystem`, capabilities not dropped, missing resource limits, and default ServiceAccount token automount**.
- The impact ranges from **none-to-noisy (missing limits) up to full node/cluster compromise (privileged, docker.sock, host namespaces)**.

> The durable takeaway: insecure workload configuration is prevalent, trivially detectable with off-the-shelf scanners, and—when it involves privilege—among the highest-severity issues a cluster can carry.

## Common Misunderstandings

### Myth 1: "Containers are isolated, so the securityContext is optional"

**Reality**: Containers share the host kernel. Isolation is a set of Linux features (namespaces, cgroups, capabilities, seccomp) that the manifest can weaken or switch off. A permissive workload is not "isolated with a small caveat"—it is a normal host process wearing a thin costume.

### Myth 2: "We run as root inside the container, but that's not host root"

**Reality**: Without user namespaces (off by default in most clusters), UID 0 in the container maps to UID 0 on the host. Combined with a writable `hostPath`, an added capability, or a kernel bug, in-container root becomes host root quickly.

### Myth 3: "Our app doesn't use the Kubernetes API, so the token doesn't matter"

**Reality**: If the app never calls the API, the automounted token is pure risk with no benefit. An attacker who lands in the Pod inherits a valid cluster credential. Set `automountServiceAccountToken: false`.

### Myth 4: "Only the CI/build workload is privileged, and that's fine"

**Reality**: Build and CI workloads process untrusted input (pull requests, dependencies, images) and are prime targets. A privileged build Pod is one of the most dangerous things in a cluster, not an acceptable exception.

### Myth 5: "Pod Security Policies are deprecated, so there's nothing to enforce with"

**Reality**: PSP was replaced by **Pod Security Admission** (built-in, with `baseline` and `restricted` levels) and by policy engines like **Kyverno** and **OPA Gatekeeper**. Enforcement is more capable now, not absent.

### Myth 6: "NetworkPolicy or a firewall will contain a privileged container"

**Reality**: A container that escapes to the node operates with the node's identity and network position, and `hostNetwork` bypasses NetworkPolicy entirely. Network controls do not contain a host-level compromise.

## How K01 Differs from Related Kubernetes Risks

| Aspect | K01 Insecure Workload Config | K03 Overly Permissive RBAC | K08 Secrets Management |
|--------|------------------------------|----------------------------|------------------------|
| **Root cause** | Permissive pod/securityContext fields | Broad roles and bindings | Secrets exposed or unencrypted |
| **Where it lives** | Workload manifests | Role / RoleBinding objects | Secret objects, mounts, etcd |
| **Typical fix** | Harden securityContext, admission policy | Least-privilege RBAC | Encrypt, scope, rotate |
| **Detection** | Manifest scan, PSA, Kyverno/Gatekeeper | RBAC audit | Secret scan, etcd config |

## Key Takeaways

1. **The manifest is the security boundary**—what the workload asks for is what the attacker gets.
2. **Defaults lean permissive**; a workload that never sets a `securityContext` is already weaker than it should be.
3. **Privilege, host namespaces, and hostPath are escape primitives**—treat any of them as a node-compromise risk.
4. **Every Pod is a cluster identity**—disable token automount when the app doesn't need the API.
5. **Enforce, don't hope**—Pod Security Admission and policy engines make hardened configuration the only configuration that admits.

## How to Identify if You're Vulnerable

Ask these questions about your workloads:

- [ ] Does any workload set `privileged: true`, and can it be removed?
- [ ] Are `hostPID`, `hostIPC`, and `hostNetwork` all `false`?
- [ ] Are there any `hostPath` mounts—especially `/` or a runtime socket?
- [ ] Is `runAsNonRoot: true` set, with an explicit non-zero `runAsUser`?
- [ ] Is `allowPrivilegeEscalation: false` on every container?
- [ ] Are all capabilities dropped (`drop: ["ALL"]`) and only the strictly necessary ones added back?
- [ ] Is `seccompProfile.type: RuntimeDefault` (never `Unconfined`)?
- [ ] Is `readOnlyRootFilesystem: true` with writable dirs mounted explicitly?
- [ ] Are CPU, memory, and ephemeral-storage limits set on every container?
- [ ] Is `automountServiceAccountToken: false` where the API isn't used?
- [ ] Is Pod Security Admission (`restricted`) or a Kyverno/Gatekeeper policy enforcing all of the above at admission?

If you answered "no" or "not sure" to several of these, you likely have exploitable insecure workloads today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers turn permissive manifests into node and cluster compromise
- **[Prevention](prevention.md)**: Build a hardened, enforced workload baseline
- **[Examples](examples.md)**: Insecure vs. secure Kubernetes manifests and admission policies
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
