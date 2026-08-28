# K01: Insecure Workload Configurations - Code Examples

Each pair below shows an **insecure** Kubernetes manifest and the **secure** version of the same workload. The examples focus on the fields that dominate real K01 findings: privilege, host namespaces, host paths, root user, capabilities, seccomp, read-only root filesystem, resource limits, and the ServiceAccount token. The final sections show `kubectl` detection commands and admission policies (Pod Security Admission, Kyverno, and OPA Gatekeeper).

## 1. The Fully Insecure Pod (Everything Wrong)

### Insecure

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: legacy-agent
spec:
  hostPID: true                 # sees all host processes
  hostIPC: true                 # host shared memory
  hostNetwork: true             # host network stack + metadata reach
  containers:
    - name: agent
      image: agent:latest       # mutable tag, unknown provenance
      securityContext:
        privileged: true                    # ~= root on the node
        runAsUser: 0                         # root in container
        allowPrivilegeEscalation: true       # setuid can gain privileges
        readOnlyRootFilesystem: false        # attacker can persist
        capabilities:
          add: ["SYS_ADMIN", "NET_ADMIN"]    # escape primitives
        seccompProfile:
          type: Unconfined                   # full kernel syscall surface
      volumeMounts:
        - name: host-root
          mountPath: /host                   # entire node filesystem
        - name: docker-sock
          mountPath: /var/run/docker.sock    # runtime takeover
      # no resources.limits -> noisy-neighbour DoS
  volumes:
    - name: host-root
      hostPath: { path: / }
    - name: docker-sock
      hostPath: { path: /var/run/docker.sock }
  # default ServiceAccount token is automounted -> cluster credential
```

This single manifest hands an attacker who lands in the Pod every escape primitive at once: privilege, host namespaces, the node filesystem, the runtime socket, root, and a cluster token.

### Secure

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: agent
spec:
  hostPID: false
  hostIPC: false
  hostNetwork: false
  automountServiceAccountToken: false        # app doesn't call the API
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault                    # syscall filtering on
  containers:
    - name: agent
      image: registry.example.com/agent@sha256:<digest>   # pinned by digest
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 10001
        capabilities:
          drop: ["ALL"]                       # add back nothing
      resources:
        requests: { cpu: "100m", memory: "128Mi" }
        limits:   { cpu: "500m", memory: "256Mi", ephemeral-storage: "1Gi" }
      volumeMounts:
        - name: tmp
          mountPath: /tmp                     # writable scratch, not the host
  volumes:
    - name: tmp
      emptyDir: {}
  # no hostPath, no docker.sock, no host namespaces
```

## 2. Running as Root vs. Non-Root

### Insecure

```yaml
spec:
  containers:
    - name: app
      image: app:1.4
      # No securityContext at all: UID defaults to the image's USER,
      # which for many images is root (UID 0). runAsNonRoot is not enforced,
      # allowPrivilegeEscalation defaults to true, capabilities are the
      # runtime default set (NET_RAW, CHOWN, SETUID, ...).
```

### Secure

```yaml
spec:
  securityContext:
    runAsNonRoot: true          # kubelet refuses to start the Pod as UID 0
    runAsUser: 10001
  containers:
    - name: app
      image: app:1.4
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
        readOnlyRootFilesystem: true
```

> **Tip**: Also fix the image. Add a non-root `USER 10001` in the Dockerfile so the container's default identity is already unprivileged, and `runAsNonRoot: true` becomes a belt-and-braces guarantee rather than the only line of defence.

## 3. Needing One Capability (the Right Way)

Some workloads genuinely need a single capability—for example binding a low port. Drop everything, add back exactly one.

### Insecure

```yaml
securityContext:
  privileged: true         # used as a lazy way to "just make port 80 work"
```

### Secure

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  runAsUser: 10001
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]   # the ONE capability actually required
# Better still: expose on a high port and let a Service map 80 -> 8080,
# so even NET_BIND_SERVICE is unnecessary.
```

## 4. Image Builds Without the Runtime Socket

### Insecure

```yaml
volumes:
  - name: docker-sock
    hostPath: { path: /var/run/docker.sock }   # docker-in-docker via the host daemon
```

### Secure

```yaml
# Use a rootless, daemonless builder - no socket, no privilege
containers:
  - name: build
    image: gcr.io/kaniko-project/executor:latest
    args:
      - "--dockerfile=Dockerfile"
      - "--context=git://github.com/example/app.git"
      - "--destination=registry.example.com/app:$(GIT_SHA)"
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: ["ALL"] }
```

## 5. Detecting Insecure Workloads with kubectl

```bash
# Find privileged containers across the cluster
kubectl get pods -A -o json | jq -r '
  .items[] | select(any(.spec.containers[];
    .securityContext.privileged == true))
  | "\(.metadata.namespace)/\(.metadata.name)"'

# Find Pods using host namespaces
kubectl get pods -A -o json | jq -r '
  .items[] | select(.spec.hostPID or .spec.hostIPC or .spec.hostNetwork)
  | "\(.metadata.namespace)/\(.metadata.name)"'

# Find hostPath volumes (and flag the dangerous ones)
kubectl get pods -A -o json | jq -r '
  .items[] | .metadata as $m | .spec.volumes[]? | select(.hostPath)
  | "\($m.namespace)/\($m.name)  ->  \(.hostPath.path)"'

# Find containers that can escalate privileges
kubectl get pods -A -o json | jq -r '
  .items[] | .metadata as $m | .spec.containers[]
  | select(.securityContext.allowPrivilegeEscalation != false)
  | "\($m.namespace)/\($m.name):\(.name)"'

# Dry-run a manifest against restricted Pod Security Standards
kubectl label --dry-run=server --overwrite ns test \
  pod-security.kubernetes.io/enforce=restricted
```

## 6. Enforcing with Pod Security Admission

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: prod
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

With this label in place, the API server rejects the insecure Pod from section 1 with a message listing each violation (privileged, host namespaces, hostPath, allowPrivilegeEscalation, missing seccomp, capabilities not dropped, runAsNonRoot).

## 7. Enforcing with Kyverno

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: workload-hardening
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: block-privileged-and-host
      match:
        any:
          - resources: { kinds: ["Pod"] }
      validate:
        message: "privileged, hostPID, hostIPC, hostNetwork and hostPath are forbidden."
        pattern:
          spec:
            =(hostPID): "false"
            =(hostIPC): "false"
            =(hostNetwork): "false"
            =(volumes):
              - X(hostPath): "null"
            containers:
              - =(securityContext):
                  =(privileged): "false"
    - name: require-hardened-securityContext
      match:
        any:
          - resources: { kinds: ["Pod"] }
      validate:
        message: "Containers must drop ALL caps, run as non-root, no privilege escalation."
        pattern:
          spec:
            containers:
              - securityContext:
                  runAsNonRoot: true
                  allowPrivilegeEscalation: "false"
                  capabilities:
                    drop: ["ALL"]
```

Kyverno can also **mutate** Pods to add a safe default (for example inject `seccompProfile: RuntimeDefault` when it is missing) rather than only rejecting them.

## 8. Enforcing with OPA Gatekeeper

```yaml
# A Constraint built on the community ConstraintTemplate library
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPAllowPrivilegeEscalationContainer
metadata:
  name: no-privilege-escalation
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostFilesystem
metadata:
  name: no-hostpath
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowedHostPaths: []        # empty list = no hostPath allowed
```

## What Changed, and Why

| Setting | Insecure | Secure |
|---------|----------|--------|
| Privilege | `privileged: true` | `privileged: false`, drop `ALL` caps |
| User | root (UID 0) / unset | `runAsNonRoot: true`, `runAsUser: 10001` |
| Escalation | `allowPrivilegeEscalation: true` | `allowPrivilegeEscalation: false` |
| Host namespaces | `hostPID/IPC/Network: true` | all `false` |
| Host mounts | `hostPath: /`, docker.sock | none; `emptyDir`/CSI/rootless builder |
| Filesystem | writable root | `readOnlyRootFilesystem: true` |
| Seccomp | `Unconfined` | `RuntimeDefault` |
| Resources | no limits | cpu/memory/ephemeral-storage limits |
| SA token | automounted default | `automountServiceAccountToken: false` |
| Enforcement | none (hope) | PSA restricted + Kyverno/Gatekeeper |

## Next Steps

- **[Prevention](prevention.md)**: The full layered hardening and enforcement strategy
- **[Attack Vectors](attack-vectors.md)**: How these misconfigurations are exploited
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
```
