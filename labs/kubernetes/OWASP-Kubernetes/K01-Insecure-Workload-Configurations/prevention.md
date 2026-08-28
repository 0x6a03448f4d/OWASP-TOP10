# K01: Insecure Workload Configurations - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [1. Hardened securityContext Baseline](#1-hardened-securitycontext-baseline)
- [2. No Host Namespaces or Host Paths](#2-no-host-namespaces-or-host-paths)
- [3. Disable ServiceAccount Token Automount](#3-disable-serviceaccount-token-automount)
- [4. Resource Limits and Quotas](#4-resource-limits-and-quotas)
- [5. Pod Security Admission](#5-pod-security-admission-built-in)
- [6. Kyverno Policies](#6-kyverno-policies-flexible-enforcement)
- [7. OPA Gatekeeper Constraints](#7-opa-gatekeeper-constraints-rego)
- [8. Shift-Left Manifest Scanning](#8-shift-left-manifest-scanning-ci)
- [9. Runtime Monitoring](#9-runtime-monitoring-and-detection)

## Prevention Strategy Overview

Preventing insecure workloads is not one control—it is **making the hardened manifest the only manifest that admits**:

1. Define a least-privilege `securityContext` that every workload inherits.
2. Forbid host namespaces, host paths, privilege, and dangerous capabilities.
3. Enforce it at admission with Pod Security Admission and/or a policy engine.
4. Catch violations earlier still—scan manifests in CI before they ever reach the cluster.
5. Watch at runtime for escapes that slip past static controls.

### Core Principles

- **Least privilege by default**: drop everything, add back only the narrow capability a workload genuinely needs, and justify it in review.
- **Secure by construction**: bake the hardened `securityContext` into base templates/Helm values so teams start safe.
- **Enforce, don't advise**: a documented standard nobody enforces drifts immediately—admission control makes it non-optional.
- **Defence in depth**: manifest hardening, admission policy, image hygiene, and runtime detection each catch what the others miss.

## 1. Hardened securityContext Baseline

This is the single most important control. Apply it at both the Pod and container level.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      automountServiceAccountToken: false   # app doesn't call the API
      securityContext:                       # Pod-level
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: web
          image: registry.example.com/web@sha256:<digest>
          securityContext:                   # container-level (wins on conflict)
            allowPrivilegeEscalation: false
            privileged: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 10001
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { cpu: "100m", memory: "128Mi" }
            limits:   { cpu: "500m", memory: "256Mi", ephemeral-storage: "1Gi" }
          volumeMounts:
            - name: tmp
              mountPath: /tmp                 # writable dir despite RO root fs
      volumes:
        - name: tmp
          emptyDir: {}
```

If a workload legitimately needs one capability (for example `NET_BIND_SERVICE` to bind port 80), drop `ALL` and add back only that one—never the reverse.

## 2. No Host Namespaces or Host Paths

These fields should be absent from virtually every production workload.

```yaml
spec:
  hostPID: false
  hostIPC: false
  hostNetwork: false
  # Do NOT use hostPath volumes. If you think you need one, prefer:
  #  - a CSI driver or PersistentVolume for storage
  #  - the downward API / projected volumes for metadata
  #  - a sidecar with a scoped emptyDir instead of the node filesystem
```

Never mount the container runtime socket (`/var/run/docker.sock`, containerd/CRI-O sockets). For image builds inside a cluster, use a rootless, daemonless builder (for example Kaniko or Buildah) rather than mounting the daemon socket.

## 3. Disable ServiceAccount Token Automount

Turn off automount for every workload that does not call the Kubernetes API, and scope the ones that do.

```yaml
# On the workload (preferred: explicit per-Pod)
spec:
  automountServiceAccountToken: false

---
# Or on a dedicated ServiceAccount used by API-less apps
apiVersion: v1
kind: ServiceAccount
metadata:
  name: no-api
automountServiceAccountToken: false
```

For workloads that *do* use the API, give them their own ServiceAccount with least-privilege RBAC (see K03), never the namespace `default`.

## 4. Resource Limits and Quotas

Set limits on every container, and enforce a floor with namespace policy so an unset limit cannot slip through.

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: prod
spec:
  limits:
    - type: Container
      default:            # applied when a container omits limits
        cpu: "500m"
        memory: "256Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
      max:                # hard ceiling per container
        cpu: "2"
        memory: "1Gi"
```

Pair a `LimitRange` (per-container defaults/ceilings) with a `ResourceQuota` (namespace-wide totals) so no single tenant can exhaust the cluster.

## 5. Pod Security Admission (Built-in)

Pod Security Admission is built into Kubernetes and enforces the Pod Security Standards. Label namespaces to `restricted` to require the hardened settings above.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: prod
  labels:
    # Block anything that violates the restricted policy
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    # Surface violations in audit log and to the user, useful during rollout
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

The `restricted` profile requires `runAsNonRoot`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, dropping `ALL` capabilities, and forbids privileged, host namespaces, and most `hostPath` usage—exactly the K01 controls. Start with `warn`/`audit` to find violators, then flip to `enforce`.

## 6. Kyverno Policies (Flexible Enforcement)

Kyverno writes policies as Kubernetes resources—no new language. It can enforce beyond PSA and even mutate manifests to add safe defaults.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-and-host
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: no-privileged
      match:
        any:
          - resources: { kinds: ["Pod"] }
      validate:
        message: "Privileged containers are not allowed."
        pattern:
          spec:
            =(ephemeralContainers):
              - securityContext:
                  =(privileged): "false"
            containers:
              - securityContext:
                  =(privileged): "false"
    - name: no-host-namespaces
      match:
        any:
          - resources: { kinds: ["Pod"] }
      validate:
        message: "hostPID, hostIPC and hostNetwork are not allowed."
        pattern:
          spec:
            =(hostPID): "false"
            =(hostIPC): "false"
            =(hostNetwork): "false"
    - name: require-drop-all
      match:
        any:
          - resources: { kinds: ["Pod"] }
      validate:
        message: "Containers must drop ALL capabilities."
        pattern:
          spec:
            containers:
              - securityContext:
                  capabilities:
                    drop: ["ALL"]
```

Kyverno also ships a curated **Pod Security** policy set that mirrors the restricted profile—a fast way to enforce the whole standard, plus extras PSA does not cover (like blocking `hostPath` outright).

## 7. OPA Gatekeeper Constraints (Rego)

Gatekeeper enforces policy written in Rego via reusable `ConstraintTemplate`s and `Constraint`s.

```yaml
# Constraint using the community template library (K8sPSPPrivilegedContainer)
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: no-privileged-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostNamespace
metadata:
  name: no-host-namespaces
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

```rego
# Sketch of the Rego logic inside a ConstraintTemplate
package k8spspprivileged
violation[{"msg": msg}] {
  c := input.review.object.spec.containers[_]
  c.securityContext.privileged == true
  msg := sprintf("Privileged container is not allowed: %v", [c.name])
}
```

Use Gatekeeper's audit mode first to inventory existing violations without breaking running workloads, then enforce.

## 8. Shift-Left Manifest Scanning (CI)

Catch insecure manifests before they reach the cluster. Fail the pipeline on findings.

```bash
# Static manifest / IaC scanning in CI
trivy config ./k8s                      # misconfig checks incl. securityContext
kubescape scan framework nsa ./k8s      # NSA/CISA hardening checks
checkov -d ./k8s                        # policy-as-code checks
kube-linter lint ./k8s                  # run-as-non-root, no-privileged, limits

# Validate a rendered Helm chart the same way
helm template ./chart | trivy config -
```

Run the same policy engine locally too: `kyverno apply ./policies -r ./k8s` lets developers test their manifests against production policy before pushing.

## 9. Runtime Monitoring and Detection

Admission control stops bad *configuration*; runtime tooling catches an *escape in progress*.

```yaml
# Falco rule concept: alert on a shell spawned in a container, or a
# write to a sensitive host path, or an unexpected capability use.
- rule: Terminal shell in container
  condition: spawned_process and container and shell_procs and proc.tty != 0
  output: "Shell in container (user=%user.name container=%container.name)"
  priority: WARNING
```

Also alert on: new listens on host ports, reads of `/var/run/*.sock` from unexpected Pods, requests to `169.254.169.254` from workloads, and any Pod created with `privileged: true` that slipped through. Feed these to your SIEM with the Pod, namespace, and node as context.

## Defence-in-Depth Summary

| Layer | Control | Stops |
|-------|---------|-------|
| Authoring | Hardened base templates / Helm values | Teams starting insecure |
| CI | trivy / kubescape / kube-linter / kyverno apply | Bad manifests before the cluster |
| Admission | Pod Security Admission (restricted) + Kyverno/Gatekeeper | Insecure Pods being created |
| Namespace | LimitRange + ResourceQuota | Resource exhaustion |
| Runtime | Falco / eBPF detection | Escapes that got through |

## Key Takeaways

1. **The hardened `securityContext` is the core fix** — runAsNonRoot, no privilege escalation, drop ALL, read-only root, RuntimeDefault seccomp.
2. **Forbid host namespaces and host paths** — there is almost never a good production reason for them.
3. **Enforce at admission** — Pod Security Admission plus Kyverno or Gatekeeper makes the secure config the only one that admits.
4. **Shift left** — scan manifests in CI so violations never reach the cluster.
5. **Watch at runtime** — detection catches the escape that static controls missed.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure manifests and admission policies
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
