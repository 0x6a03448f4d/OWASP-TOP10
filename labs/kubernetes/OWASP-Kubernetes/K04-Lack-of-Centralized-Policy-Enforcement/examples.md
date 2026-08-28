# K04: Lack of Centralized Policy Enforcement - Code Examples

Each pair below shows an **insecure** state (a cluster with no admission policy) and the **secure** version (Kyverno, OPA Gatekeeper, and Pod Security Admission enforcing the guardrail). The theme throughout: in the insecure case the manifest is *admitted*; in the secure case the same manifest is *denied* before it ever runs.

## Example 1: The Workload Nobody Blocks

### Insecure — no policy in the admission path

```yaml
# A fresh cluster with no PSA labels and no policy engine.
# This manifest is dangerous in three ways at once:
apiVersion: v1
kind: Pod
metadata:
  name: builder
  namespace: default          # no pod-security.kubernetes.io/enforce label
spec:
  hostPID: true               # host process namespace
  containers:
  - name: c
    image: anon-registry.io/tools:latest   # unapproved, unsigned image
    securityContext:
      privileged: true         # full host capabilities
    volumeMounts:
    - { name: host, mountPath: /host }
  volumes:
  - name: host
    hostPath: { path: / }       # entire node filesystem
```

```
$ kubectl apply -f builder.yaml
pod/builder created            # <-- admitted; nothing evaluated it
```

### Secure — the same manifest, now denied

```
# With PSA 'restricted' enforced on the namespace AND a Kyverno policy,
# the identical apply is rejected before the pod is persisted:
$ kubectl apply -f builder.yaml
Error from server (Forbidden): error when creating "builder.yaml":
admission webhook "validate.kyverno.svc-fail" denied the request:

resource Pod/default/builder was blocked due to the following policies:
  disallow-host-namespaces: host namespaces are not allowed
  disallow-privileged: privileged containers are not allowed
  restrict-registries: images must come from registry.example.com

Also blocked by PodSecurity "restricted:latest":
  privileged (container "c" must not set securityContext.privileged=true)
  hostPID (pod must not set spec.hostPID=true)
```

## Example 2: Namespace Baseline — Pod Security Admission

### Insecure — namespace with no enforcement (or warn-only)

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: team-a
  labels:
    # Only warns. The pod is still ADMITTED. This is a K04 trap:
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
    # No 'enforce' label == no blocking.
```

### Secure — enforce restricted, plus a cluster-wide default

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: team-a
  labels:
    pod-security.kubernetes.io/enforce: restricted     # BLOCKS violations
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
---
# API server AdmissionConfiguration so NEW namespaces are not born open:
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "baseline"          # every unlabeled namespace still has a floor
      enforce-version: "latest"
      warn: "restricted"
      audit: "restricted"
    exemptions:
      namespaces: ["kube-system"]  # keep tiny and reviewed
```

## Example 3: Custom Rule — Kyverno ClusterPolicy

### Insecure — no ClusterPolicy exists

```
# There is simply no Kyverno (or any) policy object in the cluster:
$ kubectl get clusterpolicy
No resources found
# Privileged, root, hostPath, unsigned images: all admitted.
```

### Secure — a ClusterPolicy in Enforce mode

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: pod-security-guardrails
spec:
  validationFailureAction: Enforce     # Enforce = deny (NOT Audit)
  background: true                      # also flags pre-existing violations
  rules:
  - name: disallow-privileged
    match: { any: [{ resources: { kinds: [Pod] } }] }
    validate:
      message: "Privileged containers are not allowed."
      pattern:
        spec:
          containers:
          - =(securityContext):
              =(privileged): "false"
  - name: require-run-as-non-root
    match: { any: [{ resources: { kinds: [Pod] } }] }
    validate:
      message: "Containers must run as non-root."
      pattern:
        spec:
          =(securityContext):
            =(runAsNonRoot): "true"
          containers:
          - =(securityContext):
              =(runAsNonRoot): "true"
  - name: disallow-host-path
    match: { any: [{ resources: { kinds: [Pod] } }] }
    validate:
      message: "hostPath volumes are not allowed."
      pattern:
        spec:
          =(volumes):
          - X(hostPath): "null"
```

## Example 4: Custom Rule — OPA Gatekeeper

### Insecure — no ConstraintTemplate / Constraint

```
$ kubectl get constrainttemplates
No resources found
# Gatekeeper may even be installed, but with zero constraints it enforces nothing.
```

### Secure — ConstraintTemplate + Constraint in deny mode

```yaml
# 1) Reusable template (the rule logic, in Rego)
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockhostnamespaces
spec:
  crd:
    spec:
      names:
        kind: K8sBlockHostNamespaces
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sblockhostnamespaces
      violation[{"msg": msg}] {
        input.review.object.spec.hostPID == true
        msg := "hostPID is not allowed"
      }
      violation[{"msg": msg}] {
        input.review.object.spec.hostNetwork == true
        msg := "hostNetwork is not allowed"
      }
---
# 2) Constraint that turns the template ON and sets enforcement
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockHostNamespaces
metadata:
  name: block-host-namespaces
spec:
  enforcementAction: deny            # deny = enforce (not dryrun / warn)
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
```

## Example 5: Image Provenance

### Insecure — any image from anywhere

```yaml
spec:
  containers:
  - name: app
    image: docker.io/someuser/app:latest   # arbitrary registry, no signature check
```

### Secure — allow-list plus signature verification (Kyverno)

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: image-provenance
spec:
  validationFailureAction: Enforce
  rules:
  - name: only-approved-registry
    match: { any: [{ resources: { kinds: [Pod] } }] }
    validate:
      message: "Images must come from registry.example.com."
      pattern:
        spec:
          containers:
          - image: "registry.example.com/*"
  - name: images-must-be-signed
    match: { any: [{ resources: { kinds: [Pod] } }] }
    verifyImages:
    - imageReferences: ["registry.example.com/*"]
      attestors:
      - entries:
        - keys:
            publicKeys: |-
              -----BEGIN PUBLIC KEY-----
              <cosign public key>
              -----END PUBLIC KEY-----
```

## Example 6: Fail-Open vs. Fail-Closed Webhook

### Insecure — failurePolicy: Ignore

```yaml
webhooks:
- name: validate.kyverno.svc
  failurePolicy: Ignore        # engine down/upgrading == workloads ADMITTED unchecked
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
```

### Secure — failurePolicy: Fail (fail closed)

```yaml
webhooks:
- name: validate.kyverno.svc
  failurePolicy: Fail          # if policy cannot be consulted, DENY
  timeoutSeconds: 10
  namespaceSelector:           # avoid deadlocking core/system namespaces
    matchExpressions:
    - key: kubernetes.io/metadata.name
      operator: NotIn
      values: ["kube-system", "kyverno"]
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
```

## Example 7: Uniformity via GitOps

### Insecure — hand-applied, per-cluster

```
# Policies applied ad hoc, differently on each cluster, drifting over time:
kubectl apply -f some-policy.yaml   # on prod-eu only
# staging, prod-us, and the new sandbox cluster never got it.
```

### Secure — one policy tree reconciled everywhere

```yaml
# Flux Kustomization: the SAME policy directory applied to every cluster,
# continuously reconciled so drift is corrected automatically.
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: cluster-policies
  namespace: flux-system
spec:
  interval: 10m
  path: ./policies              # PSA labels + Kyverno/Gatekeeper policies
  prune: true                   # removes policies deleted from Git
  sourceRef:
    kind: GitRepository
    name: platform-config
  wait: true                    # fail the reconcile if a policy won't apply
```

## What Changed, and Why

| Gap | Insecure state | Secure state |
|-----|----------------|--------------|
| Admission engine | None; API server admits any manifest | Kyverno/Gatekeeper in the validating path |
| Baseline floor | No PSA enforce label | PSA `enforce: restricted` + cluster default |
| Mode | Missing, or `Audit`/`warn` only | `Enforce` / `deny` |
| Image trust | Any registry, unsigned | Allow-list + Cosign signature verify |
| Failure mode | `failurePolicy: Ignore` (fail open) | `failurePolicy: Fail` (fail closed) |
| Coverage | Per-cluster, hand-applied, drifting | One Git tree reconciled to all clusters |

## Next Steps

- **[Prevention](prevention.md)**: The full enforcement strategy
- **[Attack Vectors](attack-vectors.md)**: How the enforcement gap is exploited
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts hands-on
