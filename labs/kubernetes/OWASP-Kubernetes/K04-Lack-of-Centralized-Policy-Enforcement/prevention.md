# K04: Lack of Centralized Policy Enforcement - Prevention

## Prevention Strategy Overview

Preventing K04 is about **making enforcement the default path that every workload must pass through**, applied identically everywhere:

1. Put a policy engine in the admission chain of every cluster.
2. Set a baseline floor with Pod Security Admission in `enforce` mode.
3. Source all policy from Git and apply it uniformly (GitOps).
4. Enforce, not audit—and fail closed on sensitive resources.
5. Continuously scan for drift and pre-existing violations.

### Core Principles

- **Enforce in the admission path**: a control that runs before the object is persisted is the only one that covers direct applies, Helm, and operators.
- **Uniform coverage**: every namespace and every cluster, from a single source of truth—no excluded soft targets.
- **Enforce, then observe**: audit is a migration step; the destination is `enforce` plus fail-closed.
- **Defence in depth**: PSA as the floor, a policy engine for custom rules, scanning for drift.

## 1. Adopt Pod Security Admission as the Baseline Floor

Pod Security Admission is built into Kubernetes (stable since 1.25) and needs no extra components. Label every namespace to *enforce* a profile—`restricted` where possible, `baseline` at minimum—and keep `warn`/`audit` at `restricted` so you can see how close you are to the stricter tier.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: payments
  labels:
    pod-security.kubernetes.io/enforce: restricted   # actually BLOCKS
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

Apply a cluster-wide default so *new* namespaces are not born unguarded, using the API server's `AdmissionConfiguration`:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:                 # applied where a namespace sets no label
      enforce: "baseline"
      enforce-version: "latest"
      warn: "restricted"
      audit: "restricted"
    exemptions:
      namespaces: [kube-system]   # keep this list tiny and reviewed
```

> PSA is a floor, not a ceiling. It enforces the three standard profiles but cannot express rules like "only our registry" or "images must be signed." Pair it with a policy engine (below).

## 2. Deploy a Policy Engine in Enforce Mode

A policy engine occupies the validating (and mutating) admission webhooks and enforces custom rules on every workload. The two mainstream choices are **Kyverno** (Kubernetes-native YAML policies) and **OPA Gatekeeper** (Rego via ConstraintTemplates + Constraints). Both should run in enforce/deny mode.

```yaml
# Kyverno: block privileged pods cluster-wide, in ENFORCE mode
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: Enforce      # Enforce = deny (not Audit)
  background: true                       # also scan existing resources
  rules:
  - name: no-privileged
    match:
      any:
      - resources:
          kinds: [Pod]
    validate:
      message: "Privileged containers are not allowed."
      pattern:
        spec:
          =(securityContext):
            =(privileged): "false"
          containers:
          - =(securityContext):
              =(privileged): "false"
```

The equivalent guardrails as OPA Gatekeeper (a reusable ConstraintTemplate plus a Constraint that switches it on):

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowprivileged
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowPrivileged
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sdisallowprivileged
      violation[{"msg": msg}] {
        c := input.review.object.spec.containers[_]
        c.securityContext.privileged == true
        msg := sprintf("privileged not allowed: %v", [c.name])
      }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDisallowPrivileged
metadata:
  name: disallow-privileged
spec:
  enforcementAction: deny            # deny = enforce (not dryrun/warn)
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
```

## 3. Use Mutating Policy to Set Safe Defaults

Enforcement is friendlier when the engine also *fixes* common omissions instead of only rejecting them. Kyverno mutate rules can inject a hardened `securityContext` so workloads are secure-by-default.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: default-secure-context
spec:
  rules:
  - name: add-secure-context
    match:
      any:
      - resources:
          kinds: [Pod]
    mutate:
      patchStrategicMerge:
        spec:
          securityContext:
            runAsNonRoot: true
            seccompProfile:
              type: RuntimeDefault
          containers:
          - (name): "*"
            securityContext:
              allowPrivilegeEscalation: false
              capabilities:
                drop: ["ALL"]
```

## 4. Enforce Image Provenance

Restrict images to approved registries and require signatures so untrusted images cannot run—this is the K04 answer to the supply-chain vector.

```yaml
# Kyverno: only allow images from the approved registry
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-registries
spec:
  validationFailureAction: Enforce
  rules:
  - name: allowed-registries
    match:
      any:
      - resources:
          kinds: [Pod]
    validate:
      message: "Images must come from registry.example.com."
      pattern:
        spec:
          containers:
          - image: "registry.example.com/*"
```

```yaml
# Kyverno: verify image signatures (Cosign / keyless)
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-signatures
spec:
  validationFailureAction: Enforce
  rules:
  - name: check-signature
    match:
      any:
      - resources:
          kinds: [Pod]
    verifyImages:
    - imageReferences: ["registry.example.com/*"]
      attestors:
      - entries:
        - keys:
            publicKeys: |-
              -----BEGIN PUBLIC KEY-----
              <your cosign public key>
              -----END PUBLIC KEY-----
```

## 5. Enforce Resources, Labels, and Network Posture

Require the settings that other controls depend on—resource limits (so one workload cannot starve a node) and standard labels (so NetworkPolicy and quotas actually select the right pods).

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-limits-and-labels
spec:
  validationFailureAction: Enforce
  rules:
  - name: require-resources
    match: { any: [{ resources: { kinds: [Pod] } }] }
    validate:
      message: "CPU/memory limits are required."
      pattern:
        spec:
          containers:
          - resources:
              limits:
                memory: "?*"
                cpu: "?*"
  - name: require-labels
    match: { any: [{ resources: { kinds: [Pod] } }] }
    validate:
      message: "app.kubernetes.io/name and team labels are required."
      pattern:
        metadata:
          labels:
            app.kubernetes.io/name: "?*"
            team: "?*"
```

## 6. Fail Closed, Not Open

Configure the webhooks so that when the policy engine cannot be consulted, admission of sensitive resources is *denied*—an outage must never silently disable policy. Scope the webhook so it does not deadlock the engine's own namespace.

```yaml
webhooks:
- name: validate.kyverno.svc
  failurePolicy: Fail            # deny if the engine is unreachable
  timeoutSeconds: 10
  namespaceSelector:             # avoid self-deadlock / core system ns
    matchExpressions:
    - key: kubernetes.io/metadata.name
      operator: NotIn
      values: [kube-system, kyverno]
```

> Fail-closed is a trade-off with availability. Run the policy engine highly available (multiple replicas, PodDisruptionBudget) so failing closed does not become an outage of its own.

## 7. Policy as Code in Git (GitOps)

Store every policy in version control and reconcile it to *all* clusters with a GitOps controller (Argo CD, Flux). This is what makes enforcement uniform and drift-resistant: a cluster that diverges is reconciled back, and every change is reviewed and audited.

```
policies/
  psa-namespace-labels.yaml
  kyverno/
    disallow-privileged.yaml
    restrict-registries.yaml
    verify-signatures.yaml
    require-limits-and-labels.yaml
# Flux/Argo applies this same tree to dev, staging, and every prod cluster.
# No cluster gets a hand-edited exception that silently drifts.
```

Validate policies in CI *before* they merge, so a broken or weakened policy is caught early:

```
# Test Kyverno policies against sample manifests in CI
kyverno apply ./policies/kyverno -r ./tests/manifests

# Lint/conftest Gatekeeper constraints (OPA) against fixtures
conftest test ./tests/manifests --policy ./policies/rego
```

## 8. Continuous Conformance Scanning

Admission control stops *new* violations; scanning catches drift, out-of-band changes, and workloads that predate a policy. Run these on a schedule and in CI.

```
# CIS Kubernetes Benchmark checks for the cluster components
kube-bench run --targets master,node

# Workload best-practice scan (securityContext, limits, probes)
polaris audit --format pretty

# Cluster-wide risk + misconfig scan, mapped to frameworks
kubescape scan framework nsa
trivy k8s cluster --report summary
```

Wire the results into alerting so a regression—an unlabeled namespace, a webhook flipped to `Ignore`, a policy switched back to `Audit`—pages someone instead of sitting in a log.

## 9. Migrating Off PodSecurityPolicy

PSP was removed in Kubernetes 1.25. If you relied on it, adopt the replacement *before* upgrading:

1. Turn on Pod Security Admission in `audit`/`warn` at `restricted` and read the results to find workloads that would break.
2. Fix or exempt those workloads, then flip namespaces to `enforce`.
3. Install a policy engine for the custom rules PSP used to cover (registries, labels, images) that PSA cannot express.
4. Only then upgrade past 1.25—so there is never a window with no guardrail.

## Enforcement Building Blocks at a Glance

| Need | Control | Enforce setting to check |
|------|---------|--------------------------|
| Pod-level baseline | Pod Security Admission | `pod-security.kubernetes.io/enforce: restricted` |
| Custom validating rules | Kyverno | `validationFailureAction: Enforce` |
| Custom validating rules | OPA Gatekeeper | `enforcementAction: deny` |
| Safe defaults | Kyverno mutate | mutate rules present and applied |
| Image provenance | Registry allow-list + Cosign verify | enforce on `verifyImages` |
| Availability of policy | Webhook failurePolicy | `failurePolicy: Fail` on sensitive rules |
| Uniformity | GitOps (Argo/Flux) | one policy tree reconciled to all clusters |
| Drift detection | kube-bench / Polaris / kubescape / Trivy | scheduled scans wired to alerts |

## Key Takeaways

1. **Put an engine in the admission path** — PSA for the floor, Kyverno/Gatekeeper for custom rules, on every cluster.
2. **Enforce, don't audit** — `Enforce`/`deny`/`enforce`, and fail closed on sensitive resources.
3. **Cover everything uniformly** — default PSA for new namespaces, one Git-sourced policy tree for all clusters.
4. **Validate provenance and posture** — registries, signatures, resource limits, and required labels at admission.
5. **Enforce plus scan** — admission control blocks the new; conformance scanning catches drift and the pre-existing.

## Next Steps

- **[Code Examples](examples.md)**: No-policy cluster vs. Kyverno / Gatekeeper / PSA enforcing
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts hands-on
