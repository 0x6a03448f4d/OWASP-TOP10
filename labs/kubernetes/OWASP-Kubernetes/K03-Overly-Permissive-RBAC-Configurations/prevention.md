# K03: Overly Permissive RBAC Configurations - Prevention

## Prevention Strategy Overview

Preventing over-permissioning is less about one control and more about **making least privilege the only state that ships**:

1. Start every identity from zero and add only what it demonstrably needs.
2. Prefer namespaced Roles and named resources over cluster-wide wildcards.
3. Never bind `cluster-admin` (or wildcards) to a workload ServiceAccount.
4. Disable ServiceAccount token automount where the API is not called.
5. Audit RBAC continuously and gate changes in CI.

### Core Principles

- **Least privilege by default**: grant the smallest set of verbs, on the smallest set of resources, in the smallest scope that still works.
- **One identity per workload**: a dedicated ServiceAccount per application, never the shared `default`.
- **Deny the escalation primitives**: `escalate`, `bind`, `impersonate`, broad Secret access, and `create` on Pods/exec are granted only with a documented reason.
- **RBAC is code**: manifests are versioned, reviewed, scanned, and audited like any other security control.

## 1. Write Least-Privilege Roles

Enumerate the exact verbs and resources a workload uses, then grant only those. Narrow with `resourceNames` wherever the object set is known and stable.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: config-reader
  namespace: payments
rules:
- apiGroups: [""]                 # core group only
  resources: ["configmaps"]       # not "*"
  resourceNames: ["app-config"]   # a single named object
  verbs: ["get", "watch", "list"] # read-only, no create/update/delete
```

Contrast this with the wildcard anti-pattern (`apiGroups: ["*"]`, `resources: ["*"]`, `verbs: ["*"]`), which also silently covers every future CRD. If you do not know which verbs an app needs, watch the audit log in staging and derive the set from real calls.

## 2. Prefer Namespaced Roles Over ClusterRoles

Scope is the cheapest control you have. A `Role` + `RoleBinding` confines a permission to one namespace; a `ClusterRole` + `ClusterRoleBinding` grants it everywhere.

```yaml
# GOOD: namespaced grant to a dedicated SA in one namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: config-reader-binding
  namespace: payments
subjects:
- kind: ServiceAccount
  name: payments-api          # dedicated, not "default"
  namespace: payments
roleRef:
  kind: Role                  # namespaced Role, not ClusterRole
  name: config-reader
  apiGroup: rbac.authorization.k8s.io
```

Use a `ClusterRole` only for genuinely cluster-scoped resources (nodes, namespaces, CRDs) or for a reusable rule set that you then bind *per namespace* with a `RoleBinding`—which keeps a shared ClusterRole from becoming a cluster-wide grant.

## 3. Never Bind cluster-admin (or Wildcards) to Workloads

Reserve `cluster-admin` for human break-glass accounts with strong authentication and audit, never for a ServiceAccount whose token lives inside a running Pod.

```bash
# Find and remove dangerous bindings
kubectl get clusterrolebindings -o json | jq -r '
  .items[] | select(.roleRef.name=="cluster-admin")
  | .metadata.name + "  ->  " +
    ([.subjects[]? | .kind + "/" + .name] | join(","))'

# Also reject bindings to wide groups:
#   system:authenticated, system:unauthenticated, system:masters
```

## 4. Fix the default ServiceAccount

Do not bind permissions to `default`, and stop mounting its token into Pods that never call the API.

```yaml
# Disable automount on the default SA in a namespace
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: payments
automountServiceAccountToken: false
---
# And/or per Pod: opt out explicitly for workloads that don't need the API
apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  serviceAccountName: payments-web     # dedicated SA
  automountServiceAccountToken: false  # no token on disk if API isn't used
  containers:
  - name: web
    image: nginx
```

## 5. Deny the Escalation Primitives

Treat these grants as security-sensitive and require an explicit, reviewed justification for each:

| Grant | Default stance |
|-------|----------------|
| `escalate` / `bind` on roles/clusterroles | Deny; only a tightly controlled RBAC-management identity |
| `impersonate` on users/groups/serviceaccounts | Deny; audit every use |
| `get`/`list` on `secrets` | Namespace-scoped and, where possible, limited by `resourceNames` |
| `create` on `pods`, `pods/exec`, `pods/attach` | Deny for application SAs; controllers only |
| `create` on `serviceaccounts/token` | Deny outside token-issuing controllers |
| `get` on `nodes/proxy`, CSR `approval` | Deny; node/PKI infrastructure only |

Because RBAC has no deny rules, "deny" here means *do not grant*—and back it with an admission policy (below) that rejects manifests attempting these grants.

## 6. Enforce with Admission Policy

Stop dangerous RBAC before it is applied, using a policy engine (OPA/Gatekeeper, Kyverno) or the built-in ValidatingAdmissionPolicy.

```yaml
# Kyverno: block ClusterRoles that use wildcard verbs
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-wildcard-rbac
spec:
  validationFailureAction: Enforce
  rules:
  - name: no-wildcard-verbs
    match:
      any:
      - resources:
          kinds: ["ClusterRole", "Role"]
    validate:
      message: "Wildcard verbs/resources are not allowed in RBAC rules."
      foreach:
      - list: "request.object.rules"
        deny:
          conditions:
            any:
            - key: "{{ element.verbs[] }}"
              operator: AnyIn
              value: ["*"]
            - key: "{{ element.resources[] }}"
              operator: AnyIn
              value: ["*"]
```

Add companion policies to reject bindings to `cluster-admin` for ServiceAccount subjects and bindings to `system:authenticated`/`system:unauthenticated`.

## 7. Verify with kubectl auth can-i

After applying a role, prove the identity has exactly what it should—and nothing more. Make these checks part of CI.

```bash
SA=system:serviceaccount:payments:payments-api

# Should be allowed:
kubectl auth can-i get configmaps -n payments --as=$SA        # yes

# Should be denied (these are the ones that matter):
kubectl auth can-i list secrets --all-namespaces --as=$SA     # no
kubectl auth can-i create pods -n payments --as=$SA           # no
kubectl auth can-i create clusterrolebindings --as=$SA        # no
kubectl auth can-i impersonate users --as=$SA                 # no
kubectl auth can-i '*' '*' --all-namespaces --as=$SA          # no
```

A failing "should be denied" check fails the pipeline—so over-permissioning is caught before it ships.

## 8. Audit RBAC Continuously

Use purpose-built tools to surface risky grants across the whole cluster on a schedule.

```bash
# Who can perform a dangerous action, cluster-wide?
kubectl who-can list secrets
kubectl who-can create pods -n kube-system
kubectl who-can impersonate users

# rbac-tool: analyze, visualize, and diff permissions
rbac-tool analysis                 # flags risky roles/bindings
rbac-tool who-can create clusterrolebindings
rbac-tool policy-rules -e '^system:'   # audit built-in roles

# KubiScan: hunt risky roles, bindings, and privileged SA tokens
kubiscan --all
```

Feed the output into a recurring report and alert when a new wildcard rule, a new `cluster-admin` binding, or a new escalation-verb grant appears.

## 9. Separate Duties and Aggregate Deliberately

- Split permissions by function (deploy vs. read vs. secret-manage) so no single identity holds an end-to-end escalation path.
- Prefer the built-in `view` role over `edit`, and `edit` over `admin`; never reach for `cluster-admin` as a shortcut.
- Use ClusterRole aggregation carefully—an over-broad aggregation label silently widens an aggregated role.
- Give each team its own namespace and namespaced admin, rather than cluster-wide edit.

## 10. Monitor and Detect

Enable API server audit logging and watch for the signatures of RBAC abuse.

```
# Alert on these audit events:
#  - RBAC changes:  create/update on roles, clusterroles, *bindings
#  - New binding whose roleRef.name == cluster-admin
#  - verb=impersonate on any request
#  - selfsubjectrulesreviews / "can-i --list" from a workload ServiceAccount
#  - list secrets across many namespaces by a non-system SA
#  - create serviceaccounts/token or pods in kube-system by app SAs
```

Pair detection with regular access reviews: periodically re-derive what each identity actually used from audit logs and remove permissions that were never exercised.

## Least-Privilege Checklist

- [ ] No `*` in `verbs`, `resources`, or `apiGroups` for any custom role.
- [ ] No `cluster-admin` bound to a ServiceAccount or a wide group.
- [ ] Every workload has a dedicated ServiceAccount; `default` is unused and unbound.
- [ ] `automountServiceAccountToken: false` wherever the API is not called.
- [ ] `escalate`/`bind`/`impersonate` granted only to reviewed infrastructure identities.
- [ ] Secret access is namespace-scoped and, where feasible, limited by `resourceNames`.
- [ ] Namespaced Roles used unless the resource is genuinely cluster-scoped.
- [ ] Admission policy rejects wildcard rules and dangerous bindings.
- [ ] CI runs `kubectl auth can-i` assertions for allowed and denied actions.
- [ ] RBAC audited on a schedule (rbac-tool, kubectl-who-can, KubiScan) with alerting.

## Key Takeaways

1. **Start from zero** — grant the minimum verbs and resources, narrowed by `resourceNames` and namespace.
2. **Never hand a workload cluster-admin** — and never bind roles to `default` or wide groups.
3. **Guard the escalation primitives** — `escalate`, `bind`, `impersonate`, Secret reads, and Pod/exec creation.
4. **Enforce at admission** — reject wildcard rules and dangerous bindings before they apply.
5. **Prove and audit continuously** — `kubectl auth can-i` in CI, RBAC auditors on a schedule, audit-log alerting in production.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure RBAC YAML side by side
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts in hands-on exercises
