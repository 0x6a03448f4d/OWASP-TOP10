# K03: Overly Permissive RBAC Configurations - Code Examples

Each pair below shows an **insecure** RBAC configuration and the **secure**, least-privilege version for the same use case. The YAML focuses on the mistakes that dominate real findings: wildcard rules, `cluster-admin` on ServiceAccounts, broad Secret access, and the escalation verbs. After the pairs, `kubectl auth can-i` checks show how to prove the difference.

## 1. Wildcard ClusterRole vs. Scoped Role

### Insecure
```yaml
# A "give it everything so it works" ClusterRole bound cluster-wide.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: app-superpowers
rules:
- apiGroups: ["*"]          # every API group, including future CRDs
  resources: ["*"]          # pods, secrets, nodes, rolebindings, ...
  verbs: ["*"]              # get, create, delete, escalate, bind, impersonate
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-superpowers-binding
subjects:
- kind: ServiceAccount
  name: payments-api
  namespace: payments
roleRef:
  kind: ClusterRole
  name: app-superpowers
  apiGroup: rbac.authorization.k8s.io
# Effect: this ServiceAccount is cluster-admin. One RCE = full takeover.
```

### Secure
```yaml
# Only the verbs and resources this app actually uses, in its namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payments-api-role
  namespace: payments
rules:
- apiGroups: [""]                     # core group
  resources: ["configmaps"]
  resourceNames: ["payments-config"]  # a single named object
  verbs: ["get", "list", "watch"]     # read-only
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: payments-api-binding
  namespace: payments
subjects:
- kind: ServiceAccount
  name: payments-api
  namespace: payments
roleRef:
  kind: Role                          # namespaced, not ClusterRole
  name: payments-api-role
  apiGroup: rbac.authorization.k8s.io
```

## 2. cluster-admin on a ServiceAccount vs. a Purpose-Built Role

### Insecure
```yaml
# A deployer that "needs to manage the namespace" is handed cluster-admin.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-deployer-admin
subjects:
- kind: ServiceAccount
  name: ci-deployer
  namespace: cicd
roleRef:
  kind: ClusterRole
  name: cluster-admin        # built-in god mode, bound to a token in a Pod
  apiGroup: rbac.authorization.k8s.io
```

### Secure
```yaml
# A deploy role scoped to exactly what CI touches, in the target namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployer
  namespace: production
rules:
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["services", "configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
# Note: NO secrets, NO delete on arbitrary resources, NO rbac verbs.
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: deployer-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: ci-deployer
  namespace: cicd            # subject can live in another namespace
roleRef:
  kind: Role
  name: deployer
  apiGroup: rbac.authorization.k8s.io
```

## 3. Broad Secret Access vs. Named-Secret Access

### Insecure
```yaml
# Read every secret in every namespace -- classic credential-harvest surface.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader-all
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]   # cluster-wide via a ClusterRoleBinding
```

### Secure
```yaml
# Read only the one secret this workload needs, in its own namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: db-secret-reader
  namespace: payments
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["payments-db-credentials"]  # exactly one secret
  verbs: ["get"]                               # get, not list (list ignores names)
```

> **Important:** `resourceNames` restricts `get`/`update`/`delete`, but it does *not* restrict `list` or `watch`—those return whole collections. Grant `get` on a named Secret, never `list`, when you want to limit exposure to one object.

## 4. Escalation Verbs vs. No Escalation Verbs

### Insecure
```yaml
# A tenant operator handed the meta-permissions that govern RBAC itself.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tenant-operator
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles", "clusterrolebindings"]
  verbs: ["create", "bind", "escalate"]   # self-promotion to cluster-admin
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]                  # act as any identity, incl. system:masters
```

### Secure
```yaml
# Let the operator manage tenant workloads -- NOT RBAC, identity, or nodes.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: tenant-operator
  namespace: tenant-a
rules:
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]
# No escalate / bind / impersonate. No secrets. No pods/exec. No nodes.
# If a binding is truly required, grant "bind" ONLY on one specific role
# via resourceNames, never on clusterroles broadly.
```

## 5. Over-Permissioned default SA vs. Dedicated SA + No Automount

### Insecure
```yaml
# Binding to "default" leaks the grant to EVERY pod in the namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: default-edit
  namespace: apps
subjects:
- kind: ServiceAccount
  name: default            # shared by all unspecified pods
  namespace: apps
roleRef:
  kind: ClusterRole
  name: edit               # create pods, read secrets, etc. -- for everyone
  apiGroup: rbac.authorization.k8s.io
```

### Secure
```yaml
# Dedicated SA per workload; default is left unbound and un-mounted.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: report-generator
  namespace: apps
automountServiceAccountToken: false   # this app never calls the API
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: report-generator
  namespace: apps
spec:
  selector: { matchLabels: { app: report-generator } }
  template:
    metadata:
      labels: { app: report-generator }
    spec:
      serviceAccountName: report-generator      # not "default"
      automountServiceAccountToken: false        # no token on disk
      containers:
      - name: app
        image: registry.example.com/report-generator:1.4.2
---
# Also harden the namespace default so stray pods carry no token:
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: apps
automountServiceAccountToken: false
```

## 6. Verifying with kubectl auth can-i

Prove that the secure config grants exactly what is intended—and denies the escalation paths. Use `--as` to test as the ServiceAccount, and wire these assertions into CI.

```bash
SA=system:serviceaccount:payments:payments-api

# --- Should be ALLOWED (the app's real needs) ---
kubectl auth can-i get configmaps -n payments --as=$SA
# yes

# --- Should be DENIED (the dangerous grants) ---
kubectl auth can-i list secrets --all-namespaces --as=$SA        # no
kubectl auth can-i get secrets -n kube-system --as=$SA           # no
kubectl auth can-i create pods -n payments --as=$SA              # no
kubectl auth can-i create pods/exec -n kube-system --as=$SA      # no
kubectl auth can-i create clusterrolebindings --as=$SA           # no
kubectl auth can-i escalate clusterroles --as=$SA                # no
kubectl auth can-i impersonate users --as=$SA                    # no
kubectl auth can-i create serviceaccounts/token -n payments --as=$SA  # no
kubectl auth can-i get nodes/proxy --as=$SA                      # no
kubectl auth can-i '*' '*' --all-namespaces --as=$SA             # no

# List the full effective permission set for a final review
kubectl auth can-i --list --as=$SA -n payments
```

## 7. Auditing an Existing Cluster

```bash
# Find cluster-admin bindings and their subjects
kubectl get clusterrolebindings -o json | jq -r '
  .items[] | select(.roleRef.name=="cluster-admin")
  | .metadata.name + "  ->  " +
    ([.subjects[]? | .kind + "/" + (.namespace // "-") + "/" + .name] | join(", "))'

# Find roles/clusterroles that use wildcards
kubectl get clusterroles,roles --all-namespaces -o json | jq -r '
  .items[] | select(any(.rules[]?;
      (.verbs // [] | index("*")) or
      (.resources // [] | index("*")) or
      (.apiGroups // [] | index("*"))))
  | .kind + "/" + .metadata.name'

# Who can do the dangerous things?
kubectl who-can list secrets
kubectl who-can create clusterrolebindings
kubectl who-can impersonate users
```

## What Changed, and Why

| Mistake | Insecure | Secure |
|---------|----------|--------|
| Wildcards | `*` verbs/resources/apiGroups | Explicit verbs on named resources |
| Scope | ClusterRole + ClusterRoleBinding | Namespaced Role + RoleBinding |
| Admin | `cluster-admin` on a ServiceAccount | Purpose-built role, no admin |
| Secrets | `list` secrets cluster-wide | `get` one named secret |
| Escalation verbs | `escalate`/`bind`/`impersonate` granted | None; workload-only permissions |
| Identity | Bound to `default`, token auto-mounted | Dedicated SA, automount disabled |

## Next Steps

- **[Prevention](prevention.md)**: The full least-privilege and audit strategy
- **[Attack Vectors](attack-vectors.md)**: How these misconfigurations are exploited
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts in hands-on exercises
