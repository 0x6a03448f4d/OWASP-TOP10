# K07: Missing Network Segmentation Controls - Prevention

## Prevention Strategy Overview

Preventing K07 means turning the cluster's **default-allow** network into a **default-deny** one, then explicitly allowing only the flows the application needs:

1. Run a CNI that actually enforces NetworkPolicy.
2. Apply a default-deny ingress *and* egress baseline in every namespace.
3. Allow-list required flows only — including DNS.
4. Isolate namespaces, tenants, and environments from each other.
5. Restrict egress: block the metadata endpoint, limit external destinations.
6. Add identity-based segmentation with a service mesh (mTLS).
7. Make it automatic for new namespaces, and monitor real flows.

### Core Principles
- **Deny by default**: the safe state must be the default; every allowed connection is a deliberate, reviewable exception.
- **Least connectivity**: a pod should reach only what it genuinely calls — nothing more.
- **Both directions**: ingress controls who reaches a pod; egress controls where it can go. You need both.
- **Defense in depth**: NetworkPolicy (L3/L4) plus a mesh (L7 identity, mTLS) cover different layers — use them together for sensitive workloads.

## 1. Run a Policy-Enforcing CNI

A `NetworkPolicy` object is inert unless the network plugin enforces it. Confirm your CNI supports and enforces policy before relying on it.

```
# Which CNI is running? (look at the networking pods)
kubectl get pods -n kube-system -o wide | grep -Ei 'calico|cilium|weave|canal|antrea'

# Prove enforcement end-to-end: apply a default-deny, then test a blocked flow.
# If the connection still succeeds after a deny-all policy, the CNI is NOT enforcing.
```

**Calico** and **Cilium** are the two most widely used enforcing CNIs. Cilium is eBPF-based and adds identity-aware, L7-capable policies (`CiliumNetworkPolicy`); Calico offers rich `GlobalNetworkPolicy` and ordered tiers. A plugin without policy support leaves the cluster flat no matter how many policies you write.

## 2. Default-Deny Baseline in Every Namespace

This is the single most important control. Select all pods and permit nothing, for both ingress and egress. Everything then becomes an explicit exception.

```yaml
# default-deny-all.yaml — apply to EVERY namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: app-prod
spec:
  podSelector: {}              # selects every pod in the namespace
  policyTypes:
    - Ingress
    - Egress                    # deny egress too, not just ingress
  # no ingress/egress rules => nothing is allowed
```

> A deny-all egress policy will break DNS immediately, because pods can no longer reach `kube-dns`/CoreDNS. That is expected — the next step adds DNS back explicitly. Denying first and allow-listing second is the whole point.

## 3. Allow-List Required Flows (Including DNS)

With deny-all in place, add narrow allow policies for each real dependency.

```yaml
# Allow DNS egress to CoreDNS so name resolution works
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

```yaml
# Allow ONLY the api tier to reach the orders database, on 5432 only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-ordersdb
  namespace: app-prod
spec:
  podSelector:
    matchLabels: { app: orders-db }        # this policy protects the DB
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels: { app: orders-api }  # only orders-api may connect
      ports:
        - { protocol: TCP, port: 5432 }
```

Repeat per dependency: frontend→api, api→db, api→cache. Each policy names the exact pods and ports. Anything not listed stays denied by the baseline.

## 4. Isolate Namespaces, Tenants, and Environments

Namespaces are not a network boundary by themselves. Enforce isolation so cross-namespace traffic is denied unless explicitly allowed.

```yaml
# Allow ingress only from pods in the SAME namespace; deny other namespaces
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
        - podSelector: {}        # empty selector = pods in THIS namespace only
```

```yaml
# Cross-namespace allow must be explicit and labeled, e.g. shared ingress gateway
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: { purpose: ingress-gateway }
```

Keep `dev`, `staging`, and `prod` in separate namespaces (ideally separate clusters for the strongest isolation) and never allow-list traffic between environments. Label namespaces consistently so `namespaceSelector` rules are reliable.

## 5. Restrict Egress: Block Metadata, Limit External

Egress control is what stops metadata credential theft, C2, and exfiltration. Explicitly deny the link-local metadata range and allow only known external destinations.

```yaml
# Allow external egress but EXCLUDE the metadata endpoint and internal ranges
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-external-except-metadata
  namespace: app-prod
spec:
  podSelector:
    matchLabels: { app: fetcher }   # only pods that legitimately call out
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32   # cloud metadata / IMDS — always block
              - 169.254.0.0/16       # link-local
              - 10.0.0.0/8           # internal/private ranges
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - { protocol: TCP, port: 443 }
```

Complementary controls at other layers:
- **Enforce IMDSv2** and set the hop limit so pods cannot trivially reach the metadata service; block pod access to metadata at the node level where the platform supports it.
- **Right-size the node IAM role** so that even if metadata is reached, the credentials are minimally useful. Prefer per-workload cloud identity (e.g. IRSA / Workload Identity) over broad node roles.
- **Cilium/Calico global egress**: use `GlobalNetworkPolicy` (Calico) or a cluster-wide `CiliumClusterwideNetworkPolicy` to block `169.254.169.254` everywhere in one object.

```yaml
# Calico GlobalNetworkPolicy: block metadata cluster-wide (illustrative)
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

## 6. Identity-Based Segmentation with a Service Mesh (mTLS)

NetworkPolicy segments by IP/label at L3/L4. A service mesh adds **cryptographic identity**: every workload gets a certificate, traffic is mutually authenticated and encrypted, and policy is expressed in terms of *who* the caller is — not merely where it sits on the network.

```yaml
# Istio: require mTLS for all workloads in the namespace (STRICT)
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: app-prod
spec:
  mtls:
    mode: STRICT        # reject any non-mTLS (unidentified) traffic
```

```yaml
# Istio: authorize only the orders-api identity to call orders-db
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: ordersdb-allow-api
  namespace: app-prod
spec:
  selector:
    matchLabels: { app: orders-db }
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/app-prod/sa/orders-api"]
```

**Linkerd** provides mTLS automatically between meshed pods with minimal configuration and adds its own authorization policies. Whichever mesh you choose, mTLS closes the "network position = trust" gap that lets attackers impersonate services. Treat the mesh as a complement to NetworkPolicy, not a replacement: policy still limits raw L3/L4 reachability for non-meshed traffic.

## 7. Protect the Control Plane and Metadata Surface
- Deny pod egress to node kubelet ports (`10250`) and to node IPs unless specifically required.
- Limit which workloads can reach `kubernetes.default.svc` (the API server) if your CNI/mesh supports it; most application pods never need it.
- Disable automatic ServiceAccount token mounting where the token is not used (`automountServiceAccountToken: false`), so a foothold has no bearer token to replay against the API server.

## 8. Make Segmentation Automatic and Verified

A default-deny baseline is worthless if new namespaces skip it. Enforce it as policy-as-code.

```yaml
# Gatekeeper / Kyverno idea: require every namespace to carry a default-deny policy,
# or auto-generate one on namespace creation.
# Kyverno generate rule (illustrative):
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: add-default-deny
spec:
  rules:
    - name: default-deny-per-namespace
      match:
        any:
          - resources: { kinds: [Namespace] }
      generate:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        name: default-deny-all
        namespace: "{{request.object.metadata.name}}"
        data:
          spec:
            podSelector: {}
            policyTypes: [Ingress, Egress]
```

```
# Verify enforcement continuously
kubectl get netpol -A                       # every namespace should have a deny baseline
# Test tooling: run connectivity tests that assert blocked flows stay blocked
# (e.g. Cilium's connectivity test, or scripted nc/psql probes in CI)
```

## 9. Monitor Flows and Alert on Anomalies

Segmentation and observability reinforce each other — you cannot alert on a lateral-movement flow you never record.
- Enable CNI flow logs (Calico flow logs, Cilium Hubble) or mesh telemetry.
- Alert on: any pod connecting to `169.254.169.254`, cross-namespace flows that should not exist, traffic to kubelet/API ports, and egress to unknown external hosts.
- Watch for policy *denies* spiking — a burst of blocked connections from one pod is a strong lateral-movement signal.

## Layered Defense Summary

| Layer | Control | What It Stops |
|-------|---------|---------------|
| CNI enforcement | Calico / Cilium | Makes any policy real instead of inert |
| Default-deny baseline | Ingress + egress deny-all per namespace | The flat default-allow network |
| Allow-list | Per-dependency ingress/egress rules | Unnecessary reachability |
| Namespace isolation | Same-namespace-only / labeled cross-ns | Cross-tenant / cross-env pivots |
| Egress control | Block `169.254.169.254`, limit external | Metadata theft, C2, exfiltration |
| Service mesh mTLS | Istio / Linkerd identity + encryption | Impersonation, sniffing, spoofed callers |
| Policy-as-code + monitoring | Kyverno/Gatekeeper, flow logs | Drift, unsegmented new namespaces, blind spots |

## Key Takeaways

1. **Default-deny is the foundation** — apply an ingress and egress deny-all in every namespace, then allow-list.
2. **Only real policies count** — confirm your CNI (Calico/Cilium) actually enforces NetworkPolicy.
3. **Control egress deliberately** — blocking `169.254.169.254` and limiting external destinations stops the worst escalations.
4. **Namespaces need explicit isolation** — they are not a network boundary on their own.
5. **Add mTLS for identity** — a mesh gives you "who is calling," which IP-based policy cannot; automate the baseline so new namespaces are never left flat.

## Next Steps

- **[Examples](examples.md)**: Insecure vs. secure NetworkPolicy, isolation, and egress control
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
