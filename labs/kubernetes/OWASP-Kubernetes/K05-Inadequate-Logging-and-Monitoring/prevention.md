# K05: Inadequate Logging and Monitoring - Prevention

## Prevention Strategy Overview

Preventing K05 means building a cluster that **records what matters, ships it somewhere durable, and turns high-risk events into alerts a human receives**. Think of it as four layers stacked on top of each other—each is necessary and none is sufficient alone:

1. **Capture** the signal: API-server audit, runtime, workload, node, and cloud telemetry.
2. **Centralise** it off-cluster in tamper-resistant storage with retention.
3. **Detect**: alert on the specific events that indicate compromise.
4. **Respond**: wire alerts into an incident-response process.

### Core Principles

- **Capture at the source, in real time**: ephemeral pods destroy evidence—telemetry must leave the node before the pod does.
- **Tune, don't disable**: noise is a policy problem; the answer is a sharper audit policy and better rules, never turning the signal off.
- **Collection is not detection**: every source must terminate in an alert or a query someone actually runs.
- **Assume the node is hostile**: store logs where a compromised node cannot alter or delete them (append-only, off-cluster).

## 1. Enable API-Server Audit Logging with a Sound Policy

The API audit log is the single richest security signal in Kubernetes. Enable it with a tiered policy: cheap `Metadata` for routine traffic, full `RequestResponse` for sensitive verbs, and `None` for high-volume noise.

```yaml
# audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  # Full request+response for the crown-jewel resources
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "configmaps", "serviceaccounts"]
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  # Record exec / attach / port-forward into pods in full
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]
  # Drop noisy, low-value reads to control cost
  - level: None
    users: ["system:kube-scheduler", "system:kube-proxy"]
    verbs: ["watch", "get"]
  - level: None
    resources:
      - group: ""
        resources: ["events"]
  # Everything else: metadata is cheap and still valuable
  - level: Metadata
```

```bash
# Wire the policy into kube-apiserver (self-managed clusters)
kube-apiserver \
  --audit-policy-file=/etc/kubernetes/audit-policy.yaml \
  --audit-log-path=/var/log/kubernetes/audit.log \
  --audit-log-maxage=30 \
  --audit-log-maxbackup=10 \
  --audit-log-maxsize=100
# Managed clusters: enable the provider's audit/control-plane logging
# and forward it to your log sink (this is off or minimal by default).
```

> On managed control planes you cannot pass apiserver flags directly—enable the provider's audit-logging feature and export it to your logging service or SIEM. It is frequently disabled by default.

## 2. Deploy Runtime Threat Detection (Falco / Tetragon)

API audit tells you what was asked of the control plane; a runtime sensor tells you what actually executed *inside* containers and on nodes. Deploy one as a DaemonSet on every node.

```bash
# Install Falco cluster-wide (Helm)
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl=$SLACK_WEBHOOK
```

Runtime rules should cover, at minimum: a shell spawned in a container, writes to sensitive paths, reads of the service-account token by unexpected processes, sensitive host mounts, and outbound connections to unexpected destinations. (See the [Examples](examples.md) page for concrete rules.)

## 3. Centralise Logs Off-Cluster (Tamper-Resistant)

Ship every source—audit log, runtime events, pod stdout/stderr, node logs—off the cluster in real time to storage the cluster's own identities cannot modify.

```ini
# Fluent Bit DaemonSet: tail node-local logs and forward to a sink
[INPUT]
    Name              tail
    Path              /var/log/containers/*.log
    Tag               kube.*
    Refresh_Interval  5

[INPUT]
    Name              tail
    Path              /var/log/kubernetes/audit.log
    Tag               audit.*

[FILTER]
    Name                kubernetes
    Match               kube.*
    Merge_Log           On

[OUTPUT]
    Name   es                 # or loki, splunk, http -> your SIEM
    Match  *
    Host   logs.internal.example
    Port   9200
    tls    On
    Retry_Limit  5
```

Hardening rules for the pipeline:

- The sink lives **outside the cluster** (a separate account/project), so a cluster compromise does not grant log-deletion.
- Storage is **append-only / WORM** where possible (object-lock buckets, immutable indices).
- The forwarder ships in **near-real-time** so evidence survives pod deletion.
- **Retention** is measured in weeks-to-months, matching your realistic time-to-discovery.

## 4. Alert on High-Risk Events

Collection is inert without alerting. Define rules that page a human on the events that indicate compromise.

| Event | Source | Why alert |
|-------|--------|-----------|
| `exec`/`attach` into a prod pod | API audit | Interactive access is rare and high-risk |
| Create pod with `privileged`/`hostPID`/`hostPath` | API audit / admission | Escape primitive |
| New binding granting `cluster-admin` | API audit (RBAC) | Privilege escalation |
| Bulk `get/list secrets` by one identity | API audit | Credential harvesting |
| Image pulled from non-allow-listed registry | Runtime / events | Malware / miner delivery |
| Shell or package manager run in a container | Runtime (Falco) | Post-exploitation |
| Requests from `system:anonymous` | API audit | Unauthenticated probing |

```yaml
# Prometheus Alertmanager rule (fed by a metrics exporter over audit/runtime)
groups:
- name: k8s-security
  rules:
  - alert: PrivilegedPodCreated
    expr: increase(k8s_audit_privileged_pod_created_total[5m]) > 0
    labels: { severity: critical }
    annotations:
      summary: "Privileged pod created in {{ $labels.namespace }}"
  - alert: ClusterAdminBindingCreated
    expr: increase(k8s_audit_clusteradmin_binding_total[5m]) > 0
    labels: { severity: critical }
  - alert: ExecIntoProdPod
    expr: increase(k8s_audit_pod_exec_total{namespace="prod"}[5m]) > 0
    labels: { severity: high }
```

## 5. Monitor for Cryptomining and Anomalies

- **Registry allow-list**: alert (and ideally block via admission) on any image pulled from outside approved registries.
- **Runtime pool/C2 detection**: Falco rules for connections to known mining-pool ports/domains and for miner process names.
- **Resource baselines**: alert on sustained abnormal CPU across pods that historically idle—a lagging but useful signal.
- **Egress monitoring**: enable network-policy/flow logging and alert on unexpected outbound destinations.

## 6. Collect the Cloud Control-Plane and Node Trail

The cluster is only half the picture. Forward the cloud provider's audit trail (managed control-plane logs, IAM activity, node metadata access) into the *same* SIEM so cross-plane pivots can be correlated.

- Enable managed-control-plane audit logging (off/minimal by default on several providers).
- Collect kubelet and node system logs, image-pull events, and admission-webhook decisions.
- Ensure IAM/role-assumption events land alongside cluster events for a single timeline.

## 7. Ensure Retention, Integrity, and Time Synchronisation

```bash
# Every node runs NTP/chrony so events order correctly across sources
timedatectl set-ntp true
chronyc tracking      # verify offset is small and stable
```

- **Retention**: keep logs long enough to investigate a late-discovered incident (weeks to months, per policy/compliance).
- **Integrity**: append-only/WORM storage and, where required, cryptographic signing or hashing of log batches.
- **Time sync**: without synchronised clocks, correlating node-a, node-b, and the cloud plane into one timeline is impossible.

## 8. Integrate With Incident Response

Telemetry exists to drive action. Close the loop:

- Route critical alerts to on-call paging, not just a dashboard or a chat channel nobody reads.
- Write runbooks that map each alert to an investigation and containment step (isolate node, revoke token, cordon/drain, rotate secrets).
- Rehearse: run tabletop and live-fire exercises so the telemetry is proven *before* a real incident.
- Track detection metrics (mean-time-to-detect, alert precision) and tune rules that are too noisy or too quiet.

## Defence Coverage Matrix

| Attacker activity | Primary control | Backstop control |
|-------------------|-----------------|------------------|
| Exec into pod | Audit alert on `pods/exec` | Falco shell-in-container rule |
| Privileged pod | Audit/admission alert | Runtime sensitive-mount rule |
| Secret harvesting | Audit `RequestResponse` on secrets | Per-identity anomaly alert |
| Container escape | Falco/Tetragon syscall rule | Node log + cloud audit |
| Cryptominer | Registry allow-list alert | Egress + CPU baseline |
| Evidence deletion | Off-cluster append-only sink | Audit of delete calls |

## Key Takeaways

1. **Enable API audit with a tiered policy** — metadata everywhere, full request/response for exec, secrets, and RBAC.
2. **Add a runtime sensor** — Falco/Tetragon on every node is the only view into in-container and on-node activity.
3. **Centralise off-cluster, tamper-resistant, with retention** — evidence must outlive the pod and survive a node compromise.
4. **Alert, don't just collect** — wire high-risk events to paging and a runbook.
5. **Correlate and rehearse** — sync clocks, pull in the cloud trail, and prove the pipeline before you need it.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure audit policy, Falco rules, and pipelines
- **[Attack Vectors](attack-vectors.md)**: Understand the activity you're trying to detect
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
