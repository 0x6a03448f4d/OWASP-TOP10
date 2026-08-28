# K05: Inadequate Logging and Monitoring - Code Examples

Each pair below shows an **insecure** (blind) configuration and the **secure** version that captures, ships, and alerts on the signal. The three areas mirror the layers of a working detection stack: **API-server audit logging**, **runtime detection with Falco**, and **centralisation and alerting** (Fluent Bit -> SIEM, Prometheus/Alertmanager).

## 1. Kubernetes API Audit Logging

### Insecure
```bash
# kube-apiserver started with NO audit configuration.
# There is no --audit-policy-file and no --audit-log-path.
kube-apiserver \
  --etcd-servers=https://127.0.0.1:2379 \
  --authorization-mode=Node,RBAC
  # (no audit flags at all)

# Result:
#   - No record of who exec'd into which pod
#   - No record of secret reads or RBAC changes
#   - No record of privileged-pod creation
#   - Nothing to investigate with after an incident
```

An equally common variant "has audit logging" but with a policy that captures nothing useful:

```yaml
# audit-policy.yaml  (INSECURE: logs nothing meaningful)
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: None          # everything is dropped
# The flag is present, a file is configured, and the log is empty of signal.
```

### Secure
```yaml
# audit-policy.yaml  (SECURE: tiered by sensitivity)
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  # Full request+response for crown-jewel resources
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "configmaps", "serviceaccounts"]
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  # Interactive access to pods, in full
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]
  # Deliberately drop high-volume, low-value noise to control cost
  - level: None
    users: ["system:kube-scheduler", "system:kube-proxy"]
    verbs: ["watch", "get"]
  - level: None
    resources:
      - group: ""
        resources: ["events"]
  # Everything else still gets cheap, useful metadata
  - level: Metadata
```

```bash
# Wire it into the apiserver (self-managed)
kube-apiserver \
  --audit-policy-file=/etc/kubernetes/audit-policy.yaml \
  --audit-log-path=/var/log/kubernetes/audit.log \
  --audit-log-maxage=30 \
  --audit-log-maxbackup=10 \
  --audit-log-maxsize=100
# Managed clusters: enable the provider's audit/control-plane logging
# feature (off or minimal by default) and export it to your log sink.
```

> **Why it matters**: The secure policy makes exec, secret access, and RBAC changes *expensive to hide*—each produces a full, attributable record—while keeping routine, high-volume traffic cheap so the log stays affordable and readable.

## 2. Runtime Threat Detection (Falco)

### Insecure
```bash
# No runtime sensor is deployed anywhere in the cluster.
$ kubectl get daemonset -A | grep -iE 'falco|tetragon'
# (no output)

# Consequence: a reverse shell inside a container, a read of the
# service-account token by curl, a sensitive host mount, and an
# outbound connection to a mining pool all execute with ZERO
# process-level telemetry. The control plane never sees them.
```

### Secure
```bash
# Deploy Falco as a DaemonSet on every node (Helm)
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl=$SLACK_WEBHOOK
```

```yaml
# custom-rules.yaml — high-signal runtime rules
- macro: container
  condition: container.id != host

- macro: shell_procs
  condition: proc.name in (bash, sh, zsh, ash, dash, ksh)

# 1) A shell spawned inside a container (classic post-exploitation)
- rule: Shell Spawned In Container
  desc: An interactive shell started inside a running container
  condition: >
    spawned_process and container and shell_procs
    and proc.tty != 0
  output: >
    Shell in container (user=%user.name container=%container.name
    image=%container.image.repository proc=%proc.cmdline
    pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: WARNING
  tags: [container, shell, mitre_execution]

# 2) The service-account token read by an unexpected process
- rule: SA Token Read By Unexpected Process
  desc: Something other than the app read the mounted SA token
  condition: >
    open_read and container
    and fd.name contains "/var/run/secrets/kubernetes.io/serviceaccount/token"
    and not proc.name in (java, python, node, app)
  output: >
    SA token read (proc=%proc.cmdline file=%fd.name
    pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
  tags: [container, secrets, mitre_credential_access]

# 3) A sensitive host path mounted / accessed (escape primitive)
- rule: Sensitive Host Path Accessed
  desc: Container touched a sensitive host directory
  condition: >
    open_read and container
    and (fd.name startswith /proc/1/ or
         fd.name startswith /etc/kubernetes or
         fd.name startswith /var/lib/kubelet)
  output: >
    Sensitive host path accessed (file=%fd.name
    container=%container.name pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]

# 4) Outbound connection to an unexpected port (miner / C2 heuristic)
- rule: Unexpected Outbound Connection
  desc: Container initiated egress on a non-standard port
  condition: >
    outbound and container
    and not fd.sport in (53, 80, 443)
  output: >
    Unexpected egress (connection=%fd.name proc=%proc.cmdline
    pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: NOTICE
  tags: [network, mitre_exfiltration]
```

> **Why it matters**: These rules turn the invisible half of the attack—what runs *inside* the container and on the node—into concrete, routable events. Falco ships bundled defaults; the custom rules above add the highest-signal Kubernetes-specific detections.

## 3. Centralisation and Alerting

### Insecure
```bash
# Logs live only on the node, read ad hoc:
$ kubectl logs payments-api-6d4 -n prod
# Backing files rotate and vanish on pod restart:
#   /var/log/pods/prod_payments-api-6d4_<uid>/app/0.log
# Nothing is shipped off-cluster. An attacker with node access runs:
$ rm -f /var/log/pods/*/*/*.log /var/log/containers/*.log
# ...and the only copy of the evidence is gone.
# There is no alerting: dashboards exist but no rule pages anyone.
```

### Secure — ship everything off-cluster with Fluent Bit
```ini
# fluent-bit.conf — DaemonSet tails node-local logs + the audit log
[SERVICE]
    Flush        5
    Log_Level    info

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
    Keep_Log            Off

[OUTPUT]
    Name    es                     # or loki / splunk / http -> SIEM
    Match   *
    Host    logs.internal.example  # sink OUTSIDE the cluster account
    Port    9200
    tls     On
    Retry_Limit  5
    # Target index/bucket configured as append-only / object-locked (WORM)
```

### Secure — alert on high-risk events with Prometheus/Alertmanager
```yaml
# An exporter converts audit + Falco events into metrics; alert on them.
# prometheus-rules.yaml
groups:
- name: k8s-security
  rules:
  - alert: ExecIntoProdPod
    expr: increase(k8s_audit_pod_exec_total{namespace="prod"}[5m]) > 0
    for: 0m
    labels: { severity: high }
    annotations:
      summary: "kubectl exec into prod pod {{ $labels.pod }}"
      runbook: "https://runbooks.example/k8s-exec"

  - alert: PrivilegedPodCreated
    expr: increase(k8s_audit_privileged_pod_created_total[5m]) > 0
    labels: { severity: critical }
    annotations:
      summary: "Privileged pod created in {{ $labels.namespace }}"

  - alert: ClusterAdminBindingCreated
    expr: increase(k8s_audit_clusteradmin_binding_total[5m]) > 0
    labels: { severity: critical }

  - alert: FalcoCriticalRuntimeEvent
    expr: increase(falco_events_total{priority="Critical"}[5m]) > 0
    labels: { severity: critical }
    annotations:
      summary: "Critical Falco event: {{ $labels.rule }}"
```

```yaml
# alertmanager.yaml — critical events page on-call, not a silent channel
route:
  receiver: soc-default
  routes:
    - matchers: [ severity="critical" ]
      receiver: soc-pager
receivers:
  - name: soc-default
    slack_configs: [{ channel: "#k8s-alerts", api_url: "$SLACK_WEBHOOK" }]
  - name: soc-pager
    pagerduty_configs: [{ routing_key: "$PD_ROUTING_KEY" }]
```

> **Why it matters**: Fluent Bit moves evidence off the compromised asset in near-real-time to tamper-resistant storage, so cleanup cannot erase it. Prometheus/Alertmanager closes the loop—the high-risk events become pages a human receives, with a runbook attached.

## What Changed, and Why

| Control | Insecure (blind) | Secure (sees itself) |
|---------|------------------|----------------------|
| API audit | No policy, or `level: None` | Tiered policy; `RequestResponse` for exec/secrets/RBAC |
| Runtime | No sensor deployed | Falco DaemonSet + high-signal custom rules |
| Log storage | Node-local, rotates, attacker-deletable | Shipped off-cluster, append-only, retained |
| Alerting | Dashboards nobody watches | Prometheus rules page on-call with runbooks |
| Outcome | Months of undetected dwell time | Minutes-to-detect on high-risk events |

## Next Steps

- **[Prevention](prevention.md)**: The full capture -> centralise -> detect -> respond strategy
- **[Attack Vectors](attack-vectors.md)**: The activity these controls are designed to catch
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
