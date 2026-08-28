# K09: Misconfigured Cluster Components - Code Examples

Each pair below shows an **insecure** component configuration and the **hardened** version. The examples target the components that dominate real K09 findings: the API server, the kubelet, and etcd—then show how to *detect* drift automatically with `kube-bench` (the CIS Kubernetes Benchmark).

## 1. kube-apiserver

### Insecure
```
# /etc/kubernetes/manifests/kube-apiserver.yaml (excerpt)
spec:
  containers:
    - command:
        - kube-apiserver
        - --anonymous-auth=true              # system:anonymous can authenticate
        - --authorization-mode=AlwaysAllow   # RBAC effectively OFF
        - --insecure-port=8080               # legacy no-TLS, no-auth port
        - --insecure-bind-address=0.0.0.0    # reachable from anywhere
        - --enable-admission-plugins=        # NodeRestriction/PodSecurity missing
        - --profiling=true                   # /debug/pprof exposed
        # no --audit-log-path                # no audit trail
        - --tls-min-version=VersionTLS10     # weak transport
```

### Secure
```
# /etc/kubernetes/manifests/kube-apiserver.yaml (excerpt)
spec:
  containers:
    - command:
        - kube-apiserver
        - --anonymous-auth=false
        - --authorization-mode=Node,RBAC     # Node + RBAC, never AlwaysAllow
        # legacy insecure port not set (removed in modern Kubernetes)
        - --enable-admission-plugins=NodeRestriction,PodSecurity
        - --profiling=false
        - --audit-log-path=/var/log/kubernetes/audit.log
        - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
        - --tls-min-version=VersionTLS12
        - --kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt
        - --client-ca-file=/etc/kubernetes/pki/ca.crt
        - --encryption-provider-config=/etc/kubernetes/enc/enc.yaml
```

## 2. kubelet

### Insecure
```
# /var/lib/kubelet/config.yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: true          # anonymous callers accepted on 10250
authorization:
  mode: AlwaysAllow        # no authorization check -> /exec for anyone
readOnlyPort: 10255        # unauthenticated pods/specs/env/metrics
# no clientCAFile, no cert rotation
```

### Secure
```
# /var/lib/kubelet/config.yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false         # reject anonymous callers
  webhook:
    enabled: true          # authenticate via the API server
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook            # delegate authZ to the API server
readOnlyPort: 0            # disable the unauthenticated 10255 port
protectKernelDefaults: true
tlsMinVersion: VersionTLS12
rotateCertificates: true   # automatic kubelet cert rotation
```

## 3. etcd

### Insecure
```
# etcd manifest (excerpt)
- command:
    - etcd
    - --listen-client-urls=http://0.0.0.0:2379   # plaintext, all interfaces
    - --advertise-client-urls=http://0.0.0.0:2379
    # no --client-cert-auth, no --trusted-ca-file
    # -> anyone reaching 2379 dumps every Secret:
    #    etcdctl --endpoints=http://HOST:2379 get / --prefix --keys-only
    # no encryption-at-rest -> Secrets stored in the clear
```

### Secure
```
# etcd manifest (excerpt)
- command:
    - etcd
    - --cert-file=/etc/kubernetes/pki/etcd/server.crt
    - --key-file=/etc/kubernetes/pki/etcd/server.key
    - --client-cert-auth=true                    # require client certificates
    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
    - --peer-client-cert-auth=true               # authenticate peers
    - --listen-client-urls=https://127.0.0.1:2379,https://10.0.0.5:2379
    - --advertise-client-urls=https://10.0.0.5:2379
# Secrets encrypted at rest via the API server's EncryptionConfiguration
```

#### Encryption-at-rest (referenced above)
```
# /etc/kubernetes/enc/enc.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - kms:                     # prefer an external KMS in cloud
          name: cloud-kms
          endpoint: unix:///var/run/kmsplugin/socket.sock
      - identity: {}             # read-only fallback for old data
```

## 4. controller-manager and scheduler

### Insecure
```
- kube-controller-manager
- --profiling=true
- --use-service-account-credentials=false   # shared identity for controllers
- --bind-address=0.0.0.0                     # metrics on all interfaces

- kube-scheduler
- --profiling=true
- --bind-address=0.0.0.0
```

### Secure
```
- kube-controller-manager
- --profiling=false
- --use-service-account-credentials=true     # per-controller identities
- --service-account-private-key-file=/etc/kubernetes/pki/sa.key
- --bind-address=127.0.0.1

- kube-scheduler
- --profiling=false
- --bind-address=127.0.0.1
```

## 5. Enforce PodSecurity Admission (Namespace)

### Insecure
```
apiVersion: v1
kind: Namespace
metadata:
  name: payments
  # no Pod Security labels -> privileged pods admitted freely
```

### Secure
```
apiVersion: v1
kind: Namespace
metadata:
  name: payments
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
```

## 6. Detecting Drift with kube-bench (CIS Benchmark)

The examples above are the *intended* state. `kube-bench` proves the running cluster actually matches it by evaluating the CIS Kubernetes Benchmark control-by-control. Run it as a Job, or directly on a control-plane node.

```
# Run as a Kubernetes Job:
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# Or target specific component sets on a node:
kube-bench run --targets master,node,etcd,policies
```

#### Output on the INSECURE cluster
```
[INFO] 1 Control Plane Security Configuration
[FAIL] 1.2.1  Ensure that the --anonymous-auth argument is set to false
[FAIL] 1.2.6  Ensure that the --authorization-mode argument is not AlwaysAllow
[FAIL] 1.2.17 Ensure that the --profiling argument is set to false
[FAIL] 1.2.22 Ensure that the --audit-log-path argument is set

[INFO] 2 etcd
[FAIL] 2.1    Ensure that the --client-cert-auth argument is set to true
[FAIL] 2.2    Ensure that the --auto-tls argument is not set to true

[INFO] 4 Worker Node Security Configuration
[FAIL] 4.2.1  Ensure that the --anonymous-auth argument is set to false
[FAIL] 4.2.2  Ensure that the --authorization-mode is not AlwaysAllow
[FAIL] 4.2.4  Ensure that the --read-only-port argument is set to 0

== Summary ==  0 checks PASS   9 checks FAIL   3 checks WARN
```

#### Output after applying the SECURE configuration
```
[PASS] 1.2.1  Ensure that the --anonymous-auth argument is set to false
[PASS] 1.2.6  Ensure that the --authorization-mode argument is not AlwaysAllow
[PASS] 1.2.17 Ensure that the --profiling argument is set to false
[PASS] 1.2.22 Ensure that the --audit-log-path argument is set
[PASS] 2.1    Ensure that the --client-cert-auth argument is set to true
[PASS] 4.2.1  Ensure that the --anonymous-auth argument is set to false
[PASS] 4.2.4  Ensure that the --read-only-port argument is set to 0

== Summary ==  All critical checks PASS
```

#### Fail CI/CD on regression
```
# kube-bench emits JSON; gate the pipeline on any FAIL:
kube-bench run --targets master,node,etcd --json > results.json
FAILS=$(jq '[.Controls[].tests[].results[]
             | select(.status=="FAIL")] | length' results.json)
if [ "$FAILS" -gt 0 ]; then
  echo "CIS Benchmark regressions: $FAILS — failing build"
  exit 1
fi
```

## 7. Complementary Scanning

```
# Posture and IaC scanning alongside kube-bench:
kubescape scan framework nsa,mitre .    # hardening-framework posture
polaris audit --audit-path ./cluster    # config best-practice checks
trivy config ./infra                    # component/IaC misconfig scan
```

## What Changed, and Why

| Component setting | Insecure | Hardened |
|-------------------|----------|----------|
| API-server authN | `--anonymous-auth=true`, insecure port | `--anonymous-auth=false`, no insecure port |
| API-server authZ | `AlwaysAllow` | `Node,RBAC` |
| Admission plugins | Empty / disabled | `NodeRestriction,PodSecurity` |
| Kubelet | Anonymous + `AlwaysAllow`, 10255 open | Webhook authN/authZ, `readOnlyPort: 0` |
| etcd | Plaintext `0.0.0.0`, no client-cert | mTLS, private bind, encryption-at-rest |
| Audit / profiling | No audit, profiling on | Audit policy set, `--profiling=false` |
| Verification | None | kube-bench (CIS) in CI + on schedule |

## Next Steps

- **[Prevention](prevention.md)**: The full component-hardening strategy
- **[Attack Vectors](attack-vectors.md)**: How these misconfigurations are exploited
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts hands-on
