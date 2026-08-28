# K09: Misconfigured Cluster Components - Prevention

## Prevention Strategy Overview

Hardening cluster components is not one setting—it is **making a benchmarked, locked-down state the only state that runs**, and continuously proving it has not drifted:

1. Lock down authentication and authorization on every component.
2. Require mutual TLS everywhere and encrypt Secrets at rest.
3. Enable the security-critical admission plugins and audit logging.
4. Close legacy and debug surfaces (insecure port, read-only kubelet port, profiling).
5. Measure against the CIS Kubernetes Benchmark with `kube-bench` on a schedule, and fail on regression.

### Core Principles
- **Authenticate and authorize the infrastructure**: components are subjects too—no anonymous access, no `AlwaysAllow`.
- **mTLS between every component**: the API server, kubelets, and etcd must verify each other's certificates.
- **Least surface**: every open port, profiling endpoint, and legacy flag is attack surface—disable what you do not need.
- **Benchmark, don't guess**: the CIS Kubernetes Benchmark defines "hardened"; automate the check so drift fails fast.
- **Prefer managed defaults, then verify**: let the provider run the control plane where you can, but confirm nodes and add-ons are hardened too.

## 1. Harden the API Server

Set authentication, authorization, admission, and audit deliberately. These flags live in the API-server manifest (e.g. `/etc/kubernetes/manifests/kube-apiserver.yaml` on kubeadm clusters).

```
# kube-apiserver — secure flags
--anonymous-auth=false                       # no system:anonymous
--authorization-mode=Node,RBAC               # Node + RBAC, never AlwaysAllow
# (do NOT set --insecure-port / --insecure-bind-address; the legacy
#  insecure port is removed in modern Kubernetes — keep it that way)
--enable-admission-plugins=NodeRestriction,PodSecurity
--profiling=false                            # no /debug/pprof
--audit-log-path=/var/log/kubernetes/audit.log
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--tls-min-version=VersionTLS12
--tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt   # verify kubelets
--client-ca-file=/etc/kubernetes/pki/ca.crt
```

## 2. Lock Down the Kubelet

The kubelet has its own authN/authZ, separate from the API server, and its own dangerous defaults on hand-built nodes. Configure it via the KubeletConfiguration file.

```
# /var/lib/kubelet/config.yaml — secure kubelet
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false          # reject anonymous callers on 10250
  webhook:
    enabled: true           # authenticate via the API server
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook             # delegate authZ to the API server (never AlwaysAllow)
readOnlyPort: 0             # disable the unauthenticated 10255 port
protectKernelDefaults: true
tlsMinVersion: VersionTLS12
rotateCertificates: true    # automatic kubelet cert rotation
```

With this, port `10250` requires a valid client certificate and an authorization decision, and the `10255` read-only port is closed entirely.

## 3. Secure etcd

etcd holds every Secret. Require mutual TLS, keep it on a private interface, and never expose it to workloads.

```
# etcd — mutual TLS + private binding
--cert-file=/etc/kubernetes/pki/etcd/server.crt
--key-file=/etc/kubernetes/pki/etcd/server.key
--client-cert-auth=true                        # require client certificates
--trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
--peer-client-cert-auth=true                   # authenticate peers too
--listen-client-urls=https://127.0.0.1:2379,https://<private-ip>:2379
--advertise-client-urls=https://<private-ip>:2379
```

The API server, and only the API server, should hold a client certificate for etcd. Restrict network access to `2379/2380` with host firewalls and network policy so no workload can reach it.

## 4. Encrypt Secrets at Rest

Even a hardened etcd can be snapshotted or backed up. Encrypt Secrets so a stolen datastore is not an automatic breach.

```
# EncryptionConfiguration passed to the API server via
# --encryption-provider-config=/etc/kubernetes/enc/enc.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - aescbc:                    # or a KMS provider (preferred in cloud)
          keys:
            - name: key1
              secret: <base64-32-byte-key>
      - identity: {}               # fallback for reading old data
```

Prefer a cloud **KMS provider** so the encryption key itself lives outside the cluster. After enabling, re-write existing Secrets so they are encrypted: `kubectl get secrets -A -o json | kubectl replace -f -`.

## 5. Enable the Security-Critical Admission Plugins

Two admission controllers directly defend the components layer:

- **`NodeRestriction`**: confines each kubelet to its own node and pods—contains a single-node compromise.
- **`PodSecurity`**: the built-in Pod Security Admission enforcing the Pod Security Standards.

```
# Enforce a baseline/restricted profile per namespace via PSA labels:
apiVersion: v1
kind: Namespace
metadata:
  name: payments
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
```

> **Distinction from K04:** enabling `PodSecurity` here is the *component* configuration. Building comprehensive, uniform workload policy across every cluster (with an engine like Kyverno or Gatekeeper) is **K04 — Lack of Centralized Policy Enforcement**. K09 makes sure the API server itself has the guardrail switched on.

## 6. Enable Audit Logging

Without an audit policy, exploitation of any of the above leaves no trace. Define what to record and route it off-node.

```
# audit-policy.yaml — record the security-relevant events
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse            # full detail for Secret access
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  - level: Metadata                   # who/what/when for everything else
    omitStages: ["RequestReceived"]
```

Ship audit logs to a system outside the cluster so a node compromise cannot erase them (this connects to **K05 — Inadequate Logging and Monitoring**).

## 7. Harden Scheduler, Controller-Manager, and Add-ons

```
# kube-controller-manager
--profiling=false
--use-service-account-credentials=true     # per-controller identities
--service-account-private-key-file=/etc/kubernetes/pki/sa.key
--bind-address=127.0.0.1                    # metrics not on all interfaces

# kube-scheduler
--profiling=false
--bind-address=127.0.0.1

# Add-ons (CoreDNS, etc.): grant least-privilege RBAC,
# do not expose their metrics/health beyond the cluster.
```

## 8. Rotate Certificates and Avoid Defaults

- Use a real cluster CA; never ship default or sample certificates/keys.
- Keep certificate lifetimes short and rotate automatically (`rotateCertificates: true` for kubelets; renew control-plane certs on a cadence).
- Treat any leaked component key as a full cluster compromise—re-issue the CA if the root is exposed.

## 9. Verify Continuously with kube-bench (CIS Benchmark)

The CIS Kubernetes Benchmark is the authoritative definition of a hardened cluster. `kube-bench` runs those checks against a live cluster and reports PASS/FAIL/WARN per control—turning "is this hardened?" into an automated gate.

```
# Run kube-bench as a Job on the cluster:
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# Or on a control-plane node directly:
kube-bench run --targets master,node,etcd,policies

# Example output (abridged):
# [FAIL] 1.2.1  Ensure --anonymous-auth is set to false
# [PASS] 1.2.6  Ensure --authorization-mode is not AlwaysAllow
# [FAIL] 4.2.4  Ensure the --read-only-port is set to 0
# [WARN] 2.1    Ensure etcd client cert auth is enabled
```

Wire kube-bench into CI/CD and a scheduled job so drift and newly introduced insecure flags fail the pipeline—complement it with `kubescape` or `Polaris` for broader posture and IaC scanning of your cluster manifests.

## 10. Scan Cluster Configuration as Code (IaC)

Catch insecure component settings before they ship by scanning the manifests, Terraform, and provisioning code that define the cluster.

```
# Scan cluster / IaC definitions in CI:
kubescape scan framework nsa,mitre .        # posture vs. hardening frameworks
polaris audit --audit-path ./cluster        # config best-practice checks
checkov -d ./infra                          # Terraform / K8s misconfig
trivy config ./infra                        # IaC + component config scan
```

Run these on every pull request that touches cluster provisioning, and on a schedule against the running cluster, so both new mistakes and drift are caught.

## 11. Prefer Managed, Then Verify the Shared-Responsibility Line

Managed control planes (EKS, GKE, AKS) run and harden the API server and etcd for you—a large chunk of K09 handled by the provider. But your responsibility does not vanish:

- Node/kubelet configuration, node OS hardening, and node cert rotation are frequently yours.
- Admission-plugin and audit options you can influence must still be set.
- Add-ons and anything self-managed still need benchmarking.

Run `kube-bench` in its managed-platform mode to see exactly which controls the provider covers and which remain your job.

## Component Hardening Reference

| Component | Do | Never |
|-----------|----|-------|
| kube-apiserver | `--anonymous-auth=false`, `Node,RBAC`, audit on | Insecure port, `AlwaysAllow`, empty admission set |
| kubelet | Anonymous off, `authorization.mode: Webhook`, `readOnlyPort: 0` | Anonymous auth, `AlwaysAllow`, port 10255 open |
| etcd | mTLS, private bind, encryption-at-rest | Plaintext, `0.0.0.0`, no client-cert auth |
| controller-mgr / scheduler | `--profiling=false`, bind localhost | Metrics/profiling on all interfaces |
| All components | Rotate certs, run kube-bench | Default/self-signed certs, no benchmarking |

## Key Takeaways

1. **Authenticate and authorize the infrastructure** — disable anonymous access and never use `AlwaysAllow` on the API server or kubelet.
2. **mTLS and encryption-at-rest for etcd** — require client certificates, keep it private, and encrypt Secrets so a snapshot is not a breach.
3. **Turn on the guardrails** — `NodeRestriction`, `PodSecurity`, and audit logging are the admission and forensic backbone.
4. **Close legacy and debug surfaces** — no insecure port, no `10255`, no profiling on all interfaces.
5. **Benchmark continuously** — kube-bench (CIS) plus IaC scanning turn hardening into an automated, drift-proof gate.

## Next Steps

- **[Examples](examples.md)**: Insecure vs. hardened API-server, kubelet, and etcd configuration
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the Kubernetes Top 10
- **[Practice](/practice)**: Apply these concepts hands-on
