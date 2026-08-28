# K06: Broken Authentication Mechanisms - Code Examples

Each pair below shows an **insecure** configuration and the **secure** version for the same component. The examples focus on the authentication failures that dominate real cluster findings: anonymous access, an open kubelet, exposed etcd, long-lived ServiceAccount tokens, and shared certificates/kubeconfigs.

## 1. API Server: Anonymous Authentication

### Insecure
```
# kube-apiserver flags
--anonymous-auth=true            # failed auth is downgraded to system:anonymous
--token-auth-file=/etc/kubernetes/tokens.csv   # static, non-expiring bearer creds
--basic-auth-file=/etc/kubernetes/basic.csv    # legacy username/password file

# And an accidental binding makes it catastrophic:
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oops-anonymous
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
subjects:
  - kind: Group
    name: system:unauthenticated     # anyone, with no credential, can now read
    apiGroup: rbac.authorization.k8s.io
```

### Secure
```
# kube-apiserver flags: reject the unauthenticated, no static credential files
--anonymous-auth=false
# (no --token-auth-file, no --basic-auth-file)

# Verify nothing is bound to anonymous groups:
$ kubectl get clusterrolebindings -o json \
  | jq -r '.items[] | select(.subjects[]?
        | .name=="system:anonymous" or .name=="system:unauthenticated")
        | .metadata.name'
# Expect: (no output)
```

## 2. Kubelet: API Authentication (Port 10250)

### Insecure
```
# KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: true          # anonymous callers accepted
authorization:
  mode: AlwaysAllow        # every request authorized -> open exec/logs/pods
# Result: curl https://NODE:10250/pods and /run/... work for anyone.
```

### Secure
```
# KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false         # no anonymous access
  webhook:
    enabled: true          # bearer tokens verified via the API server
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt   # client-cert auth
authorization:
  mode: Webhook            # authz delegated to the API server (SubjectAccessReview)
# Plus: restrict 10250 to control-plane source ranges via network policy / firewall.
```

## 3. etcd: Datastore Authentication

### Insecure
```
# etcd started with no client-cert auth, listening on a routable address
etcd \
  --listen-client-urls=http://0.0.0.0:2379 \   # plaintext, all interfaces
  --advertise-client-urls=http://0.0.0.0:2379
# Anyone who can reach 2379 reads/writes all cluster state, Secrets included.
```

### Secure
```
# etcd with mutual TLS, restricted listeners, and peer authentication
etcd \
  --cert-file=/etc/kubernetes/pki/etcd/server.crt \
  --key-file=/etc/kubernetes/pki/etcd/server.key \
  --client-cert-auth=true \
  --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt \
  --peer-client-cert-auth=true \
  --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt \
  --listen-client-urls=https://127.0.0.1:2379,https://10.0.0.10:2379   # control plane only

# And encrypt Secrets at rest so a datastore/backup leak is not plaintext:
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-32-byte-key>
      - identity: {}
```

## 4. ServiceAccount Tokens: Legacy vs. Projected

### Insecure
```
# A legacy, non-expiring token Secret, valid for any audience, mounted broadly.
apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  name: build-bot-token
  annotations:
    kubernetes.io/service-account.name: build-bot
---
apiVersion: v1
kind: Pod
metadata:
  name: worker
spec:
  serviceAccountName: build-bot
  # automountServiceAccountToken defaults to true -> token is mounted and stealable
  containers:
    - name: app
      image: myapp:latest        # also a mutable tag; see K02
```

### Secure
```
# Projected, audience-bound, short-lived token; auto-rotated by the kubelet.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: worker-sa
automountServiceAccountToken: false     # default-deny; opt in per pod
---
apiVersion: v1
kind: Pod
metadata:
  name: worker
spec:
  serviceAccountName: worker-sa
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.4.2@sha256:<digest>
      volumeMounts:
        - name: api-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
  volumes:
    - name: api-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: api             # scoped, not "any audience"
              expirationSeconds: 3600   # short-lived, then rotated
# A stolen token is useful for minutes and only against one audience.
```

## 5. Human Access: kubeconfig and OIDC

### Insecure
```
# One shared kubeconfig, embedded long-lived cluster-admin cert, passed around.
apiVersion: v1
kind: Config
clusters:
  - name: prod
    cluster:
      server: https://prod-api.example.com:6443
      certificate-authority-data: <base64 CA>
users:
  - name: shared-admin
    user:
      client-certificate-data: <base64 X.509, O=system:masters, 5-year validity>
      client-key-data: <base64 key>
contexts:
  - name: prod
    context: { cluster: prod, user: shared-admin }
current-context: prod
# No MFA, no revocation (certs can't be revoked), no per-user attribution.
```

### Secure
```
# API server trusts an external IdP; humans get short-lived, MFA-backed tokens.
# kube-apiserver flags:
--oidc-issuer-url=https://idp.example.com
--oidc-client-id=kubernetes
--oidc-username-claim=email
--oidc-groups-claim=groups
--oidc-username-prefix=oidc:
--oidc-groups-prefix=oidc:

# kubeconfig uses an OIDC exec/credential plugin; no static secret on disk:
users:
  - name: alice
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubelogin           # obtains a short-lived id_token via the IdP (+MFA)
        args: ["get-token", "--oidc-issuer-url=https://idp.example.com",
               "--oidc-client-id=kubernetes"]
# IdP groups map to least-privilege RBAC roles (see K03), never system:masters.
```

## 6. Client Certificates: Long-Lived vs. Short-Lived

### Insecure
```
# A hand-crafted, multi-year client cert with the master group, shared with CI.
openssl req -new -key ci.key -subj "/CN=ci/O=system:masters"
openssl x509 -req -days 1825 -in ci.csr -CA ca.crt -CAkey ca.key -out ci.crt
# 5 years of unrevocable cluster-admin sitting in a CI variable.
```

### Secure
```
# Request a short-lived, scoped client cert via the CSR API; re-issue often.
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ci-deployer
spec:
  request: <base64 CSR, CN=ci-deployer, no system:masters>
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 3600            # one hour
  usages: ["client auth"]
# Bind CN=ci-deployer to a least-privilege Role, not cluster-admin.
```

## What Changed, and Why

| Component | Insecure | Secure |
| --- | --- | --- |
| API server | Anonymous on; static token/basic-auth files | `--anonymous-auth=false`; OIDC; no static files |
| Kubelet | Anonymous on, `AlwaysAllow` | Anonymous off, webhook authn, `Webhook` authz |
| etcd | Plaintext, all interfaces, no client-cert auth | Mutual TLS, control-plane-only, encryption at rest |
| SA tokens | Legacy non-expiring, auto-mounted | Projected, audience-bound, short-lived; mount opt-in |
| Human access | Shared kubeconfig, long-lived admin cert | OIDC/SSO with MFA, short-lived id_tokens |
| Certificates | Multi-year, `system:masters`, shared | Short-lived via CSR API, scoped, rotated |

## Next Steps

- **[Prevention](prevention.md)**: The full component-by-component hardening strategy
- **[Attack Vectors](attack-vectors.md)**: How these authentication failures are exploited
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
