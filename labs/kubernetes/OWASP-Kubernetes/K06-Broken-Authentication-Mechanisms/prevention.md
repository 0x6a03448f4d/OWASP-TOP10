# K06: Broken Authentication Mechanisms - Prevention

## Prevention Strategy Overview

Preventing broken authentication is less about a single control and more about **making a verified, short-lived identity the only way in**:

1. Reject the unauthenticated—disable anonymous access on every component.
2. Authenticate every component independently—API server, kubelet, and etcd.
3. Give humans federated identity (OIDC/SSO with MFA), not shared static credentials.
4. Give workloads short-lived, audience-bound tokens, not permanent secrets.
5. Keep every credential short-lived, rotated, and revocable—and never publicly reachable.

### Core Principles
- **Deny by default**: a request that cannot prove who it is must get `401`, not an anonymous identity.
- **Authenticate every door**: the kubelet and etcd are separate authentication surfaces, not covered by the API server's config.
- **Short-lived over long-lived**: expiry is the cheapest revocation. Prefer tokens and certs measured in minutes/hours, auto-rotated.
- **No shared secrets**: one identity per human and per workload, so access can be attributed and revoked individually.

## 1. Disable Anonymous Authentication

Stop unauthenticated requests from being downgraded to an identity. Set this on the API server and confirm the kubelet is not anonymous either.

```
# kube-apiserver: reject anything that fails all real authenticators
kube-apiserver \
  --anonymous-auth=false

# Verify no binding hands anything to anonymous groups:
$ kubectl get clusterrolebindings -o json \
  | jq '.items[] | select(.subjects[]?
        | .name=="system:anonymous" or .name=="system:unauthenticated")
        | .metadata.name'
# Expect NO results.
```

> Some managed control planes keep a narrow anonymous allowance for health endpoints. That is acceptable when it is scoped to `/healthz`, `/livez`, `/readyz` only. What must never exist is a binding granting `system:anonymous` or `system:unauthenticated` access to real resources.

## 2. Authenticate and Lock Down the Kubelet

The kubelet API on port 10250 is a separate door. Require authentication and delegate authorization to the API server, and remove the always-allow escape hatch.

```
# kubelet configuration (KubeletConfiguration)
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false           # no anonymous kubelet access
  webhook:
    enabled: true            # authenticate bearer tokens via the API server
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook              # NOT AlwaysAllow; defer authz to the API server
```

Also restrict network reach: node ports (10250) should only be reachable from the control plane, never from workloads or the internet. Enforce with network policy / security groups and consider the `NodeRestriction` admission plugin so a kubelet credential can only affect its own node.

## 3. Protect etcd with Mutual TLS

etcd holds all cluster state and Secrets. It must require client-certificate authentication, use peer TLS, and never be reachable outside the control plane.

```
# etcd: require client certs and encrypt peer traffic
etcd \
  --cert-file=/etc/kubernetes/pki/etcd/server.crt \
  --key-file=/etc/kubernetes/pki/etcd/server.key \
  --client-cert-auth=true \
  --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt \
  --peer-client-cert-auth=true \
  --listen-client-urls=https://127.0.0.1:2379,https://<control-plane-ip>:2379
```

Pair this with **encryption at rest** so a datastore or backup leak does not expose Secrets in the clear:

```
# EncryptionConfiguration referenced by --encryption-provider-config
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-32-byte-key>   # ideally backed by a KMS provider
      - identity: {}
```

## 4. Use Short-Lived, Bound ServiceAccount Tokens

Prefer projected tokens issued by the TokenRequest API: they expire, are bound to a specific Pod and audience, and rotate automatically. Avoid legacy non-expiring token Secrets.

```
# A projected, audience-bound, short-lived token (auto-rotated by the kubelet)
apiVersion: v1
kind: Pod
metadata:
  name: worker
spec:
  serviceAccountName: worker-sa
  automountServiceAccountToken: false   # opt in explicitly below
  containers:
    - name: app
      image: myapp:1.2.3@sha256:<digest>
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
              audience: api            # scoped audience, not "any"
              expirationSeconds: 3600  # short-lived, then rotated
```

Turn off automatic mounting where API access is not needed, so a compromised container has no token to steal:

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: no-api-access
automountServiceAccountToken: false   # default-deny at the ServiceAccount level
```

## 5. Integrate OIDC / SSO for Humans

Humans should authenticate through your identity provider with MFA, receiving short-lived tokens and group claims that map to RBAC—never a shared kubeconfig.

```
# kube-apiserver: trust an external OIDC identity provider
kube-apiserver \
  --oidc-issuer-url=https://idp.example.com \
  --oidc-client-id=kubernetes \
  --oidc-username-claim=email \
  --oidc-groups-claim=groups \
  --oidc-username-prefix="oidc:" \
  --oidc-groups-prefix="oidc:"
```

Benefits over shared credentials: **MFA** at the IdP, **central revocation** when someone leaves, **short-lived** id_tokens, and **per-user audit attribution**. Map IdP groups to least-privilege RBAC roles (see K03), never straight to `system:masters`.

## 6. Remove Static Token and Basic-Auth Files

These legacy mechanisms are static bearer credentials with no expiry. Remove the flags entirely.

```
# DELETE these from the API server startup if present:
#   --token-auth-file=/etc/kubernetes/tokens.csv
#   --basic-auth-file=/etc/kubernetes/basic-auth.csv
# Migrate those identities to OIDC (humans) or ServiceAccounts (workloads).
```

## 7. Manage Certificates: Short-Lived, Scoped, Rotated

Because Kubernetes has no certificate revocation list, control risk with **short lifetimes** and **tight scope**.

- Issue client certificates through the `CertificateSigningRequest` API with a short `expirationSeconds`, not multi-year certs.
- Never share one `O=system:masters` cert across a team or bake it into CI images.
- Enable control-plane certificate rotation and rotate the cluster CA on a defined cadence.
- Scope each identity: a CI pipeline gets its own short-lived credential with only the permissions it needs.

```
# Request a short-lived client cert via the CSR API
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ci-deployer
spec:
  request: <base64 CSR>
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 3600        # one hour, then re-issue
  usages: ["client auth"]
```

## 8. Do Not Expose the API Server or Dashboards Publicly

- Keep the API server endpoint private (or restrict source ranges); a control plane on the open internet is scanned continuously.
- The Kubernetes Dashboard should require token authentication, be bound to a least-privilege ServiceAccount, and be reached only through authenticated, access-controlled means—never published raw.
- Put node ports (kubelet 10250) and etcd (2379) behind network controls so only the control plane can reach them.

## 9. Strong Cloud-IAM-to-RBAC Mapping

On managed clusters, the cloud identity layer is part of authentication. Keep the mapping least-privilege.

- Map specific cloud roles/groups to specific, scoped Kubernetes groups—never a broad role to `system:masters`.
- Use per-workload cloud identity (workload identity federation) so Pods get scoped cloud access without long-lived static keys.
- Review the mapping whenever cloud roles change; a broadened cloud role can silently widen cluster access.

## 10. Detect Authentication Weaknesses and Abuse

Audit for the conditions and watch for the signatures of abuse. (Detection depth is the subject of K05.)

```
# Configuration audit with a benchmark scanner:
$ kube-bench run --targets master,node   # flags anonymous-auth, kubelet authz, etc.

# Hunt for legacy long-lived SA token Secrets:
$ kubectl get secrets -A --field-selector type=kubernetes.io/service-account-token

# Alert (via audit logs) on:
#   - successful requests from system:anonymous
#   - authentication from unexpected source IPs for a ServiceAccount
#   - use of a credential after the associated identity was deprovisioned
```

## Prevention Checklist by Component

| Component | Control | Setting |
| --- | --- | --- |
| API server | No anonymous access | `--anonymous-auth=false`; no static token/basic-auth files |
| API server | Human identity | OIDC/SSO with MFA and group claims |
| Kubelet | Authn + authz | anonymous off, webhook authn, `authorization.mode: Webhook` |
| etcd | Mutual TLS, private | `--client-cert-auth=true`, control-plane-only reachability, encryption at rest |
| Workloads | Short-lived tokens | Projected/bound tokens, `automountServiceAccountToken: false` by default |
| Certificates | Short-lived, scoped | CSR API with `expirationSeconds`, rotation, no shared admin certs |
| Cloud IAM | Least-privilege mapping | Specific roles to scoped groups, workload identity federation |

## Key Takeaways

1. **Deny the anonymous** — `--anonymous-auth=false` and no binding to `system:unauthenticated`.
2. **Authenticate every door** — the kubelet and etcd need their own authentication, independent of the API server.
3. **Federate humans, scope workloads** — OIDC/SSO with MFA for people, short-lived projected tokens for Pods.
4. **Short-lived beats revocable** — expiry is the revocation Kubernetes certs don't otherwise have; keep lifetimes small and rotate.
5. **Never expose the control plane** — API server, kubelet, etcd, and dashboards stay behind network controls and authentication.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure configuration for each component
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
