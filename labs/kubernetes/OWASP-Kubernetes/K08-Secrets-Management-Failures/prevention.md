# K08: Secrets Management Failures - Prevention

## Prevention Strategy Overview

Preventing secrets failures is less about one control and more about **making the protected path the easy path**:

1. Make the stored form confidential—encryption-at-rest for etcd.
2. Source secrets from a real manager instead of embedding them.
3. Keep secrets out of images, manifests, ConfigMaps, and Git.
4. Deliver them narrowly—mounted files, least-privilege RBAC, no needless tokens.
5. Rotate, scan, and audit continuously.

### Core Principles

- **Encryption is separate from encoding**: base64 is not protection; confidentiality at rest comes from etcd encryption (ideally KMS-backed).
- **Secrets are external state**: prefer a dedicated manager (Vault, cloud secret manager) delivered at runtime, not values living in the cluster forever.
- **Least exposure**: every place a secret is copied is attack surface—minimise copies, minimise readers, minimise lifetime.
- **Assume leaks are permanent**: design for rotation, because deletion never removes a value from history, layers, or snapshots.

## 1. Enable etcd Encryption-at-Rest (KMS-backed)

Turn the default base64 storage into genuine ciphertext. A KMS provider keeps the data-encryption key outside etcd itself.

```yaml
# EncryptionConfiguration passed to the API server via --encryption-provider-config
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - kms:                       # external KMS holds the key-encryption key
          apiVersion: v2
          name: cluster-kms
          endpoint: unix:///var/run/kmsplugin/socket.sock
      - aescbc:                    # fallback local key (better than identity)
          keys:
            - name: key1
              secret: <base64-32-byte-key>
      - identity: {}               # read-only fallback; never first in the list
```

After enabling, re-encrypt existing secrets so old plaintext is replaced, and protect etcd snapshots as if they were the secrets themselves:

```bash
# Rewrite every secret through the new provider:
$ kubectl get secrets -A -o json | kubectl replace -f -

# Treat snapshots as crown jewels: encrypt + access-control the backup store.
```

## 2. Source Secrets From an External Manager

Keep the durable copy in a purpose-built manager and inject it into pods at runtime, so it is never a permanent Kubernetes object baked into manifests.

#### Secrets Store CSI Driver (mount from Vault / cloud managers)

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: db-spc
spec:
  provider: vault
  parameters:
    roleName: "app"
    vaultAddress: "https://vault.internal:8200"
    objects: |
      - objectName: "db-password"
        secretPath: "secret/data/prod/db"
        secretKey: "password"
---
# Pod mounts the secret as a file; nothing is stored as a K8s Secret
volumes:
  - name: secrets
    csi:
      driver: secrets-store.csi.x-k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "db-spc"
```

#### External Secrets Operator (sync a manager into a Secret)

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-creds
spec:
  refreshInterval: 1h            # pulls fresh values; supports rotation
  secretStoreRef:
    name: aws-secretsmanager
    kind: SecretStore
  target:
    name: db-creds              # managed K8s Secret, value never in Git
  data:
    - secretKey: password
      remoteRef:
        key: prod/db
        property: password
```

Both approaches keep the source of truth in the manager, support central rotation and auditing, and remove long-lived plaintext from your manifests.

## 3. Keep Secrets Out of Manifests and Git (Secure GitOps)

GitOps wants everything in a repo—so encrypt secrets *before* they are committed. Two established patterns:

#### Sealed Secrets (encrypt to a cluster-held key)

```bash
# Encrypt with the controller's public key; only the in-cluster controller
# can decrypt. The SealedSecret is safe to commit.
$ kubeseal --format yaml < secret.yaml > sealed-secret.yaml
$ git add sealed-secret.yaml     # ciphertext in Git, plaintext never leaves
```

#### SOPS (encrypt values with KMS/age)

```bash
# Encrypt only the values, leaving structure diff-able:
$ sops --encrypt --kms arn:aws:kms:...:key/abc secret.yaml > secret.enc.yaml
# A GitOps controller (or a decrypt step) resolves it at apply time.
```

Rule of thumb: never `git add` a plaintext credential. If a secret was ever committed, rotate it—removing the file does not remove it from history.

## 4. Restrict Secret Access With Least-Privilege RBAC

`get`/`list`/`watch` on secrets is high-privilege. Grant it to the fewest identities, in the narrowest scope.

```yaml
# A Role scoped to ONE named secret, read-only, in one namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: prod
  name: read-db-secret
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["db-creds"]   # not all secrets — just this one
    verbs: ["get"]                # no list/watch unless truly needed
```

Audit who can read secrets and treat cluster-wide `list secrets` as a red flag:

```bash
$ kubectl auth can-i list secrets --all-namespaces --as=system:serviceaccount:prod:app
# Enumerate bindings that touch secrets and review each one.
```

## 5. Disable Default ServiceAccount Token Automount

Most workloads never call the API server, so they should not carry a token an attacker can steal.

```yaml
# Default off at the ServiceAccount, opt in per-pod only where needed
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      serviceAccountName: app
      automountServiceAccountToken: false   # explicit; no token in the pod
```

Where API access *is* required, prefer short-lived, audience-bound projected tokens over the legacy long-lived variety.

## 6. Prefer File Mounts Over Environment Variables

Mounted secret files avoid the many leak channels of env vars (child processes, `/proc`, crash dumps, logs) and can carry tight file modes.

```yaml
volumes:
  - name: db
    secret:
      secretName: db-creds
      defaultMode: 0400            # read-only, owner only
containers:
  - name: app
    volumeMounts:
      - name: db
        mountPath: /etc/secrets/db
        readOnly: true
    # App reads /etc/secrets/db/password — not an env var
```

If a library truly needs an env var, populate it from a mounted file at startup rather than hardcoding the value in the pod spec.

## 7. Rotation and Lifecycle

- Rotate credentials on a schedule, and *immediately* after any suspected exposure—rotation, not deletion, is the remedy.
- Prefer short-lived, dynamically issued credentials (for example, database credentials minted on demand by a manager) so a captured copy expires quickly.
- Automate rotation through the external manager so it does not depend on someone remembering.

```yaml
# External Secrets refreshInterval + a manager that rotates the backend value
# means pods pick up new credentials without manual manifest edits.
refreshInterval: 1h
```

## 8. Scan Images, Repos, and CI for Secrets

Catch leaks before they ship, and continuously afterwards.

```bash
# Pre-commit and CI: block secrets entering Git
$ gitleaks detect --source . --redact
$ trufflehog git file://./ --only-verified

# Image scanning: catch keys baked into layers
$ trivy image --scanners secret myregistry/app:latest

# Build with secret mounts so nothing persists in a layer:
# docker build --secret id=npmtoken,src=token.txt ...
```

Wire these into pull requests and the build pipeline so a leaked secret fails the build instead of reaching a registry or the main branch.

## 9. Protect ConfigMaps and Logs

- Never place credentials in ConfigMaps—they have no confidentiality semantics. Move connection strings with embedded passwords into Secrets or a manager.
- Scrub secrets from application and build logs; disable debug logging of connection strings and headers in production.
- Ensure log aggregation does not turn a single leak into a widely readable one.

## 10. Monitoring and Detection

Watch for the signatures of secret harvesting and drift.

```
# Audit-log patterns worth alerting on:
- list/get on secrets at cluster or namespace scope by unexpected identities
- reads of many distinct secrets in a short window (enumeration)
- new RBAC bindings granting secrets verbs
- ServiceAccount tokens used from unexpected source IPs / user agents
- access to etcd endpoints or snapshot artifacts
```

Combine API audit logs with runtime detection so both "read the Secret via the API" and "read the token file in the pod" are visible.

## Defense-in-Depth Summary

| Failure | Insecure | Secure |
|---------|----------|--------|
| Storage | Unencrypted etcd; base64 assumed safe | Encryption-at-rest via KMS; snapshots protected |
| Source | Hardcoded in code/images/manifests | External manager via CSI driver / ESO |
| GitOps | Plaintext secrets committed | Sealed Secrets / SOPS ciphertext only |
| Access | Broad `get`/`list`; token automounted | Scoped RBAC; automount disabled |
| Delivery | Env vars, visible in /proc and logs | Read-only file mounts, tight modes |
| Lifecycle | Never rotated; long-lived | Scheduled rotation, short-lived creds |

## Key Takeaways

1. **Make storage confidential** — enable etcd encryption-at-rest and guard snapshots.
2. **Externalise secrets** — source them at runtime from Vault or a cloud manager via CSI/ESO.
3. **Never commit or bake secrets** — use Sealed Secrets/SOPS for GitOps; keep them out of images and ConfigMaps.
4. **Deliver narrowly** — least-privilege RBAC, disabled token automount, mounted files over env vars.
5. **Rotate, scan, and audit** — assume exposure is permanent and design for continuous rotation and detection.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure secret handling across manifests, delivery, and GitOps
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
