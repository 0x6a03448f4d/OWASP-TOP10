# K08: Secrets Management Failures - Code Examples

Each pair below shows an **insecure** way to handle a secret and the **secure** equivalent. The examples focus on the failures that dominate real findings: secrets in env vars, manifests, images, and Git, versus encryption-at-rest, external managers, file mounts, scoped RBAC, and sealed manifests.

## 1. Secret Delivery: Env Var vs. Mounted File

### Insecure
```yaml
# Plaintext in the manifest AND the pod spec; leaks via /proc, logs, crash dumps
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: myregistry/web:1.4.2
          env:
            - name: DB_PASSWORD
              value: "SuperSecret123"      # hardcoded, visible to anyone reading the pod
```

### Secure
```yaml
# Value lives in a Secret; delivered as a read-only file with tight mode
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: web
          image: myregistry/web@sha256:<digest>
          volumeMounts:
            - name: db
              mountPath: /etc/secrets/db
              readOnly: true
      volumes:
        - name: db
          secret:
            secretName: db-creds
            defaultMode: 0400              # read-only, owner only
# App reads /etc/secrets/db/password — never an env var, never in the spec
```

## 2. Reference a Secret, Don't Inline It

### Insecure
```yaml
# A ConfigMap has NO confidentiality — this is a plaintext secret in the clear
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  DATABASE_URL: "postgres://app:SuperSecret123@db:5432/prod"   # credential in a ConfigMap
```

### Secure
```yaml
# Non-secret config in the ConfigMap; the credential stays in a Secret
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  DATABASE_HOST: "db"
  DATABASE_NAME: "prod"
---
# If an env var is unavoidable, source it from a Secret key (still prefer files):
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-creds
        key: password        # value not written into the pod spec verbatim
```

## 3. etcd Storage: Base64 vs. Encryption-at-Rest

### Insecure
```bash
# Default cluster: Secret stored in etcd as base64 (reversible) plaintext
$ ETCDCTL_API=3 etcdctl get /registry/secrets/prod/db-creds
...
SuperSecret123          # recoverable from an etcd node or any snapshot
```

### Secure
```yaml
# EncryptionConfiguration for the API server (--encryption-provider-config)
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - kms:                          # KEK held in an external KMS
          apiVersion: v2
          name: cluster-kms
          endpoint: unix:///var/run/kmsplugin/socket.sock
      - identity: {}                  # read-only fallback, never first
# Then re-encrypt existing secrets:
#   kubectl get secrets -A -o json | kubectl replace -f -
```

## 4. Container Images: Baked-In vs. Runtime Injection

### Insecure
```dockerfile
# Dockerfile — the key persists in an image layer forever
FROM node:20-slim
ENV NPM_TOKEN=npm_AbCdEf0123456789        # leaks in `docker history` and layers
COPY . .                                   # may copy .env / .git too
RUN npm ci
```

### Secure
```dockerfile
# BuildKit secret mount — nothing is written into the final image
# syntax=docker/dockerfile:1.4
FROM node:20-slim
COPY package*.json ./
RUN --mount=type=secret,id=npmtoken \
    NPM_TOKEN=$(cat /run/secrets/npmtoken) npm ci
COPY . .
# Build:  docker build --secret id=npmtoken,src=token.txt .
# Scan:   trivy image --scanners secret myregistry/app:latest
```

## 5. External Secret Manager (Secrets Store CSI Driver)

### Insecure
```yaml
# A long-lived cloud key committed as a Secret and never rotated
apiVersion: v1
kind: Secret
metadata:
  name: aws-creds
type: Opaque
data:
  AWS_SECRET_ACCESS_KEY: d0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ==
```

### Secure
```yaml
# Vault-backed value mounted at runtime; no static Secret to leak
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
volumes:
  - name: secrets
    csi:
      driver: secrets-store.csi.x-k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "db-spc"
```

## 6. External Secrets Operator (sync from a cloud manager)

### Insecure
```bash
# Secret manually created and pasted around; drifts, never rotates
$ kubectl create secret generic db-creds \
    --from-literal=password='SuperSecret123'   # source of truth = someone's shell history
```

### Secure
```yaml
# Source of truth is the cloud manager; ESO syncs and refreshes it
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-creds
spec:
  refreshInterval: 1h                # picks up rotated values automatically
  secretStoreRef:
    name: aws-secretsmanager
    kind: SecretStore
  target:
    name: db-creds                   # managed Secret; value never in Git
  data:
    - secretKey: password
      remoteRef:
        key: prod/db
        property: password
```

## 7. GitOps: Plaintext Manifest vs. Sealed Secret

### Insecure
```yaml
# Committed to the GitOps repo — plaintext in history on every clone
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
type: Opaque
stringData:
  password: "SuperSecret123"         # git add + push = permanent exposure
```

### Secure
```yaml
# Encrypt before commit; only the in-cluster controller can decrypt
# $ kubeseal --format yaml < secret.yaml > sealed-secret.yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-creds
  namespace: prod
spec:
  encryptedData:
    password: AgBy3i4OJSWK+PiTySYZZA9rO43cGDEQ...   # ciphertext, safe in Git
# Alternative: SOPS-encrypted values resolved by the GitOps controller at apply time
```

## 8. RBAC: Broad Reads vs. Scoped, and Token Automount

### Insecure
```yaml
# Any bound identity can read every secret in the namespace...
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
# ...and every pod carries a token to use it:
#   automountServiceAccountToken defaults to true
```

### Secure
```yaml
# Read-only, one named secret, no list/watch
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: prod
  name: read-db-secret
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["db-creds"]
    verbs: ["get"]
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app
automountServiceAccountToken: false    # no free API token in the pod
```

## What Changed, and Why

| Failure | Insecure | Secure |
|---------|----------|--------|
| Delivery | Secret as env var, hardcoded in the spec | Read-only file mount, `defaultMode: 0400` |
| Placement | Credential in a ConfigMap | Credential in a Secret / external manager |
| Storage | Unencrypted etcd (base64) | Encryption-at-rest via KMS provider |
| Images | Key baked into a layer | BuildKit secret mount + image scanning |
| Source | Static, hand-created, never rotated | Vault/cloud manager via CSI driver / ESO |
| GitOps | Plaintext Secret committed | Sealed Secrets / SOPS ciphertext |
| Access | Broad `get`/`list`; token automounted | Scoped `get`; automount disabled |

## Next Steps

- **[Prevention](prevention.md)**: The full layered strategy for protecting secrets
- **[Attack Vectors](attack-vectors.md)**: How these failures are found and exploited
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
