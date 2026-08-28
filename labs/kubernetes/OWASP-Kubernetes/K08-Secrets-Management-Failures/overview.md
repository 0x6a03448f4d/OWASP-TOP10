# K08: Secrets Management Failures - Overview

## Table of Contents
- [What is a Secrets Management Failure?](#what-is-a-secrets-management-failure)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Signals](#prevalence-and-signals)
- [Common Misunderstandings](#common-misunderstandings)

## What is a Secrets Management Failure?

**Secrets Management Failures** occur when sensitive material—database passwords, API keys, TLS private keys, cloud credentials, service-account tokens, signing keys—is created, stored, distributed, or consumed inside a Kubernetes cluster in a way that lets an unintended party read it. It is rarely a single dramatic bug. It is the sum of small, comfortable habits: base64 mistaken for encryption, a password pasted into a manifest, a token committed to Git, a secret exported as an environment variable "because it was easy."

Kubernetes gives you a first-class `Secret` object, and that object is genuinely useful—but it is frequently misunderstood. A `Secret` is **base64-encoded, not encrypted**. By default it is stored in **etcd**, the cluster's key-value backing store, and unless you have explicitly turned on encryption-at-rest, it sits there as recoverable plaintext. Everything that can read etcd, read the Secret object through the API, read the container's environment, or read the manifest that created it, can read the secret.

### Core Concept

```
Secure secret handling:
  Encoding      -> understood as encoding; real encryption is separate
  etcd          -> encryption-at-rest enabled via a KMS provider
  Source        -> secrets pulled at runtime from a manager (Vault/CSI/ESO)
  Manifests     -> no plaintext secrets; sealed/encrypted for GitOps
  Delivery      -> mounted as files with tight file modes, not env vars
  RBAC          -> get/list on secrets granted to almost no one
  ServiceAccount-> token automount disabled unless the pod needs the API
  Lifecycle     -> rotated on a schedule and after any suspected exposure

Secrets management failure:
  Encoding      -> base64 treated as if it were encryption
  etcd          -> unencrypted; a snapshot or node disk leaks everything
  Source        -> long-lived credentials hardcoded in images and code
  Manifests     -> passwords in YAML and ConfigMaps, committed to Git
  Delivery      -> secrets in env vars, visible in /proc, logs, crash dumps
  RBAC          -> broad get/list/watch on secrets across namespaces
  ServiceAccount-> default token automounted into every pod
  Lifecycle     -> never rotated; the same key has shipped for years
```

### Why It's Critical for Kubernetes

Kubernetes concentrates several conditions that make secrets failures especially damaging:

- The cluster is a **credential hub**. Workloads hold database passwords, cloud IAM credentials, registry pull secrets, and tokens for other services—so one leaked secret often unlocks systems far outside the cluster.
- Secrets flow through **many hands and formats**: a value starts in a manifest, is stored in etcd, is projected into a pod, is read by application code, and is echoed into logs—each hop is a place it can leak.
- Kubernetes is **declarative and GitOps-driven**, so the natural place to put configuration is a YAML file in a repository—which is exactly the wrong place for a plaintext secret.
- Every pod ships with a **ServiceAccount token** by default, giving a compromised container an identity it can use to ask the API server for more secrets.

## Why Does This Matter?

### Business Impact

- **Blast radius beyond the cluster**: A leaked cloud credential or database password compromises production data and infrastructure the cluster merely talks to, not just the cluster itself.
- **Persistent, silent access**: Secrets that are never rotated give an attacker who copied them months—or years—of valid access, long after the initial intrusion is forgotten.
- **Supply-chain exposure**: A registry pull secret or signing key in an image or Git history lets an attacker pull private code or publish trusted-looking artifacts.
- **Regulatory and contractual fallout**: Credentials that guard personal or cardholder data pull GDPR, HIPAA, and PCI-DSS obligations, fines, and breach-notification duties into scope.
- **Irreversible disclosure**: Once a secret is committed to Git or baked into a published image layer, it must be treated as compromised forever; rotation, not deletion, is the only real remedy.

### Technical Impact

- **Credential theft from etcd**: An unencrypted etcd datastore, or a backup/snapshot of it, hands over every Secret in the cluster at once.
- **Environment-variable leakage**: Secrets injected as env vars appear in `/proc/<pid>/environ`, child processes, crash dumps, error trackers, and verbose logs.
- **Over-broad API access**: An identity with `get`/`list` on secrets can read them cluster-wide, turning a minor RBAC mistake into mass credential disclosure.
- **Token harvesting**: The automounted ServiceAccount token in a compromised pod is a ready-made credential for querying or pivoting through the API server.
- **Image and repo mining**: Secrets in Dockerfiles, image layers, or Git history are recovered with trivial tooling and never expire on their own.

## Technical Context

### Common Secrets Failure Scenarios in Kubernetes

#### 1. "base64 is encryption" (it is not)

```yaml
# A Secret manifest — data values are base64, fully reversible
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
type: Opaque
data:
  password: U3VwZXJTZWNyZXQxMjM=   # echo -n 'SuperSecret123' | base64
```

```bash
# Anyone who can read the object simply decodes it:
$ kubectl get secret db-creds -o jsonpath='{.data.password}' | base64 -d
SuperSecret123
```

**Risk**: base64 provides zero confidentiality. It exists so binary values survive YAML, not to hide anything.

#### 2. Unencrypted etcd

```bash
# Without encryption-at-rest, the raw value is in etcd as plaintext:
$ ETCDCTL_API=3 etcdctl get /registry/secrets/default/db-creds
...
SuperSecret123     # readable straight out of the datastore / a snapshot
```

**Risk**: etcd node disks, backups, and snapshots become credential dumps. Encryption-at-rest with a KMS provider is what makes the stored value opaque.

#### 3. Secrets as environment variables

```yaml
env:
  - name: DB_PASSWORD
    value: "SuperSecret123"        # plaintext in the manifest AND the pod spec
```

```bash
# Once running, the value is broadly visible inside the pod:
$ cat /proc/1/environ | tr '\0' '\n' | grep DB_PASSWORD
$ kubectl exec pod -- env | grep DB_PASSWORD
```

**Risk**: env vars leak into child processes, crash dumps, APM/error trackers, and logs. They are also visible in the pod spec to anyone who can read pods.

#### 4. Secrets in images, manifests, and Git

```dockerfile
# Dockerfile — baked into an image layer forever
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

```yaml
# ConfigMap — a "config" object holding a credential in plaintext
kind: ConfigMap
data:
  DATABASE_URL: "postgres://app:SuperSecret123@db:5432/prod"

# ...then git commit && git push  — now in history on every clone
```

**Risk**: image layers and Git history are permanent and widely distributed. A later "delete" does not remove the value from prior layers or commits.

#### 5. Over-permissioned RBAC and automounted tokens

```yaml
# A Role that lets a workload read every Secret in its namespace
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]

# And the default: every pod gets the ServiceAccount token mounted
#   /var/run/secrets/kubernetes.io/serviceaccount/token
```

**Risk**: a single compromised workload can enumerate secrets, and its automounted token is a credential for the API server it may never have needed.

### Layers Where Secrets Leak

| Layer | Typical Failure | Consequence |
|-------|-----------------|-------------|
| etcd datastore | No encryption-at-rest; unprotected snapshots | Whole-cluster secret disclosure |
| Secret object / API | Broad `get`/`list` RBAC; base64 assumed safe | Cluster-wide credential reads |
| Pod runtime | Secrets as env vars; verbose logging | Leakage via /proc, logs, crash dumps |
| Container image | Keys baked into layers / Dockerfile | Permanent, distributable exposure |
| Source control (GitOps) | Plaintext secrets in manifests/ConfigMaps | Exposure to everyone with repo/history access |
| CI/CD | Secrets echoed into build logs | Disclosure to anyone who can read pipelines |
| ServiceAccount | Default token automounted everywhere | Ready-made identity for a compromised pod |

## Real-World Impact

The incidents below are described as **classes of failure** that have recurred across many organisations. They are illustrative patterns, not specific attributed breaches, and deliberately avoid invented CVE numbers or precise statistics.

### Case Class 1: Credentials Leaked Through Source Control

**Failure**:
- Kubernetes manifests, Helm values, or ConfigMaps containing plaintext credentials are committed to a repository—often a public one, or a private one with broad internal read access.
- Because history is permanent, even a value later "removed" in a follow-up commit remains recoverable in earlier commits.

**Impact**:
- Automated scanners continuously crawl public forges for exactly these patterns; exposed cloud keys are frequently used within minutes for resource abuse or data access.

**Root Cause**: treating declarative config repositories as a safe home for secrets, with no pre-commit scanning and no separation between configuration and credentials.

### Case Class 2: Secrets Recovered From Container Images

**Failure**:
- Build-time secrets are passed with `ENV` or `COPY` and persist in image layers, or a `.git`/`.env` directory is copied into the image.
- The image is pushed to a registry that is public, or readable by a wider audience than intended.

**Impact**:
- Anyone who can pull the image extracts the layers offline and recovers the embedded credentials; the exposure lasts as long as the image is retained anywhere.

**Root Cause**: build pipelines that bake secrets into images instead of injecting them at runtime, with no image scanning to catch embedded keys.

### Case Class 3: Whole-Cluster Exposure via etcd

**Failure**:
- etcd is deployed without encryption-at-rest, and its backups/snapshots are stored without strong access control.
- An attacker who reaches an etcd node, an old snapshot, or a backup bucket obtains the plaintext of every Secret at once.

**Impact**:
- A single artifact yields the entire cluster's credentials—database passwords, tokens, TLS keys—turning one exposure into total compromise.

**Root Cause**: relying on the default that Secrets are "in the cluster" as if that meant "protected," without enabling encryption-at-rest or securing snapshots.

## Prevalence and Signals

Secrets Management Failures are consistently among the most common findings in Kubernetes security assessments, precisely because the insecure path is also the easiest path: base64, an env var, a value in YAML, a commit to Git.

Rather than cite precise figures (which vary by source and year), the defensible picture is:

- Secret sprawl is **the default outcome** unless a team deliberately adopts an external manager, encryption-at-rest, and scanning—the platform makes the easy choice the leaky one.
- The most commonly observed sub-issues are **plaintext secrets in Git, secrets as environment variables, unencrypted etcd, over-broad RBAC on secrets, and never-rotated long-lived credentials**.
- The impact is rated **severe**: a single recovered credential frequently reaches systems well beyond the cluster boundary.

> Note: exact percentages and incident counts differ between reports. Treat any single figure as illustrative; the durable takeaway is that secrets leak by default, the leaks are permanent, and rotation—not deletion—is the remedy.

## Common Misunderstandings

### Myth 1: "Kubernetes Secrets are encrypted"

**Reality**: A `Secret`'s `data` is base64-*encoded*, which is trivially reversible. Confidentiality at rest comes only from enabling etcd encryption-at-rest (ideally with a KMS provider); confidentiality in transit comes from TLS to the API server.

### Myth 2: "It's fine because the repo is private"

**Reality**: Private repos are read by many people and many automated systems, are cloned to laptops and CI runners, and can be made public or leaked. Git history is permanent, so a private-repo secret must still be rotated once committed.

### Myth 3: "Environment variables are a safe way to pass secrets"

**Reality**: Env vars are inherited by child processes, captured by crash reporters and APM agents, printed by debug logging, and readable via `/proc` and the pod spec. Mounted files with tight permissions are the safer default.

### Myth 4: "A ConfigMap is just configuration, so a URL with a password is fine"

**Reality**: ConfigMaps have no confidentiality semantics at all—no separate RBAC treatment, no encryption story. A connection string with an embedded password in a ConfigMap is a plaintext secret in the clear.

### Myth 5: "We deleted the secret, so we're safe"

**Reality**: Deleting a Secret object, a commit, or an image tag does not erase the value from etcd snapshots, prior Git commits, or earlier image layers. The only reliable response to exposure is to *rotate* the credential.

### Myth 6: "Every pod needs its ServiceAccount token"

**Reality**: Most workloads never call the Kubernetes API. Automounting the token everywhere hands a free API credential to any compromised container. Disable automount by default and opt in only where it is genuinely required.

## How Secrets Management Failures Differ from Related Issues

| Aspect | Secrets Management (K08) | Overly Permissive RBAC (K03) | Supply-Chain (K02) |
|--------|-------------------------|------------------------------|--------------------|
| **Root cause** | Sensitive data mishandled/exposed | Identities granted too much access | Untrusted/compromised artifacts |
| **Where it lives** | etcd, manifests, images, Git, pods | Roles/Bindings, aggregation rules | Images, dependencies, build pipeline |
| **Typical fix** | External manager, encryption, rotation | Least-privilege roles, scoping | Signing, provenance, scanning |
| **Detection** | Secret scanning, etcd/RBAC audit | RBAC review, `can-i` checks | SBOM, image/attestation verification |

Note the overlap: broad `get`/`list` on secrets is *both* an RBAC problem (K03) and a secrets-management problem (K08). The categories reinforce each other—least-privilege RBAC is part of protecting secrets.

## Key Takeaways

1. **Encoding is not encryption**—base64 hides nothing; encryption-at-rest and an external manager provide the real confidentiality.
2. **Delivery matters**—prefer mounted files over environment variables to limit where a secret leaks.
3. **Keep secrets out of permanent stores**—never in images, manifests, ConfigMaps, or Git; use sealed/encrypted forms for GitOps.
4. **Least privilege on secrets**—`get`/`list` on secrets is powerful; grant it narrowly and disable default token automount.
5. **Assume exposure is permanent**—rotate on a schedule and immediately after any suspected leak; deletion alone never suffices.

## How to Identify if You're Vulnerable

- [ ] Is etcd encryption-at-rest enabled, ideally backed by a KMS provider?
- [ ] Are etcd snapshots and backups access-controlled and themselves encrypted?
- [ ] Do any manifests, Helm values, or ConfigMaps contain plaintext credentials?
- [ ] Are any secrets committed anywhere in Git history (not just the current tree)?
- [ ] Are secrets baked into container images, Dockerfiles, or copied `.env`/`.git` dirs?
- [ ] Are secrets passed as environment variables where a mounted file would work?
- [ ] Which identities have `get`/`list`/`watch` on secrets, and do they all need it?
- [ ] Is `automountServiceAccountToken` disabled by default and enabled only where needed?
- [ ] Are secrets sourced from an external manager (Vault, cloud secret manager) via CSI/ESO?
- [ ] Are credentials rotated on a schedule, and is secret access audited?

If you answered "no" or "not sure" to several of these, you likely have exploitable secrets exposure today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers find and harvest secrets in a cluster
- **[Prevention](prevention.md)**: Build encryption-at-rest, external managers, and least-privilege secret access
- **[Examples](examples.md)**: Insecure vs. secure secret handling across manifests, delivery, and GitOps
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
