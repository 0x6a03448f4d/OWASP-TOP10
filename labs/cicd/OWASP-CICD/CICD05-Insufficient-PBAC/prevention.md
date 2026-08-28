# CICD-SEC-5: Insufficient PBAC - Prevention

## Prevention Strategy Overview

Preventing insufficient PBAC is about **making least privilege the default state of every runner and job**:

1. Scope access to the job—secrets, cloud identity, and network reach match exactly what one job needs.
2. Make runners ephemeral—a fresh, single-use environment per job, destroyed after.
3. Isolate by trust level—public and private, build and deploy, never share a runner.
4. Replace standing credentials with short-lived, per-job identities (OIDC).
5. Segment the network and verify shared state so poisoning cannot cross runs.

### Core Principles

- **Least privilege per job**: the runner should carry the minimum access the current job requires—never the union of everything any job might need.
- **Ephemeral by default**: no state should survive a job. A new job gets a clean machine, not a reused one.
- **Isolation by trust**: untrusted input (fork PRs, public repos) must never execute where trusted secrets live.
- **Short-lived over standing**: prefer per-job tokens minted at run time to long-lived roles and keys attached permanently to runners.

## 1. Scope Secrets to Specific Jobs and Environments

Stop injecting every secret into every job. Bind secrets to the job, environment, or deployment step that actually uses them.

```yaml
# GitHub Actions: environment-scoped secrets + protection rules.
# The deploy secret is only available in the 'production' environment,
# which requires approval and is restricted to protected branches.
jobs:
  build:
    runs-on: ubuntu-latest          # no secrets injected here at all
    steps:
      - run: make build

  deploy:
    needs: build
    environment: production          # PROD_DEPLOY_KEY exists ONLY in this scope
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
        env:
          PROD_DEPLOY_KEY: ${{ secrets.PROD_DEPLOY_KEY }}
```

Rules of thumb: never expose deploy/signing secrets to build or test jobs; use environment protection rules (required reviewers, branch restrictions) so sensitive secrets are gated; and never pass secrets to workflows triggered by untrusted forks.

## 2. Use Ephemeral, Single-Use Runners

A fresh VM or container per job removes all credential and artifact carry-over. Nothing a job writes can be read by the next job because there is no "next job" on that machine.

```toml
# GitLab: ephemeral runners via the Docker/Kubernetes executor.
# Each job runs in a new container that is discarded when the job ends.
[[runners]]
  name = "ephemeral-docker"
  executor = "docker"
  [runners.docker]
    image = "alpine:3.20"
    privileged = false          # no host access
    # A new container per job; no reuse of the previous job's filesystem.

# For autoscaling, provision a NEW VM per job and destroy it after:
#   - GitHub: ephemeral self-hosted runners (--ephemeral) or ARC with
#     a fresh pod per job.
#   - GitLab: docker-autoscaler / kubernetes executor, one job per instance.
```

If you must use self-hosted runners, register them with the `--ephemeral` flag (or an equivalent one-job-per-runner model) so each accepts exactly one job and is then torn down.

## 3. Isolate Runners by Trust Level

Untrusted code must never run where trusted secrets live. Separate the pools.

```yaml
# Never run this on a self-hosted runner that also serves private, credentialed jobs:
on:
  pull_request_target:        # runs in the BASE repo context with its secrets
# pull_request_target + checking out and running PR code = untrusted code with secrets.

# Safer pattern for fork PRs:
on: pull_request             # runs WITHOUT access to repository secrets
jobs:
  test:
    runs-on: ubuntu-latest    # GitHub-hosted, disposable, no private secrets
    permissions:
      contents: read          # minimal token
```

Keep public/fork-triggered pipelines on disposable, cloud-hosted runners with no private secrets. Reserve self-hosted, credentialed runners for trusted branches only, and require approval before a fork's workflow runs.

## 4. Replace Standing Cloud Roles with Short-Lived OIDC

Do not attach a broad, permanent role to a runner or store long-lived cloud keys as secrets. Mint a short-lived, narrowly scoped credential per job via OIDC.

```yaml
# GitHub Actions -> AWS via OIDC: no static keys, token scoped and short-lived.
permissions:
  id-token: write            # allow the job to request an OIDC token
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/deploy-app-only
          aws-region: us-east-1
          # The trust policy on this role restricts which repo/branch/environment
          # may assume it, and it grants ONLY the actions this deploy needs.
```

```json
// The IAM role's trust policy pins the exact workflow identity:
"Condition": {
  "StringEquals": {
    "token.actions.githubusercontent.com:sub":
      "repo:acme/app:environment:production"
  }
}
// And its permission policy is scoped -- never "Action":"*","Resource":"*".
```

## 5. Segment Runner Network Access

A build runner should not be able to reach production databases, the cluster control plane, or the cloud metadata service unless the job genuinely requires it.

```bash
# Place build runners in an isolated subnet with egress restricted to what
# builds need (package registries, artifact store) -- not prod.

# Block the cloud metadata endpoint from build containers when they don't use it:
iptables -A OUTPUT -d 169.254.169.254 -j REJECT

# Enforce IMDSv2 and hop limit so containers can't trivially reach instance creds:
#   aws ec2 modify-instance-metadata-options \
#     --http-tokens required --http-put-response-hop-limit 1

# Network policy: build namespace cannot talk to prod namespaces / the API server.
```

## 6. Separate Build and Deploy Runners

Split the pipeline so the privileged deploy step runs on a different, more-restricted runner than the build/test steps that execute untrusted code and dependencies.

```
build:   runs-on: build-pool     # untrusted deps/tests, NO deploy creds, no prod reach
         # produces a signed artifact

deploy:  runs-on: deploy-pool    # trusted, minimal, short-lived deploy identity only
         needs: build
         # verifies the artifact signature BEFORE deploying (see step 7)
```

This ensures the environment that holds deploy credentials never runs arbitrary build/test code.

## 7. Verify and Isolate Caches and Artifacts

Treat shared caches and artifacts as untrusted input unless their integrity is proven. Do not let low-trust jobs poison what high-trust jobs consume.

```yaml
# Scope caches by trust and content, and verify artifacts before use.
- uses: actions/cache@v4
  with:
    key: deps-${{ github.ref_name }}-${{ hashFiles('**/lockfile') }}
    # Separate cache namespaces per branch/trust; never share a key across
    # trust boundaries.

# Before a deploy job uses a build artifact, verify its signature/digest:
- run: |
    cosign verify-blob --key cosign.pub --signature app.sig ./dist/app
    sha256sum -c app.sha256          # fail closed if it doesn't match
```

Prefer content-addressed, integrity-checked artifacts; sign build outputs and verify signatures in the deploy stage; and clear or namespace caches so a poisoned entry cannot cross into a trusted pipeline.

## 8. Minimize the Pipeline Token's Permissions

The automatic token the platform injects is itself standing access. Default it to read-only and grant more only where needed.

```yaml
# GitHub: set a restrictive default for the whole workflow, widen per job.
permissions:
  contents: read              # default: least privilege for GITHUB_TOKEN

jobs:
  release:
    permissions:
      contents: write         # only this job can push tags/releases
      packages: write         # only this job can publish
    runs-on: ubuntu-latest
```

Set the organisation/repo default token permission to read-only, and require workflows to opt into any write scope explicitly and per job.

## 9. Clear Workspaces and State Between Runs

Even with ephemeral intent, ensure no residue survives—especially on self-hosted or autoscaled runners.

```yaml
# Explicitly wipe sensitive state at job end (defense in depth):
- run: |
    rm -rf ~/.aws ~/.docker ~/.kube ~/.npmrc
    rm -rf "$GITHUB_WORKSPACE"/* 2>/dev/null || true
  if: always()

# Better: rely on ephemeral runners so this is unnecessary -- the machine
# itself is destroyed after the job.
```

## 10. Monitor and Detect Excessive Pipeline Access

Watch for the signatures of PBAC abuse—a job doing far more than its purpose requires.

```python
# Alert on pipeline behaviour that indicates over-privilege abuse:
SUSPICIOUS = (
  'metadata endpoint access from a build job (169.254.169.254)',
  'a non-deploy job reading many secrets / calling list-secrets',
  'a build runner connecting to prod DB or the cluster API',
  'cloud role assumed by an unexpected repo/branch/environment',
  'writes to shared caches from fork/PR-triggered jobs',
)
# Feed CI audit logs + cloud CloudTrail/Activity logs into detections;
# assert that each pipeline's cloud actions match its declared purpose.
```

Also alert on new self-hosted runner registrations, jobs from forks reaching protected environments, and any use of long-lived static keys where OIDC was expected.

## Platform-Specific Hardening

### GitHub Actions

- Set default `GITHUB_TOKEN` permissions to read-only; opt into writes per job.
- Use environment protection rules to gate deploy secrets; never expose secrets to `pull_request` from forks.
- Prefer OIDC over stored cloud keys; pin the role trust policy to `repo:...:environment:...`.
- Use ephemeral self-hosted runners (`--ephemeral`) or Actions Runner Controller with a fresh pod per job; never a shared standing runner across public and private repos.

### GitLab CI/CD

- Use the Docker or Kubernetes executor for a fresh container per job; avoid the shell executor on shared hosts.
- Scope CI/CD variables to protected branches/environments and mark them *protected* and *masked*.
- Use ID tokens (OIDC) for cloud auth instead of storing long-lived keys as variables.
- Tag runners and restrict which projects may use privileged/credentialed runners.

### Jenkins

- Run builds on ephemeral agents (cloud/Kubernetes plugin), never on the controller.
- Scope credentials with the Credentials Binding plugin and folder-level credentials—bind only to the job that needs them.
- Restrict which agents a job can run on; isolate untrusted (multibranch/fork) builds onto disposable agents with no production credentials.
- Disable inbound agent reuse for untrusted work; provision a new agent per build.

## Key Takeaways

1. **Scope to the job** — secrets, cloud roles, and network reach should match one job's need, never the whole organisation.
2. **Make runners ephemeral** — a fresh, single-use machine per job removes credential and artifact carry-over entirely.
3. **Isolate by trust** — untrusted forks and public repos must never share a runner with credentialed, private pipelines.
4. **Short-lived over standing** — per-job OIDC tokens beat permanent broad roles and stored static keys.
5. **Verify shared state** — segment networks, split build from deploy, and integrity-check caches and artifacts so poisoning cannot cross runs.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure runner and secret scoping across platforms
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
