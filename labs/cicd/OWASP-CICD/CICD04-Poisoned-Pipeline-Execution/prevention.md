# CICD-SEC-4: Poisoned Pipeline Execution - Prevention

## Prevention Strategy Overview

Every PPE defence reduces to one rule: **never let untrusted code run with secrets, privileged tokens, or privileged infrastructure in scope**. Everything below is a concrete way to enforce that rule at a different layer.

1. Separate untrusted code from secrets by choosing the right trigger.
2. Never check out and run untrusted PR code in a privileged context.
3. Require human approval before running workflows on outsider contributions.
4. Pin every third-party action to an immutable commit SHA.
5. Grant the pipeline token the least privilege it needs, explicitly.
6. Isolate and make runners ephemeral.
7. Never interpolate untrusted event data into a shell.
8. Review pipeline-definition and build-script changes as security-critical.
9. Separate build credentials from deploy credentials.

### Core Principles

- **Trust boundary at the fork line**: code from someone who cannot merge is untrusted. Its CI must have no secrets.
- **Definition is code**: workflow files, scripts, hooks, and test/lint configs are all executable and must all be reviewed.
- **Least privilege everywhere**: tokens, runners, and credentials should hold only what a given job genuinely needs.
- **Immutable dependencies**: pin what you execute so it cannot silently change under you.

## 1. Choose the Right Trigger: `pull_request`, not `pull_request_target`

For fork contributions, use the trigger that runs the PR's code **without secrets**. On GitHub Actions that is `pull_request`: fork PRs run with a read-only token and no repository secrets.

```yaml
# SECURE: fork PRs run untrusted code, but with NO secrets and a read-only token
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4          # PR head, but nothing sensitive is present
      - run: npm ci && npm test
```

Reserve `pull_request_target` for tasks that genuinely need the base context (labelling, commenting) and **do not check out or run PR code** under it.

## 2. Never Check Out Untrusted PR Code in a Privileged Context

If you must combine trusted automation with fork-PR data, split it into two workflows: one runs untrusted code with no secrets; a separate, trusted workflow consumes the *result* after review.

```yaml
# SECURE pattern for pull_request_target: do privileged work only on trusted,
# non-code data, and never check out the PR head into this job.
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write        # only what labelling needs
    steps:
      - run: gh pr edit "$PR" --add-label needs-review
        env:
          PR: ${{ github.event.pull_request.number }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      # NOTE: no actions/checkout of the PR head, no build/test of PR code here
```

> If a job both needs secrets and needs to run PR code, you have designed a 3PE. Redesign so those two needs live in different jobs with different trust levels.

## 3. Require Approval to Run Workflows on Fork PRs

Configure the repository so that workflows on pull requests from first-time or outside contributors **require a maintainer to approve the run**. This puts a human between an outsider's push and any execution.

- GitHub: set fork-PR workflow approval to "Require approval for all outside collaborators" (or all fork PRs).
- GitLab: disable running pipelines for fork MRs against protected branches automatically; require a member to trigger.
- Jenkins: for multibranch/GitHub-branch-source, restrict which contributors' branches build without approval and scope credentials so PR builds cannot bind deploy secrets.

## 4. Pin Third-Party Actions to a Full Commit SHA

Mutable references (`@main`, `@v3`) can be repointed to new code. A full 40-character commit SHA is immutable.

```yaml
# INSECURE
- uses: some-org/build-action@v3        # tag can move
# SECURE
- uses: some-org/build-action@3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b  # pinned SHA
  # optional comment for humans: # v3.1.0
```

Automate this with a pinning/allow-list tool and keep pins current with a dependency-update bot so you still receive security fixes. Prefer a small allow-list of vetted actions over pulling arbitrary third-party actions.

## 5. Least-Privilege Pipeline Token

Set `permissions:` explicitly—default to read-only and grant write only to the specific scopes a job needs. This caps what poisoned code can do even if it runs.

```yaml
# SECURE: repository-wide default of read-only
permissions:
  contents: read

jobs:
  publish:
    permissions:
      contents: read
      packages: write         # only this job, only this scope
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./publish.sh
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

In GitLab, scope CI/CD variables to protected branches/environments and mark them *protected* and *masked*. In Jenkins, bind credentials only inside the narrow `withCredentials` block that needs them.

## 6. Isolate and Use Ephemeral Runners

- Prefer **ephemeral** runners that are destroyed after each job—no persistence for an attacker who lands there.
- Do not expose **self-hosted** runners to fork PRs. If self-hosted is required, dedicate a hardened, network-isolated pool and gate it behind approval.
- Give runners no standing access to production networks; use short-lived, job-scoped credentials (e.g. OIDC federation) instead of long-lived keys on the host.

## 7. Never Interpolate Untrusted Event Data into a Shell

Do not inline `${{ github.event.* }}` into a `run:` block. Pass it through an environment variable and quote it, so the shell treats it as data, not code.

```yaml
# INSECURE — expression expanded into the command before the shell runs
- run: echo "Title: ${{ github.event.pull_request.title }}"

# SECURE — value arrives as an env var and is quoted
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Title: $PR_TITLE"
```

The same applies to branch names, commit messages, issue bodies, and any other attacker-controllable field.

## 8. Review Pipeline-Definition and Build-Script Changes

Treat changes to what the pipeline executes as security-critical, requiring dedicated review.

```
# CODEOWNERS — require security/platform review for pipeline & build files
/.github/workflows/   @org/platform-security
/.gitlab-ci.yml       @org/platform-security
/Jenkinsfile          @org/platform-security
/Makefile             @org/platform-security
/scripts/             @org/platform-security
```

Combine with protected branches, required reviews, and static analysis of workflow files (dangerous triggers, unpinned actions, expression injection) in CI. Remember that I-PPE hides in `Makefile`, `package.json` scripts, and test/lint configs—include them in the review scope.

## 9. Separate Build Credentials from Deploy Credentials

A build-time compromise should not automatically reach production. Keep the credentials that build/test artifacts distinct from those that deploy them, and put a gate (approval, environment protection) between the two stages.

```yaml
# SECURE: deploy runs in a protected environment with its own reviewers,
# on a separate trusted trigger — not as part of untrusted PR builds.
jobs:
  deploy:
    if: github.ref == 'refs/heads/main'    # only trusted, merged code
    environment: production                 # required reviewers / protection rules
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write                       # OIDC: short-lived cloud creds, no static key
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh
```

## 10. Monitoring and Detection

Watch for the signatures of PPE attempts and pipeline tampering.

```
# Alert on high-risk pipeline patterns discovered in code review / scanning:
#  - pull_request_target combined with checkout of head.sha
#  - actions referenced by @main / @vN instead of a SHA
#  - ${{ github.event.* }} inside a run: block
#  - jobs on [self-hosted] triggered by fork PRs

# Alert at runtime on:
#  - outbound network connections from build steps to unexpected hosts
#  - reads of the cloud metadata endpoint (169.254.169.254) during builds
#  - unexpected use of GITHUB_TOKEN write scopes (pushes, package publishes)
#  - changes to workflow/build files landing without required review
```

## Platform Quick-Reference

| Control | GitHub Actions | GitLab CI | Jenkins |
|---------|----------------|-----------|---------|
| Untrusted fork code, no secrets | `pull_request` trigger | Fork MR pipelines without protected variables | PR builds with no bound deploy creds |
| Approval before run | Require approval for fork-PR workflows | Require member to run MR pipeline | Restrict branch-source build permissions |
| Immutable dependencies | Pin actions to commit SHA | Pin `include`/images by digest | Pin shared-library versions |
| Least-privilege token | `permissions:` block | Protected + scoped CI/CD variables | Narrow `withCredentials` scope |
| Isolated runners | Ephemeral / no self-hosted on forks | Ephemeral runners, tags | Ephemeral agents, isolated nodes |

## Key Takeaways

1. **Untrusted code and secrets must never meet**—pick the trigger that enforces this (`pull_request`, not `pull_request_target` with checkout).
2. **Approval gates outsiders**—require a maintainer before fork-PR workflows run.
3. **Pin to SHAs and least-privilege the token**—cap both what you execute and what it can do.
4. **Isolate runners**—ephemeral, and never self-hosted for fork PRs.
5. **Review the definition and the scripts**—I-PPE hides in Makefiles, hooks, and configs; separate build creds from deploy creds so a build compromise stops short of production.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure pipelines across GitHub Actions, GitLab CI, and Jenkins
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
