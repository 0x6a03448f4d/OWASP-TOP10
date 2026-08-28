# CICD-SEC-1: Insufficient Flow Control Mechanisms - Prevention

## Prevention Strategy Overview

Preventing insufficient flow control is about **making the gated path the only path**. Every transition from commit to production should require a check that a single actor cannot satisfy alone, and those checks must be enforced by configuration—not by convention or good intentions:

1. Protect the branch: no change reaches the mainline except through a reviewed pull request.
2. Require independent review and passing status checks before merge.
3. Gate deployment separately, with a second approver and protected environments.
4. Govern the pipeline definition as strictly as the code it builds.
5. Constrain untrusted (fork) contributions and automation identities.
6. Continuously verify that the gates still exist and detect drift.

### Core Principles

- **No single actor to production**: every path to a trusted output must require more than one independent decision (four-eyes).
- **Enforce, don't advise**: a check that can be skipped is not a control; mark reviews and status checks as *required* and apply them to everyone, including admins and bots.
- **Separate merge from deploy**: deciding that code is correct and deciding to release it are two decisions—keep them distinct.
- **Govern the gates**: the configuration that defines flow control is itself high-value code and must be reviewed by code owners.

## 1. Branch Protection and Required, Independent Review

Make the mainline reachable only through a pull request that a second person has reviewed. Disallow self-approval and require code-owner review for sensitive paths.

```json
# GitHub repository ruleset (branch protection) — codified, not click-ops
# .github/rulesets/main-protection.json  (applied via API / IaC)
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main"] } },
  "rules": [
    { "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 2,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true      // author's own last push cannot self-approve
      }
    },
    { "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "build" },
          { "context": "test" },
          { "context": "security-scan" }
        ]
      }
    },
    { "type": "non_fast_forward" },             // block force-push / history rewrite
    { "type": "deletion" }                      // block branch deletion
  ],
  "bypass_actors": []                            // nobody bypasses — includes admins
}
```

> The two settings that turn "review" into *independent* review are `require_last_push_approval` (the person who pushed last cannot be the approver) and an empty `bypass_actors` (admins and apps are not exempt).

## 2. Require Status Checks to Actually Block

A check only controls flow if the merge is impossible while it is failing or missing. Wire your build, tests, and scans as *required* contexts and keep branches up to date so a check cannot pass on stale code.

```yaml
# GitLab: block merge unless pipeline succeeds and threads are resolved
# Project > Settings > Merge requests (as project config / API):
only_allow_merge_if_pipeline_succeeds: true
only_allow_merge_if_all_discussions_are_resolved: true
allow_merge_on_skipped_pipeline: false          # a skipped pipeline must NOT unlock merge
merge_method: merge

# GitLab: approval rules that forbid self-approval
# Settings > Merge request approvals:
approvals_before_merge: 2
merge_requests_author_approval: false           # author cannot approve their own MR
merge_requests_disable_committers_approval: true # committers to the MR cannot approve it
reset_approvals_on_push: true
```

## 3. Protected Environments and Separate Deployment Approval

Merging code must not be the same act as releasing it. Put production behind an environment that requires a distinct approver and only deploys from the protected branch.

```yaml
# GitHub Actions: production behind a protected environment
jobs:
  deploy-prod:
    runs-on: ubuntu-latest
    environment:
      name: production          # environment has required reviewers configured
      url: https://app.example.com
    # Only run for the protected branch, never for arbitrary refs:
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh production
```

```
# The environment's protection rules (configured on the environment, via API/IaC):
#   required_reviewers: [ team:release-approvers ]   # a DIFFERENT person approves the deploy
#   prevent_self_review: true                        # the deployer cannot self-approve
#   deployment_branch_policy: protected_branches_only # no deploying from feature branches
#   wait_timer: 10                                    # optional cool-off window
```

The reviewer who approves the *deployment* should be able to differ from the reviewer who approved the *merge*, giving two independent decisions on the path to production.

## 4. Govern the Pipeline Definition With Code Owners

The files that define the gates are the highest-value files in the repository. Require dedicated review for any change to them, so an attacker cannot quietly delete a check.

```
# CODEOWNERS — changes to CI/CD config demand review by the platform team
/.github/workflows/    @org/platform-security
/.gitlab-ci.yml        @org/platform-security
/Jenkinsfile           @org/platform-security
/.github/rulesets/     @org/platform-security
/deploy/               @org/platform-security
```

Combined with `require_code_owner_review` from step 1, a pull request that touches the pipeline definition cannot merge without the owning team's approval—so removing a gate is itself gated.

## 5. Constrain Fork Pull Requests

Never run untrusted fork code in a context that holds secrets without an explicit maintainer approval first. Prefer `pull_request` (no secrets) over `pull_request_target`, and require approval to run workflows for outside contributors.

```yaml
# SECURE: build/test fork PRs WITHOUT secrets, on the PR's own code
on: pull_request           # runs with a read-only token, no repo secrets
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read        # least privilege for the job token
    steps:
      - uses: actions/checkout@v4      # checks out the PR code, but no secrets exposed
      - run: npm ci && npm test
```

Additional repository settings to enforce this uniformly:

- Require approval for all outside collaborators before any workflow runs on their pull requests.
- If a privileged step genuinely needs secrets, split it: run untrusted code in an unprivileged job, then hand only trusted, validated artifacts to a separate privileged job gated by an environment approval.
- Set the default workflow token permissions to read-only and grant write scopes per-job only where required.

## 6. Bring Automation Identities Inside the Gates

Tokens and bots must not be a bypass. Apply protection to everyone and scope automation credentials tightly.

```yaml
# Principles for machine identities in the flow:
#  - Branch protection applies to apps/bots too (no blanket bypass entries).
#  - Deploy tokens are short-lived and scoped to a single environment.
#  - Prefer OIDC federation over long-lived PATs for cloud deploys:
permissions:
  id-token: write            # mint a short-lived cloud credential per run
  contents: read
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/deploy-prod
      # the role's trust policy restricts which repo/branch/environment may assume it
```

## 7. Jenkins: Enforce Review and Approval in the Pipeline

On Jenkins the same principles apply—build only reviewed refs, and require a separate manual approval, from a distinct group, before deploying to production.

```groovy
// Jenkinsfile — build the merged/protected ref, gate prod on a second approver
pipeline {
  agent any
  stages {
    stage('Build & Test') {
      steps { sh './gradlew build test' }        // must pass before anything downstream
    }
    stage('Security Scan') {
      steps { sh './security-scan.sh' }          // required gate, fails the build on findings
    }
    stage('Deploy to Production') {
      when { branch 'main' }                      // only the protected branch deploys
      steps {
        // Four-eyes: a DIFFERENT person from the 'release-approvers' group must approve
        input message: 'Approve production deploy?',
              submitter: 'release-approvers',
              submitterParameter: 'approver'
        sh './deploy.sh production'
      }
    }
  }
}
```

Pair this with the Git provider's branch protection (Jenkins should only ever be triggered by, and check out, the protected branch) so the approval cannot be sidestepped by pointing the job at an arbitrary ref.

## 8. Detect Drift and Verify the Gates Still Exist

Controls decay: someone disables a rule "temporarily", a new repository is created without protection, a bypass entry is added. Continuously assert that the gates are present.

```bash
# CI check that fails if main is not properly protected (run on a schedule)
#!/usr/bin/env bash
set -euo pipefail
rules=$(gh api repos/$ORG/$REPO/rules/branches/main)

echo "$rules" | jq -e '
  (map(select(.type=="pull_request")) | length > 0) and
  (map(select(.type=="pull_request").parameters.required_approving_review_count) | max >= 2) and
  (map(select(.type=="required_status_checks")) | length > 0) and
  (map(select(.type=="non_fast_forward")) | length > 0)
' > /dev/null || { echo "::error::main branch protection has drifted"; exit 1; }
```

Also alert on: additions to `bypass_actors`, disabling of environment reviewers, new workflows that use production secrets without an `environment:` key, and any deploy that ran without a corresponding approval record.

## Defense-in-Depth Summary

| Layer | Control | Stops |
|-------|---------|-------|
| Source | Branch protection, required PR, no force-push | Direct push to mainline |
| Review | ≥2 approvals, no self-approval, code owners | Self-approval, rubber-stamping |
| Merge | Required status checks, strict up-to-date | Merging failing/unscanned code |
| Deploy | Protected environment, separate approver | Merge == release, solo deploy |
| Config | CODEOWNERS on pipeline definitions | Quietly deleting the gates |
| Untrusted input | No secrets for fork PRs, approval to run | Poisoned pipeline execution |
| Identity | Scoped, short-lived tokens; OIDC; no bypass | Token/bot bypass of protection |
| Assurance | Drift detection, audit of approvals | Silent decay of controls |

## Key Takeaways

1. **Require more than one** — every path to production must need an independent second decision that one actor cannot supply alone.
2. **Make checks blocking** — required reviews and required status checks that apply to admins and bots, not advisory ones.
3. **Split merge from deploy** — protected environments with a separate approver keep releasing distinct from merging.
4. **Guard the gate configuration** — code-owner review on pipeline definitions stops attackers deleting the controls.
5. **Verify continuously** — assert the gates still exist and alert on drift, because controls silently erode.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure pipeline configuration in GitHub Actions, GitLab CI, and Jenkins
- **[Attack Vectors](attack-vectors.md)**: Understand exactly what these gates are defending against
- **[CI/CD Security Track](/learn/cicd)**: Continue with the rest of the OWASP CI/CD Top 10
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
