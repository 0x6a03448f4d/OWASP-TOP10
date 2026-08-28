# CICD-SEC-1: Insufficient Flow Control Mechanisms - Code Examples

Each pair below shows an **insecure** pipeline configuration and the **secure** version in the same platform. The examples focus on the flow-control failures that dominate real findings: deploying on any push with no approval, self-approvable merges, running fork code with secrets, and pipeline definitions that can delete their own gates.

> Flow control lives in two places: the *pipeline files* shown here, and the *platform settings* (branch protection, environment reviewers, approval rules) they rely on. A secure pipeline file assumes the matching platform gate is also configured—both are required.

## GitHub Actions

### Insecure

```yaml
# .github/workflows/deploy.yml
# Any push to main goes straight to production, with no approval gate.
name: build-and-deploy
on:
  push:
    branches: [ main ]

jobs:
  ship:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
      # No environment, no reviewer, no required checks referenced here.
      # Whoever lands a commit on main (direct push, self-approved PR,
      # or a leaked token) has just deployed to production.
      - run: ./deploy.sh production
        env:
          PROD_TOKEN: ${{ secrets.PROD_DEPLOY_TOKEN }}
```

```yaml
# .github/workflows/pr-check.yml — untrusted fork code runs WITH secrets
on: pull_request_target        # base-repo secrets are available
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # attacker's fork code
      - run: npm ci && npm test    # a malicious package script runs with secrets
```

### Secure

```yaml
# .github/workflows/deploy.yml
# Merge and deploy are separate decisions; prod is behind a protected environment.
name: build-and-deploy
on:
  push:
    branches: [ main ]         # only the protected branch triggers this

permissions:
  contents: read               # least-privilege default token

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
      - run: ./security-scan.sh          # blocking gate before anything ships
      - uses: actions/upload-artifact@v4
        with: { name: app, path: dist/ }

  deploy-prod:
    needs: build                          # cannot deploy unless build+scan passed
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment:
      name: production                    # required reviewers + prevent-self-review
      url: https://app.example.com        # configured on the environment itself
    permissions:
      id-token: write                     # short-lived OIDC credential, no static token
      contents: read
    steps:
      - uses: actions/download-artifact@v4
        with: { name: app, path: dist/ }
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy-prod
      - run: ./deploy.sh production        # runs only after a SECOND person approves
```

```yaml
# .github/workflows/pr-check.yml — fork PRs build WITHOUT secrets
on: pull_request               # read-only token, no repo secrets exposed
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4          # PR code, but nothing secret to steal
      - run: npm ci && npm test
```

Required platform settings for the secure version: a ruleset on `main` requiring 2 approving reviews with `require_last_push_approval` (no self-approval) and `build`/`security-scan` as required status checks; the `production` environment configured with required reviewers, prevent-self-review, and protected-branches-only deployments; and "require approval for all outside collaborators" enabled.

## GitLab CI

### Insecure

```yaml
# .gitlab-ci.yml
# Deploy to production runs automatically on every commit to the default branch.
stages: [ build, deploy ]

build:
  stage: build
  script: [ "make build" ]

deploy_prod:
  stage: deploy
  script: [ "./deploy.sh production" ]
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: always          # no manual gate, no separate approver
  # Combined with project settings that allow author self-approval and
  # do not require the pipeline to pass, one person ships to prod alone.
```

### Secure

```yaml
# .gitlab-ci.yml
# Build/scan must pass; production is a manual job restricted to a protected env.
stages: [ build, test, deploy ]

build:
  stage: build
  script: [ "make build" ]

security_scan:
  stage: test
  script: [ "./security-scan.sh" ]      # pipeline fails (and blocks merge) on findings

deploy_prod:
  stage: deploy
  environment:
    name: production                     # a Protected Environment in GitLab
  script: [ "./deploy.sh production" ]
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: manual                       # a human must trigger the deploy
  # 'manual' + a Protected Environment means only members of the
  # 'release-approvers' group can run this job — a separate decision from merge.
  allow_failure: false
```

Required GitLab project settings for the secure version: *Merge requests* → `only_allow_merge_if_pipeline_succeeds: true` and `allow_merge_on_skipped_pipeline: false`; *Merge request approvals* → `approvals_before_merge: 2`, `merge_requests_author_approval: false`, `reset_approvals_on_push: true`; and a *Protected Environment* named `production` whose "Allowed to deploy" list is a distinct release group. Protect `main` so direct pushes are rejected.

## Jenkins

### Insecure

```groovy
// Jenkinsfile
// Builds any branch and deploys to prod with no approval and no branch guard.
pipeline {
  agent any
  stages {
    stage('Build') {
      steps { sh 'make build' }
    }
    stage('Deploy Prod') {
      steps { sh './deploy.sh production' }   // fires for any ref, any trigger,
    }                                          // no input step, no second person
  }
}
```

### Secure

```groovy
// Jenkinsfile
// Build and scan gate the pipeline; prod requires a distinct approver and the
// protected branch. Jenkins is only triggered by the protected branch upstream.
pipeline {
  agent any
  options { disableConcurrentBuilds() }
  stages {
    stage('Build') {
      steps { sh 'make build' }
    }
    stage('Security Scan') {
      steps { sh './security-scan.sh' }        // non-zero exit fails the build
    }
    stage('Deploy Prod') {
      when { branch 'main' }                    // only the protected branch deploys
      steps {
        // Four-eyes: the submitter must be in 'release-approvers' and, by policy,
        // must not be the change author.
        input message: 'Approve production deployment?',
              submitter: 'release-approvers',
              submitterParameter: 'approver'
        sh './deploy.sh production'
      }
    }
  }
}
```

Required Jenkins/SCM settings for the secure version: branch protection on `main` in the Git provider (so merges still require an independent review and the job only ever checks out reviewed code); the `release-approvers` group scoped to release engineers who are not the typical authors; and job configuration that triggers builds only from the protected branch, never from arbitrary refs or fork branches with credentials attached.

## What Changed, and Why

| Flow-control failure | Insecure | Secure |
|----------------------|----------|--------|
| Merge vs deploy | Any push to main auto-deploys to prod | Deploy is a separate, manually approved step |
| Second approver | One actor merges and ships alone | Protected environment / `input` requires a distinct approver |
| Blocking checks | Build/scan advisory or absent | Build + security scan must pass before deploy |
| Fork PRs | `pull_request_target` runs fork code with secrets | `pull_request`: fork code runs with no secrets |
| Branch guard | Deploy fires for any ref | Deploy restricted to the protected branch only |
| Credentials | Long-lived static `PROD_TOKEN` | Short-lived OIDC role, scoped to repo/branch |

## Next Steps

- **[Prevention](prevention.md)**: The full layered strategy behind these examples
- **[Attack Vectors](attack-vectors.md)**: How an uncontrolled flow is exploited end to end
- **[CI/CD Security Track](/learn/cicd)**: Continue with the rest of the OWASP CI/CD Top 10
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
