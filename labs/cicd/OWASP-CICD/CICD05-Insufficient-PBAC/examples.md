# CICD-SEC-5: Insufficient PBAC - Code Examples

Each pair below shows an **insecure** pipeline configuration and the **secure** version on the same platform. The examples focus on the patterns that dominate real findings: all-secrets-in-every-job, standing broad cloud roles, non-ephemeral and shared runners, and unverified shared state.

## GitHub Actions

### Insecure

```yaml
# .github/workflows/ci.yml
on:
  pull_request_target:                  # runs in base-repo context WITH secrets
permissions: write-all                  # GITHUB_TOKEN can write everything

env:                                    # every secret handed to every step
  AWS_ACCESS_KEY_ID:     ${{ secrets.AWS_ACCESS_KEY_ID }}      # long-lived static key
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  NPM_PUBLISH_TOKEN:     ${{ secrets.NPM_PUBLISH_TOKEN }}
  PROD_DEPLOY_KEY:       ${{ secrets.PROD_DEPLOY_KEY }}

jobs:
  build-test-deploy:
    runs-on: [self-hosted, prod]        # non-ephemeral runner, also serves prod
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # checks out UNTRUSTED PR code
      - run: make build && make test    # untrusted code runs with ALL secrets present
      - run: ./deploy.sh                # same job/runner deploys to prod
```

**Why it's dangerous**: untrusted fork code runs with every production secret in the environment, a wildcard token, static cloud keys, and on a reused runner shared with production. One malicious PR reads everything.

### Secure

```yaml
# Split trust: untrusted PR testing has NO secrets; deploy is gated + OIDC-scoped.

# 1) Untrusted PR validation -- disposable runner, no secrets, read-only token.
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest              # GitHub-hosted, ephemeral, no prod creds
    steps:
      - uses: actions/checkout@v4       # fork code, but nothing sensitive to steal
      - run: make build && make test

---
# 2) Deploy -- separate workflow, trusted branch only, short-lived OIDC, scoped role.
on:
  push:
    branches: [main]
permissions:
  id-token: write                       # request an OIDC token
  contents: read
jobs:
  deploy:
    environment: production             # protection rules: approval + branch limit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/deploy-app-only
          aws-region: us-east-1         # role scoped to THIS repo+environment, deploy-only
      - run: ./deploy.sh                # no static keys; token expires in minutes
```

## GitLab CI/CD

### Insecure

```yaml
# .gitlab-ci.yml -- shell executor on a shared, long-lived host
stages: [build, deploy]

build:
  tags: [shared-shell]                  # shell executor: writes persist on the host
  script:
    - make build                        # untrusted MR code runs directly on the host
    # AWS_* and DEPLOY_TOKEN are project variables, NOT protected/masked,
    # so they are injected into EVERY job -- including MRs from forks.
    - env                               # any script can dump them

deploy:
  tags: [shared-shell]                  # same reused host as build/test
  script:
    - aws s3 sync ./dist s3://prod-bucket   # static long-lived keys from variables
```

**Why it's dangerous**: the shell executor leaves credentials and workspaces on a reused host; variables are unprotected so fork merge requests receive them; and there is no trust separation between build and deploy.

### Secure

```yaml
# .gitlab-ci.yml -- ephemeral containers, protected/masked vars, OIDC, split trust
stages: [build, deploy]

build:
  image: alpine:3.20
  tags: [docker-ephemeral]              # fresh container per job, discarded after
  script:
    - make build                        # no deploy creds present in this job
  # No sensitive variables exposed to build/test.

deploy:
  image: alpine:3.20
  tags: [docker-ephemeral]
  stage: deploy
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"' # protected branch only; not fork MRs
  id_tokens:
    AWS_ID_TOKEN:
      aud: https://gitlab.example.com   # OIDC token, no stored static keys
  script:
    - >-
      creds=$(aws sts assume-role-with-web-identity
        --role-arn arn:aws:iam::111122223333:role/deploy-app-only
        --role-session-name ci --web-identity-token "$AWS_ID_TOKEN"
        --duration-seconds 900 --query Credentials --output json)
    - # export short-lived creds from $creds, then:
    - aws s3 sync ./dist s3://prod-bucket
# DEPLOY variables are marked "protected" + "masked" so only protected
# branches receive them, and they never appear in job logs.
```

## Jenkins

### Insecure

```groovy
// Jenkinsfile -- builds on the controller, global creds bound for the whole run
pipeline {
  agent any                             // may schedule onto the controller itself
  environment {
    // Global credentials bound across the ENTIRE pipeline, every stage:
    AWS_ACCESS_KEY_ID     = credentials('aws-prod-key')       // long-lived
    AWS_SECRET_ACCESS_KEY = credentials('aws-prod-secret')
    SIGNING_KEY           = credentials('gpg-signing-key')
  }
  stages {
    stage('Build') {
      steps { sh 'make build' }         // untrusted deps/tests run with prod + signing creds
    }
    stage('Deploy') {
      steps { sh './deploy.sh' }        // same reused agent, full standing access
    }
  }
}
```

**Why it's dangerous**: builds can land on the controller (full Jenkins compromise), production and signing credentials are bound for every stage including untrusted build steps, and reused agents retain state between runs.

### Secure

```groovy
// Jenkinsfile -- ephemeral agents, per-stage credential binding, split trust
pipeline {
  agent none                            // never the controller
  stages {
    stage('Build & Test') {
      agent { kubernetes { yaml 'build-pod.yaml' } }  // fresh pod per run, discarded
      steps { sh 'make build && make test' }          // NO deploy/signing creds here
    }
    stage('Deploy') {
      when { branch 'main' }            // trusted branch only
      agent { kubernetes { yaml 'deploy-pod.yaml' } } // separate, minimal agent
      steps {
        // Bind the deploy credential ONLY within this block, only for this stage:
        withCredentials([string(credentialsId: 'deploy-token', variable: 'DEPLOY_TOKEN')]) {
          sh './deploy.sh'
        }
      }
    }
  }
}
// Agents are provisioned per build (Kubernetes plugin) and destroyed after,
// so no credentials or workspaces carry over between jobs.
```

## Cloud Role Scoping (AWS IAM)

### Insecure

```json
# Standing role attached permanently to the self-hosted runner instance.
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"          # every job on this runner inherits full account access
}
```

### Secure

```json
# Short-lived role assumed per job via OIDC, scoped to the exact need.
# Trust policy -- who may assume it:
"Condition": {
  "StringEquals": {
    "token.actions.githubusercontent.com:sub":
      "repo:acme/app:environment:production"
  }
}
# Permission policy -- what it may do (deploy this one app, nothing else):
{
  "Effect": "Allow",
  "Action": ["s3:PutObject", "s3:GetObject"],
  "Resource": "arn:aws:s3:::prod-bucket/app/*"
}
```

## What Changed, and Why

| Insufficient PBAC | Insecure | Secure |
|-------------------|----------|--------|
| Secret scope | All secrets injected into every job | Scoped to the deploy job / protected environment |
| Cloud identity | Standing wildcard role / long-lived static keys | Short-lived OIDC token, deploy-only, per job |
| Runner lifetime | Non-ephemeral, reused between jobs | Fresh container/VM per job, destroyed after |
| Trust isolation | Fork/PR code shares runner with prod | Untrusted tests on disposable runners, no secrets |
| Build vs deploy | One job builds and deploys | Separate, differently scoped runners/stages |
| Pipeline token | `write-all` / global binding | Read-only default, write only where needed |

## Next Steps

- **[Prevention](prevention.md)**: The full least-privilege, ephemeral, isolated strategy
- **[Attack Vectors](attack-vectors.md)**: How these misconfigurations are exploited
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
