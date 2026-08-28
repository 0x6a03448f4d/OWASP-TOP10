# CICD-SEC-10: Insufficient Logging and Visibility - Prevention

## Prevention Strategy Overview

Preventing CICD-SEC-10 means building the capability to **notice and reconstruct** attacks on your pipeline. That is not a single log setting—it is a program that spans the whole toolchain:

1. Enable comprehensive audit logging across every system in the pipeline.
2. Centralise those logs into one platform that can correlate across tools.
3. Alert on the specific pipeline events that signal an attack.
4. Retain logs tamper-resistantly, long enough to investigate.
5. Watch the runners themselves, baseline normal behaviour, and wire alerts into incident response.

### Core Principles

- **Whole-toolchain coverage**: SCM, CI/CD, registries, artifact stores, secrets managers, and cloud must all emit security events—a gap anywhere is a blind spot.
- **Collect, correlate, and alert**: storage alone is not detection; the value is in joining events and firing on the dangerous ones.
- **Tamper-resistant and off-host**: security logs must live where the pipeline's own identities cannot edit or delete them.
- **Know normal to find abnormal**: a baseline of pipeline behaviour is the foundation for anomaly detection and off-hours alerting.

## 1. Enable Comprehensive Audit Logging Across the Toolchain

Turn on security audit logging—not just build/job output—in every system, and make sure it captures the security-relevant events for that tool.

```yaml
# logging-coverage.yaml (excerpt) — reviewed, versioned, applied to each tool
scm:                 # GitHub / GitLab / Bitbucket
  audit_log: enabled
  capture: [push, branch_protection_change, member_role_change,
            new_deploy_key, new_pat, webhook_change, workflow_file_change]
ci_cd:               # orchestrator
  audit_log: enabled
  capture: [pipeline_definition_change, job_trigger, fork_pr_run,
            runner_registration, secret_access, integration_change]
registry:            # container / package registry
  audit_log: enabled
  capture: [push, pull, tag_overwrite, immutability_change, new_publish_token]
secrets_manager:
  audit_log: enabled
  capture: [secret_read, policy_change, lease_create, failed_access]
cloud:
  audit_log: enabled          # e.g. CloudTrail / Audit Logs, all regions
  capture: [deploy, iam_change, new_access_key, out_of_pipeline_action]
```

Confirm the logging tier you need is actually available on your plan—on several platforms detailed audit logs are gated behind higher tiers, and "we assumed it was on" is a common root cause.

## 2. Centralise Logs into a SIEM

Ship every tool's audit stream to one platform so a cross-tool attack can be seen in one place. Forward, don't just store.

```bash
# Example: stream SCM + CI + registry + cloud audit logs to a SIEM
# 1) SCM: configure audit-log streaming to your log endpoint (S3/HTTPS/splunk)
# 2) CI: forward orchestrator + runner logs via the platform's log drain
# 3) Registry & secrets manager: enable event export / webhook to the SIEM
# 4) Cloud: deliver the audit trail to the same bucket/index

# Normalise so events from every tool share identity + time fields:
#   actor, source_tool, action, target, repo/project, ip, timestamp(UTC)
# This normalisation is what makes correlation in step 3 possible.
```

The goal is a single query surface where one investigation can span a commit in SCM, the build it triggered in CI, the token it used in the secrets manager, and the deploy it produced in the cloud.

## 3. Correlate Across Tools

Give every pipeline run a traceable identity so events can be joined into a timeline.

```bash
# Propagate a correlation id through the pipeline and stamp it on every event
export PIPELINE_TRACE_ID="${CI_PIPELINE_ID}-${GIT_COMMIT_SHA:0:12}"

# When calling the registry, cloud, or secrets manager from a job, tag actions:
#   description / user-agent / session-name = "ci:$PIPELINE_TRACE_ID"
aws sts assume-role --role-session-name "ci-$PIPELINE_TRACE_ID" ...

# In the SIEM, correlation rules can now answer:
#   commit  -> build  -> secret_read  -> artifact_push  -> deploy
# and flag any deploy whose artifact was NOT produced by a matching build.
```

## 4. Alert on High-Risk Pipeline Events

Detection is what turns logs into defence. Define alerts for the events an attacker cannot avoid generating.

```yaml
# siem-rules.yaml — alert on the events that signal pipeline attack
- name: pipeline-config-change
  match: action == "pipeline_definition_change" OR "workflow_file_change"
  notify: [security-oncall]
- name: secret-access-anomaly
  match: action == "secret_read" AND (actor.is_new OR count_last_5m > baseline)
  notify: [security-oncall]
- name: new-identity
  match: action in ["new_pat","new_deploy_key","new_service_account","iam_change"]
  notify: [security-oncall]
- name: permission-or-protection-change
  match: action in ["branch_protection_change","member_role_change","required_check_disabled"]
  notify: [security-oncall]
- name: off-hours-or-out-of-band-deploy
  match: action == "deploy" AND (outside_business_hours OR ref NOT IN protected_refs)
  notify: [security-oncall]
- name: fork-pr-workflow-run
  match: action == "job_trigger" AND trigger == "fork_pull_request"
  notify: [security-oncall]
```

Tune thresholds against your baseline so alerts are actionable rather than noisy—an ignored alert is as good as no alert.

## 5. Tamper-Resistant Retention

Logs are only evidence if the attacker cannot alter them and they outlive the incident.

```bash
# Ship security logs to append-only, off-host storage the pipeline can't edit
# e.g. object storage with immutability / object-lock and a separate account
aws s3api put-object-lock-configuration --bucket ci-audit-logs \
  --object-lock-configuration 'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=COMPLIANCE,Days=400}}'

# Principles:
#   - write-once (WORM) or append-only; pipeline identities have no delete
#   - stored in a separate trust boundary / account from the CI system
#   - retained long enough to investigate a months-old compromise
#   - integrity-checked (hash chaining) so gaps/edits are detectable
```

## 6. Monitor Runner Activity

Console output is attacker-controlled; real runner visibility means process and network telemetry from the agent itself.

```yaml
# Instrument build agents with host/EDR + egress monitoring
runner_monitoring:
  process: capture exec of unexpected binaries (curl to new hosts, compilers, nc)
  network: log + baseline outbound destinations; alert on novel egress
  filesystem: watch writes outside the workspace, new SSH keys, cron edits
  egress_policy: allow-list package mirrors / registries; deny by default
# Prefer ephemeral, single-use runners so each job starts clean and is diffable.
```

An allow-listed egress policy plus alerting on novel outbound connections is what turns runner exfiltration from invisible into obvious.

## 7. Establish a Behavioural Baseline and Detect Anomalies

You cannot flag "unusual" without a definition of "usual." Characterise normal pipeline behaviour and alert on deviations.

```python
# Baseline dimensions to model per repo/pipeline:
#   who deploys, at what times/days, how frequently
#   which branches/refs reach production
#   typical secret-read volume and actors
#   typical runner egress destinations
# Then alert on deviations:
def anomalous(event, baseline):
    return (event.actor not in baseline.actors
            or event.hour not in baseline.hours
            or event.target not in baseline.targets
            or event.rate  > baseline.p99_rate)
```

## 8. Integrate with Incident Response

Visibility only pays off if a fired alert leads to action. Wire pipeline detections into your existing IR process.

- Route pipeline alerts to the same on-call and ticketing flow as the rest of security.
- Write runbooks for the top pipeline scenarios (rogue token, poisoned workflow, artifact overwrite): how to revoke, rebuild, and verify.
- Pre-stage the queries an investigator needs (by `PIPELINE_TRACE_ID`, actor, or artifact digest) so reconstruction is fast.
- Run tabletop exercises against pipeline incidents to confirm the logs answer "what did they do, take, and ship?"

## Platform-Specific Notes

### GitHub

```
# Org-level: enable audit log streaming to your SIEM/storage
#   Settings -> Audit log -> Log streaming  (captures admin, member, repo, secret events)
# Restrict who can change Actions workflows and required reviews; log those changes.
# Alert on: new deploy keys/PATs, self-hosted runner registration,
#           secret creation, branch-protection edits, fork PR workflow runs.
```

### GitLab

```
# Enable Audit Events (group/instance) and stream them out.
# Watch: CI/CD variable access, protected-branch/tag changes,
#        new project/group access tokens, runner registration tokens.
# Prefer instance/group runners with egress controls over shared runners for secrets.
```

### Jenkins

```
# Install and forward the Audit Trail plugin (config changes, job runs, users).
# Ship $JENKINS_HOME logs + system logs off-host; JENKINS_HOME is attacker-editable.
# Alert on: new credentials, job/pipeline config changes, plugin installs,
#           script-console usage (a direct code-exec surface).
```

## Key Takeaways

1. **Cover the whole toolchain** — enable security audit logging in SCM, CI, registries, secrets managers, and cloud, not just build output.
2. **Centralise and correlate** — one SIEM with a shared identity/trace model turns scattered events into a story.
3. **Alert on the unavoidable events** — config changes, secret access, new identities, permission changes, and off-hours/fork deploys.
4. **Make logs tamper-resistant and durable** — off-host, write-once, retained long enough to investigate.
5. **Watch runners and baseline normal** — then wire every detection into incident response so alerts become action.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure logging and alerting configuration
- **[Attack Vectors](attack-vectors.md)**: Understand the undetected activity you're defending against
- **[CI/CD Security Track](/learn/cicd)**: Return to the full OWASP CI/CD Top 10
- **[Practice](/practice)**: Test your understanding with hands-on challenges
