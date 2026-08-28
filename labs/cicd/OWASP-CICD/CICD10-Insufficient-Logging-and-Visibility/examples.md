# CICD-SEC-10: Insufficient Logging and Visibility - Code Examples

Each pair below shows an **insecure** configuration—where pipeline activity goes unrecorded or unwatched—and the **secure** version that enables, centralises, or alerts on it. The examples cover the whole toolchain: SCM, CI, registry, cloud, the SIEM, and the runners.

## 1. SCM Audit Logging (GitHub org)

### Insecure
```yaml
# Audit logging left at defaults: visible only in the web UI, never exported,
# short-lived, and nobody watching. Security-relevant events are effectively lost.
org:
  audit_log_streaming: disabled        # events stay trapped in the console
  # No export of member/role changes, new deploy keys, or workflow edits.
  # An attacker who disables branch protection at 3am generates no alert.
```

### Secure
```yaml
# Stream the org audit log off-platform and capture the security-relevant events.
org:
  audit_log_streaming:
    enabled: true
    destination: s3://acme-ci-audit-logs   # off-host, immutable bucket
  # Ensure the stream includes the high-signal actions:
  captured_events:
    - repo.branch_protection.destroy       # guardrail removed
    - org.update_member                     # role change / privilege grant
    - deploy_key.create                     # new persistence key
    - personal_access_token.create
    - workflows.updated                     # the automation itself changed
    - repo.actions_secret.create
```

## 2. CI/CD Pipeline Audit Configuration (GitLab)

### Insecure
```yaml
# Only job console output exists. It is per-project, mutable, rotates in days,
# and shows nothing about who changed the pipeline or accessed variables.
ci_cd:
  audit_events: disabled
  # Protected-branch edits, variable reads, and runner registration
  # are invisible. "We have CI logs" = build debug output only.
```

### Secure
```yaml
# Enable audit events and stream them; treat pipeline changes as security events.
ci_cd:
  audit_events:
    enabled: true
    streaming_destination: https://siem.acme.internal/ingest/gitlab
  monitored:
    - ci_variable_access            # secret/variable reads
    - protected_branch_change
    - project_access_token_create   # new pipeline identity
    - runner_registration           # new runner joining the fleet
    - pipeline_definition_change     # .gitlab-ci.yml edits
# Also: require review on .gitlab-ci.yml via CODEOWNERS so changes are attributable.
```

## 3. Registry / Artifact Store Visibility

### Insecure
```yaml
# Tags are mutable and pushes are not logged. An attacker overwrites a released
# image tag with a backdoored build and nothing records the substitution.
registry:
  immutable_tags: false          # existing tags can be silently replaced
  audit:      off                # no push/pull/tag-mutation events
  publish_tokens:
    audit: off                   # new publish tokens created unnoticed
```

### Secure
```yaml
# Make artifacts immutable and log every mutation and publish-credential change.
registry:
  immutable_tags: true           # a released tag can never be overwritten
  audit:
    enabled: true
    export_to: https://siem.acme.internal/ingest/registry
    events: [image_push, tag_mutation_attempt, new_publish_token, retention_change]
  # Verify published digest == digest produced by the matching build (see cloud/CI trace id).
```

## 4. Cloud Deploy-Target Audit Trail (AWS)

### Insecure
```hcl
# A single-region trail with no data events and no integrity protection.
# Out-of-pipeline deploys and new access keys are barely captured, easily edited.
resource "aws_cloudtrail" "main" {
  name                       = "partial"
  s3_bucket_name             = aws_s3_bucket.logs.id
  is_multi_region_trail      = false     # other regions are blind
  enable_log_file_validation = false     # logs can be altered undetectably
}
```

### Secure
```hcl
# Multi-region, integrity-validated trail delivered to a locked, separate account.
resource "aws_cloudtrail" "main" {
  name                          = "org-wide"
  s3_bucket_name                = aws_s3_bucket.audit.id   # separate log-archive account
  is_multi_region_trail         = true
  is_organization_trail         = true
  enable_log_file_validation    = true                     # tamper-evident
  include_global_service_events = true
}

# Object-lock the bucket so pipeline identities cannot delete history:
resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule { default_retention { mode = "COMPLIANCE"  days = 400 } }
}
```

## 5. Centralising and Alerting (SIEM)

### Insecure
```yaml
# Each tool logs to its own console. Nothing is aggregated, so a cross-tool
# attack (SCM -> CI -> registry -> cloud) is never seen end to end, and no
# rule fires on any single step.
siem:
  sources: []            # nothing forwarded
  correlation: none
  alerts: []             # collection without detection
```

### Secure
```yaml
# All toolchain logs land in one place, normalised, correlated, and alerted on.
siem:
  sources: [github_audit, gitlab_ci, registry, secrets_manager, cloudtrail, runners]
  normalise_fields: [actor, source_tool, action, target, ip, timestamp_utc, trace_id]
  correlation:
    join_on: trace_id     # commit -> build -> secret_read -> push -> deploy
  alerts:
    - name: pipeline_config_change
      when: action in [workflows.updated, pipeline_definition_change]
    - name: new_pipeline_identity
      when: action in [deploy_key.create, personal_access_token.create,
                       project_access_token_create, iam_create_access_key]
    - name: secret_read_anomaly
      when: action == secret_read and (actor.first_seen or rate > baseline.p99)
    - name: off_hours_or_out_of_band_deploy
      when: action == deploy and (outside_business_hours or ref not in protected_refs)
    - name: fork_pr_workflow_run
      when: action == job_trigger and trigger == fork_pull_request
    - name: protection_rule_change
      when: action in [branch_protection.destroy, required_check_disabled, member_role_change]
```

## 6. Runner Visibility and Egress

### Insecure
```yaml
# Persistent shared runner, unrestricted egress, only console output captured.
# A build step can curl secrets to any host and nothing on the agent notices.
runner:
  type: shared-persistent      # state and secrets bleed between jobs
  egress: allow-all            # exfiltration to any destination
  host_monitoring: none        # no process / network telemetry
```

### Secure
```yaml
# Ephemeral runner, default-deny egress, host + network telemetry to the SIEM.
runner:
  type: ephemeral-single-use   # clean per job; easy to diff and reason about
  egress:
    default: deny
    allow: [registry.acme.internal, mirror.acme.internal, api.github.com]
  host_monitoring:
    processes: capture exec (alert on curl/nc/compilers to novel hosts)
    network:   log outbound; alert on connections outside the allow-list
    forward_to: https://siem.acme.internal/ingest/runners
```

## 7. Application-Side: Emit and Ship a Pipeline Audit Event

### Insecure
```python
# A deploy script that logs nothing durable — the record dies with the runner.
def deploy(artifact, target):
    print(f"deploying {artifact} to {target}")   # stdout only, rotates away
    run_deploy(artifact, target)                  # no actor, no trace id, no export
```

### Secure
```python
import json, logging, os, time
audit = logging.getLogger("pipeline.audit")   # handler ships off-host to the SIEM

def deploy(artifact, target, actor):
    event = {
        "action": "deploy",
        "actor": actor,                                  # who / which identity
        "artifact_digest": artifact.digest,              # what, precisely
        "target": target,
        "trace_id": os.environ["PIPELINE_TRACE_ID"],     # correlate to build/commit
        "ref": os.environ.get("GIT_REF"),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    audit.info(json.dumps(event))                        # durable, correlatable, alertable
    run_deploy(artifact, target)
```

## What Changed, and Why

| Area | Insecure | Secure |
|------|----------|--------|
| SCM | Audit log trapped in UI, key events uncaptured | Streamed off-host; protection/identity/workflow events captured |
| CI/CD | Only mutable job console output | Audit events on config, variable access, runners — streamed |
| Registry | Mutable tags, no push/token logging | Immutable tags; push/tag-mutation/token events exported |
| Cloud | Single-region, unvalidated, editable trail | Multi-region, integrity-validated, object-locked in a separate account |
| SIEM | No aggregation, correlation, or alerts | Normalised, correlated by trace id, alerting on high-risk events |
| Runners | Persistent, allow-all egress, no host telemetry | Ephemeral, default-deny egress, process/network monitoring |

## Next Steps

- **[Prevention](prevention.md)**: The full toolchain-wide visibility strategy
- **[Attack Vectors](attack-vectors.md)**: How undetected pipeline activity unfolds
- **[CI/CD Security Track](/learn/cicd)**: Return to the full OWASP CI/CD Top 10
- **[Practice](/practice)**: Test your understanding with hands-on challenges
